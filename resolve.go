package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// maxLinkHops bounds symlink chains (alternatives: iptables -> /etc/alternatives/iptables ->
// iptables-nft -> xtables-nft-multi is 3 hops).
const maxLinkHops = 8

// checkChain validates a `resolve: true` binary path. Every link in the symlink chain must be
// owned by ownerUID (root in production) and sit in a directory that passes checkTree (no
// symlinked, group/world-writable or foreign-owned directory anywhere up to "/"); the final
// target must pass checkTree itself. Because no directory on the way is a symlink, resolving
// relative link targets lexically equals what the kernel does. Returns the final target.
// The caller still execs the ORIGINAL path, so multi-call binaries (xtables-*-multi) see the
// right argv[0], and sudo sees the path named in sudoers.
func checkChain(path string, ownerUID uint32) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s: not absolute/clean", path)
	}
	cur := path
	for hop := 0; ; hop++ {
		if hop > maxLinkHops {
			return "", fmt.Errorf("%s: too many symlinks", path)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", err // dangling link or missing binary: fail closed
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if err := checkTree(cur, ownerUID); err != nil {
				return "", err
			}
			if !fi.Mode().IsRegular() {
				return "", fmt.Errorf("%s: not a regular file", cur)
			}
			if rp, err := filepath.EvalSymlinks(path); err != nil || rp != cur {
				return "", fmt.Errorf("%s: resolves inconsistently", path)
			}
			return cur, nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != ownerUID {
			return "", fmt.Errorf("%s: symlink not owned by uid %d", cur, ownerUID)
		}
		if err := checkTree(filepath.Dir(cur), ownerUID); err != nil {
			return "", err
		}
		t, err := os.Readlink(cur)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(cur), t)
		}
		cur = filepath.Clean(t)
	}
}

// internalFileRead serves a fixed set of OS identification files (no cat binary).
const internalFileRead = "internal:fileread"

// osFiles is the complete list of paths internal:fileread will ever open. Exact strings only.
var osFiles = map[string]bool{
	"/etc/os-release":     true,
	"/etc/redhat-release": true,
	"/etc/debian_version": true,
	"/etc/lsb-release":    true,
}

// osTargetRE limits where an os file's symlink chain may end (e.g. /usr/lib/os-release,
// /etc/rocky-release, /etc/centos-release).
var osTargetRE = regexp.MustCompile(`^/(?:etc|usr/lib)/[a-z][a-z0-9_-]{0,31}[-_](?:release|version)$`)

const maxOSFile = 64 << 10

// osFileRead copies one whitelisted OS identification file to w: root-owned symlink chain,
// world-readable regular target, at most maxOSFile bytes.
func osFileRead(path string, w io.Writer, ownerUID uint32) error {
	if !osFiles[path] {
		return errors.New("path not allowed")
	}
	target, err := checkChain(path, ownerUID)
	if err != nil {
		return err
	}
	if !osTargetRE.MatchString(target) || blockedPath(target) || strings.Contains(target, "..") {
		return errors.New("path resolves elsewhere")
	}
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || st.Uid != ownerUID || fi.Mode().Perm()&0o022 != 0 || fi.Mode().Perm()&0o004 == 0 {
		return errors.New("file not a root-owned, world-readable regular file")
	}
	_, err = io.Copy(w, io.LimitReader(f, maxOSFile))
	return err
}
