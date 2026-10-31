package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Only these exact /proc paths may be read; pid must be numeric (no self/thread-self/.. ).
var procPathRE = regexp.MustCompile(`^/proc/(?:meminfo|[1-9][0-9]{0,9}/(?:status|smaps_rollup))$`)

// procRead copies an allowlisted /proc file to w. The path is re-validated here
// regardless of config, and opened with O_NOFOLLOW so no final-component symlink is followed.
func procRead(path string, w io.Writer) error { return procReadWith(path, w, openProc) }

// procReadWith is procRead with an explicit opener; only tests pass a non-default one
// (via runOpts.procOpen), so production cannot swap the opener at run time.
func procReadWith(path string, w io.Writer, open func(string) (io.ReadCloser, error)) error {
	if !procPathRE.MatchString(path) {
		return errors.New("path not allowed")
	}
	if blockedPath(path) {
		return errors.New("path blocked")
	}
	// realpath must equal the requested path: no symlink anywhere in it.
	if rp, err := filepath.EvalSymlinks(path); err != nil || rp != path {
		return errors.New("path resolves elsewhere")
	}
	f, err := open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// openProc opens a validated /proc path.
func openProc(path string) (io.ReadCloser, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

// blockedPath is a defence-in-depth hard denylist (design.md section 4), applied even
// though the allowlist regex can never produce these paths.
func blockedPath(p string) bool {
	base := filepath.Base(p)
	return p == "/etc/shadow" || p == "/etc/gshadow" || strings.HasSuffix(p, ".key") ||
		base == ".env" || p == "/root" || strings.HasPrefix(p, "/root/") ||
		(strings.HasPrefix(p, "/etc/ssh/") && strings.Contains(base, "key"))
}
