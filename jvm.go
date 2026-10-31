package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

// JVM diagnostics (jcmd/jstat) must run as the JVM's own user: HotSpot attach and
// hsperfdata only work for the same uid. auditsh never runs them itself. A `jvm: true`
// rule runs `sudo -n -u <owner> -- <path> <name> <args>`, where <path> is the root-owned
// helper auditsh-jvm and <owner> is the uid of the target pid. The sudoers rule for the
// helper is generated per Java user by `auditsh-setup --java-user` (botaudit-jvm), so sudo
// itself refuses users that were not configured. The helper re-validates everything.

// jvmPidPattern is the one pid pattern a jvm rule must use (exactly once).
const jvmPidPattern = `[1-9][0-9]{0,9}`

var pidRE = regexp.MustCompile(`^` + jvmPidPattern + `$`)

// jvmTools are the only rule names a jvm rule may have (they become the helper's tool arg).
var jvmTools = map[string]bool{"jcmd": true, "jstat": true}

// jvmPid returns the first all-digit argument: the pid in every allowed jcmd/jstat form.
func jvmPid(args []string) (string, error) {
	for _, a := range args {
		if pidRE.MatchString(a) {
			return a, nil
		}
	}
	return "", errors.New("no pid")
}

// jvmOwner reads <procDir>/<pid>/status (no ptrace needed) and returns the owning user
// name. Refuses root, mixed real/effective/saved/fs uids, and processes not named java.
func jvmOwner(procDir, pid string, lookup func(uid string) (string, error)) (string, error) {
	if !pidRE.MatchString(pid) {
		return "", errors.New("bad pid")
	}
	f, err := os.Open(filepath.Join(procDir, pid, "status"))
	if err != nil {
		return "", errors.New("pid not visible (gone, or hidepid)")
	}
	defer f.Close()
	var name string
	var uids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch k {
		case "Name":
			name = strings.TrimSpace(v)
		case "Uid":
			uids = strings.Fields(v)
		}
	}
	if name != "java" {
		return "", fmt.Errorf("pid %s is not a java process", pid)
	}
	if len(uids) != 4 || uids[1] != uids[0] || uids[2] != uids[0] || uids[3] != uids[0] {
		return "", errors.New("pid has mixed uids")
	}
	if uids[0] == "0" {
		return "", errors.New("refusing JVM running as root")
	}
	u, err := lookup(uids[0])
	if err != nil || !userRE.MatchString(u) || u == "root" {
		return "", errors.New("pid owner has no valid user name")
	}
	return u, nil
}

var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func lookupUserName(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// javaUsersFile is written by install.sh (--java-user), root:root 0644, one user name per line.
// It mirrors the Runas list of /etc/sudoers.d/botaudit-jvm so an unconfigured owner is denied
// here (126) instead of producing a sudo auth failure.
const javaUsersFile = "/etc/auditsh/java-users"

func loadJavaUsers(path string, check bool, ownerUID uint32) (map[string]bool, error) {
	if check {
		if err := checkTree(path, ownerUID); err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if userRE.MatchString(ln) && ln != "root" && ln != "botaudit" {
			m[ln] = true
		}
	}
	return m, nil
}

// deniedError is a policy refusal found after the allowlist match (reported as "denied", exit 126).
type deniedError struct{ msg string }

func (d deniedError) Error() string { return d.msg }
