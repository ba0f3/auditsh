package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/auditsh/internal/dockerpolicy"
)

// ---- independent oracles (written from the policy text, not from the code under test) ----

var jcmdVerbs = map[string]bool{"GC.heap_info": true, "Thread.print": true, "VM.flags": true, "VM.uptime": true, "VM.version": true}

// num: decimal, no leading zero, value in [lo, hi].
func num(s string, lo, hi int) bool {
	if s == "" || len(s) > 10 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= lo && n <= hi
}

// jvmFormOK reports whether tool+args is one of the documented read-only JVM forms.
func jvmFormOK(argv []string) bool {
	const maxPid = 9999999999
	if len(argv) < 2 {
		return false
	}
	a := argv[1:]
	switch argv[0] {
	case "jcmd":
		switch len(a) {
		case 2:
			return num(a[0], 1, maxPid) && jcmdVerbs[a[1]]
		case 3:
			return num(a[0], 1, maxPid) && a[1] == "VM.native_memory" && a[2] == "summary"
		}
	case "jstat":
		switch len(a) {
		case 2:
			return a[0] == "-gcutil" && num(a[1], 1, maxPid)
		case 4:
			return a[0] == "-gcutil" && num(a[1], 1, maxPid) && num(a[2], 100, 1000) && num(a[3], 1, 10)
		}
	}
	return false
}

// dockerFormOK: argv (after "docker") equals one dockerpolicy.Forms entry token by token.
func dockerFormOK(argv []string) bool {
	pat := map[string]*regexp.Regexp{}
	for _, p := range []string{dockerpolicy.NamePattern, dockerpolicy.TailPattern, dockerpolicy.TimePattern} {
		pat[p] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	for _, f := range dockerpolicy.Forms {
		if len(f) != len(argv) {
			continue
		}
		ok := true
		for i, tok := range f {
			if re, isPat := pat[tok]; isPat {
				ok = ok && re.MatchString(argv[i])
			} else {
				ok = ok && tok == argv[i]
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func jvmDockerSeeds(f *testing.F) {
	for _, s := range []string{"jcmd 4242 GC.heap_info", "jcmd 4242 VM.native_memory summary", "jcmd 4242 Thread.print",
		"jcmd 4242 VM.flags", "jstat -gcutil 4242", "jstat -gcutil 4242 1000 10", "jstat -gcutil 4242 100 1",
		"jcmd 4242 GC.heap_dump /tmp/x", "jcmd 0123 VM.flags", "jcmd -l", "jstat -gcutil 4242 1001 1", "jstat -gc 4242",
		"jcmd 4242 VM.flags -all", "jcmd -J-Dx=y 4242 VM.flags", "jstat -gcutil -t 4242",
		"docker ps", "docker ps -a", "docker inspect web-1", "docker logs --tail 10 web-1",
		"docker logs --tail 10 --since 2h web-1", "docker events --since 2h --until 1h", "docker -H tcp://x ps",
		"docker exec web-1 sh", "docker logs --tail=-1 web", "docker inspect -f x web", "docker network inspect bridge"} {
		f.Add(s)
	}
}

// FuzzJVMDockerAllowlist: auditsh command line -> allowlist match. Accepted jvm rules must be
// exactly a documented JVM form (no other verbs/flags, no leading '-' operand other than jstat's
// fixed -gcutil, bounded numbers); accepted docker rules must be exactly a helper policy form.
// Both must produce the fixed sudo argv (helper by absolute path, no shell).
func FuzzJVMDockerAllowlist(f *testing.F) {
	jvmDockerSeeds(f)
	cfg := defaultCfg(f)
	now := time.Now()
	f.Fuzz(func(t *testing.T, raw string) {
		argv, err := parseCommand(raw)
		if err != nil || len(argv) == 0 {
			return
		}
		r, err := cfg.match(argv)
		if err != nil {
			if (argv[0] == "jcmd" || argv[0] == "jstat") && jvmFormOK(argv) {
				t.Fatalf("documented JVM form %q denied: %v", argv, err)
			}
			return
		}
		switch {
		case r.JVM:
			if r.Sudo || r.Docker || r.Path != "/usr/local/sbin/auditsh-jvm" || r.Name != argv[0] {
				t.Fatalf("jvm rule shape %+v", r)
			}
			if !jvmFormOK(argv) {
				t.Fatalf("jvm accepted non-form %q", argv)
			}
			for i, a := range argv[1:] {
				if strings.HasPrefix(a, "-") && !(argv[0] == "jstat" && i == 0 && a == "-gcutil") {
					t.Fatalf("leading '-' operand %q in %q", a, argv)
				}
			}
			pid, err := jvmPid(argv[1:])
			if err != nil || !pidRE.MatchString(pid) {
				t.Fatalf("pid extraction %q: %v", argv, err)
			}
			full := execArgv(r, argv[1:], sudoPath, "appj")
			want := append([]string{sudoPath, "-n", "-u", "appj", "--", r.Path, argv[0]}, argv[1:]...)
			if !slices.Equal(full, want) {
				t.Fatalf("jvm exec argv %q", full)
			}
		case r.Docker:
			if r.Sudo || r.JVM || r.Path != "/usr/local/sbin/auditsh-docker" || argv[0] != "docker" {
				t.Fatalf("docker rule shape %+v", r)
			}
			if !dockerFormOK(argv[1:]) {
				t.Fatalf("docker accepted non-form %q", argv)
			}
			// Times are only checked for ordering/range by the helper; anything else it must accept.
			if _, err := dockerpolicy.Validate(argv[1:], now); err != nil && !errors.Is(err, dockerpolicy.ErrDenied) {
				t.Fatalf("helper error type %v", err)
			}
			full := execArgv(r, argv[1:], sudoPath, "")
			if !slices.Equal(full, append([]string{sudoPath, "-n", "--", r.Path}, argv[1:]...)) {
				t.Fatalf("docker exec argv %q", full)
			}
		default:
			if argv[0] == "jcmd" || argv[0] == "jstat" || argv[0] == "docker" {
				t.Fatalf("%q matched non-jvm/docker rule %s", argv, r.ID)
			}
		}
	})
}

// FuzzJVMOwner: arbitrary /proc/<pid>/status content, pid string and passwd name. An accepted
// owner must come from a "java" process whose four uids agree and are non-zero, and be a safe,
// non-root user name; bad pids (traversal etc.) never reach the filesystem.
func FuzzJVMOwner(f *testing.F) {
	f.Add("Name:\tjava\nUid:\t1001\t1001\t1001\t1001\n", "4242", "app")
	f.Add("Name:\tjava\nUid:\t0\t0\t0\t0\n", "4242", "root")
	f.Add("Name:\tjava\nUid:\t1001\t0\t1001\t1001\n", "4242", "app")
	f.Add("Name:\tpython3\nUid:\t1001\t1001\t1001\t1001\n", "4242", "app")
	f.Add("Name:\tjava\nUid:\t1001\t1001\t1001\t1001\nName:\tsh\n", "../4242", "app")
	f.Add("Name: java \nUid: 7 7 7 7\n", "7", "Bad;Name")
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, status, pid, name string) {
		if pidRE.MatchString(pid) {
			if err := os.MkdirAll(filepath.Join(dir, pid), 0o755); err != nil {
				return
			}
			if err := os.WriteFile(filepath.Join(dir, pid, "status"), []byte(status), 0o644); err != nil {
				return
			}
		}
		var gotUID string
		u, err := jvmOwner(dir, pid, func(uid string) (string, error) { gotUID = uid; return name, nil })
		if err != nil {
			return
		}
		if !pidRE.MatchString(pid) {
			t.Fatalf("bad pid %q accepted", pid)
		}
		if u != name || u == "root" || !userRE.MatchString(u) {
			t.Fatalf("owner %q", u)
		}
		var lastName string
		var lastUID []string
		for _, ln := range strings.Split(status, "\n") {
			k, v, ok := strings.Cut(ln, ":")
			if !ok {
				continue
			}
			switch k {
			case "Name":
				lastName = strings.TrimSpace(v)
			case "Uid":
				lastUID = strings.Fields(v)
			}
		}
		if lastName != "java" || len(lastUID) != 4 || gotUID == "0" || gotUID != lastUID[0] {
			t.Fatalf("accepted status %q (uid %q)", status, gotUID)
		}
		for _, x := range lastUID {
			if x != gotUID {
				t.Fatalf("mixed uids accepted %q", lastUID)
			}
		}
	})
}

// FuzzJavaUsers: only safe names, never root/botaudit, survive from /etc/auditsh/java-users.
func FuzzJavaUsers(f *testing.F) {
	f.Add("app\nroot\nbotaudit\n  svc-1 \nBad;Name\n")
	f.Add("")
	f.Add("a\r\nb\x00c\n-x\n_ok\n")
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content string) {
		p := filepath.Join(dir, "java-users")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := loadJavaUsers(p, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		for u := range m {
			if !userRE.MatchString(u) || u == "root" || u == "botaudit" || strings.HasPrefix(u, "-") {
				t.Fatalf("unsafe java user %q", u)
			}
		}
	})
}

// gateErrors are deploy/auditsh-jvm's argv-gate refusals. Anything else means the gate accepted
// the form and the script moved on to the /proc checks.
var gateErrors = []string{"usage:", "jcmd form not allowed", "jstat form not allowed", "bad interval", "bad count",
	"tool not allowed", "pid must be digits"}

// FuzzJVMHelperScript: differential fuzz of the shell helper's argv gate against the Go oracle.
// The helper never reaches exec here: no java process owned by the test user may exist (checked).
func FuzzJVMHelperScript(f *testing.F) {
	jvmDockerSeeds(f)
	if out, _ := exec.Command("pgrep", "-u", strconv.Itoa(os.Getuid()), "java").Output(); len(bytes.TrimSpace(out)) > 0 {
		f.Skip("a java process owned by this user exists; the helper could really attach")
	}
	if os.Getuid() == 0 {
		f.Skip("helper refuses root anyway; run unprivileged")
	}
	f.Fuzz(func(t *testing.T, raw string) {
		args := strings.Fields(raw)
		if len(args) > 8 {
			return
		}
		for _, a := range args {
			if strings.ContainsRune(a, 0) {
				return
			}
		}
		out, err := exec.Command("sh", append([]string{"deploy/auditsh-jvm"}, args...)...).CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 126 {
			t.Fatalf("%q: helper did not refuse (err %v): %q", args, err, out)
		}
		gateRefused := false
		for _, g := range gateErrors {
			if bytes.Contains(out, []byte(g)) {
				gateRefused = true
			}
		}
		if !gateRefused && !jvmFormOK(args) {
			t.Fatalf("helper gate passed non-form %q: %q", args, out)
		}
		if gateRefused && jvmFormOK(args) {
			t.Fatalf("helper gate refused documented form %q: %q", args, out)
		}
	})
}

// TestFuzzTargetsListed: every Fuzz* function in the repo is wired into `make fuzz`.
func TestFuzzTargetsListed(t *testing.T) {
	mk, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)
	err = filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		pkg := "./" + filepath.Dir(p)
		if pkg == "./." {
			pkg = "."
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			if !bytes.Contains(mk, []byte(pkg+":"+string(m[1]))) {
				t.Errorf("%s:%s not in Makefile FUZZ_TARGETS", pkg, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
