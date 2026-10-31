package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func defaultCfg(t testing.TB) *config {
	t.Helper()
	b, err := os.ReadFile("allowlist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func check(c *config, raw string) error {
	argv, err := parseCommand(raw)
	if err != nil {
		return err
	}
	_, err = c.match(argv)
	return err
}

func TestAllowed(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		"ps aux", "ps -eo pid,rss,comm", "ps -eo pid,%mem,comm --sort=-rss", "top -b -n1",
		"free", "free -m", "free -h", "cat /proc/meminfo", "cat /proc/1/status",
		"cat /proc/4242/smaps_rollup", "ss -tlnp", "ss -ulnp",
		"systemctl status nginx.service --no-pager", "systemctl status getty@tty1.service --no-pager",
		"journalctl -u nginx.service --since today --no-pager",
		"journalctl -u nginx.service --since '2 hours ago' --no-pager -n 100",
		"journalctl -u ssh.socket --since '2026-10-01 12:00:00' --no-pager",
		"df", "df -h", "uptime", "dmesg -T", "dmesg -T --level=err,warn",
	} {
		if err := check(c, cmd); err != nil {
			t.Errorf("%q denied: %v", cmd, err)
		}
	}
}

func TestSystemAuditAllowed(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		"who", "last -n 1", "last -n 50", "last -n 9999", "uname -a", "dpkg-query -l", "rpm -qa",
		"systemctl list-units --failed --no-pager", "systemctl list-timers --no-pager",
		"getent passwd", "getent group", "sshd -T", "crontab -l -u root", "nft list ruleset", "auditctl -l", "wtmpdb last -n 50", "iptables -L -n -v", "ip6tables -L -n -v",
	} {
		if err := check(c, cmd); err != nil {
			t.Errorf("%q denied: %v", cmd, err)
		}
	}
}

func TestDenied(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		"", "ps aux; reboot", "ps aux && reboot", "ps aux | sh", "ps `id`", "ps $(id)", "ps aux\nreboot",
		"ps aux\x00", "ps aux\r", "ps\taux", "cat /proc/*/status", "cat /proc/1/stat?s",
		"cat /proc/../etc/shadow", "cat /proc/self/../etc/shadow", "cat /proc/self/status",
		"cat /proc/1/environ", "cat /proc/1/root/etc/shadow", "cat /proc/1/cwd/x", "cat /proc/01/status",
		"cat /etc/shadow", "cat /proc/meminfo /etc/shadow", "cat 'proc/meminfo'",
		"ps\u00a0aux", "ps aux\u200b", "ｐｓ aux", "ps аux", // NBSP, ZWSP, fullwidth, cyrillic a
		"ps aux extra", "uptime -p", "free -m -h", "df -h /", "top -b -n1 -d0",
		"journalctl -u x.service --since today", "journalctl -u x.service --since today --no-pager --file=/etc/shadow",
		"journalctl --file=/etc/shadow", "journalctl -u x.service --since today --no-pager -f",
		"journalctl -u x.service --since today --no-pager -o export", "journalctl --vacuum-size=1",
		"journalctl -u -x.service --since today --no-pager", "journalctl -u x.service --since -1h --no-pager",
		"systemctl status -H host", "systemctl status x.service -H host --no-pager", "systemctl --no-pager status x; reboot",
		"systemctl status --no-pager", "systemctl status -x.service --no-pager", "systemctl stop x.service --no-pager",
		"systemctl status ../x.service --no-pager", "dmesg -c", "dmesg -C", "dmesg -T -c", "dmesg -D", "dmesg -n 1", "dmesg -E",
		"dmesg -T --level=debug", "ps -p 1 -o cmd", "ps -o cmd -p 1", "ps -eo cmd", "ps -eo pid,args", "ps -eo pid -- x",
		"ps -- aux", "ps --sort=-rss", "pmap -x 1", "ss -tlnpK", "ss -K", "less /etc/passwd", "vim", "bash", "sh -c id",
		"env LD_PRELOAD=x ps aux", "LD_PRELOAD=/tmp/x.so ps aux", "find / -exec sh ;", "awk 1", "xargs", "tee /x", "python3",
		"/usr/bin/ps aux", "ps '' aux", "ps \"aux\"x", "ps 'unterminated",
		strings.Repeat("a", 2000), "uptime" + strings.Repeat(" x", 20),
	} {
		if err := check(c, cmd); err == nil {
			t.Errorf("%q allowed, want deny", cmd)
		}
	}
}

func TestSystemAuditDenied(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		// extra / missing / reordered args
		"who am i", "who -a", "who /var/log/wtmp", "last", "last -n", "last -n 0", "last -n 10000", "last -n 05",
		"last -n -1", "last -n 10 -f /etc/shadow", "last -f /etc/shadow -n 10", "last root", "uname", "uname -a -r",
		"dpkg-query -l x", "dpkg-query -W", "dpkg -l", "rpm -qa x", "rpm -qal", "rpm -e x", "rpm --eval %(id)",
		"systemctl list-units --failed", "systemctl list-units --no-pager", "systemctl list-units --failed --no-pager -H h",
		"systemctl list-timers", "systemctl list-timers --no-pager --all", "systemctl --failed --no-pager",
		"getent", "getent shadow", "getent gshadow", "getent passwd root", "getent hosts x",
		"sshd", "sshd -T -f /etc/shadow", "sshd -T -C user=root", "sshd -t", "sshd -d",
		"crontab -l", "wtmpdb last", "wtmpdb last -n 0", "wtmpdb last -n 5 -f /tmp/x", "wtmpdb boot", "crontab -l -u botaudit", "crontab -e -u root", "crontab -r -u root", "crontab -u root -l",
		"crontab /tmp/x", "nft list ruleset -a", "nft flush ruleset", "nft -f /tmp/x", "nft list tables",
		"auditctl -l -k x", "auditctl -D", "auditctl -e 0", "auditctl -s",
		// pagers / exec
		"systemctl list-units --failed --pager", "systemctl list-timers --no-pager | less", "less", "more", "pager",
		"last -n 10 | less", "PAGER=less systemctl list-timers --no-pager",
		// shell metacharacters
		"who; id", "who && id", "uname -a | sh", "uname `id`", "uname $(id)", "last -n 1$(id)", "getent passwd>/tmp/x",
		"getent passwd </etc/shadow", "crontab -l -u root;id", "nft list ruleset & id", "auditctl -l\nid", "who\nid",
		"last -n {1..9}", "getent pass*", "getent passw?", "uname ~", "who #x", "sshd -T!",
	} {
		if err := check(c, cmd); err == nil {
			t.Errorf("%q allowed, want deny", cmd)
		}
	}
}

func TestDashRequiresLiteral(t *testing.T) {
	c, err := parseConfig([]byte("commands:\n  - {name: x, path: /bin/x, args: ['.*']}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"x -rf", "x --file=/etc/shadow", "x --"} {
		if check(c, a) == nil {
			t.Errorf("%q allowed by regex pattern", a)
		}
	}
	if check(c, "x ok") != nil {
		t.Error("plain arg denied")
	}
}

func TestBadConfigs(t *testing.T) {
	for _, y := range []string{
		"commands: []", "commands:\n  - {name: x, path: bin/x}", "commands:\n  - {name: x, path: /bin/../x}",
		"commands:\n  - {name: x, path: /bin/x, args: ['(']}", "commands:\n  - {name: x, path: /bin/x, bogus: 1}",
		"commands:\n  - {name: 'a;b', path: /bin/x}", "commands:\n  - {name: x, path: 'internal:procread', sudo: true}",
	} {
		if _, err := parseConfig([]byte(y)); err == nil {
			t.Errorf("config accepted: %q", y)
		}
	}
}

func TestConfigPerms(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := safeDir(t)
	os.Chmod(dir, 0o755)
	p := filepath.Join(dir, "a.yaml")
	os.WriteFile(p, []byte("commands:\n  - {name: uptime, path: /usr/bin/uptime}\n"), 0o644)
	os.Chmod(p, 0o644)
	if _, err := loadConfig(p, uid); err != nil {
		t.Fatalf("good perms refused: %v", err)
	}
	if _, err := loadConfig(p, uid+1); err == nil {
		t.Error("wrong owner accepted")
	}
	for _, m := range []os.FileMode{0o664, 0o646, 0o666} {
		os.Chmod(p, m)
		if _, err := loadConfig(p, uid); err == nil {
			t.Errorf("mode %v accepted", m)
		}
	}
	os.Chmod(p, 0o644)
	os.Chmod(dir, 0o777)
	if _, err := loadConfig(p, uid); err == nil {
		t.Error("world-writable dir accepted")
	}
	os.Chmod(dir, 0o755)
	tp := filepath.Join(t.TempDir(), "a.yaml") // parent chain includes /tmp (1777)
	os.WriteFile(tp, []byte("commands:\n  - {name: uptime, path: /usr/bin/uptime}\n"), 0o644)
	os.Chmod(filepath.Dir(tp), 0o755)
	if _, err := loadConfig(tp, uid); err == nil {
		t.Error("config under world-writable ancestor accepted")
	}
	l := filepath.Join(dir, "l.yaml")
	os.Symlink(p, l)
	if _, err := loadConfig(l, uid); err == nil {
		t.Error("symlinked config accepted")
	}
}

// fake writes an executable script and returns a one-rule config for it.
func fake(t *testing.T, body string) *config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake")
	os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	c, err := parseConfig([]byte("commands:\n  - {name: fake, path: " + p + ", args: []}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func run(t *testing.T, c *config, raw string, o runOpts) (int, string, string, logEntry) {
	t.Helper()
	code, out, errs, les := runAll(t, c, raw, o)
	return code, out, errs, les[len(les)-1]
}

// runAll returns every audit record written for one invocation.
func runAll(t *testing.T, c *config, raw string, o runOpts) (int, string, string, []logEntry) {
	t.Helper()
	var out, errb bytes.Buffer
	var lines []string
	if o.timeout == 0 {
		o.timeout = 5 * time.Second
	}
	if o.maxOutput == 0 {
		o.maxOutput = 1 << 20
	}
	code := serve(env{raw: raw, cfg: c, stdout: &out, stderr: &errb, opts: o, user: "botaudit",
		client: "192.0.2.1", logf: func(s string) error { lines = append(lines, s); return nil }})
	var les []logEntry
	for _, line := range lines {
		var le logEntry
		if err := json.Unmarshal([]byte(line), &le); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		les = append(les, le)
	}
	if len(les) == 0 {
		t.Fatal("no audit record")
	}
	return code, out.String(), errb.String(), les
}

// safeDir makes a temp dir under the repo (parents 0755) because /tmp is world-writable
// and would fail the parent-directory check.
func safeDir(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	d, err := os.MkdirTemp(wd, ".t")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestEnvNotPropagated(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("TERM", "xterm")
	t.Setenv("PAGER", "less")
	code, out, _, _ := run(t, fake(t, "env; read x && echo GOTSTDIN; exit 0"), "fake", runOpts{})
	if code != 0 {
		t.Fatal(code)
	}
	for _, bad := range []string{"LD_PRELOAD", "TERM=", "PAGER=less", "GOTSTDIN"} {
		if strings.Contains(out, bad) {
			t.Errorf("leaked %s:\n%s", bad, out)
		}
	}
	for _, want := range []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "PAGER=cat", "LESSSECURE=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestTimeoutKillsGroup(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	c := fake(t, "sleep 30 & echo $! > "+pidf+"; wait")
	start := time.Now()
	code, _, _, le := run(t, c, "fake", runOpts{timeout: 300 * time.Millisecond})
	if time.Since(start) > 3*time.Second || code == 0 || !le.TimedOut {
		t.Fatalf("timeout not enforced: code=%d %+v", code, le)
	}
	b, _ := os.ReadFile(pidf)
	time.Sleep(100 * time.Millisecond)
	if st, err := os.ReadFile("/proc/" + strings.TrimSpace(string(b)) + "/stat"); err == nil && !strings.Contains(string(st), ") Z") {
		t.Error("grandchild survived")
	}
}

func TestTruncation(t *testing.T) {
	code, out, errs, le := run(t, fake(t, "head -c 100000 /dev/zero; echo e >&2; sleep 10"), "fake", runOpts{maxOutput: 1000})
	_ = code
	if len(out) != 1000 || !le.Truncated || le.Bytes != 1000 || !strings.Contains(errs, "truncated") {
		t.Fatalf("len=%d %+v", len(out), le)
	}
	if le.DurationMS > 3000 {
		t.Error("process not stopped after cap")
	}
}

func TestLogging(t *testing.T) {
	c := fake(t, "echo hi; exit 3")
	code, out, _, le := run(t, c, "fake", runOpts{})
	if code != 3 || out != "hi\n" || le.Decision != "allow" || le.Exit != 3 || le.Bytes != 3 || le.Rule != "fake#0" || le.Client != "192.0.2.1" {
		t.Fatalf("%d %q %+v", code, out, le)
	}
	code, _, _, le = run(t, c, "fake; reboot\n\x01", runOpts{})
	if code == 0 || le.Decision != "deny" || le.Deny == "" || strings.ContainsAny(le.Command, "\n\x01") {
		t.Fatalf("%+v", le)
	}
	_, _, errs, le := run(t, c, "", runOpts{})
	if le.Decision != "deny" || !strings.Contains(errs, "fake") {
		t.Fatal("empty command must deny and list commands")
	}
	_, _, _, le = run(t, c, strings.Repeat("x", 5000), runOpts{})
	if len(le.Command) > maxLogCmd+20 {
		t.Error("log raw not capped")
	}
}

func TestLogFailureFailsClosed(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	var out, errb bytes.Buffer
	code := serve(env{raw: "fake", cfg: fake(t, "touch "+marker+"; echo hi"), stdout: &out, stderr: &errb,
		opts: runOpts{timeout: time.Second, maxOutput: 100}, logf: func(string) error { return os.ErrClosed }})
	if code != 125 || out.Len() != 0 {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command executed although start record failed")
	}
}

func TestStartEndRecords(t *testing.T) {
	_, _, _, les := runAll(t, fake(t, "echo hi"), "fake", runOpts{})
	if len(les) != 2 || les[0].Phase != "start" || les[1].Phase != "end" || les[0].Rule != "fake#0" || les[1].Bytes != 3 {
		t.Fatalf("%+v", les)
	}
	// killed midway by timeout: start then end with timed_out and a kill exit code
	_, _, _, les = runAll(t, fake(t, "echo partial; sleep 30"), "fake", runOpts{timeout: 300 * time.Millisecond})
	if len(les) != 2 || les[0].Phase != "start" || les[1].Phase != "end" || !les[1].TimedOut || les[1].Exit == 0 || les[1].Bytes != 8 {
		t.Fatalf("%+v", les)
	}
	_, _, _, les = runAll(t, fake(t, "echo x"), "fake; id", runOpts{})
	if len(les) != 1 || les[0].Phase != "deny" {
		t.Fatalf("%+v", les)
	}
}

func TestWaitDelaySetsidPipeHolder(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	c := fake(t, "setsid sh -c 'echo $$ > "+pidf+"; exec sleep 40' & sleep 40")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidf); err == nil {
			var pid int
			fmt.Sscan(string(b), &pid)
			if pid > 1 {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	to := 300 * time.Millisecond
	start := time.Now()
	_, _, _, le := run(t, c, "fake", runOpts{timeout: to})
	if d := time.Since(start); d > to+waitDelay+time.Second {
		t.Fatalf("returned after %v", d)
	}
	if !le.TimedOut || le.Phase != "end" {
		t.Fatalf("%+v", le)
	}
}

func TestResolveCommand(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		orig    string
		origSet bool
		want    string
		ok      bool
	}{
		{[]string{"-c", selfPath}, "uptime", true, "uptime", true},
		{[]string{"-c", selfPath}, "", false, "", true}, // -> empty -> deny with list
		{[]string{"-c", "uptime"}, "", false, "uptime", true},
		{[]string{"-c", "uptime"}, "uptime", true, "uptime", true},
		{[]string{"-c", "uptime"}, "free", true, "", false},
		{nil, "uptime", true, "", false},
		{[]string{"-c"}, "", false, "", false},
		{[]string{"-c", "uptime", "x"}, "", false, "", false},
		{[]string{"-l"}, "", false, "", false},
		{[]string{"-i", "uptime"}, "", false, "", false},
	} {
		got, err := resolveCommand(tc.args, tc.orig, tc.origSet)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%v: got %q err=%v", tc.args, got, err)
		}
	}
	var b bytes.Buffer
	var line string
	code := serve(env{invErr: fmt.Errorf("bad invocation"), stdout: &b, stderr: &b, logf: func(s string) error { line = s; return nil }})
	if code == 0 || !strings.Contains(line, `"phase":"deny"`) {
		t.Fatal("bad invocation must deny and log")
	}
}

func TestCheckTree(t *testing.T) {
	if err := checkTree("/usr/bin/env", 0); err != nil {
		t.Errorf("root-owned binary refused: %v", err)
	}
	d := safeDir(t)
	p := filepath.Join(d, "bin")
	os.WriteFile(p, []byte("x"), 0o755)
	if err := checkTree(p, 0); err == nil {
		t.Error("non-root binary/parents accepted")
	}
	if err := checkTree("/usr/bin/../bin/env", 0); err == nil {
		t.Error("unclean path accepted")
	}
	w := filepath.Join(d, "w")
	os.Mkdir(w, 0o755)
	os.Chmod(w, 0o777)
	os.WriteFile(filepath.Join(w, "b"), []byte("x"), 0o755)
	if err := checkTree(filepath.Join(w, "b"), uint32(os.Getuid())); err == nil {
		t.Error("world-writable parent accepted")
	}
}

func TestLogEscapesNonASCII(t *testing.T) {
	_, _, _, le := run(t, fake(t, "true"), "uptime é\u202e", runOpts{})
	for _, r := range le.Command {
		if r > 0x7e {
			t.Fatalf("non-ASCII in log: %q", le.Command)
		}
	}
}

func TestConfigErrorDenies(t *testing.T) {
	code, _, _, le := func() (int, string, string, logEntry) {
		var b bytes.Buffer
		var line string
		code := serve(env{cfgErr: os.ErrPermission, raw: "uptime", stdout: &b, stderr: &b, logf: func(s string) error { line = s; return nil }})
		var le logEntry
		json.Unmarshal([]byte(line), &le)
		return code, "", "", le
	}()
	if code == 0 || le.Decision != "deny" {
		t.Fatal("config error must deny")
	}
}

func TestSudoArgv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sudo")
	os.WriteFile(p, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\n"), 0o755)
	c, _ := parseConfig([]byte("commands:\n  - {name: ss, path: /usr/bin/ss, sudo: true, args: ['-tlnp']}\n"))
	_, out, _, _ := run(t, c, "ss -tlnp", runOpts{sudo: p})
	if out != "-n|--|/usr/bin/ss|-tlnp|" {
		t.Fatalf("sudo argv %q", out)
	}
}

func TestBinaryOwnerCheck(t *testing.T) {
	c := fake(t, "echo hi")
	code, out, _, _ := run(t, c, "fake", runOpts{checkBin: true, binOwnerUID: uint32(os.Getuid()) + 1})
	if code != 126 || out != "" {
		t.Fatal("binary with wrong owner executed")
	}
}

func TestProcRead(t *testing.T) {
	var b bytes.Buffer
	if err := procRead("/proc/meminfo", &b); err != nil || !strings.Contains(b.String(), "MemTotal") {
		t.Fatal(err)
	}
	for _, p := range []string{"/proc/self/status", "/proc/1/environ", "/etc/shadow", "/proc/1/../../etc/shadow", "/proc/meminfo/"} {
		if procRead(p, &b) == nil {
			t.Errorf("%s readable", p)
		}
	}
	for _, p := range []string{"/etc/shadow", "/etc/gshadow", "/x/server.key", "/app/.env", "/root", "/root/x", "/etc/ssh/ssh_host_ed25519_key"} {
		if !blockedPath(p) {
			t.Errorf("%s not blocked", p)
		}
	}
}

func TestKeyFingerprint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth")
	os.WriteFile(p, []byte("publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n"), 0o600)
	if fp := keyFingerprint(p); !strings.HasPrefix(fp, "SHA256:") {
		t.Fatal(fp)
	}
	if keyFingerprint("") != "" || keyFingerprint("rel") != "" {
		t.Fatal("bad path accepted")
	}
}

func TestNoKeyFPDenied(t *testing.T) {
	for _, fp := range []string{"", "SHA256:x"} {
		marker := filepath.Join(t.TempDir(), "ran")
		var out, errb bytes.Buffer
		var lines []string
		code := serve(env{raw: "fake", cfg: fake(t, "touch "+marker), stdout: &out, stderr: &errb,
			sshConn: "192.0.2.1 5555 192.0.2.2 22", keyFP: fp,
			opts: runOpts{timeout: time.Second, maxOutput: 100},
			logf: func(s string) error { lines = append(lines, s); return nil }})
		_, err := os.Stat(marker)
		if fp == "" {
			if code != 126 || err == nil || len(lines) != 1 || !strings.Contains(lines[0], `"reason":"no key_fp"`) {
				t.Fatalf("missing key_fp not denied: code=%d lines=%v", code, lines)
			}
		} else if code != 0 || err != nil {
			t.Fatalf("valid key_fp denied: %d %v", code, lines)
		}
	}
	// unreadable / unparseable ExposeAuthInfo yields "" and therefore a deny
	p := filepath.Join(t.TempDir(), "auth")
	os.WriteFile(p, []byte("publickey ssh-ed25519 !!notbase64!!\n"), 0o600)
	if keyFingerprint(p) != "" || keyFingerprint(filepath.Join(t.TempDir(), "gone")) != "" {
		t.Fatal("bad auth info produced a fingerprint")
	}
}

// Output that exactly fills the cap and then continues must be marked truncated and the
// command stopped (previously the overflow write was silently dropped and it ran to timeout).
func TestCapExactBoundary(t *testing.T) {
	start := time.Now()
	_, out, errs, le := run(t, fake(t, "head -c 1000 /dev/zero; sleep 0.2; echo more; sleep 10"), "fake",
		runOpts{maxOutput: 1000, timeout: 5 * time.Second})
	if len(out) != 1000 || le.Bytes != 1000 || !le.Truncated || !strings.Contains(errs, "truncated") {
		t.Fatalf("len=%d %+v", len(out), le)
	}
	if le.TimedOut || time.Since(start) > 3*time.Second {
		t.Fatalf("command not killed at cap: %+v", le)
	}
	// exactly at the cap with nothing more is NOT truncated
	_, out, _, le = run(t, fake(t, "head -c 1000 /dev/zero"), "fake", runOpts{maxOutput: 1000})
	if len(out) != 1000 || le.Truncated {
		t.Fatalf("exact-fit output marked truncated: %+v", le)
	}
}

func TestLogEscapesDELAndC1(t *testing.T) {
	s := encodeLog(logEntry{User: "a\x7fb\u0085c\u009bd\u0080", SSHConn: "\u2028"})
	for _, r := range s {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 {
			t.Fatalf("unescaped %U in %q", r, s)
		}
	}
	var le logEntry
	if err := json.Unmarshal([]byte(s), &le); err != nil || le.User != "a\x7fb\u0085c\u009bd\u0080" {
		t.Fatalf("roundtrip: %v %q", err, le.User)
	}
	// through serve(): a DEL/C1 in the SSH_CONNECTION-derived field reaches syslog escaped
	var line string
	var b bytes.Buffer
	serve(env{raw: "x", cfg: fake(t, "true"), stdout: &b, stderr: &b, user: "u\x7f\u009b", logf: func(s string) error { line = s; return nil }})
	if strings.ContainsAny(line, "\x7f\u009b") {
		t.Fatalf("raw DEL/C1 in log line %q", line)
	}
}

// Every sudo rule in allowlist.yaml must have an exact fixed-argv NOEXEC grant in
// deploy/sudoers.botaudit, and every sudoers grant must correspond to a sudo rule.
func TestSudoersMatchesAllowlist(t *testing.T) {
	b, err := os.ReadFile("deploy/sudoers.botaudit")
	if err != nil {
		t.Fatal(err)
	}
	grants := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		const pfx = "botaudit ALL=(root) NOPASSWD: NOEXEC: "
		if !strings.HasPrefix(ln, "botaudit ") {
			continue
		}
		if !strings.HasPrefix(ln, pfx) {
			t.Errorf("sudoers grant without NOPASSWD: NOEXEC: %q", ln)
			continue
		}
		for _, g := range strings.Split(strings.ReplaceAll(ln[len(pfx):], "\\,", "\x00"), ", ") {
			g = strings.ReplaceAll(g, "\x00", ",")
			if strings.ContainsAny(strings.TrimSuffix(g, ` ""`), "*?[]^$\"") {
				t.Errorf("sudoers wildcard/regex in %q", g)
			}
			grants[g] = true
		}
	}
	c := defaultCfg(t)
	want := map[string]bool{}
	for _, n := range c.Order {
		for _, r := range c.Rules[n] {
			if !r.Sudo {
				continue
			}
			parts := []string{r.Path}
			for _, a := range r.Args {
				if a.literal == "" {
					t.Errorf("%s: sudo rule with non-literal arg", r.ID)
				}
				parts = append(parts, a.literal)
			}
			if len(r.Args) == 0 {
				parts = append(parts, `""`) // sudoers: no args; a bare path would allow any args
			}
			g := strings.Join(parts, " ")
			want[g] = true
			if !grants[g] {
				t.Errorf("%s: no sudoers grant for %q", r.ID, g)
			}
		}
	}
	for g := range grants {
		if !want[g] {
			t.Errorf("sudoers grant %q has no allowlist rule", g)
		}
	}
}
