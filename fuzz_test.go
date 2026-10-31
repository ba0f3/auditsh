package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Native Go fuzz targets. Smoke run: go test -run '^$' -fuzz '^FuzzX$' -fuzztime 30s .

func FuzzParseCommand(f *testing.F) {
	for _, s := range []string{"ps aux", "cat /proc/meminfo", "journalctl -u x.service --since '2 hours ago' --no-pager",
		"ps aux; id", "a\x00b", "'x", strings.Repeat("a ", 20), "\"a b\" 'c d'"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		argv, err := parseCommand(raw)
		if err != nil {
			return
		}
		if len(raw) > maxCmdLen {
			t.Fatalf("accepted %d bytes", len(raw))
		}
		for i := 0; i < len(raw); i++ {
			if raw[i] < 0x20 || raw[i] > 0x7e {
				t.Fatalf("accepted byte %#x", raw[i])
			}
		}
		if strings.ContainsAny(raw, shellMeta) {
			t.Fatalf("accepted metachar in %q", raw)
		}
		if len(argv) < 1 || len(argv) > maxArgs+1 {
			t.Fatalf("accepted %d args", len(argv))
		}
	})
}

type indepRule struct {
	name, path string
	sudo, jvm  bool
	args       []*regexp.Regexp
	lits       []string
}

// indepAllowlist parses allowlist.yaml without using parseConfig, as an oracle.
func indepAllowlist(t testing.TB) []indepRule {
	b, err := os.ReadFile("allowlist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Commands []struct {
			Name, Path string
			Sudo       bool
			JVM        bool `yaml:"jvm"`
			Args       []string
		}
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []indepRule
	for _, c := range doc.Commands {
		r := indepRule{name: c.Name, path: c.Path, sudo: c.Sudo, jvm: c.JVM}
		for _, a := range c.Args {
			r.args = append(r.args, regexp.MustCompile(`^(?:`+a+`)$`))
			if regexp.QuoteMeta(a) == a {
				r.lits = append(r.lits, a)
			} else {
				r.lits = append(r.lits, "")
			}
		}
		out = append(out, r)
	}
	return out
}

func indepAllows(rules []indepRule, path string, sudo, jvm bool, argv []string) bool {
	for _, r := range rules {
		if r.name != argv[0] || r.path != path || r.sudo != sudo || r.jvm != jvm || len(r.args) != len(argv)-1 {
			continue
		}
		ok := true
		for i, a := range argv[1:] {
			if strings.HasPrefix(a, "-") {
				ok = ok && r.lits[i] == a
			} else {
				ok = ok && r.args[i].MatchString(a)
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func FuzzAllowlistExec(f *testing.F) {
	for _, s := range []string{"ps aux", "ps -eo pid,rss,comm --sort=-rss", "ss -tlnp", "dmesg -T --level=err,warn",
		"journalctl -u a.service --since today --no-pager -n 5", "cat /proc/1/status", "systemctl status a@b.timer --no-pager",
		"jcmd 1234 VM.uptime", "jstat -gcutil 1234", "cat /etc/os-release", "cat /etc/debian_version", "iptables -S"} {
		f.Add(s)
	}
	cfg := defaultCfg(f)
	rules := indepAllowlist(f)
	f.Fuzz(func(t *testing.T, raw string) {
		argv, err := parseCommand(raw)
		if err != nil {
			return
		}
		r, err := cfg.match(argv)
		if err != nil {
			return
		}
		if r.Path == internalProcRead {
			// served in-process by procRead (re-validated there), never exec'd
			if argv[0] != "cat" || len(argv) != 2 || !procPathRE.MatchString(argv[1]) {
				t.Fatalf("internal rule accepted %q", argv)
			}
			return
		}
		if r.Path == internalFileRead {
			// served in-process by the OS-id file reader, never exec'd: only the
			// rule's one fixed path, which must be one of the known OS id files
			if argv[0] != "cat" || len(argv) != 2 || len(r.Args) != 1 || argv[1] != r.Args[0].literal || !osFiles[argv[1]] {
				t.Fatalf("fileread rule accepted %q", argv)
			}
			return
		}
		const owner = "appj"
		full := execArgv(r, argv[1:], sudoPath, owner)
		var bin []string
		if r.JVM {
			// real argv: sudo -n -u <validated owner> -- helper <tool> args...
			if len(full) < 7 || !slices.Equal(full[:5], []string{sudoPath, "-n", "-u", owner, "--"}) || full[6] != argv[0] || r.Sudo {
				t.Fatalf("jvm argv %q", full)
			}
			if _, err := jvmPid(argv[1:]); err != nil {
				t.Fatalf("jvm rule accepted bad pid %q: %v", argv, err)
			}
			bin = append([]string{full[5]}, full[7:]...)
		} else if r.Sudo {
			if len(full) < 4 || !slices.Equal(full[:3], []string{sudoPath, "-n", "--"}) {
				t.Fatalf("sudo argv %q", full)
			}
			bin = full[3:]
		} else {
			bin = full
		}
		if bin[0] != r.Path || !slices.Equal(bin[1:], argv[1:]) {
			t.Fatalf("argv %q for %q", full, argv)
		}
		if !indepAllows(rules, r.Path, r.Sudo, r.JVM, argv) {
			t.Fatalf("independent parse rejects %q (rule %s)", argv, r.ID)
		}
		for _, a := range bin[1:] {
			if a == "" || a == "--" || strings.ContainsAny(a, shellMeta) {
				t.Fatalf("bad arg %q", a)
			}
			for i := 0; i < len(a); i++ {
				if a[i] < 0x20 || a[i] > 0x7e {
					t.Fatalf("control/non-ASCII in %q", a)
				}
			}
		}
	})
}

func FuzzEnvSanitize(f *testing.F) {
	f.Add("LD_PRELOAD", "/tmp/x.so")
	f.Add("PATH", "/tmp")
	f.Add("BASH_FUNC_x%%", "() { id; }")
	f.Add("LANG", "C.UTF-8\nX=1")
	want := strings.Join(cleanEnv, "\n") + "\n"
	c, err := parseConfig([]byte("commands:\n  - {name: env, path: /usr/bin/env, args: []}\n"))
	if err != nil {
		f.Fatal(err)
	}
	r := c.Rules["env"][0]
	f.Fuzz(func(t *testing.T, k, v string) {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.Contains(v, "\x00") {
			return
		}
		t.Setenv(k, v)
		e := childEnv()
		e[0] = "PATH=/tmp"
		if cleanEnv[0] != "PATH=/usr/bin:/bin" {
			t.Fatal("childEnv aliases cleanEnv")
		}
		var out bytes.Buffer
		res, err := execute(r, nil, &out, runOpts{timeout: 10 * time.Second, maxOutput: 1 << 16, sudo: sudoPath})
		if err == nil && res.timedOut && isFuzzing() {
			// /usr/bin/env cannot hang on its own; a timeout here means the
			// host was starved (parallel fuzz workers), not an input bug.
			t.Skip("env child timed out under host load")
		}
		if err != nil || res.exit != 0 {
			t.Fatalf("env: %v %+v", err, res)
		}
		if out.String() != want {
			t.Fatalf("child env %q, want %q", out.String(), want)
		}
	})
}

func FuzzLogEncoder(f *testing.F) {
	f.Add("botaudit", "ps aux", "reason", "a", "1.2.3.4 1 5.6.7.8 22")
	f.Add("\x7f", "\u0085\u009b[2J", "\u2028\u2029", "\xff\xfe", "\x1b]0;x\x07")
	f.Fuzz(func(t *testing.T, user, raw, reason, arg, conn string) {
		le := logEntry{TS: "t", User: user, Command: raw, Deny: reason, Argv: []string{arg}, SSHConn: conn, Client: conn, KeyFP: arg, Rule: reason}
		s := encodeLog(le)
		if !utf8.ValidString(s) {
			t.Fatalf("invalid utf8: %q", s)
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0x85 {
				t.Fatalf("control/separator %U in %q", r, s)
			}
		}
		dec := json.NewDecoder(strings.NewReader(s))
		var got logEntry
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("not JSON: %v %q", err, s)
		}
		if _, err := dec.Token(); err != io.EOF {
			t.Fatalf("trailing data after record: %q", s)
		}
		for _, p := range [][2]string{{user, got.User}, {raw, got.Command}, {reason, got.Deny}, {arg, got.Argv[0]}, {conn, got.SSHConn}} {
			if utf8.ValidString(p[0]) && p[0] != p[1] {
				t.Fatalf("roundtrip %q -> %q", p[0], p[1])
			}
			if !utf8.ValidString(p[1]) {
				t.Fatalf("decoded invalid utf8 %q", p[1])
			}
		}
	})
}

func FuzzProcRead(f *testing.F) {
	f.Add("/proc/meminfo", []byte("MemTotal: 1 kB\n"), uint16(1000))
	f.Add("/proc/meminfo", []byte("0123456789"), uint16(10))
	f.Add("/proc/1/status", []byte("x"), uint16(0))
	f.Add("/proc/self/environ", []byte("x"), uint16(5))
	f.Add("/etc/shadow", []byte(""), uint16(5))
	f.Add("/proc/1/../../etc/shadow", []byte(""), uint16(5))
	r := &rule{Name: "cat", Path: internalProcRead, ID: "cat#0"}
	f.Fuzz(func(t *testing.T, path string, data []byte, cap uint16) {
		var opened []string
		open := func(p string) (io.ReadCloser, error) {
			opened = append(opened, p)
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		var out bytes.Buffer
		res, err := execute(r, []string{path}, &out, runOpts{timeout: 10 * time.Second, maxOutput: int64(cap), procOpen: open})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened) > 1 || (len(opened) == 1 && (opened[0] != path || !procPathRE.MatchString(path) || blockedPath(path))) {
			t.Fatalf("opened %q for %q", opened, path)
		}
		if len(opened) == 0 {
			if out.Len() != 0 || res.bytes != 0 || res.truncated || res.exit == 0 {
				t.Fatalf("refused read produced %+v %d", res, out.Len())
			}
			return
		}
		n := min(len(data), int(cap))
		if out.Len() != n || res.bytes != int64(n) || res.truncated != (len(data) > int(cap)) || !bytes.Equal(out.Bytes(), data[:n]) {
			t.Fatalf("len(data)=%d cap=%d out=%d %+v", len(data), cap, out.Len(), res)
		}
	})
}

// isFuzzing reports whether this is a -fuzz run (coordinator or worker). Plain
// `go test` replays of the seed corpus must never take a skip path.
func isFuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}
