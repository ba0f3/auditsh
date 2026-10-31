package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIptablesOSAllowed(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{"iptables -S", "iptables-save", "ip6tables -S", "ip6tables-save",
		"cat /etc/os-release", "cat /etc/redhat-release", "cat /etc/debian_version", "cat /etc/lsb-release", "lsb_release -a"} {
		if err := check(c, cmd); err != nil {
			t.Errorf("%q denied: %v", cmd, err)
		}
	}
}

func TestIptablesOSDenied(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{"iptables", "iptables -L", "iptables -S INPUT", "iptables -F", "iptables -S -t nat",
		"iptables -A INPUT -j ACCEPT", "iptables-save -t nat", "iptables-save -f /tmp/x", "iptables-save > /tmp/x",
		"iptables-restore", "ip6tables -F", "ip6tables-save -c", "xtables-nft-multi iptables -F", "iptables-legacy -S",
		"cat /etc/shadow", "cat /etc/os-release /etc/shadow", "cat /usr/lib/os-release", "cat /etc/../etc/os-release",
		"cat /etc/os-release*", "cat /etc/rocky-release", "cat /etc/issue", "lsb_release", "lsb_release -a -s", "lsb_release -c"} {
		if err := check(c, cmd); err == nil {
			t.Errorf("%q allowed, want deny", cmd)
		}
	}
}

func TestResolveBadConfigs(t *testing.T) {
	for _, y := range []string{
		"commands:\n  - {name: cat, path: 'internal:fileread', args: ['/etc/shadow']}\n",
		"commands:\n  - {name: cat, path: 'internal:fileread', args: ['/etc/os-release', '/etc/lsb-release']}\n",
		"commands:\n  - {name: cat, path: 'internal:fileread', args: ['/etc/(os|lsb)-release']}\n",
		"commands:\n  - {name: cat, path: 'internal:fileread', sudo: true, args: ['/etc/os-release']}\n",
		"commands:\n  - {name: cat, path: 'internal:fileread', resolve: true, args: ['/etc/os-release']}\n",
		"commands:\n  - {name: cat, path: 'internal:procread', resolve: true, args: ['/proc/meminfo']}\n",
		"commands:\n  - {name: jcmd, path: /usr/local/sbin/auditsh-jvm, jvm: true, resolve: true, args: ['[1-9][0-9]{0,9}', 'VM.uptime']}\n",
	} {
		if _, err := parseConfig([]byte(y)); err == nil {
			t.Errorf("accepted: %s", y)
		}
	}
}

// chain builds links in a safe (uid-owned, 0755) dir; ownerUID = our uid stands in for root.
func TestCheckChain(t *testing.T) {
	uid := uint32(os.Getuid())
	d := safeDir(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	sb, alt := filepath.Join(d, "sbin"), filepath.Join(d, "alt")
	must(os.Mkdir(sb, 0o755))
	must(os.Mkdir(alt, 0o755))
	multi := filepath.Join(sb, "xtables-nft-multi")
	must(os.WriteFile(multi, []byte("#!/bin/sh\n"), 0o755))
	must(os.Symlink("xtables-nft-multi", filepath.Join(sb, "iptables-nft")))
	must(os.Symlink(filepath.Join(sb, "iptables-nft"), filepath.Join(alt, "iptables")))
	must(os.Symlink(filepath.Join(alt, "iptables"), filepath.Join(sb, "iptables")))
	if got, err := checkChain(filepath.Join(sb, "iptables"), uid); err != nil || got != multi {
		t.Fatalf("good chain: %q %v", got, err)
	}
	if _, err := checkChain(multi, uid); err != nil {
		t.Errorf("plain file: %v", err)
	}
	if _, err := checkChain(filepath.Join(sb, "iptables"), 0); err == nil {
		t.Error("chain not owned by uid 0 accepted")
	}
	// user/world-writable target
	w := filepath.Join(d, "w")
	must(os.Mkdir(w, 0o755))
	must(os.WriteFile(filepath.Join(w, "evil"), []byte("x"), 0o755))
	must(os.Chmod(filepath.Join(w, "evil"), 0o757))
	must(os.Symlink(filepath.Join(w, "evil"), filepath.Join(sb, "a")))
	// target in a world-writable directory
	ww := filepath.Join(d, "ww")
	must(os.Mkdir(ww, 0o755))
	must(os.Chmod(ww, 0o777))
	must(os.WriteFile(filepath.Join(ww, "t"), []byte("x"), 0o755))
	must(os.Symlink(filepath.Join(ww, "t"), filepath.Join(sb, "b")))
	// link that lives in a world-writable directory
	must(os.Symlink(multi, filepath.Join(ww, "l")))
	must(os.Symlink(filepath.Join(ww, "l"), filepath.Join(sb, "c")))
	// loop, dangling, symlinked directory on the way, directory target, too long
	must(os.Symlink("loop2", filepath.Join(sb, "loop1")))
	must(os.Symlink("loop1", filepath.Join(sb, "loop2")))
	must(os.Symlink("nothere", filepath.Join(sb, "dangling")))
	must(os.Symlink(sb, filepath.Join(d, "sbinlink")))
	must(os.Symlink(filepath.Join(d, "sbinlink", "xtables-nft-multi"), filepath.Join(sb, "viadir")))
	must(os.Symlink(alt, filepath.Join(sb, "dir")))
	prev := "xtables-nft-multi"
	for i := 0; i < maxLinkHops+1; i++ {
		n := "h" + strings.Repeat("x", i)
		must(os.Symlink(prev, filepath.Join(sb, n)))
		prev = n
	}
	for _, n := range []string{"a", "b", "c", "loop1", "dangling", "viadir", "dir", prev} {
		if got, err := checkChain(filepath.Join(sb, n), uid); err == nil {
			t.Errorf("%s accepted -> %s", n, got)
		}
	}
	for _, p := range []string{"rel/iptables", sb + "/../sbin/iptables", sb + "/"} {
		if _, err := checkChain(p, uid); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if _, err := checkChain("/nonexistent/iptables", 0); err == nil {
		t.Error("missing binary accepted")
	}
}

func TestOSFileRead(t *testing.T) {
	var b bytes.Buffer
	for _, p := range []string{"/etc/shadow", "/etc/passwd", "/usr/lib/os-release", "/etc/os-release/", "/etc//os-release", "/proc/meminfo", ""} {
		if osFileRead(p, &b, 0) == nil {
			t.Errorf("%q readable", p)
		}
	}
	if b.Len() != 0 {
		t.Fatal("denied reads produced output")
	}
	if _, err := os.Stat("/etc/os-release"); err == nil {
		if err := osFileRead("/etc/os-release", &b, 0); err != nil || !strings.Contains(b.String(), "ID=") {
			t.Fatalf("os-release: %v %q", err, b.String())
		}
	}
	for _, tg := range []string{"/usr/lib/os-release", "/etc/rocky-release", "/etc/centos-release", "/etc/debian_version"} {
		if !osTargetRE.MatchString(tg) {
			t.Errorf("target %s refused", tg)
		}
	}
	for _, tg := range []string{"/etc/shadow", "/tmp/os-release", "/etc/ssh/x-release", "/home/u/os-release", "/usr/lib/../../etc/shadow-release", "/etc/passwd"} {
		if osTargetRE.MatchString(tg) {
			t.Errorf("target %s accepted", tg)
		}
	}
}

func FuzzCheckChain(f *testing.F) {
	d := f.TempDir()
	for _, s := range []string{"xtables-nft-multi", "../x", "/etc/shadow", "a/b", "", "loop"} {
		f.Add(s)
	}
	uid := uint32(os.Getuid())
	f.Fuzz(func(t *testing.T, target string) {
		// Any link the fuzzer builds lives under /tmp (1777): checkChain must never accept it.
		p := filepath.Join(d, "l")
		os.Remove(p)
		if os.Symlink(target, p) != nil {
			return
		}
		if got, err := checkChain(p, uid); err == nil {
			t.Fatalf("accepted %q -> %q", target, got)
		}
	})
}
