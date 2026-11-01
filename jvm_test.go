package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestJVMAllowed(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		"jcmd 4242 GC.heap_info", "jcmd 4242 VM.native_memory summary", "jcmd 4242 Thread.print",
		"jcmd 4242 VM.flags", "jcmd 4242 VM.uptime", "jcmd 4242 VM.version",
		"jstat -gcutil 4242", "jstat -gcutil 4242 1000 10", "jstat -gcutil 4242 250 3",
	} {
		if err := check(c, cmd); err != nil {
			t.Errorf("%q denied: %v", cmd, err)
		}
	}
}

func TestJVMDenied(t *testing.T) {
	c := defaultCfg(t)
	for _, cmd := range []string{
		"jcmd 4242 GC.heap_dump /tmp/x", "jcmd 4242 GC.heap_dump", "jcmd 4242 JFR.start", "jcmd 4242 JFR.dump filename=/tmp/x",
		"jcmd 4242 VM.command_line", "jcmd 4242 VM.system_properties", "jcmd 4242 VM.set_flag HeapDumpPath /tmp",
		"jcmd 4242 ManagementAgent.start", "jcmd 4242 Compiler.directives_add /x", "jcmd 4242 JVMTI.agent_load /x.so",
		"jcmd 4242 System.trim_native_heap", "jcmd 4242 help", "jcmd 4242 GC.class_histogram", // never offered (L-1)
		"jcmd 4242 GC.heap_info extra", "jcmd 4242 Thread.print -l", "jcmd 4242 VM.native_memory detail",
		"jcmd 4242 VM.native_memory summary.diff", "jcmd 4242 VM.native_memory baseline",
		"jcmd abc GC.heap_info", "jcmd 0 GC.heap_info", "jcmd 0123 GC.heap_info", "jcmd -1 GC.heap_info",
		"jcmd 12345678901 GC.heap_info", "jcmd self GC.heap_info", "jcmd org.app.Main GC.heap_info",
		"jcmd -l", "jcmd 4242", "jcmd GC.heap_info 4242", "jcmd -J-Dx=y 4242 GC.heap_info",
		"jstat -gcutil abc", "jstat -gcutil 4242 99 1", "jstat -gcutil 4242 1001 1", "jstat -gcutil 4242 1000 11",
		"jstat -gcutil 4242 1000 0", "jstat -gcutil 4242 1000", "jstat -gcutil 4242 1s 5", "jstat -gc 4242",
		"jstat -gcutil -t 4242", "jstat -J-Dx 4242", "jstat -gcutil 4242 500 5 extra",
	} {
		if err := check(c, cmd); err == nil {
			t.Errorf("%q allowed, want deny", cmd)
		}
	}
}

func TestJVMBadConfigs(t *testing.T) {
	for _, y := range []string{
		"commands:\n  - {name: jcmd, path: /x, jvm: true, sudo: true, args: ['[1-9][0-9]{0,9}', 'VM.flags']}\n",
		"commands:\n  - {name: java, path: /x, jvm: true, args: ['[1-9][0-9]{0,9}']}\n",
		"commands:\n  - {name: jcmd, path: 'internal:procread', jvm: true, args: ['[1-9][0-9]{0,9}']}\n",
		"commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['[0-9]+', 'VM.flags']}\n",
		"commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['VM.flags']}\n",
		// unescaped '.' is a regex wildcard: would admit "GC0heap_info" (FuzzJVMDockerAllowlist finding)
		"commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['[1-9][0-9]{0,9}', 'GC.heap_info']}\n",
		"commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['[1-9][0-9]{0,9}', 'VM\\.(flags|uptime)']}\n",
		"commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['VM\\.flags', '[1-9][0-9]{0,9}']}\n",
	} {
		if _, err := parseConfig([]byte(y)); err == nil {
			t.Errorf("accepted bad jvm config %q", y)
		}
	}
}

// fakeProc writes <dir>/<pid>/status.
func fakeProc(t *testing.T, pid, name, uid string) string {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, pid), 0o755)
	os.WriteFile(filepath.Join(d, pid, "status"), []byte("Name:\t"+name+"\nUmask:\t0022\nUid:\t"+uid+"\nGid:\t1000\t1000\t1000\t1000\n"), 0o644)
	return d
}

func TestJVMEscapedVerbOK(t *testing.T) {
	c, err := parseConfig([]byte("commands:\n  - {name: jcmd, path: /x, jvm: true, args: ['[1-9][0-9]{0,9}', 'GC\\.heap_info']}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a := c.Rules["jcmd"][0].Args[1]; a.literal != "GC.heap_info" || a.re.MatchString("GC0heap_info") {
		t.Fatalf("escaped verb not exact: %+v", a)
	}
}

func lookupFake(uid string) (string, error) {
	switch uid {
	case "1001":
		return "app", nil
	case "1002":
		return "Bad;Name", nil
	}
	return "", errors.New("unknown")
}

func TestJVMOwner(t *testing.T) {
	ok := fakeProc(t, "4242", "java", "1001\t1001\t1001\t1001")
	if u, err := jvmOwner(ok, "4242", lookupFake); err != nil || u != "app" {
		t.Fatalf("got %q %v", u, err)
	}
	for _, tc := range []struct{ dir, pid string }{
		{ok, "4243"}, // gone / hidepid
		{ok, "../4242"},
		{fakeProc(t, "4242", "python3", "1001\t1001\t1001\t1001"), "4242"},
		{fakeProc(t, "4242", "java", "0\t0\t0\t0"), "4242"},
		{fakeProc(t, "4242", "java", "1001\t0\t1001\t1001"), "4242"},
		{fakeProc(t, "4242", "java", "1003\t1003\t1003\t1003"), "4242"}, // no passwd entry
		{fakeProc(t, "4242", "java", "1002\t1002\t1002\t1002"), "4242"}, // unsafe name
	} {
		if u, err := jvmOwner(tc.dir, tc.pid, lookupFake); err == nil {
			t.Errorf("%s/%s accepted as %q", tc.dir, tc.pid, u)
		}
	}
}

func TestJVMSudoArgv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sudo")
	os.WriteFile(p, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\n"), 0o755)
	c := defaultCfg(t)
	proc := fakeProc(t, "4242", "java", "1001\t1001\t1001\t1001")
	ju := filepath.Join(t.TempDir(), "java-users")
	os.WriteFile(ju, []byte("app\n"), 0o644)
	o := runOpts{sudo: p, procDir: proc, lookupUser: lookupFake, javaUsers: ju}
	_, out, _, le := run(t, c, "jstat -gcutil 4242 500 5", o)
	if out != "-n|-u|app|--|/usr/local/sbin/auditsh-jvm|jstat|-gcutil|4242|500|5|" || le.Phase != "end" {
		t.Fatalf("sudo argv %q", out)
	}
	_, out, _, _ = run(t, c, "jcmd 4242 VM.native_memory summary", o)
	if out != "-n|-u|app|--|/usr/local/sbin/auditsh-jvm|jcmd|4242|VM.native_memory|summary|" {
		t.Fatalf("sudo argv %q", out)
	}
	// L-2: owner not in java-users, or java-users missing/empty: denied before sudo.
	for _, content := range []string{"other\n", "", "root\nbotaudit\n", "-"} {
		o2 := o
		o2.javaUsers = filepath.Join(t.TempDir(), "java-users")
		if content != "-" {
			os.WriteFile(o2.javaUsers, []byte(content), 0o644)
		}
		code, out, errs, le := run(t, c, "jcmd 4242 VM.flags", o2)
		if code != 126 || out != "" || !strings.Contains(errs, "auditsh: denied: ") || le.Decision != "deny" {
			t.Fatalf("java-users %q: code %d out %q err %q", content, code, out, errs)
		}
	}
	// Not a JVM / root JVM / missing pid: sudo is never run.
	for _, raw := range []string{"jcmd 4243 VM.flags", "jcmd 4242 VM.flags"} {
		o2 := o
		if raw == "jcmd 4242 VM.flags" {
			o2.procDir = fakeProc(t, "4242", "java", "0\t0\t0\t0")
		}
		code, out, _, le := run(t, c, raw, o2)
		if code != 126 || out != "" || le.Deny == "" {
			t.Fatalf("%q: code %d out %q deny %q", raw, code, out, le.Deny)
		}
	}
}

// The helper is the sudo policy gate: every malformed form must die before touching /proc.
func TestJVMHelperRejects(t *testing.T) {
	for _, args := range [][]string{
		{}, {"jcmd"}, {"jcmd", "1"}, {"java", "1", "VM.flags"}, {"sh", "-c", "id"},
		{"jcmd", "1", "GC.heap_dump", "/tmp/x"}, {"jcmd", "1", "GC.class_histogram"}, {"jcmd", "1", "GC.heap_dump"}, {"jcmd", "1", "JFR.start"},
		{"jcmd", "1", "VM.command_line"}, {"jcmd", "1", "VM.system_properties"}, {"jcmd", "1", "VM.set_flag", "x", "y"},
		{"jcmd", "1", "JVMTI.agent_load", "/x.so"}, {"jcmd", "1", "ManagementAgent.start"}, {"jcmd", "1", "VM.flags", "-all"},
		{"jcmd", "1", "GC.heap_info", "x"}, {"jcmd", "1", "VM.native_memory", "detail"},
		{"jcmd", "abc", "VM.flags"}, {"jcmd", "01", "VM.flags"}, {"jcmd", "-l", "VM.flags"}, {"jcmd", "1 2", "VM.flags"},
		{"jcmd", "12345678901", "VM.flags"}, {"jcmd", "", "VM.flags"},
		{"jstat", "-gc", "1"}, {"jstat", "-gcutil", "x"}, {"jstat", "-gcutil", "1", "99", "1"}, {"jstat", "-gcutil", "1", "1001", "1"},
		{"jstat", "-gcutil", "1", "500", "11"}, {"jstat", "-gcutil", "1", "500"}, {"jstat", "-gcutil", "1", "500", "5", "x"},
		{"jstat", "-gcutil", "1", "500", "05"},
		{"jcmd", "1", "VM.flags"}, // pid 1 is never ours (or we are root): refused
	} {
		cmd := exec.Command("sh", append([]string{"deploy/auditsh-jvm"}, args...)...)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 126 || !strings.HasPrefix(string(out), "auditsh-jvm: ") {
			t.Errorf("%q: err %v out %q", args, err, out)
		}
	}
}
