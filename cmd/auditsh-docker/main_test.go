package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// tree returns a checker anchored at a fresh 0755 temp dir owned by the test user.
func tree(t *testing.T) (fsCheck, string) {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return fsCheck{uid: uint32(os.Getuid()), top: d}, d
}

func TestPluginDirs(t *testing.T) {
	c, d := tree(t)
	a, b := filepath.Join(d, "libexec", "cli-plugins"), filepath.Join(d, "local", "cli-plugins")
	if err := c.plugins([]string{a, b}); err != nil {
		t.Fatalf("absent dirs must pass: %v", err)
	}
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Dir(p), 0o755)
	}
	os.WriteFile(filepath.Join(a, "docker-compose"), []byte("x"), 0o755)
	os.WriteFile(filepath.Join(b, "docker-buildx"), []byte("x"), 0o755)
	if err := c.plugins([]string{a, b}); err != nil {
		t.Fatalf("safe dirs refused: %v", err)
	}
	bad := []struct {
		name  string
		setup func() func()
	}{
		{"world-writable dir", func() func() { os.Chmod(a, 0o777); return func() { os.Chmod(a, 0o755) } }},
		{"group-writable dir", func() func() { os.Chmod(b, 0o775); return func() { os.Chmod(b, 0o755) } }},
		{"writable parent", func() func() {
			p := filepath.Dir(a)
			os.Chmod(p, 0o757)
			return func() { os.Chmod(p, 0o755) }
		}},
		{"writable plugin", func() func() {
			p := filepath.Join(a, "docker-compose")
			os.Chmod(p, 0o757)
			return func() { os.Chmod(p, 0o755) }
		}},
		{"symlink plugin to non-owned target", func() func() {
			p := filepath.Join(b, "docker-evil")
			os.Symlink("/bin/sh", p)
			return func() { os.Remove(p) }
		}},
		{"symlink plugin to writable target", func() func() {
			tg := filepath.Join(d, "evil-target")
			os.WriteFile(tg, []byte("x"), 0o757)
			os.Chmod(tg, 0o757)
			p := filepath.Join(b, "docker-evil")
			os.Symlink(tg, p)
			return func() { os.Remove(p); os.Remove(tg) }
		}},
		{"symlink plugin, target in writable dir", func() func() {
			wd := filepath.Join(d, "wdir")
			os.Mkdir(wd, 0o777)
			os.Chmod(wd, 0o777)
			os.WriteFile(filepath.Join(wd, "t"), []byte("x"), 0o755)
			p := filepath.Join(b, "docker-evil")
			os.Symlink(filepath.Join(wd, "t"), p)
			return func() { os.Remove(p); os.RemoveAll(wd) }
		}},
		{"dangling symlink plugin", func() func() {
			p := filepath.Join(b, "docker-evil")
			os.Symlink(filepath.Join(d, "nope"), p)
			return func() { os.Remove(p) }
		}},
		{"symlinked dir", func() func() {
			os.Rename(b, b+".real")
			os.Symlink(b+".real", b)
			return func() { os.Remove(b); os.Rename(b+".real", b) }
		}},
	}
	for _, tc := range bad {
		undo := tc.setup()
		if err := c.plugins([]string{a, b}); err == nil {
			t.Errorf("%s accepted", tc.name)
		}
		undo()
	}
	wrong := fsCheck{uid: c.uid + 1, top: d}
	if err := wrong.plugins([]string{a}); err == nil {
		t.Error("wrong owner accepted")
	}
	if err := c.plugins([]string{a, b}); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	// Symlink whose resolved target (via a symlinked safe dir) passes safe() is allowed.
	sd := filepath.Join(d, "real")
	os.Mkdir(sd, 0o755)
	os.Chmod(sd, 0o755)
	os.WriteFile(filepath.Join(sd, "compose"), []byte("x"), 0o755)
	os.Symlink(sd, filepath.Join(d, "alias"))
	os.Symlink(filepath.Join(d, "alias", "compose"), filepath.Join(a, "docker-compose2"))
	if err := c.plugins([]string{a, b}); err != nil {
		t.Fatalf("safe symlinked plugin refused: %v", err)
	}
}

func TestSafeDockerBin(t *testing.T) {
	c, d := tree(t)
	bin := filepath.Join(d, "docker")
	os.WriteFile(bin, []byte("x"), 0o755)
	if err := c.safe(bin); err != nil {
		t.Fatal(err)
	}
	os.Chmod(bin, 0o775)
	if c.safe(bin) == nil {
		t.Error("group-writable binary accepted")
	}
	if c.safe(d+"/../x") == nil {
		t.Error("unclean path accepted")
	}
}

func TestLockSlots(t *testing.T) {
	c, d := tree(t)
	l0, err := c.acquire(d, 2)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := c.acquire(d, 2)
	if err != nil {
		t.Fatal(err)
	}
	if l0.Name() == l1.Name() {
		t.Fatal("same slot twice")
	}
	if _, err := c.acquire(d, 2); !errors.Is(err, errBusy) {
		t.Fatalf("3rd concurrent run: want busy, got %v", err)
	}
	fi, _ := os.Stat(l0.Name())
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("lock mode %v", fi.Mode().Perm())
	}
	l0.Close() // slot freed on close/exit
	l2, err := c.acquire(d, 2)
	if err != nil {
		t.Fatalf("freed slot not reusable: %v", err)
	}
	l1.Close()
	l2.Close()
}

func TestLockRefusesUnsafe(t *testing.T) {
	for name, setup := range map[string]func(d string){
		"symlink": func(d string) { os.Symlink(filepath.Join(d, "target"), filepath.Join(d, "auditsh-docker.0.lock")) },
		"readable": func(d string) {
			os.WriteFile(filepath.Join(d, "auditsh-docker.0.lock"), nil, 0o644)
			os.Chmod(filepath.Join(d, "auditsh-docker.0.lock"), 0o644)
		},
		"hardlink": func(d string) {
			p := filepath.Join(d, "auditsh-docker.0.lock")
			os.WriteFile(p, nil, 0o600)
			os.Link(p, filepath.Join(d, "other"))
		},
		"fifo":          func(d string) { syscall.Mkfifo(filepath.Join(d, "auditsh-docker.0.lock"), 0o600) },
		"directory":     func(d string) { os.Mkdir(filepath.Join(d, "auditsh-docker.0.lock"), 0o700) },
		"writable /run": func(d string) { os.Chmod(d, 0o777) },
	} {
		c, d := tree(t)
		setup(d)
		f, err := c.acquire(d, 2)
		if err == nil {
			f.Close()
			t.Errorf("%s: accepted", name)
		} else if errors.Is(err, errBusy) {
			t.Errorf("%s: reported busy, want hard refusal", name)
		}
		os.Chmod(d, 0o755)
	}
	if os.Getuid() != 0 {
		if _, err := prod.acquire(t.TempDir(), 1); err == nil || !strings.Contains(err.Error(), "not owned by uid 0") {
			t.Errorf("non-root-owned lock dir with production checker: %v", err)
		}
	}
}
