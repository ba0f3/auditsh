// auditsh-docker: run ONE read-only docker diagnostic as root, for the botaudit account.
//
// Installed root:root 0755 at /usr/local/sbin/auditsh-docker and invoked only by auditsh as
//
//	sudo -n -- /usr/local/sbin/auditsh-docker <docker args...>
//
// The sudoers grant (/etc/sudoers.d/botaudit-docker) is the bare helper path, so THIS program is
// the policy gate: argv is re-validated against a fixed table (internal/dockerpolicy), the docker
// argv (including every --format template) is built here, docker is run by absolute path with a
// fixed environment (DOCKER_HOST pinned, no config dir, no context, no plugins), no shell, no stdin,
// bounded time and output, and inspect/info JSON is passed through an allowlist redaction.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/ba0f3/auditsh/internal/dockerpolicy"
)

const (
	dockerBin  = "/usr/bin/docker"
	dockerHost = "unix:///var/run/docker.sock"
	timeout    = 12 * time.Second // below sudoers command_timeout=15s
	maxOut     = 8 << 20
	maxJSON    = 16 << 20
)

// env is the COMPLETE child environment; nothing is inherited.
var env = []string{
	"PATH=/usr/bin:/bin",
	"LC_ALL=C",
	"HOME=/nonexistent",
	"DOCKER_HOST=" + dockerHost,
	"DOCKER_CONFIG=/nonexistent/auditsh-docker", // no config.json: no aliases, credsStore, proxies, contexts
	"DOCKER_CLI_HINTS=false",
}

func die(code int, f string, a ...any) {
	fmt.Fprintf(os.Stderr, "auditsh-docker: "+f+"\n", a...)
	os.Exit(code)
}

// fsCheck holds the trust anchors; tests substitute a temp tree and their own uid.
type fsCheck struct {
	uid uint32 // required owner (0 in production)
	top string // walk parents up to and including this dir ("/" in production)
}

var prod = fsCheck{uid: 0, top: "/"}

// safe: p and every parent up to c.top are owned by c.uid, not symlinks, not group/world-writable.
func (c fsCheck) safe(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s: not absolute/clean", p)
	}
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if err := c.node(p, fi); err != nil {
			return err
		}
		if p == c.top || p == "/" {
			return nil
		}
		p = filepath.Dir(p)
	}
}

func (c fsCheck) node(p string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != c.uid {
		return fmt.Errorf("%s not owned by uid %d", p, c.uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s group/world-writable", p)
	}
	return nil
}

// pluginDirs are the system docker CLI plugin dirs. The CLI may exec every entry (as root) to probe
// plugin metadata (e.g. for `info`), so each existing dir, its parents and every entry must be safe.
var pluginDirs = []string{"/usr/libexec/docker/cli-plugins", "/usr/local/lib/docker/cli-plugins"}

func (c fsCheck) plugins(dirs []string) error {
	for _, d := range dirs {
		if _, err := os.Lstat(d); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := c.safe(d); err != nil {
			return err
		}
		ents, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			if err := c.node(p, fi); err != nil {
				return err
			}
		}
	}
	return nil
}

// Concurrency cap: lockSlots root-only lock files in /run; each run holds one (non-blocking flock,
// released by the kernel on exit). All busy -> refuse with exitBusy immediately.
const (
	lockDir   = "/run"
	lockSlots = 2
	exitBusy  = 75 // EX_TEMPFAIL
)

var errBusy = errors.New("busy: all slots in use, try again later")

// acquire returns the held lock file (keep it open for the life of the run).
func (c fsCheck) acquire(dir string, slots int) (*os.File, error) {
	if err := c.safe(dir); err != nil {
		return nil, err
	}
	for i := 0; i < slots; i++ {
		p := filepath.Join(dir, fmt.Sprintf("auditsh-docker.%d.lock", i))
		f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
		if err != nil {
			return nil, fmt.Errorf("lock %s: %w", p, err)
		}
		fi, err := f.Stat()
		if err == nil {
			err = c.node(p, fi)
		}
		if err == nil {
			st := fi.Sys().(*syscall.Stat_t)
			if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || st.Nlink != 1 {
				err = fmt.Errorf("lock %s: not a private regular file", p)
			}
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); {
		case err == nil:
			return f, nil
		case errors.Is(err, syscall.EWOULDBLOCK):
			f.Close()
		default:
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", p, err)
		}
	}
	return nil, errBusy
}

// capWriter keeps at most limit bytes, then cancels the command.
type capWriter struct {
	mu     sync.Mutex
	w      io.Writer
	n      int64
	limit  int64
	full   bool
	cancel func()
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.full {
		return len(p), nil
	}
	if room := c.limit - c.n; int64(len(p)) > room {
		_, _ = c.w.Write(p[:room])
		c.n, c.full = c.limit, true
		c.cancel()
		return len(p), nil
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return len(p), err
}

func main() {
	plan, err := dockerpolicy.Validate(os.Args[1:], time.Now())
	if err != nil {
		die(126, "%v", err)
	}
	if os.Geteuid() != 0 {
		die(126, "must run as root via sudo")
	}
	if err := prod.safe(dockerBin); err != nil {
		die(126, "docker binary check: %v", err)
	}
	if err := prod.plugins(pluginDirs); err != nil {
		die(126, "docker cli-plugins check: %v", err)
	}
	lock, err := prod.acquire(lockDir, lockSlots)
	if errors.Is(err, errBusy) {
		die(exitBusy, "%v", err)
	} else if err != nil {
		die(126, "%v", err)
	}
	code := run(plan)
	lock.Close()
	os.Exit(code)
}

func run(plan dockerpolicy.Plan) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, dockerBin, plan.Argv...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdin = nil
	// Pdeathsig: if the helper itself is SIGKILLed (e.g. sudo command_timeout), the kernel kills docker.
	// It fires on exit of the creating *thread*, so pin this goroutine to its thread first.
	runtime.LockOSThread()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second

	var jsonBuf bytes.Buffer
	var out *capWriter
	switch plan.Kind {
	case dockerpolicy.KindStream, dockerpolicy.KindLogs:
		out = &capWriter{w: os.Stdout, limit: maxOut, cancel: cancel}
	default:
		out = &capWriter{w: &jsonBuf, limit: maxJSON, cancel: cancel}
	}
	errw := &capWriter{w: os.Stderr, limit: 64 << 10, cancel: func() {}}
	cmd.Stdout = out
	cmd.Stderr = errw
	if plan.Kind == dockerpolicy.KindLogs {
		cmd.Stderr = out // container stderr: same cap, merged
	}
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		code = ee.ExitCode()
	default:
		code = 1
	}
	if out.full {
		// streams were cut at the cap; JSON is never emitted partially (it could not be redacted).
		fmt.Fprintln(os.Stderr, "auditsh-docker: output truncated at cap")
		return 1
	}
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintln(os.Stderr, "auditsh-docker: timed out")
		return 124
	}
	if plan.Kind == dockerpolicy.KindStream || plan.Kind == dockerpolicy.KindLogs {
		return code
	}
	if jsonBuf.Len() == 0 {
		return code
	}
	var red []byte
	switch plan.Kind {
	case dockerpolicy.KindInspectContainer:
		red, err = dockerpolicy.RedactContainers(jsonBuf.Bytes())
	case dockerpolicy.KindInspectNetwork:
		red, err = dockerpolicy.RedactNetworks(jsonBuf.Bytes())
	case dockerpolicy.KindInfo:
		red, err = dockerpolicy.RedactInfo(jsonBuf.Bytes())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "auditsh-docker: unexpected docker JSON; nothing printed")
		return 1
	}
	_, _ = os.Stdout.Write(red)
	return code
}
