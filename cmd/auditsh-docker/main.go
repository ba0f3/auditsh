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

// safe: path and every parent are root-owned, not symlinks, not group/world-writable.
func safe(p string) error {
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fmt.Errorf("%s not root-owned", p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s group/world-writable", p)
		}
		if p == "/" {
			return nil
		}
		p = filepath.Dir(p)
	}
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
	if err := safe(dockerBin); err != nil {
		die(126, "docker binary check: %v", err)
	}
	os.Exit(run(plan))
}

func run(plan dockerpolicy.Plan) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, dockerBin, plan.Argv...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
