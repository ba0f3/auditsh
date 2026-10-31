package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	sudoPath  = "/usr/bin/sudo"
	waitDelay = 2 * time.Second
)

var cleanEnv = []string{
	"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "PAGER=cat",
	"SYSTEMD_PAGER=", "SYSTEMD_LESS=", "LESSSECURE=1", "SYSTEMD_COLORS=0",
}

// childEnv returns a fresh copy of the fixed child environment (callers may not alias cleanEnv).
func childEnv() []string { return append([]string(nil), cleanEnv...) }

// execArgv returns the exact argv for an allowlisted external rule: [path args...] or,
// for sudo rules, [sudo -n -- path args...]. argv[0] is the binary actually executed.
func execArgv(r *rule, args []string, sudo string) []string {
	if r.Sudo {
		return append([]string{sudo, "-n", "--", r.Path}, args...)
	}
	return append([]string{r.Path}, args...)
}

// capWriter forwards at most limit bytes to w, then drops the rest and calls onFull once.
type capWriter struct {
	mu        sync.Mutex
	w         io.Writer
	limit     int64
	n         int64
	truncated bool
	onFull    func()
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.n
	if room <= 0 {
		// Output already filled the cap exactly; any further byte means truncation.
		if len(p) > 0 && !c.truncated {
			c.truncated = true
			if c.onFull != nil {
				c.onFull()
			}
		}
		return len(p), nil
	}
	q := p
	if int64(len(q)) > room {
		q = q[:room]
	}
	m, err := c.w.Write(q)
	c.n += int64(m)
	if err != nil {
		return m, err
	}
	if int64(len(p)) > room && !c.truncated {
		c.truncated = true
		if c.onFull != nil {
			c.onFull()
		}
	}
	return len(p), nil
}

type result struct {
	exit      int
	bytes     int64
	truncated bool
	timedOut  bool
}

type runOpts struct {
	timeout     time.Duration
	maxOutput   int64
	binOwnerUID uint32
	checkBin    bool
	sudo        string
}

func execute(r *rule, args []string, out io.Writer, o runOpts) (result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	cw := &capWriter{w: out, limit: o.maxOutput, onFull: cancel}

	if r.Path == internalProcRead {
		if len(args) != 1 {
			return result{exit: 2}, errors.New("procread needs one path")
		}
		err := procRead(args[0], cw)
		res := result{bytes: cw.n, truncated: cw.truncated}
		if err != nil {
			res.exit = 1
			fmt.Fprintln(os.Stderr, "auditsh: read failed")
		}
		return res, nil
	}

	if o.checkBin {
		if err := checkTree(r.Path, o.binOwnerUID); err != nil {
			return result{exit: 126}, fmt.Errorf("binary check: %w", err)
		}
		if r.Sudo {
			if err := checkTree(o.sudo, o.binOwnerUID); err != nil {
				return result{exit: 126}, fmt.Errorf("sudo check: %w", err)
			}
		}
	}
	full := execArgv(r, args, o.sudo)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	// On timeout/cap: SIGKILL the whole process group, then after WaitDelay force-close
	// our pipe ends so a setsid'd descendant holding stdout cannot stall Wait.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	cmd.Env = childEnv()
	cmd.Stdout = cw
	cmd.Stderr = cw
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return result{exit: 126}, err
	}
	defer devnull.Close()
	cmd.Stdin = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return result{exit: 126}, err
	}
	werr := cmd.Wait()
	res := result{bytes: cw.n, truncated: cw.truncated}
	res.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			res.exit = ee.ExitCode()
			if res.exit < 0 {
				res.exit = 137
			}
		} else {
			res.exit = 1
		}
	}
	return res, nil
}
