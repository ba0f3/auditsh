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
	procDir     string                           // default "/proc"
	lookupUser  func(uid string) (string, error) // default lookupUserName
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

	if r.Path == internalFileRead {
		if len(args) != 1 {
			return result{exit: 2}, errors.New("fileread needs one path")
		}
		err := osFileRead(args[0], cw, o.binOwnerUID)
		res := result{bytes: cw.n, truncated: cw.truncated}
		if err != nil {
			res.exit = 1
			fmt.Fprintln(os.Stderr, "auditsh: read failed")
		}
		return res, nil
	}

	if o.checkBin {
		check := func(p string, uid uint32) error { return checkTree(p, uid) }
		if r.Resolve {
			check = func(p string, uid uint32) error { _, err := checkChain(p, uid); return err }
		}
		if err := check(r.Path, o.binOwnerUID); err != nil {
			return result{exit: 126}, fmt.Errorf("binary check: %w", err)
		}
		if r.Sudo {
			if err := checkTree(o.sudo, o.binOwnerUID); err != nil {
				return result{exit: 126}, fmt.Errorf("sudo check: %w", err)
			}
		}
	}
	name, argv := r.Path, args
	if r.JVM {
		if o.checkBin {
			if err := checkTree(o.sudo, o.binOwnerUID); err != nil {
				return result{exit: 126}, fmt.Errorf("sudo check: %w", err)
			}
		}
		procDir, lookup := o.procDir, o.lookupUser
		if procDir == "" {
			procDir = "/proc"
		}
		if lookup == nil {
			lookup = lookupUserName
		}
		pid, err := jvmPid(args)
		if err != nil {
			return result{exit: 126}, err
		}
		owner, err := jvmOwner(procDir, pid, lookup)
		if err != nil {
			fmt.Fprintln(os.Stderr, "auditsh: "+err.Error())
			return result{exit: 126}, err
		}
		name = o.sudo
		argv = append([]string{"-n", "-u", owner, "--", r.Path, r.Name}, args...)
	} else if r.Sudo {
		name = o.sudo
		argv = append([]string{"-n", "--", r.Path}, args...)
	}
	cmd := exec.CommandContext(ctx, name, argv...)
	// On timeout/cap: SIGKILL the whole process group, then after WaitDelay force-close
	// our pipe ends so a setsid'd descendant holding stdout cannot stall Wait.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	cmd.Env = cleanEnv
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
