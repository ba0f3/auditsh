package main

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// errOutputDeadline is returned once the overall deadline has passed for an output stream.
var errOutputDeadline = errors.New("output deadline exceeded")

// boundedWriter bounds every write to w by a fixed deadline, so a client that stops reading
// cannot hold auditsh past its time limit. For a pollable *os.File the kernel-level write
// deadline is used. Otherwise each write runs in a goroutine and is abandoned at the deadline
// (it is never waited for; process exit reclaims it). After a deadline miss all later writes
// fail at once.
type boundedWriter struct {
	mu       sync.Mutex
	w        io.Writer
	deadline time.Time
	pollable bool
	dead     bool
}

func newBoundedWriter(w io.Writer, deadline time.Time) *boundedWriter {
	b := &boundedWriter{w: w, deadline: deadline}
	if f, ok := w.(*os.File); ok && f.SetWriteDeadline(deadline) == nil {
		b.pollable = true
	}
	return b
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dead || !time.Now().Before(b.deadline) {
		b.dead = true
		return 0, errOutputDeadline
	}
	if b.pollable {
		n, err := b.w.Write(p)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			b.dead = true
			return n, errOutputDeadline
		}
		return n, err
	}
	q := append([]byte(nil), p...) // the abandoned goroutine must not alias the caller's buffer
	type wr struct {
		n   int
		err error
	}
	ch := make(chan wr, 1)
	go func() {
		n, err := b.w.Write(q)
		ch <- wr{n, err}
	}()
	t := time.NewTimer(time.Until(b.deadline))
	defer t.Stop()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-t.C:
		b.dead = true
		return 0, errOutputDeadline
	}
}

// pollableStdio returns an *os.File for fd that supports write deadlines when fd is a pipe or
// socket (what sshd gives a ForceCommand): the fd is switched to O_NONBLOCK and handed to
// Go's poller. Ttys and regular files are left untouched (fallback: goroutine writes).
func pollableStdio(fd int, name string, def *os.File) *os.File {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return def
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK:
	default:
		return def
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		return def
	}
	return os.NewFile(uintptr(fd), name)
}
