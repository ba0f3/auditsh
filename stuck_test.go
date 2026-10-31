package main

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// stuckPipe returns the write end of a pipe whose reader never reads (an SSH client that
// stopped reading). The read end is closed at cleanup, which unblocks any abandoned write.
func stuckPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return w
}

func TestStuckStdoutTimeoutBoundsOutput(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		pipe       bool
	}{
		{"pollable-pipe", "head -c 4000000 /dev/zero; sleep 30", true},
		{"fallback-writer", "head -c 4000000 /dev/zero; sleep 30", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr io.Writer = stuckPipe(t), stuckPipe(t)
			if !tc.pipe {
				// not an *os.File: no kernel deadline, exercises the goroutine fallback
				stdout, stderr = blockWriter(t), blockWriter(t)
			}
			var mu sync.Mutex
			var lines []string
			to := 500 * time.Millisecond
			done := make(chan int, 1)
			start := time.Now()
			go func() {
				done <- serve(env{raw: "fake", cfg: fake(t, tc.body), stdout: stdout, stderr: stderr,
					opts: runOpts{timeout: to, maxOutput: 1 << 30}, user: "botaudit",
					logf: func(s string) error { mu.Lock(); lines = append(lines, s); mu.Unlock(); return nil }})
			}()
			limit := to + waitDelay + 1500*time.Millisecond
			var code int
			select {
			case code = <-done:
			case <-time.After(limit):
				t.Fatalf("serve still blocked on a stuck stdout after %v", limit)
			}
			if d := time.Since(start); d > limit {
				t.Fatalf("returned after %v", d)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(lines) != 2 {
				t.Fatalf("want start+end records, got %q", lines)
			}
			var le logEntry
			if err := json.Unmarshal([]byte(lines[1]), &le); err != nil {
				t.Fatal(err)
			}
			if le.Phase != "end" || !le.TimedOut || code == 0 || le.Exit == 0 {
				t.Fatalf("code=%d %+v", code, le)
			}
		})
	}
}

// blockWriter accepts 64 KiB and then blocks every write until the test ends.
type blocking struct {
	mu   sync.Mutex
	n    int
	stop chan struct{}
}

func (b *blocking) Write(p []byte) (int, error) {
	b.mu.Lock()
	full := b.n+len(p) > 64<<10
	if !full {
		b.n += len(p)
	}
	b.mu.Unlock()
	if full {
		<-b.stop
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func blockWriter(t *testing.T) io.Writer {
	b := &blocking{stop: make(chan struct{})}
	t.Cleanup(func() { close(b.stop) })
	return b
}

// sshd hands auditsh a blocking pipe/socket on fds 1/2: pollableStdio must make it deadline-capable.
func TestPollableStdioPipe(t *testing.T) {
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(p[0])
	f := pollableStdio(p[1], "w", nil)
	if f == nil {
		t.Fatal("pipe not made pollable")
	}
	defer f.Close()
	b := newBoundedWriter(f, time.Now().Add(300*time.Millisecond))
	if !b.pollable {
		t.Fatal("SetWriteDeadline unsupported on a pollable pipe")
	}
	start := time.Now()
	buf := make([]byte, 1<<16)
	var err error
	for err == nil && time.Since(start) < 3*time.Second {
		_, err = b.Write(buf)
	}
	if err != errOutputDeadline || time.Since(start) > time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	if _, err := b.Write([]byte("x")); err != errOutputDeadline {
		t.Fatal("writes after the deadline must fail at once")
	}
	// ttys/regular files are left alone
	tf, _ := os.CreateTemp(t.TempDir(), "f")
	if got := pollableStdio(int(tf.Fd()), "f", tf); got != tf {
		t.Fatal("regular file must not be switched to nonblocking")
	}
}
