// Command auditsh is an sshd ForceCommand that runs only allowlisted, read-only commands.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// configPath is fixed at build time (override only with -ldflags -X), never from env or args.
var configPath = "/etc/auditsh/allowlist.yaml"

const (
	defaultTimeout = 15 * time.Second
	defaultMaxOut  = 1 << 20
	maxLogCmd      = 512
)

type logEntry struct {
	TS         string   `json:"ts"`
	User       string   `json:"user"`
	Client     string   `json:"client_ip"`
	SSHConn    string   `json:"ssh_conn"`
	KeyFP      string   `json:"key_fp"`
	Command    string   `json:"raw"`
	Argv       []string `json:"argv,omitempty"`
	Phase      string   `json:"phase"` // deny | start | end
	Decision   string   `json:"decision"`
	Rule       string   `json:"rule,omitempty"`
	Deny       string   `json:"reason,omitempty"`
	Exit       int      `json:"exit"`
	DurationMS int64    `json:"duration_ms"`
	Bytes      int64    `json:"bytes"`
	Truncated  bool     `json:"truncated"`
	TimedOut   bool     `json:"timed_out,omitempty"`
}

func clientIP() string {
	for _, k := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		if f := strings.Fields(os.Getenv(k)); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

type env struct {
	raw     string
	cfg     *config
	cfgErr  error
	stdout  io.Writer
	stderr  io.Writer
	invErr  error // bad invocation shape (see resolveCommand)
	logf    func(string) error
	opts    runOpts
	user    string
	client  string
	sshConn string
	keyFP   string
}

// selfPath is where auditsh is installed; it is both the login shell and the ForceCommand.
const selfPath = "/usr/local/sbin/auditsh"

// resolveCommand derives the client command from how sshd invoked us. auditsh is the
// login shell, so sshd runs `auditsh -c <cmd>`:
//   - ["-c", selfPath]: ForceCommand / authorized_keys command= path; the client's
//     command is SSH_ORIGINAL_COMMAND (may be empty -> deny with list).
//   - ["-c", X]: no ForceCommand applied (e.g. Match block lost); X is the client command.
//     If SSH_ORIGINAL_COMMAND is also set it must equal X, otherwise deny.
//   - anything else (no args = interactive login, extra args, other flags): deny.
func resolveCommand(args []string, orig string, origSet bool) (string, error) {
	if len(args) != 2 || args[0] != "-c" {
		return "", errors.New("bad invocation (interactive login or unexpected argv)")
	}
	if args[1] == selfPath {
		return orig, nil
	}
	if origSet && orig != args[1] {
		return "", errors.New("-c command disagrees with SSH_ORIGINAL_COMMAND")
	}
	return args[1], nil
}

// serve handles one invocation and returns the process exit code. Denials log one
// "deny" record; allowed commands log "start" (required before exec) and "end".
func serve(e env) int {
	start := time.Now()
	le := logEntry{TS: start.UTC().Format(time.RFC3339Nano), User: e.user, Client: e.client, SSHConn: e.sshConn, KeyFP: e.keyFP, Decision: "deny"}
	le.Command = e.raw
	if len(le.Command) > maxLogCmd {
		le.Command = le.Command[:maxLogCmd] + "...[cut]"
	}
	le.Command = fmt.Sprintf("%+q", le.Command) // ASCII-only: escapes controls and all non-ASCII
	finish := func(code int) int {
		le.Exit = code
		le.DurationMS = time.Since(start).Milliseconds()
		b, _ := json.Marshal(le)
		if err := e.logf(string(b)); err != nil {
			fmt.Fprintln(e.stderr, "auditsh: audit log unavailable")
			return 125
		}
		return code
	}
	deny := func(reason string) int {
		le.Phase = "deny"
		le.Deny = reason
		fmt.Fprintf(e.stderr, "auditsh: denied: %s\n", reason)
		return finish(126)
	}
	if e.invErr != nil {
		return deny(e.invErr.Error())
	}
	// Attribution is mandatory over SSH: no key fingerprint, no command (fail closed).
	if e.sshConn != "" && e.keyFP == "" {
		return deny("no key_fp")
	}
	if e.cfgErr != nil {
		return deny("config refused: " + e.cfgErr.Error())
	}
	if e.raw == "" {
		fmt.Fprintln(e.stderr, "auditsh: no interactive shell. Allowed commands:")
		printAllowed(e.cfg, e.stderr)
		return deny("empty command")
	}
	argv, err := parseCommand(e.raw)
	if err != nil {
		return deny(err.Error())
	}
	r, err := e.cfg.match(argv)
	if err != nil {
		return deny(err.Error())
	}
	le.Rule, le.Argv, le.Decision, le.Phase = r.ID, argv, "allow", "start"
	// Fail closed: nothing executes unless the start record was accepted by syslog.
	if b, _ := json.Marshal(le); e.logf(string(b)) != nil {
		fmt.Fprintln(e.stderr, "auditsh: audit log unavailable, refusing")
		return 125
	}
	le.Phase = "end"
	res, err := execute(r, argv[1:], e.stdout, e.opts)
	le.Bytes, le.Truncated, le.TimedOut = res.bytes, res.truncated, res.timedOut
	if err != nil {
		le.Deny = err.Error()
		var de deniedError
		if errors.As(err, &de) {
			le.Decision = "deny"
			fmt.Fprintln(e.stderr, "auditsh: denied: "+de.msg)
		} else {
			fmt.Fprintln(e.stderr, "auditsh: exec failed")
		}
	}
	if res.truncated {
		fmt.Fprintf(e.stderr, "\nauditsh: output truncated at %d bytes\n", e.opts.maxOutput)
	}
	if res.timedOut {
		fmt.Fprintf(e.stderr, "\nauditsh: timed out after %s\n", e.opts.timeout)
	}
	return finish(res.exit)
}

func printAllowed(c *config, w io.Writer) {
	if c == nil {
		return
	}
	for _, n := range c.Order {
		for _, r := range c.Rules[n] {
			parts := []string{n}
			for _, a := range r.Args {
				s := a.re.String()
				parts = append(parts, s[4:len(s)-2]) // strip ^(?: )$
			}
			fmt.Fprintln(w, "  "+strings.Join(parts, " "))
		}
	}
}

// keyFingerprint returns the SHA256 fingerprint of the first publickey in the sshd
// ExposeAuthInfo file. The path comes from sshd; content is only hashed, never trusted.
func keyFingerprint(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	for _, line := range strings.Split(string(b), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 3 && fs[0] == "publickey" {
			raw, err := base64.StdEncoding.DecodeString(fs[2])
			if err != nil {
				return ""
			}
			sum := sha256.Sum256(raw)
			return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		}
	}
	return ""
}

func main() {
	// Read sshd's ExposeAuthInfo file first: sshd deletes it at session teardown, so
	// an early client disconnect (e.g. ssh -tt with PTY refused) can race this read.
	keyFP := keyFingerprint(os.Getenv("SSH_USER_AUTH"))
	// Handle (not ignore) HUP/PIPE so a client disconnect cannot kill us before the end
	// record; handled dispositions reset to default in exec'd children.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP, syscall.SIGPIPE)
	orig, origSet := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	raw, invErr := resolveCommand(os.Args[1:], orig, origSet)
	if invErr != nil {
		raw = strings.Join(os.Args[1:], " ")
	}
	cfg, cfgErr := loadConfig(configPath, 0)
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
	}
	sl, slErr := syslog.New(syslog.LOG_LOCAL7|syslog.LOG_INFO, "auditsh")
	logf := func(s string) error {
		if slErr != nil {
			return slErr
		}
		return sl.Info(s)
	}
	os.Exit(serve(env{
		raw: raw, invErr: invErr, cfg: cfg, cfgErr: cfgErr,
		stdout: os.Stdout, stderr: os.Stderr, logf: logf,
		user: u, client: clientIP(), sshConn: os.Getenv("SSH_CONNECTION"), keyFP: keyFP,
		opts: runOpts{timeout: defaultTimeout, maxOutput: defaultMaxOut, checkBin: true, binOwnerUID: 0, sudo: sudoPath},
	}))
}
