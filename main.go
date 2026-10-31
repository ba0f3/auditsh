// Command auditsh is an sshd ForceCommand that runs only allowlisted, read-only commands.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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
	logf    func(string) error
	opts    runOpts
	user    string
	client  string
	sshConn string
	keyFP   string
}

// serve handles one invocation and returns the process exit code. It always logs exactly once.
func serve(e env) int {
	start := time.Now()
	le := logEntry{TS: start.UTC().Format(time.RFC3339Nano), User: e.user, Client: e.client, SSHConn: e.sshConn, KeyFP: e.keyFP, Decision: "deny"}
	le.Command = e.raw
	if len(le.Command) > maxLogCmd {
		le.Command = le.Command[:maxLogCmd] + "...[cut]"
	}
	le.Command = fmt.Sprintf("%q", le.Command) // escapes controls/non-ASCII
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
		le.Deny = reason
		fmt.Fprintf(e.stderr, "auditsh: denied: %s\n", reason)
		return finish(126)
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
	le.Rule, le.Argv, le.Decision = r.ID, argv, "allow"
	res, err := execute(r, argv[1:], e.stdout, e.opts)
	le.Bytes, le.Truncated, le.TimedOut = res.bytes, res.truncated, res.timedOut
	if err != nil {
		le.Deny = err.Error()
		fmt.Fprintln(e.stderr, "auditsh: exec failed")
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
		raw: os.Getenv("SSH_ORIGINAL_COMMAND"), cfg: cfg, cfgErr: cfgErr,
		stdout: os.Stdout, stderr: os.Stderr, logf: logf,
		user: u, client: clientIP(), sshConn: os.Getenv("SSH_CONNECTION"), keyFP: keyFingerprint(os.Getenv("SSH_USER_AUTH")),
		opts: runOpts{timeout: defaultTimeout, maxOutput: defaultMaxOut, checkBin: true, binOwnerUID: 0, sudo: sudoPath},
	}))
}
