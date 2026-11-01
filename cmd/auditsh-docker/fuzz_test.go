package main

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ba0f3/auditsh/internal/dockerpolicy"
)

// matchesForm: independent oracle. argv must equal one dockerpolicy.Forms entry token by token
// (pattern tokens as anchored regexps, everything else literal).
func matchesForm(argv []string) bool {
	pat := map[string]*regexp.Regexp{}
	for _, p := range []string{dockerpolicy.NamePattern, dockerpolicy.TailPattern, dockerpolicy.TimePattern} {
		pat[p] = regexp.MustCompile(`^(?:` + p + `)$`)
	}
	for _, f := range dockerpolicy.Forms {
		if len(f) != len(argv) {
			continue
		}
		ok := true
		for i, tok := range f {
			if re, isPat := pat[tok]; isPat {
				ok = ok && re.MatchString(argv[i])
			} else {
				ok = ok && tok == argv[i]
			}
		}
		if ok {
			return true
		}
	}
	return false
}

var fuzzNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// FuzzHelperArgv drives the helper's entry path (os.Args[1:] -> Validate -> command) without
// executing anything. Accepted input must be one of the policy Forms, and the built child must be
// the fixed docker binary with the fixed env, own pgid, SIGKILL-on-parent-death, no global flags,
// and every operand after "--" (never a leading '-').
func FuzzHelperArgv(f *testing.F) {
	for _, s := range []string{"ps", "ps\x00-a", "images", "info", "version", "stats\x00--no-stream", "network\x00ls",
		"volume\x00ls", "inspect\x00web-1", "network\x00inspect\x00bridge", "logs\x00--tail\x0010\x00web",
		"logs\x00--tail\x0010\x00--since\x002h\x00web", "events\x00--since\x002h\x00--until\x001h",
		"-H\x00tcp://x\x00ps", "--context\x00x\x00ps", "inspect\x00-f\x00{{.Config.Env}}\x00web", "logs\x00-f\x00web",
		"exec\x00web\x00sh", "inspect\x00--\x00web", "logs\x00--tail=5\x00web", "ps\x00--format\x00{{json .}}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		args := strings.Split(s, "\x00")
		plan, err := dockerpolicy.Validate(args, fuzzNow)
		if err != nil {
			if !errors.Is(err, dockerpolicy.ErrDenied) {
				t.Fatalf("non-denied error %v", err)
			}
			return
		}
		if !matchesForm(args) {
			t.Fatalf("accepted %q which is not a policy form", args)
		}
		cmd := command(context.Background(), plan)
		if cmd.Path != dockerBin || cmd.Args[0] != dockerBin || !slices.Equal(cmd.Args[1:], plan.Argv) {
			t.Fatalf("child %q %q", cmd.Path, cmd.Args)
		}
		if !slices.Equal(cmd.Env, env) || cmd.Dir != "/" || cmd.Stdin != nil {
			t.Fatalf("child env/dir/stdin %q %q", cmd.Env, cmd.Dir)
		}
		if a := cmd.SysProcAttr; a == nil || !a.Setpgid || a.Pdeathsig != syscall.SIGKILL || a.Credential != nil || a.Chroot != "" {
			t.Fatalf("child attrs %+v", a)
		}
		globals := map[string]bool{"-H": true, "--host": true, "--context": true, "-c": true, "--config": true,
			"-D": true, "--debug": true, "-l": true, "--log-level": true, "--tls": true, "--tlsverify": true}
		dd := slices.Index(plan.Argv, "--")
		for i, a := range plan.Argv {
			if globals[a] || strings.HasPrefix(a, "-H") || strings.Contains(a, "=") && strings.HasPrefix(a, "-") {
				t.Fatalf("global/joined flag %q in %q", a, plan.Argv)
			}
			if dd >= 0 && i > dd && strings.HasPrefix(a, "-") {
				t.Fatalf("leading '-' operand %q", a)
			}
			if i > 0 && plan.Argv[i-1] == "--format" {
				continue // helper-built template (checked against the fixed set in dockerpolicy tests)
			}
			for j := 0; j < len(a); j++ {
				if a[j] < 0x20 || a[j] == 0x7f {
					t.Fatalf("control byte in %q", a)
				}
			}
		}
		if dd >= 0 && dd != len(plan.Argv)-2 {
			t.Fatalf("-- not before the single operand: %q", plan.Argv)
		}
	})
}
