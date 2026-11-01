// Package dockerpolicy is the argv policy and output redaction of the auditsh-docker helper.
//
// The helper runs as root (docker.sock is root-equivalent), so it trusts nothing from its caller:
// Validate accepts only a fixed table of read-only forms and returns the exact docker argv to run,
// including any --format template (the caller can never supply one). Times are re-encoded as unix
// seconds and bounded; names must match a strict regex and can never start with '-'.
package dockerpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Kind tells the helper how to treat docker's stdout.
type Kind int

const (
	KindStream           Kind = iota // copy (capped)
	KindLogs                         // copy stdout+stderr merged (container stderr arrives on stderr)
	KindInspectContainer             // JSON, filtered by RedactContainers
	KindInspectNetwork               // JSON, filtered by RedactNetworks
	KindInfo                         // JSON, filtered by RedactInfo
)

// Plan is the validated docker invocation (argv excludes the docker binary itself).
type Plan struct {
	Argv []string
	Kind Kind
}

const (
	MaxTail         = 1000
	MaxLogsSince    = 7 * 24 * time.Hour
	MaxEventsWindow = 24 * time.Hour
)

// NamePattern is a container/network name or id: docker's own name charset, first char alnum
// (so never '-'), max 128 chars.
const NamePattern = `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`

// TimePattern: unix seconds, RFC3339 (Z or ±hh:mm), or a relative duration <N>s|m|h ago.
const TimePattern = `[0-9]{1,11}|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})|[1-9][0-9]{0,5}[smh]`

// TailPattern: 1..1000 (range re-checked numerically).
const TailPattern = `[1-9][0-9]{0,3}`

var (
	nameRE = regexp.MustCompile(`^(?:` + NamePattern + `)$`)
	timeRE = regexp.MustCompile(`^(?:` + TimePattern + `)$`)
	tailRE = regexp.MustCompile(`^(?:` + TailPattern + `)$`)
	durRE  = regexp.MustCompile(`^[1-9][0-9]{0,5}[smh]$`)
)

const (
	psFormat     = "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.Ports}}"
	imagesFormat = "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}"
	statsFormat  = "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
	eventsFormat = `{{.Time}} {{.Type}} {{.Action}} {{.Actor.ID}} {{index .Actor.Attributes "name"}}`
	jsonFormat   = "{{json .}}"
)

// ErrDenied wraps every refusal.
var ErrDenied = errors.New("denied")

func deny(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(f, a...)) }

func name(s string) (string, error) {
	if !nameRE.MatchString(s) {
		return "", deny("bad name %q", s)
	}
	return s, nil
}

// parseTime returns the absolute time for a TimePattern value (durations are "ago" from now).
func parseTime(s string, now time.Time) (time.Time, error) {
	if !timeRE.MatchString(s) {
		return time.Time{}, deny("bad time %q", s)
	}
	if durRE.MatchString(s) {
		n, _ := strconv.ParseInt(s[:len(s)-1], 10, 64)
		unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour}[s[len(s)-1]]
		return now.Add(-time.Duration(n) * unit), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, deny("bad time %q", s)
	}
	return t, nil
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// Validate maps caller argv to a Plan, or refuses. now is injected for tests.
func Validate(args []string, now time.Time) (Plan, error) {
	n := len(args)
	if n == 0 {
		return Plan{}, deny("no command")
	}
	is := func(want ...string) bool {
		if n != len(want) {
			return false
		}
		for i, w := range want {
			if w != "" && args[i] != w {
				return false
			}
		}
		return true
	}
	switch {
	case is("ps"):
		return Plan{[]string{"ps", "--format", psFormat}, KindStream}, nil
	case is("ps", "-a"):
		return Plan{[]string{"ps", "-a", "--format", psFormat}, KindStream}, nil
	case is("images"):
		return Plan{[]string{"images", "--format", imagesFormat}, KindStream}, nil
	case is("info"):
		return Plan{[]string{"info", "--format", jsonFormat}, KindInfo}, nil
	case is("version"):
		return Plan{[]string{"version"}, KindStream}, nil
	case is("stats", "--no-stream"):
		return Plan{[]string{"stats", "--no-stream", "--format", statsFormat}, KindStream}, nil
	case is("network", "ls"):
		return Plan{[]string{"network", "ls"}, KindStream}, nil
	case is("volume", "ls"):
		return Plan{[]string{"volume", "ls"}, KindStream}, nil
	case is("inspect", ""):
		c, err := name(args[1])
		if err != nil {
			return Plan{}, err
		}
		return Plan{[]string{"container", "inspect", "--", c}, KindInspectContainer}, nil
	case is("network", "inspect", ""):
		c, err := name(args[2])
		if err != nil {
			return Plan{}, err
		}
		return Plan{[]string{"network", "inspect", "--", c}, KindInspectNetwork}, nil
	case is("logs", "--tail", "", ""), is("logs", "--tail", "", "--since", "", ""):
		if !tailRE.MatchString(args[2]) {
			return Plan{}, deny("bad --tail %q", args[2])
		}
		if t, _ := strconv.Atoi(args[2]); t < 1 || t > MaxTail {
			return Plan{}, deny("--tail must be 1..%d", MaxTail)
		}
		c, err := name(args[n-1])
		if err != nil {
			return Plan{}, err
		}
		argv := []string{"logs", "--tail", args[2]}
		if n == 6 {
			s, err := parseTime(args[4], now)
			if err != nil {
				return Plan{}, err
			}
			if s.After(now) || now.Sub(s) > MaxLogsSince {
				return Plan{}, deny("--since must be within the last %v", MaxLogsSince)
			}
			argv = append(argv, "--since", unix(s))
		}
		return Plan{append(argv, "--", c), KindLogs}, nil
	case is("events", "--since", "", "--until", ""):
		s, err := parseTime(args[2], now)
		if err != nil {
			return Plan{}, err
		}
		u, err := parseTime(args[4], now)
		if err != nil {
			return Plan{}, err
		}
		// until in the future would make docker wait for live events: refused.
		if !s.Before(u) || u.After(now) || u.Sub(s) > MaxEventsWindow {
			return Plan{}, deny("events needs since < until <= now and a window <= %v", MaxEventsWindow)
		}
		return Plan{[]string{"events", "--since", unix(s), "--until", unix(u), "--format", eventsFormat}, KindStream}, nil
	}
	return Plan{}, deny("form not allowed")
}
