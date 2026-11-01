package dockerpolicy

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1_790_000_000, 0)

func u(d time.Duration) string { return strconv.FormatInt(now.Add(-d).Unix(), 10) }

func TestAllowed(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
		kind Kind
	}{
		{"ps", []string{"ps", "--format", psFormat}, KindStream},
		{"ps -a", []string{"ps", "-a", "--format", psFormat}, KindStream},
		{"images", []string{"images", "--format", imagesFormat}, KindStream},
		{"info", []string{"info", "--format", "{{json .}}"}, KindInfo},
		{"version", []string{"version"}, KindStream},
		{"stats --no-stream", []string{"stats", "--no-stream", "--format", statsFormat}, KindStream},
		{"network ls", []string{"network", "ls"}, KindStream},
		{"volume ls", []string{"volume", "ls"}, KindStream},
		{"inspect web-1", []string{"container", "inspect", "--", "web-1"}, KindInspectContainer},
		{"network inspect bridge", []string{"network", "inspect", "--", "bridge"}, KindInspectNetwork},
		{"logs --tail 1000 a.b_c", []string{"logs", "--tail", "1000", "--", "a.b_c"}, KindLogs},
		{"logs --tail 1 --since 2h web", []string{"logs", "--tail", "1", "--since", u(2 * time.Hour), "--", "web"}, KindLogs},
		{"logs --tail 5 --since 168h web", []string{"logs", "--tail", "5", "--since", u(168 * time.Hour), "--", "web"}, KindLogs},
		{"logs --tail 5 --since " + u(time.Hour) + " web", []string{"logs", "--tail", "5", "--since", u(time.Hour), "--", "web"}, KindLogs},
		{"logs --tail 5 --since " + now.Add(-time.Hour).UTC().Format(time.RFC3339) + " web", []string{"logs", "--tail", "5", "--since", u(time.Hour), "--", "web"}, KindLogs},
		{"events --since 2h --until 1h", []string{"events", "--since", u(2 * time.Hour), "--until", u(time.Hour), "--format", eventsFormat}, KindStream},
		{"events --since 24h --until 0s", nil, 0}, // 0s is not a valid duration -> denied below
	} {
		p, err := Validate(strings.Fields(c.in), now)
		if c.want == nil {
			if err == nil {
				t.Errorf("%q allowed", c.in)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(p.Argv, c.want) || p.Kind != c.kind {
			t.Errorf("%q -> %q %v %v", c.in, p.Argv, p.Kind, err)
		}
	}
	if _, err := Validate([]string{"events", "--since", "24h", "--until", u(0)}, now); err != nil {
		t.Errorf("24h window up to now denied: %v", err)
	}
}

func TestDenied(t *testing.T) {
	future := strconv.FormatInt(now.Add(time.Minute).Unix(), 10)
	for _, a := range [][]string{
		nil, {""}, {"exec", "web", "sh"}, {"run", "alpine"}, {"cp", "web:/x", "."}, {"rm", "web"}, {"kill", "web"},
		{"restart", "web"}, {"pull", "alpine"}, {"build", "."}, {"system", "prune"}, {"system", "prune", "-af"},
		{"start", "web"}, {"stop", "web"}, {"commit", "web"}, {"export", "web"}, {"save", "x"}, {"login"},
		{"container", "inspect", "web"}, {"attach", "web"}, {"update", "web"}, {"plugin", "ls"}, {"context", "ls"},
		{"-H", "tcp://x", "ps"}, {"--host", "unix:///x", "ps"}, {"--host=tcp://x", "ps"}, {"--context", "x", "ps"},
		{"--config", "/tmp", "ps"}, {"-c", "x", "ps"}, {"--tls", "ps"}, {"-D", "ps"}, {"--log-level", "debug", "ps"},
		{"ps", "-H", "x"}, {"ps", "--format", "{{json .}}"}, {"ps", "-f", "name=x"}, {"ps", "--filter", "x"},
		{"ps", "-a", "--no-trunc"}, {"ps", "-aq"}, {"ps", "-q"}, {"images", "-a"}, {"info", "--format", "x"},
		{"version", "-f", "x"}, {"stats"}, {"stats", "--no-stream", "web"}, {"stats", "--no-stream", "--format", "x"},
		{"network", "ls", "-f", "x"}, {"network", "create", "x"}, {"network", "rm", "x"}, {"network", "connect", "a", "b"},
		{"volume", "rm", "x"}, {"volume", "inspect", "x"}, {"volume", "ls", "--format", "x"},
		{"inspect", "-H"}, {"inspect", "--host"}, {"inspect", "-f", "{{.Config.Env}}", "web"}, {"inspect", "--format=x", "web"},
		{"inspect", "--type", "image", "x"}, {"inspect", "a", "b"}, {"inspect", "-web"}, {"inspect", ".web"}, {"inspect", "_x"},
		{"inspect", "a/b"}, {"inspect", "a b"}, {"inspect", "a\x00"}, {"inspect", "web\n"}, {"inspect", "ẃeb"},
		{"inspect", strings.Repeat("a", 129)}, {"inspect", ""}, {"network", "inspect", "-H"}, {"network", "inspect", "--verbose", "x"},
		{"logs", "web"}, {"logs", "-f", "web"}, {"logs", "--tail=-1", "web"}, {"logs", "--tail", "-1", "web"},
		{"logs", "--tail", "0", "web"}, {"logs", "--tail", "1001", "web"}, {"logs", "--tail", "9999", "web"},
		{"logs", "--tail", "all", "web"}, {"logs", "--tail", "01", "web"}, {"logs", "--tail", "+5", "web"},
		{"logs", "--tail", "10", "-H"}, {"logs", "--tail", "10", "--", "web"}, {"logs", "--tail", "10", "-f", "web"},
		{"logs", "--tail", "10", "--follow", "web"}, {"logs", "--tail", "10", "--details", "web"},
		{"logs", "--tail", "10", "--since", "-1h", "web"}, {"logs", "--tail", "10", "--since", "169h", "web"},
		{"logs", "--tail", "10", "--since", "0", "web"}, {"logs", "--tail", "10", "--since", future, "web"},
		{"logs", "--tail", "10", "--since", "1d", "web"}, {"logs", "--tail", "10", "--since", "1h30m", "web"},
		{"logs", "--tail", "10", "--since", "1h", "--until", "0s", "web"}, {"logs", "--tail", "10", "--until", "1h", "web"},
		{"logs", "--tail", "10", "--since", "2026-10-01", "web"}, {"logs", "--since", "1h", "--tail", "10", "web"},
		{"events"}, {"events", "--since", "1h"}, {"events", "--until", "1h"}, {"events", "--since", "1h", "--until", future},
		{"events", "--since", "1h", "--until", "2h"}, {"events", "--since", "1h", "--until", "1h"},
		{"events", "--since", "25h", "--until", "0h"}, {"events", "--since", "48h", "--until", "1h"},
		{"events", "--since", "2h", "--until", "1h", "--format", "x"}, {"events", "--since", "2h", "--until", "1h", "-f", "x"},
		{"events", "--until", "1h", "--since", "2h"}, {"events", "--since=2h", "--until=1h"},
	} {
		if p, err := Validate(a, now); err == nil {
			t.Errorf("%q allowed -> %q", a, p.Argv)
		} else if !errors.Is(err, ErrDenied) {
			t.Errorf("%q: non-denied error %v", a, err)
		}
	}
}

// Property for fuzzing: whatever is accepted maps to a fixed, safe argv.
func checkPlan(t *testing.T, args []string, p Plan) {
	t.Helper()
	if len(p.Argv) == 0 {
		t.Fatalf("%q: empty plan", args)
	}
	verbs := map[string]bool{"ps": true, "images": true, "info": true, "version": true, "stats": true,
		"network": true, "volume": true, "container": true, "logs": true, "events": true}
	if !verbs[p.Argv[0]] {
		t.Fatalf("%q: verb %q", args, p.Argv[0])
	}
	ownFormats := map[string]bool{psFormat: true, imagesFormat: true, statsFormat: true, eventsFormat: true, jsonFormat: true}
	afterDD := false
	for i, a := range p.Argv {
		if a == "--" {
			afterDD = true
			if i != len(p.Argv)-2 {
				t.Fatalf("%q: -- not before last", args)
			}
			continue
		}
		if afterDD && !nameRE.MatchString(a) {
			t.Fatalf("%q: bad name %q", args, a)
		}
		if strings.HasPrefix(a, "-") && !map[string]bool{"-a": true, "--format": true, "--no-stream": true,
			"--tail": true, "--since": true, "--until": true}[a] {
			t.Fatalf("%q: flag %q", args, a)
		}
		if i > 0 && p.Argv[i-1] == "--format" && !ownFormats[a] {
			t.Fatalf("%q: format %q", args, a)
		}
		if i > 0 && p.Argv[i-1] == "--tail" {
			if n, err := strconv.Atoi(a); err != nil || n < 1 || n > MaxTail {
				t.Fatalf("%q: tail %q", args, a)
			}
		}
		if i > 0 && (p.Argv[i-1] == "--since" || p.Argv[i-1] == "--until") {
			n, err := strconv.ParseInt(a, 10, 64)
			if err != nil || n > now.Unix() || n < now.Add(-MaxLogsSince).Unix() {
				t.Fatalf("%q: time %q", args, a)
			}
		}
		for _, r := range a {
			if r == 0 || r == '\n' {
				t.Fatalf("%q: control char", args)
			}
		}
	}
	if p.Argv[0] == "events" {
		s, _ := strconv.ParseInt(p.Argv[2], 10, 64)
		e, _ := strconv.ParseInt(p.Argv[4], 10, 64)
		if p.Argv[3] != "--until" || s >= e || e-s > int64(MaxEventsWindow/time.Second) {
			t.Fatalf("%q: events window", args)
		}
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{"ps", "ps\x00-a", "inspect\x00web", "logs\x00--tail\x0010\x00web",
		"logs\x00--tail\x00=-1\x00web", "logs\x00--tail\x0010\x00--since\x002h\x00web", "events\x00--since\x002h\x00--until\x001h",
		"inspect\x00-H", "-H\x00x\x00ps", "network\x00inspect\x00bridge", "stats\x00--no-stream"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		args := strings.Split(s, "\x00")
		p, err := Validate(args, now)
		if err != nil {
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("non-denied error %v", err)
			}
			return
		}
		checkPlan(t, args, p)
	})
}

func TestFormsValidate(t *testing.T) {
	sample := map[string][]string{
		NamePattern: {"web-1", "a", strings.Repeat("z", 128)},
		TailPattern: {"1", "1000"},
	}
	seen := map[string]bool{}
	for _, f := range Forms {
		key := strings.Join(f, " ")
		if seen[key] {
			t.Errorf("duplicate form %q", key)
		}
		seen[key] = true
		// events / logs --since need a valid ordered window, so fill times positionally.
		times := []string{"2h", "1h"}
		for _, v := range []int{0, len(sample[NamePattern]) - 1} {
			ti := 0
			var args []string
			for _, tok := range f {
				switch tok {
				case NamePattern, TailPattern:
					s := sample[tok]
					args = append(args, s[min(v, len(s)-1)])
				case TimePattern:
					args = append(args, times[ti])
					ti++
				default:
					args = append(args, tok)
				}
			}
			if _, err := Validate(args, now); err != nil {
				t.Errorf("form %q instance %q denied: %v", key, args, err)
			}
		}
	}
}
