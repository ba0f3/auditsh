package dockerpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

const secret = "S3CRET-hunter2"

// Shaped like real `docker container inspect` output, with secrets in every place they hide.
var containerJSON = `[{
 "Id": "abc123", "Created": "2026-10-01T00:00:00Z", "Path": "/entry.sh",
 "Args": ["--password=` + secret + `"],
 "State": {"Status": "running", "Running": true, "Pid": 42, "ExitCode": 0,
   "Health": {"Status": "healthy", "FailingStreak": 0, "Log": [{"Output": "token ` + secret + `"}]}},
 "Image": "sha256:ff", "Name": "/web", "RestartCount": 0, "Driver": "overlay2", "Platform": "linux",
 "ResolvConfPath": "/x", "GraphDriver": {"Data": {"MergedDir": "/var/lib/docker/x"}},
 "Mounts": [{"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": true}],
 "Config": {"Hostname": "web", "User": "app", "Image": "nginx:1",
   "Env": ["DB_PASSWORD=` + secret + `", "PATH=/usr/bin"],
   "Cmd": ["nginx", "-p", "` + secret + `"], "Entrypoint": ["/entry.sh", "` + secret + `"],
   "Healthcheck": {"Test": ["CMD", "curl", "-u", "admin:` + secret + `"]},
   "Labels": {"com.example.token": "` + secret + `", "maintainer": "x"},
   "OnBuild": ["RUN echo ` + secret + `"], "FutureField": "` + secret + `"},
 "HostConfig": {"Privileged": true, "NetworkMode": "bridge", "Binds": ["/srv/data:/data"], "Memory": 1073741824,
   "NanoCpus": 9007199254740993, "LogConfig": {"Type": "splunk", "Config": {"splunk-token": "` + secret + `"}},
   "ContainerIDFile": "` + secret + `", "ExtraHosts": ["` + secret + `:1.2.3.4"]},
 "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
 "SomeNewTopLevel": {"k": "` + secret + `"}
}]`

func TestRedactContainers(t *testing.T) {
	out, err := RedactContainers([]byte(containerJSON))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, secret) {
		t.Fatalf("secret leaked:\n%s", s)
	}
	for _, k := range []string{`"Env"`, `"Cmd"`, `"Entrypoint"`, `"Args"`, `"Healthcheck"`, `"Log"`, `"OnBuild"`, `"GraphDriver"`, `"ExtraHosts"`} {
		if strings.Contains(s, k) {
			t.Errorf("%s not dropped", k)
		}
	}
	for _, want := range []string{`"/srv/data"`, `"Privileged": true`, `"172.17.0.2"`, `"Type": "splunk"`,
		`"com.example.token": "[redacted]"`, `"healthy"`, `"Name": "/web"`, `9007199254740993`, `"AuditshRedacted"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	var v []map[string]any
	if err := json.Unmarshal(out, &v); err != nil || len(v) != 1 {
		t.Fatalf("output not valid JSON array: %v", err)
	}
}

func TestRedactNetworks(t *testing.T) {
	in := `[{"Name":"bridge","Id":"n1","Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]},
	 "Containers":{"abc":{"Name":"web","IPv4Address":"172.17.0.2/16"}},"Options":{"com.docker.network.bridge.name":"docker0"},
	 "Labels":{"secret":"` + secret + `"},"Unknown":"` + secret + `"}]`
	out, err := RedactNetworks([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, secret) || !strings.Contains(s, "172.17.0.0/16") || !strings.Contains(s, `"secret": "[redacted]"`) {
		t.Fatalf("bad network redaction:\n%s", s)
	}
}

func TestRedactInfo(t *testing.T) {
	in := `{"ID":"x","Containers":3,"HTTPProxy":"http://u:` + secret + `@p:3128","HTTPSProxy":"http://u:` + secret + `@p","NoProxy":"` + secret + `",
	 "Labels":["env=` + secret + `","` + secret + `"],"ServerVersion":"27.5.1"}`
	out, err := RedactInfo([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, secret) || strings.Contains(s, "Proxy") || !strings.Contains(s, "27.5.1") || !strings.Contains(s, "env=[redacted]") {
		t.Fatalf("bad info redaction:\n%s", s)
	}
}

func TestRedactRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not json", `{"Id":1}`, `[{"Id":"a"}] [{"Env":["x"]}]`, `[{"Id":"a"}`} {
		if _, err := RedactContainers([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// Redaction fuzzers are structured: a raw mutated JSON blob almost never parses, so mutating bytes of
// one big sample explores nothing (~0 new coverage). Instead each input is a small JSON object
// (merged into a minimal valid doc) plus a canary planted in one sensitive location, wrapped in a
// fuzz-chosen JSON shape. Property: output is valid JSON, only allowlisted keys survive, and the
// canary never appears.

const canary = "CANARY-9f3b1c0d7e2a4b65"

// shape wraps the canary in one of several JSON shapes; sensitive fields must be removed or masked
// whatever their type (fail closed on unexpected shapes).
func shape(n uint8, key string) any {
	switch n % 7 {
	case 0:
		return canary
	case 1:
		return []any{"k=" + canary, canary}
	case 2:
		return obj{key: canary}
	case 3:
		return obj{key: []any{obj{"v": canary}}}
	case 4:
		return []any{obj{key: canary}}
	case 5:
		return []any{[]any{canary}}
	default:
		return obj{"a": obj{"b": obj{key: canary}}}
	}
}

// plant puts v at path (creating objects on the way) in o.
func plant(o obj, path []string, v any) {
	for _, k := range path[:len(path)-1] {
		n, ok := o[k].(obj)
		if !ok {
			n = obj{}
			o[k] = n
		}
		o = n
	}
	o[path[len(path)-1]] = v
}

// mergeRaw decodes raw (if it is a JSON object without the canary) into base: lets the fuzzer
// mutate arbitrary extra structure while the doc stays valid.
func mergeRaw(base obj, raw string) bool {
	if strings.Contains(raw, canary) || strings.Contains(strings.ToLower(raw), strings.ToLower(canary)) {
		return false
	}
	var extra obj
	if raw != "" && json.Unmarshal([]byte(raw), &extra) == nil {
		for k, v := range extra {
			base[k] = v
		}
	}
	return true
}

// Sensitive spots in a container inspect object (canary there must never leak).
var containerSpots = [][]string{{"Args"}, {"Config", "Env"}, {"Config", "Cmd"}, {"Config", "Entrypoint"},
	{"Config", "Labels"}, {"Config", "Healthcheck"}, {"Config", "OnBuild"}, {"Config", "Future"},
	{"State", "Health", "Log"}, {"HostConfig", "LogConfig", "Config"}, {"HostConfig", "ExtraHosts"},
	{"HostConfig", "ContainerIDFile"}, {"GraphDriver"}, {"NewTop"}, {"State", "Health", "Future"}}

func checkKeys(t *testing.T, o obj, allow map[string]bool, what string) {
	for k := range o {
		if !allow[k] {
			t.Fatalf("%s.%s survived", what, k)
		}
	}
}

func FuzzRedactContainers(f *testing.F) {
	for i, s := range []string{"", `{}`, `{"Id":"a","Name":"/w"}`, `{"Config":{"Labels":{"x":"y"}}}`, `{"State":{"Health":{"Status":"ok"}}}`,
		`{"HostConfig":{"LogConfig":{"Type":"json-file"}}}`, `{"Config":"str"}`, `{"Config":{"Labels":["a=b"]}}`, `{"Mounts":[{"Source":"/x"}]}`} {
		f.Add(s, uint8(i), uint8(i*3))
	}
	f.Fuzz(func(t *testing.T, raw string, sh, where uint8) {
		c := obj{"Id": "abc", "Config": obj{"Image": "x"}, "State": obj{"Status": "running"}, "HostConfig": obj{}}
		if !mergeRaw(c, raw) {
			return
		}
		plant(c, containerSpots[int(where)%len(containerSpots)], shape(sh, "token"))
		in, err := json.Marshal([]any{c})
		if err != nil {
			return
		}
		out, err := RedactContainers(in)
		if err != nil {
			t.Fatalf("valid doc rejected: %v", err)
		}
		if strings.Contains(string(out), canary) {
			t.Fatalf("canary leaked via %v:\n%s", containerSpots[int(where)%len(containerSpots)], out)
		}
		var v []obj
		if json.Unmarshal(out, &v) != nil || len(v) != 1 {
			t.Fatal("invalid output")
		}
		r := v[0]
		delete(r, "AuditshRedacted")
		checkKeys(t, r, containerTop, "top")
		if cfg, ok := r["Config"].(obj); ok {
			checkKeys(t, cfg, containerConfig, "Config")
		}
		if hc, ok := r["HostConfig"].(obj); ok {
			checkKeys(t, hc, containerHost, "HostConfig")
			if lc, ok := hc["LogConfig"].(obj); ok {
				checkKeys(t, lc, set("Type"), "LogConfig")
			}
		}
		if st, ok := r["State"].(obj); ok {
			checkKeys(t, st, containerState, "State")
			if h, ok := st["Health"].(obj); ok {
				checkKeys(t, h, healthKeep, "Health")
			}
		}
	})
}

var networkSpots = [][]string{{"Labels"}, {"Unknown"}, {"Secret"}}

func FuzzRedactNetworks(f *testing.F) {
	for i, s := range []string{"", `{}`, `{"Name":"bridge","Driver":"bridge"}`, `{"Labels":{"a":"b"}}`, `{"Labels":["a=b"]}`,
		`{"IPAM":{"Config":[{"Subnet":"10.0.0.0/8"}]}}`, `{"Containers":{"x":{"Name":"w"}}}`} {
		f.Add(s, uint8(i), uint8(i))
	}
	f.Fuzz(func(t *testing.T, raw string, sh, where uint8) {
		n := obj{"Name": "bridge", "Id": "n1"}
		if !mergeRaw(n, raw) {
			return
		}
		spot := networkSpots[int(where)%len(networkSpots)]
		plant(n, spot, shape(sh, "token"))
		in, err := json.Marshal([]any{n})
		if err != nil {
			return
		}
		out, err := RedactNetworks(in)
		if err != nil {
			t.Fatalf("valid doc rejected: %v", err)
		}
		if strings.Contains(string(out), canary) {
			t.Fatalf("canary leaked via %v:\n%s", spot, out)
		}
		var v []obj
		if json.Unmarshal(out, &v) != nil || len(v) != 1 {
			t.Fatal("invalid output")
		}
		checkKeys(t, v[0], networkTop, "network")
	})
}

var infoSpots = [][]string{{"HTTPProxy"}, {"HTTPSProxy"}, {"NoProxy"}, {"Labels"}}

func FuzzRedactInfo(f *testing.F) {
	for i, s := range []string{"", `{}`, `{"ID":"x","ServerVersion":"27.5.1"}`, `{"Labels":["a=b","bare"]}`, `{"Labels":{"a":"b"}}`,
		`{"Labels":"x=y"}`, `{"Labels":[1,{"a":"b"}]}`} {
		f.Add(s, uint8(i), uint8(i))
	}
	f.Fuzz(func(t *testing.T, raw string, sh, where uint8) {
		o := obj{"ID": "x"}
		if !mergeRaw(o, raw) {
			return
		}
		spot := infoSpots[int(where)%len(infoSpots)]
		plant(o, spot, shape(sh, "token"))
		in, err := json.Marshal(o)
		if err != nil {
			return
		}
		out, err := RedactInfo(in)
		if err != nil {
			t.Fatalf("valid doc rejected: %v", err)
		}
		if strings.Contains(string(out), canary) {
			t.Fatalf("canary leaked via %v:\n%s", spot, out)
		}
		var v obj
		if json.Unmarshal(out, &v) != nil {
			t.Fatal("invalid output")
		}
		for k := range infoDrop {
			if _, ok := v[k]; ok {
				t.Fatalf("%s survived", k)
			}
		}
	})
}

// Raw byte-level fuzz of all three decoders: garbage must error, never panic, and never yield
// non-JSON output.
func FuzzRedactRaw(f *testing.F) {
	for _, s := range []string{"[]", "[{}]", "{}", `[{"Id":"a"}]`, `{"Labels":["a=b"]}`, `[{"Config":{"Labels":{"a":1}}}]`, "[1]", "null", `[{"State":null}]`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, fn := range []func([]byte) ([]byte, error){RedactContainers, RedactNetworks, RedactInfo} {
			out, err := fn([]byte(s))
			if err == nil && !json.Valid(out) {
				t.Fatalf("invalid JSON out for %q", s)
			}
		}
	})
}
