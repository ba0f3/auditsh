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
	 "Labels":["env=` + secret + `","bare"],"ServerVersion":"27.5.1"}`
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

func FuzzRedactContainers(f *testing.F) {
	f.Add(containerJSON)
	f.Fuzz(func(t *testing.T, s string) {
		out, err := RedactContainers([]byte(s))
		if err != nil {
			return
		}
		var v []map[string]any
		if json.Unmarshal(out, &v) != nil {
			t.Fatal("invalid output")
		}
		for _, c := range v {
			for _, k := range []string{"Args", "Env"} {
				if _, ok := c[k]; ok {
					t.Fatalf("%s survived", k)
				}
			}
			if cfg, ok := c["Config"].(map[string]any); ok {
				for k := range cfg {
					if !containerConfig[k] {
						t.Fatalf("Config.%s survived", k)
					}
				}
			}
		}
	})
}
