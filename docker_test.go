package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/auditsh/internal/dockerpolicy"
)

// The outer allowlist (auditsh) and the helper's own validator must agree on the core forms, and
// the outer layer must refuse every dangerous form on its own (defence in depth).
func TestDockerAllowlistLayer(t *testing.T) {
	c := defaultCfg(t)
	now := time.Unix(1700007200, 0) // fixed: absolute times below must stay within the 7-day lookback
	for _, cmd := range []string{
		"docker ps", "docker ps -a", "docker images", "docker info", "docker version", "docker stats --no-stream",
		"docker network ls", "docker volume ls", "docker inspect web-1", "docker network inspect bridge",
		"docker logs --tail 100 web_1", "docker logs --tail 1000 --since 2h web", "docker logs --tail 5 --since 1h abc123",
		"docker events --since 2h --until 1h", "docker events --since 1700000000 --until 1700003600",
	} {
		argv, err := parseCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.match(argv)
		if err != nil {
			t.Errorf("%q denied by allowlist: %v", cmd, err)
			continue
		}
		if !r.Docker || r.Path != dockerHelperPath {
			t.Errorf("%q matched non-docker rule %+v", cmd, r)
		}
		got := execArgv(r, argv[1:], "/usr/bin/sudo", "")
		want := append([]string{"/usr/bin/sudo", "-n", "--", dockerHelperPath}, argv[1:]...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q execArgv %q", cmd, got)
		}
		if _, err := dockerpolicy.Validate(argv[1:], now); err != nil {
			t.Errorf("%q allowed outside but denied by helper: %v", cmd, err)
		}
	}
	for _, cmd := range []string{
		"docker", "docker exec web sh", "docker run alpine", "docker cp web:/etc/shadow .", "docker rm web",
		"docker kill web", "docker restart web", "docker pull alpine", "docker build .", "docker system prune -f",
		"docker -H tcp://x ps", "docker --host unix:///x ps", "docker --context x ps", "docker --config /tmp ps",
		"docker ps --format '{{json .}}'", "docker ps -f name=x", "docker inspect -f '{{.Config.Env}}' web",
		"docker inspect --format x web", "docker inspect -H", "docker inspect --host", "docker inspect -web",
		"docker logs --tail=-1 web", "docker logs --tail -1 web", "docker logs --tail 0 web", "docker logs --tail all web",
		"docker logs --tail 10 -f web", "docker logs -f web", "docker logs --tail 10 --since -1h web",
		"docker events", "docker events --since 1h", "docker stats", "docker container ls", "docker inspect a b",
		"docker network create x", "docker volume rm x", "docker version --format x", "docker inspect web\x00",
		"DOCKER_HOST=tcp://x docker ps", "docker logs --tail 10 --since 1h -- web",
	} {
		if err := check(c, cmd); err == nil {
			t.Errorf("%q allowed by allowlist", cmd)
		}
	}
}

func TestDockerRuleConfig(t *testing.T) {
	for _, y := range []string{
		"commands:\n  - {name: docker, path: /usr/bin/docker, docker: true, args: [ps]}\n",
		"commands:\n  - {name: dock, path: /usr/local/sbin/auditsh-docker, docker: true, args: [ps]}\n",
		"commands:\n  - {name: docker, path: /usr/local/sbin/auditsh-docker, docker: true, sudo: true, args: [ps]}\n",
		"commands:\n  - {name: docker, path: /usr/local/sbin/auditsh-docker, args: [ps]}\n",
		"commands:\n  - {name: docker, path: /usr/local/sbin/auditsh-docker, sudo: true, args: [ps]}\n",
	} {
		if _, err := parseConfig([]byte(y)); err == nil {
			t.Errorf("accepted %q", y)
		}
	}
	ok := "commands:\n  - {name: docker, path: /usr/local/sbin/auditsh-docker, docker: true, args: [ps]}\n"
	if _, err := parseConfig([]byte(ok)); err != nil {
		t.Errorf("valid docker rule rejected: %v", err)
	}
}

// allowlist.yaml docker rules must be exactly the helper's policy table (no drift either way).
func TestDockerAllowlistMatchesPolicy(t *testing.T) {
	c := defaultCfg(t)
	want := map[string]bool{}
	for _, f := range dockerpolicy.Forms {
		want[strings.Join(f, "\x00")] = true
	}
	got := map[string]bool{}
	for _, r := range c.Rules["docker"] {
		var pats []string
		for _, a := range r.Args {
			src := strings.TrimSuffix(strings.TrimPrefix(a.re.String(), "^(?:"), ")$")
			pats = append(pats, src)
		}
		got[strings.Join(pats, "\x00")] = true
		if !r.Docker {
			t.Errorf("docker rule without docker: true: %q", pats)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("policy form missing from allowlist.yaml: %q", strings.ReplaceAll(k, "\x00", " "))
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("allowlist.yaml docker rule not in helper policy: %q", strings.ReplaceAll(k, "\x00", " "))
		}
	}
}
