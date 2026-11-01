package dockerpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Redaction is an ALLOWLIST: only the keys below survive; anything unknown (including fields a
// future docker adds) is dropped. Env, Cmd, Entrypoint, Args, Healthcheck commands, log-driver
// options and health-check output are never emitted; label values are replaced.

const redacted = "[redacted]"

type obj = map[string]any

var (
	containerTop = set("Id", "Created", "Path", "State", "Image", "Name", "RestartCount", "Driver",
		"Platform", "AppArmorProfile", "Mounts", "NetworkSettings", "HostConfig", "Config", "SizeRw", "SizeRootFs")
	containerConfig = set("Hostname", "Domainname", "User", "Image", "WorkingDir", "ExposedPorts", "Tty",
		"OpenStdin", "StopSignal", "Volumes", "Labels")
	containerHost = set("NetworkMode", "RestartPolicy", "Privileged", "CapAdd", "CapDrop", "SecurityOpt",
		"ReadonlyRootfs", "PidMode", "IpcMode", "UsernsMode", "UTSMode", "CgroupnsMode", "Memory", "MemorySwap",
		"NanoCpus", "CpuShares", "CpusetCpus", "PidsLimit", "PortBindings", "Binds", "Devices", "Runtime", "Init",
		"AutoRemove", "LogConfig", "Tmpfs", "ShmSize", "OomKillDisable", "Ulimits")
	containerState = set("Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead", "Pid", "ExitCode",
		"Error", "StartedAt", "FinishedAt", "Health")
	healthKeep = set("Status", "FailingStreak")
	networkTop = set("Name", "Id", "Created", "Scope", "Driver", "EnableIPv4", "EnableIPv6", "IPAM", "Internal",
		"Attachable", "Ingress", "ConfigFrom", "ConfigOnly", "Containers", "Options", "Labels", "Peers")
	infoDrop = set("HTTPProxy", "HTTPSProxy", "NoProxy")
)

func set(k ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range k {
		m[s] = true
	}
	return m
}

func keep(o obj, allow map[string]bool) obj {
	out := obj{}
	for k, v := range o {
		if allow[k] {
			out[k] = v
		}
	}
	return out
}

// maskValues masks every value of a label map. Any other shape (array, string, number...) is not
// what docker emits and could carry a value, so it is replaced whole (fail closed).
func maskValues(v any) any {
	m, ok := v.(obj)
	if !ok {
		if v == nil {
			return nil
		}
		return redacted
	}
	out := obj{}
	for k := range m {
		out[k] = redacted
	}
	return out
}

func decodeArray(b []byte) ([]obj, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var a []obj
	if err := d.Decode(&a); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data")
	}
	return a, nil
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetIndent("", "    ")
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RedactContainers filters `docker container inspect` JSON.
func RedactContainers(b []byte) ([]byte, error) {
	a, err := decodeArray(b)
	if err != nil {
		return nil, err
	}
	out := make([]obj, 0, len(a))
	for _, c := range a {
		r := keep(c, containerTop)
		if cfg, ok := r["Config"].(obj); ok {
			k := keep(cfg, containerConfig)
			if l, ok := k["Labels"]; ok {
				k["Labels"] = maskValues(l)
			}
			r["Config"] = k
		} else {
			delete(r, "Config")
		}
		if hc, ok := r["HostConfig"].(obj); ok {
			k := keep(hc, containerHost)
			if lc, ok := k["LogConfig"].(obj); ok {
				k["LogConfig"] = obj{"Type": lc["Type"]} // driver options may hold tokens (splunk, gelf...)
			}
			r["HostConfig"] = k
		} else {
			delete(r, "HostConfig")
		}
		if st, ok := r["State"].(obj); ok {
			k := keep(st, containerState)
			if h, ok := k["Health"].(obj); ok {
				k["Health"] = keep(h, healthKeep) // Health.Log = health-check command output
			}
			r["State"] = k
		} else {
			delete(r, "State")
		}
		r["AuditshRedacted"] = "allowlisted fields only; Env/Cmd/Entrypoint/Args/Healthcheck/LogConfig options removed, label values masked"
		out = append(out, r)
	}
	return encode(out)
}

// RedactNetworks filters `docker network inspect` JSON.
func RedactNetworks(b []byte) ([]byte, error) {
	a, err := decodeArray(b)
	if err != nil {
		return nil, err
	}
	out := make([]obj, 0, len(a))
	for _, n := range a {
		r := keep(n, networkTop)
		if l, ok := r["Labels"]; ok {
			r["Labels"] = maskValues(l)
		}
		out = append(out, r)
	}
	return encode(out)
}

// RedactInfo filters `docker info --format '{{json .}}'`: proxy settings (may embed credentials)
// are removed and engine label values masked. Info is daemon metadata, so this one is a denylist.
func RedactInfo(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var o obj
	if err := d.Decode(&o); err != nil {
		return nil, err
	}
	for k := range infoDrop {
		delete(o, k)
	}
	// Engine labels are a []string of k=v. Values are masked; non-string elements and any other
	// Labels shape are replaced whole (fail closed).
	if lv, present := o["Labels"]; present && lv != nil {
		l, ok := lv.([]any)
		if !ok {
			o["Labels"] = redacted
		} else {
			m := make([]any, len(l))
			for i, v := range l {
				s, ok := v.(string)
				if !ok {
					m[i] = redacted
					continue
				}
				if k, _, found := bytes.Cut([]byte(s), []byte("=")); found {
					m[i] = string(k) + "=" + redacted
				} else {
					m[i] = redacted // not k=v: unknown content, mask whole
				}
			}
			o["Labels"] = m
		}
	}
	return encode(o)
}
