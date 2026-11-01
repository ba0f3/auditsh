package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"syscall"

	"gopkg.in/yaml.v3"
)

// internalProcRead is the pseudo-path for rules served by Go's own /proc reader.
const internalProcRead = "internal:procread"

// dockerHelperPath is the only path a docker: true rule may use (root-owned helper, deploy/docker/README.md).
const dockerHelperPath = "/usr/local/sbin/auditsh-docker"

type rawRule struct {
	Name    string   `yaml:"name"`
	Path    string   `yaml:"path"`
	Sudo    bool     `yaml:"sudo"`
	JVM     bool     `yaml:"jvm"`
	Docker  bool     `yaml:"docker"`
	Resolve bool     `yaml:"resolve"`
	Args    []string `yaml:"args"`
}

type rawConfig struct {
	Commands []rawRule `yaml:"commands"`
}

type argPattern struct {
	re      *regexp.Regexp
	literal string // non-empty when the pattern is a plain literal (only such patterns may match '-' args)
}

type rule struct {
	Name    string
	Path    string
	Sudo    bool
	Resolve bool // path may be a root-owned symlink chain (checkChain); exec the original path
	JVM     bool // run <Path> (the auditsh-jvm helper) via sudo as the target pid's owner
	Docker  bool // run <Path> (the auditsh-docker helper) via sudo as root; the helper re-validates argv
	Args    []argPattern
	ID      string // e.g. "ps#1" for logs
}

type config struct {
	Rules map[string][]*rule
	Order []string
}

// checkOwnedSafe refuses files that are not owned by ownerUID or are group/world writable.
func checkOwnedSafe(path string, ownerUID uint32) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: is a symlink", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot stat owner")
	}
	if st.Uid != ownerUID {
		return fmt.Errorf("%s: owner uid %d, want %d", path, st.Uid, ownerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/world writable (%v)", path, fi.Mode().Perm())
	}
	return nil
}

// checkTree checks path and every parent directory up to "/": none may be a symlink or
// group/world-writable, and each must be owned by root or ownerUID (both 0 in production).
func checkTree(path string, ownerUID uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s: not absolute/clean", path)
	}
	if err := checkOwnedSafe(path, ownerUID); err != nil {
		return err
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		err := checkOwnedSafe(d, ownerUID)
		if err != nil && ownerUID != 0 {
			err = checkOwnedSafe(d, 0)
		}
		if err != nil {
			return err
		}
		if d == "/" {
			return nil
		}
	}
}

func loadConfig(path string, ownerUID uint32) (*config, error) {
	if err := checkTree(path, ownerUID); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func parseConfig(b []byte) (*config, error) {
	var rc rawConfig
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c := &config{Rules: map[string][]*rule{}}
	for i, r := range rc.Commands {
		if !nameRE.MatchString(r.Name) {
			return nil, fmt.Errorf("rule %d: bad name %q", i, r.Name)
		}
		internal := r.Path == internalProcRead || r.Path == internalFileRead
		if internal {
			if r.Sudo || r.Resolve {
				return nil, fmt.Errorf("rule %d: internal rule cannot use sudo", i)
			}
		} else if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
			return nil, fmt.Errorf("rule %d: path must be absolute and clean: %q", i, r.Path)
		}
		if r.JVM && (r.Sudo || r.Resolve || internal || !jvmTools[r.Name]) {
			return nil, fmt.Errorf("rule %d: jvm rule must be jcmd/jstat, not sudo/internal", i)
		}
		if r.Docker && (r.Sudo || r.JVM || r.Resolve || r.Name != "docker" || r.Path != dockerHelperPath) {
			return nil, fmt.Errorf("rule %d: docker rule must be name docker, path %s, not sudo/jvm/resolve", i, dockerHelperPath)
		}
		if !r.Docker && r.Path == dockerHelperPath {
			return nil, fmt.Errorf("rule %d: %s only via docker: true", i, dockerHelperPath)
		}
		if r.Resolve && (!resolveNames[r.Name] || r.Path != "/usr/sbin/"+r.Name) {
			return nil, fmt.Errorf("rule %d: resolve only for /usr/sbin/{iptables,ip6tables}[-save]", i)
		}
		if r.Path == internalFileRead && (len(r.Args) != 1 || !osFiles[r.Args[0]]) {
			return nil, fmt.Errorf("rule %d: fileread rule needs exactly one fixed os file path", i)
		}
		nr := &rule{Name: r.Name, Path: r.Path, Sudo: r.Sudo, JVM: r.JVM, Docker: r.Docker, Resolve: r.Resolve}
		for _, p := range r.Args {
			re, err := regexp.Compile(`^(?:` + p + `)$`)
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad pattern %q: %w", i, p, err)
			}
			ap := argPattern{re: re}
			if lit, ok := literalOf(p); ok {
				ap.literal = lit
			}
			if p == "--" {
				return nil, fmt.Errorf("rule %d: '--' not allowed", i)
			}
			nr.Args = append(nr.Args, ap)
		}
		if r.JVM {
			npid := 0
			for _, a := range nr.Args {
				if a.literal == "" && a.re.String() == `^(?:`+jvmPidPattern+`)$` {
					npid++
				}
			}
			if npid != 1 {
				return nil, fmt.Errorf("rule %d: jvm rule needs exactly one pid arg %q", i, jvmPidPattern)
			}
			if r.Name == "jcmd" {
				for j, a := range nr.Args {
					if j != 0 || a.literal != "" || a.re.String() != `^(?:`+jvmPidPattern+`)$` {
						if j == 0 || a.literal == "" {
							return nil, fmt.Errorf("rule %d: jcmd verb/option %q must be an exact literal after the pid (escape '.')", i, r.Args[j])
						}
					}
				}
			}
		}
		if _, ok := c.Rules[r.Name]; !ok {
			c.Order = append(c.Order, r.Name)
		}
		nr.ID = fmt.Sprintf("%s#%d", r.Name, len(c.Rules[r.Name]))
		c.Rules[r.Name] = append(c.Rules[r.Name], nr)
	}
	if len(c.Rules) == 0 {
		return nil, errors.New("config has no commands")
	}
	return c, nil
}

// literalOf reports whether pattern p matches exactly one string (e.g. `GC\.heap_info`), and returns it.
func literalOf(p string) (string, bool) {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return "", false
	}
	re = re.Simplify()
	if re.Op != syntax.OpLiteral || re.Flags&syntax.FoldCase != 0 {
		return "", false
	}
	return string(re.Rune), true
}
