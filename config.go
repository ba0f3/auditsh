package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"gopkg.in/yaml.v3"
)

// internalProcRead is the pseudo-path for rules served by Go's own /proc reader.
const internalProcRead = "internal:procread"

type rawRule struct {
	Name string   `yaml:"name"`
	Path string   `yaml:"path"`
	Sudo bool     `yaml:"sudo"`
	Args []string `yaml:"args"`
}

type rawConfig struct {
	Commands []rawRule `yaml:"commands"`
}

type argPattern struct {
	re      *regexp.Regexp
	literal string // non-empty when the pattern is a plain literal (only such patterns may match '-' args)
}

type rule struct {
	Name string
	Path string
	Sudo bool
	Args []argPattern
	ID   string // e.g. "ps#1" for logs
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

func loadConfig(path string, ownerUID uint32) (*config, error) {
	// The file and its parent directory must be owner-controlled.
	if err := checkOwnedSafe(filepath.Dir(path), ownerUID); err != nil {
		return nil, err
	}
	if err := checkOwnedSafe(path, ownerUID); err != nil {
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
		if r.Path == internalProcRead {
			if r.Sudo {
				return nil, fmt.Errorf("rule %d: internal rule cannot use sudo", i)
			}
		} else if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
			return nil, fmt.Errorf("rule %d: path must be absolute and clean: %q", i, r.Path)
		}
		nr := &rule{Name: r.Name, Path: r.Path, Sudo: r.Sudo}
		for _, p := range r.Args {
			re, err := regexp.Compile(`^(?:` + p + `)$`)
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad pattern %q: %w", i, p, err)
			}
			ap := argPattern{re: re}
			if regexp.QuoteMeta(p) == p {
				ap.literal = p
			}
			if p == "--" {
				return nil, fmt.Errorf("rule %d: '--' not allowed", i)
			}
			nr.Args = append(nr.Args, ap)
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
