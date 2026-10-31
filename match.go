package main

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/google/shlex"
)

const (
	maxCmdLen = 1024
	maxArgs   = 16
)

// Characters with shell meaning (other than quoting, which shlex handles) are rejected outright.
const shellMeta = ";&|`$<>(){}*?[]!~\\#"

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// parseCommand validates the raw SSH_ORIGINAL_COMMAND and splits it into argv.
func parseCommand(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("empty command")
	}
	if len(raw) > maxCmdLen {
		return nil, errors.New("command too long")
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x20 || c > 0x7e { // NUL, newline, tabs, controls, DEL, any non-ASCII/unicode
			return nil, errors.New("non-printable or non-ASCII byte")
		}
	}
	if strings.ContainsAny(raw, shellMeta) {
		return nil, errors.New("shell metacharacter")
	}
	argv, err := shlex.Split(raw)
	if err != nil {
		return nil, errors.New("unparseable quoting")
	}
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	if len(argv) > maxArgs+1 {
		return nil, errors.New("too many args")
	}
	return argv, nil
}

// match returns the first rule whose fixed arity and per-arg patterns all match.
func (c *config) match(argv []string) (*rule, error) {
	rules, ok := c.Rules[argv[0]]
	if !ok {
		return nil, errors.New("command not allowed")
	}
	args := argv[1:]
	for _, a := range args {
		if a == "" || a == "--" {
			return nil, errors.New("empty or '--' arg")
		}
	}
outer:
	for _, r := range rules {
		if len(r.Args) != len(args) {
			continue
		}
		for i, a := range args {
			p := r.Args[i]
			if strings.HasPrefix(a, "-") {
				if p.literal == "" || p.literal != a {
					continue outer
				}
				continue
			}
			if !p.re.MatchString(a) {
				continue outer
			}
		}
		return r, nil
	}
	return nil, errors.New("arguments not allowed")
}
