//go:build selfupdate_faults

package faultinject

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Enabled reports whether fault injection is compiled in.
const Enabled = true

// Baked holds faults set at link time
// (-ldflags "-X github.com/step-security/dev-machine-guard/internal/faultinject.Baked=<spec>").
// It is merged with DMG_FAULT, Baked first.
var Baked string

const (
	envFault = "DMG_FAULT"
	envTrace = "DMG_FAULT_TRACE"
)

// exit and isSystem are swapped by tests.
var (
	exit     = os.Exit
	isSystem = runningAsSystem
)

type rule struct {
	checkpoint string
	principal  string // "", "user" or "system"
	action     string
}

// parse splits a spec list; malformed entries are returned as rules with an
// empty checkpoint so Point can report them instead of silently ignoring them.
func parse(spec string) []rule {
	var rules []rule
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		i := strings.LastIndexByte(entry, ':')
		if i <= 0 || i == len(entry)-1 {
			rules = append(rules, rule{action: entry})
			continue
		}
		r := rule{checkpoint: entry[:i], action: entry[i+1:]}
		if j := strings.LastIndexByte(r.checkpoint, '@'); j > 0 {
			switch p := r.checkpoint[j+1:]; p {
			case "user", "system":
				r.principal, r.checkpoint = p, r.checkpoint[:j]
			}
		}
		rules = append(rules, r)
	}
	return rules
}

// Point acts on the first fault configured for name, if any.
func Point(name string) error {
	trace(name)
	for _, r := range parse(Baked + "," + os.Getenv(envFault)) {
		if r.checkpoint == "" {
			return fmt.Errorf("%w: malformed %s entry %q", ErrInjected, envFault, r.action)
		}
		if r.checkpoint != name {
			continue
		}
		if r.principal != "" && (r.principal == "system") != isSystem() {
			continue
		}
		return act(name, r.action)
	}
	return nil
}

func act(name, action string) error {
	switch action {
	case "kill":
		exit(137)
	case "err":
		return fmt.Errorf("%w: err at %s", ErrInjected, name)
	case "diskfull":
		return fmt.Errorf("%w: diskfull at %s: %w", ErrInjected, name, errDiskFull)
	case "hang":
		for {
			time.Sleep(time.Hour)
		}
	default:
		if n, ok := strings.CutPrefix(action, "exit"); ok {
			if code, err := strconv.Atoi(n); err == nil && code >= 0 {
				exit(code)
				return nil // only reached when exit is stubbed
			}
		}
		return fmt.Errorf("%w: unknown action %q at %s", ErrInjected, action, name)
	}
	return nil // only reached when exit is stubbed
}

func trace(name string) {
	path := os.Getenv(envTrace)
	if path == "" {
		return
	}
	// #nosec G304 -- test-only trace file chosen by the harness.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(name + "\n")
	_ = f.Close()
}
