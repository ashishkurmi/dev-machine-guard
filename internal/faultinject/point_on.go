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

// parse splits a spec list. Every entry must be <checkpoint>[@user|@system]:<action>
// with a known action; the action is split off the last ':' because
// checkpoint names contain ':' (S4.downloaded:<asset>).
func parse(spec string) ([]rule, error) {
	var rules []rule
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		i := strings.LastIndexByte(entry, ':')
		if i <= 0 || i == len(entry)-1 {
			return nil, fmt.Errorf("entry %q: want <checkpoint>:<action>", entry)
		}
		r := rule{checkpoint: entry[:i], action: entry[i+1:]}
		if !validAction(r.action) {
			return nil, fmt.Errorf("entry %q: unknown action %q", entry, r.action)
		}
		if j := strings.LastIndexByte(r.checkpoint, '@'); j >= 0 {
			switch p := r.checkpoint[j+1:]; p {
			case "user", "system":
				r.principal, r.checkpoint = p, r.checkpoint[:j]
			default:
				return nil, fmt.Errorf("entry %q: unknown principal qualifier %q (want @user or @system)", entry, p)
			}
		}
		if r.checkpoint == "" {
			return nil, fmt.Errorf("entry %q: empty checkpoint", entry)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func validAction(a string) bool {
	switch a {
	case "kill", "err", "hang", "diskfull":
		return true
	}
	n, ok := strings.CutPrefix(a, "exit")
	code, err := strconv.Atoi(n)
	return ok && err == nil && code >= 0
}

// Point acts on the first fault configured for name, if any. A malformed
// DMG_FAULT or Baked spec panics: a typo must never let a fault test pass
// without injecting anything.
func Point(name string) error {
	trace(name)
	rules, err := parse(Baked + "," + os.Getenv(envFault))
	if err != nil {
		panic(fmt.Sprintf("faultinject: invalid %s/Baked fault spec: %v", envFault, err))
	}
	for _, r := range rules {
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
