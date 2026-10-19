package updatestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Pointers is the frozen bootstrap read contract of state.json: the fields
// every bootstrap, including the first one ever shipped, must keep reading.
// Probation and Updater are only filled for schema 1; a higher schema is read
// as current/previous only and never as corrupt.
type Pointers struct {
	Schema    int
	Current   string
	Previous  string
	Probation string // probation version, "" when none (schema 1 only)
	// Updater bookkeeping (schema 1 only).
	UpdaterVersion  string
	UpdaterFailures int
}

// LoadPointers reads state.json for the bootstrap. Schema 1 must pass the
// full Validate (so the bootstrap and the updater agree on what is corrupt).
// A higher schema only needs a strict current; an invalid previous is
// dropped. The (p, corrupt, err) contract matches Load.
func LoadPointers(path string) (p *Pointers, corrupt bool, err error) {
	data, err := readBounded(path, maxStateSize)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case errors.Is(err, errUnreadable):
		return nil, true, nil
	case err != nil:
		return nil, false, err
	}
	p, derr := decodePointers(data)
	if derr != nil {
		return nil, true, nil
	}
	return p, false, nil
}

func decodePointers(data []byte) (*Pointers, error) {
	var head struct {
		Schema   int    `json:"schema"`
		Current  string `json:"current"`
		Previous string `json:"previous"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}
	switch {
	case head.Schema == SchemaVersion:
		s, err := decodeState(data)
		if err != nil {
			return nil, err
		}
		p := &Pointers{Schema: s.Schema, Current: s.Current, Previous: s.Previous,
			UpdaterVersion: s.Updater.Version, UpdaterFailures: s.Updater.ConsecutiveFailures}
		if s.Probation != nil {
			p.Probation = s.Probation.Version
		}
		return p, nil
	case head.Schema > SchemaVersion:
		if !validVersion(head.Current) {
			return nil, fmt.Errorf("invalid current %q", head.Current)
		}
		p := &Pointers{Schema: head.Schema, Current: head.Current}
		if validVersion(head.Previous) {
			p.Previous = head.Previous
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported schema %d", head.Schema)
	}
}

// Fallback reasons for the bootstrap's EnvBootstrapFallback. Reasons about a
// named version carry it after a colon (current_missing:1.20.0) so the agent
// can report update_pointer_invalid with update_from = that version.
const (
	FallbackStateMissing      = "state_missing"
	FallbackStateCorrupt      = "state_corrupt"
	FallbackStateUnreadable   = "state_unreadable"
	FallbackCurrentMissing    = "current_missing"
	FallbackCurrentIncomplete = "current_incomplete"
	FallbackStartFailed       = "start_failed"
	FallbackUpdaterFailed     = "updater_failed"
	FallbackNoUpdater         = "no_confirmed_updater"
	FallbackNothingRunnable   = "no_runnable_version"
)

// VersionDirUsable reports whether dir holds LauncherFile and AgentFile as
// non-empty regular files: what the bootstrap needs to launch a version.
// It is file presence only; integrity is the updater's manifest check
// (VerifyVersionDir), not the bootstrap's.
func VersionDirUsable(dir string) bool {
	for _, name := range []string{LauncherFile, AgentFile} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// FindSeed returns the newest usable seed\<v>\ version.
func (l Layout) FindSeed() (Version, bool) {
	entries, err := os.ReadDir(filepath.Join(l.InstallRoot, "seed"))
	if err != nil {
		return Version{}, false
	}
	var best Version
	found := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v, err := ParseVersion(e.Name())
		if err != nil || !VersionDirUsable(l.SeedDir(v)) {
			continue
		}
		if !found || Compare(v, best) > 0 {
			best, found = v, true
		}
	}
	return best, found
}

// RunChoice is one launchable directory in the bootstrap's run order.
type RunChoice struct {
	Version Version
	Dir     string
	Reason  string // why this is not the state's current; "" when it is
}

// LoadReason maps a LoadPointers/Load result to a fallback reason, "" when
// a state was read.
func LoadReason(found bool, corrupt bool, err error) string {
	switch {
	case err != nil:
		return FallbackStateUnreadable
	case corrupt:
		return FallbackStateCorrupt
	case !found:
		return FallbackStateMissing
	}
	return ""
}

// CheckVersionDir validates versions\<s>\ and returns its version, or the
// fallback reason (current_missing / current_incomplete) it is unusable.
func (l Layout) CheckVersionDir(s string) (Version, string) {
	v, err := ParseVersion(s)
	if err != nil {
		return Version{}, FallbackCurrentMissing + ":" + s
	}
	dir := l.VersionDir(v)
	if _, err := os.Lstat(dir); err != nil {
		return Version{}, FallbackCurrentMissing + ":" + s
	}
	if !VersionDirUsable(dir) {
		return Version{}, FallbackCurrentIncomplete + ":" + s
	}
	return v, ""
}

// ResolveRunChain orders current → previous → seed, skipping unusable
// directories. p is the LoadPointers result (nil when missing or corrupt);
// stateReason is LoadReason of that load. Every choice after the state's
// current carries the reason current was not used.
func ResolveRunChain(l Layout, p *Pointers, stateReason string) []RunChoice {
	var out []RunChoice
	seen := map[Version]bool{}
	reason := stateReason
	if p != nil {
		if v, why := l.CheckVersionDir(p.Current); why == "" {
			out = append(out, RunChoice{Version: v, Dir: l.VersionDir(v)})
			seen[v] = true
		} else {
			reason = why
		}
		if p.Previous != "" && p.Previous != p.Current {
			if v, why := l.CheckVersionDir(p.Previous); why == "" && !seen[v] {
				out = append(out, RunChoice{Version: v, Dir: l.VersionDir(v), Reason: reason})
				seen[v] = true
			}
		}
	}
	if v, ok := l.FindSeed(); ok {
		out = append(out, RunChoice{Version: v, Dir: l.SeedDir(v), Reason: reason})
	}
	return out
}

// ResolveRunVersion is the version a scan launched now would run for st
// (nil = missing or corrupt state), with the fallback reason ("" when it is
// st.Current). With nothing runnable it returns the zero Version and
// FallbackNothingRunnable.
func ResolveRunVersion(l Layout, st *State) (Version, string) {
	var p *Pointers
	if st != nil {
		p = &Pointers{Schema: st.Schema, Current: st.Current, Previous: st.Previous}
	}
	chain := ResolveRunChain(l, p, LoadReason(st != nil, false, nil))
	if len(chain) == 0 {
		return Version{}, FallbackNothingRunnable
	}
	return chain[0].Version, chain[0].Reason
}
