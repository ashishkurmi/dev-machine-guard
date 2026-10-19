package updatestate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// MaxRunRecords is how many run records a runs\<v>.json keeps.
const MaxRunRecords = 10

// maxRunsSize bounds what ReadRuns reads from the user-writable file.
const maxRunsSize = 64 << 10

// RunRecord is one bootstrap launch of a version. The bootstrap appends it,
// the agent sets Started (with its execution_id) right after a successful
// run-status "started", and the bootstrap finalizes ExitCode,
// WatchdogKilled and At. A nil ExitCode means not finalized yet.
type RunRecord struct {
	Version        string    `json:"version"`
	ExecutionID    string    `json:"execution_id,omitempty"`
	Started        bool      `json:"started"`
	ExitCode       *int      `json:"exit_code,omitempty"`
	WatchdogKilled bool      `json:"watchdog_killed,omitempty"`
	At             time.Time `json:"at,omitzero"`
}

type runFile struct {
	Records []RunRecord `json:"records"`
}

// ErrNoOpenRun means the run file has no unfinalized record to update.
var ErrNoOpenRun = errors.New("updatestate: no open run record")

// ReadRuns returns the newest MaxRunRecords records, oldest first. The file
// is user-writable, so anything unreadable or malformed reads as no records
// and records with an invalid version are dropped; it never fails.
func ReadRuns(path string) []RunRecord {
	data, err := readBounded(path, maxRunsSize)
	if err != nil {
		return nil
	}
	return decodeRuns(data)
}

func decodeRuns(data []byte) []RunRecord {
	var f runFile
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	out := f.Records[:0]
	for _, r := range f.Records {
		if validVersion(r.Version) {
			out = append(out, r)
		}
	}
	if len(out) > MaxRunRecords {
		out = out[len(out)-MaxRunRecords:]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func writeRuns(path string, recs []RunRecord) error {
	if len(recs) > MaxRunRecords {
		recs = recs[len(recs)-MaxRunRecords:]
	}
	data, err := json.Marshal(runFile{Records: recs})
	if err != nil {
		return err
	}
	// #nosec G301 -- runs\ is shared by the user scan and the SYSTEM updater.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, data, nil, nil)
}

// AppendRun appends r, keeping the newest MaxRunRecords.
func AppendRun(path string, r RunRecord) error {
	if !validVersion(r.Version) {
		return errors.New("updatestate: run record needs a strict x.y.z version")
	}
	return writeRuns(path, append(ReadRuns(path), r))
}

// MarkRunStarted sets the started marker on the newest open record.
func MarkRunStarted(path, executionID string) error {
	return updateOpenRun(path, func(r *RunRecord) {
		r.Started = true
		r.ExecutionID = executionID
	})
}

// FinalizeRun closes the newest open record.
func FinalizeRun(path string, exitCode int, watchdogKilled bool, at time.Time) error {
	return updateOpenRun(path, func(r *RunRecord) {
		r.ExitCode = &exitCode
		r.WatchdogKilled = watchdogKilled
		r.At = at.UTC()
	})
}

func updateOpenRun(path string, fn func(*RunRecord)) error {
	recs := ReadRuns(path)
	if len(recs) == 0 || ClassifyRun(recs[len(recs)-1]) != RunOpen {
		return ErrNoOpenRun
	}
	fn(&recs[len(recs)-1])
	return writeRuns(path, recs)
}

// RunVerdict is the health reading of one run record (spec §4).
type RunVerdict int

const (
	// RunOpen: not finalized (still running, or the bootstrap died).
	RunOpen RunVerdict = iota
	// RunHealthy: the started marker is set, no panic exit, no watchdog kill.
	RunHealthy
	// RunBad: a watchdog kill, exit code 2 (Go panic), or an exit before the
	// started marker with a crash-like code (anything but 0 or 1).
	RunBad
	// RunNeutral: exited 0 or 1 without the started marker. That is how the
	// agent ends when the backend is unreachable or another scan holds the
	// instance lock; spec §4 says environmental failures are not bad runs.
	RunNeutral
)

// panicExitCode is the exit status of an unrecovered Go panic (and of the
// agent's watchdog hard-out).
const panicExitCode = 2

// ClassifyRun applies the bad-run rule to one record.
func ClassifyRun(r RunRecord) RunVerdict {
	switch {
	case r.WatchdogKilled:
		return RunBad
	case r.ExitCode == nil:
		return RunOpen
	case *r.ExitCode == panicExitCode:
		return RunBad
	case r.Started:
		return RunHealthy
	case *r.ExitCode == 0 || *r.ExitCode == 1:
		return RunNeutral
	default:
		return RunBad
	}
}
