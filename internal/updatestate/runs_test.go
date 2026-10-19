package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunRecordsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs", "1.19.0.json")
	if recs := ReadRuns(path); recs != nil {
		t.Fatalf("missing file = %v", recs)
	}
	if err := MarkRunStarted(path, "x"); err != ErrNoOpenRun {
		t.Fatalf("MarkRunStarted on empty = %v", err)
	}
	if err := AppendRun(path, RunRecord{Version: "bad"}); err == nil {
		t.Fatal("AppendRun accepted a bad version")
	}
	at := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)
	for i := 0; i < 13; i++ {
		id := fmt.Sprintf("run-%d", i)
		if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := MarkRunStarted(path, id); err != nil {
				t.Fatal(err)
			}
		}
		if err := FinalizeRun(path, id, i%3, false, at.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := FinalizeRun(path, "run-12", 0, false, at); err != ErrNoOpenRun {
		t.Fatalf("FinalizeRun with no open record = %v", err)
	}
	recs := ReadRuns(path)
	if len(recs) != MaxRunRecords {
		t.Fatalf("kept %d records, want %d", len(recs), MaxRunRecords)
	}
	first, last := recs[0], recs[len(recs)-1]
	if !first.At.Equal(at.Add(3*time.Minute)) || !last.At.Equal(at.Add(12*time.Minute)) {
		t.Fatalf("kept the wrong window: %v .. %v", first.At, last.At)
	}
	if !last.Started || last.RunID != "run-12" || *last.ExitCode != 0 {
		t.Fatalf("last record %+v", last)
	}
	if err := AppendRun(path, RunRecord{RunID: "run-13", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); ClassifyRun(recs[len(recs)-1]) != RunOpen {
		t.Fatal("new record is not open")
	}
}

// R-F1-1: overlapping launches (hourly + logon on wake) each keep their own
// record, whatever order they start and finish in.
func TestOverlappingRunsMatchByRunID(t *testing.T) {
	at := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	for _, aFirst := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "1.19.0.json")
		for _, id := range []string{"A", "B"} {
			if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
				t.Fatal(err)
			}
		}
		finalizeA := func() {
			if err := MarkRunStarted(path, "A"); err != nil {
				t.Fatalf("mark A: %v", err)
			}
			if err := FinalizeRun(path, "A", 0, false, at); err != nil {
				t.Fatalf("finalize A: %v", err)
			}
		}
		finalizeB := func() {
			if err := FinalizeRun(path, "B", 1, false, at); err != nil {
				t.Fatalf("finalize B: %v", err)
			}
		}
		if aFirst {
			finalizeA()
			finalizeB()
		} else {
			finalizeB()
			finalizeA()
		}
		got := map[string]RunVerdict{}
		for _, r := range ReadRuns(path) {
			got[r.RunID] = ClassifyRun(r)
		}
		if got["A"] != RunHealthy || got["B"] != RunNeutral {
			t.Fatalf("aFirst=%v verdicts = %v, want A healthy, B neutral", aFirst, got)
		}
		if err := MarkRunStarted(path, "A"); err != ErrNoOpenRun {
			t.Fatalf("closed record reopened: %v", err)
		}
		if err := MarkRunStarted(path, ""); err != ErrNoOpenRun {
			t.Fatalf("empty run id matched: %v", err)
		}
	}
}

// D13: a record without a run_id, or with one already in the file, could
// never be matched (or would be matched twice), so AppendRun refuses it.
func TestAppendRunRequiresUniqueRunID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.19.0.json")
	if err := AppendRun(path, RunRecord{Version: "1.19.0"}); err == nil {
		t.Fatal("empty run_id accepted")
	}
	if err := AppendRun(path, RunRecord{RunID: "A", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if err := AppendRun(path, RunRecord{RunID: "A", Version: "1.19.0"}); err == nil {
		t.Fatal("duplicate run_id accepted")
	}
	if recs := ReadRuns(path); len(recs) != 1 {
		t.Fatalf("records = %+v", recs)
	}
}

func TestReadRunsToleratesGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "1.19.0.json")
	for _, body := range []string{"", "garbage", "[]", `{"records":"x"}`, `{"records":[{"version":1}]}`,
		`{"records":[{"version":"1.19.0","exit_code":"x"}]}`, `{"records":[{"version":"../x"}]}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if recs := ReadRuns(path); recs != nil {
			t.Errorf("ReadRuns(%q) = %+v, want none", body, recs)
		}
	}
	// Garbage is replaced, not appended to.
	if err := AppendRun(path, RunRecord{RunID: "r1", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); len(recs) != 1 {
		t.Fatalf("after append over garbage: %+v", recs)
	}
	// Records with bad versions are dropped individually.
	body := `{"records":[{"version":"1.19.0","started":true,"exit_code":0},{"version":"x"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); len(recs) != 1 || !recs[0].Started {
		t.Fatalf("mixed file: %+v", recs)
	}
	big := make([]byte, maxRunsSize+1)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); recs != nil {
		t.Fatalf("oversize file read as %d records", len(recs))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); recs != nil {
		t.Fatal("directory read as records")
	}
}

func TestClassifyRun(t *testing.T) {
	code := func(c int) *int { return &c }
	for _, tc := range []struct {
		name string
		r    RunRecord
		want RunVerdict
	}{
		{"open", RunRecord{}, RunOpen},
		{"open started", RunRecord{Started: true}, RunOpen},
		{"watchdog while open", RunRecord{WatchdogKilled: true}, RunBad},
		{"healthy", RunRecord{Started: true, ExitCode: code(0)}, RunHealthy},
		{"healthy error exit", RunRecord{Started: true, ExitCode: code(1)}, RunHealthy},
		{"panic after start", RunRecord{Started: true, ExitCode: code(2)}, RunBad},
		{"watchdog after start", RunRecord{Started: true, ExitCode: code(0), WatchdogKilled: true}, RunBad},
		{"panic before start", RunRecord{ExitCode: code(2)}, RunBad},
		{"crash before start", RunRecord{ExitCode: code(-1073741819)}, RunBad},
		{"crash code before start", RunRecord{ExitCode: code(3221225477)}, RunBad},
		{"offline or lock held", RunRecord{ExitCode: code(1)}, RunNeutral},
		{"clean exit without marker", RunRecord{ExitCode: code(0)}, RunNeutral},
	} {
		if got := ClassifyRun(tc.r); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// D17: trimming to the last MaxRunRecords evicts the oldest CLOSED records
// first; a record still open (its launch is running) is never evicted, so
// its own finalize/marker still finds it.
func TestTrimNeverEvictsOpenRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1.19.0.json")
	at := time.Date(2026, 10, 19, 1, 0, 0, 0, time.UTC)
	if err := AppendRun(path, RunRecord{RunID: "long-running", Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxRunRecords+3; i++ {
		id := fmt.Sprintf("r%d", i)
		if err := AppendRun(path, RunRecord{RunID: id, Version: "1.19.0"}); err != nil {
			t.Fatal(err)
		}
		if err := FinalizeRun(path, id, 0, false, at); err != nil {
			t.Fatal(err)
		}
	}
	recs := ReadRuns(path)
	if len(recs) != MaxRunRecords || recs[0].RunID != "long-running" || recs[len(recs)-1].RunID != fmt.Sprintf("r%d", MaxRunRecords+2) {
		t.Fatalf("kept %d records: first %q last %q", len(recs), recs[0].RunID, recs[len(recs)-1].RunID)
	}
	if err := MarkRunStarted(path, "long-running"); err != nil {
		t.Fatalf("open record evicted: %v", err)
	}
	if err := FinalizeRun(path, "long-running", 0, false, at); err != nil {
		t.Fatalf("open record evicted: %v", err)
	}
}
