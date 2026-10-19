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
		if err := AppendRun(path, RunRecord{Version: "1.19.0"}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := MarkRunStarted(path, fmt.Sprintf("exec-%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		if err := FinalizeRun(path, i%3, false, at.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := FinalizeRun(path, 0, false, at); err != ErrNoOpenRun {
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
	if !last.Started || last.ExecutionID != "exec-12" || *last.ExitCode != 0 {
		t.Fatalf("last record %+v", last)
	}
	if err := AppendRun(path, RunRecord{Version: "1.19.0"}); err != nil {
		t.Fatal(err)
	}
	if recs := ReadRuns(path); ClassifyRun(recs[len(recs)-1]) != RunOpen {
		t.Fatal("new record is not open")
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
	if err := AppendRun(path, RunRecord{Version: "1.19.0"}); err != nil {
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
