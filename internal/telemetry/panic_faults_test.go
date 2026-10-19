//go:build selfupdate_faults

package telemetry

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// FR1-2: a real panic in the scan, before or after run-status "started",
// is recovered by Run but must end the process as a crash (exit 2), so the
// run record classifies Bad, never Healthy or Neutral.
func TestScanPanicIsABadRun(t *testing.T) {
	for _, cp := range []string{"scan.before-started", "scan.after-started"} {
		t.Run(cp, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer srv.Close()
			defer withEnterpriseConfig(t, srv.URL)()
			t.Setenv(paths.HomeEnvVar, t.TempDir())
			target := filepath.Join(t.TempDir(), "test.flock")
			if runtime.GOOS == "windows" {
				target = fmt.Sprintf("dmg-panic-test-%d-%d", os.Getpid(), time.Now().UnixNano())
			}
			defer lock.SetTargetForTest(target)()

			runs := filepath.Join(t.TempDir(), "runs", "1.20.0.json")
			if err := updatestate.AppendRun(runs, updatestate.RunRecord{RunID: "r1", Version: "1.20.0"}); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvRunRecord, runs)
			t.Setenv(EnvRunID, "r1")
			t.Setenv("DMG_FAULT", cp+":panic")

			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformLinux)
			mock.SetFile("/sys/class/dmi/id/product_serial", []byte("SER-TEST-123\n"))
			err := Run(mock, progress.NewLogger(progress.LevelError), &cli.Config{SearchDirs: []string{t.TempDir()}})
			if !errors.Is(err, ErrPanic) {
				t.Fatalf("Run = %v, want ErrPanic", err)
			}
			code := ExitCode(err)
			if err := updatestate.FinalizeRun(runs, "r1", code, false, time.Now()); err != nil {
				t.Fatal(err)
			}
			rec := updatestate.ReadRuns(runs)[0]
			if v := updatestate.ClassifyRun(rec); v != updatestate.RunBad {
				t.Fatalf("panic %s: exit %d, started=%v → verdict %v, want Bad", cp, code, rec.Started, v)
			}
		})
	}
}
