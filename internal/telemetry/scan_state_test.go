package telemetry

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/state"
)

func tempStateFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "scan-state.json")
}

func nodeResult(path, pm string, stdout string) model.NodeScanResult {
	return model.NodeScanResult{
		ProjectPath:     path,
		PackageManager:  pm,
		PMVersion:       "10.2.0",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		ExitCode:        0,
	}
}

func nodeGlobal(pm, stdout string, exit int) model.NodeScanResult {
	return model.NodeScanResult{
		PackageManager:  pm,
		PMVersion:       "10.2.0",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		ExitCode:        exit,
	}
}

func TestCommitScanState_FirstRunPopulatesState(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	npm := []model.NodeScanResult{
		nodeResult("/svc-api", "npm", `{"deps":{"x":"1.0"}}`),
		nodeResult("/svc-web", "npm", `{"deps":{"y":"2.0"}}`),
	}
	discovered := []string{"/svc-api", "/svc-web"}

	commitScanState(log, s, path, "exec-1", npm, discovered, nil, nil, nil, nil, false)

	reloaded, err := state.Load(path, buildinfo.Version)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(reloaded.NPMProjects) != 2 {
		t.Errorf("expected 2 npm entries, got %d", len(reloaded.NPMProjects))
	}
	if reloaded.LastSuccessfulExecutionID != "exec-1" {
		t.Errorf("execution_id not stamped: %s", reloaded.LastSuccessfulExecutionID)
	}
}

func TestCommitScanState_SecondRunSameHashesStaysUnchanged(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	npm := []model.NodeScanResult{nodeResult("/svc", "npm", `{"deps":{"x":"1.0"}}`)}
	discovered := []string{"/svc"}

	commitScanState(log, s, path, "exec-1", npm, discovered, nil, nil, nil, nil, false)

	s2, _ := state.Load(path, buildinfo.Version)
	prevEntry := s2.NPMProjects["/svc"]

	commitScanState(log, s2, path, "exec-2", npm, discovered, nil, nil, nil, nil, false)

	s3, _ := state.Load(path, buildinfo.Version)
	if s3.NPMProjects["/svc"].ScanOutputHash != prevEntry.ScanOutputHash {
		t.Errorf("identical input should produce identical hash")
	}
	if s3.LastSuccessfulExecutionID != "exec-2" {
		t.Errorf("expected exec-2, got %s", s3.LastSuccessfulExecutionID)
	}
}

func TestCommitScanState_RemovedProjectGoesIntoPendingAck(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	// First run: two projects on disk.
	npm := []model.NodeScanResult{
		nodeResult("/a", "npm", `{"x":1}`),
		nodeResult("/b", "npm", `{"y":2}`),
	}
	commitScanState(log, s, path, "exec-1", npm, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	// Second run: /b is gone from disk.
	s2, _ := state.Load(path, buildinfo.Version)
	npm2 := []model.NodeScanResult{nodeResult("/a", "npm", `{"x":1}`)}
	commitScanState(log, s2, path, "exec-2", npm2, []string{"/a"}, nil, nil, nil, nil, false)

	s3, _ := state.Load(path, buildinfo.Version)
	pending := s3.PendingRemovalsFor(state.EcosystemNPM)
	if len(pending) != 1 || pending[0].Path != "/b" {
		t.Errorf("expected /b in pending removals, got %+v", pending)
	}
}

func TestCommitScanState_CapDroppedProjectIsNotMarkedRemoved(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	// First run: /a and /b both seen.
	npm := []model.NodeScanResult{
		nodeResult("/a", "npm", `{"x":1}`),
		nodeResult("/b", "npm", `{"y":2}`),
	}
	commitScanState(log, s, path, "exec-1", npm, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	// Second run: /b is still on disk (in `discovered`) but didn't get scanned
	// (e.g. capped). Must NOT be marked as removed.
	s2, _ := state.Load(path, buildinfo.Version)
	scanned := []model.NodeScanResult{nodeResult("/a", "npm", `{"x":1}`)}
	commitScanState(log, s2, path, "exec-2", scanned, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	s3, _ := state.Load(path, buildinfo.Version)
	if got := s3.PendingRemovalsFor(state.EcosystemNPM); len(got) != 0 {
		t.Errorf("cap-dropped project must not be marked removed: %+v", got)
	}
	if _, ok := s3.NPMProjects["/b"]; !ok {
		t.Errorf("cap-dropped project entry should be preserved")
	}
}

func TestCommitScanState_FailedScanDoesNotOverwriteHash(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	good := []model.NodeScanResult{nodeResult("/svc", "npm", `{"x":1}`)}
	commitScanState(log, s, path, "exec-1", good, []string{"/svc"}, nil, nil, nil, nil, false)
	goodHash := s.NPMProjects["/svc"].ScanOutputHash

	s2, _ := state.Load(path, buildinfo.Version)
	bad := []model.NodeScanResult{{
		ProjectPath:     "/svc",
		PackageManager:  "npm",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(`{"x":2}`)),
		ExitCode:        1,
	}}
	commitScanState(log, s2, path, "exec-2", bad, []string{"/svc"}, nil, nil, nil, nil, false)

	s3, _ := state.Load(path, buildinfo.Version)
	if s3.NPMProjects["/svc"].ScanOutputHash != goodHash {
		t.Errorf("failed scan must not overwrite prior hash: got %s want %s",
			s3.NPMProjects["/svc"].ScanOutputHash, goodHash)
	}
}

func TestCommitScanState_PythonRoundTrip(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	py := []model.ProjectInfo{
		{Path: "/proj/.venv", PackageManager: "pip", Packages: []model.PackageDetail{{Name: "django", Version: "5.0"}}},
	}
	commitScanState(log, s, path, "exec-1", nil, nil, py, []string{"/proj/.venv"}, nil, nil, false)

	reloaded, _ := state.Load(path, buildinfo.Version)
	if len(reloaded.PythonProjects) != 1 {
		t.Fatalf("expected 1 python entry, got %d", len(reloaded.PythonProjects))
	}
	if reloaded.PythonProjects["/proj/.venv"].PackageManager != "pip" {
		t.Errorf("PM not stored: %+v", reloaded.PythonProjects["/proj/.venv"])
	}
}

func TestCommitScanState_GlobalsAreTracked(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	globals := []model.NodeScanResult{
		nodeGlobal("npm", `{"dependencies":{"tsc":"5.0"}}`, 0),
		nodeGlobal("yarn", `{"dependencies":{"create-react-app":"5.0"}}`, 0),
	}
	commitScanState(log, s, path, "exec-1", nil, nil, nil, nil, globals, nil, false)

	reloaded, _ := state.Load(path, buildinfo.Version)
	if len(reloaded.NPMGlobal) != 2 {
		t.Errorf("expected 2 global entries, got %d", len(reloaded.NPMGlobal))
	}
	if reloaded.NPMGlobal["npm"].ScanOutputHash == "" {
		t.Errorf("npm global hash empty")
	}
}

func TestCommitScanState_FullSyncBumpsHorizon(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	log := progress.NewLogger(progress.LevelDebug)

	npm := []model.NodeScanResult{nodeResult("/svc", "npm", `{"x":1}`)}
	commitScanState(log, s, path, "exec-1", npm, []string{"/svc"}, nil, nil, nil, nil, true)

	reloaded, _ := state.Load(path, buildinfo.Version)
	if reloaded.LastFullSyncAt.IsZero() {
		t.Errorf("full-sync timestamp not refreshed")
	}
}
