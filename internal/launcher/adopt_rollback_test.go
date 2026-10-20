package launcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

func (f *fixture) adoptFlag(flag string) {
	f.t.Helper()
	if code := f.b.AdoptSeed([]string{flag}); code != 0 {
		f.t.Fatalf("adopt-seed %s exit = %d", flag, code)
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// DMG-I5-2: a failed major upgrade rolls adopt-seed back: the pre-MSI
// current returns, the seed dir adopt-seed created goes, the snapshot goes.
func TestAdoptSeedRollback_RestoresUpgrade(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.4.0","future":"kept"}`)
	f.version("1.4.0")
	var running []string
	f.b.SetRunningVersion = func(v string) error { running = append(running, v); return nil }
	f.adopt(f.seed("1.5.0"))
	if f.load().Current != "1.5.0" {
		t.Fatal("seed not adopted")
	}
	// The MSI fails later and rolls back.
	if err := os.RemoveAll(filepath.Join(f.layout.InstallRoot, "seed", "1.5.0")); err != nil {
		t.Fatal(err)
	}
	f.adoptFlag("--rollback")
	st := f.load()
	if st.Current != "1.4.0" || st.Previous != "" || st.Extra["future"] == nil {
		t.Fatalf("state after rollback = %+v", st)
	}
	if exists(f.layout.VersionDir(updatestate.Version{Major: 1, Minor: 5})) {
		t.Fatal("versions\\1.5.0 created by adopt-seed was kept")
	}
	if exists(f.layout.AdoptSnapshotFile()) {
		t.Fatal("snapshot kept")
	}
	if running[len(running)-1] != "1.4.0" {
		t.Fatalf("RunningVersion = %v", running)
	}
}

// A first install that fails: no state existed, so none remains.
func TestAdoptSeedRollback_FreshInstall(t *testing.T) {
	f := newFixture(t)
	f.adopt(f.seed("1.5.0"))
	f.adoptFlag("--rollback")
	if exists(f.layout.StateFile()) || exists(f.layout.VersionDir(updatestate.Version{Major: 1, Minor: 5})) {
		t.Fatal("fresh install not rolled back")
	}
}

// A versions dir that existed before adopt-seed (e.g. self-updated earlier)
// is never removed by the rollback.
func TestAdoptSeedRollback_KeepsPreexistingDir(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.4.0"}`)
	f.version("1.4.0")
	f.adopt(f.seed("1.5.0")) // copies versions\1.5.0 (created)
	f.adoptFlag("--commit")
	if exists(f.layout.AdoptSnapshotFile()) {
		t.Fatal("commit kept the snapshot")
	}
	// A repair later: versions\1.5.0 already there, current already 1.5.0.
	f.adopt(f.seed("1.5.0"))
	f.adoptFlag("--rollback")
	if f.load().Current != "1.5.0" || !exists(f.layout.VersionDir(updatestate.Version{Major: 1, Minor: 5})) {
		t.Fatalf("repair rollback changed a pre-existing install: %+v", f.load())
	}
}

// A state written by someone else after adopt-seed (an updater tick) is
// not overwritten by the rollback.
func TestAdoptSeedRollback_SkipsIfStateMovedOn(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.4.0"}`)
	f.version("1.4.0")
	f.adopt(f.seed("1.5.0"))
	st := f.load()
	st.Current, st.Previous = "1.6.0", "1.5.0"
	f.version("1.6.0")
	if err := updatestate.Save(f.layout.StateFile(), st); err != nil {
		t.Fatal(err)
	}
	f.adoptFlag("--rollback")
	if got := f.load(); got.Current != "1.6.0" {
		t.Fatalf("rollback clobbered a newer state: %+v", got)
	}
	if !exists(f.layout.VersionDir(updatestate.Version{Major: 1, Minor: 5})) {
		t.Fatal("removed a version the newer state points at")
	}
}

// A stale snapshot (an MSI that ended without commit or rollback) is
// never applied, and is swept.
func TestAdoptSeedRollback_IgnoresStaleSnapshot(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.4.0"}`)
	f.version("1.4.0")
	f.adopt(f.seed("1.5.0"))
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(f.layout.AdoptSnapshotFile(), old, old); err != nil {
		t.Fatal(err)
	}
	f.adoptFlag("--rollback")
	if f.load().Current != "1.5.0" || exists(f.layout.AdoptSnapshotFile()) {
		t.Fatalf("stale snapshot applied or kept: %+v", f.load())
	}
}
