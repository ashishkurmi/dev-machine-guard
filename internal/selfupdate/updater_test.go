package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// env is one simulated MSI install plus a fake backend.
type env struct {
	t        *testing.T
	L        updatestate.Layout
	api      *fakeAPI
	now      time.Time
	self     string
	auto     bool
	pubErr   error
	smokeErr map[string]error
	busy     int // AcquireInstance fails this many more times
	sendErr  error
	drift    []string

	mu   sync.Mutex
	sent []updatestate.OutboxEvent // since the last events() call
	all  []updatestate.OutboxEvent
}

const testArch = "amd64"

func payload(kind, v string) []byte { return []byte(kind + "-" + v) }

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t: t, L: updatestate.Layout{InstallRoot: filepath.Join(root, "pf"), DataRoot: filepath.Join(root, "pd")},
		api: newFakeAPI(t), now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		self: "1.19.0", auto: true, smokeErr: map[string]error{},
	}
	for _, v := range []string{"1.18.0", "1.19.0", "1.20.0", "1.21.0"} {
		e.api.addRelease(v, testArch, payload("agent", v), payload("task", v), payload("linux", v))
	}
	e.api.setTarget("1.20.0")
	e.writeSeed("1.19.0")
	knobOverrides = map[knob]time.Duration{knobSwitchWait: 0}
	t.Cleanup(func() { knobOverrides = map[knob]time.Duration{} })
	return e
}

func (e *env) writeSeed(v string) {
	pv, _ := updatestate.ParseVersion(v)
	dir := e.L.SeedDir(pv)
	must(e.t, os.MkdirAll(dir, 0o755))
	for _, f := range []struct{ name, kind string }{{updatestate.AgentFile, "agent"}, {updatestate.LauncherFile, "task"}, {updatestate.LinuxFile, "linux"}} {
		must(e.t, os.WriteFile(filepath.Join(dir, f.name), payload(f.kind, v), 0o755))
	}
}

// installVersion writes a complete, manifest-checked versions\<v>.
func (e *env) installVersion(v string) {
	pv, _ := updatestate.ParseVersion(v)
	dir := e.L.VersionDir(pv)
	must(e.t, os.MkdirAll(dir, 0o755))
	m := updatestate.Manifest{Version: v, Files: map[string]string{}}
	for _, f := range []struct{ name, kind string }{{updatestate.AgentFile, "agent"}, {updatestate.LauncherFile, "task"}, {updatestate.LinuxFile, "linux"}} {
		b := payload(f.kind, v)
		must(e.t, os.WriteFile(filepath.Join(dir, f.name), b, 0o755))
		m.Files[f.name] = sum(b)
	}
	must(e.t, updatestate.WriteManifest(dir, m))
}

func (e *env) writeState(st *updatestate.State) {
	must(e.t, os.MkdirAll(e.L.StateDir(), 0o755))
	must(e.t, updatestate.Save(e.L.StateFile(), st))
}

func (e *env) state() *updatestate.State {
	st, corrupt, err := updatestate.Load(e.L.StateFile())
	if err != nil || corrupt || st == nil {
		e.t.Fatalf("state: %v corrupt=%v nil=%v", err, corrupt, st == nil)
	}
	return st
}

func (e *env) deps() *Deps {
	self, _ := updatestate.ParseVersion(e.self)
	return &Deps{
		Layout: e.L, Self: self, SelfExe: filepath.Join(e.L.VersionDir(self), updatestate.AgentFile),
		Client:     e.api.client(testArch),
		AutoUpdate: e.auto,
		VerifyPublisher: func(p string) error {
			if _, err := os.Stat(p); err != nil {
				return err
			}
			return e.pubErr
		},
		Smoke: func(_ context.Context, exe string, want updatestate.Version) error {
			if _, err := os.Stat(exe); err != nil {
				return err
			}
			return e.smokeErr[want.String()]
		},
		AcquireInstance: func() (func(), error) {
			if e.busy > 0 {
				e.busy--
				return nil, errors.New("held")
			}
			return func() {}, nil
		},
		EnsureACLs: func() ([]string, error) { d := e.drift; e.drift = nil; return d, nil },
		Send: func(_ context.Context, ev updatestate.OutboxEvent) error {
			if e.sendErr != nil {
				return e.sendErr
			}
			e.mu.Lock()
			e.sent = append(e.sent, ev)
			e.all = append(e.all, ev)
			e.mu.Unlock()
			return nil
		},
		Now:  func() time.Time { return e.now },
		Logf: func(f string, a ...any) { e.t.Logf("[updater] "+f, a...) },
	}
}

func (e *env) tick() int { e.t.Helper(); return Run(context.Background(), e.deps()) }

// events returns and clears the sent event names.
func (e *env) events() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.sent {
		out = append(out, ev.Event)
	}
	e.sent = nil
	return out
}

func (e *env) lastSent(event string) updatestate.OutboxEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.all) - 1; i >= 0; i-- {
		if e.all[i].Event == event {
			return e.all[i]
		}
	}
	e.t.Fatalf("no %s sent", event)
	return updatestate.OutboxEvent{}
}

// addRun appends a finalized run record for v.
func (e *env) addRun(v string, started bool, exit int) {
	pv, _ := updatestate.ParseVersion(v)
	must(e.t, updatestate.AppendRun(e.L.RunFile(pv), updatestate.RunRecord{RunID: uuid.NewString(), Version: v, Started: started, ExitCode: &exit, At: e.now}))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// assertHygiene is U6 on the versions dir.
func assertHygiene(t *testing.T, e *env) {
	t.Helper()
	st := e.state()
	allowed := map[string]bool{st.Current: true, st.Previous: true, e.self: true}
	if st.Probation != nil {
		allowed[st.Probation.Version] = true
	}
	for _, s := range seedVersions(e.L) {
		allowed[s.String()] = true
	}
	entries, _ := os.ReadDir(e.L.VersionsDir())
	for _, en := range entries {
		if updatestate.IsSweepable(en.Name()) || !allowed[en.Name()] {
			t.Errorf("leftover in versions: %s", en.Name())
		}
	}
}

func baseState(cur, prev string) *updatestate.State {
	return &updatestate.State{Schema: 1, Current: cur, Previous: prev}
}

func TestFreshInstallUpdatesThenConfirms(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))

	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventOK)
	ok := e.lastSent(EventOK)
	_ = ok
	st := e.state()
	if st.Current != "1.20.0" || st.Previous != "1.19.0" || st.Probation == nil || st.Probation.Version != "1.20.0" || len(st.Outbox) != 0 {
		t.Fatalf("after switch: %+v", st)
	}
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.20.0")), mustV("1.20.0")); err != nil {
		t.Fatal(err)
	}

	// Probation open: no target check, no events.
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events())

	e.addRun("1.20.0", true, 0)
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventConfirmed)
	if st := e.state(); st.Probation != nil || st.Current != "1.20.0" {
		t.Fatalf("after confirm: %+v", st)
	}
	assertHygiene(t, e)
}

func mustV(s string) updatestate.Version {
	v, err := updatestate.ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func TestMissingStateRebuildsOnSeed(t *testing.T) {
	e := newEnv(t)
	e.api.setTarget("1.19.0")
	e.tick()
	wantEvents(t, e.events(), EventStateCorrupt)
	if st := e.state(); st.Current != "1.19.0" {
		t.Fatalf("current = %s", st.Current)
	}
	// versions\1.19.0 was absent, so it is staged from the release.
	if err := updatestate.VerifyVersionDir(e.L.VersionDir(mustV("1.19.0")), mustV("1.19.0")); err != nil {
		t.Fatalf("seed version not staged: %v", err)
	}
}

func TestCorruptStateIsReported(t *testing.T) {
	e := newEnv(t)
	must(t, os.MkdirAll(e.L.StateDir(), 0o755))
	must(t, os.WriteFile(e.L.StateFile(), []byte("{garbage"), 0o644))
	e.api.setTarget("1.19.0")
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventStateCorrupt)
	if ev := e.lastSentOrNil(EventStateCorrupt); ev == nil || ev.Error == "" {
		t.Fatal("no reason on update_state_corrupt")
	}
}

func (e *env) lastSentOrNil(event string) *updatestate.OutboxEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.all) - 1; i >= 0; i-- {
		if e.all[i].Event == event {
			ev := e.all[i]
			return &ev
		}
	}
	return nil
}

func probationState(t *testing.T, e *env) {
	t.Helper()
	e.installVersion("1.19.0")
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "1.19.0")
	st.Probation = &updatestate.Probation{Version: "1.20.0", Since: e.now.Add(-time.Minute), SmokeOK: true}
	st.LastCheck = e.now
	e.writeState(st)
}

func TestBadRunsRollBackAndQuarantineForever(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.addRun("1.20.0", false, 2)
	e.tick()
	wantEvents(t, e.events())
	e.addRun("1.20.0", false, 0xC0000005)
	e.tick()
	got := e.events()
	if len(got) == 0 || got[0] != EventRolledBack {
		t.Fatalf("events = %v", got)
	}
	rb := e.lastSent(EventRolledBack)
	if rb.From != "1.20.0" || rb.To != "1.19.0" || rb.Error != ReasonBadRuns {
		t.Fatalf("rollback event = %+v", rb)
	}
	st := e.state()
	if st.Current != "1.19.0" || st.Probation != nil || st.Quarantine["1.20.0"].Reason != ReasonBadRuns || !st.Quarantine["1.20.0"].Until.IsZero() {
		t.Fatalf("after rollback: %+v", st)
	}
	// U8: the target stays 1.20.0 for days; it is never current again and
	// never re-staged.
	for i := 0; i < 5; i++ {
		e.now = e.now.Add(7 * time.Hour)
		e.tick()
		if st := e.state(); st.Current != "1.19.0" {
			t.Fatalf("quarantined version came back: %+v", st)
		}
	}
	if _, err := os.Stat(e.L.VersionDir(mustV("1.20.0"))); !os.IsNotExist(err) {
		t.Fatalf("quarantined version dir not collected: %v", err)
	}
	assertHygiene(t, e)
}

func TestNeutralRunsNeverRollBack(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	for i := 0; i < 5; i++ {
		e.addRun("1.20.0", false, 1)
	}
	e.tick()
	if st := e.state(); st.Probation == nil || st.Current != "1.20.0" {
		t.Fatalf("neutral runs closed the probation: %+v", st)
	}
}

func TestInconclusiveProbationQuarantinesForAWeek(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	for i := 0; i < 6; i++ {
		e.addRun("1.20.0", false, 1)
	}
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	rb := e.lastSent(EventRolledBack)
	if rb.Error != ReasonInconclusive {
		t.Fatalf("rollback = %+v", rb)
	}
	st := e.state()
	q := st.Quarantine["1.20.0"]
	if st.Current != "1.19.0" || q.Until.IsZero() || q.Until.Sub(e.now) != 7*24*time.Hour {
		t.Fatalf("after inconclusive: %+v %+v", st, q)
	}
	e.events()
	// After the quarantine expires the target is taken again.
	e.now = e.now.Add(7*24*time.Hour + time.Minute)
	e.tick()
	if st := e.state(); st.Current != "1.20.0" {
		t.Fatalf("not retried after expiry: %+v", st)
	}
	wantEvents(t, e.events(), EventOK)
}

func TestSmokeOnlyPromotion(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	c := e.lastSent(EventConfirmed)
	if c.To != "1.20.0" || c.Error != "smoke_only" {
		t.Fatalf("confirm = %+v", c)
	}
}

func TestReSmokeFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	e.smokeErr["1.20.0"] = errors.New("boom")
	e.now = e.now.Add(73 * time.Hour)
	e.tick()
	if rb := e.lastSent(EventRolledBack); rb.Error != ReasonSmokeFailed {
		t.Fatalf("rollback = %+v", rb)
	}
}

func TestPointerInvalidDuringProbation(t *testing.T) {
	e := newEnv(t)
	probationState(t, e)
	must(t, os.Remove(filepath.Join(e.L.VersionDir(mustV("1.20.0")), updatestate.AgentFile)))
	e.tick()
	if rb := e.lastSent(EventRolledBack); rb.Error != ReasonPointerInvalid || rb.To != "1.19.0" {
		t.Fatalf("rollback = %+v", rb)
	}
}

func TestSmokeFailureQuarantinesWithoutSwitch(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.smokeErr["1.20.0"] = errors.New("exit 3")
	e.tick()
	wantEvents(t, e.events(), EventHealthFailed)
	st := e.state()
	if st.Current != "1.19.0" || st.Quarantine["1.20.0"].Reason != ReasonSmokeFailed {
		t.Fatalf("state = %+v", st)
	}
	e.now = e.now.Add(7 * time.Hour)
	e.tick()
	wantEvents(t, e.events())
	assertHygiene(t, e)
}

func TestPolicyOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(e *env)
		event  string
		code   int
		staged bool
	}{
		{"disabled", func(e *env) { e.auto = false }, EventDisabled, ExitOK, false},
		{"below floor", func(e *env) { e.api.setTarget("1.18.0") }, EventRefusedFloor, ExitOK, false},
		{"check failed", func(e *env) { e.api.metaStatus = 500 }, EventCheckFailed, ExitFailed, false},
		{"bad signature", func(e *env) {
			e.api.badSig["stepsecurity-dev-machine-guard-1.20.0-windows_amd64.exe"] = true
		}, EventVerifyFailed, ExitOK, false},
		{"wrong publisher", func(e *env) { e.pubErr = errors.New("publisher differs") }, EventVerifyFailed, ExitOK, false},
		{"sha mismatch", func(e *env) {
			e.api.checksumOver["stepsecurity-dev-machine-guard-1.20.0-linux_amd64"] = sum([]byte("other"))
		}, EventVerifyFailed, ExitOK, false},
		{"download failed", func(e *env) { e.api.githubDown = true }, EventDownloadFailed, ExitFailed, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.installVersion("1.19.0")
			e.writeState(baseState("1.19.0", ""))
			tc.setup(e)
			if code := e.tick(); code != tc.code {
				t.Fatalf("tick = %d, want %d", code, tc.code)
			}
			wantEvents(t, e.events(), tc.event)
			if st := e.state(); st.Current != "1.19.0" {
				t.Fatalf("current moved: %+v", st)
			}
			if _, err := os.Stat(e.L.VersionDir(mustV("1.20.0"))); err == nil {
				t.Fatal("target staged")
			}
			if tc.name == "bad signature" {
				for remote, n := range e.api.githubHits {
					if n > 0 {
						t.Fatalf("downloaded %s before verifying signatures", remote)
					}
				}
			}
			// Deduped within the window, reported again after it.
			e.now = e.now.Add(7 * time.Hour)
			e.tick()
			wantEvents(t, e.events())
			e.now = e.now.Add(25 * time.Hour)
			e.tick()
			wantEvents(t, e.events(), tc.event)
			assertHygiene(t, e)
		})
	}
}

func TestCheckIntervalGatesNetwork(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	e.writeState(baseState("1.20.0", ""))
	e.tick()
	n := len(e.api.latestRequests)
	e.now = e.now.Add(time.Hour)
	e.tick()
	if len(e.api.latestRequests) != n {
		t.Fatal("target checked again within the 6 h interval")
	}
	e.now = e.now.Add(6 * time.Hour)
	e.tick()
	if len(e.api.latestRequests) == n {
		t.Fatal("target not checked after the interval")
	}
}

func TestDowngradeAboveFloor(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.21.0")
	e.self = "1.21.0"
	e.writeState(baseState("1.21.0", "1.19.0"))
	e.tick()
	ok := e.lastSent(EventOK)
	if ok.From != "1.21.0" || ok.To != "1.20.0" {
		t.Fatalf("update_ok = %+v", ok)
	}
}

func TestSwitchDeferredWhileScanRuns(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.busy = 100
	for i := 1; i <= 4; i++ {
		e.now = e.now.Add(time.Hour)
		e.tick()
		if st := e.state(); st.Current != "1.19.0" {
			t.Fatal("switched while the scan held the mutex")
		}
	}
	wantEvents(t, e.events(), EventSwitchDeferred)
	e.busy = 0
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventOK)
	if st := e.state(); st.Current != "1.20.0" || st.SwitchDeferrals != 0 {
		t.Fatalf("after release: %+v", st)
	}
}

func TestLockHeldExitsQuietly(t *testing.T) {
	e := newEnv(t)
	e.writeState(baseState("1.19.0", ""))
	lk, err := updatestate.AcquireLock(e.L.LockFile())
	must(t, err)
	defer lk.Release()
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	if len(e.api.latestRequests) != 0 {
		t.Fatal("second updater did work")
	}
}

func TestOutboxRetriedNextTick(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.sendErr = errors.New("backend down")
	if code := e.tick(); code != ExitOK {
		t.Fatalf("send failure changed the outcome: %d", code)
	}
	st := e.state()
	if st.Current != "1.20.0" || len(st.Outbox) != 1 || st.Outbox[0].Event != EventOK {
		t.Fatalf("state = %+v", st)
	}
	e.sendErr = nil
	e.now = e.now.Add(time.Hour)
	e.tick()
	wantEvents(t, e.events(), EventOK)
	if st := e.state(); len(st.Outbox) != 0 {
		t.Fatalf("outbox not drained: %+v", st.Outbox)
	}
	// Rejected events are dropped, not retried forever.
	e.drift = []string{"versions"}
	e.sendErr = fmt.Errorf("%w: HTTP 400", ErrEventRejected)
	e.now = e.now.Add(time.Hour)
	e.tick()
	if st := e.state(); len(st.Outbox) != 0 {
		t.Fatalf("rejected event kept: %+v", st.Outbox)
	}
}

func TestACLDriftAndUpdaterFailureReported(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "")
	st.Updater = updatestate.Updater{Version: "1.20.0", ConsecutiveFailures: 3}
	e.writeState(st)
	e.drift = []string{"versions"}
	e.tick()
	got := e.events()
	slices.Sort(got)
	wantEvents(t, got, EventACLDrift, EventUpdaterFailed)
	uf := e.lastSent(EventUpdaterFailed)
	if uf.From != "1.20.0" || uf.To != "1.19.0" {
		t.Fatalf("update_updater_failed = %+v", uf)
	}
}

func TestGCKeepsPointersAndSweepsLeftovers(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"1.18.0", "1.19.0", "1.20.0", "1.21.0"} {
		e.installVersion(v)
	}
	must(t, os.MkdirAll(filepath.Join(e.L.VersionsDir(), ".staging-1.21.0-x"), 0o755))
	must(t, os.MkdirAll(filepath.Join(e.L.VersionsDir(), ".trash-1.17.0-y"), 0o755))
	st := baseState("1.20.0", "1.19.0")
	st.LastCheck = e.now
	e.writeState(st)
	e.self = "1.19.0"
	e.tick()
	entries, _ := os.ReadDir(e.L.VersionsDir())
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	if !slices.Equal(names, []string{"1.19.0", "1.20.0"}) {
		t.Fatalf("versions = %v", names)
	}
}

// D9: every event gets its own execution_id; a retried event (carried in
// the outbox to a later tick) keeps its id.
func TestEventExecutionIDs(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.drift = []string{"versions"}
	e.sendErr = errors.New("backend down")
	e.tick()
	pending := e.state().Outbox
	if len(pending) != 2 {
		t.Fatalf("outbox = %+v", pending)
	}
	if pending[0].ExecutionID == pending[1].ExecutionID || pending[0].ExecutionID == "" {
		t.Fatalf("events share an execution_id: %+v", pending)
	}
	e.sendErr = nil
	e.now = e.now.Add(time.Hour)
	e.tick()
	ids := map[string]bool{}
	for _, ev := range e.all {
		ids[ev.ExecutionID] = true
		if ev.Event == EventRolledBack && ev.From == "" {
			t.Fatal("update_rolled_back without update_from")
		}
	}
	for _, p := range pending {
		if !ids[p.ExecutionID] {
			t.Fatalf("retry of %s used a new execution_id", p.Event)
		}
	}
	if len(ids) != len(e.all) {
		t.Fatalf("delivered events reuse ids: %+v", e.all)
	}
}

func TestMissingLinuxFieldsReportVerifyFailed(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.api.noLinuxFields = true
	if code := e.tick(); code != ExitOK {
		t.Fatalf("tick = %d", code)
	}
	wantEvents(t, e.events(), EventVerifyFailed)
	if len(e.api.githubHits) != 0 {
		t.Fatalf("downloaded before verification: %v", e.api.githubHits)
	}
}

// D11: the fallback updater reports update_updater_failed only on a tick
// where it reached latest-binary itself; during an outage the primary's
// failures prove nothing.
func TestUpdaterFailedOnlyAfterReachingBackend(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	st := baseState("1.20.0", "")
	st.Updater = updatestate.Updater{Version: "1.20.0", ConsecutiveFailures: 3}
	e.writeState(st)
	e.api.metaStatus = 503
	e.tick()
	if got := e.events(); slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("reported during an outage: %v", got)
	}
	e.api.metaStatus = 0
	e.now = e.now.Add(time.Hour) // no target check due: still not reported
	e.tick()
	if got := e.events(); slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("reported without reaching the backend: %v", got)
	}
	e.now = e.now.Add(6 * time.Hour)
	e.tick()
	if got := e.events(); !slices.Contains(got, EventUpdaterFailed) {
		t.Fatalf("not reported once the backend answered: %v", got)
	}
}

// failingSaves makes every state write fail without touching the disk
// (landed=false) or write and then fail (landed=true), like a late error.
func failingSaves(t *testing.T, landed bool) {
	t.Helper()
	old := saveState
	saveState = func(path string, st *updatestate.State, prefix string) error {
		if landed {
			if err := old(path, st, prefix); err != nil {
				return err
			}
		}
		return errors.New("injected state write failure")
	}
	t.Cleanup(func() { saveState = old })
}

// R-C2-1: a tick whose state write never lands still reports its events
// (sent directly) instead of dropping them.
func TestUnlandedWriteSendsEventsDirectly(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	e.pubErr = errors.New("publisher differs")
	failingSaves(t, false)
	if code := e.tick(); code != ExitFailed {
		t.Fatalf("tick = %d, want ExitFailed when state can't be written", code)
	}
	wantEvents(t, e.events(), EventVerifyFailed)
}

func TestSwitchWriteFailureReported(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	failingSaves(t, false)
	e.tick()
	got := e.events()
	if !slices.Contains(got, EventSwitchFailed) || slices.Contains(got, EventOK) {
		t.Fatalf("events = %v, want update_switch_failed and no update_ok", got)
	}
	if st := e.state(); st.Current != "1.19.0" {
		t.Fatalf("current moved: %s", st.Current)
	}
}

// A write that landed but returned an error (late failure) is recognised
// by its generation: the switch counts, and no false switch_failed is sent.
func TestLandedWriteWithErrorIsNotAFailure(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.19.0")
	e.writeState(baseState("1.19.0", ""))
	failingSaves(t, true)
	e.tick()
	got := e.events()
	if slices.Contains(got, EventSwitchFailed) || !slices.Contains(got, EventOK) {
		t.Fatalf("events = %v, want update_ok only", got)
	}
	if st := e.state(); st.Current != "1.20.0" {
		t.Fatalf("current = %s", st.Current)
	}
}

// R-C2-3: a retryable send failure keeps the event with a backoff; the
// outbox is capped at 64, dropping the oldest and counting the drops.
func TestOutboxBackoffAndCap(t *testing.T) {
	e := newEnv(t)
	e.installVersion("1.20.0")
	e.self = "1.20.0"
	st := baseState("1.20.0", "")
	st.LastCheck = e.now
	for i := 0; i < 70; i++ {
		enqueueTo(st, e.now, time.Hour, EventCheckFailed, "1.20.0", "", fmt.Sprint(i), "")
	}
	if len(st.Outbox) != 64 || st.OutboxDropped != 6 || st.Outbox[0].Error != "6" {
		t.Fatalf("cap: len=%d dropped=%d first=%q", len(st.Outbox), st.OutboxDropped, st.Outbox[0].Error)
	}
	st.Outbox = st.Outbox[:1]
	e.writeState(st)
	calls := 0
	d := e.deps()
	d.Send = func(context.Context, updatestate.OutboxEvent) error { calls++; return errors.New("HTTP 429") }
	Run(context.Background(), d)
	if calls != 1 {
		t.Fatalf("first attempt calls = %d", calls)
	}
	pending := e.state().Outbox
	if len(pending) != 1 || pending[0].Attempts != 1 || !pending[0].NextAttempt.After(e.now) {
		t.Fatalf("after a 429: %+v", pending)
	}
	// Within the backoff: not retried.
	e.now = e.now.Add(30 * time.Minute)
	Run(context.Background(), d)
	if calls != 1 {
		t.Fatalf("retried inside the backoff (calls=%d)", calls)
	}
	e.now = e.now.Add(2 * time.Hour)
	Run(context.Background(), d)
	if calls != 2 || e.state().Outbox[0].Attempts != 2 {
		t.Fatalf("not retried after the backoff: calls=%d %+v", calls, e.state().Outbox)
	}
}
