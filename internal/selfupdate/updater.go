package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// Spec constants (§3/§4, D5).
const (
	badRunsToRollback     = 2  // K
	inconclusiveMinRuns   = 6  // D5
	switchDeferralsReport = 4  // update_switch_deferred after this many
	updaterFailureLimit   = 3  // update_updater_failed threshold
	maxOutbox             = 32 // pending events kept
	inconclusiveRetry     = 7 * 24 * time.Hour
	freeSpaceMargin       = 50 << 20
	runTimeout            = 25 * time.Minute // under the task's 30 min limit
)

// Event names (spec §7).
const (
	EventOK             = "update_ok"
	EventConfirmed      = "update_confirmed"
	EventRolledBack     = "update_rolled_back"
	EventDownloadFailed = "update_download_failed"
	EventVerifyFailed   = "update_verify_failed"
	EventStageFailed    = "update_stage_failed"
	EventHealthFailed   = "update_health_failed"
	EventSwitchFailed   = "update_switch_failed"
	EventSwitchDeferred = "update_switch_deferred"
	EventCheckFailed    = "update_check_failed"
	EventRefusedFloor   = "update_refused_floor"
	EventDisabled       = "update_disabled"
	EventPointerInvalid = "update_pointer_invalid"
	EventACLDrift       = "update_acl_drift"
	EventStateCorrupt   = "update_state_corrupt"
	EventUpdaterFailed  = "update_updater_failed"
)

// Rollback and quarantine reasons (error_message of update_rolled_back).
const (
	ReasonBadRuns        = "bad_runs"
	ReasonSmokeFailed    = "smoke_failed"
	ReasonPointerInvalid = "pointer_invalid"
	ReasonInconclusive   = "inconclusive"
)

// ErrEventRejected marks an event the backend refused (4xx); it is dropped
// rather than retried.
var ErrEventRejected = errors.New("update event rejected by the backend")

// Deps are the updater's side effects, injected so the state machine runs
// unchanged in tests and as SYSTEM.
type Deps struct {
	Layout  updatestate.Layout
	Self    updatestate.Version // version of this process
	SelfExe string
	Client  *Client
	// AutoUpdate=false still checks and reports update_disabled.
	AutoUpdate bool
	// VerifyPublisher checks a staged exe's Authenticode signature and
	// publisher (authenticode.SamePublisher against SelfExe).
	VerifyPublisher func(path string) error
	// Smoke runs `<exe> self-check` and checks it reports version want.
	Smoke func(ctx context.Context, exe string, want updatestate.Version) error
	// AcquireInstance takes the scan instance mutex without blocking.
	AcquireInstance func() (release func(), err error)
	// EnsureACLs re-asserts versions\, state\ and config.json ACLs and
	// returns what had drifted.
	EnsureACLs func() (drifted []string, err error)
	// RefreshDeviceID probes the hardware as SYSTEM and rewrites the
	// device-id file (M-9).
	RefreshDeviceID func(ctx context.Context)
	// Send posts one update event.
	Send func(ctx context.Context, ev updatestate.OutboxEvent) error
	// SetRunningVersion records HKLM RunningVersion (inventory only).
	SetRunningVersion func(v string)
	// FreeBytes reports free space on the volume holding path.
	FreeBytes func(path string) (uint64, error)
	Now       func() time.Time
	Logf      func(format string, args ...any)
}

// Exit codes. Non-zero tells the bootstrap this updater failed (three in a
// row make it fall back to the seed's updater).
const (
	ExitOK     = 0
	ExitFailed = 1
)

type tick struct {
	d     *Deps
	L     updatestate.Layout
	st    *updatestate.State
	now   time.Time
	seeds []updatestate.Version
}

// checkpoint is faultinject.Point; a var so unit tests can observe order.
var checkpoint = faultinject.Point

// Run executes one updater tick (S0–S7). It never panics on bad state and
// always leaves a state the next tick converges from.
func Run(ctx context.Context, d *Deps) int {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	t := &tick{d: d, L: d.Layout, now: d.Now()}

	// S0 Lock. Creating state\ the first time is not ACL drift; existing
	// dirs are re-asserted in S1.
	if _, err := os.Stat(t.L.StateDir()); errors.Is(err, os.ErrNotExist) {
		if _, err := updatestate.EnsureProtectedDir(t.L.StateDir()); err != nil {
			d.Logf("self-update: create %s: %v", t.L.StateDir(), err)
			return ExitFailed
		}
	}
	lk, err := updatestate.AcquireLock(t.L.LockFile())
	if errors.Is(err, updatestate.ErrLocked) {
		d.Logf("self-update: another updater holds the lock; exiting")
		return ExitOK
	}
	if err != nil {
		d.Logf("self-update: lock: %v", err)
		return ExitFailed
	}
	defer lk.Release()
	if err := checkpoint("S0.locked"); err != nil {
		return t.fail(err)
	}
	if err := t.load(); err != nil {
		d.Logf("self-update: read state: %v", err)
		return ExitFailed
	}

	// S1 Sweep.
	t.sweep(ctx)
	if err := checkpoint("S1.swept"); err != nil {
		return t.finish(ctx, ExitFailed)
	}

	// S2 Health.
	closed, err := t.health(ctx)
	if err != nil {
		return t.finish(ctx, ExitFailed)
	}
	if err := checkpoint("S2.evaluated"); err != nil {
		return t.finish(ctx, ExitFailed)
	}

	return t.update(ctx, closed)
}

func (t *tick) fail(err error) int {
	t.d.Logf("self-update: %v", err)
	return ExitFailed
}

// load reads state.json; missing or corrupt state is rebuilt on the seed
// (or this updater's own version) and reported.
func (t *tick) load() error {
	t.seeds = seedVersions(t.L)
	st, corrupt, err := updatestate.Load(t.L.StateFile())
	if err != nil {
		return err
	}
	if st != nil {
		t.st = st
		normalize(st)
		return nil
	}
	cur := t.d.Self
	if len(t.seeds) > 0 {
		cur = t.seeds[len(t.seeds)-1]
	}
	t.st = &updatestate.State{Schema: updatestate.SchemaVersion, Current: cur.String()}
	normalize(t.st)
	reason := "state.json missing"
	if corrupt {
		reason = "state.json unreadable or of an unknown schema"
	}
	t.d.Logf("self-update: %s; rebuilding on %s", reason, cur)
	t.enqueue(EventStateCorrupt, "", cur.String(), reason, EventStateCorrupt)
	return nil
}

func normalize(st *updatestate.State) {
	if st.Quarantine == nil {
		st.Quarantine = map[string]updatestate.Quarantine{}
	}
	if st.Dedupe == nil {
		st.Dedupe = map[string]time.Time{}
	}
}

// seedVersions lists MSI seed versions that hold an agent and launcher,
// oldest first.
func seedVersions(L updatestate.Layout) []updatestate.Version {
	entries, err := os.ReadDir(filepath.Join(L.InstallRoot, "seed"))
	if err != nil {
		return nil
	}
	var out []updatestate.Version
	for _, e := range entries {
		v, err := updatestate.ParseVersion(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		ok := true
		for _, f := range []string{updatestate.AgentFile, updatestate.LauncherFile} {
			if fi, err := os.Lstat(filepath.Join(L.SeedDir(v), f)); err != nil || !fi.Mode().IsRegular() {
				ok = false
			}
		}
		if ok {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return updatestate.Compare(out[i], out[j]) < 0 })
	return out
}

func (t *tick) dedupeWindow() time.Duration { return duration(knobDedupeWindow) }

// enqueue adds an event to the outbox unless dedupeKey was used within the
// dedupe window. An empty key never dedupes.
func (t *tick) enqueue(event, from, to, msg, dedupeKey string) {
	enqueueTo(t.st, t.now, t.dedupeWindow(), event, from, to, msg, dedupeKey)
}

func enqueueTo(st *updatestate.State, now time.Time, window time.Duration, event, from, to, msg, dedupeKey string) {
	if dedupeKey != "" {
		if last, ok := st.Dedupe[dedupeKey]; ok && now.Sub(last) < window && !now.Before(last) {
			return
		}
		st.Dedupe[dedupeKey] = now
	}
	if len(msg) > 2048 {
		msg = msg[:2048]
	}
	st.Outbox = append(st.Outbox, updatestate.OutboxEvent{
		ExecutionID: uuid.NewString(), Event: event, From: from, To: to, Error: msg, At: now.UTC(),
	})
	if len(st.Outbox) > maxOutbox {
		st.Outbox = st.Outbox[len(st.Outbox)-maxOutbox:]
	}
}

// sweep is S1: temp/staging/trash cleanup, GC, ACLs, device id, dedupe and
// quarantine expiry, updater-failure report. Never fatal.
func (t *tick) sweep(ctx context.Context) {
	updatestate.SweepTemps(t.L.StateFile())
	if t.d.EnsureACLs != nil {
		drifted, err := t.d.EnsureACLs()
		if err != nil {
			t.d.Logf("self-update: ACL re-assert: %v", err)
		}
		if len(drifted) > 0 {
			t.enqueue(EventACLDrift, "", "", "ACL drift fixed on: "+strings.Join(drifted, ", "), EventACLDrift)
		}
	}
	t.gc()
	if t.d.RefreshDeviceID != nil {
		t.d.RefreshDeviceID(ctx)
	}
	for k, at := range t.st.Dedupe {
		if t.now.Sub(at) > 2*t.dedupeWindow() || at.After(t.now.Add(48*time.Hour)) {
			delete(t.st.Dedupe, k)
		}
	}
	for v, q := range t.st.Quarantine {
		if !q.Until.IsZero() && t.now.After(q.Until) {
			t.d.Logf("self-update: quarantine of %s expired", v)
			delete(t.st.Quarantine, v)
		}
	}
	if u := t.st.Updater; u.ConsecutiveFailures >= updaterFailureLimit && u.Version != "" && u.Version != t.d.Self.String() {
		t.enqueue(EventUpdaterFailed, u.Version, t.d.Self.String(),
			fmt.Sprintf("updater %s failed %d times in a row; running the %s updater", u.Version, u.ConsecutiveFailures, t.d.Self),
			EventUpdaterFailed+":"+u.Version)
	}
}

// keep is the set of version dirs GC must not touch.
func (t *tick) keep() map[string]bool {
	k := map[string]bool{t.st.Current: true, t.d.Self.String(): true}
	if t.st.Previous != "" {
		k[t.st.Previous] = true
	}
	if p := t.st.Probation; p != nil {
		k[p.Version] = true
	}
	for _, s := range t.seeds {
		k[s.String()] = true
	}
	return k
}

// gc deletes staging and trash dirs and moves unneeded version dirs to trash
// before deleting them. A dir in use (AV, running image) fails to rename or
// delete and is retried next tick.
func (t *tick) gc() {
	entries, err := os.ReadDir(t.L.VersionsDir())
	if err != nil {
		return
	}
	keep := t.keep()
	for _, e := range entries {
		p := filepath.Join(t.L.VersionsDir(), e.Name())
		if updatestate.IsSweepable(e.Name()) {
			if err := os.RemoveAll(p); err != nil {
				t.d.Logf("self-update: sweep %s: %v (retry next tick)", e.Name(), err)
			}
			continue
		}
		if _, err := updatestate.ParseVersion(e.Name()); err != nil || keep[e.Name()] || !e.IsDir() {
			continue
		}
		trash := filepath.Join(t.L.VersionsDir(), updatestate.TrashPrefix+e.Name()+"-"+uuid.NewString()[:8])
		if err := os.Rename(p, trash); err != nil {
			t.d.Logf("self-update: GC %s: %v (retry next tick)", e.Name(), err)
			continue
		}
		if err := os.RemoveAll(trash); err != nil {
			t.d.Logf("self-update: GC %s: %v (retry next tick)", e.Name(), err)
		}
	}
}

func (t *tick) dirValid(v string) bool {
	pv, err := updatestate.ParseVersion(v)
	return err == nil && updatestate.VerifyVersionDir(t.L.VersionDir(pv), pv) == nil
}

// health is S2. It reports whether a probation closed this tick.
func (t *tick) health(ctx context.Context) (closed bool, err error) {
	p := t.st.Probation
	if p == nil {
		return false, nil
	}
	if p.Version != t.st.Current {
		t.d.Logf("self-update: probation %s is not current %s; dropping it", p.Version, t.st.Current)
		t.st.Probation = nil
		return true, nil
	}
	if !t.dirValid(p.Version) {
		return true, t.rollback(ReasonPointerInvalid, time.Time{})
	}
	healthy, neutral, bad := 0, 0, 0
	v, _ := updatestate.ParseVersion(p.Version)
	for _, r := range updatestate.ReadRuns(t.L.RunFile(v)) {
		if r.At.Before(p.Since) {
			continue
		}
		switch updatestate.ClassifyRun(r) {
		case updatestate.RunHealthy:
			healthy++
			bad = 0
		case updatestate.RunNeutral:
			neutral++
		case updatestate.RunBad:
			bad++
		}
	}
	p.OK, p.Bad = healthy, bad
	window := duration(knobProbationWindow)
	switch {
	case healthy > 0:
		t.confirm("")
		return true, nil
	case bad >= badRunsToRollback:
		return true, t.rollback(ReasonBadRuns, time.Time{})
	case t.now.Sub(p.Since) < window:
		return false, nil
	case neutral >= inconclusiveMinRuns:
		return true, t.rollback(ReasonInconclusive, t.now.Add(inconclusiveRetry).UTC())
	}
	// Window over with too few runs to judge: re-smoke, then promote on it.
	if err := t.d.Smoke(ctx, filepath.Join(t.L.VersionDir(v), updatestate.AgentFile), v); err != nil {
		t.d.Logf("self-update: re-smoke of %s failed: %v", v, err)
		return true, t.rollback(ReasonSmokeFailed, time.Time{})
	}
	t.confirm("smoke_only")
	return true, nil
}

func (t *tick) confirm(note string) {
	v := t.st.Probation.Version
	t.st.Probation = nil
	t.d.Logf("self-update: %s confirmed %s", v, note)
	t.enqueue(EventConfirmed, t.st.Previous, v, note, "")
}

// rollback moves current back to previous (else the seed), quarantines the
// probation version and reports it, all in one atomic state write.
func (t *tick) rollback(reason string, until time.Time) error {
	bad := t.st.Current
	target := ""
	for _, c := range t.rollbackCandidates() {
		if c != bad && !t.quarantined(c) {
			target = c
			break
		}
	}
	if target == "" {
		target = t.d.Self.String()
	}
	next := cloneState(t.st)
	next.Current = target
	next.Previous = ""
	next.Probation = nil
	next.Quarantine[bad] = updatestate.Quarantine{Reason: reason, At: t.now.UTC(), Until: until}
	enqueueTo(next, t.now, t.dedupeWindow(), EventRolledBack, bad, target, reason, "")
	t.d.Logf("self-update: rolling back %s -> %s (%s)", bad, target, reason)
	if err := t.save(next, "rollback"); err != nil {
		return err
	}
	t.setRunning(target)
	// The quarantined dir is garbage now; a scan still running it keeps it
	// until a later tick.
	t.gc()
	return nil
}

func (t *tick) rollbackCandidates() []string {
	var c []string
	if t.st.Previous != "" && t.dirValid(t.st.Previous) {
		c = append(c, t.st.Previous)
	}
	for i := len(t.seeds) - 1; i >= 0; i-- {
		c = append(c, t.seeds[i].String())
	}
	if t.st.Previous != "" {
		c = append(c, t.st.Previous)
	}
	return c
}

func (t *tick) quarantined(v string) bool {
	q, ok := t.st.Quarantine[v]
	return ok && (q.Until.IsZero() || t.now.Before(q.Until))
}

// save writes next with the given checkpoint prefix. After any error the
// state on disk may be old or new, so it is re-read; t.st becomes whatever
// is on disk, and an error is returned only if next did not land.
func (t *tick) save(next *updatestate.State, prefix string) error {
	err := updatestate.SaveCheckpointed(t.L.StateFile(), next, prefix)
	if err == nil {
		t.st = next
		return nil
	}
	t.d.Logf("self-update: state write (%s): %v", prefix, err)
	disk, _, lerr := updatestate.Load(t.L.StateFile())
	if lerr == nil && disk != nil {
		normalize(disk)
		t.st = disk
		if disk.Current == next.Current && sameProbation(disk.Probation, next.Probation) {
			return nil
		}
	}
	return err
}

func sameProbation(a, b *updatestate.Probation) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Version == b.Version && a.Since.Equal(b.Since)
}

func (t *tick) setRunning(v string) {
	if t.d.SetRunningVersion != nil {
		t.d.SetRunningVersion(v)
	}
}

func cloneState(s *updatestate.State) *updatestate.State {
	c := *s
	if s.Probation != nil {
		p := *s.Probation
		c.Probation = &p
	}
	c.Quarantine = make(map[string]updatestate.Quarantine, len(s.Quarantine))
	for k, v := range s.Quarantine {
		c.Quarantine[k] = v
	}
	c.Dedupe = make(map[string]time.Time, len(s.Dedupe))
	for k, v := range s.Dedupe {
		c.Dedupe[k] = v
	}
	c.Outbox = append([]updatestate.OutboxEvent(nil), s.Outbox...)
	return &c
}

// update is S3–S7, then finish.
func (t *tick) update(ctx context.Context, probationClosed bool) int {
	st := t.st
	currentValid := t.dirValid(st.Current)
	due := st.LastCheck.IsZero() || t.now.Sub(st.LastCheck) >= duration(knobCheckInterval) ||
		st.LastCheck.After(t.now) || probationClosed || !currentValid
	if st.Probation != nil || !due {
		return t.finish(ctx, ExitOK)
	}

	// S3 Target.
	rel, err := t.d.Client.Latest(ctx)
	t.st.LastCheck = t.now.UTC()
	if err != nil {
		t.d.Logf("self-update: %v", err)
		t.enqueue(EventCheckFailed, st.Current, "", err.Error(), EventCheckFailed)
		return t.finish(ctx, ExitFailed)
	}
	if err := checkpoint("S3.target"); err != nil {
		return t.finish(ctx, ExitFailed)
	}
	target := rel.Version.String()
	switch {
	case !t.d.AutoUpdate:
		if target != st.Current {
			t.enqueue(EventDisabled, st.Current, target, "auto_update is off", EventDisabled+":"+target)
		}
		return t.finish(ctx, ExitOK)
	case updatestate.Compare(rel.Version, Floor()) < 0:
		t.enqueue(EventRefusedFloor, st.Current, target,
			fmt.Sprintf("target %s is below the self-update floor %s", target, Floor()), EventRefusedFloor+":"+target)
		return t.finish(ctx, ExitOK)
	case t.quarantined(target):
		t.d.Logf("self-update: target %s is quarantined (%s)", target, t.st.Quarantine[target].Reason)
		return t.finish(ctx, ExitOK)
	case target == st.Current && currentValid:
		return t.finish(ctx, ExitOK)
	}

	// S4 Stage.
	if event, err := t.stage(ctx, rel); err != nil {
		t.d.Logf("self-update: stage %s: %v", target, err)
		t.enqueue(event, st.Current, target, err.Error(), event+":"+target)
		code := ExitOK
		if event != EventVerifyFailed {
			code = ExitFailed
		}
		return t.finish(ctx, code)
	}

	if target == st.Current {
		// Current's dir was missing or damaged and is now restaged in place:
		// the pointer already names it, so there is nothing to switch.
		t.d.Logf("self-update: restaged current %s", target)
		return t.finish(ctx, ExitOK)
	}

	// S5 Smoke.
	agent := filepath.Join(t.L.VersionDir(rel.Version), updatestate.AgentFile)
	if err := t.d.Smoke(ctx, agent, rel.Version); err != nil {
		t.d.Logf("self-update: smoke of %s failed: %v", target, err)
		t.st.Quarantine[target] = updatestate.Quarantine{Reason: ReasonSmokeFailed, At: t.now.UTC()}
		t.enqueue(EventHealthFailed, st.Current, target, err.Error(), "")
		return t.finish(ctx, ExitOK)
	}
	if err := checkpoint("S5.smoked"); err != nil {
		return t.finish(ctx, ExitFailed)
	}

	// S6 Switch.
	return t.switchTo(ctx, rel.Version)
}

func (t *tick) switchTo(ctx context.Context, v updatestate.Version) int {
	target, old := v.String(), t.st.Current
	release, ok := t.waitInstance(ctx)
	if !ok {
		t.st.SwitchDeferrals++
		// Retry the switch next tick instead of after the check interval.
		t.st.LastCheck = time.Time{}
		t.d.Logf("self-update: a scan holds the instance mutex; switch to %s deferred (%d)", target, t.st.SwitchDeferrals)
		if t.st.SwitchDeferrals >= switchDeferralsReport {
			t.enqueue(EventSwitchDeferred, old, target,
				fmt.Sprintf("scan instance mutex busy for %d update ticks", t.st.SwitchDeferrals), "")
			t.st.SwitchDeferrals = 0
		}
		return t.finish(ctx, ExitOK)
	}
	defer release()
	if err := checkpoint("S6.mutex"); err != nil {
		return t.finish(ctx, ExitFailed)
	}
	next := cloneState(t.st)
	next.Previous = old
	next.Current = target
	next.Probation = &updatestate.Probation{Version: target, Since: t.now.UTC(), SmokeOK: true}
	next.SwitchDeferrals = 0
	enqueueTo(next, t.now, t.dedupeWindow(), EventOK, old, target, "", "")
	if err := t.save(next, "S6"); err != nil {
		t.enqueue(EventSwitchFailed, old, target, err.Error(), EventSwitchFailed+":"+target)
		return t.finish(ctx, ExitFailed)
	}
	t.setRunning(target)
	release()
	t.d.Logf("self-update: switched %s -> %s", old, target)

	// S7 Report.
	t.flush(ctx)
	if err := checkpoint("S7.reported"); err != nil {
		return t.finish(ctx, ExitFailed)
	}
	return t.finish(ctx, ExitOK)
}

// waitInstance polls the scan instance mutex for up to the switch wait.
func (t *tick) waitInstance(ctx context.Context) (func(), bool) {
	deadline := time.Now().Add(duration(knobSwitchWait))
	for {
		release, err := t.d.AcquireInstance()
		if err == nil {
			return release, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(2 * time.Second):
		}
	}
}

// stage is S4. It returns the event to report on failure.
func (t *tick) stage(ctx context.Context, rel *Release) (string, error) {
	v := rel.Version
	dir := t.L.VersionDir(v)
	if _, err := os.Lstat(dir); err == nil {
		if updatestate.VerifyVersionDir(dir, v) == nil {
			t.d.Logf("self-update: reusing staged %s", v)
			return "", nil
		}
		trash := filepath.Join(t.L.VersionsDir(), updatestate.TrashPrefix+v.String()+"-"+uuid.NewString()[:8])
		if err := os.Rename(dir, trash); err != nil {
			return EventStageFailed, fmt.Errorf("move invalid %s aside: %w", dir, err)
		}
		_ = os.RemoveAll(trash)
	}
	if err := t.d.Client.VerifySignatures(rel); err != nil {
		return EventVerifyFailed, err
	}
	if _, err := updatestate.EnsureProtectedDir(t.L.VersionsDir()); err != nil {
		return EventStageFailed, err
	}
	if err := t.checkFreeSpace(); err != nil {
		return EventStageFailed, err
	}
	staging, err := t.L.StagingDir(v)
	if err != nil {
		return EventStageFailed, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	m := updatestate.Manifest{Version: v.String(), Files: map[string]string{}}
	for _, a := range rel.Assets {
		if err := t.d.Client.Download(ctx, v, a, staging); err != nil {
			switch {
			case errors.Is(err, ErrVerify):
				return EventVerifyFailed, err
			case errors.Is(err, ErrDownload):
				return EventDownloadFailed, err
			}
			return EventStageFailed, err
		}
		if err := checkpoint("S4.downloaded:" + a.File); err != nil {
			return EventStageFailed, err
		}
		m.Files[a.File] = a.Checksum
	}
	for _, f := range []string{updatestate.AgentFile, updatestate.LauncherFile} {
		if err := t.d.VerifyPublisher(filepath.Join(staging, f)); err != nil {
			return EventVerifyFailed, fmt.Errorf("%w: %s: %w", ErrVerify, f, err)
		}
	}
	if err := checkpoint("S4.verified"); err != nil {
		return EventStageFailed, err
	}
	if err := updatestate.WriteManifest(staging, m); err != nil {
		return EventStageFailed, err
	}
	if err := checkpoint("S4.manifest"); err != nil {
		return EventStageFailed, err
	}
	if err := os.Rename(staging, dir); err != nil {
		return EventStageFailed, err
	}
	committed = true
	if err := checkpoint("S4.renamed"); err != nil {
		return EventStageFailed, err
	}
	return "", nil
}

// checkFreeSpace requires 3x the running version's files plus 50 MB.
func (t *tick) checkFreeSpace() error {
	if t.d.FreeBytes == nil {
		return nil
	}
	var size int64
	for _, f := range updatestate.VersionFiles {
		if fi, err := os.Stat(filepath.Join(filepath.Dir(t.d.SelfExe), f)); err == nil {
			size += fi.Size()
		}
	}
	need := uint64(3*size) + freeSpaceMargin // #nosec G115 -- file sizes are non-negative
	free, err := t.d.FreeBytes(t.L.VersionsDir())
	if err != nil {
		return nil // unknown: let the download find out
	}
	if free < need {
		return fmt.Errorf("not enough disk space: %d bytes free, %d needed", free, need)
	}
	return nil
}

// finish persists the state (with any new events), sends the outbox and
// persists again without the delivered events.
func (t *tick) finish(ctx context.Context, code int) int {
	if err := t.save(t.st, ""); err != nil {
		return ExitFailed
	}
	if t.flush(ctx) {
		if err := t.save(t.st, ""); err != nil {
			return ExitFailed
		}
	}
	return code
}

// flush sends pending events oldest first. Delivered and rejected events
// are removed; anything else stays for the next tick. It never blocks the
// update outcome, which is already on disk. It reports whether the outbox
// changed.
func (t *tick) flush(ctx context.Context) bool {
	if len(t.st.Outbox) == 0 || t.d.Send == nil {
		return false
	}
	var keep []updatestate.OutboxEvent
	for _, ev := range t.st.Outbox {
		err := t.d.Send(ctx, ev)
		switch {
		case err == nil:
		case errors.Is(err, ErrEventRejected):
			t.d.Logf("self-update: %s dropped: %v", ev.Event, err)
		default:
			t.d.Logf("self-update: %s not sent (kept for the next tick): %v", ev.Event, err)
			keep = append(keep, ev)
		}
	}
	changed := len(keep) != len(t.st.Outbox)
	t.st.Outbox = keep
	return changed
}
