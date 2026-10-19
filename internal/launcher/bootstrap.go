package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// Bootstrap mode (spec §2, D2). The MSI installs this launcher a second time
// as BootstrapBinary in the install root; under that name it resolves the
// state.json pointer and launches the versioned binaries. It must stay tiny
// and frozen-safe: no network and no crypto, never crash, and read
// state.json only through the frozen pointer contract.
const (
	BootstrapBinary = "stepsecurity-dev-machine-guard-bootstrap.exe"

	// ExitCannotStart is returned when no child could be started (D5). It is
	// outside {0, 1}, so a run record carrying it classifies as bad.
	ExitCannotStart = 70
	// ExitKilled is the exit status given to a child tree the bootstrap
	// terminated at its deadline.
	ExitKilled = 124
	// exitUsage is returned for a malformed bootstrap command line.
	exitUsage = 64

	EnvRunRecord         = "STEPSEC_RUN_RECORD"
	EnvRunID             = "STEPSEC_RUN_ID"
	EnvBootstrapVersion  = "STEPSEC_BOOTSTRAP_VERSION"
	EnvBootstrapFallback = "STEPSEC_BOOTSTRAP_FALLBACK"

	// envMaxExecution mirrors telemetry.EnvMaxExecutionDuration; the
	// bootstrap reads it (and config.json) to bound a scan it launched.
	envMaxExecution = "STEPSEC_MAX_EXECUTION_DURATION"

	// UpdaterFailureThreshold consecutive failures of one updater version
	// make `update` fall back to the seed's updater.
	UpdaterFailureThreshold = 3
)

// Fallback reasons passed in EnvBootstrapFallback. Reasons about a named
// version carry it after a colon (current_missing:1.20.0) so the agent can
// report update_pointer_invalid with update_from = that version.
const (
	ReasonStateMissing      = updatestate.FallbackStateMissing
	ReasonStateCorrupt      = updatestate.FallbackStateCorrupt
	ReasonStateUnreadable   = updatestate.FallbackStateUnreadable
	ReasonCurrentMissing    = updatestate.FallbackCurrentMissing
	ReasonCurrentIncomplete = updatestate.FallbackCurrentIncomplete
	ReasonStartFailed       = updatestate.FallbackStartFailed
	ReasonUpdaterFailed     = updatestate.FallbackUpdaterFailed
	ReasonNoUpdater         = updatestate.FallbackNoUpdater
)

const (
	defaultExecutionDeadline = 4 * time.Hour
	// runDeadlineSlack lets the agent's own watchdog fire first; the scan
	// task's ExecutionTimeLimit is the watchdog + 30 min.
	runDeadlineSlack = 10 * time.Minute
	// defaultUpdateDeadline stays under the update task's 30 min
	// ExecutionTimeLimit so a hung updater is recorded as a failure.
	defaultUpdateDeadline = 25 * time.Minute
	// defaultRunLockWait bounds the wait for a run-record lock; past it the
	// bookkeeping is skipped and the scan still runs.
	defaultRunLockWait = 5 * time.Second
	maxConfigSize      = 1 << 20
	maxLogSize         = 1 << 20
)

// IsBootstrapBinary reports whether exePath is the bootstrap's file name.
func IsBootstrapBinary(exePath string) bool {
	base := exePath
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	return strings.EqualFold(base, BootstrapBinary)
}

// Bootstrap runs the bootstrap verbs. All fields are injectable for tests;
// NewBootstrap fills production values.
type Bootstrap struct {
	Layout   updatestate.Layout
	Spawn    Spawner
	IsSystem func() bool
	Now      func() time.Time
	Sleep    func(time.Duration)
	Getenv   func(string) string
	Environ  func() []string
	Out      io.Writer
	NewRunID func() string
	// SetRunningVersion records the version adopt-seed made current
	// (HKLM RunningVersion on Windows); nil skips it.
	SetRunningVersion func(string) error

	AdoptLockWait  time.Duration // adopt-seed: bounded wait for the update lock
	RecordLockWait time.Duration // update: wait to record the updater result
	LockPoll       time.Duration
	RunLockWait    time.Duration // run-record lock; 0 means defaultRunLockWait
	UpdateDeadline time.Duration

	log io.Writer
}

// NewBootstrap returns a production bootstrap rooted at the directory of
// exePath, with runs under the default data root.
func NewBootstrap(exePath string, isSystem func() bool) *Bootstrap {
	return &Bootstrap{
		Layout:            updatestate.Layout{InstallRoot: filepath.Dir(exePath), DataRoot: updatestate.DefaultDataRoot},
		Spawn:             SpawnHidden,
		IsSystem:          isSystem,
		Now:               time.Now,
		Sleep:             time.Sleep,
		Getenv:            os.Getenv,
		Environ:           os.Environ,
		Out:               os.Stdout,
		NewRunID:          uuid.NewString,
		SetRunningVersion: SetRunningVersion,
		AdoptLockWait:     60 * time.Second,
		RecordLockWait:    30 * time.Second,
		LockPoll:          500 * time.Millisecond,
		UpdateDeadline:    defaultUpdateDeadline,
	}
}

// Main dispatches a bootstrap command line (argv without the program name).
func (b *Bootstrap) Main(argv []string) int {
	if len(argv) == 0 {
		b.logf("usage: %s run <args...> | update | adopt-seed --seed-dir <dir>", BootstrapBinary)
		return exitUsage
	}
	switch argv[0] {
	case "run":
		return b.Run(argv[1:])
	case "update":
		return b.Update()
	case "adopt-seed":
		return b.AdoptSeed(argv[1:])
	default:
		b.logf("unknown bootstrap verb %q", argv[0])
		return exitUsage
	}
}

func (b *Bootstrap) logf(format string, args ...any) {
	line := b.Now().UTC().Format(time.RFC3339) + " bootstrap: " + fmt.Sprintf(format, args...) + "\n"
	if b.Out != nil {
		_, _ = io.WriteString(b.Out, line)
	}
	if b.log != nil {
		_, _ = io.WriteString(b.log, line)
	}
}

// openUpdateLog appends SYSTEM-verb logs to state\update.log (best effort,
// restarted when it grows past maxLogSize).
func (b *Bootstrap) openUpdateLog() func() {
	path := b.Layout.LogFile()
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- fixed path in the protected state dir
	if err != nil {
		return func() {}
	}
	b.log = f
	return func() { b.log = nil; _ = f.Close() }
}

// installDirArg returns the --install-dir value in args, if any.
func installDirArg(args []string) string {
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--install-dir="):
			return strings.Trim(strings.TrimPrefix(a, "--install-dir="), `"`)
		case a == "--install-dir" && i+1 < len(args):
			return strings.Trim(args[i+1], `"`)
		}
	}
	return ""
}

// childEnv is the bootstrap's environment with our variables replaced.
func (b *Bootstrap) childEnv(set map[string]string) []string {
	ours := []string{EnvRunRecord, EnvRunID, EnvBootstrapVersion, EnvBootstrapFallback}
	var env []string
	for _, kv := range b.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, o := range ours {
			if strings.EqualFold(k, o) {
				drop = true
			}
		}
		if !drop {
			env = append(env, kv)
		}
	}
	for _, k := range ours {
		if v, ok := set[k]; ok && v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func parseDeadline(v string) (time.Duration, bool) {
	switch v {
	case "":
		return 0, false
	case "0", "off":
		return 0, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// runDeadline mirrors the agent's execution watchdog (env > config.json >
// 4 h) plus slack. It catches a scan that hangs before the agent arms its
// own watchdog. 0 disables it, as for the agent.
func (b *Bootstrap) runDeadline(dataRoot string) time.Duration {
	d, ok := parseDeadline(b.Getenv(envMaxExecution))
	if !ok {
		var cfg struct {
			MaxExecutionDuration string `json:"max_execution_duration"`
		}
		if data, err := readSmall(filepath.Join(dataRoot, "config.json"), maxConfigSize); err == nil && json.Unmarshal(data, &cfg) == nil {
			d, ok = parseDeadline(cfg.MaxExecutionDuration)
		}
	}
	if !ok {
		d = defaultExecutionDeadline
	}
	if d == 0 {
		return 0
	}
	return d + runDeadlineSlack
}

func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the agent's own config path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("too large")
	}
	return data, nil
}

func checkpointLogged(b *Bootstrap, name string) {
	if err := faultinject.Point(name); err != nil {
		b.logf("checkpoint %s: %v (continuing)", name, err)
	}
}

// Run is `run <agent args...>`: launch versions\<v>\task.exe with args from
// the first usable of current → previous → seed, record the run, and return
// the child's exit code.
func (b *Bootstrap) Run(args []string) int {
	layout := b.Layout
	if d := installDirArg(args); d != "" {
		layout.DataRoot = d
	}
	p, corrupt, err := updatestate.LoadPointers(layout.StateFile())
	if err != nil {
		b.logf("reading state: %v", err)
	}
	cands := updatestate.ResolveRunChain(layout, p, updatestate.LoadReason(p != nil, corrupt, err))
	checkpointLogged(b, "boot.resolved")
	if len(cands) == 0 {
		b.logf("no launchable version (state, previous and seed all unusable)")
		return ExitCannotStart
	}
	deadline := b.runDeadline(layout.DataRoot)
	startReason := ""
	for _, c := range cands {
		reason := c.Reason
		if startReason != "" {
			reason = startReason
		}
		runFile := layout.RunFile(c.Version)
		runID := b.NewRunID()
		runLock := layout.RunLockFile(c.Version)
		if err := b.withRunLock(runLock, func() error {
			return updatestate.AppendRun(runFile, updatestate.RunRecord{RunID: runID, Version: c.Version.String()})
		}); err != nil {
			// Never block a scan on bookkeeping: launch without a run id,
			// so the agent skips the started marker.
			b.logf("run record %s: %v; launching without one", runFile, err)
			runID = ""
		}
		env := b.childEnv(map[string]string{
			EnvRunRecord:         runFile,
			EnvRunID:             runID,
			EnvBootstrapVersion:  c.Version.String(),
			EnvBootstrapFallback: reason,
		})
		res := b.Spawn(filepath.Join(c.Dir, updatestate.LauncherFile), args, env, deadline, func() {
			checkpointLogged(b, "boot.launched")
		})
		if !res.Started {
			b.logf("starting %s: %v", c.Dir, res.Err)
			b.finalize(runLock, runFile, runID, ExitCannotStart, false)
			startReason = ReasonStartFailed + ":" + c.Version.String()
			continue
		}
		code := res.ExitCode
		if res.Killed {
			code = ExitKilled
		}
		b.finalize(runLock, runFile, runID, code, res.Killed)
		return code
	}
	return ExitCannotStart
}

func (b *Bootstrap) finalize(runLock, runFile, runID string, code int, killed bool) {
	if runID == "" {
		return
	}
	if err := b.withRunLock(runLock, func() error {
		return updatestate.FinalizeRun(runFile, runID, code, killed, b.Now())
	}); err != nil {
		b.logf("finalizing run record %s: %v", runFile, err)
	}
}

// withRunLock runs fn holding the run-record lock (R-B-2), waiting at most
// RunLockWait. It returns an error, without running fn, when the lock can't
// be taken; callers skip the bookkeeping and never block the scan.
func (b *Bootstrap) withRunLock(path string, fn func() error) error {
	wait := b.RunLockWait
	if wait <= 0 {
		wait = defaultRunLockWait
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	deadline := b.Now().Add(wait)
	for {
		l, err := updatestate.AcquireLock(path)
		if err == nil {
			defer l.Release()
			return fn()
		}
		if !errors.Is(err, updatestate.ErrLocked) || !b.Now().Before(deadline) {
			return fmt.Errorf("run-record lock %s: %w", path, err)
		}
		b.Sleep(b.LockPoll)
	}
}

// lockWithWait polls for the update lock for up to wait.
func (b *Bootstrap) lockWithWait(wait time.Duration) (*updatestate.Lock, error) {
	deadline := b.Now().Add(wait)
	for {
		l, err := updatestate.AcquireLock(b.Layout.LockFile())
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, updatestate.ErrLocked) || !b.Now().Before(deadline) {
			return nil, err
		}
		b.Sleep(b.LockPoll)
	}
}

// Update is `update` (SYSTEM): pick the updater binary, run
// `agent.exe self-update --system`, and record its result in state.updater.
func (b *Bootstrap) Update() int {
	if !b.IsSystem() {
		b.logf("update must run as SYSTEM")
		return 1
	}
	defer b.openUpdateLog()()

	p, corrupt, err := updatestate.LoadPointers(b.Layout.StateFile())
	if err != nil {
		b.logf("reading state: %v", err)
	}
	var primary *updatestate.RunChoice
	reason := updatestate.LoadReason(p != nil, corrupt, err)
	if p != nil {
		pick := p.Current
		if p.Probation != "" && p.Probation == p.Current {
			pick = p.Previous
		}
		if pick == "" {
			reason = ReasonNoUpdater
		} else if v, why := b.Layout.CheckVersionDir(pick); why != "" {
			reason = why
		} else if p.UpdaterVersion == pick && p.UpdaterFailures >= UpdaterFailureThreshold {
			reason = ReasonUpdaterFailed + ":" + pick
		} else {
			primary = &updatestate.RunChoice{Version: v, Dir: b.Layout.VersionDir(v)}
		}
	}
	var cands []updatestate.RunChoice
	if primary != nil {
		cands = append(cands, *primary)
	}
	if v, ok := b.Layout.FindSeed(); ok {
		cands = append(cands, updatestate.RunChoice{Version: v, Dir: b.Layout.SeedDir(v), Reason: reason})
	}
	checkpointLogged(b, "boot.resolved")
	if len(cands) == 0 {
		b.logf("no updater binary available")
		return ExitCannotStart
	}
	for i, c := range cands {
		isPrimary := primary != nil && i == 0
		if !isPrimary {
			b.logf("updater fallback to seed %s (%s)", c.Version, c.Reason)
		}
		agent := filepath.Join(c.Dir, updatestate.AgentFile)
		res := b.Spawn(agent, []string{"self-update", "--system"}, b.childEnv(nil), b.UpdateDeadline, func() {
			checkpointLogged(b, "boot.launched")
		})
		code := res.ExitCode
		switch {
		case !res.Started:
			b.logf("starting updater %s: %v", agent, res.Err)
			code = ExitCannotStart
		case res.Killed:
			b.logf("updater %s killed after %s", c.Version, b.UpdateDeadline)
			code = ExitKilled
		}
		b.logf("updater %s exited %d", c.Version, code)
		if isPrimary {
			b.recordUpdater(c.Version.String(), code)
		}
		if res.Started {
			return code
		}
	}
	return ExitCannotStart
}

// recordUpdater stores the updater result for the next tick's selection.
func (b *Bootstrap) recordUpdater(version string, code int) {
	l, err := b.lockWithWait(b.RecordLockWait)
	if err != nil {
		b.logf("not recording updater result (lock: %v)", err)
		return
	}
	defer l.Release()
	path := b.Layout.StateFile()
	st, corrupt, err := updatestate.Load(path)
	if err != nil || corrupt || st == nil {
		b.logf("not recording updater result (state missing, corrupt or unreadable: %v)", err)
		return
	}
	switch {
	case code == 0:
		st.Updater.Version, st.Updater.ConsecutiveFailures = version, 0
	case st.Updater.Version == version:
		st.Updater.ConsecutiveFailures++
	default:
		st.Updater.Version, st.Updater.ConsecutiveFailures = version, 1
	}
	if err := updatestate.SaveCheckpointed(path, st, "boot"); err != nil {
		b.logf("recording updater result: %v", err)
	}
}

// AdoptSeed is `adopt-seed --seed-dir <dir>` (SYSTEM, MSI custom action):
// protect versions\ and state\, copy the seed into versions\<seed> if
// absent, and point current at it when current is unusable or older. It
// always exits 0: it must never fail the MSI.
func (b *Bootstrap) AdoptSeed(args []string) int {
	seedDir := ""
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--seed-dir="):
			seedDir = strings.TrimPrefix(a, "--seed-dir=")
		case a == "--seed-dir" && i+1 < len(args):
			seedDir = args[i+1]
		}
	}
	if seedDir == "" {
		b.logf("adopt-seed: --seed-dir is required")
		return 0
	}
	if !b.IsSystem() {
		b.logf("adopt-seed must run as SYSTEM")
		return 0
	}
	seedDir = filepath.Clean(strings.Trim(seedDir, `"`))
	v, err := updatestate.ParseVersion(filepath.Base(seedDir))
	if err != nil {
		b.logf("adopt-seed: seed dir %q is not seed\\<x.y.z>: %v", seedDir, err)
		return 0
	}
	if !samePath(seedDir, b.Layout.SeedDir(v)) {
		b.logf("adopt-seed: seed dir %q is not %q", seedDir, b.Layout.SeedDir(v))
		return 0
	}
	if !seedComplete(seedDir) {
		b.logf("adopt-seed: seed %s is incomplete", seedDir)
		return 0
	}
	for _, d := range []string{b.Layout.VersionsDir(), b.Layout.StateDir()} {
		fixed, err := updatestate.EnsureProtectedDir(d)
		if err != nil {
			b.logf("adopt-seed: protecting %s: %v", d, err)
			return 0
		}
		if fixed {
			b.logf("adopt-seed: re-asserted owner/DACL on %s", d)
		}
	}
	defer b.openUpdateLog()()

	l, err := b.lockWithWait(b.AdoptLockWait)
	if err != nil {
		b.logf("adopt-seed: update lock not taken (%v); the updater converges on its next tick", err)
		return 0
	}
	defer l.Release()

	if err := b.copySeed(v, seedDir); err != nil {
		b.logf("adopt-seed: copying seed %s: %v", v, err)
	}
	if err := updatestate.VerifyVersionDir(b.Layout.VersionDir(v), v); err != nil {
		b.logf("adopt-seed: versions\\%s unusable (%v); state left unchanged", v, err)
		return 0
	}
	b.adoptState(v)
	return 0
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// seedComplete reports whether dir holds every updatestate.VersionFiles entry.
func seedComplete(dir string) bool {
	for _, name := range updatestate.VersionFiles {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// copySeed copies the seed into versions\<v> through a staging dir, writes
// its manifest (so the updater treats it as a verified version) and renames
// it into place. A dir that already verifies is kept (immutable); anything
// else at that path is moved to trash first.
func (b *Bootstrap) copySeed(v updatestate.Version, seedDir string) error {
	dst := b.Layout.VersionDir(v)
	if _, err := os.Lstat(dst); err == nil {
		if updatestate.VerifyVersionDir(dst, v) == nil {
			return nil
		}
		trash := filepath.Join(b.Layout.VersionsDir(), updatestate.TrashPrefix+v.String()+"-"+strconv.FormatInt(b.Now().UnixNano(), 36))
		if err := os.Rename(dst, trash); err != nil {
			return fmt.Errorf("moving unverifiable %s aside: %w", dst, err)
		}
		b.logf("adopt-seed: moved unverifiable %s to %s", dst, trash)
		_ = os.RemoveAll(trash)
	}
	staging, err := b.Layout.StagingDir(v)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(staging)
		}
	}()
	m := updatestate.Manifest{Version: v.String(), Files: map[string]string{}}
	for _, name := range updatestate.VersionFiles {
		dstFile := filepath.Join(staging, name)
		if err := copyFile(filepath.Join(seedDir, name), dstFile); err != nil {
			return err
		}
		sum, err := updatestate.FileSHA256(dstFile)
		if err != nil {
			return err
		}
		m.Files[name] = sum
	}
	if err := updatestate.WriteManifest(staging, m); err != nil {
		return err
	}
	if err := faultinject.Point("adopt.copied"); err != nil {
		return err
	}
	if err := os.Rename(staging, dst); err != nil {
		return err
	}
	done = true
	b.logf("adopt-seed: copied seed %s into %s", v, dst)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- MSI-owned seed payload
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) // #nosec G304 G302 -- fresh staging dir
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// adoptState sets current = seed when there is no state yet, when current
// is unusable, or when the seed is newer than current (and not quarantined).
// An existing state is never replaced (R-B-1): only current/previous (and
// probation, which belonged to the old current) change, through the
// unknown-field-preserving Save; a state this build can't round-trip
// (unreadable pointers, fields Load rejects, a newer schema) is left
// byte-for-byte alone for the updater to handle. An MSI never downgrades a
// self-updated device. Called with the update lock held.
func (b *Bootstrap) adoptState(seed updatestate.Version) {
	path := b.Layout.StateFile()
	s := seed.String()
	p, corrupt, err := updatestate.LoadPointers(path)
	switch {
	case err != nil:
		b.logf("adopt-seed: reading state: %v; left unchanged", err)
		return
	case corrupt:
		b.logf("adopt-seed: state pointers unreadable; left unchanged for the updater")
		return
	case p == nil:
		st := &updatestate.State{Schema: updatestate.SchemaVersion, Current: s}
		if err := updatestate.SaveCheckpointed(path, st, "adopt"); err != nil {
			b.logf("adopt-seed: writing state: %v", err)
			return
		}
		b.logf("adopt-seed: no state; current = seed %s", s)
		b.recordRunningVersion(s)
		return
	case p.Schema > updatestate.SchemaVersion:
		b.logf("adopt-seed: state schema %d is newer than this bootstrap; left unchanged", p.Schema)
		return
	}
	st, corrupt, err := updatestate.Load(path)
	if err != nil || corrupt || st == nil {
		b.logf("adopt-seed: state has fields this build can't round-trip (%v); left unchanged", err)
		return
	}
	old := st.Current
	cur, _ := updatestate.ParseVersion(old)
	switch {
	case !updatestate.VersionDirUsable(b.Layout.VersionDir(cur)):
		st.Current = s
		if st.Probation != nil && st.Probation.Version == old {
			st.Probation = nil
		}
		if st.Previous == s {
			st.Previous = ""
		}
		b.logf("adopt-seed: current %s unusable; current = seed %s", old, s)
	case updatestate.Compare(seed, cur) <= 0:
		return
	default:
		if _, q := st.Quarantine[s]; q {
			b.logf("adopt-seed: seed %s is quarantined; current %s kept", s, old)
			return
		}
		st.Previous, st.Current, st.Probation = old, s, nil
		b.logf("adopt-seed: seed %s newer than current %s; current = seed", s, old)
	}
	if err := updatestate.SaveCheckpointed(path, st, "adopt"); err != nil {
		b.logf("adopt-seed: writing state: %v", err)
		return
	}
	b.recordRunningVersion(s)
}

// recordRunningVersion sets RunningVersion after adopt-seed set current
// (R-B-4). Best effort: inventory only.
func (b *Bootstrap) recordRunningVersion(v string) {
	if b.SetRunningVersion == nil {
		return
	}
	if err := b.SetRunningVersion(v); err != nil {
		b.logf("adopt-seed: setting RunningVersion: %v", err)
	}
}
