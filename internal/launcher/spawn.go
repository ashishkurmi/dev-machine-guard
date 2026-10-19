package launcher

import (
	"errors"
	"github.com/step-security/dev-machine-guard/internal/awakeclock"
	"os/exec"
	"time"
)

// SpawnResult is the outcome of one child run.
type SpawnResult struct {
	Started  bool  // false: the child never started (Err says why)
	ExitCode int   // valid when Started
	Killed   bool  // the deadline fired and the child's tree was terminated
	Slept    bool  // ...after the system had slept (not evidence of a hang)
	Err      error // start error, or a wait error with no exit status
}

// Spawner starts path with args and env, calls onStart once the child is
// running, and waits for it. A positive deadline terminates the child's whole
// process tree when it expires.
type Spawner func(path string, args, env []string, deadline time.Duration, onStart func()) SpawnResult

// watchdogPoll is how often the awake-time deadline is checked.
var watchdogPoll = 10 * time.Second

// waitWithDeadline waits for a started cmd, calling kill once if deadline
// (when > 0) expires first.
func waitWithDeadline(cmd *exec.Cmd, deadline time.Duration, kill func()) SpawnResult {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// The deadline counts awake time (sleep excluded), see awakeclock.
	type expiry struct{ slept bool }
	timeout := make(chan expiry, 1)
	stop := make(chan struct{})
	defer close(stop)
	if deadline > 0 {
		start := awakeclock.Begin(awakeclock.System)
		go func() {
			if fired, slept := start.Wait(deadline, stop, watchdogPoll); fired {
				timeout <- expiry{slept}
			}
		}()
	}
	res := SpawnResult{Started: true}
	var err error
	select {
	case err = <-done:
	case e := <-timeout:
		res.Killed, res.Slept = true, e.slept
		kill()
		err = <-done
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.ExitCode = 1
		res.Err = err
	}
	return res
}
