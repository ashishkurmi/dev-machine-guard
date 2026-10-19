package launcher

import (
	"errors"
	"os/exec"
	"time"
)

// SpawnResult is the outcome of one child run.
type SpawnResult struct {
	Started  bool  // false: the child never started (Err says why)
	ExitCode int   // valid when Started
	Killed   bool  // the deadline fired and the child's tree was terminated
	Err      error // start error, or a wait error with no exit status
}

// Spawner starts path with args and env, calls onStart once the child is
// running, and waits for it. A positive deadline terminates the child's whole
// process tree when it expires.
type Spawner func(path string, args, env []string, deadline time.Duration, onStart func()) SpawnResult

// waitWithDeadline waits for a started cmd, calling kill once if deadline
// (when > 0) expires first.
func waitWithDeadline(cmd *exec.Cmd, deadline time.Duration, kill func()) SpawnResult {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var timeout <-chan time.Time
	if deadline > 0 {
		t := time.NewTimer(deadline)
		defer t.Stop()
		timeout = t.C
	}
	res := SpawnResult{Started: true}
	var err error
	select {
	case err = <-done:
	case <-timeout:
		res.Killed = true
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
