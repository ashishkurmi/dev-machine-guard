//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

// armExecutionWatchdog (Windows): same intent as the Unix version but
// skips the SIGTERM step. Windows console-signal mechanics (CTRL_C_EVENT
// via os.Process.Signal(os.Interrupt)) only reach console-attached
// processes, and the scheduled-task path under
// stepsecurity-dev-machine-guard-task.exe runs without a console. Calling
// os.Exit(2) directly skips the deferred lock release; the next launch's
// loader-side stale-process killer (scripts/windows-device-agent/
// stepsecurity-loader.ps1 Stop-StaleDmgProcesses) plus lock.Acquire's
// own dead-PID handling clean up any stale state. With no signal to route
// through telemetry.Run's handler, the failed run-status is posted directly.
func armExecutionWatchdog(d time.Duration, log *progress.Logger) {
	if d <= 0 {
		return
	}
	go func() {
		time.Sleep(d)
		log.Warn("execution-watchdog: max duration %s exceeded — exiting", d)
		telemetry.ReportFatal(fmt.Sprintf("execution-watchdog: max duration %s exceeded", d), 10*time.Second)
		os.Exit(2)
	}()
}
