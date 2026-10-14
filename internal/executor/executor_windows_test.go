//go:build windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A .cmd whose grandchild (ping) inherits stdout. Without a tree kill and
// WaitDelay, Wait blocks until ping exits (~60s) despite the timeout.
func TestRunWithTimeout_KillsGrandchildHoldingStdout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "hang.cmd")
	body := "@echo off\r\necho started\r\nping -n 60 127.0.0.1\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	const timeout = 2 * time.Second
	start := time.Now()
	_, _, code, err := (&Real{}).RunWithTimeout(context.Background(), timeout, script)
	elapsed := time.Since(start)

	if code != 124 || err == nil {
		t.Errorf("want timeout (124), got code=%d err=%v", code, err)
	}
	// WaitDelay alone would return at ~timeout+2s; the job kill is faster.
	if elapsed > timeout+3*time.Second {
		t.Fatalf("RunWithTimeout took %s, want < %s", elapsed, timeout+3*time.Second)
	}
}

func TestNewKillOnCloseJob(t *testing.T) {
	job, err := newKillOnCloseJob()
	if err != nil {
		t.Fatalf("newKillOnCloseJob: %v", err)
	}
	_ = windows.CloseHandle(job)
}
