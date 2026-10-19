//go:build windows

package launcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const envTree = "DMG_TEST_TREE"

// TestHelperTree is a subprocess body: "parent" starts a "child" copy of
// this binary (inheriting the job), writes the child's pid and sleeps; the
// child just sleeps. It does nothing in a normal test run.
func TestHelperTree(t *testing.T) {
	switch os.Getenv(envTree) {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestHelperTree$")
		child.Env = append(os.Environ(), envTree+"=child")
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		_ = os.WriteFile(os.Getenv(envTree+"_PIDFILE"), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		time.Sleep(time.Minute)
	case "child":
		time.Sleep(time.Minute)
	default:
		t.Skip("subprocess helper")
	}
}

// R-B-5: the bootstrap deadline terminates the whole job tree (the child's
// own children included) with exit code 124.
func TestSpawnHidden_DeadlineKillsWholeTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	env := append(os.Environ(), envTree+"=parent", envTree+"_PIDFILE="+pidFile)
	start := time.Now()
	res := SpawnHidden(os.Args[0], []string{"-test.run=^TestHelperTree$"}, env, 4*time.Second, nil)
	if !res.Started || !res.Killed || res.ExitCode != ExitKilled {
		t.Fatalf("result = %+v, want started, killed, exit %d", res, ExitKilled)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Fatalf("took %s", el)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child never started: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) // #nosec G115 -- test pid
	if err != nil {
		return // already gone
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 5000); ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("grandchild %d survived the deadline kill", pid)
	}
}
