//go:build windows

package executor

import (
	"context"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// setupKillgroupOnCancel bounds how long Wait blocks on pipe copies after
// cancel or exit, so a grandchild holding stdout can't stall the run.
// runCommand adds the job object that kills the whole tree.
func setupKillgroupOnCancel(cmd *exec.Cmd) {
	cmd.WaitDelay = 2 * time.Second
}

// runCommand runs cmd inside its own job so cancel takes down grandchildren
// too, mirroring the Unix process-group kill. Only cancel terminates the job;
// helpers a command leaves behind on normal exit keep running, as on Unix.
// Nested jobs need Windows 8+; if the job can't be created or assigned,
// cancel falls back to killing the direct child and WaitDelay bounds Wait.
func runCommand(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return cmd.Run()
	}
	defer windows.CloseHandle(job)

	var assigned atomic.Bool
	cmd.Cancel = func() error {
		if assigned.Load() && windows.TerminateJobObject(job, 1) == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if assignToJob(job, cmd.Process.Pid) == nil {
		assigned.Store(true)
	}
	return cmd.Wait()
}

// assignToJob opens pid and adds it to job. The started cmd holds its own
// process handle, so the pid can't be reused underneath us.
func assignToJob(job windows.Handle, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}

func (r *Real) IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (r *Real) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := r.Run(ctx, "cmd", "/c", command)
	return strings.TrimSpace(stdout), err
}

func (r *Real) DiskCapacityBytes(path string) uint64 {
	if path == "" {
		return 0
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var freeBytesAvail, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvail, &totalBytes, &totalFreeBytes); err != nil {
		return 0
	}
	return totalBytes
}
