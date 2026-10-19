//go:build windows

package schtasks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/progress"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// instanceMutex is the scan singleton (internal/lock).
const instanceMutex = `Global\StepSecurityDevMachineGuard`

// stopDMGProcessesPlatform waits up to wait for a running scan to release the
// instance mutex, then terminates every process (other than this one) whose
// image lives under root: launchers, agents and bootstraps from versions\,
// seed\ or the root itself. Fixes the files-in-use reboot of M-18.
func stopDMGProcessesPlatform(root string, wait time.Duration, log *progress.Logger) error {
	if waitForInstanceMutex(wait) {
		log.Debug("instance mutex free; no scan running")
	} else {
		log.Warn("a scan still holds the instance mutex after %s; terminating DMG processes", wait)
	}
	return terminateUnder(root, log)
}

// waitForInstanceMutex reports whether the mutex is absent or was acquired
// (and released) within wait. Ownership is per thread, so the wait and the
// release run on one locked OS thread.
func waitForInstanceMutex(wait time.Duration) bool {
	res := make(chan bool, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		name, _ := windows.UTF16PtrFromString(instanceMutex)
		h, err := windows.OpenMutex(windows.SYNCHRONIZE|windows.MUTEX_MODIFY_STATE, false, name)
		if err != nil {
			res <- errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
			return
		}
		defer func() { _ = windows.CloseHandle(h) }()
		ev, _ := windows.WaitForSingleObject(h, uint32(wait/time.Millisecond)) // #nosec G115 -- bounded constant
		if ev == windows.WAIT_OBJECT_0 || ev == windows.WAIT_ABANDONED {
			_ = windows.ReleaseMutex(h)
			res <- true
			return
		}
		res <- false
	}()
	return <-res
}

func terminateUnder(root string, log *progress.Logger) error {
	prefix := strings.ToLower(filepath.Clean(root)) + `\`
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("process snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	self := uint32(os.Getpid()) // #nosec G115 -- a pid fits in uint32
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var errs []error
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == self || pe.ProcessID == 0 {
			continue
		}
		h, oerr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pe.ProcessID)
		if oerr != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if qerr := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); qerr == nil {
			img := windows.UTF16ToString(buf[:n])
			if strings.HasPrefix(strings.ToLower(img), prefix) {
				if terr := windows.TerminateProcess(h, 1); terr != nil {
					errs = append(errs, fmt.Errorf("terminating %s (pid %d): %w", img, pe.ProcessID, terr))
				} else {
					_, _ = windows.WaitForSingleObject(h, 5000)
					log.Progress("Stopped running DMG process %s (pid %d)", img, pe.ProcessID)
				}
			}
		}
		_ = windows.CloseHandle(h)
	}
	return errors.Join(errs...)
}

// deleteRunningVersionPlatform removes HKLM\Software\StepSecurity\RunningVersion
// (updater-owned). AgentVersion is MSI-owned and left to the MSI.
func deleteRunningVersionPlatform() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\StepSecurity`, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue("RunningVersion"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
