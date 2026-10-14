package device

import (
	"context"
	"os"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// machineIDFile is the machine-wide identity: written by privileged runs,
// readable by every user. Without it Linux user contexts (no DMI access)
// would report /etc/machine-id while root reports the hardware serial.
func machineIDFile(goos string) string {
	if goos == model.PlatformWindows {
		return `C:\ProgramData\StepSecurity\device-id`
	}
	return "/etc/stepsecurity/device-id"
}

type atomicWriter interface {
	WriteFileAtomic(path string, data []byte, perm os.FileMode) error
}

// resolveID: privileged runs probe the hardware and refresh the shared file
// (healing a stale or planted one); everyone else reads the file first and
// only probes when it is absent. Unprivileged runs never write it.
func resolveID(ctx context.Context, exec executor.Executor) string {
	path := machineIDFile(exec.GOOS())
	if exec.IsRoot() {
		id := probeSerial(ctx, exec)
		if !usableSerial(id) {
			if stored := readIDFile(exec, path); stored != "" {
				return stored
			}
			return id
		}
		if readIDFile(exec, path) != id {
			writeIDFile(exec, path, id)
		}
		return id
	}
	if stored := readIDFile(exec, path); stored != "" {
		return stored
	}
	return probeSerial(ctx, exec)
}

// readIDFile returns the trimmed ID at path, or "" if missing or unusable.
func readIDFile(exec executor.Executor, path string) string {
	data, err := exec.ReadFile(path)
	if err != nil || len(data) > 256 {
		return ""
	}
	if id := strings.TrimSpace(string(data)); usableSerial(id) {
		return id
	}
	return ""
}

// writeIDFile is best-effort: a failed write only means the next run probes.
func writeIDFile(exec executor.Executor, path, id string) {
	if w, ok := exec.(atomicWriter); ok {
		_ = w.WriteFileAtomic(path, []byte(id+"\n"), 0o644)
	}
}
