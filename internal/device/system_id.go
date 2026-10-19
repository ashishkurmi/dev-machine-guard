package device

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// systemProbeTimeout bounds the hardware probe (the WMI subprocess).
const systemProbeTimeout = 20 * time.Second

// SystemID is the device identity for the SYSTEM self-updater. It never
// reads the shared device-id file, which users can write (M-9): the
// configured device_id wins, else the hardware probe (BIOS serial from the
// registry, then WMI, then MachineGuid), which is then written to the file
// for unprivileged runs. "" when nothing usable is found.
func SystemID(ctx context.Context, exec executor.Executor) string {
	if id := strings.TrimSpace(config.DeviceID); id != "" {
		return id
	}
	ctx, cancel := context.WithTimeout(ctx, systemProbeTimeout)
	defer cancel()
	id, _ := probeSerial(ctx, exec)
	if !usableSerial(id) {
		return ""
	}
	if w, ok := exec.(idWriter); ok {
		_ = w.WriteFileAtomic(machineIDFile(exec.GOOS()), []byte(id+"\n"), 0o644) // best-effort
	}
	return id
}
