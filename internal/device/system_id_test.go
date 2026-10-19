//go:build !windows

package device

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

const winIDFile = `C:\ProgramData\StepSecurity\device-id`

// R-C2-2: the SYSTEM updater never takes its identity from the
// user-writable device-id file; it probes and rewrites the file.
func TestSystemIDNeverReadsTheFile(t *testing.T) {
	newMock := func(bios string) *executor.Mock {
		m := executor.NewMock()
		m.SetGOOS("windows")
		m.SetIsRoot(true)
		m.SetFile(winIDFile, []byte("PLANTED-BY-USER\n"))
		m.SetCommand("SerialNumber\n"+bios+"\n", "", 0, "wmic", "bios", "get", "serialnumber")
		m.SetCommand(bios+"\n", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber")
		return m
	}
	old := config.DeviceID
	t.Cleanup(func() { config.DeviceID = old })
	config.DeviceID = ""

	m := newMock("To be filled by O.E.M.")
	if got := SystemID(context.Background(), m); got == "PLANTED-BY-USER" {
		t.Fatal("SYSTEM id came from the user-writable file")
	}

	m = newMock("HW-SERIAL-1")
	if got := SystemID(context.Background(), m); got != "HW-SERIAL-1" {
		t.Fatalf("SystemID = %q", got)
	}
	if b, _ := m.ReadFile(winIDFile); string(b) != "HW-SERIAL-1\n" {
		t.Fatalf("file not rewritten: %q", b)
	}

	config.DeviceID = "configured-1"
	if got := SystemID(context.Background(), newMock("HW-SERIAL-1")); got != "configured-1" {
		t.Fatalf("configured id lost: %q", got)
	}
}
