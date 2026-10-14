package device

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// countingExec counts hardware probes (Linux DMI reads).
type countingExec struct {
	*executor.Mock
	probes atomic.Int32
}

func (c *countingExec) ReadFile(path string) ([]byte, error) {
	if path == "/sys/class/dmi/id/product_serial" {
		c.probes.Add(1)
	}
	return c.Mock.ReadFile(path)
}

func TestSerialNumberResolvesOncePerProcess(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-1\n"))
	exec := &countingExec{Mock: mock}

	first := SerialNumber(context.Background(), exec)
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-2\n"))
	second := Gather(context.Background(), exec).SerialNumber
	if first != "HW-1" || second != first {
		t.Fatalf("ids = %q, %q; want HW-1 twice", first, second)
	}
	if n := exec.probes.Load(); n != 1 {
		t.Fatalf("probes = %d, want 1", n)
	}
}

func TestSerialNumberDoesNotCacheFailure(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	if got := SerialNumber(context.Background(), mock); got != "unknown" {
		t.Fatalf("first = %q", got)
	}
	mock.SetFile("/etc/machine-id", []byte("mid-1\n"))
	if got := SerialNumber(context.Background(), mock); got != "mid-1" {
		t.Fatalf("retry = %q, want mid-1", got)
	}
}

const linuxIDFile = "/etc/stepsecurity/device-id"

func TestMachineWideIDSharedBetweenRootAndUser(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ctx := context.Background()

	// Root: DMI readable; persists the hardware serial.
	ResetIDCache()
	root := executor.NewMock()
	root.SetGOOS("linux")
	root.SetIsRoot(true)
	root.SetFile("/sys/class/dmi/id/product_serial", []byte("HW-SERIAL\n"))
	root.SetFile("/etc/machine-id", []byte("machine-id-1\n"))
	if got := SerialNumber(ctx, root); got != "HW-SERIAL" {
		t.Fatalf("root = %q", got)
	}
	persisted, err := root.ReadFile(linuxIDFile)
	if err != nil || string(persisted) != "HW-SERIAL\n" {
		t.Fatalf("persisted = %q, %v", persisted, err)
	}

	// User: DMI unreadable, would otherwise fall to machine-id.
	ResetIDCache()
	user := executor.NewMock()
	user.SetGOOS("linux")
	user.SetFile("/etc/machine-id", []byte("machine-id-1\n"))
	user.SetFile(linuxIDFile, persisted)
	if got := SerialNumber(ctx, user); got != "HW-SERIAL" {
		t.Fatalf("user = %q, want root's persisted serial", got)
	}
	if _, err := user.ReadFile(linuxIDFile); err != nil {
		t.Fatal(err)
	}
}

func TestMachineWideIDFile(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		root       bool
		want       string
		wantFile   string
	}{
		{"user prefers file over probe", " PERSISTED \n", false, "PERSISTED", " PERSISTED \n"},
		{"user ignores placeholder file", "Default string\n", false, "PROBED", "Default string\n"},
		{"user ignores empty file", "\n", false, "PROBED", "\n"},
		{"user never writes", "", false, "PROBED", ""},
		{"root refreshes stale file", "OTHER\n", true, "PROBED", "PROBED\n"},
		{"root writes missing file", "", true, "PROBED", "PROBED\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(ResetIDCache)
			ResetIDCache()
			mock := executor.NewMock()
			mock.SetGOOS("linux")
			mock.SetIsRoot(tc.root)
			mock.SetFile("/sys/class/dmi/id/product_serial", []byte("PROBED\n"))
			if tc.file != "" {
				mock.SetFile(linuxIDFile, []byte(tc.file))
			}
			if got := SerialNumber(context.Background(), mock); got != tc.want {
				t.Fatalf("id = %q, want %q", got, tc.want)
			}
			got, _ := mock.ReadFile(linuxIDFile)
			if string(got) != tc.wantFile {
				t.Fatalf("file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

func TestMachineIDFilePerOS(t *testing.T) {
	if got := machineIDFile("windows"); got != `C:\ProgramData\StepSecurity\device-id` {
		t.Errorf("windows = %q", got)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := machineIDFile(goos); got != linuxIDFile {
			t.Errorf("%s = %q", goos, got)
		}
	}
}

func TestConfiguredIDBeatsMachineWideFile(t *testing.T) {
	t.Cleanup(ResetIDCache)
	ResetIDCache()
	old := config.DeviceID
	t.Cleanup(func() { config.DeviceID = old })
	config.DeviceID = "custom-1"
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile(linuxIDFile, []byte("PERSISTED\n"))
	dev := Gather(context.Background(), mock)
	if got := ID(dev); got != "custom-1" {
		t.Fatalf("ID = %q, want override", got)
	}
	if dev.SerialNumber != "PERSISTED" {
		t.Fatalf("serial = %q, want machine-wide ID", dev.SerialNumber)
	}
}
