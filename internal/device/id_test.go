package device

import (
	"context"
	"sync/atomic"
	"testing"

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
