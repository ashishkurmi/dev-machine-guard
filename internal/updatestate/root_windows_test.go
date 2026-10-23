//go:build windows

package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A custom root outside any user profile, owned by SYSTEM with a
// protected DACL (as the MSI leaves INSTALLFOLDER), is accepted.
func TestResolveInstallRoot_ProtectedCustomRoot(t *testing.T) {
	top := filepath.Join(os.Getenv("SystemDrive")+`\`, fmt.Sprintf("dmg-root-test-%d", time.Now().UnixNano()))
	root := filepath.Join(top, "StepSecurity")
	t.Cleanup(func() { _ = os.RemoveAll(top) })
	for _, d := range []string{top, root} {
		if _, err := EnsureProtectedDir(d); err != nil {
			t.Skipf("needs an elevated runner: %v", err)
		}
	}
	touch(t, filepath.Join(root, BootstrapFile))
	got, err := ResolveInstallRoot(filepath.Join(root, "versions", "1.20.0", AgentFile))
	if err != nil || got != root {
		t.Fatalf("ResolveInstallRoot = %q, %v; want %q", got, err, root)
	}
}

func TestDataRootIsProgramDataKnownFolder(t *testing.T) {
	want := filepath.Join(os.Getenv("ProgramData"), "StepSecurity")
	if got := DataRoot(); !strings.EqualFold(got, want) {
		t.Fatalf("DataRoot = %q, want %q", got, want)
	}
}
