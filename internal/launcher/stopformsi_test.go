package launcher

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D29: adopt-seed keeps a helper copy of the bootstrap in state\msi\ for
// the MSI's stop-for-msi action (not an MSI file, so the action's own
// image never races InstallFiles).
func TestAdoptSeedRefreshesMSIHelper(t *testing.T) {
	f := newFixture(t)
	self := filepath.Join(t.TempDir(), "stepsecurity-dev-machine-guard-bootstrap.exe")
	if err := os.WriteFile(self, []byte("bootstrap-image-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.b.SelfExe = self
	f.adopt(f.seed("1.5.0"))
	got, err := os.ReadFile(f.layout.MSIHelperFile())
	if err != nil || !bytes.Equal(got, []byte("bootstrap-image-v1")) {
		t.Fatalf("helper = %q, %v", got, err)
	}
	if err := os.WriteFile(self, []byte("bootstrap-image-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.adopt(f.seed("1.5.0"))
	if got, _ := os.ReadFile(f.layout.MSIHelperFile()); string(got) != "bootstrap-image-v2" {
		t.Fatalf("helper not refreshed: %q", got)
	}
}

func TestStopForMSIVerb(t *testing.T) {
	f := newFixture(t)
	if code := f.b.Main([]string{"stop-for-msi", "--install-dir", f.layout.InstallRoot}); code != 0 {
		t.Fatalf("stop-for-msi = %d", code)
	}
	if !strings.Contains(f.out.String(), "stop-for-msi") {
		t.Fatalf("not logged: %s", f.out.String())
	}
	if code := f.b.Main([]string{"stop-for-msi"}); code != 0 {
		t.Fatal("stop-for-msi without --install-dir must not fail the MSI")
	}
}
