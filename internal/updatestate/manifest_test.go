package updatestate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeVersionDir(t *testing.T, dir, v string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Version: v, Files: map[string]string{}}
	for _, name := range VersionFiles {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(name+v), 0o755); err != nil {
			t.Fatal(err)
		}
		h, err := FileSHA256(p)
		if err != nil {
			t.Fatal(err)
		}
		m.Files[name] = h
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyVersionDir(t *testing.T) {
	v, _ := ParseVersion("1.20.0")
	dir := filepath.Join(t.TempDir(), "1.20.0")
	writeVersionDir(t, dir, "1.20.0")
	if err := VerifyVersionDir(dir, v); err != nil {
		t.Fatalf("good dir: %v", err)
	}
	other, _ := ParseVersion("1.21.0")
	if err := VerifyVersionDir(dir, other); err == nil {
		t.Fatal("version mismatch accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, LinuxFile), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVersionDir(dir, v); err == nil {
		t.Fatal("tampered file accepted")
	}
	if err := os.Remove(filepath.Join(dir, AgentFile)); err != nil {
		t.Fatal(err)
	}
	if err := VersionDirComplete(dir); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing agent: %v", err)
	}
	if err := WriteManifest(dir, Manifest{Version: "v1"}); err == nil {
		t.Fatal("non-strict manifest version written")
	}
}
