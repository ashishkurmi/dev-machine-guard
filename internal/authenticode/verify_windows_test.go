//go:build windows

package authenticode

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// testCert is a self-signed code-signing cert in LocalMachine\My, trusted
// through LocalMachine\Root and TrustedPublisher for the test's duration.
type testCert struct {
	thumb   string
	subject string
}

func powershell(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$ErrorActionPreference='Stop'; "+script).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell: %v\n%s\nscript: %s", err, out, script)
	}
	return strings.TrimSpace(string(out))
}

func newTestCert(t *testing.T, cn string) *testCert {
	t.Helper()
	subject := fmt.Sprintf("CN=%s %d", cn, time.Now().UnixNano())
	thumb := powershell(t, fmt.Sprintf(`
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject '%s' -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(2)
$f = Join-Path $env:TEMP ($c.Thumbprint + '.cer')
Export-Certificate -Cert $c -FilePath $f | Out-Null
Import-Certificate -FilePath $f -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $f -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Remove-Item $f
$c.Thumbprint`, subject))
	t.Cleanup(func() {
		for _, store := range []string{"My", "Root", "TrustedPublisher"} {
			_ = exec.Command("powershell.exe", "-NoProfile", "-Command",
				fmt.Sprintf(`Remove-Item -Force -ErrorAction SilentlyContinue Cert:\LocalMachine\%s\%s`, store, thumb)).Run()
		}
	})
	return &testCert{thumb: thumb, subject: subject}
}

// sign signs path; tsa empty means no timestamp. It reports false when the
// timestamp server could not be reached.
func (c *testCert) sign(t *testing.T, path, tsa string) bool {
	t.Helper()
	ts := ""
	if tsa != "" {
		ts = "-TimestampServer '" + tsa + "'"
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(`
$c = Get-Item Cert:\LocalMachine\My\%s
$r = Set-AuthenticodeSignature -FilePath '%s' -Certificate $c -HashAlgorithm SHA256 %s
$r.Status`, c.thumb, path, ts)).CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil || status != "Valid" {
		if tsa != "" {
			t.Logf("timestamped signing unavailable (%v): %s", err, status)
			return false
		}
		t.Fatalf("signing %s: %v: %s", path, err, status)
	}
	return true
}

func copyExe(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	p := filepath.Join(t.TempDir(), "candidate.exe")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to trust a test certificate machine-wide")
	}
}

func TestVerifyUnsignedWindows(t *testing.T) {
	if _, err := Verify(copyExe(t)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: %v, want ErrUnsigned", err)
	}
	// The test binary is unsigned, so without a pin no update is allowed.
	if testPinnedSubject() == "" {
		self, _ := os.Executable()
		if err := samePublisher(copyExe(t), self, func(string) (*Signature, error) { return &Signature{Subject: "CN=x"}, nil }, Inspect, ""); !errors.Is(err, ErrNoPublisher) {
			t.Fatalf("unsigned self: %v, want ErrNoPublisher", err)
		}
	}
}

func TestVerifySignedWindows(t *testing.T) {
	requireElevated(t)
	a := newTestCert(t, "DMG Test Publisher A")

	noTS := copyExe(t)
	a.sign(t, noTS, "")
	if _, err := Verify(noTS); !errors.Is(err, ErrNotTimestamped) {
		t.Fatalf("untimestamped: %v, want ErrNotTimestamped", err)
	}
	if sig, err := Inspect(noTS); err != nil || sig.Subject != a.subject {
		t.Fatalf("Inspect = %+v, %v; want subject %q", sig, err, a.subject)
	}

	// A flipped byte after signing breaks the digest.
	tampered := copyExe(t)
	a.sign(t, tampered, "")
	f, err := os.OpenFile(tampered, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	_, _ = f.ReadAt(b, 4096)
	b[0] ^= 0xff
	_, _ = f.WriteAt(b, 4096)
	_ = f.Close()
	if err := winVerifyTrust(tampered); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered: %v, want ErrUntrusted", err)
	}

	const tsa = "http://timestamp.digicert.com"
	good := copyExe(t)
	if !a.sign(t, good, tsa) {
		t.Skip("timestamp server unreachable; timestamped cases not run")
	}
	sig, err := Verify(good)
	if err != nil {
		t.Fatalf("timestamped signed: %v", err)
	}
	if sig.Subject != a.subject || !sig.Timestamped {
		t.Fatalf("sig = %+v", sig)
	}
	self := copyExe(t)
	a.sign(t, self, tsa)
	if err := SamePublisher(good, self); err != nil && testPinnedSubject() == "" {
		t.Fatalf("same publisher: %v", err)
	}

	bCert := newTestCert(t, "DMG Test Publisher B")
	wrong := copyExe(t)
	if !bCert.sign(t, wrong, tsa) {
		t.Skip("timestamp server unreachable")
	}
	if err := SamePublisher(wrong, self); !errors.Is(err, ErrPublisherMismatch) {
		t.Fatalf("wrong publisher: %v, want ErrPublisherMismatch", err)
	}
	if err := samePublisher(good, copyExe(t), Verify, Inspect, a.subject); err != nil {
		t.Fatalf("pinned subject: %v", err)
	}
}
