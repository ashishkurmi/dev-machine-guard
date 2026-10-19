package selfupdate

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

func newReleaseFixture(t *testing.T) (*fakeAPI, *Client) {
	t.Helper()
	f := newFakeAPI(t)
	f.addRelease("1.20.0", "arm64", []byte("agent-1.20.0"), []byte("task-1.20.0"), []byte("linux-1.20.0"))
	f.setTarget("1.20.0")
	return f, f.client("arm64")
}

func TestLatestRequestsNativeArchWithAuth(t *testing.T) {
	f, c := newReleaseFixture(t)
	c.LagBehind, c.CooldownHours = 1, 24
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version.String() != "1.20.0" || len(rel.Assets) != 3 {
		t.Fatalf("release = %+v", rel)
	}
	wantRemote := map[string]string{
		updatestate.AgentFile:    "stepsecurity-dev-machine-guard-1.20.0-windows_arm64.exe",
		updatestate.LauncherFile: "stepsecurity-dev-machine-guard-task-1.20.0-windows_arm64.exe",
		updatestate.LinuxFile:    "stepsecurity-dev-machine-guard-1.20.0-linux_arm64",
	}
	for _, a := range rel.Assets {
		if wantRemote[a.File] != a.Remote {
			t.Errorf("%s remote = %s, want %s", a.File, a.Remote, wantRemote[a.File])
		}
	}
	// D11: one resolution = one version; dmg-linux comes from the same
	// windows response.
	if len(f.requests) != 1 {
		t.Fatalf("latest-binary requests = %d, want 1", len(f.requests))
	}
	for i, goos := range []string{"windows"} {
		r := f.requests[i]
		q := r.URL.Query()
		if q.Get("os") != goos || q.Get("arch") != "arm64" || q.Get("lag_behind") != "1" || q.Get("cooldown_hours") != "24" {
			t.Errorf("query %d = %s", i, r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "Bearer key" || r.Header.Get("X-Agent-Version") != "1.19.0" {
			t.Errorf("headers %d = %v", i, r.Header)
		}
	}
}

func TestLatestRejectsNonStrictVersions(t *testing.T) {
	for _, v := range []string{"1.20.0-rc.1", "v1.20.0", "1.20", "../1.20.0", `..\x`, "01.2.3", "1.2.3+meta", ""} {
		t.Run(v, func(t *testing.T) {
			f, c := newReleaseFixture(t)
			f.setTarget(v)
			if _, err := c.Latest(context.Background()); !errors.Is(err, ErrCheck) {
				t.Fatalf("Latest(%q) err = %v, want ErrCheck", v, err)
			}
		})
	}
}

func TestLatestFailures(t *testing.T) {
	cases := map[string]func(f *fakeAPI){
		"http 500":        func(f *fakeAPI) { f.metaStatus = 500 },
		"http 422":        func(f *fakeAPI) { f.metaStatus = 422 },
		"garbage":         func(f *fakeAPI) { f.metaBody = "<html>" },
		"oversized":       func(f *fakeAPI) { f.metaBody = `{"version":"` + strings.Repeat("1", maxMetaBytes) + `"}` },
		"no launcher":     func(f *fakeAPI) { f.metaBody = `{"version":"1.20.0","checksum":"a","signed_checksum":"b"}` },
		"missing release": func(f *fakeAPI) { f.target = "1.21.0" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := newReleaseFixture(t)
			mut(f)
			if _, err := c.Latest(context.Background()); !errors.Is(err, ErrCheck) {
				t.Fatalf("err = %v, want ErrCheck", err)
			}
		})
	}
}

// D11: a response without the dmg-linux fields is a verify failure, not a
// silent skip and not a check failure.
func TestMissingLinuxFieldsFailVerification(t *testing.T) {
	f, c := newReleaseFixture(t)
	f.noLinuxFields = true
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest = %v, want a release whose verification fails", err)
	}
	if err := c.VerifySignatures(rel); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), updatestate.LinuxFile) {
		t.Fatalf("VerifySignatures = %v, want ErrVerify naming %s", err, updatestate.LinuxFile)
	}
}

func TestVerifySignatures(t *testing.T) {
	f, c := newReleaseFixture(t)
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifySignatures(rel); err != nil {
		t.Fatalf("good release rejected: %v", err)
	}

	other := newTestSigner(t)
	wrongKey := *c
	wrongKey.SigningKey = other.pubB64
	if err := wrongKey.VerifySignatures(rel); !errors.Is(err, ErrVerify) {
		t.Fatalf("wrong key: err = %v", err)
	}

	f.badSig["stepsecurity-dev-machine-guard-task-1.20.0-windows_arm64.exe"] = true
	rel2, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifySignatures(rel2); !errors.Is(err, ErrVerify) {
		t.Fatalf("bad launcher signature: err = %v", err)
	}

	rel2.Assets[1].Signed = ""
	if err := c.VerifySignatures(rel2); !errors.Is(err, ErrVerify) {
		t.Fatalf("missing signature: err = %v", err)
	}
	rel2.Assets[1].Checksum = "nothex"
	if err := c.VerifySignatures(rel2); !errors.Is(err, ErrVerify) {
		t.Fatalf("non-sha checksum: err = %v", err)
	}
}

func TestReleaseKeyIsPinnedByDefault(t *testing.T) {
	c := &Client{}
	if testSSHSIGKey() == "" && c.signingKey() != releasePublicKeyB64 {
		t.Fatalf("default signing key = %q", c.signingKey())
	}
	if testReleaseBaseURL() == "" && c.releaseBase() != defaultReleaseBaseURL {
		t.Fatalf("default release base = %q", c.releaseBase())
	}
}

func TestDownloadGitHubThenMirror(t *testing.T) {
	f, c := newReleaseFixture(t)
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v := rel.Version
	agent := rel.Assets[0]

	dir := t.TempDir()
	if err := c.Download(context.Background(), v, agent, dir); err != nil {
		t.Fatalf("github download: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, updatestate.AgentFile)); string(b) != "agent-1.20.0" {
		t.Fatalf("content = %q", b)
	}

	f.githubDown = true
	if err := c.Download(context.Background(), v, agent, t.TempDir()); !errors.Is(err, ErrDownload) {
		t.Fatalf("github down, no mirror: err = %v", err)
	}
	c.MirrorURL = f.URL() + "/mirror"
	if err := c.Download(context.Background(), v, agent, t.TempDir()); err != nil {
		t.Fatalf("mirror fallback: %v", err)
	}
	if f.mirrorHits[agent.Remote] != 1 {
		t.Fatalf("mirror hits = %d", f.mirrorHits[agent.Remote])
	}
	f.mirrorDown = true
	if err := c.Download(context.Background(), v, agent, t.TempDir()); !errors.Is(err, ErrDownload) {
		t.Fatalf("both down: err = %v", err)
	}
}

func TestDownloadRejectsInsecureMirror(t *testing.T) {
	f, c := newReleaseFixture(t)
	rel, _ := c.Latest(context.Background())
	f.githubDown = true
	u, _ := url.Parse(f.URL())
	u.Scheme = "http"
	c.MirrorURL = u.String() + "/mirror"
	err := c.Download(context.Background(), rel.Version, rel.Assets[0], t.TempDir())
	if testAllowInsecureMirror() {
		t.Skip("insecure mirror allowed by DMG_TEST_ALLOW_HTTP_MIRROR")
	}
	if err == nil || !strings.Contains(err.Error(), "invalid HTTPS update mirror") {
		t.Fatalf("err = %v", err)
	}
}

func TestDownloadChecksumMismatchIsVerifyFailure(t *testing.T) {
	_, c := newReleaseFixture(t)
	rel, _ := c.Latest(context.Background())
	a := rel.Assets[2]
	a.Checksum = strings.Repeat("ab", 32)
	if err := c.Download(context.Background(), rel.Version, a, t.TempDir()); !errors.Is(err, ErrVerify) {
		t.Fatalf("err = %v, want ErrVerify", err)
	}
}

func TestDownloadSizeLimit(t *testing.T) {
	f, c := newReleaseFixture(t)
	big := make([]byte, maxAssetBytes+1)
	f.addRelease("1.20.0", "arm64", big, []byte("t"), []byte("l"))
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Download(context.Background(), rel.Version, rel.Assets[0], t.TempDir()); !errors.Is(err, ErrDownload) {
		t.Fatalf("err = %v, want ErrDownload (size limit)", err)
	}
}

func TestDecodeSignedChecksum(t *testing.T) {
	if _, err := decodeSignedChecksum("!!!"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := decodeSignedChecksum("aGVsbG8="); err == nil {
		t.Fatal("non-armored payload accepted")
	}
	if got, err := decodeSignedChecksum(fixtureSig); err != nil || got != fixtureSig {
		t.Fatalf("raw armor: %v", err)
	}
}

func TestFloorParses(t *testing.T) {
	if Floor().String() != minWindowsSelfUpdateVersion {
		t.Fatal(Floor())
	}
}

func TestProxyParsing(t *testing.T) {
	mp := parseWinHTTPProxy("http=proxy:3128;https=secure:8443", "<local>;*.corp.example;10.*")
	mustProxy := func(raw, want string) {
		t.Helper()
		u, _ := url.Parse(raw)
		got := mp.proxyFor(u)
		gs := ""
		if got != nil {
			gs = got.Host
		}
		if gs != want {
			t.Errorf("proxyFor(%s) = %q, want %q", raw, gs, want)
		}
	}
	mustProxy("https://api.stepsecurity.io/x", "secure:8443")
	mustProxy("http://example.com/", "proxy:3128")
	mustProxy("https://intranet/", "")
	mustProxy("https://a.corp.example/", "")
	mustProxy("https://10.1.2.3/", "")
	mustProxy("https://127.0.0.1/", "")

	single := parseWinHTTPProxy("http://gw.example:8080", "")
	u, _ := url.Parse("https://github.com/")
	if p := single.proxyFor(u); p == nil || p.Host != "gw.example:8080" {
		t.Fatalf("single proxy = %v", p)
	}
	if parseWinHTTPProxy("", "") != nil || parseWinHTTPProxy(" ; ", "") != nil {
		t.Fatal("empty proxy list parsed as a proxy")
	}
}

func TestProxyFuncPrefersEnvironment(t *testing.T) {
	envURL, _ := url.Parse("http://env-proxy:1")
	mp := parseWinHTTPProxy("machine:2", "")
	req, _ := http.NewRequest(http.MethodGet, "https://api.example/", nil)

	fromEnv := proxyFunc(func(*http.Request) (*url.URL, error) { return envURL, nil }, mp)
	if u, _ := fromEnv(req); u.Host != "env-proxy:1" {
		t.Fatalf("env proxy not preferred: %v", u)
	}
	noEnv := proxyFunc(func(*http.Request) (*url.URL, error) { return nil, nil }, mp)
	if u, _ := noEnv(req); u == nil || u.Host != "machine:2" {
		t.Fatalf("machine proxy not used: %v", u)
	}
	none := proxyFunc(func(*http.Request) (*url.URL, error) { return nil, nil }, nil)
	if u, _ := none(req); u != nil {
		t.Fatalf("proxy without config: %v", u)
	}
	if NewHTTPClient() == nil {
		t.Fatal("nil client")
	}
}

func TestNativeArch(t *testing.T) {
	if a := NativeArch(); a != "amd64" && a != "arm64" && a != "386" && a != "riscv64" && a != "s390x" && a != "ppc64le" && a != "loong64" {
		t.Fatalf("NativeArch = %q", a)
	}
}
