package updatestate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStateFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPointers(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCorr bool
		want     *Pointers
	}{
		{"schema1", `{"schema":1,"current":"1.2.3","previous":"1.2.2","probation":{"version":"1.2.3"},"updater":{"version":"1.2.2","consecutive_failures":3}}`,
			false, &Pointers{Schema: 1, Current: "1.2.3", Previous: "1.2.2", Probation: "1.2.3", Updater: Updater{Version: "1.2.2", ConsecutiveFailures: 3}}},
		{"schema1 extra fields", `{"schema":1,"current":"1.2.3","future":{"x":1}}`, false, &Pointers{Schema: 1, Current: "1.2.3"}},
		{"higher schema reads pointers only", `{"schema":7,"current":"2.0.0","previous":"bogus","probation":"???","updater":5}`,
			false, &Pointers{Schema: 7, Current: "2.0.0"}},
		{"higher schema bad current", `{"schema":2,"current":"..\\x"}`, true, nil},
		{"schema0", `{"schema":0,"current":"1.2.3"}`, true, nil},
		{"traversal", `{"schema":1,"current":"..\\x"}`, true, nil},
		{"garbage", `not json`, true, nil},
		{"empty", ``, true, nil},
		{"schema1 invalid counter", `{"schema":1,"current":"1.2.3","switch_deferrals":-1}`, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, corrupt, err := LoadPointers(writeStateFile(t, tc.body))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if corrupt != tc.wantCorr {
				t.Fatalf("corrupt = %v, want %v", corrupt, tc.wantCorr)
			}
			if tc.want == nil {
				if p != nil {
					t.Fatalf("p = %+v, want nil", p)
				}
				return
			}
			if *p != *tc.want {
				t.Fatalf("p = %+v, want %+v", *p, *tc.want)
			}
		})
	}
}

func TestLoadPointers_MissingAndHuge(t *testing.T) {
	p, corrupt, err := LoadPointers(filepath.Join(t.TempDir(), "nope.json"))
	if p != nil || corrupt || err != nil {
		t.Fatalf("missing: %v %v %v", p, corrupt, err)
	}
	huge := `{"schema":1,"current":"1.2.3","pad":"` + strings.Repeat("a", maxStateSize) + `"}`
	p, corrupt, err = LoadPointers(writeStateFile(t, huge))
	if p != nil || !corrupt || err != nil {
		t.Fatalf("huge: %v %v %v", p, corrupt, err)
	}
}

func TestPatchCheckpointed_KeepsUnknownFields(t *testing.T) {
	path := writeStateFile(t, `{"schema":1,"current":"1.2.3","future_field":{"a":[1,2]},"updater":{"version":"1.2.3","consecutive_failures":1}}`)
	err := PatchCheckpointed(path, "", func(s *State) error {
		s.Updater.ConsecutiveFailures++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st, corrupt, err := Load(path)
	if err != nil || corrupt {
		t.Fatalf("load: %v %v", corrupt, err)
	}
	if st.Updater.ConsecutiveFailures != 2 {
		t.Fatalf("failures = %d", st.Updater.ConsecutiveFailures)
	}
	data, _ := os.ReadFile(path)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["future_field"]) == "" {
		t.Fatalf("future_field dropped: %s", data)
	}
}

func TestPatchCheckpointed_RefusesNonPatchable(t *testing.T) {
	for _, body := range []string{"", "garbage", `{"schema":2,"current":"1.2.3"}`} {
		path := writeStateFile(t, body)
		err := PatchCheckpointed(path, "", func(*State) error { return nil })
		if !errors.Is(err, ErrStateNotPatchable) {
			t.Fatalf("%q: err = %v", body, err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != body {
			t.Fatalf("%q: file changed to %q", body, got)
		}
	}
	err := PatchCheckpointed(filepath.Join(t.TempDir(), "missing.json"), "", func(*State) error { return nil })
	if !errors.Is(err, ErrStateNotPatchable) {
		t.Fatalf("missing: err = %v", err)
	}
}

func TestPatchCheckpointed_RejectsInvalidResult(t *testing.T) {
	path := writeStateFile(t, `{"schema":1,"current":"1.2.3"}`)
	err := PatchCheckpointed(path, "", func(s *State) error { s.Current = "nope"; return nil })
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestPatchCheckpointed_KeepsNestedUnknownFieldsOfUntouchedKeys(t *testing.T) {
	path := writeStateFile(t, `{"schema":1,"current":"1.2.3","quarantine":{"1.2.4":{"reason":"bad_runs","at":"2026-01-01T00:00:00Z","until":"2026-01-08T00:00:00Z"}}}`)
	if err := PatchCheckpointed(path, "", func(s *State) error { s.Updater.ConsecutiveFailures = 1; return nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"until"`) {
		t.Fatalf("nested quarantine field dropped: %s", data)
	}
}

func TestPatchCheckpointed_NoChangeNoWrite(t *testing.T) {
	body := `{"schema":1,"current":"1.2.3"}`
	path := writeStateFile(t, body)
	if err := PatchCheckpointed(path, "", func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Fatalf("rewritten: %s", got)
	}
}

func TestResolveRunVersion(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	mk := func(dir string, files ...string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if v, why := ResolveRunVersion(l, nil); why != FallbackNothingRunnable || v != (Version{}) {
		t.Fatalf("empty: %v %q", v, why)
	}
	mk(filepath.Join(l.InstallRoot, "seed", "1.0.0"), RunnableAgentName, RunnableTaskName)
	mk(filepath.Join(l.InstallRoot, "seed", "0.9.0"), RunnableAgentName, RunnableTaskName)
	mk(filepath.Join(l.InstallRoot, "seed", "2.0.0"), RunnableAgentName) // incomplete: ignored
	if v, why := ResolveRunVersion(l, nil); v.String() != "1.0.0" || why != FallbackStateMissing {
		t.Fatalf("missing state: %v %q", v, why)
	}
	st := &State{Schema: 1, Current: "1.2.0", Previous: "1.1.0"}
	mk(l.VersionDir(Version{1, 1, 0}), RunnableAgentName, RunnableTaskName)
	if v, why := ResolveRunVersion(l, st); v.String() != "1.1.0" || why != FallbackCurrentMissing+":1.2.0" {
		t.Fatalf("previous: %v %q", v, why)
	}
	mk(l.VersionDir(Version{1, 2, 0}), RunnableTaskName)
	if _, why := ResolveRunVersion(l, st); why != FallbackCurrentIncomplete+":1.2.0" {
		t.Fatalf("incomplete: %q", why)
	}
	mk(l.VersionDir(Version{1, 2, 0}), RunnableAgentName)
	if v, why := ResolveRunVersion(l, st); v.String() != "1.2.0" || why != "" {
		t.Fatalf("current: %v %q", v, why)
	}
}
