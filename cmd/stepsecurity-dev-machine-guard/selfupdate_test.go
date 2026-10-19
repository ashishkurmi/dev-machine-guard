package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunSelfUpdateArgs(t *testing.T) {
	if code := runSelfUpdate(nil); code != 2 {
		t.Fatalf("no --system: %d", code)
	}
	if code := runSelfUpdate([]string{"--user"}); code != 2 {
		t.Fatalf("unknown flag: %d", code)
	}
	if runtime.GOOS != "windows" {
		if code := runSelfUpdate([]string{"--system"}); code != 2 {
			t.Fatalf("non-Windows --system: %d", code)
		}
	}
}

func TestUpdateLogRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "update.log")
	logf := newUpdateLog(p)
	logf("hello %d", 1)
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "hello 1") {
		t.Fatalf("log = %q, %v", b, err)
	}
	if err := os.WriteFile(p, make([]byte, updateLogMaxBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	logf("after")
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("not rotated: %v", err)
	}
}

// STEPSEC_BOOTSTRAP_FALLBACK=<reason>[:<version>]: reason is the part
// before the first ':', update_to the version actually run (the suffix, or
// this binary's version), update_from the version state.json named.
func TestParseBootstrapFallback(t *testing.T) {
	for _, tc := range []struct{ env, named, self, reason, from, to string }{
		{"current_incomplete:1.19.0", "1.20.0", "1.19.0", "current_incomplete", "1.20.0", "1.19.0"},
		{"seed_fallback", "1.20.0", "1.18.0", "seed_fallback", "1.20.0", "1.18.0"},
		{"state_corrupt:1.18.0:extra", "", "1.18.0", "state_corrupt", "", "1.18.0"},
		{"bad:not-a-version", "1.20.0", "1.18.0", "bad", "1.20.0", "1.18.0"},
	} {
		reason, from, to := parseBootstrapFallback(tc.env, tc.named, tc.self)
		if reason != tc.reason || from != tc.from || to != tc.to {
			t.Errorf("%q: got (%q,%q,%q), want (%q,%q,%q)", tc.env, reason, from, to, tc.reason, tc.from, tc.to)
		}
	}
}
