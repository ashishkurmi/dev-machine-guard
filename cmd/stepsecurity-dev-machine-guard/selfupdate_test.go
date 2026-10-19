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
