package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// SelfCheck is the `agent self-check` output (spec Contracts: CLI).
type SelfCheck struct {
	Version  string `json:"version"`
	DeviceID string `json:"device_id"`
	ConfigOK bool   `json:"config_ok"`
}

// limitedBuffer keeps at most max bytes.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// RunSmoke runs `<exe> self-check` with the smoke time limit and checks
// that it exits 0 reporting version want, a loaded config and a device id.
func RunSmoke(ctx context.Context, exe string, want updatestate.Version) error {
	ctx, cancel := context.WithTimeout(ctx, duration(knobSmokeTimeout))
	defer cancel()
	// #nosec G204 -- exe is a verified, manifest-checked version dir binary.
	cmd := exec.CommandContext(ctx, exe, "self-check")
	stdout := &limitedBuffer{max: 64 << 10}
	stderr := &limitedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	prepareSmoke(cmd)
	if err := runSmokeCmd(cmd); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("self-check timed out after %s", duration(knobSmokeTimeout))
		}
		return fmt.Errorf("self-check: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return checkSelfCheck(stdout.Bytes(), want)
}

func checkSelfCheck(out []byte, want updatestate.Version) error {
	var sc SelfCheck
	if err := json.Unmarshal(bytes.TrimSpace(out), &sc); err != nil {
		return fmt.Errorf("self-check output is not JSON: %w", err)
	}
	switch {
	case sc.Version != want.String():
		return fmt.Errorf("self-check reports version %q, want %s", sc.Version, want)
	case !sc.ConfigOK:
		return fmt.Errorf("self-check could not load the config")
	case strings.TrimSpace(sc.DeviceID) == "" || sc.DeviceID == "unknown":
		return fmt.Errorf("self-check resolved no device id")
	}
	return nil
}
