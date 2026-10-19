// Package authenticode checks Windows code signatures for the self-updater:
// the candidate must carry a valid, timestamped Authenticode signature whose
// leaf signer subject equals the running updater's own signer subject, so
// no publisher is hard-coded and a Trusted Signing certificate rotation
// (same subject, new key) keeps working.
//
// Trust (chain, digest) comes from WinVerifyTrust on Windows. The signer
// subject and the timestamp are read from the PE's PKCS#7 blob in Go, which
// is portable and testable everywhere.
package authenticode

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsigned means the file has no Authenticode signature.
	ErrUnsigned = errors.New("authenticode: file is not signed")
	// ErrNotTimestamped means the signature has no countersignature
	// timestamp, so it stops validating when the signing cert expires.
	ErrNotTimestamped = errors.New("authenticode: signature is not timestamped")
	// ErrUntrusted means WinVerifyTrust rejected the signature.
	ErrUntrusted = errors.New("authenticode: signature not trusted")
	// ErrPublisherMismatch means the candidate's signer differs from ours.
	ErrPublisherMismatch = errors.New("authenticode: publisher differs from the running updater")
	// ErrNoPublisher means the running updater has no signer to compare
	// against (an unsigned dev build) and no test pin is configured.
	ErrNoPublisher = errors.New("authenticode: running updater is unsigned; refusing updates")
	// ErrUnsupported is returned off Windows, where WinVerifyTrust is absent.
	ErrUnsupported = errors.New("authenticode: verification is only supported on Windows")
)

// Signature describes a file's primary Authenticode signature.
type Signature struct {
	Subject     string // leaf signer subject, RFC 2253 form
	Timestamped bool
}

// Verify checks path with WinVerifyTrust (revocation off) and requires a
// timestamped signature.
func Verify(path string) (*Signature, error) {
	if err := winVerifyTrust(path); err != nil {
		return nil, err
	}
	sig, err := Inspect(path)
	if err != nil {
		return nil, err
	}
	if !sig.Timestamped {
		return nil, fmt.Errorf("%w: %s", ErrNotTimestamped, path)
	}
	return sig, nil
}

// SamePublisher verifies candidate and checks that its leaf subject equals
// the subject of self (the running updater). A selfupdate_testkeys build may
// pin the expected subject instead (DMG_TEST_AUTHENTICODE_SUBJECT). An
// unsigned self with no pin refuses every candidate.
func SamePublisher(candidate, self string) error {
	return samePublisher(candidate, self, Verify, Inspect, testPinnedSubject())
}

func samePublisher(candidate, self string, verify, inspect func(string) (*Signature, error), pin string) error {
	got, err := verify(candidate)
	if err != nil {
		return err
	}
	want := pin
	if want == "" {
		// Our own image only supplies the expected subject; it is already
		// running, so re-checking its trust adds nothing.
		own, err := inspect(self)
		switch {
		case errors.Is(err, ErrUnsigned):
			return ErrNoPublisher
		case err != nil:
			return fmt.Errorf("authenticode: read own signature: %w", err)
		}
		want = own.Subject
	}
	if want == "" || got.Subject != want {
		return fmt.Errorf("%w: %q, want %q", ErrPublisherMismatch, got.Subject, want)
	}
	return nil
}
