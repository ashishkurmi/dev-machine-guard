//go:build !windows

package authenticode

func winVerifyTrust(string) error { return ErrUnsupported }
