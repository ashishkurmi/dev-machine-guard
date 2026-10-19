//go:build windows

package authenticode

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	trustENoSignature    = 0x800B0100 // TRUST_E_NOSIGNATURE
	trustESubjectFormUnk = 0x800B0003 // TRUST_E_SUBJECT_FORM_UNKNOWN
)

// newTrustData builds the WINTRUST_DATA for a file: no UI, no revocation.
// For GENERIC_VERIFY_V2 revocation is off only with
// WTD_REVOCATION_CHECK_NONE in dwProvFlags (fdwRevocationChecks=WTD_REVOKE_NONE
// alone applies to HTTPSPROV_ACTION), so both are set.
func newTrustData(file *windows.WinTrustFileInfo) *windows.WinTrustData {
	data := &windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
	}
	data.Size = uint32(unsafe.Sizeof(*data))
	return data
}

// winVerifyTrust runs WINTRUST_ACTION_GENERIC_VERIFY_V2 on path with no UI
// and no revocation checks (offline devices must not fail). Chain building
// may still fetch missing roots through Windows root auto-update.
func winVerifyTrust(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := &windows.WinTrustFileInfo{FilePath: p}
	file.Size = uint32(unsafe.Sizeof(*file))
	data := newTrustData(file)
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verr == nil {
		return nil
	}
	var errno windows.Errno
	if errors.As(verr, &errno) && (uint32(errno) == trustENoSignature || uint32(errno) == trustESubjectFormUnk) {
		return fmt.Errorf("%w: %s", ErrUnsigned, path)
	}
	return fmt.Errorf("%w: %s: %w", ErrUntrusted, path, verr)
}
