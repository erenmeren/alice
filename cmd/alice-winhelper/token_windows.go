//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errTokenRead = errors.New("the token's elevation could not be read")

// tokenElevated reports whether the helper's own process token is elevated (TOKEN_ELEVATION). W0 (F3)
// read an elevated token, elevation type default and high integrity for a key-based OpenSSH logon of a
// local administrator, with and without LocalAccountTokenFilterPolicy. This is the reading of
// windows.Token.IsElevated, made here because IsElevated drops the call's error.
func tokenElevated() (bool, error) {
	var elevation uint32 // TOKEN_ELEVATION { DWORD TokenIsElevated; }
	var n uint32
	// unsafe: GetTokenInformation writes the 4-byte TOKEN_ELEVATION into elevation, sized by the call.
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &n)
	if err != nil || n != uint32(unsafe.Sizeof(elevation)) {
		return false, errTokenRead
	}
	return elevation != 0, nil
}
