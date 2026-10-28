//go:build windows

package main

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// Security review M1 (W6, R69): the key's descriptor is bounded before Windows reads it. These are
// crafted buffers, not a key: the test runs on every Windows run, without ALICE_WIN_REAL.

const testDACLOff = minRelativeSD // the DACL right after the 20-byte header

// craftedSD is a self-relative descriptor with control and a DACL at off holding the ACEs (aclSize and
// count as given), in an 8-byte-aligned buffer of n bytes; it returns the buffer and its byte view.
func craftedSD(t *testing.T, n int, control uint16, off, aclSize, count int, aces ...[]byte) ([]uint64, []byte) {
	t.Helper()
	buf := make([]uint64, (n+7)/8)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], control)
	binary.LittleEndian.PutUint32(b[16:], uint32(off)) //nolint:gosec // G115: a test offset
	if off >= minRelativeSD && off+8 <= n {
		b[off] = 2                                                // ACL_REVISION
		binary.LittleEndian.PutUint16(b[off+2:], uint16(aclSize)) //nolint:gosec // G115: a test size
		binary.LittleEndian.PutUint16(b[off+4:], uint16(count))   //nolint:gosec // G115: a test count
		pos := off + 8
		for _, a := range aces {
			pos += copy(b[pos:], a)
		}
	}
	return buf, b
}

func networkServiceACE(t *testing.T) []byte {
	t.Helper()
	ns, err := windows.CreateWellKnownSid(windows.WinNetworkServiceSid)
	require.NoError(t, err)
	ace, err := explicitACE(windows.GRANT_ACCESS, rdpGrantMask, ns)
	require.NoError(t, err)
	return ace
}

func TestCheckRelativeDACL(t *testing.T) {
	ace := networkServiceACE(t)
	self, present := uint16(windows.SE_SELF_RELATIVE), uint16(windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT)
	acl := 8 + len(ace)
	n := testDACLOff + acl
	short := binary.LittleEndian.AppendUint16([]byte{0, 0}, 4) // an ACE of 4 bytes

	ok := map[string][]byte{}
	_, ok["one ACE"] = craftedSD(t, n, present, testDACLOff, acl, 1, ace)
	_, ok["no DACL (NULL)"] = craftedSD(t, minRelativeSD, self, 0, 0, 0)
	_, ok["DACL present at offset 0 (NULL)"] = craftedSD(t, minRelativeSD, present, 0, 0, 0)
	_, ok["an empty DACL"] = craftedSD(t, testDACLOff+8, present, testDACLOff, 8, 0)
	for name, b := range ok {
		assert.NoError(t, checkRelativeDACL(b), name)
	}

	bad := map[string][]byte{}
	_, bad["shorter than the header"] = craftedSD(t, minRelativeSD, present, 0, 0, 0)
	bad["shorter than the header"] = bad["shorter than the header"][:minRelativeSD-1]
	_, bad["not self-relative"] = craftedSD(t, n, windows.SE_DACL_PRESENT, testDACLOff, acl, 1, ace)
	_, bad["the DACL inside the header"] = craftedSD(t, n, present, 8, acl, 1)
	_, bad["the DACL header past the end"] = craftedSD(t, n, present, n-4, acl, 1)
	_, bad["AclSize past the end"] = craftedSD(t, n, present, testDACLOff, acl+4, 1, ace)
	_, bad["AclSize below its header"] = craftedSD(t, n, present, testDACLOff, 4, 0)
	_, bad["too many ACEs"] = craftedSD(t, n, present, testDACLOff, acl, maxACEs+1, ace)
	_, bad["an ACE below 8 bytes"] = craftedSD(t, n, present, testDACLOff, acl, 1, short)
	_, bad["a second ACE past the ACL"] = craftedSD(t, n+len(ace), present, testDACLOff, acl, 2, ace, ace)
	_, bad["an ACE header past the ACL"] = craftedSD(t, n, present, testDACLOff, 8, 1, ace)
	for name, b := range bad {
		assert.ErrorIs(t, checkRelativeDACL(b), errKeyACL, name)
	}
}

// eachACE stops at an ACE that ends past AclSize, whatever GetAce answers.
func TestEachACEStaysInsideTheACL(t *testing.T) {
	ace := networkServiceACE(t)
	acl := 8 + len(ace)
	buf, _ := craftedSD(t, testDACLOff+acl, windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT, testDACLOff, acl, 1, ace)
	// unsafe: the ACL at testDACLOff inside buf (8-byte aligned).
	dacl := (*windows.ACL)(unsafe.Add(unsafe.Pointer(&buf[0]), testDACLOff))
	var seen int
	require.NoError(t, eachACE(dacl, func(_ *windows.ACCESS_ALLOWED_ACE, sid *windows.SID, raw []byte) {
		seen++
		assert.NotNil(t, sid)
		assert.Equal(t, ace, raw)
	}))
	assert.Equal(t, 1, seen)

	buf2, _ := craftedSD(t, testDACLOff+acl+len(ace), windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT, testDACLOff, acl, 2, ace, ace)
	// unsafe: as above; AceCount 2 while AclSize holds one ACE.
	dacl2 := (*windows.ACL)(unsafe.Add(unsafe.Pointer(&buf2[0]), testDACLOff))
	assert.ErrorIs(t, eachACE(dacl2, func(*windows.ACCESS_ALLOWED_ACE, *windows.SID, []byte) {}), errKeyACL)
}

// wellKnownACE is one explicit ACE of this mode and mask for a well-known SID.
func wellKnownACE(t *testing.T, mode windows.ACCESS_MODE, mask uint32, who windows.WELL_KNOWN_SID_TYPE) []byte {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(who)
	require.NoError(t, err)
	ace, err := explicitACE(mode, mask, sid)
	require.NoError(t, err)
	return ace
}

// TestNetworkServiceCanReadDeny (WIN-65, residual risk 7's deny half, R70) walks crafted DACLs: a deny
// with a read bit for NETWORK SERVICE or Everyone is errKeyReadDenied, in the generic form, the form
// the KSP stores (0x80120089) and the specific-only form; a deny for Guests, a deny without a read bit
// (WRITE_DAC; GENERIC_WRITE as the KSP stores it, with READ_CONTROL and SYNCHRONIZE) and an
// inherit-only deny are not. The real runner carries the NETWORK SERVICE rows (TestRealRDPKeyReadRefusesADeny).
func TestNetworkServiceCanReadDeny(t *testing.T) {
	ns, world, guests := windows.WELL_KNOWN_SID_TYPE(windows.WinNetworkServiceSid), windows.WELL_KNOWN_SID_TYPE(windows.WinWorldSid),
		windows.WELL_KNOWN_SID_TYPE(windows.WinBuiltinGuestsSid)
	inheritOnly := wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_READ, ns)
	inheritOnly[1] |= windows.INHERIT_ONLY_ACE // byte 1 of an ACE is its flags
	for _, c := range []struct {
		name   string
		aces   [][]byte
		denied bool
		read   bool
	}{
		{"NETWORK SERVICE denied GENERIC_READ", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_READ, ns)}, true, false},
		{"NETWORK SERVICE denied as the KSP stores it", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, rdpGrantMask, ns)}, true, false},
		{"NETWORK SERVICE denied the specific read bits", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, 0x120089, ns)}, true, false},
		{"Everyone denied GENERIC_READ", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_READ, world)}, true, false},
		{"a deny beside the grant", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_READ, ns), networkServiceACE(t)}, true, false},
		{"Guests denied GENERIC_READ", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_READ, guests)}, false, false},
		{"NETWORK SERVICE denied WRITE_DAC only", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.WRITE_DAC, ns)}, false, false},
		{"NETWORK SERVICE denied GENERIC_WRITE as the KSP stores it", [][]byte{wellKnownACE(t, windows.DENY_ACCESS, windows.GENERIC_WRITE|0x120116, ns)}, false, false},
		{"an inherit-only deny", [][]byte{inheritOnly}, false, false},
		{"the grant alone", [][]byte{networkServiceACE(t)}, false, true},
	} {
		acl := 8
		for _, a := range c.aces {
			acl += len(a)
		}
		buf, _ := craftedSD(t, testDACLOff+acl, windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT, testDACLOff, acl, len(c.aces), c.aces...)
		// unsafe: buf holds the crafted self-relative descriptor (8-byte aligned).
		readable, err := networkServiceCanRead((*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0])))
		if c.denied {
			assert.ErrorIs(t, err, errKeyReadDenied, c.name)
			assert.False(t, readable, c.name)
			continue
		}
		require.NoError(t, err, c.name)
		assert.Equal(t, c.read, readable, c.name)
	}
}
