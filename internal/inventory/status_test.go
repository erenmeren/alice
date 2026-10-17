package inventory

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

// statusAfterSuccess over every status, with and without a pinned key, for an explicit connection
// test and for a discovery or removal.
func TestStatusAfterSuccessTable(t *testing.T) {
	type in struct {
		current      string
		pinned, test bool
	}
	want := map[in]string{
		// An explicit connection test connects every status a person does not own, and a target
		// without a pinned key goes back to waiting for its confirmation.
		{StatusPendingHostKey, false, true}: StatusPendingHostKey,
		{StatusPendingHostKey, true, true}:  StatusOK,
		{StatusChecking, false, true}:       StatusPendingHostKey,
		{StatusChecking, true, true}:        StatusOK,
		{StatusOK, false, true}:             StatusPendingHostKey,
		{StatusOK, true, true}:              StatusOK,
		{StatusUnreachable, false, true}:    StatusPendingHostKey,
		{StatusUnreachable, true, true}:     StatusOK,
		{StatusAuthFailed, false, true}:     StatusPendingHostKey,
		{StatusAuthFailed, true, true}:      StatusOK,
		{StatusHostKeyChanged, false, true}: StatusHostKeyChanged,
		{StatusHostKeyChanged, true, true}:  StatusHostKeyChanged,
		{StatusDisabled, false, true}:       StatusDisabled,
		{StatusDisabled, true, true}:        StatusDisabled,
		// A discovery or a removal connects only an unreachable or checking target with a pinned
		// key; it never leaves a status a person must act on.
		{StatusPendingHostKey, false, false}: StatusPendingHostKey,
		{StatusPendingHostKey, true, false}:  StatusPendingHostKey,
		{StatusChecking, false, false}:       StatusChecking,
		{StatusChecking, true, false}:        StatusOK,
		{StatusOK, false, false}:             StatusOK,
		{StatusOK, true, false}:              StatusOK,
		{StatusUnreachable, false, false}:    StatusUnreachable,
		{StatusUnreachable, true, false}:     StatusOK,
		{StatusAuthFailed, false, false}:     StatusAuthFailed,
		{StatusAuthFailed, true, false}:      StatusAuthFailed,
		{StatusHostKeyChanged, false, false}: StatusHostKeyChanged,
		{StatusHostKeyChanged, true, false}:  StatusHostKeyChanged,
		{StatusDisabled, false, false}:       StatusDisabled,
		{StatusDisabled, true, false}:        StatusDisabled,
	}
	statuses := []string{StatusPendingHostKey, StatusChecking, StatusOK, StatusUnreachable, StatusAuthFailed, StatusHostKeyChanged, StatusDisabled}
	assert.Len(t, want, len(statuses)*4, "every status, pinned or not, test or not")
	for _, current := range statuses {
		for _, pinned := range []bool{false, true} {
			for _, test := range []bool{false, true} {
				k := in{current, pinned, test}
				exp, ok := want[k]
				if !assert.True(t, ok, "missing case %+v", k) {
					continue
				}
				assert.Equal(t, exp, statusAfterSuccess(current, pinned, test), fmt.Sprintf("%+v", k))
			}
		}
	}
}

// AUD-25 (a), ruling S4: a server whose name now resolves to an address Alice refuses to connect
// to shows that as its connection problem, like ssh.unreachable: unreachable, except a target
// waiting for its first confirmation (its recorded candidate stays confirmable) and the statuses
// only a person leaves.
func TestStatusForAddressNotAllowed(t *testing.T) {
	const reason = "ssh.address_not_allowed"
	for _, current := range []string{StatusPendingHostKey, StatusChecking, StatusOK, StatusUnreachable, StatusAuthFailed, StatusHostKeyChanged, StatusDisabled} {
		for _, pinned := range []bool{false, true} {
			assert.Equal(t, statusFor("ssh.unreachable", current, pinned), statusFor(reason, current, pinned), "%s pinned=%v", current, pinned)
		}
	}
	assert.Equal(t, StatusUnreachable, statusFor(reason, StatusOK, true))
	assert.Equal(t, StatusPendingHostKey, statusFor(reason, StatusPendingHostKey, false))
	assert.Equal(t, StatusHostKeyChanged, statusFor(reason, StatusHostKeyChanged, true))
}

// A report that does not name the software keeps the stored one; a report that finds no web server
// replaces the version and configuration path with "".
func TestMergeWebServerFactsKeepsTheSoftware(t *testing.T) {
	old := &providers.WebServerFacts{Software: "nginx", Found: true, Version: "1.24.0", ConfPath: "/etc/nginx/nginx.conf"}
	got := mergeWebServerFacts(old, providers.WebServerFacts{Found: true, ConfigValid: true})
	assert.Equal(t, &providers.WebServerFacts{Software: "nginx", Found: true, ConfigValid: true, Version: "1.24.0",
		ConfPath: "/etc/nginx/nginx.conf"}, got)
	gone := mergeWebServerFacts(old, providers.WebServerFacts{Software: "nginx", Found: false})
	assert.Equal(t, &providers.WebServerFacts{Software: "nginx"}, gone, "not found: version and path are emptied")
	assert.Equal(t, "ngin\ufffd", mergeWebServerFacts(nil, providers.WebServerFacts{Software: "ngin\x00"}).Software, "jsonb refuses NUL")
}
