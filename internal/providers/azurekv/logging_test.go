package azurekv

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

const probeEnv = "ALICE_AZUREKV_LOGGING_PROBE"

// TestSDKLoggingProbe is run only in a subprocess by TestSDKLoggingVariableKeepsAzureTextOutOfTheOutput:
// the SDK reads AZURE_SDK_GO_LOGGING when it is initialised, so a variable set inside a running test
// proves nothing. The probe makes the vault answer 403 with the canary in the body and calls it.
func TestSDKLoggingProbe(t *testing.T) {
	mode := os.Getenv(probeEnv)
	if mode == "" {
		t.Skip("run by TestSDKLoggingVariableKeepsAzureTextOutOfTheOutput")
	}
	if mode == "control" {
		// The SDK is already initialised with logging on. Emptying the variable lets Open through,
		// which is exactly the state the refusal exists to prevent.
		t.Setenv("AZURE_SDK_GO_LOGGING", "")
	}
	s := fakekv.Start(t, fakekv.Options{})
	s.FailAll("/certificates", fakekv.Fault{Status: 403, Body: kvBody("Forbidden", "ForbiddenByRbac", canary)})
	clk := nearNow()
	sess, err := testProvider(s).Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{Clock: clk})
	if mode == "refuse" {
		require.Error(t, err)
		assert.Equal(t, codeAddressNotAllowed, asProviderError(t, err).Code)
		assert.Empty(t, s.Requests(), "nothing was sent: the SDK had no call to log")
		return
	}
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	_, err = sess.(*session).api.GetCertificate(context.Background(), "web-cert", "")
	assert.Equal(t, codeForbidden, asProviderError(t, err).Code)
}

func runProbe(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSDKLoggingProbe$", "-test.count=1", "-test.v") //nolint:gosec // G204: our own test binary
	cmd.Env = append(os.Environ(), "AZURE_SDK_GO_LOGGING=all", probeEnv+"="+mode)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Run(), "the probe failed:\n%s", out.String())
	return out.String()
}

// N1: with the logging variable set at process start, Open is refused, nothing is sent and no Azure
// text reaches stdout or stderr. The control run shows the probe would see the leak: the same call
// with Open let through makes the SDK print the canary.
func TestSDKLoggingVariableKeepsAzureTextOutOfTheOutput(t *testing.T) {
	refused := runProbe(t, "refuse")
	assert.Contains(t, refused, "--- PASS: TestSDKLoggingProbe")
	assert.NotContains(t, refused, canary)

	control := runProbe(t, "control")
	assert.Contains(t, control, canary, "the control must show the leak the refusal prevents, or this test proves nothing")
}
