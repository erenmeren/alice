package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

type composeService struct {
	Image           string   `yaml:"image"`
	Ports           []any    `yaml:"ports"`
	Networks        []string `yaml:"networks"`
	Init            bool     `yaml:"init"`
	StopGracePeriod string   `yaml:"stop_grace_period"`
	Healthcheck     struct {
		Test []string `yaml:"test"`
	} `yaml:"healthcheck"`
	Build struct {
		Context    string `yaml:"context"`
		Dockerfile string `yaml:"dockerfile"`
	} `yaml:"build"`
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Networks map[string]struct {
		Internal bool `yaml:"internal"`
	} `yaml:"networks"`
}

func readCompose(t *testing.T, path string) composeFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var c composeFile
	require.NoError(t, yaml.Unmarshal(raw, &c))
	return c
}

// The e2e SSH target exists only in the test overlay, publishes nothing and sits only on the
// internal backend network; the release compose file has no test service. Alice gets the time
// it needs to finish running jobs at shutdown (§8.8).
func TestE2ETargetIsTestOnlyAndUnpublished(t *testing.T) {
	base := readCompose(t, "../../deploy/docker-compose.yml")
	_, inBase := base.Services["sshtarget"]
	assert.False(t, inBase, "the release compose file has no SSH test target")
	assert.True(t, base.Networks["backend"].Internal)
	assert.Equal(t, "90s", base.Services["alice"].StopGracePeriod)

	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	names := make([]string, 0, len(overlay.Services))
	for name := range overlay.Services {
		names = append(names, name)
	}
	assert.ElementsMatch(t, []string{"alice", "sshtarget"}, names, "the overlay adds only the SSH target (which also runs Nginx)")
	// The e2e build answers the unauthenticated /test/* endpoints: it is published on loopback only (AUD-07).
	assert.Equal(t, []any{"127.0.0.1:${ALICE_E2E_PORT:-9443}:8443"}, overlay.Services["alice"].Ports,
		"the e2e Alice is published on 127.0.0.1 only")
	target, ok := overlay.Services["sshtarget"]
	require.True(t, ok)
	assert.Empty(t, target.Ports, "the SSH target publishes no port on the host")
	assert.Equal(t, []string{"backend"}, target.Networks)
	assert.True(t, target.Init, "an init process reaps sshd's children")
	assert.Equal(t, "alice-e2e-sshtarget", target.Image)
	assert.Equal(t, "..", target.Build.Context)
	assert.Equal(t, "test/images/e2e-target/Dockerfile", target.Build.Dockerfile)
	_, err := os.Stat("../../" + target.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"CMD-SHELL", "pgrep -x sshd >/dev/null && pgrep -x nginx >/dev/null"}, target.Healthcheck.Test,
		"the target is healthy only while sshd and nginx run")
}

// The test-only shims and fixtures of the SSH target are copied into its image only: the release
// Dockerfile never names them.
func TestReleaseImageHasNoTestTarget(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/Dockerfile")
	require.NoError(t, err)
	for _, s := range []string{"test/images", "e2e-target", "alice-e2e", "alice-test-ca", "nginx-wrapper", "/usr/bin/systemctl",
		"nginx-www.conf", "dpkg-divert"} {
		assert.NotContains(t, string(raw), s)
	}
}
