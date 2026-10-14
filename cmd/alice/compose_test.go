package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakefleet"
)

type composeService struct {
	Image           string            `yaml:"image"`
	Environment     map[string]string `yaml:"environment"`
	Ports           []any             `yaml:"ports"`
	Networks        composeNetworks   `yaml:"networks"`
	Init            bool              `yaml:"init"`
	StopGracePeriod string            `yaml:"stop_grace_period"`
	Healthcheck     struct {
		Test []string `yaml:"test"`
	} `yaml:"healthcheck"`
	Build struct {
		Context    string `yaml:"context"`
		Dockerfile string `yaml:"dockerfile"`
	} `yaml:"build"`
	User        string            `yaml:"user"`
	ReadOnly    bool              `yaml:"read_only"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Sysctls     map[string]string `yaml:"sysctls"`
	MemLimit    string            `yaml:"mem_limit"`
	PidsLimit   int               `yaml:"pids_limit"`
	Volumes     []string          `yaml:"volumes"`
	Command     []string          `yaml:"command"`
	DependsOn   map[string]struct {
		Condition string `yaml:"condition"`
	} `yaml:"depends_on"`
	EnvFile any `yaml:"env_file"`
}

// composeNetworks reads a service's networks as a list of names or as a map of names to their
// options (aliases, a fixed address).
type composeNetworks map[string]composeNetwork

type composeNetwork struct {
	Aliases     []string `yaml:"aliases"`
	IPv4Address string   `yaml:"ipv4_address"`
}

func (n *composeNetworks) UnmarshalYAML(node *yaml.Node) error {
	*n = composeNetworks{}
	switch node.Kind {
	case yaml.SequenceNode:
		var names []string
		if err := node.Decode(&names); err != nil {
			return err
		}
		for _, name := range names {
			(*n)[name] = composeNetwork{}
		}
		return nil
	case yaml.MappingNode:
		var m map[string]composeNetwork
		if err := node.Decode(&m); err != nil {
			return err
		}
		*n = m
		return nil
	}
	return errors.New("networks must be a list or a map")
}

func (n composeNetworks) names() []string {
	out := make([]string, 0, len(n))
	for name := range n {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Networks map[string]struct {
		Internal bool `yaml:"internal"`
		IPAM     struct {
			Config []struct {
				Subnet  string `yaml:"subnet"`
				Gateway string `yaml:"gateway"`
			} `yaml:"config"`
		} `yaml:"ipam"`
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
	// The overlay adds the SSH target and the fake Azure service, nothing else; the release file has neither.
	assert.ElementsMatch(t, []string{"alice", "sshtarget", "fakeazure", "fakeacme", "fakesmtp", "fakeidp", "fakefleet"}, names, "the overlay adds only the SSH target (which also runs Nginx) and the fake Azure, ACME, SMTP, identity provider and TLS fleet services")
	for _, fake := range []string{"fakeazure", "fakeacme", "fakefleet"} {
		_, fakeInBase := base.Services[fake]
		assert.False(t, fakeInBase, "the release compose file has no %s service", fake)
	}
	// The e2e build answers the unauthenticated /test/* endpoints: it is published on loopback only (AUD-07).
	assert.Equal(t, []any{"127.0.0.1:${ALICE_E2E_PORT:-9443}:8443"}, overlay.Services["alice"].Ports,
		"the e2e Alice is published on 127.0.0.1 only")
	target, ok := overlay.Services["sshtarget"]
	require.True(t, ok)
	assert.Empty(t, target.Ports, "the SSH target publishes no port on the host")
	assert.Equal(t, []string{"backend"}, target.Networks.names())
	// Only the test website's name points at the target (the HTTP-01 journey): never a real or another service's name.
	assert.Equal(t, []string{"www.example.test"}, target.Networks["backend"].Aliases)
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

// AUD-24: the variables the configuration reads reach the container, and make up uses the
// documented override file while the e2e project never does.
func TestComposePassesConfigurationAndUsesTheOverride(t *testing.T) {
	base := readCompose(t, "../../deploy/docker-compose.yml")
	env := base.Services["alice"].Environment
	assert.Equal(t, "${ALICE_TRUSTED_PROXIES:-}", env["ALICE_TRUSTED_PROXIES"])
	assert.Equal(t, "${ALICE_LOG_LEVEL:-}", env["ALICE_LOG_LEVEL"])
	mk, err := os.ReadFile("../../Makefile")
	require.NoError(t, err)
	var compose, composeE2E string
	for _, line := range strings.Split(string(mk), "\n") {
		switch {
		case strings.HasPrefix(line, "COMPOSE :="):
			compose = line
		case strings.HasPrefix(line, "COMPOSE_E2E :="):
			composeE2E = line
		}
	}
	assert.Contains(t, compose, "$(wildcard deploy/docker-compose.override.yml)")
	assert.Contains(t, compose, "-f deploy/docker-compose.override.yml")
	assert.NotContains(t, composeE2E, "override", "the e2e project never reads the developer's override")
	assert.Contains(t, composeE2E, "-p $(E2E_PROJECT)")
}

// Every variable internal/platform/config reads reaches the alice container through the Compose
// file, except the ones whose image or built-in default is the right value there.
func TestComposePassesEveryConfigurationVariable(t *testing.T) {
	notInCompose := map[string]string{
		"ALICE_HEALTH_ADDR":                    "the default 127.0.0.1:8081 is what alice healthcheck in the image asks",
		"ALICE_KEYS_DIR":                       "the default /opt/alice/keys is the alice-keys volume",
		"ALICE_LISTEN_ADDR":                    "the default :8443 is the published container port",
		"ALICE_MIGRATE":                        "the default on-start is the development behaviour (the production compose sets external)",
		"ALICE_DATABASE_PASSWORD_FILE":         "the development URLs carry their passwords from deploy/.env",
		"ALICE_MIGRATE_DATABASE_PASSWORD_FILE": "the development URLs carry their passwords from deploy/.env",
	}
	dir := "../../internal/platform/config"
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	re := regexp.MustCompile(`"(ALICE_[A-Z0-9_]+)"`)
	read := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(dir + "/" + e.Name())
		require.NoError(t, err)
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			read[m[1]] = true
		}
	}
	require.Contains(t, read, "ALICE_DATABASE_URL", "the configuration reader moved; this test reads nothing")
	env := readCompose(t, "../../deploy/docker-compose.yml").Services["alice"].Environment
	var missing []string
	for name := range read {
		if _, ok := env[name]; !ok && notInCompose[name] == "" {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	assert.Empty(t, missing, "read by internal/platform/config but not passed by deploy/docker-compose.yml")
	for name := range notInCompose {
		assert.True(t, read[name], "%s is no longer read; remove it from the exceptions", name)
		_, inCompose := env[name]
		assert.False(t, inCompose, "%s is passed now; remove it from the exceptions", name)
	}
}

// The fake Azure service exists only in the test overlay, publishes nothing, sits only on the internal
// backend network under the two Azure host names Alice dials, is hardened like the other services (no
// capability, read-only root, non-root, limits) and shares its CA with alice read-only (R40 row 35).
func TestE2EFakeAzureIsTestOnlyHardenedAndSharesItsCA(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakeazure"]
	require.True(t, ok)
	marker := makeVarOf(t, "E2E_AZURE_MARKER")
	require.Equal(t, "/run/alice-e2e-azure", marker)

	assert.Empty(t, fake.Ports, "the fake Azure service publishes nothing")
	assert.Equal(t, []string{"backend"}, fake.Networks.names(), "only the internal network")
	assert.Equal(t, []string{"login.microsoftonline.com", "alice-e2e.vault.azure.net"}, fake.Networks["backend"].Aliases)
	assert.True(t, readCompose(t, "../../deploy/docker-compose.yml").Networks["backend"].Internal)
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd, "port 443 is bound through the unprivileged port start sysctl, not a capability")
	assert.Equal(t, map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}, fake.Sysctls)
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User, "non-root")
	assert.NotEmpty(t, fake.MemLimit)
	assert.Positive(t, fake.PidsLimit)
	assert.Equal(t, "alice-e2e-fakeazure", fake.Image)
	assert.Equal(t, "..", fake.Build.Context)
	assert.Equal(t, "test/images/fakeazure/Dockerfile", fake.Build.Dockerfile)
	_, err := os.Stat("../../" + fake.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"CMD", "/alice-fakeazure", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, []string{"serve", "--listen", ":443", "--admin", "127.0.0.1:9090", "--ca-out", marker + "/ca.pem"}, fake.Command,
		"the admin API stays on loopback; the CA goes to the shared volume")

	assert.Equal(t, []string{"fakeazure-ca:" + marker}, fake.Volumes)
	alice := overlay.Services["alice"]
	assert.Contains(t, alice.Volumes, "fakeazure-ca:"+marker+":ro", "alice reads the CA, never writes it")
	assert.Equal(t, "service_healthy", alice.DependsOn["fakeazure"].Condition, "alice starts after the fake wrote its CA")
	raw, err := os.ReadFile("../../deploy/docker-compose.e2e.yml")
	require.NoError(t, err)
	assert.Contains(t, string(raw), "\nvolumes:\n  fakeazure-ca: {}", "the CA volume is declared")

	// The e2e build reads exactly the file the fake writes.
	src, err := os.ReadFile("testapi_e2e.go")
	require.NoError(t, err)
	assert.Contains(t, string(src), `"`+marker+`/ca.pem"`)
}

// The fake ACME CA exists only in the test overlay, publishes nothing, sits only on the internal backend
// network under acme.test.alice, is hardened like the other fakes and shares its TLS CA with alice read-only.
func TestE2EFakeACMEIsTestOnlyHardenedAndSharesItsCA(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakeacme"]
	require.True(t, ok)
	marker := makeVarOf(t, "E2E_ACME_MARKER")
	require.Equal(t, "/run/alice-e2e-acme", marker)

	assert.Empty(t, fake.Ports, "the fake ACME CA publishes nothing")
	assert.Equal(t, []string{"backend"}, fake.Networks.names(), "only the internal network")
	assert.Equal(t, []string{"acme.test.alice"}, fake.Networks["backend"].Aliases)
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd, "port 443 is bound through the unprivileged port start sysctl, not a capability")
	assert.Equal(t, map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}, fake.Sysctls)
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User, "non-root")
	assert.NotEmpty(t, fake.MemLimit)
	assert.Positive(t, fake.PidsLimit)
	assert.Equal(t, "alice-e2e-fakeacme", fake.Image)
	assert.Equal(t, "..", fake.Build.Context)
	assert.Equal(t, "test/images/fakeacme/Dockerfile", fake.Build.Dockerfile)
	_, err := os.Stat("../../" + fake.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"CMD", "/alice-fakeacme", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, []string{"serve", "--listen", ":443", "--admin", "127.0.0.1:9091", "--ca-out", marker + "/ca.pem"}, fake.Command,
		"the admin API stays on loopback; the TLS CA goes to the shared volume")

	assert.Equal(t, []string{"fakeacme-ca:" + marker}, fake.Volumes)
	alice := overlay.Services["alice"]
	assert.Contains(t, alice.Volumes, "fakeacme-ca:"+marker+":ro", "alice reads the CA, never writes it")
	assert.Equal(t, "service_healthy", alice.DependsOn["fakeacme"].Condition, "alice starts after the fake wrote its CA")
	raw, err := os.ReadFile("../../deploy/docker-compose.e2e.yml")
	require.NoError(t, err)
	assert.Contains(t, string(raw), "\n  fakeacme-ca: {}", "the CA volume is declared")

	// The e2e build reads exactly the file the fake writes.
	src, err := os.ReadFile("testapi_e2e.go")
	require.NoError(t, err)
	assert.Contains(t, string(src), `"`+marker+`/ca.pem"`)
}

// The release compose file and image never mention the fake ACME CA, its CA directory or its host name.
func TestReleaseComposeAndImageNeverMentionTheFakeACME(t *testing.T) {
	for _, path := range []string{"../../deploy/docker-compose.yml", "../../deploy/Dockerfile"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, s := range []string{"alice-e2e-acme", "fakeacme", "alice-fakeacme", "acme.test.alice"} {
			assert.NotContains(t, string(raw), s, "%s", path)
		}
	}
}

// The fake ACME image builds on the same two pinned base images as the release image and the other fakes.
func TestFakeACMEDockerfileReusesTheReleaseBaseImages(t *testing.T) {
	release := dockerfileFroms(t, "../../deploy/Dockerfile")
	fake := dockerfileFroms(t, "../../test/images/fakeacme/Dockerfile")
	require.Len(t, fake, 2, "a builder and a runtime image")
	for ref := range fake {
		assert.Contains(t, ref, "@sha256:")
		assert.True(t, release[ref], "%s is not a base image of deploy/Dockerfile", ref)
	}
}

// The release compose file and image never mention the fake Azure service, its CA or its host names:
// a release Alice has no way to trust it.
func TestReleaseComposeAndImageNeverMentionTheFakeAzure(t *testing.T) {
	for _, path := range []string{"../../deploy/docker-compose.yml", "../../deploy/Dockerfile"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, s := range []string{"alice-e2e-azure", "fakeazure", "alice-fakeazure", "login.microsoftonline.com", "vault.azure.net", "fakekv"} {
			assert.NotContains(t, string(raw), s, "%s", path)
		}
	}
	mk := makeVarOf(t, "E2E_AZURE_MARKER")
	raw, err := os.ReadFile("../../deploy/docker-compose.yml")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), mk)
}

// The Key Vault provider refuses to open a session when AZURE_SDK_GO_LOGGING, MSAL_FORCE_REGION or
// AZURE_REGIONAL_AUTHORITY_NAME is set (the SDK would log Azure's answers or call the metadata address
// outside the guard): no compose file, env file template or Dockerfile of the stack sets them, so the
// e2e journeys never meet that refusal.
func TestComposeAndImagesNeverSetTheSDKLoggingOrRegionVariables(t *testing.T) {
	forbidden := []string{"AZURE_SDK_GO_LOGGING", "MSAL_FORCE_REGION", "AZURE_REGIONAL_AUTHORITY_NAME"}
	for _, path := range []string{"../../deploy/docker-compose.yml", "../../deploy/docker-compose.e2e.yml"} {
		c := readCompose(t, path)
		for name, svc := range c.Services {
			for _, v := range forbidden {
				_, set := svc.Environment[v]
				assert.False(t, set, "%s: service %s sets %s", path, name, v)
			}
			assert.Nil(t, svc.EnvFile, "%s: service %s reads an env file, which this test cannot see into", path, name)
		}
	}
	// Dockerfiles: an ENV or ARG line (comments may name the variables). The setup script that writes
	// deploy/.env must not either.
	for _, path := range []string{"../../deploy/Dockerfile", "../../test/images/fakeazure/Dockerfile", "../../test/images/fakeacme/Dockerfile", "../../test/images/fakefleet/Dockerfile", "../../test/images/e2e-target/Dockerfile"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, l := range dockerfileInstructions(string(raw)) {
			if strings.HasPrefix(l, "ENV ") || strings.HasPrefix(l, "ARG ") {
				for _, v := range forbidden {
					assert.NotContains(t, l, v, "%s", path)
				}
			}
		}
	}
	raw, err := os.ReadFile("../../deploy/dev/init-env.sh")
	require.NoError(t, err)
	for _, v := range forbidden {
		assert.NotContains(t, string(raw), v)
	}
}

// makeVarOf returns the value of a Makefile variable defined with :=.
func makeVarOf(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../Makefile")
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^` + name + `\s*:=\s*(\S+)`).FindStringSubmatch(string(raw))
	require.NotNil(t, m, "Makefile defines no %s", name)
	return m[1]
}

// dockerfileInstructions returns a Dockerfile's instructions with their continuation lines joined
// (a trailing backslash) and comment lines dropped.
func dockerfileInstructions(src string) []string {
	var out []string
	cur := ""
	for _, line := range strings.Split(src, "\n") {
		l := strings.TrimSpace(line)
		if cur == "" && (l == "" || strings.HasPrefix(l, "#")) {
			continue
		}
		if cur != "" && strings.HasPrefix(l, "#") { // a comment inside a continued instruction
			continue
		}
		if strings.HasSuffix(l, "\\") {
			cur += strings.TrimSuffix(l, "\\") + " "
			continue
		}
		out = append(out, strings.TrimSpace(cur+l))
		cur = ""
	}
	if cur != "" {
		out = append(out, strings.TrimSpace(cur))
	}
	return out
}

func TestDockerfileInstructionsJoinContinuationLines(t *testing.T) {
	got := dockerfileInstructions("# c\nFROM a AS b\nRUN x \\\n  && y\nENV A=1 \\\n  AZURE_SDK_GO_LOGGING=all\n\nCMD [\"z\"]\n")
	assert.Equal(t, []string{"FROM a AS b", "RUN x  && y", "ENV A=1  AZURE_SDK_GO_LOGGING=all", `CMD ["z"]`}, got)
}

// The fake Azure image builds on the two base images deploy/Dockerfile already pins, by the same
// digests: no new base image enters the supply chain.
func TestFakeAzureDockerfileReusesTheReleaseBaseImages(t *testing.T) {
	release := dockerfileFroms(t, "../../deploy/Dockerfile")
	fake := dockerfileFroms(t, "../../test/images/fakeazure/Dockerfile")
	require.Len(t, fake, 2, "a builder and a runtime image")
	for ref := range fake {
		assert.Contains(t, ref, "@sha256:")
		assert.True(t, release[ref], "%s is not a base image of deploy/Dockerfile", ref)
	}
}

// dockerfileFroms is the set of image references the FROM lines of a Dockerfile name.
func dockerfileFroms(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	out := map[string]bool{}
	for _, l := range dockerfileInstructions(string(raw)) {
		if ref, ok := strings.CutPrefix(l, "FROM "); ok {
			out[strings.Fields(ref)[0]] = true
		}
	}
	return out
}

// The mail and identity provider fakes' images build on the two base images deploy/Dockerfile pins, by the
// same digests, and hold no key material (their certificates are generated when the container starts).
func TestMailAndIdPFakeDockerfilesReuseTheReleaseBaseImages(t *testing.T) {
	release := dockerfileFroms(t, "../../deploy/Dockerfile")
	for _, f := range []string{"../../test/images/fakesmtp/Dockerfile", "../../test/images/fakeidp/Dockerfile"} {
		froms := dockerfileFroms(t, f)
		require.Len(t, froms, 2, "%s: a builder and a runtime image", f)
		for from := range froms {
			assert.Contains(t, from, "@sha256:", f)
			assert.True(t, release[from], "%s uses only base images the release build pins: %s", f, from)
		}
	}
}

// The e2e target's Dockerfile unlocks the deploy account right after creating it: no password, but "*"
// instead of useradd's "!", so an sshd without PAM accepts a key login too (R37 item 2's form). Its
// fixture keys are generated at build time and their private halves deleted in the same layer: no key
// material is committed. This checks the Dockerfile text only; the login itself is proven by the Phase 6
// journey (Task 18), which deploys a generated key to deploy and logs in with it.
func TestE2ETargetDockerfileUnlocksTheDeployAccount(t *testing.T) {
	raw, err := os.ReadFile("../../test/images/e2e-target/Dockerfile")
	require.NoError(t, err)
	src := string(raw)
	add := strings.Index(src, "useradd --uid 1001 --create-home --shell /bin/bash deploy;")
	unlock := strings.Index(src, "usermod -p '*' deploy;")
	require.Positive(t, add, "the deploy account is created")
	assert.Greater(t, unlock, add, "the deploy account is unlocked right after it is created")
	assert.NotContains(t, src, "PRIVATE "+"KEY", "no key material in the Dockerfile")
	assert.Contains(t, src, `rm -rf "$tmp"`, "the fixture keys' private halves are deleted in the layer that made them")
}

// The fake SMTP server exists only in the test overlay, publishes nothing, sits only on the internal backend
// network and is hardened like the other services; port 2525 needs no sysctl and no capability.
func TestE2EFakeSMTPIsTestOnlyAndHardened(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakesmtp"]
	require.True(t, ok)
	assert.Empty(t, fake.Ports, "the fake SMTP server publishes nothing")
	assert.Equal(t, []string{"backend"}, fake.Networks.names())
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd)
	assert.Empty(t, fake.Sysctls, "port 2525 needs no sysctl")
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User)
	assert.NotEmpty(t, fake.MemLimit)
	assert.Positive(t, fake.PidsLimit)
	assert.Equal(t, "alice-e2e-fakesmtp", fake.Image)
	assert.Equal(t, "test/images/fakesmtp/Dockerfile", fake.Build.Dockerfile)
	_, err := os.Stat("../../" + fake.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"serve", "--listen", ":2525", "--api", "127.0.0.1:8025", "--hostname", "fakesmtp"}, fake.Command)
	assert.Equal(t, []string{"CMD", "/alice-fakesmtp", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, "service_healthy", overlay.Services["alice"].DependsOn["fakesmtp"].Condition)
}

// The fake identity provider exists only in the test overlay; it is the one fake published on the host, on
// loopback only, because the browser reaches it there; its admin API stays on loopback inside the container.
func TestE2EFakeIdPIsTestOnlyHardenedAndLoopbackPublished(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakeidp"]
	require.True(t, ok)
	assert.Equal(t, []any{"127.0.0.1:9444:9444"}, fake.Ports, "loopback only: the browser reaches it on this host")
	assert.Equal(t, []string{"frontend"}, fake.Networks.names())
	assert.Equal(t, []string{"idp.alice-e2e.test"}, fake.Networks["frontend"].Aliases)
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd)
	assert.Empty(t, fake.Sysctls)
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User)
	assert.NotEmpty(t, fake.MemLimit)
	assert.Positive(t, fake.PidsLimit)
	assert.Equal(t, "alice-e2e-fakeidp", fake.Image)
	assert.Equal(t, "test/images/fakeidp/Dockerfile", fake.Build.Dockerfile)
	_, err := os.Stat("../../" + fake.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"serve", "--listen", ":9444", "--host", "idp.alice-e2e.test", "--admin", "127.0.0.1:9091", "--redirect-prefix", "https://localhost:"}, fake.Command,
		"the admin API stays on loopback")
	assert.Equal(t, []string{"CMD", "/alice-fakeidp", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, "service_healthy", overlay.Services["alice"].DependsOn["fakeidp"].Condition)
}

// A release Alice has no way to reach the mail or identity provider fakes.
func TestReleaseComposeNeverMentionsTheMailAndIdPFakes(t *testing.T) {
	for _, f := range []string{"../../deploy/docker-compose.yml", "../../deploy/Dockerfile"} {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, word := range []string{"fakesmtp", "fakeidp", "idp.alice-e2e.test"} {
			assert.NotContains(t, string(raw), word, f)
		}
	}
}

// M-2: the development stack keeps backups in their own named volume, which the image's 10001-owned
// /opt/alice/backups directory initialises, and tells Alice where it is.
func TestComposeMountsTheBackupVolume(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/docker-compose.yml")
	require.NoError(t, err)
	var c struct {
		Volumes map[string]any `yaml:"volumes"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &c))
	assert.Contains(t, c.Volumes, "alice-backups")
	alice := readCompose(t, "../../deploy/docker-compose.yml").Services["alice"]
	assert.Contains(t, alice.Volumes, "alice-backups:/opt/alice/backups")
	assert.Equal(t, "/opt/alice/backups", alice.Environment["ALICE_BACKUP_DIR"])
}

// The fake TLS fleet exists only in the test overlay. It sits only on its own internal network "fleet" at a fixed
// address, under a name per server kind, publishes nothing, is hardened like the other fakes and needs no volume:
// discovery trusts nothing, so alice reads none of its CA. Alice joins the fleet network at a fixed address too.
func TestE2EFakeFleetIsTestOnlyHardenedOnItsOwnNetwork(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakefleet"]
	require.True(t, ok)
	assert.Empty(t, fake.Ports, "the fleet publishes nothing")
	assert.Equal(t, []string{"fleet"}, fake.Networks.names(), "only its own network")
	assert.Equal(t, fleetIP, fake.Networks["fleet"].IPv4Address)
	wantAliases := []string{fleetDomain}
	for _, k := range fakefleet.AllKinds {
		wantAliases = append(wantAliases, string(k)+"."+fleetDomain)
	}
	assert.Equal(t, wantAliases, fake.Networks["fleet"].Aliases, "a name per server kind, the names its certificates carry")
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd, "port 443 is bound through the unprivileged port start sysctl, not a capability")
	assert.Equal(t, map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}, fake.Sysctls)
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User, "non-root")
	assert.NotEmpty(t, fake.MemLimit)
	assert.Positive(t, fake.PidsLimit)
	assert.Empty(t, fake.Volumes, "no shared CA: discovery trusts nothing")
	assert.Equal(t, "alice-e2e-fakefleet", fake.Image)
	assert.Equal(t, "..", fake.Build.Context)
	assert.Equal(t, "test/images/fakefleet/Dockerfile", fake.Build.Dockerfile)
	_, err := os.Stat("../../" + fake.Build.Dockerfile)
	assert.NoError(t, err)
	assert.Equal(t, []string{"CMD", "/alice-fakefleet", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, []string{"serve", "--bind", "0.0.0.0", "--domain", fleetDomain, "--ctl", "127.0.0.1:9092"}, fake.Command,
		"the control API stays on loopback; every kind on its default port")

	fleetNet, ok := overlay.Networks["fleet"]
	require.True(t, ok, "the overlay declares the fleet network")
	assert.True(t, fleetNet.Internal, "no route out, and no default route for alice")
	require.Len(t, fleetNet.IPAM.Config, 1)
	assert.Equal(t, fleetSubnet, fleetNet.IPAM.Config[0].Subnet)
	assert.Equal(t, "10.89.0.1", fleetNet.IPAM.Config[0].Gateway)

	alice := overlay.Services["alice"]
	assert.Equal(t, []string{"fleet"}, alice.Networks.names(), "the overlay adds only the fleet network to alice's base networks")
	assert.Equal(t, aliceFleetIP, alice.Networks["fleet"].IPv4Address)
	_, waits := alice.DependsOn["fakefleet"]
	assert.False(t, waits, "alice does not need the fleet to start")
	base := readCompose(t, "../../deploy/docker-compose.yml")
	_, inBase := base.Networks["fleet"]
	assert.False(t, inBase, "the release compose file has no fleet network")
}

const (
	fleetDomain  = "fleet.alice-e2e.test"
	fleetSubnet  = "10.89.0.0/24"
	fleetIP      = "10.89.0.10"
	aliceFleetIP = "10.89.0.2"
)

// The fleet's subnet is outside every range the scan policy refuses by itself: with 10.89.0.0/24 allowed, every
// address of it may be scanned except alice's own address on it (the policy reads alice's interfaces) — and the
// policy refuses alice's own address there, so the journeys can show that refusal too.
func TestFleetSubnetIsScannableExceptAlicesOwnAddress(t *testing.T) {
	subnet := netip.MustParsePrefix(fleetSubnet)
	own := netip.MustParseAddr(aliceFleetIP)
	policy, err := netaddr.NewScanPolicy(context.Background(), netaddr.ScanPolicyInputs{
		AllowedNetworks: []netip.Prefix{subnet},
		DatabaseURL:     "postgres://alice@postgres:5432/alice",
		LookupHost: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("172.30.0.5")}, nil
		},
		InterfaceAddrs:  func() ([]netip.Addr, error) { return []netip.Addr{own, netip.MustParseAddr("172.30.0.4")}, nil },
		DefaultGateways: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("172.31.0.1")}, nil },
	})
	require.NoError(t, err)
	assert.NoError(t, policy.CheckScan(netip.MustParseAddr(fleetIP)), "the fleet itself")
	assert.ErrorIs(t, policy.CheckScan(own), netaddr.ErrScanRefused, "alice's own address on the fleet network")
	for a := subnet.Addr().Next(); subnet.Contains(a); a = a.Next() {
		if a != own {
			assert.NoError(t, policy.CheckScan(a), "%s", a)
		}
	}
	assert.ErrorIs(t, policy.CheckScan(netip.MustParseAddr("10.89.1.10")), netaddr.ErrScanRefused, "outside the allowed network")
}

// The release compose file and image never mention the fake fleet, its network or its names.
func TestReleaseComposeAndImageNeverMentionTheFakeFleet(t *testing.T) {
	for _, path := range []string{"../../deploy/docker-compose.yml", "../../deploy/Dockerfile"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, s := range []string{"fakefleet", "alice-fakefleet", fleetDomain, "10.89.0."} {
			assert.NotContains(t, string(raw), s, "%s", path)
		}
	}
}

// The fake fleet image builds on the same two pinned base images as the release image and the other fakes.
func TestFakeFleetDockerfileReusesTheReleaseBaseImages(t *testing.T) {
	release := dockerfileFroms(t, "../../deploy/Dockerfile")
	fake := dockerfileFroms(t, "../../test/images/fakefleet/Dockerfile")
	require.Len(t, fake, 2, "a builder and a runtime image")
	for ref := range fake {
		assert.Contains(t, ref, "@sha256:")
		assert.True(t, release[ref], "%s is not a base image of deploy/Dockerfile", ref)
	}
	raw, err := os.ReadFile("../../test/images/fakefleet/Dockerfile")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "PRIVATE "+"KEY", "no key material in the image")
	assert.Contains(t, string(raw), "USER 65532:65532")
}
