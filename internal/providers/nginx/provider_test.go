package nginx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/providertest"
)

func TestNginxProviderDescribesItself(t *testing.T) {
	e := newEnv(t)
	providertest.CheckProvider(t, e.prov)
	assert.Equal(t, providers.KindNginx, e.prov.Kind())
	assert.Equal(t, "provider.nginx.name", e.prov.DisplayNameKey())
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDiscoverCerts, providers.CapDiscoverSSHKeys,
		providers.CapTestConnection, providers.CapVerifyDeployment}, e.prov.Capabilities().Sorted())
	assert.Equal(t, TLSProber{}, New(Options{}).prober, "Alice's own TLS probe when none is given")
	var _ providers.ConnectionCache = e.prov
	assert.Equal(t, e.prov.ssh.ConfigSchema(), e.prov.ConfigSchema())
	assert.Empty(t, e.prov.CredentialSchema().Fields)
	e.prov.ForgetTarget(testTarget)
	assert.Empty(t, e.prov.ValidateConfig(e.ref.Config))
	assert.NotEmpty(t, e.prov.ValidateConfig(providers.TargetConfig{"port": 22}))
}

func TestNginxConformance(t *testing.T) {
	e := newEnv(t)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: e.prov.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
		},
		Secrets: e.cred.secrets(t),
	})
}

func TestTheDeploySessionMethodsStayUnsupported(t *testing.T) {
	s := newEnv(t).open(t)
	_, err := s.DeployCertificate(context.Background(), providers.DeployRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.RollbackDeployment(context.Background(), providers.RollbackRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.DeploymentStatus(context.Background(), testTarget)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{})
	assert.NotErrorIs(t, err, providers.ErrUnsupported)
}

// F-14: a server prepared with the Linux profile only.
func TestTestConnectionChecksTheNginxProfile(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.Nginx)
	assert.True(t, rep.Nginx.Found)
	assert.True(t, rep.Nginx.ConfigValid)
	assert.Empty(t, rep.Nginx.ConfigError)
	assert.NotEmpty(t, rep.HostKey.Fingerprint, "the Linux part of the report is kept")
	assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
	require.NoError(t, s.Close())

	e.emu.SetNginxProfile(false)
	s = e.open(t)
	_, err = s.TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "nginx.profile_missing", pe.Code)
	assert.Equal(t, map[string]string{"subcommand": "nginx-test", "profile": "nginx"}, pe.Params)
	assert.False(t, pe.Retryable)
}

func TestTestConnectionWarnsWhenNginxIsMissingOrInvalid(t *testing.T) {
	for _, class := range []string{helperproto.ConfigErrSyntax, helperproto.ConfigErrKeyMismatch, helperproto.ConfigErrFileMissing,
		helperproto.ConfigErrCertLoad, helperproto.ConfigErrKeyLoad} {
		e := newEnv(t)
		e.emu.SetConfigInvalid(class)
		rep, err := e.open(t).TestConnection(context.Background())
		require.NoError(t, err)
		require.NotNil(t, rep.Nginx)
		assert.True(t, rep.Nginx.Found)
		assert.False(t, rep.Nginx.ConfigValid)
		assert.Equal(t, class, rep.Nginx.ConfigError, "the class is carried, never nginx's text")
		assert.Contains(t, warningCodes(rep.Warnings), "nginx_config_invalid")
	}

	e := newEnv(t, withoutNginx())
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.Nginx)
	assert.False(t, rep.Nginx.Found)
	assert.Contains(t, warningCodes(rep.Warnings), "nginx_not_found")
}

func TestTestConnectionKilledNginxIsARetryableError(t *testing.T) {
	e := newEnv(t)
	e.emu.SetNginxKilled(true)
	_, err := e.open(t).TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, "IO_ERROR", pe.Params["helper_code"])
	assert.True(t, pe.Retryable, "IO_ERROR is what a killed or timed-out nginx gives")
}

func TestTestConnectionKeepsTheLinuxFailures(t *testing.T) {
	e := newEnv(t)
	e.emu.SetHelperMissing(true)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.helper_missing", providerErr(t, err).Code, "the linuxssh part fails first, unchanged")
}

func TestOpenRefusesAnOutdatedHelper(t *testing.T) {
	e := newEnv(t)
	e.emu.SetProtocol(3)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.helper_outdated", providerErr(t, err).Code, "F-14: the deploy never starts with an old helper")
}

func TestOpenRefusesAnInvalidConfig(t *testing.T) {
	e := newEnv(t)
	e.ref.Config = providers.TargetConfig{"port": 22}
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "target.invalid_config", providerErr(t, err).Code)
}

func TestAClosedSessionRunsNothing(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "closing twice is fine")
	before := len(e.srv.Commands())
	_, err := s.TestConnection(context.Background())
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Len(t, e.srv.Commands(), before, "a closed session's connection may serve another session")
}

func helperErr(sub, code string, retryable bool) error {
	return providers.NewError("ssh.helper_refused", retryable, errors.New("cause"), map[string]string{"subcommand": sub, "helper_code": code})
}

func TestMapHelper(t *testing.T) {
	deploy := helperproto.SubNginxDeploy
	cause := errors.New("plain")
	tests := []struct {
		name      string
		err       error
		sub       string
		code      string
		params    map[string]string
		retryable bool
	}{
		{"sudo refused", providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": "nginx-dump", "exit_code": "1"}),
			"nginx-dump", "nginx.profile_missing", map[string]string{"subcommand": "nginx-dump", "profile": "nginx"}, false},
		{"helper not installed stays", providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": "nginx-dump", "exit_code": "127"}),
			"nginx-dump", "ssh.helper_missing", map[string]string{"subcommand": "nginx-dump", "exit_code": "127"}, false},
		{"not found", helperErr("nginx-dump", "NGINX_NOT_FOUND", false), "nginx-dump", "nginx.not_found", map[string]string{}, false},
		{"config invalid", helperErr(deploy, "CONFIG_INVALID", false), deploy, "nginx.config_invalid", map[string]string{}, false},
		{"config changed", helperErr(deploy, "CONFIG_CHANGED", false), deploy, "nginx.config_changed", map[string]string{}, false},
		{"hash mismatch", providers.NewError("ssh.file_changed", false, nil, map[string]string{"subcommand": deploy, "helper_code": "HASH_MISMATCH"}),
			deploy, "nginx.file_changed", map[string]string{}, false},
		{"no space", helperErr(deploy, "NO_SPACE", false), deploy, "nginx.no_space", map[string]string{}, false},
		{"busy", helperErr(deploy, "BUSY", true), deploy, "nginx.busy", map[string]string{}, true},
		{"write failed", helperErr(deploy, "IO_ERROR", true), deploy, "nginx.write_failed", map[string]string{}, false},
		{"io error of the dump stays", helperErr("nginx-dump", "IO_ERROR", true), "nginx-dump", "ssh.helper_refused",
			map[string]string{"subcommand": "nginx-dump", "helper_code": "IO_ERROR"}, true},
		{"path not allowed", helperErr(deploy, "PATH_NOT_ALLOWED", false), deploy, "nginx.location_unsupported", map[string]string{}, false},
		{"unsafe file", helperErr(deploy, "UNSAFE_FILE", false), deploy, "nginx.location_unsupported", map[string]string{}, false},
		{"not regular", helperErr(deploy, "NOT_REGULAR_FILE", false), deploy, "nginx.location_unsupported", map[string]string{}, false},
		{"not found file", helperErr(deploy, "NOT_FOUND", false), deploy, "nginx.location_unsupported", map[string]string{}, false},
		{"too large", helperErr(deploy, "TOO_LARGE", false), deploy, "nginx.location_unsupported", map[string]string{}, false},
		{"bad content", helperErr(deploy, "BAD_CONTENT", false), deploy, "certificate.invalid", map[string]string{}, false},
		{"anything else", helperErr(deploy, "SUPERSEDED", false), deploy, "ssh.helper_refused",
			map[string]string{"subcommand": deploy, "helper_code": "SUPERSEDED"}, false},
		{"output too large stays", providers.NewError("ssh.output_too_large", false, nil, map[string]string{"subcommand": "nginx-dump"}),
			"nginx-dump", "ssh.output_too_large", map[string]string{"subcommand": "nginx-dump"}, false},
		{"other provider error stays", providers.NewError("ssh.unreachable", true, nil, nil), "nginx-dump", "ssh.unreachable", map[string]string{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pe := providerErr(t, mapHelper(tc.err, tc.sub))
			assert.Equal(t, tc.code, pe.Code)
			assert.Equal(t, tc.params, pe.Params)
			assert.Equal(t, tc.retryable, pe.Retryable)
			if c := errors.Unwrap(tc.err); c != nil {
				assert.ErrorIs(t, pe, c, "the cause is kept")
			}
		})
	}
	assert.NoError(t, mapHelper(nil, deploy))
	assert.Equal(t, cause, mapHelper(cause, deploy), "an error that is not a provider error passes through")
	pe := providerErr(t, mapHelperIn(helperErr(deploy, "IO_ERROR", true), deploy, "/etc/nginx/ssl"))
	assert.Equal(t, "nginx.write_failed", pe.Code)
	assert.Equal(t, map[string]string{"directory": "/etc/nginx/ssl"}, pe.Params)
}

func TestNewDefaults(t *testing.T) {
	p := New(Options{})
	assert.Equal(t, 2*time.Second, p.retryWait)
	assert.Equal(t, 5, p.attempts)
	p = New(Options{RetryWait: time.Millisecond, Attempts: 3})
	assert.Equal(t, time.Millisecond, p.retryWait)
	assert.Equal(t, 3, p.attempts)
}

func TestSudoRefusalMapsForEveryNginxSubcommand(t *testing.T) {
	for _, sub := range []string{helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore,
		helperproto.SubNginxStatus} {
		err := providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": sub, "exit_code": "1"})
		assert.Equal(t, "nginx.profile_missing", providerErr(t, mapHelper(err, sub)).Code, sub)
	}
	err := providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": "sshd-dump", "exit_code": "1"})
	assert.Equal(t, "ssh.helper_missing", providerErr(t, mapHelper(err, "sshd-dump")).Code, "only the nginx subcommands")
}
