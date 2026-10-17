package webserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
)

const authKeysLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1O1ywhjuNQkuBWbKQ2CbnMFgn8QF0v1kbbmVYh8y8c deploy@laptop"

// scriptOn answers every command of subcommand sub with r; every other command is the emulator's.
func scriptOn(e *env, sub string, r linuxsshtest.Response) {
	h := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " "+sub+" ") || strings.HasSuffix(cmd, " "+sub) {
			return r
		}
		return h(cmd, stdin)
	})
}

func TestNewBaseRefusesAnIncompleteSpec(t *testing.T) {
	lp := linuxssh.New(linuxssh.Options{})
	assert.NotPanics(t, func() { NewBase(lp, testSpec()) })
	dumpOnly := testSpec()
	dumpOnly.Test = nil
	assert.NotPanics(t, func() { NewBase(lp, dumpOnly) }, "Test is optional")
	tests := []struct {
		name string
		ssh  *linuxssh.Provider
		edit func(*Spec)
	}{
		{"nil ssh", nil, func(*Spec) {}},
		{"empty Kind", lp, func(s *Spec) { s.Kind = "" }},
		{"empty DisplayNameKey", lp, func(s *Spec) { s.DisplayNameKey = "" }},
		{"nil Dump", lp, func(s *Spec) { s.Dump = nil }},
		{"empty NotFoundCode", lp, func(s *Spec) { s.NotFoundCode = "" }},
		{"MinProtocol below the helper's", lp, func(s *Spec) { s.MinProtocol = helperproto.MinProtocol - 1 }},
		{"no Subcommands", lp, func(s *Spec) { s.Subcommands = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			tc.edit(&spec)
			assert.Panics(t, func() { NewBase(tc.ssh, spec) })
		})
	}
}

func TestBaseDescribesItself(t *testing.T) {
	e := newEnv(t, true)
	assert.Equal(t, providers.KindNginx, e.base.Kind())
	assert.Equal(t, "provider.nginx.name", e.base.DisplayNameKey())
	assert.Equal(t, "nginx", testSpec().Software())
	assert.Equal(t, e.ssh.ConfigSchema(), e.base.ConfigSchema())
	assert.Equal(t, e.ssh.CredentialSchema(), e.base.CredentialSchema())
	assert.Empty(t, e.base.ValidateConfig(e.ref.Config))
	assert.NotEmpty(t, e.base.ValidateConfig(providers.TargetConfig{"port": 22}))
	e.base.ForgetTarget(testTarget)
	assert.Equal(t, []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
		providers.CapDiscoverCerts, providers.CapKeyLogin}, BaseCapabilities())
}

func TestOpenSessionKeepsTheLinuxFailures(t *testing.T) {
	e := newEnv(t, true)
	e.ref.Config = providers.TargetConfig{"port": 22}
	_, err := e.base.OpenSession(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "target.invalid_config", providerErr(t, err).Code)

	e = newEnv(t, true)
	e.emu.SetProtocol(3)
	_, err = e.base.OpenSession(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.helper_outdated", providerErr(t, err).Code)
}

func TestSharedReason(t *testing.T) {
	spec := testSpec()
	sudo := func(sub string) error {
		return providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": sub, "exit_code": "1"})
	}
	helper := func(reason, code string) error {
		return providers.NewError(reason, false, nil, map[string]string{"subcommand": "nginx-deploy", "helper_code": code})
	}

	pe := spec.SharedReason(sudo(helperproto.SubNginxDeploy), helperproto.SubNginxDeploy)
	require.NotNil(t, pe)
	assert.Equal(t, "nginx.profile_missing", pe.Code)
	assert.Equal(t, map[string]string{"subcommand": "nginx-deploy", "profile": "nginx"}, pe.Params)
	assert.False(t, pe.Retryable)
	for _, sub := range spec.Subcommands {
		assert.Equal(t, "nginx.profile_missing", spec.SharedReason(sudo(sub), sub).Code, sub)
	}
	assert.Nil(t, spec.SharedReason(sudo(helperproto.SubACMEChallengePut), helperproto.SubACMEChallengePut), "not a subcommand of the profile")
	notInstalled := providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": "nginx-dump", "exit_code": "127"})
	assert.Nil(t, spec.SharedReason(notInstalled, helperproto.SubNginxDump), "a missing helper is not a missing profile")

	pe = spec.SharedReason(helper("ssh.helper_refused", helperproto.CodeNginxNotFound), helperproto.SubNginxDump)
	require.NotNil(t, pe)
	assert.Equal(t, "nginx.not_found", pe.Code)
	assert.Empty(t, pe.Params)
	pe = spec.SharedReason(helper("ssh.file_changed", helperproto.CodeConfigInvalid), helperproto.SubNginxDeploy)
	require.NotNil(t, pe)
	assert.Equal(t, "nginx.config_invalid", pe.Code)
	cause := helper("ssh.helper_refused", helperproto.CodeConfigInvalid)
	assert.ErrorIs(t, spec.SharedReason(cause, helperproto.SubNginxDeploy), cause, "the cause is kept")

	assert.Nil(t, spec.SharedReason(helper("ssh.helper_refused", helperproto.CodeBusy), helperproto.SubNginxDeploy))
	assert.Nil(t, spec.SharedReason(helper("ssh.output_too_large", helperproto.CodeNginxNotFound), helperproto.SubNginxDump),
		"only a refusal or a changed file carries a helper code")
	assert.Nil(t, spec.SharedReason(errors.New("plain"), helperproto.SubNginxDeploy))
	assert.Nil(t, spec.SharedReason(nil, helperproto.SubNginxDeploy))
}

func TestIsHelperCode(t *testing.T) {
	err := providers.NewError("ssh.helper_refused", false, nil, map[string]string{"helper_code": helperproto.CodeBusy})
	assert.True(t, IsHelperCode(err, helperproto.CodeBusy))
	assert.True(t, IsHelperCode(fmt.Errorf("wrapped: %w", err), helperproto.CodeBusy))
	assert.False(t, IsHelperCode(err, helperproto.CodeIOError))
	assert.False(t, IsHelperCode(errors.New("plain"), helperproto.CodeBusy))
	assert.False(t, IsHelperCode(nil, helperproto.CodeBusy))
}

func TestTestConnectionReportsTheWebServer(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		e := newEnv(t, true)
		s := e.open(t)
		assert.NotNil(t, s.Conn())
		require.NoError(t, s.Live())
		rep, err := s.TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx", Found: true, ConfigValid: true}, rep.WebServer)
		assert.Empty(t, rep.Warnings)
		assert.NotEmpty(t, rep.HostKey.Fingerprint, "the Linux part of the report is kept")
		assert.Equal(t, helperproto.Protocol, rep.HelperProtocol)
	})
	t.Run("invalid", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetConfigInvalid(helperproto.ConfigErrKeyMismatch)
		rep, err := e.open(t).TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx", Found: true, ConfigError: helperproto.ConfigErrKeyMismatch}, rep.WebServer)
		assert.Equal(t, []string{providers.WarnWebServerConfigInvalid}, warningCodes(rep.Warnings))
	})
	t.Run("an unknown error class is not passed on", func(t *testing.T) {
		e := newEnv(t, true)
		scriptOn(e, helperproto.SubNginxTest, linuxsshtest.Response{Stdout: []byte(`{"ok":true,"valid":false,"error":"bogus"}`)})
		rep, err := e.open(t).TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx", Found: true}, rep.WebServer)
	})
	t.Run("no nginx", func(t *testing.T) {
		e := newEnv(t, false)
		rep, err := e.open(t).TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx"}, rep.WebServer)
		assert.Equal(t, []string{providers.WarnWebServerNotFound}, warningCodes(rep.Warnings))
		assert.Equal(t, map[string]string{}, rep.Warnings[0].Params)
	})
	t.Run("profile missing", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetNginxProfile(false)
		_, err := e.open(t).TestConnection(context.Background())
		pe := providerErr(t, err)
		assert.Equal(t, "nginx.profile_missing", pe.Code)
		assert.Equal(t, map[string]string{"subcommand": "nginx-test", "profile": "nginx"}, pe.Params)
	})
	t.Run("a killed nginx stays a retryable helper refusal", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetNginxKilled(true)
		_, err := e.open(t).TestConnection(context.Background())
		pe := providerErr(t, err)
		assert.Equal(t, "ssh.helper_refused", pe.Code)
		assert.True(t, pe.Retryable)
	})
	t.Run("a dropped connection", func(t *testing.T) {
		e := newEnv(t, true)
		scriptOn(e, helperproto.SubNginxTest, linuxsshtest.Response{Hangup: true})
		_, err := e.open(t).TestConnection(context.Background())
		require.Error(t, err)
	})
	t.Run("the Linux test fails first", func(t *testing.T) {
		e := newEnv(t, true)
		s := e.open(t)
		e.emu.SetHelperMissing(true)
		_, err := s.TestConnection(context.Background())
		assert.Equal(t, "ssh.helper_missing", providerErr(t, err).Code)
	})
}

func TestDiscoverHalves(t *testing.T) {
	t.Run("certificates only", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))
		n := len(e.srv.Commands())
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		for _, line := range e.srv.Commands()[n:] {
			assert.NotContains(t, line, "authkeys", "a certificates-only request runs no SSH-key discovery")
		}
		require.NotNil(t, res.WebServer)
		assert.Equal(t, providers.WebServerFacts{Software: "nginx", Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true},
			*res.WebServer)
		require.Len(t, res.Certificates, 1)
		assert.Equal(t, wwwCert, res.Certificates[0].Location.CertPath)
		assert.True(t, res.Certificates[0].Location.Supported)
		assert.Equal(t, hexSHA(e.leaf.FullchainPEM), res.Certificates[0].FileSHA256)
		assert.Empty(t, res.SSHKeys)
	})
	t.Run("both halves", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
		require.NoError(t, err)
		assert.NotEmpty(t, res.SSHKeys)
		assert.Len(t, res.Certificates, 1)
		require.NotNil(t, res.WebServer)
	})
	t.Run("SSH keys only", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(authKeysLine+"\n"))
		n := len(e.srv.Commands())
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
		require.NoError(t, err)
		for _, line := range e.srv.Commands()[n:] {
			assert.NotContains(t, line, helperproto.SubNginxDump, "an SSH-keys-only request runs no dump")
		}
		assert.NotEmpty(t, res.SSHKeys)
		assert.Nil(t, res.WebServer)
		assert.Empty(t, res.Certificates)
	})
	t.Run("no nginx", func(t *testing.T) {
		e := newEnv(t, false)
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
		assert.Equal(t, "nginx.not_found", providerErr(t, err).Code)
		assert.Equal(t, providers.DiscoveryResult{}, res)
	})
	t.Run("invalid configuration", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax)
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Contains(t, warningCodes(res.Warnings), providers.WarnWebServerConfigInvalid)
		assert.Empty(t, res.Certificates)
		require.NotNil(t, res.WebServer)
		assert.False(t, res.WebServer.ConfigValid)
		assert.Equal(t, "nginx", res.WebServer.Software)
	})
	t.Run("invalid configuration with too many warnings", func(t *testing.T) {
		e := newEnv(t, true)
		d := helperproto.ServerDumpResponse{OK: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigError: helperproto.ConfigErrSyntax}
		for i := range maxDumpWarnings + 1 {
			d.Warnings = append(d.Warnings, "w_"+strings.Repeat("a", i+1))
		}
		out, err := json.Marshal(d)
		require.NoError(t, err)
		scriptOn(e, helperproto.SubNginxDump, linuxsshtest.Response{Stdout: out})
		res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		codes := warningCodes(res.Warnings)
		assert.Equal(t, providers.WarnWebServerConfigInvalid, codes[0])
		assert.Equal(t, providers.WarnListTruncated, codes[len(codes)-1])
		assert.Len(t, codes, maxDumpWarnings+2)
	})
	t.Run("errors", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetNginxProfile(false)
		_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		assert.Equal(t, "nginx.profile_missing", providerErr(t, err).Code)

		e = newEnv(t, true)
		e.emu.SetNginxKilled(true)
		_, err = e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		pe := providerErr(t, err)
		assert.Equal(t, "ssh.helper_refused", pe.Code, "not a shared reason: unchanged")
		assert.Equal(t, helperproto.CodeIOError, pe.Params["helper_code"])

		e = newEnv(t, true)
		scriptOn(e, helperproto.SubNginxDump, linuxsshtest.Response{Hangup: true})
		_, err = e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.Error(t, err)

		e = newEnv(t, true)
		s := e.open(t)
		e.emu.SetHelperMissing(true)
		_, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
		require.Error(t, err, "the dump runs first and fails")
	})
	t.Run("the SSH half fails after the dump", func(t *testing.T) {
		e := newEnv(t, true)
		scriptOn(e, helperproto.SubAuthKeysList, linuxsshtest.Response{Hangup: true})
		_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
		require.Error(t, err)
	})
}

func TestClosedSessionIsNotLive(t *testing.T) {
	e := newEnv(t, true)
	s := e.open(t)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "closing twice is fine")
	before := len(e.srv.Commands())
	assert.Equal(t, "ssh.unreachable", providerErr(t, s.Live()).Code)
	_, err := s.TestConnection(context.Background())
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Len(t, e.srv.Commands(), before, "a closed session's connection may serve another session")
}

func TestSessionConformance(t *testing.T) {
	e := newEnv(t, true)
	caps := providers.NewCapabilitySet(BaseCapabilities()...)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: caps,
		Open: func(ctx context.Context) (providers.Session, error) {
			s, err := e.base.OpenSession(ctx, e.ref, e.cred, providers.Env{})
			if err != nil {
				return nil, err
			}
			return s, nil
		},
	})
}

func TestTestConnectionFromTheDump(t *testing.T) {
	dumpOnly := func(e *env) *Session {
		spec := testSpec()
		spec.Test = nil
		e.base = NewBase(e.ssh, spec)
		return e.open(t)
	}
	t.Run("valid", func(t *testing.T) {
		e := newEnv(t, true)
		n := len(e.srv.Commands())
		rep, err := dumpOnly(e).TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx", Found: true, Version: "1.22.1", ConfPath: "/etc/nginx/nginx.conf", ConfigValid: true}, rep.WebServer)
		assert.Empty(t, rep.Warnings)
		for _, line := range e.srv.Commands()[n:] {
			assert.NotContains(t, line, helperproto.SubNginxTest)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax)
		rep, err := dumpOnly(e).TestConnection(context.Background())
		require.NoError(t, err)
		require.NotNil(t, rep.WebServer)
		assert.False(t, rep.WebServer.ConfigValid)
		assert.Equal(t, helperproto.ConfigErrSyntax, rep.WebServer.ConfigError)
		assert.Equal(t, []string{providers.WarnWebServerConfigInvalid}, warningCodes(rep.Warnings))
	})
	t.Run("no nginx", func(t *testing.T) {
		e := newEnv(t, false)
		rep, err := dumpOnly(e).TestConnection(context.Background())
		require.NoError(t, err)
		assert.Equal(t, &providers.WebServerFacts{Software: "nginx"}, rep.WebServer)
		assert.Equal(t, []string{providers.WarnWebServerNotFound}, warningCodes(rep.Warnings))
	})
	t.Run("profile missing", func(t *testing.T) {
		e := newEnv(t, true)
		e.emu.SetNginxProfile(false)
		_, err := dumpOnly(e).TestConnection(context.Background())
		assert.Equal(t, "nginx.profile_missing", providerErr(t, err).Code)
	})
}

func TestSharedReasonUsesTheSpecsNotFoundCode(t *testing.T) {
	spec := testSpec()
	spec.NotFoundCode = "SOFTWARE_NOT_FOUND"
	refusal := func(code string) error {
		return providers.NewError("ssh.helper_refused", false, nil, map[string]string{"subcommand": "nginx-dump", "helper_code": code})
	}
	pe := spec.SharedReason(refusal("SOFTWARE_NOT_FOUND"), helperproto.SubNginxDump)
	require.NotNil(t, pe)
	assert.Equal(t, "nginx.not_found", pe.Code)
	assert.Nil(t, spec.SharedReason(refusal(helperproto.CodeNginxNotFound), helperproto.SubNginxDump))
}

func TestHelperTooOldIsAWarningNotAFailure(t *testing.T) {
	e := newEnv(t, true)
	e.emu.SetProtocol(helperproto.MinProtocol)
	spec := testSpec()
	spec.MinProtocol = helperproto.MinProtocol + 1
	e.base = NewBase(e.ssh, spec)
	s := e.open(t)

	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Nil(t, rep.WebServer)
	assert.Equal(t, []string{providers.WarnWebServerHelperTooOld}, warningCodes(rep.Warnings))

	n := len(e.srv.Commands())
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	pe := providerErr(t, err)
	assert.Equal(t, "nginx.helper_too_old", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, map[string]string{"helper_protocol": "6", "required_protocol": "7"}, pe.Params)
	for _, line := range e.srv.Commands()[n:] {
		assert.NotContains(t, line, helperproto.SubNginxDump, "the dump is not asked of a helper that is too old")
	}

	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Nil(t, res.WebServer)
}

func TestTestConnectionFromTheDumpFailures(t *testing.T) {
	e := newEnv(t, true)
	spec := testSpec()
	spec.Test = nil
	e.base = NewBase(e.ssh, spec)
	s := e.open(t)
	scriptOn(e, helperproto.SubNginxDump, linuxsshtest.Response{Hangup: true})
	_, err := s.TestConnection(context.Background())
	require.Error(t, err)
}
