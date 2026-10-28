package windows

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/providers/windows/winproto"
)

func TestWindowsProviderDescribesItself(t *testing.T) {
	p := newEnv(t).prov
	assert.Equal(t, providers.KindWindows, p.Kind())
	assert.Equal(t, "provider.windows.name", p.DisplayNameKey())
	assert.Equal(t, []providers.Capability{providers.CapCleanupCertificates, providers.CapDeployCertificate, providers.CapDiscoverCerts,
		providers.CapTestConnection, providers.CapVerifyDeployment}, p.Capabilities().Sorted(),
		"W3 advertises what it implements: deployment, verification and cleanup")
	assert.Empty(t, p.CredentialSchema().Fields, "targets use the platform key; no per-target secret")
	fields := map[string]providers.Field{}
	for _, f := range p.ConfigSchema().Fields {
		fields[f.Name] = f
		assert.Equal(t, "provider.windows.fields."+f.Name+".label", f.LabelKey)
		assert.Equal(t, "provider.windows.fields."+f.Name+".help", f.HelpKey)
	}
	require.Len(t, fields, 3)
	assert.True(t, fields["host"].Required)
	assert.Equal(t, 22, fields["port"].Default)
	assert.Equal(t, DefaultUser, fields["username"].Default)
	assert.Equal(t, userRE.String(), fields["username"].Pattern, "the form and the provider apply one rule")
	var _ providers.ConnectionCache = p
	providertest.CheckProvider(t, p)
}

// Review Focus 1: a domain account is kept verbatim; a Linux-only or malformed name is refused.
func TestParseConfigTakesDomainAccounts(t *testing.T) {
	for _, u := range []string{"alice", `CORP\alice-svc`, `A1\b.c-d_e`, "a", strings.Repeat("d", 15) + `\` + strings.Repeat("n", 20)} {
		c, errs := ParseConfig(providers.TargetConfig{"host": "iis-01.corp.example", "username": u})
		assert.Empty(t, errs, u)
		assert.Equal(t, u, c.Username, "kept as typed")
		assert.True(t, ValidUser(u), u)
	}
	for _, u := range []string{`corp\`, `\alice`, `a\b\c`, "alice@corp.example", strings.Repeat("d", 16) + `\alice`,
		strings.Repeat("n", 21), "ali ce", "al'ice", "", "-alice", `CORP\-alice`, "alice\n", `CORP/alice`, "älice"} {
		_, errs := ParseConfig(providers.TargetConfig{"host": "iis-01", "username": u})
		require.Len(t, errs, 1, "%q", u)
		assert.Equal(t, "username", errs[0].Field)
		assert.Equal(t, validate.Pattern, errs[0].Code)
		assert.False(t, ValidUser(u), u)
	}
	_, errs := ParseConfig(providers.TargetConfig{"host": "iis-01", "username": 7})
	require.Len(t, errs, 1)
	assert.Equal(t, validate.Pattern, errs[0].Code)

	c, errs := ParseConfig(providers.TargetConfig{"host": "iis-01"})
	require.Empty(t, errs)
	assert.Equal(t, linuxssh.Config{Host: "iis-01", Port: 22, Username: DefaultUser}, c)
	c, errs = ParseConfig(providers.TargetConfig{"host": "iis-01", "port": float64(2222), "username": nil})
	require.Empty(t, errs)
	assert.Equal(t, linuxssh.Config{Host: "iis-01", Port: 2222, Username: DefaultUser}, c)

	// host and port follow the Linux rules (one shared check).
	_, errs = ParseConfig(providers.TargetConfig{"port": 70000, "username": "a b"})
	got := map[string]string{}
	for _, fe := range errs {
		got[fe.Field] = fe.Code
	}
	assert.Equal(t, map[string]string{"host": validate.Required, "port": validate.OutOfRange, "username": validate.Pattern}, got)
	assert.Equal(t, errs, newEnv(t).prov.ValidateConfig(providers.TargetConfig{"port": 70000, "username": "a b"}))
}

func TestOpenSendsBareCommands(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	_, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"version", "win-facts"}, e.srv.Commands(), "no sudo, no path: sshd forces the helper")
	users := e.sshUsers()
	require.NotEmpty(t, users)
	for _, u := range users {
		assert.Equal(t, `CORP\alice-svc`, u, "the configured account, verbatim")
	}
}

// W0 (design §8): Windows OpenSSH gives every later session on a connection the first session's
// command, so every helper call has its own connection; none is kept open afterwards.
func TestEveryHelperCallUsesItsOwnConnection(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	assert.Equal(t, 1, e.srv.Connections())
	e.waitNoOpenConnections(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err, "a reused connection would answer win-facts as version")
	assert.Equal(t, "10.0.20348.2700", rep.Windows.Build)
	assert.Equal(t, 2, e.srv.Connections())
	e.waitNoOpenConnections(t)
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err, "a reused connection would answer iis-dump as version")
	assert.Equal(t, 3, e.srv.Connections(), "one connection per helper call")
	assert.Equal(t, []string{"version", "win-facts", "iis-dump"}, e.srv.Commands())
	e.waitNoOpenConnections(t)
	require.NoError(t, s.Close())
	assert.Equal(t, 3, e.srv.Connections(), "closing dials nothing")
}

func TestTestConnectionReport(t *testing.T) {
	e := newEnv(t)
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ssh.FingerprintSHA256(e.srv.HostKey()), rep.HostKey.Fingerprint)
	assert.Equal(t, "1.2.0", rep.HelperVersion)
	assert.Equal(t, 1, rep.HelperProtocol)
	assert.Equal(t, providers.OSRelease{ID: "windows", VersionID: "10.0.20348.2700", PrettyName: "Windows Server 2022 Datacenter"}, rep.OS)
	assert.Equal(t, &providers.WindowsFacts{Build: "10.0.20348.2700", Product: "Windows Server 2022 Datacenter", InstallationType: "Server",
		Elevated: true, IISInstalled: true, IISVersion: "10.0", Stores: []string{"My", "WebHosting", "CA", "Root"},
		OpenSSHVersion: "OpenSSH_for_Windows_8.1p1"}, rep.Windows)
	assert.Equal(t, &providers.WebServerFacts{Software: "iis", Version: "10.0", Found: true, ConfigValid: true}, rep.WebServer)
	assert.Empty(t, rep.Warnings)
	assert.Nil(t, rep.Azure)

	e.model.SetIIS(winproto.IISFacts{})
	rep, err = e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &providers.WebServerFacts{Software: "iis"}, rep.WebServer)
	assert.False(t, rep.Windows.IISInstalled)
	require.Len(t, rep.Warnings, 1)
	assert.Equal(t, providers.WarnWebServerNotFound, rep.Warnings[0].Code)
	assert.NotNil(t, rep.Warnings[0].Params)
}

// The facts are remote text: cleaned, bounded, at most 16 stores.
func TestReportCleansTheFacts(t *testing.T) {
	stores := make([]string, 0, 20)
	for i := range 20 {
		stores = append(stores, "S"+strings.Repeat("x", i))
	}
	stores[0] = "\x1b[31mMy\u202e"
	long := strings.Repeat("é", 300)
	f := winproto.WinFactsResponse{OK: true, OSBuild: " 10.0.1\x00 ", OSProduct: long, InstallationType: "Server\r\nCore",
		Elevated: true, IIS: winproto.IISFacts{Installed: true, Version: "10.0\x07"}, Stores: stores, OpenSSHVersion: "\x1b]0;x\x07OpenSSH"}
	w, ws := facts(f)
	assert.Equal(t, "10.0.1", w.Build)
	assert.Equal(t, strings.Repeat("é", maxFactLength), w.Product)
	assert.Equal(t, "ServerCore", w.InstallationType)
	assert.Equal(t, "10.0", w.IISVersion)
	assert.Equal(t, "]0;xOpenSSH", w.OpenSSHVersion)
	require.Len(t, w.Stores, maxStores)
	assert.Equal(t, "[31mMy", w.Stores[0])
	assert.Equal(t, &providers.WebServerFacts{Software: "iis", Version: "10.0", Found: true, ConfigValid: true}, ws)

	w, _ = facts(winproto.WinFactsResponse{Stores: []string{"\x1b", "My"}})
	assert.Equal(t, []string{"My"}, w.Stores, "a name that cleans to nothing is dropped")
	w, _ = facts(winproto.WinFactsResponse{})
	assert.NotNil(t, w.Stores, "an empty list, not null")
}

func TestOpenHelperMissing(t *testing.T) {
	e := newEnv(t)
	e.model.SetHelperMissing(true)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	pe := providerErr(t, err)
	assert.Equal(t, "windows.helper_missing", pe.Code)
	assert.Equal(t, "1", pe.Params["exit_code"])
	assert.Equal(t, "version", pe.Params["subcommand"])
	assert.False(t, pe.Retryable)
}

// Review Focus 5: the key works but sshd has no ForceCommand, so the login shell (cmd.exe) runs the
// line: helper missing from version, and nothing else is sent.
func TestOpenWithoutForcedCommandIsHelperMissing(t *testing.T) {
	e := newEnv(t)
	e.model.SetNoForcedCommand(true)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "windows.helper_missing", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, e.srv.Commands())
}

func TestOpenHelperOutdated(t *testing.T) {
	e := newEnv(t)
	e.model.SetProtocol(0)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	pe := providerErr(t, err)
	assert.Equal(t, "windows.helper_outdated", pe.Code)
	assert.Equal(t, "0", pe.Params["helper_protocol"])
	assert.Equal(t, "1", pe.Params["required_protocol"])
	assert.Equal(t, []string{"version"}, e.srv.Commands())

	e.model.SetProtocol(2)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err, "a newer helper serves an older Alice (MinProtocol)")
	assert.Equal(t, 2, rep.HelperProtocol)
}

// Ruling 3: an unelevated token is named, so the target's last error says what to fix.
func TestTestConnectionNotElevated(t *testing.T) {
	e := newEnv(t)
	e.model.SetElevated(false)
	_, err := e.open(t).TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "windows.not_elevated", pe.Code)
	assert.False(t, pe.Retryable)
}

// Ruling 13: a helper that does not know a subcommand is outdated.
func TestUnknownSubcommandIsOutdated(t *testing.T) {
	e := newEnv(t)
	inner := e.model.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if cmd == winproto.SubWinFacts {
			b, _ := json.Marshal(winproto.ErrorResponse{Code: winproto.CodeUnknownSubcommand, Message: "unknown subcommand"})
			return linuxsshtest.Response{Stdout: b, Exit: winproto.ExitRefused}
		}
		return inner(cmd, stdin)
	})
	_, err := e.open(t).TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, "windows.helper_outdated", pe.Code)
	assert.Equal(t, "win-facts", pe.Params["subcommand"])
	assert.Equal(t, winproto.CodeUnknownSubcommand, pe.Params["helper_code"])
}

func TestMapHelper(t *testing.T) {
	plain := errors.New("plain")
	assert.Same(t, plain, mapHelper(plain))
	timeout := providers.NewError("ssh.timeout", true, nil, map[string]string{"subcommand": "iis-dump"})
	assert.Same(t, timeout, mapHelper(timeout))
	tooLarge := providers.NewError("ssh.output_too_large", false, nil, map[string]string{"subcommand": "iis-dump", "helper_code": "OUTPUT_TOO_LARGE"})
	assert.Same(t, tooLarge, mapHelper(tooLarge), "not a refusal code of the helper's: kept")
	noCode := providers.NewError("ssh.helper_refused", false, nil, map[string]string{"subcommand": "iis-dump"})
	assert.Same(t, noCode, mapHelper(noCode))
	missing := providers.NewError("ssh.helper_missing", false, nil, map[string]string{"subcommand": "version", "exit_code": "127"})
	pe := providerErr(t, mapHelper(missing))
	assert.Equal(t, "windows.helper_missing", pe.Code)
	assert.Equal(t, map[string]string{"subcommand": "version", "exit_code": "127"}, pe.Params)
	assert.ErrorIs(t, pe, missing, "the shared error stays the cause")
	missing.Params["exit_code"] = "1"
	assert.Equal(t, "127", pe.Params["exit_code"], "own params")
	for code, want := range map[string]string{winproto.CodeUnknownSubcommand: "windows.helper_outdated", winproto.CodeNotElevated: "windows.not_elevated"} {
		in := providers.NewError("ssh.helper_refused", false, nil, map[string]string{"subcommand": "iis-dump", "helper_code": code})
		pe := providerErr(t, mapHelper(in))
		assert.Equal(t, want, pe.Code)
		assert.Equal(t, map[string]string{"subcommand": "iis-dump", "helper_code": code}, pe.Params)
		assert.False(t, pe.Retryable)
	}

	// W2 Ruling 6: every Windows helper code has a reason of its own; none stays ssh.helper_refused.
	for _, tc := range []struct {
		code, exit, want string
		retryable        bool
	}{
		{winproto.CodeHashMismatch, "3", ReasonBindingChanged, true},
		{winproto.CodeBindingNotFound, "3", ReasonBindingNotFound, false},
		{winproto.CodeBusy, "4", ReasonBusy, true},
		{winproto.CodeIOError, "4", ReasonIOError, true},
		{winproto.CodeJournalFailed, "4", ReasonIOError, true},
		{winproto.CodeStoreError, "4", ReasonStoreError, false},
		{winproto.CodeKeyUnusable, "3", ReasonKeyUnusable, false},
		{winproto.CodeBackupMissing, "3", ReasonBackupMissing, false},
		{winproto.CodeRecoveryPending, "3", "deployment.recovery_pending", false},
		{winproto.CodeFenced, "3", "deployment.interrupted", false},
		{winproto.CodeSuperseded, "3", "deployment.superseded", false},
		{winproto.CodeUnknownOp, "3", "deployment.unknown_operation", false},
		{winproto.CodeUnknownSubcommand, "2", ReasonHelperOutdated, false},
		{winproto.CodeNotElevated, "2", ReasonNotElevated, false},
		{winproto.CodeOperationExists, "3", ReasonHelperRefused, false},
		{winproto.CodeOutcomeUnknown, "4", ReasonHelperRefused, false},
		{winproto.CodeBadContent, "2", ReasonHelperRefused, false},
		{winproto.CodeInvalidArgument, "2", ReasonHelperRefused, false},
		{winproto.CodeTooLarge, "2", ReasonHelperRefused, false},
		{winproto.CodeUsage, "2", ReasonHelperRefused, false},
		{winproto.CodeProbeFailed, "4", ReasonHelperRefused, false},
		{winproto.CodeIISNotFound, "3", ReasonHelperRefused, false},
		{"SOMETHING_NEW", "3", ReasonHelperRefused, false},
	} {
		// DecodeHelper names HASH_MISMATCH at exit 3 ssh.file_changed, everything else ssh.helper_refused.
		shared := "ssh.helper_refused"
		if tc.code == winproto.CodeHashMismatch {
			shared = "ssh.file_changed"
		}
		params := map[string]string{"subcommand": "iis-deploy", "helper_code": tc.code}
		in := providers.NewError(shared, tc.code == winproto.CodeBusy || tc.code == winproto.CodeIOError, nil, params)
		pe := providerErr(t, mapHelper(in))
		assert.Equal(t, tc.want, pe.Code, tc.code)
		assert.Equal(t, tc.retryable, pe.Retryable, tc.code)
		assert.ErrorIs(t, pe, in, "the shared error stays the cause")
		assert.NotEqual(t, "ssh.helper_refused", pe.Code)
		if tc.want == ReasonHelperRefused || tc.want == ReasonHelperOutdated || tc.want == ReasonNotElevated {
			assert.Equal(t, tc.code, pe.Params["helper_code"], "%s names the helper's code", tc.code)
		}
		if tc.code == winproto.CodeHashMismatch {
			in = providers.NewError("ssh.helper_refused", false, nil, params) // the same code at another exit status
			assert.Equal(t, ReasonBindingChanged, providerErr(t, mapHelper(in)).Code)
		}
	}
	pending := providers.NewError("ssh.helper_refused", false, nil, map[string]string{"subcommand": "iis-deploy",
		"helper_code": winproto.CodeRecoveryPending, "operation_id": "0190f5a0-0000-7000-8000-0000000000aa"})
	pe = providerErr(t, mapHelper(pending))
	assert.Equal(t, map[string]string{"operation_id": "0190f5a0-0000-7000-8000-0000000000aa"}, pe.Params,
		"the engine's pending-operation path reads operation_id")
	pending = providers.NewError("ssh.helper_refused", false, nil, map[string]string{"subcommand": "iis-deploy", "helper_code": winproto.CodeRecoveryPending})
	assert.Empty(t, providerErr(t, mapHelper(pending)).Params)
	for _, c := range []string{"ssh.unreachable", "ssh.timeout", "target.host_key_changed", "ssh.protocol_error"} {
		in := providers.NewError(c, true, nil, map[string]string{"subcommand": "iis-restore", "helper_code": winproto.CodeBusy})
		assert.Same(t, in, mapHelper(in), "the transport's codes stay: %s", c)
	}
}

// Every reason of the Windows provider is a windows.* name (or the shared deployment.* ones of Ruling 6).
func TestWindowsReasons(t *testing.T) {
	for _, r := range []string{ReasonHelperMissing, ReasonHelperOutdated, ReasonNotElevated, ReasonBindingChanged, ReasonBindingNotFound, ReasonBusy,
		ReasonIOError, ReasonStoreError, ReasonKeyUnusable, ReasonBackupMissing, ReasonLocationUnsupported, ReasonHelperRefused} {
		assert.True(t, strings.HasPrefix(r, "windows."), r)
	}
	assert.Equal(t, "windows.location_unsupported", ReasonLocationUnsupported)
	assert.Equal(t, "windows.helper_refused", ReasonHelperRefused)
}

func TestCommandsAreForcedLines(t *testing.T) {
	for _, tc := range []struct {
		sub     string
		args    []string
		timeout bool // the long budget
		line    string
	}{
		{winproto.SubVersion, nil, false, "version"},
		{winproto.SubWinFacts, nil, false, "win-facts"},
		{winproto.SubIISDump, nil, true, "iis-dump"},
		{winproto.SubTLSProbe, []string{"--addr", "10.0.0.5", "--port", "443", "--sni", "-", "--key-type", "any"}, false,
			"tls-probe --addr 10.0.0.5 --port 443 --sni - --key-type any"},
	} {
		c, err := cmd(tc.sub, nil, tc.args...)
		require.NoError(t, err, tc.sub)
		assert.Equal(t, tc.line, c.Line())
		assert.Equal(t, tc.sub, c.Subcommand())
	}
	assert.Equal(t, budget{linuxssh.DefaultCommandTimeout, 64 << 10}, budgets[winproto.SubVersion])
	assert.Equal(t, budget{linuxssh.DefaultCommandTimeout, 64 << 10}, budgets[winproto.SubWinFacts])
	assert.Equal(t, budget{linuxssh.LongCommandTimeout, winproto.DumpOutput}, budgets[winproto.SubIISDump])
	assert.Equal(t, budget{linuxssh.DefaultCommandTimeout, 128 << 10}, budgets[winproto.SubTLSProbe])
	assert.Equal(t, budget{linuxssh.LongCommandTimeout, 1 << 20}, budgets[winproto.SubIISCleanup])
	assert.Less(t, winproto.HelperBudget, linuxssh.LongCommandTimeout, "the helper gives up before Alice cuts the connection")
	for _, bad := range [][]string{{"winrm-deploy"}, {"version", "a b"}, {"version", "%x%"}, {"ssh"}} {
		_, err := cmd(bad[0], nil, bad[1:]...)
		assert.ErrorIs(t, err, linuxssh.ErrInvalidArgument, "%q", bad)
	}
}

// linuxssh.ForcedCommand applies winproto's token rule (linuxssh cannot import it): the two agree.
func TestForcedCommandAgreesWithTheProtocol(t *testing.T) {
	samples := []string{"version", "a", "A-Z_0.9:@+", "-", "--addr", "10.0.0.5", "[::1]", "a b", "a'b", `a"b`, "a&b", "%x%", "a^b",
		"a|b", "a<b", "a>b", "a!b", `C:\x`, "a\tb", "ç", "", strings.Repeat("a", 253), strings.Repeat("a", 254), "a,b", "a;b", "a=b", "a/b"}
	for _, s := range samples {
		_, err := linuxssh.ForcedCommand([]string{s}, nil, linuxssh.DefaultCommandTimeout, 1)
		assert.Equal(t, winproto.ValidToken(s), err == nil, "%q", s)
	}
	tokens := make([]string, winproto.MaxTokens+1)
	for i := range tokens {
		tokens[i] = "a"
	}
	_, err := linuxssh.ForcedCommand(tokens[:winproto.MaxTokens], nil, linuxssh.DefaultCommandTimeout, 1)
	require.NoError(t, err)
	_, err = linuxssh.ForcedCommand(tokens, nil, linuxssh.DefaultCommandTimeout, 1)
	assert.ErrorIs(t, err, linuxssh.ErrInvalidArgument)
	line, ok := winproto.JoinCommandLine(tokens[:winproto.MaxTokens])
	require.True(t, ok)
	got, ok := winproto.SplitCommandLine(line)
	require.True(t, ok)
	assert.Equal(t, tokens[:winproto.MaxTokens], got)
	assert.LessOrEqual(t, winproto.MaxTokens*253+winproto.MaxTokens-1, winproto.MaxLineBytes, "the byte bound never cuts a valid list")
}

func TestOpenRefusesAnInvalidConfig(t *testing.T) {
	e := newEnv(t)
	e.ref.Config = providers.TargetConfig{"host": "", "username": "alice"}
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	pe := providerErr(t, err)
	assert.Equal(t, "target.invalid_config", pe.Code)
	assert.Zero(t, e.srv.Connections(), "nothing connects")
}

func TestAClosedSessionRunsNothing(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "closing twice is fine")
	dials := e.srv.Connections()
	_, err := s.TestConnection(context.Background())
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Equal(t, dials, e.srv.Connections(), "a closed session dials nothing")
	assert.Equal(t, []string{"version"}, e.srv.Commands())
}

// Every call is a fresh connection (design §8), so a fresh env still dials once per call.
func TestOpenWithFreshConnectionDials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	env := providers.Env{Clock: clock.Real{}, HostKeys: e.hk}
	s1, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	require.NoError(t, s1.Close())
	assert.Equal(t, 1, e.srv.Connections())
	s2, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	require.NoError(t, s2.Close())
	assert.Equal(t, 2, e.srv.Connections(), "never an idle connection")
	env.FreshConnection = true
	s3, err := e.prov.Open(ctx, e.ref, e.cred, env)
	require.NoError(t, err)
	_, err = s3.TestConnection(ctx)
	require.NoError(t, err)
	require.NoError(t, s3.Close())
	assert.Equal(t, 4, e.srv.Connections(), "one dial per helper call")
	e.waitNoOpenConnections(t)
}

// A re-keyed server (reinstalled, or a MITM) is refused by the shared dial.
func TestHostKeyChangedRefuses(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	e.srv.SetHostKey(linuxsshtest.NewHostKey(t))
	_, err := s.TestConnection(context.Background())
	assert.Equal(t, "target.host_key_changed", providerErr(t, err).Code, "a later call dials again and sees the new key")
	_, err = e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "target.host_key_changed", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, e.srv.Commands(), "nothing runs on a changed key")
}

// A deleted target is forgotten through the shared pool: it is not dialled again.
func TestProviderForgetsADeletedTarget(t *testing.T) {
	e := newEnv(t)
	var cc providers.ConnectionCache = e.prov
	cc.ForgetTarget(testTarget)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Zero(t, e.srv.Connections())
}

// A helper answer that is not the protocol (cmd.exe banner on stdout, exit 0) is a protocol error.
func TestGarbageAnswerIsAProtocolError(t *testing.T) {
	e := newEnv(t)
	e.srv.SetHandler(func(string, []byte) linuxsshtest.Response {
		return linuxsshtest.Response{Stdout: []byte("Microsoft Windows [Version 10.0.20348]\r\n")}
	})
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	assert.Equal(t, "ssh.protocol_error", providerErr(t, err).Code)
}

// The version string is remote text: cleaned and cut to 40 runes.
func TestOpenCleansTheHelperVersion(t *testing.T) {
	e := newEnv(t)
	inner := e.model.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if cmd == winproto.SubVersion {
			b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: "\x1b[2J" + strings.Repeat("9", 60), Protocol: 1})
			return linuxsshtest.Response{Stdout: b}
		}
		return inner(cmd, stdin)
	})
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "[2J"+strings.Repeat("9", 37), rep.HelperVersion)
}

// A call cut short by its context is ssh.timeout, and its connection does not stay open.
func TestACallThatTimesOutClosesItsConnection(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	e.model.Delay(winproto.SubWinFacts, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := s.TestConnection(ctx)
	pe := providerErr(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.True(t, pe.Retryable)
	e.waitNoOpenConnections(t)
}

// A call whose command cannot be built is an internal error and sends nothing.
func TestCallRefusesAnInvalidCommand(t *testing.T) {
	e := newEnv(t)
	s, ok := e.open(t).(*session)
	require.True(t, ok)
	_, _, err := call[winproto.VersionResponse](context.Background(), s, "version", "a b")
	assert.Equal(t, "internal.unexpected", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, e.srv.Commands())
}
