package providers_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
	"alice/internal/secrets"
)

// stub is the smallest valid provider; tests break one property at a time.
type stub struct {
	kind   providers.Kind
	name   string
	caps   providers.CapabilitySet
	config providers.ConfigSchema
	creds  providers.CredentialSchema
}

func validStub(kind providers.Kind) *stub {
	return &stub{
		kind: kind, name: "provider.stub.name",
		caps: providers.NewCapabilitySet(providers.CapTestConnection),
		config: providers.ConfigSchema{Fields: []providers.Field{
			{Name: "host", Type: providers.FieldHost, Required: true, LabelKey: "provider.stub.fields.host.label"},
			{Name: "port", Type: providers.FieldInt, Min: 1, Max: 65535, Default: 22, LabelKey: "provider.stub.fields.port.label"},
			{Name: "mode", Type: providers.FieldEnum, Values: []string{"a", "b"}, LabelKey: "provider.stub.fields.mode.label", Pattern: `^[ab]$`},
		}},
	}
}

func (s *stub) Kind() providers.Kind                         { return s.kind }
func (s *stub) DisplayNameKey() string                       { return s.name }
func (s *stub) Capabilities() providers.CapabilitySet        { return s.caps }
func (s *stub) ConfigSchema() providers.ConfigSchema         { return s.config }
func (s *stub) CredentialSchema() providers.CredentialSchema { return s.creds }
func (s *stub) ValidateConfig(providers.TargetConfig) []validate.FieldError {
	return nil
}
func (s *stub) Open(context.Context, providers.TargetRef, providers.CredentialSource, providers.Env) (providers.Session, error) {
	return providers.UnsupportedSession{}, nil
}

func TestRegistryRegistersFreezesAndLists(t *testing.T) {
	r := providers.NewRegistry()
	r.Register(validStub(providers.KindNginx))
	r.Register(validStub(providers.KindLinuxSSH))
	r.Freeze()

	p, ok := r.Get(providers.KindLinuxSSH)
	require.True(t, ok)
	assert.Equal(t, providers.KindLinuxSSH, p.Kind())
	_, ok = r.Get(providers.KindAzureKV)
	assert.False(t, ok)

	list := r.List()
	require.Len(t, list, 2)
	assert.Equal(t, providers.KindLinuxSSH, list[0].Kind, "sorted by kind")
	assert.Equal(t, providers.KindNginx, list[1].Kind)
	assert.Equal(t, []providers.Capability{providers.CapTestConnection}, list[0].Capabilities)
	assert.Equal(t, "provider.stub.name", list[0].DisplayNameKey)
	assert.Len(t, list[0].ConfigSchema.Fields, 3)

	assert.PanicsWithValue(t, "providers: registry is frozen; cannot register azurekv", func() {
		r.Register(validStub(providers.KindAzureKV))
	})
}

func TestRegistryRefusesBrokenProviders(t *testing.T) {
	cases := map[string]func(s *stub){
		"empty kind":               func(s *stub) { s.kind = "" },
		"no display name":          func(s *stub) { s.name = "" },
		"no capabilities":          func(s *stub) { s.caps = providers.NewCapabilitySet() },
		"bad field name":           func(s *stub) { s.config.Fields[0].Name = "Host" },
		"field name digit":         func(s *stub) { s.config.Fields[0].Name = "1host" },
		"duplicate field":          func(s *stub) { s.config.Fields[1].Name = "host" },
		"bad field type":           func(s *stub) { s.config.Fields[0].Type = "url" },
		"empty label key":          func(s *stub) { s.config.Fields[0].LabelKey = "" },
		"bad pattern":              func(s *stub) { s.config.Fields[2].Pattern = `^[a` },
		"enum without value":       func(s *stub) { s.config.Fields[2].Values = nil },
		"min above max":            func(s *stub) { s.config.Fields[1].Min = 70000 },
		"int default is a string":  func(s *stub) { s.config.Fields[1].Default = "22" },
		"string default is an int": func(s *stub) { s.config.Fields[0].Default = 5 },
		"bool default is a string": func(s *stub) {
			s.config.Fields = append(s.config.Fields, providers.Field{Name: "flag", Type: providers.FieldBool, Default: "true", LabelKey: "x"})
		},
		"enum default not a value": func(s *stub) { s.config.Fields[2].Default = "c" },
		"int default below min":    func(s *stub) { s.config.Fields[1].Default = 0 },
		"int default above max":    func(s *stub) { s.config.Fields[1].Default = 70000 },
		"negative min":             func(s *stub) { s.config.Fields[1].Min = -1 },
		"negative max":             func(s *stub) { s.config.Fields[1].Max = -1 },
		"pattern without ^":        func(s *stub) { s.config.Fields[2].Pattern = `[ab]$` },
		"pattern without $":        func(s *stub) { s.config.Fields[2].Pattern = `^[ab]` },
		"unknown capability":       func(s *stub) { s.caps = providers.NewCapabilitySet("teleport") },
		"bad credential field": func(s *stub) {
			s.creds = providers.CredentialSchema{Fields: []providers.Field{{Name: "secret", Type: "blob", LabelKey: "x"}}}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			s := validStub(providers.KindLinuxSSH)
			breakIt(s)
			assert.Panics(t, func() { providers.NewRegistry().Register(s) })
		})
	}
	t.Run("duplicate kind", func(t *testing.T) {
		r := providers.NewRegistry()
		r.Register(validStub(providers.KindLinuxSSH))
		assert.PanicsWithValue(t, "providers: kind linuxssh is registered twice", func() {
			r.Register(validStub(providers.KindLinuxSSH))
		})
	})
	t.Run("nil provider", func(t *testing.T) {
		assert.Panics(t, func() { providers.NewRegistry().Register(nil) })
	})
	// An anchored pattern that is not a regular expression passes the ^...$ check and is refused
	// by the compile check, so a schema never carries a pattern that would accept nothing.
	t.Run("anchored pattern that does not compile", func(t *testing.T) {
		s := validStub(providers.KindLinuxSSH)
		s.config.Fields[2].Pattern = `^[a$`
		assert.PanicsWithValue(t, `providers: linuxssh config schema: field "mode" has a pattern that does not compile`, func() {
			providers.NewRegistry().Register(s)
		})
	})
}

func TestKindForTargetType(t *testing.T) {
	for typ, want := range map[string]providers.Kind{
		"linux": providers.KindLinuxSSH, "nginx": providers.KindNginx, "azure_key_vault": providers.KindAzureKV,
	} {
		got, ok := providers.KindForTargetType(typ)
		assert.True(t, ok, typ)
		assert.Equal(t, want, got, typ)
	}
	for _, typ := range []string{"", "Linux", "linuxssh", "windows"} {
		_, ok := providers.KindForTargetType(typ)
		assert.False(t, ok, typ)
	}
}

// A shared web-server reason is the provider kind, a dot and the reason (plan Ruling 4).
func TestKindReason(t *testing.T) {
	assert.Equal(t, "nginx.not_found", providers.KindNginx.Reason(providers.ReasonNotFound))
	assert.Equal(t, "nginx.profile_missing", providers.KindNginx.Reason(providers.ReasonProfileMissing))
	assert.Equal(t, "nginx.config_invalid", providers.KindNginx.Reason(providers.ReasonConfigInvalid))
}

func TestCapabilitySet(t *testing.T) {
	c := providers.NewCapabilitySet(providers.CapAuthorizedKeys, providers.CapTestConnection, providers.CapAuthorizedKeys)
	assert.True(t, c.Has(providers.CapTestConnection))
	assert.False(t, c.Has(providers.CapDeployCertificate))
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapTestConnection}, c.Sorted())
	assert.Empty(t, providers.NewCapabilitySet().Sorted())
	var nilSet providers.CapabilitySet
	assert.False(t, nilSet.Has(providers.CapTestConnection))
}

// Spec §6.3 item 5: no secret in errors. The message is the stable code only, whatever the cause says.
func TestErrorNeverShowsItsCause(t *testing.T) {
	cause := errors.New("ssh: handshake failed: password=CANARY-hunter2")
	err := providers.NewError("ssh.auth_failed", false, cause, map[string]string{"host": "web-01"})
	assert.Equal(t, "providers: ssh.auth_failed", err.Error())
	for _, s := range []string{fmt.Sprint(err), fmt.Sprintf("%v %+v %s %q", err, err, err, err), fmt.Errorf("job: %w", err).Error()} {
		assert.NotContains(t, s, "CANARY", s)
	}
	assert.ErrorIs(t, err, cause, "the cause stays reachable for errors.Is")
	var pe *providers.Error
	require.True(t, errors.As(fmt.Errorf("wrapped: %w", err), &pe))
	assert.Equal(t, "ssh.auth_failed", pe.Code)
	assert.False(t, pe.Retryable)
	assert.Equal(t, map[string]string{"host": "web-01"}, pe.Params)

	retry := providers.NewError("ssh.unreachable", true, nil, nil)
	assert.True(t, retry.Retryable)
	assert.NotNil(t, retry.Params, "params are never nil")
	assert.NoError(t, retry.Unwrap())
}

func TestUnsupportedSession(t *testing.T) {
	ctx := context.Background()
	s := providers.UnsupportedSession{}
	assert.NoError(t, s.Close())
	_, err := s.TestConnection(ctx)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.ListAuthorizedKeys(ctx)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}

func TestRegistryAcceptsValidDefaultsAndOpenEndedMax(t *testing.T) {
	s := validStub(providers.KindLinuxSSH)
	s.config.Fields[2].Default = "a"
	// Max == 0 is unbounded, so a positive Min alone is a valid lower bound.
	s.config.Fields = append(s.config.Fields,
		providers.Field{Name: "retries", Type: providers.FieldInt, Min: 3, Default: 5, LabelKey: "x"},
		providers.Field{Name: "flag", Type: providers.FieldBool, Default: true, LabelKey: "x"})
	assert.NotPanics(t, func() { providers.NewRegistry().Register(s) })
}

func TestCapabilitySetCloneIsIndependent(t *testing.T) {
	c := providers.NewCapabilitySet(providers.CapTestConnection)
	d := c.Clone()
	d[providers.CapAuthorizedKeys] = struct{}{}
	assert.False(t, c.Has(providers.CapAuthorizedKeys))
}

func TestErrorSerialisationNeverShowsItsCause(t *testing.T) {
	cause := errors.New("password=CANARY-hunter2")
	err := providers.NewError("ssh.auth_failed", true, cause, map[string]string{"host": "web-01"})

	raw, mErr := json.Marshal(err)
	require.NoError(t, mErr)
	assert.JSONEq(t, `{"code":"ssh.auth_failed","params":{"host":"web-01"}}`, string(raw))

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("failed", "err", err)
	assert.NotContains(t, buf.String(), "CANARY")
	assert.Contains(t, buf.String(), "ssh.auth_failed")
	assert.Contains(t, buf.String(), "web-01")
}

// Run with -race: the registry is used concurrently while providers are still being registered.
func TestRegistryConcurrentUseBeforeFreeze(t *testing.T) {
	r := providers.NewRegistry()
	kinds := []providers.Kind{providers.KindLinuxSSH, providers.KindNginx, providers.KindAzureKV}
	var wg sync.WaitGroup
	for _, k := range kinds {
		wg.Add(1)
		go func() { defer wg.Done(); r.Register(validStub(k)) }()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.Get(providers.KindLinuxSSH)
				_ = r.List()
			}
		}()
	}
	wg.Wait()
	r.Freeze()
	assert.Len(t, r.List(), 3)
}

// A-9: a field pattern is matched as ^(?:pattern)$ (like the HTML pattern attribute), so an
// alternation that only looks anchored ("^a|b$") cannot match a value that merely starts or ends
// right.
func TestFieldPatternIsFullyAnchored(t *testing.T) {
	f := providers.Field{Name: "x", Type: providers.FieldString, Pattern: `^admin|ops$`}
	assert.True(t, f.MatchPattern("admin"))
	assert.True(t, f.MatchPattern("ops"))
	for _, v := range []string{"admin; rm -rf /", "x ops", "adminops"} {
		assert.False(t, f.MatchPattern(v), "%q", v)
	}
	assert.True(t, providers.Field{Name: "y"}.MatchPattern("anything"), "no pattern accepts everything")
	assert.False(t, providers.Field{Name: "z", Pattern: `^[a$`}.MatchPattern("a"), "a broken pattern accepts nothing")
}

// A-9: the log value lists params in key order, so equal errors log the same line.
func TestErrorLogValueIsDeterministic(t *testing.T) {
	params := map[string]string{}
	for _, k := range []string{"zeta", "alpha", "mid", "beta", "omega", "gamma", "delta", "kappa"} {
		params[k] = k
	}
	err := providers.NewError("ssh.timeout", true, nil, params)
	first := ""
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "err", err)
		line := buf.String()[strings.Index(buf.String(), "err."):]
		if i == 0 {
			first = line
			assert.Regexp(t, `err.code=ssh.timeout err.param.alpha=alpha err.param.beta=beta err.param.delta=delta`, line)
			continue
		}
		assert.Equal(t, first, line)
	}
}

func TestUnsupportedSessionAnswersErrUnsupportedForDeployMethods(t *testing.T) {
	var s providers.Session = providers.UnsupportedSession{}
	ctx := context.Background()
	_, err := s.DeployCertificate(ctx, providers.DeployRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.RollbackDeployment(ctx, providers.RollbackRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.VerifyDeployment(ctx, providers.VerifyRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.DeploymentStatus(ctx, uuid.New())
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	state, err := s.FenceDeployment(ctx, uuid.New())
	assert.ErrorIs(t, err, providers.ErrUnsupported, "a provider without deployments cannot fence one")
	assert.Equal(t, providers.DeploymentState{}, state, "no tombstone is claimed")
}

const keyCanary = "KEY-MATERIAL-CANARY"

func TestDeployRequestNeverPrintsTheKey(t *testing.T) {
	req := providers.DeployRequest{
		OperationID:   uuid.New(),
		PrivateKeyPEM: secrets.NewPlaintext([]byte(keyCanary)),
	}
	for _, v := range []any{req, &req} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
			out := fmt.Sprintf(verb, v)
			assert.NotContains(t, out, keyCanary, "%s of %T", verb, v)
			assert.NotContains(t, out, fmt.Sprintf("%x", keyCanary), "%s of %T", verb, v)
		}
		var text, js bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("deploy", "req", v)
		slog.New(slog.NewJSONHandler(&js, nil)).Info("deploy", slog.Any("req", v))
		assert.NotContains(t, text.String(), keyCanary)
		assert.NotContains(t, js.String(), keyCanary)
		assert.Contains(t, text.String(), "redacted")
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(b), keyCanary)
	assert.NotContains(t, string(b), "PrivateKeyPEM", "the key field is not part of any JSON form")
}

func TestBackupRefJSON(t *testing.T) {
	id := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")
	b, err := json.Marshal(providers.BackupRef{OperationID: id, Dir: "/var/lib/alice-helper/backups/" + id.String()})
	require.NoError(t, err)
	assert.JSONEq(t, `{"operation_id":"0190f5a0-0000-7000-8000-0000000000aa","dir":"/var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-0000000000aa"}`, string(b))
}

// The framework mirrors the helper's vocabulary as strings (the package may not import
// helperproto); these tests pin every mirrored value to its source.
func TestMirroredPhasesStepsAndErrorsEqualTheHelperProtocol(t *testing.T) {
	assert.Equal(t, helperproto.PhaseNone, providers.PhaseNone)
	assert.Equal(t, helperproto.PhasePrepared, providers.PhasePrepared)
	assert.Equal(t, helperproto.PhaseWriting, providers.PhaseWriting)
	assert.Equal(t, helperproto.PhaseCommitted, providers.PhaseCommitted)
	assert.Equal(t, helperproto.PhaseUnchanged, providers.PhaseUnchanged)
	assert.Equal(t, helperproto.PhaseRestoring, providers.PhaseRestoring)
	assert.Equal(t, helperproto.PhaseRestored, providers.PhaseRestored)
	assert.Equal(t, helperproto.PhaseRestoreFailed, providers.PhaseRestoreFailed)

	assert.Equal(t, helperproto.StepBackup, providers.StepNameBackup)
	assert.Equal(t, helperproto.StepWriteKey, providers.StepNameWriteKey)
	assert.Equal(t, helperproto.StepWriteCert, providers.StepNameWriteCert)
	assert.Equal(t, helperproto.StepConfigTest, providers.StepNameConfigTest)
	assert.Equal(t, helperproto.StepReload, providers.StepNameReload)
	assert.Equal(t, helperproto.StepJournal, providers.StepNameJournal)
	assert.Equal(t, helperproto.StepRestore, providers.StepNameRestore)
	assert.Equal(t, helperproto.StepRollbackConfigTest, providers.StepNameRollbackConfigTest)
	assert.Equal(t, helperproto.StepRollbackReload, providers.StepNameRollbackReload)

	assert.Equal(t, helperproto.RestoreErrFileChanged, providers.DeployErrFileChanged)
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, providers.ConfigErrKeyMismatch)
	assert.Equal(t, helperproto.ConfigErrFileMissing, providers.ConfigErrFileMissing)
	assert.Equal(t, helperproto.ConfigErrCertLoad, providers.ConfigErrCertLoad)
	assert.Equal(t, helperproto.ConfigErrKeyLoad, providers.ConfigErrKeyLoad)
	assert.Equal(t, helperproto.ConfigErrSyntax, providers.ConfigErrSyntax)
	assert.Equal(t, helperproto.ConfigErrUntrusted, providers.ConfigErrUntrusted)
	assert.Equal(t, helperproto.ConfigErrUnsupported, providers.ConfigErrUnsupported)

	assert.Equal(t, helperproto.ConfigReasonNotRootControlled, providers.ConfigReasonNotRootControlled)
	assert.Equal(t, helperproto.ConfigReasonSpecialFS, providers.ConfigReasonSpecialFS)
	assert.Equal(t, helperproto.ConfigReasonMissing, providers.ConfigReasonMissing)
	assert.Equal(t, helperproto.ConfigReasonNotRegular, providers.ConfigReasonNotRegular)
	assert.Equal(t, helperproto.ConfigReasonChanged, providers.ConfigReasonChanged)
	assert.Equal(t, helperproto.ConfigReasonNameNotAllowed, providers.ConfigReasonNameNotAllowed)
	assert.Equal(t, helperproto.ConfigReasonUnexpectedText, providers.ConfigReasonUnexpectedText)
	assert.Equal(t, helperproto.ConfigReasonWrongFirstFile, providers.ConfigReasonWrongFirstFile)
	assert.Equal(t, helperproto.ConfigReasonDuplicateFile, providers.ConfigReasonDuplicateFile)
	assert.Equal(t, helperproto.ConfigReasonNoConfPath, providers.ConfigReasonNoConfPath)
	assert.Equal(t, helperproto.ConfigReasonTooLarge, providers.ConfigReasonTooLarge)
	assert.Equal(t, helperproto.ConfigReasonTooComplex, providers.ConfigReasonTooComplex)
	assert.Equal(t, helperproto.ConfigReasonIncludeLoop, providers.ConfigReasonIncludeLoop)
	assert.Equal(t, helperproto.ConfigReasonNULByte, providers.ConfigReasonNULByte)
}

func TestMirroredReasonsProblemsAndWarningsEqualTheirSources(t *testing.T) {
	assert.Equal(t, nginxconf.ReasonVariable, providers.UnsupportedVariable)
	assert.Equal(t, nginxconf.ReasonDataValue, providers.UnsupportedDataValue)
	assert.Equal(t, nginxconf.ReasonEngineKey, providers.UnsupportedEngineKey)
	assert.Equal(t, nginxconf.ReasonKeyMissing, providers.UnsupportedKeyMissing)
	assert.Equal(t, nginxconf.ReasonPasswordFile, providers.UnsupportedPasswordFile)
	assert.Equal(t, nginxconf.ReasonPathNotAllowed, providers.UnsupportedPathNotAllowed)
	assert.Equal(t, nginxconf.ReasonStream, providers.UnsupportedStream)
	assert.Equal(t, nginxconf.ReasonCombinedFile, providers.UnsupportedCombinedFile)
	assert.Equal(t, nginxconf.ReasonConfigFileWritable, providers.UnsupportedConfigFileWritable)

	assert.Equal(t, helperproto.FileMissing, providers.CertProblemMissing)
	assert.Equal(t, helperproto.FileNotRootControlled, providers.CertProblemNotRootControlled)
	assert.Equal(t, helperproto.FileNotRegular, providers.CertProblemNotRegular)
	assert.Equal(t, helperproto.FileHardLinked, providers.CertProblemHardLinked)
	assert.Equal(t, helperproto.FileTooLarge, providers.CertProblemTooLarge)
	assert.Equal(t, helperproto.FileNotACertificate, providers.CertProblemNotACertificate)
	assert.Equal(t, helperproto.FileLeafUnreadable, providers.CertProblemLeafUnreadable)
	assert.Equal(t, helperproto.FileUnreadable, providers.CertProblemUnreadable)
	assert.Equal(t, helperproto.FileBadName, providers.CertProblemBadName)
	assert.Equal(t, helperproto.FileSpecialFS, providers.CertProblemSpecialFS)
	assert.Equal(t, helperproto.FileNameNotAllowed, providers.CertProblemNameNotAllowed)

	assert.Equal(t, helperproto.WarnStreamTLS, providers.WarnStreamTLS)
	assert.Equal(t, helperproto.WarnMailTLS, providers.WarnMailTLS)
	assert.Equal(t, helperproto.WarnCertificateBlockDropped, providers.WarnCertificateBlockDropped)
	assert.Equal(t, helperproto.WarnKeyGroupOpen, providers.WarnKeyGroupOpen)
	assert.Equal(t, helperproto.WarnConfigFileWritable, providers.WarnConfigFileWritable)
}

func TestDeployResultsAreDistinct(t *testing.T) {
	seen := map[providers.DeployResult]bool{}
	for _, r := range []providers.DeployResult{providers.DeployCommitted, providers.DeployUnchanged,
		providers.DeployNoChange, providers.DeployRolledBack, providers.DeployRollbackFailed, providers.DeployUncertain} {
		assert.NotEmpty(t, r)
		assert.False(t, seen[r], r)
		seen[r] = true
	}
	assert.Equal(t, "uncertain", string(providers.DeployUncertain))
}

// holder keeps a request in an UNEXPORTED field: fmt cannot call methods on such a value, so it
// prints the fields by reflection.
type holder struct {
	req  providers.DeployRequest
	reqs []providers.DeployRequest
	ptr  *providers.DeployRequest
}

func TestKeyNeverPrintsThroughUnexportedFields(t *testing.T) {
	req := providers.DeployRequest{PrivateKeyPEM: secrets.NewPlaintext([]byte(keyCanary))}
	raw := []byte(keyCanary)
	needles := []string{
		keyCanary,
		fmt.Sprintf("%x", keyCanary),
		strings.Trim(fmt.Sprintf("%d", raw), "[]"),
		strings.ReplaceAll(strings.Trim(fmt.Sprintf("%d", raw), "[]"), " ", ","),
		base64.StdEncoding.EncodeToString([]byte(keyCanary)),
		base64.RawStdEncoding.EncodeToString([]byte(keyCanary)),
	}
	values := []any{
		holder{req: req, reqs: []providers.DeployRequest{req}, ptr: &req},
		&holder{req: req},
		struct{ r providers.DeployRequest }{req},
		struct{ k secrets.Plaintext }{req.PrivateKeyPEM},
		[]providers.DeployRequest{req},
		map[string]providers.DeployRequest{"a": req},
	}
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
			out := fmt.Sprintf(verb, v)
			for _, n := range needles {
				assert.NotContains(t, out, n, "%s of %T", verb, v)
			}
		}
	}
}

// stringConsts returns the string constants of a Go source file whose names start with a prefix,
// name -> value, so a value added to helperproto or nginxconf later is noticed.
func stringConsts(t *testing.T, file string, prefixes ...string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	require.NoError(t, err)
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				for _, p := range prefixes {
					if strings.HasPrefix(n.Name, p) {
						v, err := strconv.Unquote(lit.Value)
						require.NoError(t, err)
						out[n.Name] = v
					}
				}
			}
		}
	}
	return out
}

func valueSet(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func TestMirroredSetsAreCompleteAgainstTheirSources(t *testing.T) {
	hp := "linuxssh/helperproto/helperproto.go"
	assert.Equal(t, sortedCopy([]string{
		providers.ConfigReasonNotRootControlled, providers.ConfigReasonSpecialFS, providers.ConfigReasonMissing,
		providers.ConfigReasonNotRegular, providers.ConfigReasonChanged, providers.ConfigReasonNameNotAllowed,
		providers.ConfigReasonUnexpectedText, providers.ConfigReasonWrongFirstFile, providers.ConfigReasonDuplicateFile,
		providers.ConfigReasonNoConfPath, providers.ConfigReasonTooLarge, providers.ConfigReasonTooComplex,
		providers.ConfigReasonIncludeLoop, providers.ConfigReasonNULByte,
	}), valueSet(stringConsts(t, hp, "ConfigReason")), "config reasons")
	assert.Equal(t, sortedCopy([]string{
		providers.ConfigErrKeyMismatch, providers.ConfigErrFileMissing, providers.ConfigErrCertLoad, providers.ConfigErrKeyLoad,
		providers.ConfigErrSyntax, providers.ConfigErrUntrusted, providers.ConfigErrUnsupported,
	}), valueSet(stringConsts(t, hp, "ConfigErr")), "config error classes")
	assert.Equal(t, sortedCopy([]string{
		providers.CertProblemMissing, providers.CertProblemNotRootControlled, providers.CertProblemNotRegular,
		providers.CertProblemHardLinked, providers.CertProblemTooLarge, providers.CertProblemNotACertificate,
		providers.CertProblemUnreadable, providers.CertProblemBadName, providers.CertProblemSpecialFS, providers.CertProblemNameNotAllowed,
		providers.CertProblemLeafUnreadable,
	}), valueSet(stringConsts(t, hp, "File")), "file problems")
	assert.Equal(t, sortedCopy([]string{
		providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted,
		providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed, providers.PhaseFenced,
	}), valueSet(stringConsts(t, hp, "Phase")), "phases")
	assert.Equal(t, sortedCopy([]string{
		providers.StepNameBackup, providers.StepNameWriteKey, providers.StepNameWriteCert, providers.StepNameConfigTest,
		providers.StepNameReload, providers.StepNameJournal, providers.StepNameRestore,
		providers.StepNameRollbackConfigTest, providers.StepNameRollbackReload,
	}), valueSet(stringConsts(t, hp, "Step")), "helper steps")

	// The nginx-dump warnings; the first eight Warn* of helperproto belong to linuxssh (three are
	// Alice's for unlisted accounts, AUD-03).
	warns := stringConsts(t, hp, "Warn")
	for _, linux := range []string{"WarnSSHDUnreadable", "WarnDirectoryUsers", "WarnUnsupportedPath", "WarnTooManyUsers",
		"WarnAccountNameUnsupported", "WarnAccountHomeUnsupported", "WarnAccountIDUnsupported", "WarnAccountsNUL"} {
		delete(warns, linux)
	}
	assert.Equal(t, sortedCopy([]string{
		providers.WarnStreamTLS, providers.WarnMailTLS, providers.WarnConfigFileWritable, providers.WarnTooManyFiles,
		providers.WarnCertificateBlockDropped, providers.WarnKeyGroupOpen,
	}), valueSet(warns), "nginx-dump warnings")

	reasons := stringConsts(t, "nginx/nginxconf/nginxconf.go", "Reason")
	assert.Equal(t, sortedCopy([]string{
		providers.UnsupportedVariable, providers.UnsupportedDataValue, providers.UnsupportedEngineKey,
		providers.UnsupportedKeyMissing, providers.UnsupportedPasswordFile, providers.UnsupportedPathNotAllowed,
		providers.UnsupportedStream, providers.UnsupportedCombinedFile,
	}), valueSet(reasons), "nginxconf reasons (ReasonConfigFileWritable is an alias of a helperproto value and is not a literal)")
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestHTTP01IsAKnownCapability(t *testing.T) {
	assert.Equal(t, providers.Capability("http01_challenge"), providers.CapHTTP01)
	reg := providers.NewRegistry()
	assert.NotPanics(t, func() { reg.Register(fake.New(providers.KindNginx, providers.CapHTTP01)) })
}

func TestKeyLoginIsAKnownCapabilityAndUnsupportedByDefault(t *testing.T) {
	assert.True(t, providers.NewCapabilitySet(providers.CapKeyLogin).Has(providers.CapKeyLogin))
	_, err := providers.UnsupportedSession{}.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	for _, o := range []providers.KeyLoginOutcome{providers.KeyLoginAccepted, providers.KeyLoginRefused, providers.KeyLoginUnprovable} {
		assert.NotEmpty(t, string(o))
	}
}

// Follow-up 2: a listing states its own coverage; absence proves nothing without it.
func TestKeyListingAbsenceNeedsCompleteCoverage(t *testing.T) {
	const f = "/home/deploy/.ssh/authorized_keys"
	l := providers.KeyListing{
		Keys: []providers.DiscoveredSSHKey{{OSUser: "deploy", FilePath: f, Fingerprint: "SHA256:held"}},
		Files: []providers.FileCoverage{
			{OSUser: "deploy", FilePath: f, State: providers.CoverageComplete},
			{OSUser: "deploy", FilePath: "/u", State: providers.CoverageUnread},
			{OSUser: "deploy", FilePath: "/p", State: providers.CoveragePartial},
		},
	}
	assert.Equal(t, providers.CoverageComplete, l.Coverage("deploy", f))
	assert.Equal(t, providers.CoverageUnread, l.Coverage("deploy", "/u"))
	assert.Equal(t, providers.CoveragePartial, l.Coverage("deploy", "/p"))
	assert.Equal(t, providers.CoverageUnknown, l.Coverage("deploy", "/never"))
	assert.Equal(t, providers.CoverageUnknown, l.Coverage("other", f), "coverage is per user and file")

	assert.True(t, l.Absent("deploy", f, "SHA256:other"), "read completely, not there")
	assert.False(t, l.Absent("deploy", f, "SHA256:held"), "there")
	for _, file := range []string{"/u", "/p", "/never"} {
		assert.False(t, l.Absent("deploy", file, "SHA256:other"), "no proof of absence from %s", file)
	}
	assert.False(t, l.Absent("other", f, "SHA256:other"))
	assert.False(t, providers.KeyListing{}.Absent("deploy", f, "SHA256:x"), "an empty listing proves nothing")

	_, err := providers.UnsupportedSession{}.ListKeys(context.Background())
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	for _, s := range []providers.CoverageState{providers.CoverageComplete, providers.CoverageUnread, providers.CoveragePartial, providers.CoverageUnknown} {
		assert.NotEmpty(t, string(s))
	}
}
