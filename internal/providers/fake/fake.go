// Package fake is an in-memory provider for inventory and job tests. Behaviour is scripted with
// Configure; every call is recorded. Open follows the pinning rules of the real linuxssh dialer.
package fake

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// Call is one recorded method call.
type Call struct {
	Method string // "Open", "TestConnection", "Discover", "ListAuthorizedKeys", "AddAuthorizedKey", "RemoveAuthorizedKey", "DeployCertificate", "RollbackDeployment", "DeploymentStatus", "VerifyDeployment", "Close"
	Target uuid.UUID
	Change providers.AuthKeyChange // Add/Remove only
	// Deploy is the DeployCertificate request with PrivateKeyPEM replaced by an empty value: the
	// fake never keeps a key.
	Deploy providers.DeployRequest
	// Rollback and Verify are the RollbackDeployment and VerifyDeployment requests.
	Rollback providers.RollbackRequest
	Verify   providers.VerifyRequest
	// Op is the operation id of DeployCertificate, RollbackDeployment and DeploymentStatus.
	Op uuid.UUID
}

// Config is the scripted behaviour.
type Config struct {
	OpenErr          error
	SkipHostKeyCheck bool              // Open does not consult env.HostKeys
	PresentedKey     providers.HostKey // the key "the server" presents; "" fingerprint = do not check
	Report           providers.ConnectionReport
	TestErr          error
	Discovery        providers.DiscoveryResult
	DiscoverErr      error
	Keys             []providers.DiscoveredSSHKey
	ListErr          error
	AddResult        providers.AuthKeyResult
	AddErr           error
	RemoveResult     providers.AuthKeyResult
	RemoveErr        error

	// Deploy decides the outcome of DeployCertificate; nil = committed, verified "remote". To
	// simulate each outcome return DeployNoChange (a refusal), DeployUnchanged, DeployRolledBack,
	// DeployRollbackFailed, or DeployUncertain together with an error.
	Deploy func(req providers.DeployRequest) (providers.DeployOutcome, error)
	// Rollback decides the outcome of RollbackDeployment; nil = rolled back.
	Rollback func(req providers.RollbackRequest) (providers.RollbackOutcome, error)
	// Verify decides VerifyDeployment; nil = OK, Served = req.Fingerprint, ServedChainLength =
	// req.ChainLength.
	Verify func(req providers.VerifyRequest) (providers.VerifyResult, error)
	// Status decides DeploymentStatus; nil = phase none.
	Status func(op uuid.UUID) (providers.DeploymentState, error)
	// DeploySteps, when non-nil (an empty slice included), are exactly the steps DeployCertificate
	// reports (status ok) to its logger, whatever Deploy returns. When nil: with Deploy set, the
	// steps of the outcome Deploy returns (with their statuses); on the default committed path,
	// the five helper steps and verify. The default six never accompany a scripted outcome.
	DeploySteps []string
}

var defaultDeploySteps = []string{
	providers.StepNameBackup, providers.StepNameWriteKey, providers.StepNameWriteCert,
	providers.StepNameConfigTest, providers.StepNameReload, providers.StepNameVerify,
}

// Provider is the scriptable provider.
type Provider struct {
	kind  providers.Kind
	caps  providers.CapabilitySet
	mu    sync.Mutex
	cfg   Config
	calls []Call
}

// New returns a fake of kind with caps (test_connection, discover_ssh_keys and authorized_keys
// when none are given).
func New(kind providers.Kind, caps ...providers.Capability) *Provider {
	if len(caps) == 0 {
		caps = []providers.Capability{providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys}
	}
	return &Provider{kind: kind, caps: providers.NewCapabilitySet(caps...)}
}

// Configure changes the scripted behaviour under the lock.
func (p *Provider) Configure(fn func(c *Config)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(&p.cfg)
}

// Calls returns a copy of the recorded calls.
func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := slices.Clone(p.calls)
	for i := range out {
		out[i] = cloneCall(out[i])
	}
	return out
}

// Count returns how many calls of method were recorded.
func (p *Provider) Count(method string) int {
	n := 0
	for _, c := range p.Calls() {
		if c.Method == method {
			n++
		}
	}
	return n
}

func (p *Provider) record(c Call) Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, cloneCall(c))
	return p.cfg.clone()
}

func cloneCall(c Call) Call {
	c.Change.ProtectedFingerprints = slices.Clone(c.Change.ProtectedFingerprints)
	c.Deploy.Location = cloneLocation(c.Deploy.Location)
	c.Deploy.CertificatePEM = slices.Clone(c.Deploy.CertificatePEM)
	c.Deploy.SANs = slices.Clone(c.Deploy.SANs)
	c.Deploy.OldSANs = slices.Clone(c.Deploy.OldSANs)
	c.Rollback.Location = cloneLocation(c.Rollback.Location)
	c.Rollback.OldSANs = slices.Clone(c.Rollback.OldSANs)
	c.Verify.Location = cloneLocation(c.Verify.Location)
	c.Verify.SANs = slices.Clone(c.Verify.SANs)
	return c
}

func cloneLocation(l providers.CertLocation) providers.CertLocation {
	l.Warnings = slices.Clone(l.Warnings)
	servers := make([]providers.CertServer, len(l.Servers))
	for i, sv := range l.Servers {
		sv.Names = slices.Clone(sv.Names)
		sv.Listens = slices.Clone(sv.Listens)
		servers[i] = sv
	}
	if l.Servers == nil {
		servers = nil
	}
	l.Servers = servers
	return l
}

// clone copies the slices so a caller of the returned Config cannot race with Configure.
func (c Config) clone() Config {
	c.Keys = slices.Clone(c.Keys)
	c.Discovery.SSHKeys = slices.Clone(c.Discovery.SSHKeys)
	c.Discovery.HostKeys = slices.Clone(c.Discovery.HostKeys)
	c.Discovery.UnreadableLines = slices.Clone(c.Discovery.UnreadableLines)
	c.Discovery.Warnings = slices.Clone(c.Discovery.Warnings)
	c.Discovery.ReadFiles = slices.Clone(c.Discovery.ReadFiles)
	c.Report.Warnings = slices.Clone(c.Report.Warnings)
	if c.Report.Nginx != nil {
		n := *c.Report.Nginx
		c.Report.Nginx = &n
	}
	if c.Discovery.Nginx != nil {
		n := *c.Discovery.Nginx
		c.Discovery.Nginx = &n
	}
	if c.Discovery.Certificates != nil {
		certs := make([]providers.DiscoveredCertificate, len(c.Discovery.Certificates))
		for i, dc := range c.Discovery.Certificates {
			dc.Location = cloneLocation(dc.Location)
			dc.PEMChain = slices.Clone(dc.PEMChain)
			certs[i] = dc
		}
		c.Discovery.Certificates = certs
	}
	c.Discovery.UID0Users = slices.Clone(c.Discovery.UID0Users)
	c.Discovery.Accounts = slices.Clone(c.Discovery.Accounts)
	c.DeploySteps = slices.Clone(c.DeploySteps)
	return c
}

// Kind implements providers.Provider.
func (p *Provider) Kind() providers.Kind { return p.kind }

// DisplayNameKey implements providers.Provider.
func (p *Provider) DisplayNameKey() string { return "provider.fake.name" }

// Capabilities implements providers.Provider.
func (p *Provider) Capabilities() providers.CapabilitySet { return p.caps.Clone() }

// ConfigSchema implements providers.Provider.
func (p *Provider) ConfigSchema() providers.ConfigSchema {
	return providers.ConfigSchema{Fields: []providers.Field{
		{Name: "host", Type: providers.FieldHost, Required: true, LabelKey: "provider.fake.fields.host.label"},
		{Name: "port", Type: providers.FieldInt, Min: 1, Max: 65535, Default: 22, LabelKey: "provider.fake.fields.port.label"},
		{Name: "username", Type: providers.FieldString, Default: "alice-svc", LabelKey: "provider.fake.fields.username.label"},
	}}
}

// CredentialSchema implements providers.Provider.
func (p *Provider) CredentialSchema() providers.CredentialSchema { return providers.CredentialSchema{} }

// ValidateConfig implements providers.Provider: only host is required.
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError {
	if h, _ := cfg["host"].(string); h == "" {
		return []validate.FieldError{{Field: "host", Code: validate.Required}}
	}
	return nil
}

// Open implements providers.Provider with the pinning rules of the real dialer.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	cfg := p.record(Call{Method: "Open", Target: t.ID})
	if cfg.OpenErr != nil {
		return nil, cfg.OpenErr
	}
	presented := cfg.PresentedKey
	if !cfg.SkipHostKeyCheck && env.HostKeys != nil && presented.Fingerprint != "" {
		pinned, err := env.HostKeys.Pinned(ctx, t.ID)
		switch {
		case errors.Is(err, providers.ErrNoPinnedKey):
			if err := env.HostKeys.Observed(ctx, t.ID, presented, false); err != nil {
				return nil, providers.NewError("target.hostkey_store", true, err, nil)
			}
			return nil, providers.NewError("target.host_key_unconfirmed", false, nil, map[string]string{"fingerprint": presented.Fingerprint})
		case err != nil:
			return nil, providers.NewError("target.hostkey_store", true, err, nil)
		case pinned.Fingerprint != presented.Fingerprint:
			if err := env.HostKeys.Observed(ctx, t.ID, presented, true); err != nil {
				return nil, providers.NewError("target.hostkey_store", true, err, nil)
			}
			return nil, providers.NewError("target.host_key_changed", false, nil,
				map[string]string{"old_fingerprint": pinned.Fingerprint, "new_fingerprint": presented.Fingerprint})
		}
	}
	if cred != nil {
		_, release, err := cred.SSHSigner(ctx)
		if err != nil {
			return nil, providers.NewError("ssh.credential", false, err, nil)
		}
		release()
	}
	return &session{p: p, target: t.ID}, nil
}

type session struct {
	p      *Provider
	target uuid.UUID
}

func (s *session) Close() error {
	s.p.record(Call{Method: "Close", Target: s.target})
	return nil
}

func (s *session) TestConnection(context.Context) (providers.ConnectionReport, error) {
	cfg := s.p.record(Call{Method: "TestConnection", Target: s.target})
	if !s.p.caps.Has(providers.CapTestConnection) {
		return providers.ConnectionReport{}, providers.ErrUnsupported
	}
	rep := cfg.Report
	if rep.HostKey.Fingerprint == "" {
		rep.HostKey = cfg.PresentedKey
	}
	return rep, cfg.TestErr
}

func (s *session) Discover(_ context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	cfg := s.p.record(Call{Method: "Discover", Target: s.target})
	if !s.p.caps.Has(providers.CapDiscoverSSHKeys) && !s.p.caps.Has(providers.CapDiscoverCerts) {
		return providers.DiscoveryResult{}, providers.ErrUnsupported
	}
	res := cfg.Discovery
	if !req.SSHKeys {
		res.SSHKeys, res.HostKeys, res.SSHD, res.UnreadableLines = nil, nil, providers.SSHDSummary{}, nil
		res.UID0Users, res.Accounts, res.AccountsComplete, res.ReadFiles = nil, nil, false, nil
	}
	if !req.Certificates {
		res.Certificates, res.Nginx = nil, nil
	}
	return res, cfg.DiscoverErr
}

func (s *session) ListAuthorizedKeys(context.Context) ([]providers.DiscoveredSSHKey, error) {
	cfg := s.p.record(Call{Method: "ListAuthorizedKeys", Target: s.target})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return nil, providers.ErrUnsupported
	}
	return cfg.Keys, cfg.ListErr
}

func (s *session) AddAuthorizedKey(_ context.Context, req providers.AuthKeyChange, _ providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "AddAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	return cfg.AddResult, cfg.AddErr
}

func (s *session) RemoveAuthorizedKey(_ context.Context, req providers.AuthKeyChange, _ providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "RemoveAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	return cfg.RemoveResult, cfg.RemoveErr
}

// mustHonour panics when a scripted result breaks the provider contract: that is a mistake of the
// test that scripted it, and failing loudly beats an engine test that passes on a bogus shape.
func mustHonour(method string, err error) {
	if err != nil {
		panic("fake: scripted " + method + " result breaks the provider contract: " + err.Error())
	}
}

func (s *session) DeployCertificate(_ context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	kept := req
	kept.PrivateKeyPEM = providers.DeployRequest{}.PrivateKeyPEM // the zero value: the fake never keeps a key
	cfg := s.p.record(Call{Method: "DeployCertificate", Target: s.target, Deploy: kept, Op: req.OperationID})
	if !s.p.caps.Has(providers.CapDeployCertificate) {
		return providers.DeployOutcome{}, providers.ErrUnsupported
	}
	var out providers.DeployOutcome
	var err error
	if cfg.Deploy != nil {
		out, err = cfg.Deploy(req)
	} else {
		names := defaultDeploySteps
		if cfg.DeploySteps != nil {
			names = cfg.DeploySteps
		}
		out = providers.DeployOutcome{
			Result: providers.DeployCommitted, Phase: providers.PhaseCommitted,
			Verified: "remote", Backup: providers.BackupRef{OperationID: req.OperationID},
		}
		for _, n := range names {
			out.Steps = append(out.Steps, providers.DeployStep{Name: n, Status: providers.StepOK})
		}
	}
	mustHonour("DeployCertificate", providers.CheckDeployReturn(out, err))
	if log != nil {
		reported := out.Steps
		if cfg.DeploySteps != nil && cfg.Deploy != nil {
			reported = nil
			for _, n := range cfg.DeploySteps {
				reported = append(reported, providers.DeployStep{Name: n, Status: providers.StepOK})
			}
		}
		for _, st := range reported {
			log.Step(st.Name, st.Status, nil)
		}
	}
	return out, err
}

func (s *session) RollbackDeployment(_ context.Context, req providers.RollbackRequest, _ providers.StepLogger) (providers.RollbackOutcome, error) {
	cfg := s.p.record(Call{Method: "RollbackDeployment", Target: s.target, Rollback: req, Op: req.OperationID})
	if !s.p.caps.Has(providers.CapDeployCertificate) {
		return providers.RollbackOutcome{}, providers.ErrUnsupported
	}
	out := providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"}
	var err error
	if cfg.Rollback != nil {
		out, err = cfg.Rollback(req)
	}
	mustHonour("RollbackDeployment", providers.CheckRollbackReturn(out, err))
	return out, err
}

func (s *session) VerifyDeployment(_ context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	cfg := s.p.record(Call{Method: "VerifyDeployment", Target: s.target, Verify: req})
	if !s.p.caps.Has(providers.CapVerifyDeployment) {
		return providers.VerifyResult{}, providers.ErrUnsupported
	}
	if cfg.Verify != nil {
		return cfg.Verify(req)
	}
	return providers.VerifyResult{OK: true, Mode: "remote", Served: req.Fingerprint, ServedChainLength: req.ChainLength}, nil
}

func (s *session) DeploymentStatus(_ context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	cfg := s.p.record(Call{Method: "DeploymentStatus", Target: s.target, Op: op})
	if !s.p.caps.Has(providers.CapDeployCertificate) {
		return providers.DeploymentState{}, providers.ErrUnsupported
	}
	st := providers.DeploymentState{Phase: providers.PhaseNone}
	var err error
	if cfg.Status != nil {
		st, err = cfg.Status(op)
	}
	if err == nil {
		mustHonour("DeploymentStatus", st.Validate())
	}
	return st, err
}

var (
	_ providers.Provider = (*Provider)(nil)
	_ providers.Session  = (*session)(nil)
)
