// Package providertest holds the conformance checks every provider runs (spec §6.5 item 5).
// It uses only testing.TB, so it never pulls test libraries into a build that imports it.
package providertest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// CheckProvider verifies the static contract: kind, display name, capabilities, schemas that a
// registry accepts, and that ValidateConfig reports every required field of an empty config.
func CheckProvider(t testing.TB, p providers.Provider) {
	t.Helper()
	if p.Kind() == "" {
		t.Errorf("provider has no kind")
	}
	if p.DisplayNameKey() == "" {
		t.Errorf("%s: no display name key", p.Kind())
	}
	if len(p.Capabilities()) == 0 {
		t.Errorf("%s: no capabilities", p.Kind())
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: a registry refuses it: %v", p.Kind(), r)
			}
		}()
		providers.NewRegistry().Register(p)
	}()
	reported := map[string]bool{}
	for _, fe := range p.ValidateConfig(providers.TargetConfig{}) {
		if fe.Code == validate.Required {
			reported[fe.Field] = true
		}
	}
	for _, f := range p.ConfigSchema().Fields {
		if f.Required && f.Default == nil && !reported[f.Name] {
			t.Errorf("%s: an empty config does not report the required field %q", p.Kind(), f.Name)
		}
	}
}

// CheckUnsupported verifies that every operation of a capability the provider does not
// advertise answers ErrUnsupported (spec §6.1), so the job layer can rely on Capabilities().
func CheckUnsupported(t testing.TB, s providers.Session, caps providers.CapabilitySet) {
	t.Helper()
	ctx := context.Background()
	expect := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, providers.ErrUnsupported) {
			t.Errorf("%s without its capability: got %v, want ErrUnsupported", name, err)
		}
	}
	if !caps.Has(providers.CapTestConnection) {
		_, err := s.TestConnection(ctx)
		expect("TestConnection", err)
	}
	if !caps.Has(providers.CapDiscoverSSHKeys) && !caps.Has(providers.CapDiscoverCerts) {
		// One call: a provider with neither discovery capability must refuse a request for both.
		_, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true, Certificates: true})
		expect("Discover", err)
	}
	if !caps.Has(providers.CapDeployCertificate) {
		_, err := s.DeployCertificate(ctx, providers.DeployRequest{}, nil)
		expect("DeployCertificate", err)
		_, err = s.RollbackDeployment(ctx, providers.RollbackRequest{}, nil)
		expect("RollbackDeployment", err)
		_, err = s.DeploymentStatus(ctx, uuid.New())
		expect("DeploymentStatus", err)
		_, err = s.FenceDeployment(ctx, uuid.New())
		expect("FenceDeployment", err)
	}
	if !caps.Has(providers.CapVerifyDeployment) {
		_, err := s.VerifyDeployment(ctx, providers.VerifyRequest{})
		expect("VerifyDeployment", err)
	}
	if !caps.Has(providers.CapAuthorizedKeys) {
		_, err := s.ListAuthorizedKeys(ctx)
		expect("ListAuthorizedKeys", err)
		_, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
		expect("AddAuthorizedKey", err)
		_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
		expect("RemoveAuthorizedKey", err)
	}
}

// SessionHarness opens sessions of one provider against a working counterpart (a fake server,
// a container) for CheckSession.
type SessionHarness struct {
	// Capabilities is what the provider advertises.
	Capabilities providers.CapabilitySet
	// Open opens a fresh session; ctx is the context Provider.Open receives.
	Open func(ctx context.Context) (providers.Session, error)
	// Secrets must never appear in any result, error, JSON or log line (private key material,
	// a canary planted in the credential).
	Secrets []string
	// CancelBound is how long a call with a cancelled context may take (default 5 s).
	CancelBound time.Duration
}

type sessionOp struct {
	name string
	cap  providers.Capability
	call func(ctx context.Context, s providers.Session) (any, error)
}

// CheckDeployOutcome reports a DeployCertificate result that breaks the provider contract
// (providers.CheckDeployReturn: Validate, and how the error relates to the Result). A provider
// runs it on every outcome its own deploy tests produce.
func CheckDeployOutcome(t testing.TB, out providers.DeployOutcome, err error) {
	t.Helper()
	if cerr := providers.CheckDeployReturn(out, err); cerr != nil {
		t.Errorf("DeployCertificate: %v", cerr)
	}
}

// CheckRollbackOutcome is CheckDeployOutcome for RollbackDeployment.
func CheckRollbackOutcome(t testing.TB, out providers.RollbackOutcome, err error) {
	t.Helper()
	if cerr := providers.CheckRollbackReturn(out, err); cerr != nil {
		t.Errorf("RollbackDeployment: %v", cerr)
	}
}

// CheckDeploymentState reports a DeploymentStatus answer (returned with a nil err) that fails
// DeploymentState.Validate.
func CheckDeploymentState(t testing.TB, st providers.DeploymentState, err error) {
	t.Helper()
	if err != nil {
		return
	}
	if verr := st.Validate(); verr != nil {
		t.Errorf("DeploymentStatus returned an invalid result: %v", verr)
	}
}

var sessionOps = []sessionOp{
	{"TestConnection", providers.CapTestConnection, func(ctx context.Context, s providers.Session) (any, error) {
		return s.TestConnection(ctx)
	}},
	{"Discover", providers.CapDiscoverSSHKeys, func(ctx context.Context, s providers.Session) (any, error) {
		return s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	}},
	{"DiscoverCertificates", providers.CapDiscoverCerts, func(ctx context.Context, s providers.Session) (any, error) {
		return s.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	}},
	{"ListAuthorizedKeys", providers.CapAuthorizedKeys, func(ctx context.Context, s providers.Session) (any, error) {
		return s.ListAuthorizedKeys(ctx)
	}},
	{"AddAuthorizedKey", providers.CapAuthorizedKeys, func(ctx context.Context, s providers.Session) (any, error) {
		return s.AddAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	}},
	{"RemoveAuthorizedKey", providers.CapAuthorizedKeys, func(ctx context.Context, s providers.Session) (any, error) {
		return s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{}, nil)
	}},
	// DeployCertificate and RollbackDeployment change servers and cannot be called against a
	// real counterpart here: only the read-only DeploymentStatus is. See CheckSession.
	{"DeploymentStatus", providers.CapDeployCertificate, func(ctx context.Context, s providers.Session) (any, error) {
		return s.DeploymentStatus(ctx, uuid.New())
	}},
	{"VerifyDeployment", providers.CapVerifyDeployment, func(ctx context.Context, s providers.Session) (any, error) {
		return s.VerifyDeployment(ctx, providers.VerifyRequest{})
	}},
}

// CheckSession runs the session conformance checks of spec §6.5 item 5 against a live
// counterpart. It cannot call DeployCertificate or RollbackDeployment (they change servers), so
// for CapDeployCertificate it calls only the read-only DeploymentStatus and validates its answer.
// A provider that advertises CapDeployCertificate must therefore carry its own test that
// DeployCertificate and RollbackDeployment do not return ErrUnsupported, and run CheckDeployOutcome
// and CheckRollbackOutcome on every outcome those tests produce.
//
// The checks: every advertised capability's methods are implemented (never ErrUnsupported) and
// return only *providers.Error; the others answer ErrUnsupported (CheckUnsupported); Open and
// every advertised method honour a cancelled context promptly with an error that wraps
// context.Canceled; and no secret appears in any result or error, however it is rendered.
func CheckSession(t testing.TB, h SessionHarness) {
	t.Helper()
	bound := h.CancelBound
	if bound <= 0 {
		bound = 5 * time.Second
	}
	var seen []any
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	var openErr error
	if !within(bound, func() {
		s, err := h.Open(cancelled)
		if err == nil {
			_ = s.Close()
		}
		openErr = err
	}) {
		t.Errorf("Open with a cancelled context did not return within %s", bound)
	} else {
		checkCancelled(t, "Open", openErr)
		seen = append(seen, openErr)
	}

	for _, op := range sessionOps {
		if !h.Capabilities.Has(op.cap) {
			continue
		}
		s, err := h.Open(context.Background())
		if err != nil {
			t.Errorf("Open: %v", err)
			return
		}
		out, err := op.call(context.Background(), s)
		_ = s.Close()
		seen = append(seen, out, err)
		if st, ok := out.(providers.DeploymentState); ok {
			CheckDeploymentState(t, st, err)
		}
		switch {
		case errors.Is(err, providers.ErrUnsupported):
			t.Errorf("%s answers ErrUnsupported although %s is advertised", op.name, op.cap)
		case err != nil && !isProviderError(err):
			t.Errorf("%s returned %T, want *providers.Error", op.name, err)
		}

		s, err = h.Open(context.Background())
		if err != nil {
			t.Errorf("Open: %v", err)
			return
		}
		var cerr error
		if !within(bound, func() { out, cerr = op.call(cancelled, s) }) {
			t.Errorf("%s with a cancelled context did not return within %s", op.name, bound)
		} else {
			checkCancelled(t, op.name, cerr)
			seen = append(seen, out, cerr)
		}
		_ = s.Close()
	}

	s, err := h.Open(context.Background())
	if err != nil {
		t.Errorf("Open: %v", err)
		return
	}
	CheckUnsupported(t, s, h.Capabilities)
	_ = s.Close()
	CheckNoSecrets(t, h.Secrets, seen...)
}

func isProviderError(err error) bool {
	var pe *providers.Error
	return errors.As(err, &pe)
}

func checkCancelled(t testing.TB, name string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s with a cancelled context succeeded", name)
	case !errors.Is(err, context.Canceled):
		t.Errorf("%s with a cancelled context: got %v, want an error wrapping context.Canceled", name, err)
	case !isProviderError(err):
		t.Errorf("%s with a cancelled context returned %T, want *providers.Error", name, err)
	}
}

// within runs fn and reports whether it returned within d (fn keeps running otherwise).
func within(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// CheckNoSecrets fails when a secret appears in any value as JSON, as %+v, as an error message
// or as a structured log line. For an error, every error in its Unwrap chain is rendered too: a
// cause may reach a log through a wrapper the provider does not control.
func CheckNoSecrets(t testing.TB, secrets []string, values ...any) {
	t.Helper()
	for _, v := range values {
		if v == nil {
			continue
		}
		var texts []string
		if err, ok := v.(error); ok {
			for _, e := range chain(err) {
				texts = append(texts, renderings(e)...)
			}
		} else {
			texts = renderings(v)
		}
		if leaks(texts, secrets) {
			t.Errorf("a secret appears in the output of %T", v)
		}
	}
}

// chain returns err and every error it wraps (Unwrap() error and Unwrap() []error), depth first.
func chain(err error) []error {
	var out []error
	var walk func(error, int)
	walk = func(e error, depth int) {
		if e == nil || depth > 32 {
			return
		}
		out = append(out, e)
		switch u := e.(type) { //nolint:errorlint // walking the chain by hand, one level at a time
		case interface{ Unwrap() error }:
			walk(u.Unwrap(), depth+1)
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x, depth+1)
			}
		}
	}
	walk(err, 0)
	return out
}

func leaks(texts, secrets []string) bool {
	for _, text := range texts {
		for _, s := range secrets {
			if s != "" && strings.Contains(text, s) {
				return true
			}
		}
	}
	return false
}

func renderings(v any) []string {
	var out []string
	if b, err := json.Marshal(v); err == nil {
		out = append(out, string(b))
	}
	out = append(out, fmt.Sprintf("%+v", v))
	if err, ok := v.(error); ok {
		out = append(out, err.Error())
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("check", slog.Any("value", v))
	return append(out, buf.String())
}
