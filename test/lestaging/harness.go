package lestaging

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/http01"
	"alice/internal/acme/transport"
	"alice/internal/platform/clock"
)

// The steps, in order.
const (
	StepPreflight = "preflight"
	StepDirectory = "directory"
	StepRoots     = "roots"
	StepAccount   = "account"
	StepLeftovers = "leftovers"
	StepOrder     = "order"
	StepChain     = "chain"
	StepARI       = "ari"
	StepRenewal   = "renewal"
	StepRevoke    = "revoke"
	StepCleanup   = "cleanup"
)

// Steps lists every step in the order they run.
func Steps() []string {
	return []string{StepPreflight, StepDirectory, StepRoots, StepAccount, StepLeftovers, StepOrder, StepChain, StepARI,
		StepRenewal, StepRevoke, StepCleanup}
}

// The outcomes of a step.
const (
	Pass = "PASS"
	Fail = "FAIL"
	Skip = "SKIP"
	Warn = "WARN"
)

// Result is one step's outcome.
type Result struct {
	Step, Status, Detail string
	Took                 time.Duration
}

// Report is a run's outcome.
type Report struct {
	Results []Result
}

// OK says no step failed.
func (r *Report) OK() bool {
	for _, x := range r.Results {
		if x.Status == Fail {
			return false
		}
	}
	return true
}

// Status is the outcome of one step ("" when it did not run).
func (r *Report) Status(step string) string {
	for _, x := range r.Results {
		if x.Step == step {
			return x.Status
		}
	}
	return ""
}

// Summary is the last line of a report.
func (r *Report) Summary() string {
	n := map[string]int{}
	for _, x := range r.Results {
		n[x.Status]++
	}
	verdict := Pass
	if !r.OK() {
		verdict = Fail
	}
	return fmt.Sprintf("RESULT: %s (%d passed, %d failed, %d warnings, %d skipped)", verdict, n[Pass], n[Fail], n[Warn], n[Skip])
}

// Runner runs the harness once.
type Runner struct {
	cfg Config
	out io.Writer
	now func() time.Time

	acmeHTTP  *http.Client // the guarded ACME transport
	rootsHTTP *http.Client // for the staging roots (same transport, system roots)

	// Test seams: the HTTP-01 solver's own check (http01.SetTestTarget in the integration tests) and the local
	// listener's address.
	http01Seam func(*http01.Solver)
	onListen   func(addr string)

	rep    *Report
	st     *state
	client *acme.Client
	dir    acme.Directory
	roots  []*x509.Certificate
	acct   acme.Account

	mu        sync.Mutex
	presented []solver.Challenge
	cleaned   int
	cleanErrs int
}

// NewRunner builds the run; it contacts nothing. out receives the live report.
func NewRunner(cfg Config, out io.Writer) (*Runner, error) {
	hc, err := transport.New(cfg.CABundlePEM)
	if err != nil {
		return nil, fmt.Errorf("lestaging: %s: %w", EnvCAFile, err)
	}
	rc, err := transport.New("")
	if err != nil {
		return nil, err
	}
	return &Runner{cfg: cfg, out: out, now: clock.Real{}.Now, acmeHTTP: hc, rootsHTTP: rc}, nil
}

func (r *Runner) record(step, status, detail string, start time.Time) {
	res := Result{Step: step, Status: status, Detail: detail, Took: r.now().Sub(start).Round(time.Millisecond)}
	r.rep.Results = append(r.rep.Results, res)
	_, _ = fmt.Fprintf(r.out, "[%s] %-10s %s", status, step, detail)
	if res.Took >= time.Second {
		_, _ = fmt.Fprintf(r.out, " (%s)", res.Took.Round(100*time.Millisecond))
	}
	_, _ = fmt.Fprintln(r.out)
}

func (r *Runner) skip(why string, steps ...string) {
	for _, s := range steps {
		r.record(s, Skip, why, r.now())
	}
}

// Run runs every step and returns the report (also printed to out as it goes).
func (r *Runner) Run(ctx context.Context) *Report {
	r.rep = &Report{}
	_, _ = fmt.Fprintf(r.out, "Let's Encrypt staging acceptance: %s, %s, names %s\n", r.cfg.DirectoryURL, r.cfg.Challenge,
		strings.Join(r.cfg.Names(), " "))
	r.run(ctx)
	_, _ = fmt.Fprintln(r.out, r.rep.Summary())
	return r.rep
}

func (r *Runner) run(ctx context.Context) {
	rest := Steps()[1:]
	start := r.now()
	if !r.preflight(start) {
		r.skip("preflight failed", rest...)
		return
	}
	if !r.directory(ctx) {
		r.skip("the directory could not be read", rest[1:]...)
		return
	}
	if !r.loadRoots(ctx) {
		r.skip("no roots to verify chains against", rest[2:]...)
		return
	}
	if !r.account(ctx) {
		r.skip("no account", rest[3:]...)
		return
	}
	if !r.leftovers(ctx) && r.rateLimited() {
		r.skip("the CA rate-limited the run", rest[4:]...)
		return
	}

	first := r.order(ctx)
	var leaf *x509.Certificate
	if first == nil {
		r.skip("no certificate was issued", StepChain, StepARI, StepRenewal)
	} else {
		leaf = r.chain(first)
		if leaf == nil {
			r.skip("the chain did not verify", StepARI, StepRenewal)
		} else {
			r.ari(ctx, first)
			r.renewal(ctx, first)
		}
	}
	if r.rateLimited() {
		r.skip("the CA rate-limited the run; the next run revokes what is left", StepRevoke)
	} else {
		r.revoke(ctx)
	}
	r.cleanup(ctx)
}

// rateLimited says the CA asked to wait.
func (r *Runner) rateLimited() bool { return r.st != nil && r.st.CANotBefore.After(r.now()) }

// fail records a step's failure; a rate limit stores the CA's time so that no run asks before it.
func (r *Runner) fail(step string, err error, start time.Time) {
	detail := err.Error()
	if acme.ReasonOf(err) == acme.ReasonCARateLimited {
		var e *acme.Error
		wait := time.Hour // the CA gave no Retry-After: an hour, the shortest staging limit window that matters
		if errors.As(err, &e) && e.RetryAfter() > 0 {
			wait = e.RetryAfter()
		}
		r.st.CANotBefore = r.now().Add(wait).Truncate(time.Second)
		if serr := r.st.save(r.cfg.StateDir); serr != nil {
			detail += "; the CA's time could not be stored: " + serr.Error()
		}
		detail += fmt.Sprintf("; the CA asked to wait until %s (no run asks it before then)", r.st.CANotBefore.Format(time.RFC3339))
	}
	if h := hint(err, r.cfg); h != "" {
		detail += "\n             hint: " + h
	}
	r.record(step, Fail, detail, start)
}

func (r *Runner) preflight(start time.Time) bool {
	if err := checkDirectory(r.cfg.DirectoryURL, true); err != nil {
		r.record(StepPreflight, Fail, err.Error(), start)
		return false
	}
	st, err := loadState(r.cfg.StateDir)
	if err != nil {
		r.record(StepPreflight, Fail, err.Error(), start)
		return false
	}
	r.st = st
	if r.rateLimited() {
		r.record(StepPreflight, Fail, fmt.Sprintf("an earlier run was rate-limited: the CA asked to wait until %s; "+
			"nothing is sent before then (remove ca_not_before from %s to override)", st.CANotBefore.Format(time.RFC3339),
			filepath.Join(r.cfg.StateDir, stateFile)), start)
		return false
	}
	if r.cfg.Challenge == solver.DNS01 {
		if _, ok := dnsProvider(r.cfg.DNSProvider); !ok {
			r.record(StepPreflight, Fail, "unknown DNS provider "+r.cfg.DNSProvider, start)
			return false
		}
	}
	key, reused, err := accountKey(r.cfg.StateDir)
	if err != nil {
		r.record(StepPreflight, Fail, err.Error(), start)
		return false
	}
	r.client, err = acme.New(acme.Config{DirectoryURL: r.cfg.DirectoryURL, Key: key, AccountURL: st.AccountURL,
		HTTPClient: r.acmeHTTP, Contact: r.cfg.Email, CallTimeout: r.cfg.CallTimeout, OrderTimeout: r.cfg.OrderTimeout})
	if err != nil {
		r.record(StepPreflight, Fail, err.Error(), start)
		return false
	}
	k := "a new account key"
	if reused {
		k = "the account key of an earlier run"
	}
	r.record(StepPreflight, Pass, fmt.Sprintf("state %s, %s, %d certificate(s) of earlier runs to revoke", r.cfg.StateDir, k, len(st.Pending)), start)
	return true
}

func (r *Runner) directory(ctx context.Context) bool {
	start := r.now()
	d, err := r.client.Discover(ctx)
	if err != nil {
		r.fail(StepDirectory, err, start)
		return false
	}
	r.dir = d
	yesno := func(b bool) string {
		if b {
			return "yes"
		}
		return "NO"
	}
	detail := fmt.Sprintf("renewalInfo %s, revokeCert %s, keyChange %s, external account binding required %s",
		yesno(d.SupportsARI()), yesno(d.SupportsRevocation()), yesno(d.SupportsRollover()), yesno(d.ExternalAccountRequired))
	if d.TermsOfService != "" {
		detail += ", terms " + d.TermsOfService
	}
	status := Pass
	if !d.SupportsARI() || !d.SupportsRevocation() {
		status = Warn
	}
	if d.ExternalAccountRequired {
		r.record(StepDirectory, Fail, detail+": the harness registers without a binding (staging needs none)", start)
		return false
	}
	r.record(StepDirectory, status, detail, start)
	return true
}

func (r *Runner) loadRoots(ctx context.Context) bool {
	start := r.now()
	switch {
	case r.cfg.RootsPEM != nil:
		roots, err := parseCerts(r.cfg.RootsPEM)
		if err != nil {
			r.record(StepRoots, Fail, EnvRootsFile+" holds no certificate", start)
			return false
		}
		r.roots = roots
	case r.cfg.ExpectStaging:
		roots, err := fetchRoots(ctx, r.rootsHTTP, StagingRootURLs)
		if err != nil {
			r.record(StepRoots, Fail, err.Error()+" (download the roots yourself and set "+EnvRootsFile+")", start)
			return false
		}
		r.roots = roots
	default:
		r.record(StepRoots, Pass, "the system's trusted roots (production)", start)
		return true
	}
	names := make([]string, 0, len(r.roots))
	for _, c := range r.roots {
		names = append(names, c.Subject.CommonName)
	}
	r.record(StepRoots, Pass, strings.Join(names, "; "), start)
	return true
}

func (r *Runner) account(ctx context.Context) bool {
	start := r.now()
	a, err := r.client.RegisterAccount(ctx, r.cfg.Email, nil, r.cfg.AcceptTOS)
	if err != nil {
		r.fail(StepAccount, err, start)
		return false
	}
	r.acct = a
	r.st.AccountURL = a.URL
	if err := r.st.save(r.cfg.StateDir); err != nil {
		r.record(StepAccount, Fail, err.Error(), start)
		return false
	}
	what := "registered a new account"
	if a.Existing {
		what = "the CA returned the existing account"
	}
	r.record(StepAccount, Pass, what+" "+a.URL, start)
	return true
}

// leftovers revokes the certificates an earlier run issued and did not revoke.
func (r *Runner) leftovers(ctx context.Context) bool {
	start := r.now()
	if len(r.st.Pending) == 0 {
		r.record(StepLeftovers, Pass, "nothing left by earlier runs", start)
		return true
	}
	n, total := 0, len(r.st.Pending)
	for _, name := range append([]string(nil), r.st.Pending...) {
		der, err := leafOf(r.cfg.StateDir, name)
		if err == nil {
			err = r.client.Revoke(ctx, der, acme.RevokeCessationOfOperation)
		}
		switch {
		case err == nil, errors.Is(err, os.ErrNotExist), acme.ReasonOf(err) == acme.ReasonRevokeUnauthorized:
			// Revoked now or before (alreadyRevoked is success), or not this account's to revoke (another account key).
			if serr := r.st.done(r.cfg.StateDir, name); serr != nil {
				r.record(StepLeftovers, Fail, serr.Error(), start)
				return false
			}
			n++
		default:
			r.fail(StepLeftovers, fmt.Errorf("%s: %w", name, err), start)
			return false
		}
	}
	r.record(StepLeftovers, Pass, fmt.Sprintf("revoked %d of %d certificate(s) left by earlier runs", n, total), start)
	return true
}

func (r *Runner) orderOpts() []acme.OrderOption {
	return []acme.OrderOption{
		acme.WithOnPresent(func(ch solver.Challenge) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.presented = append(r.presented, ch)
			return nil
		}),
		acme.WithOnCleanUp(func(_ solver.Challenge, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.cleaned++
			if err != nil {
				r.cleanErrs++
			}
		}),
	}
}

// issue orders a certificate for the configured names with a fresh key and stores it for revocation.
func (r *Runner) issue(ctx context.Context, extra ...acme.OrderOption) ([][]byte, error) {
	k, err := keygen.Generate(r.cfg.KeyType)
	if err != nil {
		return nil, err
	}
	defer k.Zero()
	csr, err := keygen.NewCSR(k.Signer, r.cfg.Names())
	if err != nil {
		return nil, err
	}
	s, closeSolver, err := r.buildSolver()
	if err != nil {
		return nil, err
	}
	defer closeSolver()
	chain, err := r.client.Order(ctx, r.cfg.Names(), csr, s, append(r.orderOpts(), extra...)...)
	if err != nil {
		return nil, err
	}
	if _, err := r.st.keepCertificate(r.cfg.StateDir, chain); err != nil {
		return chain, fmt.Errorf("the certificate was issued but could not be stored for revocation: %w", err)
	}
	return chain, nil
}

func (r *Runner) order(ctx context.Context) [][]byte {
	start := r.now()
	chain, err := r.issue(ctx)
	if err != nil {
		r.fail(StepOrder, err, start)
		return nil
	}
	leaf, _ := x509.ParseCertificate(chain[0])
	r.record(StepOrder, Pass, fmt.Sprintf("issued serial %s for %s, valid until %s, %d certificate(s) in the chain, %d challenge(s) presented",
		leaf.SerialNumber.Text(16), strings.Join(leaf.DNSNames, " "), leaf.NotAfter.Format(time.RFC3339), len(chain), r.presentedCount()), start)
	return chain
}

func (r *Runner) presentedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.presented)
}

func (r *Runner) chain(chain [][]byte) *x509.Certificate {
	start := r.now()
	rep, err := verifyChain(chain, r.roots, r.cfg.Names(), r.cfg.ExpectStaging, r.now())
	if err != nil {
		r.record(StepChain, Fail, err.Error(), start)
		return nil
	}
	r.record(StepChain, Pass, strings.Join(rep.path, " -> "), start)
	return rep.leaf
}

func (r *Runner) ari(ctx context.Context, chain [][]byte) {
	start := r.now()
	if !r.dir.SupportsARI() {
		r.record(StepARI, Fail, "the directory has no renewalInfo", start)
		return
	}
	w, err := r.client.RenewalInfo(ctx, chain[0])
	if err != nil {
		r.fail(StepARI, err, start)
		return
	}
	leaf, _ := x509.ParseCertificate(chain[0])
	detail := fmt.Sprintf("suggested window %s .. %s", w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
	if w.RetryAfter > 0 {
		detail += ", ask again after " + w.RetryAfter.String()
	}
	status := Pass
	if w.End.After(leaf.NotAfter) || w.Start.Before(leaf.NotBefore) {
		status = Warn
		detail += " (outside the certificate's validity: Alice would ignore it and use its own rule)"
	}
	r.record(StepARI, status, detail, start)
}

func (r *Runner) renewal(ctx context.Context, first [][]byte) {
	start := r.now()
	leaf, _ := x509.ParseCertificate(first[0])
	id, err := acme.CertID(leaf)
	if err != nil {
		r.record(StepRenewal, Fail, "no RFC 9773 identifier for the first certificate", start)
		return
	}
	var outcome string
	chain, err := r.issue(ctx, acme.WithReplaces(acme.Replaces{CertID: id, AccountURL: r.acct.URL,
		OnOutcome: func(o string) error { outcome = o; return nil }}))
	if err != nil {
		r.fail(StepRenewal, err, start)
		return
	}
	rep, err := verifyChain(chain, r.roots, r.cfg.Names(), r.cfg.ExpectStaging, r.now())
	if err != nil {
		r.record(StepRenewal, Fail, "the renewed certificate's chain: "+err.Error(), start)
		return
	}
	detail := fmt.Sprintf("issued serial %s replacing %s, replaces %s", rep.leaf.SerialNumber.Text(16), id, outcome)
	if outcome != acme.ReplacesSent {
		r.record(StepRenewal, Fail, detail+" (expected "+acme.ReplacesSent+": the CA did not take the replaces field)", start)
		return
	}
	r.record(StepRenewal, Pass, detail, start)
}

// revoke revokes every certificate of this run (newest first), then the first one once more: a CA answers a
// second revocation alreadyRevoked, which Alice treats as done.
func (r *Runner) revoke(ctx context.Context) {
	start := r.now()
	if len(r.st.Pending) == 0 {
		r.record(StepRevoke, Skip, "nothing to revoke", start)
		return
	}
	pending := append([]string(nil), r.st.Pending...)
	reasons := []acme.RevocationReason{acme.RevokeSuperseded, acme.RevokeCessationOfOperation}
	var again []byte
	for i := len(pending) - 1; i >= 0; i-- {
		der, err := leafOf(r.cfg.StateDir, pending[i])
		if err == nil {
			err = r.client.Revoke(ctx, der, reasons[i%2])
		}
		if err != nil {
			r.fail(StepRevoke, fmt.Errorf("%s: %w", pending[i], err), start)
			return
		}
		if err := r.st.done(r.cfg.StateDir, pending[i]); err != nil {
			r.record(StepRevoke, Fail, err.Error(), start)
			return
		}
		again = der
	}
	if err := r.client.Revoke(ctx, again, acme.RevokeSuperseded); err != nil {
		r.fail(StepRevoke, fmt.Errorf("revoking an already revoked certificate again: %w", err), start)
		return
	}
	r.record(StepRevoke, Pass, fmt.Sprintf("revoked %d certificate(s); a second revocation answered as done", len(pending)), start)
}

func (r *Runner) cleanup(ctx context.Context) {
	start := r.now()
	r.mu.Lock()
	presented, cleaned, errs := len(r.presented), r.cleaned, r.cleanErrs
	r.mu.Unlock()
	var problems []string
	if cleaned != presented || errs > 0 {
		problems = append(problems, fmt.Sprintf("%d of %d challenge(s) cleaned up, %d with an error (remove the TXT records or token files by hand)",
			cleaned-errs, presented, errs))
	}
	if r.st != nil && len(r.st.Pending) > 0 {
		problems = append(problems, fmt.Sprintf("%d certificate(s) not revoked yet; the next run revokes them", len(r.st.Pending)))
	}
	deact := ""
	if r.cfg.Deactivate && r.client != nil && r.acct.URL != "" && !r.rateLimited() {
		if err := r.client.Deactivate(ctx); err != nil {
			problems = append(problems, "the account could not be deactivated: "+err.Error())
		} else if err := os.Remove(filepath.Join(r.cfg.StateDir, accountKeyFile)); err != nil {
			problems = append(problems, "the account was deactivated but its key could not be removed: "+err.Error())
		} else {
			r.st.AccountURL = ""
			_ = r.st.save(r.cfg.StateDir)
			deact = ", account deactivated"
		}
	}
	if len(problems) > 0 {
		r.record(StepCleanup, Fail, strings.Join(problems, "; "), start)
		return
	}
	r.record(StepCleanup, Pass, fmt.Sprintf("%d challenge(s) presented and removed, nothing left to revoke%s", presented, deact), start)
}

// hint is the owner's next step for the common failures.
func hint(err error, cfg Config) string {
	switch acme.ReasonOf(err) {
	case acme.ReasonValidationFailedHTTP:
		return "the check of http://" + cfg.Domain + "/.well-known/acme-challenge/<token> failed: port 80 of the name's " +
			"address must reach this harness (" + EnvHTTP01Listen + ") or the web server of " + EnvHTTP01Webroot +
			"; behind NAT, an /etc/hosts line for the name pointing at 127.0.0.1 lets Alice's own check succeed"
	case acme.ReasonValidationFailedDNS:
		return "the CA did not see the TXT record _acme-challenge." + cfg.Domain + ": raise " + EnvDNSWait +
			" or check that the hook writes to the zone's authoritative servers"
	case acme.ReasonHookRefused:
		return "the DNS hook refused or could not be reached (check its URL, secret and certificate; " + EnvDNSHookCAFile + ")"
	case acme.ReasonCARateLimited:
		return "staging limits: https://letsencrypt.org/docs/staging-environment/"
	case acme.ReasonTLSTrustFailed:
		return "the CA's HTTPS certificate is not trusted: check the system roots (or " + EnvCAFile + ")"
	case acme.ReasonNameNotAllowed, acme.ReasonIdentifierRefused:
		return "the CA refuses the name: use a name in a public DNS zone you control"
	}
	return ""
}
