package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"slices"

	xacme "golang.org/x/crypto/acme"

	"alice/internal/acme/solver"
)

// OrderOption configures one Order or TestOrder.
type OrderOption func(*orderOpts)

type orderOpts struct {
	onOrder    func(orderURL string) error
	onFinalize func() error
	onPresent  func(solver.Challenge) error
	onCleanUp  func(solver.Challenge, error)
	replaces   *Replaces
}

// WithOnOrder is called with the order's URL as soon as the CA created the order, before any challenge is
// presented, so the caller can persist it and resume the order after a crash (ResumeOrder). An error stops the
// order before anything is presented; it is returned as an *Error with reason directory_invalid whose
// errors.Is still finds the callback's error.
func WithOnOrder(f func(orderURL string) error) OrderOption {
	return func(o *orderOpts) { o.onOrder = f }
}

// WithOnPresent is called with every challenge right before it is presented, so the caller can persist it
// (plan A12) and clean it up after a crash. An error stops the order before that challenge is presented; it
// is returned as an *Error (reason of the proof method) whose text says only ErrSolver, while errors.Is still
// finds both ErrSolver and the callback's error.
func WithOnPresent(f func(solver.Challenge) error) OrderOption {
	return func(o *orderOpts) { o.onPresent = f }
}

// WithOnCleanUp is called after every CleanUp with its result (nil: the challenge is gone).
func WithOnCleanUp(f func(solver.Challenge, error)) OrderOption {
	return func(o *orderOpts) { o.onCleanUp = f }
}

// WithBeforeFinalize is called by Order after every authorization is valid and right before the CSR is sent
// (finalize), so the caller can ask once more whether it may still change anything (a licence lock). An error stops the
// order before finalize, as an *Error with reason directory_invalid whose errors.Is finds the callback's error.
func WithBeforeFinalize(f func() error) OrderOption {
	return func(o *orderOpts) { o.onFinalize = f }
}

// Order orders a certificate for names with the CSR csrDER and returns the chain (leaf first, DER). The CSR
// must hold exactly the names (checked before the CA is contacted). Every presented challenge is cleaned up
// before Order returns, whatever happens.
func (c *Client) Order(ctx context.Context, names []string, csrDER []byte, s solver.Solver, opts ...OrderOption) ([][]byte, error) {
	norm, err := NormalizeNames(names)
	if err != nil {
		return nil, err
	}
	csr, err := checkCSR(csrDER, norm)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.OrderTimeout)
	defer cancel()
	o, err := c.authorize(ctx, norm, s, opts)
	if err != nil {
		return nil, err
	}
	var oo orderOpts
	for _, f := range opts {
		f(&oo)
	}
	if oo.onFinalize != nil {
		if err := oo.onFinalize(); err != nil {
			return nil, &Error{Reason: ReasonDirectoryInvalid, cause: callbackCause{err: err}}
		}
	}
	var chain [][]byte
	err = c.call(ctx, func(ctx context.Context) error {
		ready, err := c.lib.WaitOrder(ctx, o.URI)
		if err != nil {
			return err
		}
		chain, _, err = c.lib.CreateOrderCert(ctx, ready.FinalizeURL, csrDER, true)
		return err
	})
	if err != nil {
		return nil, c.classify(err, opOrder, "", "")
	}
	if err := checkChain(chain, csr.PublicKey, norm); err != nil {
		return nil, err
	}
	return chain, nil
}

// TestOrder runs an order up to validated authorizations and stops: no CSR is sent and nothing is issued. It
// leaves the validated authorizations (a later Order may reuse them) and a pending, never-finalized order at
// the CA, which expires there on its own.
func (c *Client) TestOrder(ctx context.Context, names []string, s solver.Solver, opts ...OrderOption) error {
	norm, err := NormalizeNames(names)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.OrderTimeout)
	defer cancel()
	_, err = c.authorize(ctx, norm, s, opts)
	return err
}

// ResumeOrder finishes an order an earlier process created (its URL came from WithOnOrder) and returns the
// chain (leaf first, DER), as Order would have: an order the CA already issued is downloaded, an order that is
// ready is finalized with csrDER (which must hold exactly names, as for Order), an order still processing is
// waited for. An order that is still pending (its challenges were never validated) or invalid cannot be resumed:
// *Error not_issued_in_time with ErrOrderNotResumable (the caller abandons it). Nothing is presented.
func (c *Client) ResumeOrder(ctx context.Context, orderURL string, names []string, csrDER []byte) ([][]byte, error) {
	norm, err := NormalizeNames(names)
	if err != nil {
		return nil, err
	}
	csr, err := checkCSR(csrDER, norm)
	if err != nil {
		return nil, err
	}
	if c.cfg.Key == nil {
		return nil, newError(ReasonAccountRejected, ErrNoKey)
	}
	if orderURL == "" {
		return nil, newError(ReasonNotIssuedInTime, ErrOrderNotResumable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.OrderTimeout)
	defer cancel()
	if _, err := c.Discover(ctx); err != nil {
		return nil, c.orderTimeout(err)
	}
	var o *xacme.Order
	if err := c.call(ctx, func(ctx context.Context) error {
		var err error
		o, err = c.lib.GetOrder(ctx, orderURL)
		return err
	}); err != nil {
		return nil, c.classify(err, opOrder, "", "")
	}
	var chain [][]byte
	err = c.call(ctx, func(ctx context.Context) error {
		var err error
		switch o.Status {
		case xacme.StatusProcessing:
			if o, err = c.lib.WaitOrder(ctx, orderURL); err != nil {
				return err
			}
			if o.Status != xacme.StatusValid {
				return errNotResumable
			}
			chain, err = c.lib.FetchCert(ctx, o.CertURL, true)
		case xacme.StatusValid:
			chain, err = c.lib.FetchCert(ctx, o.CertURL, true)
		case xacme.StatusReady:
			chain, _, err = c.lib.CreateOrderCert(ctx, o.FinalizeURL, csrDER, true)
		default:
			return errNotResumable
		}
		return err
	})
	if errors.Is(err, errNotResumable) {
		return nil, newError(ReasonNotIssuedInTime, ErrOrderNotResumable)
	}
	if err != nil {
		return nil, c.classify(err, opOrder, "", "")
	}
	if err := checkChain(chain, csr.PublicKey, norm); err != nil {
		return nil, err
	}
	return chain, nil
}

// errNotResumable marks an order state ResumeOrder cannot finish (mapped to ErrOrderNotResumable).
var errNotResumable = errors.New("acme: the order cannot be resumed")

// callbackCause hides a WithOnOrder callback's error text behind ErrBadAnswer but keeps it for errors.Is/As.
type callbackCause struct{ err error }

func (c callbackCause) Error() string   { return "acme: the order's URL could not be recorded" }
func (c callbackCause) Unwrap() []error { return []error{c.err} }

// pendingChallenge is a challenge chosen for a pending authorization.
type pendingChallenge struct {
	authzURL string
	lib      *xacme.Challenge
	ch       solver.Challenge
	name     string
}

// authorize creates the order and brings every authorization to valid, cleaning up what it presented.
func (c *Client) authorize(ctx context.Context, names []string, s solver.Solver, opts []OrderOption) (o *xacme.Order, err error) {
	var oo orderOpts
	for _, f := range opts {
		f(&oo)
	}
	if s == nil {
		return nil, newError(ReasonChallengeUnavailable, ErrChallengeUnavailable)
	}
	types := s.Types()
	for _, n := range names {
		if isWildcard(n) && !slices.Contains(types, solver.DNS01) {
			return nil, &Error{Reason: ReasonChallengeUnavailable, Identifier: n, cause: ErrChallengeUnavailable}
		}
	}
	if c.cfg.Key == nil {
		return nil, newError(ReasonAccountRejected, ErrNoKey)
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return nil, c.orderTimeout(err)
	}
	ids := make([]xacme.AuthzID, len(names))
	for i, n := range names {
		ids[i] = xacme.AuthzID{Type: "dns", Value: n}
	}
	o, outcome, err := c.newOrder(ctx, d, ids, names, oo.replaces)
	if outcome != "" && oo.replaces.OnOutcome != nil {
		if cerr := oo.replaces.OnOutcome(outcome); cerr != nil && err == nil {
			return nil, &Error{Reason: ReasonDirectoryInvalid, cause: callbackCause{err: cerr}}
		}
	}
	if err != nil {
		return nil, c.classify(err, opOrder, "", "")
	}
	if o.URI == "" || len(o.AuthzURLs) == 0 || len(o.AuthzURLs) > len(names) {
		return nil, newError(ReasonDirectoryInvalid, ErrBadAnswer)
	}
	if oo.onOrder != nil {
		if err := oo.onOrder(o.URI); err != nil {
			return nil, &Error{Reason: ReasonDirectoryInvalid, cause: callbackCause{err: err}}
		}
	}

	var presented []solver.Challenge
	defer func() {
		// A fresh context: cleanup must run after a cancellation or a deadline of the order.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.CleanupTimeout)
		defer cancel()
		for i := len(presented) - 1; i >= 0; i-- {
			cerr := s.CleanUp(cctx, presented[i])
			if oo.onCleanUp != nil {
				oo.onCleanUp(presented[i], cerr)
			}
		}
	}()

	var pending []pendingChallenge
	for _, u := range o.AuthzURLs {
		var z *xacme.Authorization
		if err := c.call(ctx, func(ctx context.Context) error {
			var err error
			z, err = c.lib.GetAuthorization(ctx, u)
			return err
		}); err != nil {
			return nil, c.classify(err, opOrder, "", "")
		}
		name := z.Identifier.Value
		if z.Wildcard {
			name = "*." + name
		}
		if z.Identifier.Type != "dns" || !slices.Contains(names, asciiLower(name)) {
			return nil, newError(ReasonDirectoryInvalid, ErrBadAnswer)
		}
		switch z.Status {
		case xacme.StatusValid:
			continue
		case xacme.StatusPending:
		default:
			return nil, &Error{Reason: ReasonDirectoryInvalid, Identifier: name, cause: ErrBadAnswer}
		}
		p, err := c.choose(z, u, name, types)
		if err != nil {
			return nil, err
		}
		pending = append(pending, p)
	}

	for _, p := range pending {
		if oo.onPresent != nil {
			if err := oo.onPresent(p.ch); err != nil {
				return nil, presentError(err, p)
			}
		}
		presented = append(presented, p.ch)
		// A hung hook may take one call's budget, not the whole order's.
		if err := c.call(ctx, func(ctx context.Context) error { return s.Present(ctx, p.ch) }); err != nil {
			return nil, presentError(err, p)
		}
	}
	for _, p := range pending {
		if err := c.call(ctx, func(ctx context.Context) error {
			_, err := c.lib.Accept(ctx, p.lib)
			return err
		}); err != nil {
			return nil, c.classify(err, opOrder, p.ch.Type, p.name)
		}
	}
	for _, p := range pending {
		if err := c.call(ctx, func(ctx context.Context) error {
			_, err := c.lib.WaitAuthorization(ctx, p.authzURL)
			return err
		}); err != nil {
			return nil, c.classify(err, opOrder, p.ch.Type, p.name)
		}
	}
	return o, nil
}

// orderTimeout makes a discovery timeout during an order an order timeout.
func (c *Client) orderTimeout(err error) error {
	var e *Error
	if errors.As(err, &e) && (errors.Is(e.cause, context.DeadlineExceeded) || errors.Is(e.cause, context.Canceled)) {
		e.Reason = ReasonNotIssuedInTime
	}
	return err
}

// choose picks the solver's most preferred challenge the authorization offers.
func (c *Client) choose(z *xacme.Authorization, authzURL, name string, types []string) (pendingChallenge, error) {
	for _, t := range types {
		if z.Wildcard && t != solver.DNS01 {
			continue
		}
		for _, ch := range z.Challenges {
			if ch.Type != t || ch.Status == xacme.StatusInvalid {
				continue
			}
			if !validToken(ch.Token) {
				return pendingChallenge{}, &Error{Reason: ReasonDirectoryInvalid, Identifier: name, cause: ErrBadAnswer}
			}
			sc := solver.Challenge{Type: t, Domain: z.Identifier.Value, Wildcard: z.Wildcard, Token: ch.Token}
			var err error
			switch t {
			case solver.DNS01:
				sc.DNSName = "_acme-challenge." + asciiLower(z.Identifier.Value)
				sc.DNSValue, err = c.lib.DNS01ChallengeRecord(ch.Token)
			case solver.HTTP01:
				sc.HTTPPath = c.lib.HTTP01ChallengePath(ch.Token)
				sc.KeyAuth, err = c.lib.HTTP01ChallengeResponse(ch.Token)
			default:
				continue
			}
			if err != nil {
				return pendingChallenge{}, newError(ReasonAccountRejected, ErrNoKey)
			}
			return pendingChallenge{authzURL: authzURL, lib: ch, ch: sc, name: name}, nil
		}
	}
	return pendingChallenge{}, &Error{Reason: ReasonChallengeUnavailable, Identifier: name, cause: ErrChallengeUnavailable}
}

// validToken accepts 16..256 base64url characters (RFC 8555 section 8.1 asks for at least 128 bits).
func validToken(t string) bool {
	if len(t) < 16 || len(t) > 256 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// solverCause hides a solver's (or OnPresent's) error text behind ErrSolver but keeps it for errors.Is/As.
type solverCause struct{ err error }

func (s solverCause) Error() string   { return ErrSolver.Error() }
func (s solverCause) Unwrap() []error { return []error{ErrSolver, s.err} }

// presentError keeps a solver's *Error and otherwise maps the failure to the proof method; the solver's own
// text is dropped (it may quote a hook's answer).
func presentError(err error, p pendingChallenge) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		ce := context.DeadlineExceeded
		if errors.Is(err, context.Canceled) {
			ce = context.Canceled
		}
		return &Error{Reason: ReasonNotIssuedInTime, Identifier: p.name, cause: ce}
	}
	cause := solverCause{err: err}
	if p.ch.Type == solver.DNS01 {
		return &Error{Reason: ReasonHookRefused, Identifier: p.name, cause: cause}
	}
	return &Error{Reason: ReasonValidationFailedHTTP, Identifier: p.name, cause: cause}
}

// checkCSR parses the CSR and checks its signature and that its DNS names are exactly names (and nothing
// else: no IP, e-mail or URI names).
func checkCSR(der []byte, names []string) (*x509.CertificateRequest, error) {
	bad := newError(ReasonKeyPolicyNotAllowed, ErrCSRMismatch)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, bad
	}
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 || !sameNames(csr.DNSNames, names) {
		return nil, bad
	}
	return csr, nil
}

func sameNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	set := make(map[string]bool, len(want))
	for _, n := range want {
		set[n] = true
	}
	for _, n := range got {
		if !set[asciiLower(n)] {
			return false
		}
		delete(set, asciiLower(n))
	}
	return len(set) == 0
}

// checkChain checks that the CA returned a certificate for the CSR's key and exactly the ordered names: a chain that
// does not parse is ErrBadAnswer (like any garbled answer), a leaf of another key or other names ErrChainKeyMismatch.
func checkChain(chain [][]byte, pub crypto.PublicKey, names []string) error {
	bad := newError(ReasonDirectoryInvalid, ErrBadAnswer)
	if len(chain) == 0 {
		return bad
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return bad
	}
	k, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !k.Equal(leaf.PublicKey) || !sameNames(leaf.DNSNames, names) {
		// A well-formed certificate that is not the one ordered: a CA-side refusal of this order, not a garbled answer.
		return newError(ReasonDirectoryInvalid, ErrChainKeyMismatch)
	}
	for _, der := range chain[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return bad
		}
	}
	return nil
}
