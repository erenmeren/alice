package acme

import (
	"context"
	"errors"
	"net/http"

	xacme "golang.org/x/crypto/acme"
)

// What became of the replaces field of a renewal (RFC 9773 section 5; R50, docs/superpowers/rulings/acme-ari.md),
// reported once by Replaces.OnOutcome.
const (
	// ReplacesSent: the order was created with the field.
	ReplacesSent = "sent"
	// ReplacesAdopted: the CA answered alreadyReplaced and an earlier order of Alice's that replaces the certificate
	// (Replaces.Earlier: a lost answer, an interrupted run) was taken over instead of ordering anew.
	ReplacesAdopted = "adopted"
	// ReplacesNoARI: not sent, the CA's directory has no renewalInfo (RFC 9773: a client SHOULD NOT send it then).
	ReplacesNoARI = "no_ari"
	// ReplacesOtherAccount: not sent, the predecessor was ordered with another account (the CA would refuse it).
	ReplacesOtherAccount = "other_account"
	// ReplacesAlreadyReplaced: the CA answered alreadyReplaced and no earlier order could be taken over; the order was
	// made once more without the field.
	ReplacesAlreadyReplaced = "already_replaced"
	// ReplacesRefused: the CA refused the field itself (malformed, unauthorized); the order was made once more without it.
	ReplacesRefused = "refused"
)

// ReplacesOutcomes lists every outcome OnOutcome can report.
func ReplacesOutcomes() []string {
	return []string{ReplacesSent, ReplacesAdopted, ReplacesNoARI, ReplacesOtherAccount, ReplacesAlreadyReplaced, ReplacesRefused}
}

// maxAdopt bounds the earlier orders looked at after alreadyReplaced.
const maxAdopt = 3

// Replaces names the predecessor of a renewal.
type Replaces struct {
	// CertID is the predecessor's RFC 9773 identifier (CertID); "" sends nothing.
	CertID string
	// AccountURL is the account the predecessor was ordered with ("" when it is not known: the field is sent and a
	// refusal is handled as ReplacesRefused).
	AccountURL string
	// Earlier are the CA URLs of Alice's earlier orders that were created replacing the same certificate, newest first
	// (at most maxAdopt are looked at).
	Earlier []string
	// OnOutcome is called once with the outcome as soon as it is known, before WithOnOrder's callback (also when the
	// order made again without the field fails). An error stops the order like an error of WithOnOrder's callback.
	OnOutcome func(outcome string) error
}

// WithReplaces makes the order the renewal of r.CertID: newOrder carries the replaces field when the CA offers
// renewalInfo and the predecessor is this account's (RFC 9773 section 5). golang.org/x/crypto/acme cannot send the
// field, so that one request is signed here (postNewOrder); everything after it goes through the library as before.
// A CA that answers alreadyReplaced gets one of Alice's earlier orders taken over (pending or ready, the same names)
// or, without one, the order once more without the field; a CA that refuses the field itself (malformed,
// unauthorized) gets the order once more without it. Any other refusal is the order's failure, classified as usual.
func WithReplaces(r Replaces) OrderOption {
	return func(o *orderOpts) { o.replaces = &r }
}

// newOrder creates the order for ids (names normalized), with the replaces field when r asks for it and the CA may take
// it, and returns what became of the field ("" without r).
func (c *Client) newOrder(ctx context.Context, d Directory, ids []xacme.AuthzID, names []string, r *Replaces) (*xacme.Order, string, error) {
	plain := func() (*xacme.Order, error) {
		var o *xacme.Order
		err := c.call(ctx, func(ctx context.Context) error {
			var err error
			o, err = c.lib.AuthorizeOrder(ctx, ids)
			return err
		})
		return o, err
	}
	switch {
	case r == nil || r.CertID == "":
		o, err := plain()
		return o, "", err
	case !d.SupportsARI():
		o, err := plain()
		return o, ReplacesNoARI, err
	case r.AccountURL != "" && r.AccountURL != c.AccountURL():
		o, err := plain()
		return o, ReplacesOtherAccount, err
	}
	var o *xacme.Order
	err := c.call(ctx, func(ctx context.Context) error {
		var err error
		o, err = c.postNewOrder(ctx, d, ids, r.CertID)
		return err
	})
	if err == nil {
		return o, ReplacesSent, nil
	}
	var ae *xacme.Error
	if !errors.As(err, &ae) {
		return nil, "", err
	}
	var outcome string
	switch t := shortType(cleanProblemType(ae.ProblemType)); {
	case t == "alreadyReplaced", t == "" && ae.StatusCode == http.StatusConflict:
		if o := c.adopt(ctx, r.Earlier, names); o != nil {
			return o, ReplacesAdopted, nil
		}
		outcome = ReplacesAlreadyReplaced
	case t == "malformed", t == "unauthorized":
		outcome = ReplacesRefused
	default:
		return nil, "", err
	}
	o, err = plain()
	return o, outcome, err
}

// adopt takes over the first of the earlier orders (at most maxAdopt) that the CA still holds as pending or ready for
// exactly names; nil when none can be (unknown, another account's, valid already, other names, unreachable).
func (c *Client) adopt(ctx context.Context, earlier, names []string) *xacme.Order {
	for i, u := range earlier {
		if i >= maxAdopt {
			break
		}
		var o *xacme.Order
		if err := c.call(ctx, func(ctx context.Context) error {
			var err error
			o, err = c.lib.GetOrder(ctx, u)
			return err
		}); err != nil {
			continue
		}
		if o.Status != xacme.StatusPending && o.Status != xacme.StatusReady {
			continue
		}
		values := make([]string, 0, len(o.Identifiers))
		dns := true
		for _, id := range o.Identifiers {
			dns = dns && id.Type == "dns"
			values = append(values, id.Value)
		}
		if !dns || !sameNames(values, names) {
			continue
		}
		o.URI = u // a POST-as-GET of an order carries no Location
		return o
	}
	return nil
}
