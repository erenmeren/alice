package acme

import (
	"strings"
	"testing"
)

// The parsers read what a CA (or anything at its address) sends: no input may panic, and every result must
// stay inside its documented bounds.

func FuzzParseProblem(f *testing.F) {
	for _, s := range []string{
		`{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"x"}`,
		`{"type":"urn:acme:error:badNonce","status":400}`,
		`{"type":"about:blank"}`, `{"type":null,"status":1e400}`, `{"subproblems":[{"type":"x"}]}`, `[]`, `"`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p := ParseProblem(b)
		if p.Type != "" && (!strings.HasPrefix(p.Type, ProblemPrefix) || len(p.Type) > len(ProblemPrefix)+40) {
			t.Fatalf("type %q escaped the namespace", p.Type)
		}
		if p.Status != 0 && (p.Status < 100 || p.Status > 599) {
			t.Fatalf("status %d", p.Status)
		}
	})
}

func FuzzParseARI(f *testing.F) {
	for _, s := range []string{
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"},"explanationURL":"https://x"}`,
		`{"suggestedWindow":{"start":"2030-01-01T00:00:00+14:00","end":"2030-01-01T00:00:00-12:00"}}`,
		`{"suggestedWindow":{"start":"9999-12-31T23:59:59Z","end":"0000-01-01T00:00:00Z"}}`,
		`{"suggestedWindow":null}`, `{}`, `x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		start, end, err := ParseARI(b)
		if err == nil && !start.Before(end) {
			t.Fatalf("window %v..%v accepted", start, end)
		}
	})
}

func FuzzParseDirectory(f *testing.F) {
	for _, s := range []string{
		`{"newNonce":"https://ca/n","newAccount":"https://ca/a","newOrder":"https://ca/o","keyChange":"https://ca/k",` +
			`"renewalInfo":"https://ca/ari","meta":{"termsOfService":"https://ca/tos","externalAccountRequired":true}}`,
		`{"newNonce":"http://ca/n","newAccount":"https://ca/a","newOrder":"https://ca/o"}`,
		`{"newNonce":"https://u@ca/n","newAccount":"https://ca/a","newOrder":"https://169.254.169.254/o"}`,
		`{"meta":{"website":"javascript:x"}}`, `null`, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := ParseDirectory(b)
		if err != nil {
			return
		}
		for _, u := range []string{d.NewNonce, d.NewAccount, d.NewOrder} {
			if !strings.HasPrefix(u, "https://") {
				t.Fatalf("required URL %q is not https", u)
			}
		}
		for _, u := range []string{d.KeyChange, d.RenewalInfo} {
			if u != "" && !strings.HasPrefix(u, "https://") {
				t.Fatalf("optional URL %q is not https", u)
			}
		}
		for _, u := range []string{d.NewNonce, d.NewAccount, d.NewOrder, d.KeyChange, d.RenewalInfo, d.TermsOfService, d.Website} {
			if len(u) > 3*maxURLLen {
				t.Fatalf("URL too long: %d", len(u))
			}
		}
	})
}
