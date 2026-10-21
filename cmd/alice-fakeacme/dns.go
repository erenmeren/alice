package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/fakecloudflare"
	"alice/internal/testutil/fakeroute53"
)

// The fake DNS providers of the e2e stack (R57; serve --dns-providers): the fake Cloudflare API and the fake Route 53
// and STS, served on the fake CA's own listener for the host names the compose file gives this container as aliases
// (api.cloudflare.com, route53.amazonaws.com, sts.amazonaws.com), each with its own certificate chosen by the TLS
// server name, and the CAs of all three in the --ca-out file the e2e build of Alice trusts. Both mirror every TXT
// value into the fake CA's DNS table, so the CA validates what Alice published through them. The zone is the e2e
// stack's domain, example.test. Their credentials are generated at start and printed by "ctl dns-providers" only.

// dnsZone is the e2e stack's domain.
const dnsZone = "example.test"

type dnsFakes struct {
	cf  *fakecloudflare.Server
	r53 *fakeroute53.Server
}

func newDNSFakes(ca *fakeacme.Server) (*dnsFakes, error) {
	cf, err := fakecloudflare.New(fakecloudflare.Options{Zones: []string{dnsZone}, Sink: ca})
	if err != nil {
		return nil, err
	}
	r53, err := fakeroute53.New(fakeroute53.Options{Zones: []fakeroute53.Zone{{Name: dnsZone}}, InsyncAfter: 1, Sink: ca})
	if err != nil {
		cf.Close()
		return nil, err
	}
	return &dnsFakes{cf: cf, r53: r53}, nil
}

func (d *dnsFakes) Close() {
	d.cf.Close()
	d.r53.Close()
}

// caPEM is the CAs of both fakes.
func (d *dnsFakes) caPEM() []byte {
	return append(append([]byte{}, d.cf.CAPEM()...), d.r53.CAPEM()...)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	b := []byte(strings.TrimSuffix(h, "."))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// tlsConfig is base with a certificate per server name: a fake provider's for its hosts, base's for every other name.
func (d *dnsFakes) tlsConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	cf, r53 := d.cf.TLSConfig().Certificates[0], d.r53.TLSConfig().Certificates[0]
	c.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		switch hostOnly(h.ServerName) {
		case fakecloudflare.Host:
			return &cf, nil
		case fakeroute53.Route53Host, fakeroute53.STSHost:
			return &r53, nil
		}
		return nil, nil // the fake CA's own certificate
	}
	return c
}

// handler routes a request by its host: the fake providers' hosts to them, everything else to the CA.
func (d *dnsFakes) handler(ca http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch hostOnly(r.Host) {
		case fakecloudflare.Host:
			d.cf.Handler().ServeHTTP(w, r)
		case fakeroute53.Route53Host, fakeroute53.STSHost:
			d.r53.Handler().ServeHTTP(w, r)
		default:
			ca.ServeHTTP(w, r)
		}
	})
}

// dnsProvidersAnswer is what "ctl dns-providers" prints: the credentials the fakes accept and what they hold.
type dnsProvidersAnswer struct {
	Zone       string `json:"zone"`
	Cloudflare struct {
		Token   string              `json:"token"`
		Records map[string][]string `json:"records"`
	} `json:"cloudflare"`
	Route53 struct {
		AccessKeyID     string              `json:"access_key_id"`
		SecretAccessKey string              `json:"secret_access_key"`
		Records         map[string][]string `json:"records"`
	} `json:"route53"`
}

// admin adds GET /dns-providers to the fake CA's admin API (loopback only, as the rest of it).
func (d *dnsFakes) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-providers" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var a dnsProvidersAnswer
		a.Zone = dnsZone
		a.Cloudflare.Token, a.Cloudflare.Records = d.cf.Token(), map[string][]string{}
		for _, rec := range d.cf.Records() {
			if rec.Type == "TXT" {
				a.Cloudflare.Records[rec.Name] = append(a.Cloudflare.Records[rec.Name], fakecloudflare.Unquote(rec.Content))
			}
		}
		a.Route53.AccessKeyID, a.Route53.SecretAccessKey, a.Route53.Records = d.r53.AccessKeyID(), d.r53.SecretAccessKey(), d.r53.Records()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	})
}
