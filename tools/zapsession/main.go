// Command zapsession prepares the signed-in sessions the authenticated ZAP scans use (spec §25.7).
// On a fresh Alice (the alice-zap stack of deploy/dev/zap-stack.sh) it runs the setup wizard through
// the API with the one-time setup code, creates an Operator and an Auditor, signs every role in
// with TOTP (codes computed from the enrolment secrets, never reused), steps the Administrator up
// and writes one file per role:
//
//	go run ./tools/zapsession -base https://127.0.0.1:9445 -ca bin/zap/tls.crt -setup-code CODE -out bin/zap
//
// <out>/admin.env, operator.env and auditor.env hold the two lines
//
//	COOKIE=__Host-alice_session=<session token>
//	CSRF=<CSRF token of that session>
//
// (mode 0600) for ZAP's replacer. The wizard's HTTPS step installs a certificate for 127.0.0.1 and
// localhost issued by a throwaway test CA made here (its key never leaves memory); <out>/test-ca.crt is
// that CA, so testssl.sh checks the release image's TLS with a complete chain of trust (the temporary
// self-signed certificate can never have one). The passwords, TOTP secrets and the recovery passphrase are random,
// held in memory only and never printed: the stack is disposable and deleted after the scan.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const sessionCookie = "__Host-alice_session"

func main() {
	os.Exit(run(os.Args[1:], clock{now: time.Now, sleep: time.Sleep}, os.Stdout, os.Stderr)) //nolint:forbidigo // a developer tool, not product code
}

// clock is the time the TOTP codes are computed from and the wait for the next TOTP step.
type clock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

func run(args []string, clk clock, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("zapsession", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "https://127.0.0.1:9445", "the Alice to prepare (a fresh installation)")
	caFile := fs.String("ca", "", "PEM file with the certificate Alice serves (keys/tls.crt)")
	code := fs.String("setup-code", "", "the one-time setup code (alice setup-token --reset)")
	out := fs.String("out", "", "directory for <role>.env")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *caFile == "" || *code == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "usage: zapsession -base URL -ca FILE -setup-code CODE -out DIR")
		return 2
	}
	sessions, testCA, err := Prepare(*base, *caFile, *code, clk)
	if err == nil {
		err = Write(*out, sessions, testCA)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "zapsession:", err)
		return 1
	}
	for _, s := range sessions {
		_, _ = fmt.Fprintf(stdout, "zapsession: %s signed in as %s (%s)\n", s.Role, s.Username, filepath.Join(*out, s.Role+".env"))
	}
	return 0
}

// Session is one signed-in role.
type Session struct {
	Role, Username, Cookie, CSRF string
}

// account is a user and the last TOTP step it used (Alice never accepts a step twice, SEC-006).
type account struct {
	username, password, role, secret string
	last                             int64
}

// client is a browser-like API client: a cookie jar, the CSRF token of the last answer that carried one.
type client struct {
	base string
	hc   *http.Client
	csrf string
	clk  clock
}

// Prepare runs the wizard and signs the three roles in. It returns the sessions and the PEM of the
// test CA that issued the HTTPS certificate it installed.
func Prepare(base, caFile, setupCode string, clk clock) ([]Session, []byte, error) {
	served, err := os.ReadFile(caFile) //nolint:gosec // G304: the certificate file named on the command line
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(served) {
		return nil, nil, fmt.Errorf("%s holds no PEM certificate", caFile)
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, nil, fmt.Errorf("-base %q is not an https URL", base)
	}
	testCA, certPEM, keyPEM, err := issueHTTPS(clk.now(), u.Hostname())
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyPEM)
	caCert, _ := pem.Decode(testCA)
	ca, err := x509.ParseCertificate(caCert.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pool.AddCert(ca) // the certificate the wizard installs; until then the one Alice served first
	newClient := func() (*client, error) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		return &client{base: base, clk: clk, hc: &http.Client{Jar: jar, Timeout: 60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
	}

	admin := &account{username: "zap-admin", password: random(), role: "admin"}
	others := []*account{
		{username: "zap-operator", password: random(), role: "operator"},
		{username: "zap-auditor", password: random(), role: "auditor"},
	}
	passphrase := random()

	// The wizard, as the web UI runs it: the setup session, the administrator with TOTP, the recovery
	// passphrase, an HTTPS certificate of the test CA, no mail, the evaluation license.
	ac, err := newClient()
	if err != nil {
		return nil, nil, err
	}
	var enr struct {
		Secret string `json:"secret"`
	}
	steps := []func() error{
		func() error {
			return ac.do(http.MethodPost, "/api/v1/setup/session", map[string]string{"code": setupCode}, nil)
		},
		func() error {
			return ac.do(http.MethodPut, "/api/v1/setup/language", map[string]string{"language": "en"}, nil)
		},
		func() error {
			return ac.do(http.MethodPost, "/api/v1/setup/admin/enrollment", map[string]string{
				"username": admin.username, "display_name": "ZAP Administrator", "email": "", "password": admin.password,
			}, &enr)
		},
		func() error {
			admin.secret = enr.Secret
			return ac.do(http.MethodPost, "/api/v1/setup/admin", func() any { return map[string]string{"code": ac.code(admin)} }, nil)
		},
		func() error {
			return ac.do(http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{
				"passphrase": passphrase, "passphrase_confirm": passphrase,
			}, nil)
		},
		func() error { return ac.stepUp(admin) },
		func() error {
			return ac.do(http.MethodPut, "/api/v1/settings/https", map[string]string{"cert_pem": string(certPEM), "key_pem": string(keyPEM)}, nil)
		},
		func() error { return ac.do(http.MethodPost, "/api/v1/setup/mail/skip", nil, nil) },
		func() error { return ac.do(http.MethodPost, "/api/v1/setup/evaluation", nil, nil) },
		func() error { return ac.do(http.MethodPost, "/api/v1/setup/complete", nil, nil) },
	}
	for _, o := range others {
		steps = append(steps, func() error {
			return ac.do(http.MethodPost, "/api/v1/users", map[string]string{
				"username": o.username, "display_name": "ZAP " + o.role, "email": "", "role": o.role, "password": o.password,
			}, nil)
		})
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, nil, err
		}
	}

	var out []Session
	for _, o := range others {
		c, err := newClient()
		if err != nil {
			return nil, nil, err
		}
		if err := c.signIn(o); err != nil {
			return nil, nil, err
		}
		s, err := c.session(o)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, s)
	}
	// The Administrator steps up last, so the scan starts with as much of the 5 minutes as possible.
	if err := ac.stepUp(admin); err != nil {
		return nil, nil, err
	}
	s, err := ac.session(admin)
	if err != nil {
		return nil, nil, err
	}
	return append([]Session{s}, out...), testCA, nil
}

// Write stores one <role>.env per session (mode 0600) and test-ca.crt in dir.
func Write(dir string, sessions []Session, testCA []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "test-ca.crt"), testCA, 0o644); err != nil { //nolint:gosec // G306: a public certificate
		return err
	}
	for _, s := range sessions {
		body := "COOKIE=" + sessionCookie + "=" + s.Cookie + "\nCSRF=" + s.CSRF + "\n"
		if err := os.WriteFile(filepath.Join(dir, s.Role+".env"), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) session(a *account) (Session, error) {
	u, _ := url.Parse(c.base + "/")
	for _, ck := range c.hc.Jar.Cookies(u) {
		if ck.Name == sessionCookie && ck.Value != "" && c.csrf != "" {
			return Session{Role: a.role, Username: a.username, Cookie: ck.Value, CSRF: c.csrf}, nil
		}
	}
	return Session{}, fmt.Errorf("%s: no %s cookie and CSRF token after the sign-in", a.username, sessionCookie)
}

// signIn signs a user in for the first time (TOTP enrolment) or again (TOTP).
func (c *client) signIn(a *account) error {
	var login struct {
		Status string `json:"status"`
	}
	if err := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": a.username, "password": a.password}, &login); err != nil {
		return err
	}
	switch login.Status {
	case "mfa_enrollment_required":
		var enr struct {
			Secret string `json:"secret"`
		}
		if err := c.do(http.MethodPost, "/api/v1/auth/mfa/enroll", nil, &enr); err != nil {
			return err
		}
		a.secret = enr.Secret
	case "mfa_required":
		if a.secret == "" {
			return fmt.Errorf("%s: TOTP is asked for but was never enrolled here", a.username)
		}
	default:
		return fmt.Errorf("%s: unexpected sign-in status %q", a.username, login.Status)
	}
	return c.do(http.MethodPost, "/api/v1/auth/mfa/verify", func() any { return map[string]string{"code": c.code(a)} }, nil)
}

func (c *client) stepUp(a *account) error {
	return c.do(http.MethodPost, "/api/v1/auth/stepup", func() any { return map[string]string{"code": c.code(a)} }, nil)
}

// code is a TOTP code for a step after the last one a used: Alice accepts one step either side of
// now and only steps after the last accepted one, so this waits when the window is used up.
func (c *client) code(a *account) string {
	for {
		now := c.clk.now().Unix() / 30
		step := max(now-1, a.last+1)
		if step <= now+1 {
			code, err := totp.GenerateCodeCustom(a.secret, time.Unix(step*30, 0), totp.ValidateOpts{
				Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
			})
			if err != nil {
				return "" // an unusable secret: Alice refuses the empty code and names the step
			}
			a.last = step
			return code
		}
		c.clk.sleep(time.Unix((step-1)*30, 0).Sub(c.clk.now()) + 200*time.Millisecond)
	}
}

// do sends one request as the web UI does (same-origin, CSRF token, activity marker) and decodes a
// 2xx answer into out. A body given as func() any is built per attempt (a TOTP code after a wait).
// A 429 is waited out (Retry-After). Error messages carry the method, path, status and Alice's
// error code, never a request body.
func (c *client) do(method, path string, body any, out any) error {
	for attempt := 0; ; attempt++ {
		b := body
		if f, ok := body.(func() any); ok {
			b = f()
		}
		var data []byte
		if b != nil {
			var err error
			if data, err = json.Marshal(b); err != nil {
				return err
			}
		}
		req, err := http.NewRequest(method, c.base+path, bytes.NewReader(data)) //nolint:noctx // a command-line tool with a client timeout
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-Alice-Activity", "1")
		if b != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.csrf != "" && method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
		res, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt < 20 {
			wait, _ := strconv.Atoi(res.Header.Get("Retry-After"))
			c.clk.sleep(time.Duration(max(wait, 1))*time.Second + 500*time.Millisecond)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode > 299 {
			var e struct {
				Error struct {
					Code   string `json:"code"`
					Reason string `json:"reason"`
				} `json:"error"`
			}
			_ = json.Unmarshal(raw, &e)
			return fmt.Errorf("%s %s: HTTP %d %s %s", method, path, res.StatusCode, e.Error.Code, e.Error.Reason)
		}
		var probe struct {
			CSRFToken string `json:"csrf_token"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.CSRFToken != "" {
			c.csrf = probe.CSRFToken
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("%s %s: %w", method, path, err)
			}
		}
		return nil
	}
}

// random is a 32-character secret from 24 random bytes.
func random() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(errors.Join(errors.New("zapsession: no randomness"), err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// issueHTTPS makes a throwaway CA and a server certificate it issues for host (and localhost and
// 127.0.0.1), valid for 90 days (testssl.sh warns below 30). The CA's key is dropped when this returns.
func issueHTTPS(now time.Time, host string) (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		return n
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Alice ZAP test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.Equal(leaf.IPAddresses[0]) {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		}
	} else if host != "localhost" {
		leaf.DNSNames = append(leaf.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
