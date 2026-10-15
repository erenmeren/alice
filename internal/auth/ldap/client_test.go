package ldap

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/ldap/ldapx"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

func pw(s string) secrets.Plaintext { return secrets.NewPlaintext([]byte(s)) }

func reasonOf(err error) (string, string) {
	var le *LoginError
	if errors.As(err, &le) {
		return le.Reason, le.Detail
	}
	return "", ""
}

// miniDirectory is a directory pointing at the in-process server and trusting its CA.
func miniDirectory(m *miniServer) Directory {
	return Directory{Name: "Mini", Addresses: []string{m.address()}, UserBaseDN: "ou=people,dc=example,dc=test",
		UserFilter: "(uid={login})", LoginAttribute: "uid", UniqueIDAttribute: "entryUUID", DisplayNameAttribute: "cn",
		EmailAttribute: "mail", BindDN: "cn=svc,dc=example,dc=test", GroupBaseDN: "ou=groups,dc=example,dc=test",
		GroupFilter: DefaultGroupFilter, GroupNameAttribute: "cn", CAPEM: string(m.ca.RootPEM), Enabled: true}
}

var adaEntry = miniEntry{dn: "uid=ada,ou=people,dc=example,dc=test", attrs: map[string][]string{"uid": {"ada"},
	"entryUUID": {"6f1c5b7e-0d3a-4c1e-9a55-1b2c3d4e5f60"}, "cn": {"Ada Lovelace"}, "mail": {"ada@example.test"}}}

func fastClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *netClient {
	return &netClient{dial: dial, limits: timeouts{dial: 2 * time.Second, operation: 2 * time.Second, verify: 5 * time.Second}}
}

func TestNetClientHappyPathAgainstTheMiniServer(t *testing.T) {
	m := startMini(t)
	m.set(func(m *miniServer) {
		m.entries = func(base, _ string) []miniEntry {
			if strings.HasPrefix(base, "ou=groups") {
				return []miniEntry{{dn: "cn=ops,ou=groups", attrs: map[string][]string{"cn": {"ops", "operators"}}},
					{dn: "cn=ops2,ou=groups", attrs: map[string][]string{"CN": {"ops"}}}}
			}
			return []miniEntry{adaEntry}
		}
	})
	d := miniDirectory(m)
	c := fastClient(nil)
	ctx := context.Background()
	e, err := c.Authenticate(ctx, d, pw("svc"), "ada", pw("secret"))
	require.NoError(t, err)
	assert.Equal(t, adaEntry.dn, e.DN)
	id, err := identityOf(d, e, "ada")
	require.NoError(t, err)
	assert.Equal(t, Identity{UniqueID: "36663163356237652d306433612d346331652d396135352d316232633364346535663630", Login: "ada",
		DisplayName: "Ada Lovelace", Email: "ada@example.test"}, id)
	groups, err := c.Groups(ctx, d, pw("svc"), e, "ada")
	require.NoError(t, err)
	assert.Equal(t, []string{"ops", "operators"}, groups, "values of every entry, case-insensitive attribute, no duplicates")
	d.GroupNameAttribute = ""
	groups, err = c.Groups(ctx, d, pw("svc"), e, "ada")
	require.NoError(t, err)
	assert.Equal(t, []string{"cn=ops,ou=groups", "cn=ops2,ou=groups"}, groups, "no attribute: the DNs")
	require.NoError(t, c.CheckConnection(ctx, d, pw("svc")))
	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, []string{d.BindDN, adaEntry.dn, d.BindDN, d.BindDN, d.BindDN}, m.binds)
	assert.Equal(t, "(uid=ada)", m.filters[0])
	assert.Equal(t, "(member=uid=ada,ou=people,dc=example,dc=test)", m.filters[1])
	assert.Equal(t, []int64{UserSizeLimit, GroupSizeLimit, GroupSizeLimit, 1}, m.sizeLimits)
}

func TestNetClientRefusesBeforeAnyTraffic(t *testing.T) {
	var dials atomic.Int64
	c := fastClient(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no")
	})
	d := Directory{Addresses: []string{"ldaps://ldap.example.test"}, UserFilter: "(uid={login})"}
	for _, x := range []struct {
		login, password, reason, detail string
	}{
		{"ada", "", ReasonBadCredentials, DetailPassword},
		{"ada", strings.Repeat("p", MaxPasswordBytes+1), ReasonBadCredentials, DetailPassword},
		{"", "p", ReasonLoginInvalid, DetailLoginName},
		{" ada", "p", ReasonLoginInvalid, DetailLoginName},
		{"a\x00da", "p", ReasonLoginInvalid, DetailLoginName},
		{"a\u200bda", "p", ReasonLoginInvalid, DetailLoginName},
		{"a\u202eda", "", ReasonLoginInvalid, DetailLoginName}, // the name rule comes first
		{"*", "p", ReasonBadCredentials, DetailLoginName},      // ErrFilterValue: no letter or digit
		{"---", "p", ReasonBadCredentials, DetailLoginName},
		{"*)(", "p", ReasonBadCredentials, DetailLoginName},
	} {
		_, err := c.Authenticate(context.Background(), d, pw("svc"), x.login, pw(x.password))
		r, det := reasonOf(err)
		assert.Equal(t, [2]string{x.reason, x.detail}, [2]string{r, det}, "%q", x.login)
	}
	// The order is the carry's: ValidLoginName before ExpandFilter. A name ExpandFilter alone would accept, but the
	// rule refuses, never becomes a filter.
	assert.True(t, ldapx.ValidLoginName("*"))
	_, ferr := ldapx.ExpandFilter("(uid={login})", map[string]string{"login": " ada"})
	assert.NoError(t, ferr, "ExpandFilter alone would send a name with a leading space")
	d.UserFilter = "(uid={login}"
	_, err := c.Authenticate(context.Background(), d, pw("svc"), "ada", pw("p"))
	r, det := reasonOf(err)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailUserSearch}, [2]string{r, det})
	assert.Zero(t, dials.Load(), "nothing was dialled")
}

func TestNetClientResults(t *testing.T) {
	m := startMini(t)
	d := miniDirectory(m)
	c := fastClient(nil)
	ctx := context.Background()
	check := func(err error, reason, detail string) {
		t.Helper()
		r, det := reasonOf(err)
		assert.Equal(t, [2]string{reason, detail}, [2]string{r, det}, "%v", err)
	}

	_, err := c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonBadCredentials, DetailNotFound)

	m.set(func(m *miniServer) {
		m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry, adaEntry} }
	})
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonAmbiguousUser, DetailUserSearch)

	// A server that ignores the size limit is cut by the client (EnforceSizeLimit).
	m.set(func(m *miniServer) {
		m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry, adaEntry, adaEntry, adaEntry} }
	})
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonAmbiguousUser, DetailUserSearch)

	// The server's own size limit result.
	m.set(func(m *miniServer) {
		m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry} }
		m.doneCode = goldap.LDAPResultSizeLimitExceeded
	})
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonAmbiguousUser, DetailUserSearch)

	// A referral result is a failure; nothing follows it.
	m.set(func(m *miniServer) { m.doneCode = goldap.LDAPResultReferral })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailUserSearch)

	m.set(func(m *miniServer) { m.doneCode = goldap.LDAPResultNoSuchObject })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailUserSearch)
	check(c.CheckConnection(ctx, d, pw("svc")), ReasonMisconfigured, DetailUserSearch)

	m.set(func(m *miniServer) { m.doneCode = goldap.LDAPResultBusy })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonUnreachable, DetailConnect)
	m.set(func(m *miniServer) { m.doneCode = goldap.LDAPResultTimeLimitExceeded })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonUnreachable, DetailTimeout)

	// Wrong password, other bind failures, the service account.
	m.set(func(m *miniServer) {
		m.doneCode = goldap.LDAPResultSuccess
		m.bindCode[adaEntry.dn] = goldap.LDAPResultInvalidCredentials
	})
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonBadCredentials, DetailUserBind)
	m.set(func(m *miniServer) { m.bindCode[adaEntry.dn] = goldap.LDAPResultUnwillingToPerform })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailUserBind)
	m.set(func(m *miniServer) { m.bindCode[d.BindDN] = goldap.LDAPResultInvalidCredentials })
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailServiceBind)
	_, err = c.Groups(ctx, d, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	check(err, ReasonMisconfigured, DetailServiceBind)
	_, err = c.Authenticate(ctx, d, secrets.Plaintext{}, "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailNoSecret)

	// An entry without a DN is never bound to.
	m.set(func(m *miniServer) {
		delete(m.bindCode, d.BindDN)
		m.entries = func(string, string) []miniEntry { return []miniEntry{{dn: "", attrs: adaEntry.attrs}} }
	})
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	check(err, ReasonMisconfigured, DetailUserSearch)

	// Groups: a bad template, the size limit, a failing search.
	bad := d
	bad.GroupFilter = "(member={dn}"
	_, err = c.Groups(ctx, bad, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	check(err, ReasonMisconfigured, DetailGroupSearch)
	many := make([]miniEntry, GroupSizeLimit+1)
	for i := range many {
		many[i] = miniEntry{dn: "cn=g,ou=groups", attrs: map[string][]string{"cn": {"g"}}}
	}
	m.set(func(m *miniServer) { m.entries = func(string, string) []miniEntry { return many } })
	_, err = c.Groups(ctx, d, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	check(err, ReasonMisconfigured, DetailSizeLimit)
	m.set(func(m *miniServer) {
		m.doneCode = goldap.LDAPResultInsufficientAccessRights
		m.entries = func(string, string) []miniEntry { return nil }
	})
	_, err = c.Groups(ctx, d, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	check(err, ReasonMisconfigured, DetailGroupSearch)
}

// Search references are collected by go-ldap and never followed: the referenced server is never dialled.
func TestReferencesAreNotFollowed(t *testing.T) {
	m := startMini(t)
	other := startMini(t)
	m.set(func(m *miniServer) {
		m.references = []string{other.address() + "/ou=people,dc=example,dc=test"}
		m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry} }
	})
	e, err := fastClient(nil).Authenticate(context.Background(), miniDirectory(m), pw("svc"), "ada", pw("p"))
	require.NoError(t, err)
	assert.Equal(t, adaEntry.dn, e.DN)
	assert.Zero(t, other.conns.Load(), "the referral was not followed")
}

func TestTimeouts(t *testing.T) {
	ctx := context.Background()
	// Accepts and never starts TLS: the dial timeout ends the handshake.
	m := startMini(t)
	m.set(func(m *miniServer) { m.noTLS = true })
	c := &netClient{limits: timeouts{dial: 300 * time.Millisecond, operation: 300 * time.Millisecond, verify: 5 * time.Second}}
	start := time.Now()
	_, err := c.Authenticate(ctx, miniDirectory(m), pw("svc"), "ada", pw("p"))
	r, det := reasonOf(err)
	assert.Equal(t, [2]string{ReasonUnreachable, DetailTimeout}, [2]string{r, det}, "%v", err)
	assert.Less(t, time.Since(start), 3*time.Second)

	// TLS completes, no LDAP answer: the operation timeout.
	m.set(func(m *miniServer) { m.noTLS, m.silent = false, true })
	start = time.Now()
	_, err = c.Authenticate(ctx, miniDirectory(m), pw("svc"), "ada", pw("p"))
	r, det = reasonOf(err)
	assert.Equal(t, [2]string{ReasonUnreachable, DetailTimeout}, [2]string{r, det}, "%v", err)
	assert.Less(t, time.Since(start), 3*time.Second)

	// The caller's context ends first: the connection is closed and the request fails at once.
	c.limits.operation = time.Minute
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = c.Authenticate(cctx, miniDirectory(m), pw("svc"), "ada", pw("p"))
	r, det = reasonOf(err)
	assert.Equal(t, [2]string{ReasonUnreachable, DetailTimeout}, [2]string{r, det}, "%v", err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || time.Since(start) < 3*time.Second)
	assert.Less(t, time.Since(start), 3*time.Second)
}

func TestTLSAndAddresses(t *testing.T) {
	m := startMini(t)
	m.set(func(m *miniServer) { m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry} } })
	ctx := context.Background()
	c := fastClient(nil)
	try := func(d Directory) (string, string) {
		_, err := c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
		return reasonOf(err)
	}
	d := miniDirectory(m)
	d.CAPEM = string(pki.NewCA("other", pki.ECDSA256, time.Now()).RootPEM)
	r, det := try(d)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailTLS}, [2]string{r, det}, "another authority")
	d.CAPEM = ""
	r, det = try(d)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailTLS}, [2]string{r, det}, "the system roots do not know the test CA")
	d.CAPEM = "not pem"
	r, det = try(d)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailTLS}, [2]string{r, det}, "a bundle without a certificate")

	// The host name is checked: the certificate names localhost and 127.0.0.1, not this name.
	d = miniDirectory(m)
	d.Addresses = []string{"ldaps://wrong.example.test:636"}
	c.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, m.ln.Addr().String())
	}
	r, det = try(d)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailTLS}, [2]string{r, det}, "wrong host name")
	c.dial = nil

	// A plain (non-TLS) LDAP server behind an ldaps:// address fails the handshake.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer plain.Close()
	go func() {
		for {
			conn, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("0\x84\x00\x00\x00\x10\x02\x01\x01a\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"))
			_ = conn.Close()
		}
	}()
	d = miniDirectory(m)
	d.Addresses = []string{"ldaps://" + plain.Addr().String()}
	r, det = try(d)
	assert.Equal(t, ReasonMisconfigured, r, det)

	// Addresses are tried in order: a dead first address moves on to the next.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := dead.Addr().String()
	require.NoError(t, dead.Close())
	d = miniDirectory(m)
	d.Addresses = []string{"ldaps://" + deadAddr, m.address()}
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	require.NoError(t, err)
	d.Addresses = []string{"ldaps://" + deadAddr}
	r, det = try(d)
	assert.Equal(t, [2]string{ReasonUnreachable, DetailConnect}, [2]string{r, det})
	d.Addresses = []string{"ldap://" + m.ln.Addr().String()}
	r, det = try(d)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailConnect}, [2]string{r, det}, "plain ldap:// is never dialled")
}

// The default dial is netaddr's: a link-local address (the cloud metadata service) is never connected; an injected
// dial replaces it.
func TestDialIsTheInjectedOne(t *testing.T) {
	ctx := context.Background()
	d := Directory{Addresses: []string{"ldaps://169.254.169.254:636"}, UserFilter: "(uid={login})"}
	_, err := fastClient(nil).Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	r, det := reasonOf(err)
	assert.Equal(t, [2]string{ReasonMisconfigured, DetailConnect}, [2]string{r, det}, "%v", err)

	m := startMini(t)
	m.set(func(m *miniServer) { m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry} } })
	var seen []string
	c := fastClient(func(ctx context.Context, network, addr string) (net.Conn, error) {
		seen = append(seen, addr)
		return (&net.Dialer{}).DialContext(ctx, network, m.ln.Addr().String())
	})
	d = miniDirectory(m)
	d.Addresses = []string{"ldaps://localhost:1636"}
	_, err = c.Authenticate(ctx, d, pw("svc"), "ada", pw("p"))
	require.NoError(t, err)
	assert.Equal(t, []string{"localhost:1636"}, seen, "the injected dial got the configured address")
}

func TestIdentityOf(t *testing.T) {
	d := Directory{LoginAttribute: "uid", UniqueIDAttribute: "objectGUID", DisplayNameAttribute: "displayName", EmailAttribute: ""}
	guid := []byte{0x01, 0x02, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0}
	id, err := identityOf(d, Entry{DN: "x", Attrs: map[string][][]byte{"objectGUID": {guid},
		"displayName": {[]byte(strings.Repeat("ş", 150))}}}, "typed")
	require.NoError(t, err)
	assert.Equal(t, "0102ff00102030405060708090a0b0c0", id.UniqueID, "binary objectGUID as hex")
	assert.Equal(t, "typed", id.Login, "no login attribute value: the typed name")
	assert.Equal(t, 100, len([]rune(id.DisplayName)))
	assert.Empty(t, id.Email)
	for _, attrs := range []map[string][][]byte{{}, {"objectGUID": {guid, guid}}, {"objectGUID": {{}}},
		{"objectGUID": {make([]byte, ldapx.MaxUniqueIDBytes+1)}}} {
		_, err := identityOf(d, Entry{Attrs: attrs}, "x")
		r, det := reasonOf(err)
		assert.Equal(t, [2]string{ReasonMisconfigured, DetailUniqueID}, [2]string{r, det})
	}
}

func TestLoginErrorText(t *testing.T) {
	cause := errors.New("cause")
	err := refuse(ReasonUnreachable, DetailTimeout, cause)
	assert.Equal(t, "ldap: the directory sign-in was refused (directory_unreachable)", err.Error())
	assert.ErrorIs(t, err, cause)
	assert.Nil(t, (*LoginError)(nil).orNil())
}

// Review fix: an unknown name does the same work as a wrong password: a bind with the typed password, here to a DN
// that does not exist, on the same connection; both end in the same reason.
func TestUnknownUserBindsLikeAWrongPassword(t *testing.T) {
	m := startMini(t)
	d := miniDirectory(m)
	c := fastClient(nil)
	_, errUnknown := c.Authenticate(context.Background(), d, pw("svc"), "nobody", pw("typed"))
	m.set(func(m *miniServer) {
		m.entries = func(string, string) []miniEntry { return []miniEntry{adaEntry} }
		m.bindCode[adaEntry.dn] = goldap.LDAPResultInvalidCredentials
	})
	_, errWrong := c.Authenticate(context.Background(), d, pw("svc"), "ada", pw("typed"))
	r1, _ := reasonOf(errUnknown)
	r2, _ := reasonOf(errWrong)
	assert.Equal(t, ReasonBadCredentials, r1)
	assert.Equal(t, r1, r2)
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Len(t, m.binds, 4)
	assert.Equal(t, d.BindDN, m.binds[0])
	assert.True(t, strings.HasPrefix(m.binds[1], "cn=alice-absent-") && strings.HasSuffix(m.binds[1], ","+d.UserBaseDN), m.binds[1])
	assert.Equal(t, []string{d.BindDN, adaEntry.dn}, m.binds[2:])
	assert.Equal(t, 2, len(m.filters), "one search each")
}

// Review fix: a directory cannot make Alice read more than MaxResponseBytes per connection, nor keep more than
// MaxAttributeValues values of an attribute.
func TestResponseByteAndValueLimits(t *testing.T) {
	m := startMini(t)
	d := miniDirectory(m)
	var conns []*countingConn
	var mu sync.Mutex
	c := fastClient(nil)
	c.limits.operation = 10 * time.Second
	c.seen = func(cc *countingConn) { mu.Lock(); conns = append(conns, cc); mu.Unlock() }
	check := func(name string, err error, reason, detail string) {
		t.Helper()
		r, det := reasonOf(err)
		assert.Equal(t, [2]string{reason, detail}, [2]string{r, det}, "%s: %v", name, err)
		mu.Lock()
		defer mu.Unlock()
		last := conns[len(conns)-1]
		assert.LessOrEqual(t, last.read.Load(), int64(MaxResponseBytes), name)
	}

	// An endless value: the read budget ends it long before the operation timeout.
	m.set(func(m *miniServer) { m.endless = true })
	start := time.Now()
	_, err := c.Authenticate(context.Background(), d, pw("svc"), "ada", pw("p"))
	check("endless", err, ReasonMisconfigured, DetailResponseSize)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Greater(t, m.sent.Load(), int64(MaxResponseBytes)/2, "the server really streamed")

	// One oversized attribute value.
	big := strings.Repeat("x", MaxResponseBytes+1024)
	m.set(func(m *miniServer) {
		m.endless = false
		m.entries = func(string, string) []miniEntry {
			return []miniEntry{{dn: adaEntry.dn, attrs: map[string][]string{"uid": {"ada"}, "cn": {big}}}}
		}
	})
	_, err = c.Authenticate(context.Background(), d, pw("svc"), "ada", pw("p"))
	check("oversized value", err, ReasonMisconfigured, DetailResponseSize)

	// Too many values of one attribute: in the user entry and in a group entry.
	many := make([]string, MaxAttributeValues+1)
	for i := range many {
		many[i] = "g" + strconv.Itoa(i)
	}
	m.set(func(m *miniServer) {
		m.entries = func(base, _ string) []miniEntry {
			if strings.HasPrefix(base, "ou=groups") {
				return []miniEntry{{dn: "cn=g,ou=groups", attrs: map[string][]string{"cn": many}}}
			}
			return []miniEntry{{dn: adaEntry.dn, attrs: map[string][]string{"uid": {"ada"}, "mail": many, "entryUUID": {"x"}}}}
		}
	})
	_, err = c.Authenticate(context.Background(), d, pw("svc"), "ada", pw("p"))
	check("user values", err, ReasonMisconfigured, DetailSizeLimit)
	_, err = c.Groups(context.Background(), d, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	check("group values", err, ReasonMisconfigured, DetailSizeLimit)
	// At the limit: accepted, deduplicated in order.
	m.set(func(m *miniServer) {
		m.entries = func(string, string) []miniEntry {
			return []miniEntry{{dn: "cn=g,ou=groups", attrs: map[string][]string{"cn": many[:MaxAttributeValues]}},
				{dn: "cn=h,ou=groups", attrs: map[string][]string{"cn": many[:2]}}}
		}
	})
	groups, err := c.Groups(context.Background(), d, pw("svc"), Entry{DN: adaEntry.dn}, "ada")
	require.NoError(t, err)
	assert.Equal(t, many[:MaxAttributeValues], groups)
}

func TestCountingConnStopsAtTheLimit(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { _, _ = b.Write(make([]byte, 100)); _ = b.Close() }()
	cc := &countingConn{Conn: a, limit: 10}
	buf := make([]byte, 64)
	n, err := cc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 10, n, "never more than the budget")
	assert.True(t, cc.exhausted())
	_, err = cc.Read(buf)
	assert.ErrorIs(t, err, errResponseTooLarge)
}
