package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"alice/internal/auth/ldap/ldapx"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/pemca"
	"alice/internal/secrets"
)

// Entry is a directory entry: its DN and the raw values of the attributes Alice asked for, keyed by the configured
// attribute names.
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

// Client talks to a directory. Every failure is a *LoginError. The bind password and the user's password are the
// caller's: the client never keeps or zeroes them.
type Client interface {
	// Authenticate binds as the service account, finds exactly one entry with the user filter and binds as it with
	// password. An empty password never reaches the directory.
	Authenticate(ctx context.Context, d Directory, bindPassword secrets.Plaintext, login string, password secrets.Plaintext) (Entry, error)
	// Groups binds as the service account and runs the group search for user.
	Groups(ctx context.Context, d Directory, bindPassword secrets.Plaintext, user Entry, login string) ([]string, error)
}

// ConnectionChecker is a Client that can also check the settings without a user: the service account bind and one
// search of the user base DN (Test connection). The real client implements it.
type ConnectionChecker interface {
	CheckConnection(ctx context.Context, d Directory, bindPassword secrets.Plaintext) error
}

// netClient is the real client: ldaps:// only, TLS 1.2 or later verified against the system roots plus the
// directory's PEM authority with the address's host name, every connection through the injected dial (netaddr by
// default), referrals never followed (go-ldap does not chase them; a search reference is ignored and a referral
// result is a failure), size and time limits on every search.
type netClient struct {
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	limits timeouts
	// Test seams: responseLimit replaces MaxResponseBytes when positive; seen gets every counting connection.
	responseLimit int64
	seen          func(*countingConn)
}

var (
	_ Client            = (*netClient)(nil)
	_ ConnectionChecker = (*netClient)(nil)
)

func (c *netClient) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.dial != nil {
		return c.dial
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return netaddr.DialContext(ctx, &net.Dialer{Timeout: c.limits.dial}, network, addr)
	}
}

// Response limits: a directory's answers are small (one user entry, at most GroupSizeLimit group entries). A hostile
// or broken directory could otherwise stream gigabytes within the operation timeout, or one attribute with millions of
// values that go-ldap would hold in memory.
const (
	// MaxResponseBytes is the most a connection reads from a directory (TLS records included), counted below TLS.
	MaxResponseBytes = 8 << 20
	// MaxAttributeValues is the most values of one attribute Alice reads from an entry.
	MaxAttributeValues = 5000
)

var errResponseTooLarge = errors.New("ldap: the directory's response exceeds the size limit")

// countingConn counts the bytes read from the network and fails every read once MaxResponseBytes (limit) have been
// read: go-ldap's reader then ends the connection and the pending request fails.
type countingConn struct {
	net.Conn
	limit int64
	read  atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	left := c.limit - c.read.Load()
	if left <= 0 {
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// exhausted reports whether the connection read its whole budget.
func (c *countingConn) exhausted() bool { return c.read.Load() >= c.limit }

// conn is an open, started LDAP connection; close it exactly once.
type conn struct {
	l    *goldap.Conn
	raw  *countingConn
	stop func() bool
}

func (c conn) close() {
	c.stop()
	_ = c.l.Close()
}

// connect opens the first address that answers and passes the TLS checks, in the configured order. A refused or
// unreachable address moves on to the next; the error is the last address's.
func (c *netClient) connect(ctx context.Context, d Directory) (conn, error) {
	roots, ok := pemca.Pool(d.CAPEM)
	if !ok {
		return conn{}, refuse(ReasonMisconfigured, DetailTLS, nil)
	}
	last := refuse(ReasonMisconfigured, DetailConnect, nil) // no address (cannot happen after validation)
	for _, addr := range d.Addresses {
		host, port, ok := splitAddress(addr)
		if !ok {
			last = refuse(ReasonMisconfigured, DetailConnect, nil)
			continue
		}
		l, raw, err := c.open(ctx, host, port, roots)
		if err != nil {
			last = err
			continue
		}
		l.SetTimeout(c.limits.operation)
		// The context bounds the whole exchange: when it ends, the connection is closed and the pending request fails.
		stop := context.AfterFunc(ctx, func() { _ = l.Close() })
		return conn{l: l, raw: raw, stop: stop}, nil
	}
	return conn{}, last
}

// open dials one address and completes the TLS handshake within the dial timeout.
func (c *netClient) open(ctx context.Context, host string, port int, roots *x509.CertPool) (*goldap.Conn, *countingConn, *LoginError) {
	dctx, cancel := context.WithTimeout(ctx, c.limits.dial)
	defer cancel()
	nc, err := c.dialer()(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, dialError(dctx, err)
	}
	raw := &countingConn{Conn: nc, limit: c.maxResponse()}
	if c.seen != nil {
		c.seen(raw)
	}
	tc := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host})
	if err := tc.HandshakeContext(dctx); err != nil {
		_ = nc.Close()
		return nil, nil, tlsError(dctx, err)
	}
	l := goldap.NewConn(tc, true)
	l.Start()
	return l, raw, nil
}

func (c *netClient) maxResponse() int64 {
	if c.responseLimit > 0 {
		return c.responseLimit
	}
	return MaxResponseBytes
}

func dialError(ctx context.Context, err error) *LoginError {
	var ne net.Error
	switch {
	case errors.Is(err, netaddr.ErrNotAllowed):
		// The address resolves to one Alice never connects to (link-local, metadata, multicast...).
		return refuse(ReasonMisconfigured, DetailConnect, err)
	case ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout():
		return refuse(ReasonUnreachable, DetailTimeout, err)
	default:
		return refuse(ReasonUnreachable, DetailConnect, err)
	}
}

func tlsError(ctx context.Context, err error) *LoginError {
	var (
		verify *tls.CertificateVerificationError
		host   x509.HostnameError
		auth   x509.UnknownAuthorityError
		inval  x509.CertificateInvalidError
		record tls.RecordHeaderError
		alert  tls.AlertError
		ne     net.Error
	)
	switch {
	case errors.As(err, &verify), errors.As(err, &host), errors.As(err, &auth), errors.As(err, &inval), errors.As(err, &record),
		errors.As(err, &alert):
		return refuse(ReasonMisconfigured, DetailTLS, err)
	case ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout():
		return refuse(ReasonUnreachable, DetailTimeout, err)
	default:
		return refuse(ReasonUnreachable, DetailConnect, err)
	}
}

// opError classifies a failed bind or search: a network failure or a timeout is directory_unreachable, any LDAP result
// is directory_misconfigured with detail (the caller handles the results that mean something else first).
func opError(ctx context.Context, err error, detail string, late bool) *LoginError {
	var le *goldap.Error
	switch {
	case ctx.Err() != nil:
		return refuse(ReasonUnreachable, DetailTimeout, err)
	case errors.As(err, &le) && le.ResultCode == goldap.ErrorNetwork:
		if late {
			return refuse(ReasonUnreachable, DetailTimeout, err)
		}
		return refuse(ReasonUnreachable, DetailConnect, err)
	case errors.As(err, &le) && (le.ResultCode == goldap.LDAPResultTimeLimitExceeded || le.ResultCode == goldap.LDAPResultTimeout):
		return refuse(ReasonUnreachable, DetailTimeout, err)
	case errors.As(err, &le) && (le.ResultCode == goldap.LDAPResultBusy || le.ResultCode == goldap.LDAPResultUnavailable):
		return refuse(ReasonUnreachable, DetailConnect, err)
	default:
		return refuse(ReasonMisconfigured, detail, err)
	}
}

// do runs one LDAP request and classifies its failure: first by special (the results that mean something else for
// this request; nil: none), then by opError. late is set when the request ran into (nearly) the operation timeout, so
// that go-ldap's network error for a timed-out request reads as a timeout.
func (c *netClient) do(ctx context.Context, cn conn, detail string, f func() error, special func(error) *LoginError) error {
	var late atomic.Bool
	timer := time.AfterFunc(c.limits.operation*9/10, func() { late.Store(true) })
	err := f()
	timer.Stop()
	if err == nil {
		return nil
	}
	if cn.raw != nil && cn.raw.exhausted() {
		// The directory sent more than MaxResponseBytes: a setting (a base DN or filter that returns far too much) or
		// a hostile server; either way the Administrator's to look at.
		return refuse(ReasonMisconfigured, DetailResponseSize, err)
	}
	if special != nil {
		if le := special(err); le != nil {
			return le
		}
	}
	return opError(ctx, err, detail, late.Load())
}

// serviceBind binds as the directory's service account. Any refusal is directory_misconfigured: the person signing
// in is never told the service account failed.
func (c *netClient) serviceBind(ctx context.Context, cn conn, d Directory, bindPassword secrets.Plaintext) error {
	if len(bindPassword.Bytes()) == 0 {
		return refuse(ReasonMisconfigured, DetailNoSecret, nil)
	}
	return c.do(ctx, cn, DetailServiceBind, func() error {
		_, err := cn.l.SimpleBind(&goldap.SimpleBindRequest{Username: d.BindDN, Password: string(bindPassword.Bytes())})
		return err
	}, nil)
}

func (c *netClient) timeLimit() int { return max(1, int(c.limits.operation.Seconds())) }

// userAttributes are the attributes the user search asks for: only the configured ones.
func userAttributes(d Directory) []string {
	var out []string
	for _, a := range []string{d.LoginAttribute, d.UniqueIDAttribute, d.DisplayNameAttribute, d.EmailAttribute} {
		if a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func isSizeLimit(err error) bool {
	return errors.Is(err, goldap.ErrSizeLimitExceeded) || goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded)
}

// Authenticate implements Client.
func (c *netClient) Authenticate(ctx context.Context, d Directory, bindPassword secrets.Plaintext, login string,
	password secrets.Plaintext,
) (Entry, error) {
	// Before any traffic: the sign-in name rule first, then the template (ErrFilterValue is a bad name), then the
	// password.
	if lerr := checkCredentials(login, password); lerr != nil {
		return Entry{}, lerr
	}
	filter, err := ldapx.ExpandFilter(d.UserFilter, map[string]string{ldapx.PlaceholderLogin: login})
	switch {
	case errors.Is(err, ldapx.ErrFilterValue):
		return Entry{}, refuse(ReasonBadCredentials, DetailLoginName, nil)
	case err != nil:
		return Entry{}, refuse(ReasonMisconfigured, DetailUserSearch, nil)
	}
	cn, err := c.connect(ctx, d)
	if err != nil {
		return Entry{}, err
	}
	defer cn.close()
	if err := c.serviceBind(ctx, cn, d, bindPassword); err != nil {
		return Entry{}, err
	}
	var res *goldap.SearchResult
	err = c.do(ctx, cn, DetailUserSearch, func() (err error) {
		res, err = cn.l.Search(&goldap.SearchRequest{BaseDN: d.UserBaseDN, Scope: goldap.ScopeWholeSubtree,
			DerefAliases: goldap.NeverDerefAliases, SizeLimit: UserSizeLimit, TimeLimit: c.timeLimit(), Filter: filter,
			Attributes: userAttributes(d), EnforceSizeLimit: true})
		return err
	}, func(err error) *LoginError {
		if isSizeLimit(err) {
			return refuse(ReasonAmbiguousUser, DetailUserSearch, nil)
		}
		return nil
	})
	switch {
	case err != nil:
		return Entry{}, err
	case len(res.Entries) == 0:
		// The same answer as a wrong password, after the same work: a bind with the typed password to a DN that does
		// not exist, on this connection (the same verified TLS session to the same directory), so an unknown name
		// takes as long as a wrong password (on AD including the forwarding to the PDC). Its result is ignored; no
		// account exists that it could lock.
		absent := "cn=alice-absent-" + uuid.NewString() + "," + d.UserBaseDN
		_ = c.do(ctx, cn, DetailUserBind, func() error {
			_, err := cn.l.SimpleBind(&goldap.SimpleBindRequest{Username: absent, Password: string(password.Bytes())})
			return err
		}, nil)
		return Entry{}, refuse(ReasonBadCredentials, DetailNotFound, nil)
	case len(res.Entries) > 1:
		return Entry{}, refuse(ReasonAmbiguousUser, DetailUserSearch, nil)
	}
	e := res.Entries[0]
	if e.DN == "" {
		// A bind with an empty DN and a password is an unauthenticated bind on some servers: never.
		return Entry{}, refuse(ReasonMisconfigured, DetailUserSearch, nil)
	}
	if err := c.do(ctx, cn, DetailUserBind, func() error {
		_, err := cn.l.SimpleBind(&goldap.SimpleBindRequest{Username: e.DN, Password: string(password.Bytes())})
		return err
	}, func(err error) *LoginError {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return refuse(ReasonBadCredentials, DetailUserBind, nil)
		}
		return nil
	}); err != nil {
		return Entry{}, err
	}
	out := Entry{DN: e.DN, Attrs: map[string][][]byte{}}
	for _, a := range userAttributes(d) {
		v := e.GetEqualFoldRawAttributeValues(a)
		if len(v) > MaxAttributeValues {
			return Entry{}, refuse(ReasonMisconfigured, DetailSizeLimit, nil)
		}
		if len(v) > 0 {
			out.Attrs[a] = v
		}
	}
	return out, nil
}

// Groups implements Client: the values of the group name attribute of every entry the group search returns (or
// the entries' DNs when the attribute is empty), without duplicates, in the order found. More than GroupSizeLimit
// entries is directory_misconfigured (size_limit): a cut list would give a role by chance.
func (c *netClient) Groups(ctx context.Context, d Directory, bindPassword secrets.Plaintext, user Entry, login string) ([]string, error) {
	filter, err := ldapx.ExpandFilter(d.GroupFilter, map[string]string{ldapx.PlaceholderDN: user.DN, ldapx.PlaceholderLogin: login})
	if err != nil {
		return nil, refuse(ReasonMisconfigured, DetailGroupSearch, nil)
	}
	cn, err := c.connect(ctx, d)
	if err != nil {
		return nil, err
	}
	defer cn.close()
	if err := c.serviceBind(ctx, cn, d, bindPassword); err != nil {
		return nil, err
	}
	attrs := []string{"1.1"} // RFC 4511: no attributes
	if d.GroupNameAttribute != "" {
		attrs = []string{d.GroupNameAttribute}
	}
	var res *goldap.SearchResult
	if err := c.do(ctx, cn, DetailGroupSearch, func() (err error) {
		res, err = cn.l.Search(&goldap.SearchRequest{BaseDN: d.GroupBaseDN, Scope: goldap.ScopeWholeSubtree,
			DerefAliases: goldap.NeverDerefAliases, SizeLimit: GroupSizeLimit, TimeLimit: c.timeLimit(), Filter: filter,
			Attributes: attrs, EnforceSizeLimit: true})
		return err
	}, func(err error) *LoginError {
		if isSizeLimit(err) {
			return refuse(ReasonMisconfigured, DetailSizeLimit, nil)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	groups, seen := []string{}, map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			groups = append(groups, v)
		}
	}
	for _, e := range res.Entries {
		if d.GroupNameAttribute == "" {
			add(e.DN)
			continue
		}
		vals := e.GetEqualFoldAttributeValues(d.GroupNameAttribute)
		if len(vals) > MaxAttributeValues {
			return nil, refuse(ReasonMisconfigured, DetailSizeLimit, nil)
		}
		for _, v := range vals {
			add(v)
		}
	}
	return groups, nil
}

// CheckConnection implements ConnectionChecker: the service account bind and a base search of the user base DN.
func (c *netClient) CheckConnection(ctx context.Context, d Directory, bindPassword secrets.Plaintext) error {
	cn, err := c.connect(ctx, d)
	if err != nil {
		return err
	}
	defer cn.close()
	if err := c.serviceBind(ctx, cn, d, bindPassword); err != nil {
		return err
	}
	return c.do(ctx, cn, DetailUserSearch, func() error {
		_, err := cn.l.Search(&goldap.SearchRequest{BaseDN: d.UserBaseDN, Scope: goldap.ScopeBaseObject,
			DerefAliases: goldap.NeverDerefAliases, SizeLimit: 1, TimeLimit: c.timeLimit(), Filter: "(objectClass=*)",
			Attributes: []string{"1.1"}, EnforceSizeLimit: true})
		return err
	}, nil)
}

// identityOf reads the identity from an authenticated entry: the unique id (required: directory_misconfigured
// without one), the sign-in name attribute (the typed name when the entry has none), the display name (cut to 100
// runes) and the e-mail.
func identityOf(d Directory, e Entry, login string) (Identity, error) {
	raw := e.Attrs[d.UniqueIDAttribute]
	if len(raw) != 1 {
		return Identity{}, refuse(ReasonMisconfigured, DetailUniqueID, nil)
	}
	uid, err := ldapx.UniqueID(raw[0])
	if err != nil {
		return Identity{}, refuse(ReasonMisconfigured, DetailUniqueID, err)
	}
	first := func(attr string) string {
		if attr == "" || len(e.Attrs[attr]) == 0 {
			return ""
		}
		return string(e.Attrs[attr][0])
	}
	id := Identity{UniqueID: uid, Login: first(d.LoginAttribute), DisplayName: first(d.DisplayNameAttribute), Email: first(d.EmailAttribute)}
	if id.Login == "" {
		id.Login = login
	}
	if r := []rune(id.DisplayName); len(r) > maxDisplayRunes {
		id.DisplayName = string(r[:maxDisplayRunes])
	}
	return id, nil
}

// maxDisplayRunes is the longest display name kept (plan ruling 4).
const maxDisplayRunes = 100
