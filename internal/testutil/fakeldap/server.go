//go:build integration

// Package fakeldap gives integration tests a real OpenLDAP over ldaps:// (testcontainers): a CA and a server
// certificate generated at start, the memberOf overlay on groupOfNames/member, a read-only service account and a
// fixed set of people and groups (ada, a Turkish-named user, a user in no group, a login that two entries share, a
// nested group, a posixGroup, a referral). One container serves every test of a process; Stop removes it.
//
// What OpenLDAP cannot show: the Active Directory matching rule for nested groups (1.2.840.113556.1.4.1941) and the
// binary objectGUID. The tests use entryUUID (an ASCII string) as the unique id.
package fakeldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// Names of the directory tree.
const (
	BaseDN        = "dc=example,dc=test"
	PeopleDN      = "ou=people," + BaseDN
	ContractorsDN = "ou=contractors," + PeopleDN
	GroupsDN      = "ou=groups," + BaseDN
	ServicesDN    = "ou=services," + BaseDN
	ServiceDN     = "cn=alice-svc," + ServicesDN
	AdminDN       = "cn=admin," + BaseDN
	OpsDN         = "cn=alice-ops," + GroupsDN      // members: ada and the nested group alice-auditors
	AuditorsDN    = "cn=alice-auditors," + GroupsDN // member: çiğdem
	PosixDN       = "cn=alice-posix," + GroupsDN    // posixGroup, memberUid: ada

	// UserFilter and GroupFilter are the generic LDAP settings that fit this tree.
	UserFilter  = "(&(objectClass=inetOrgPerson)(uid={login}))"
	GroupFilter = "(&(objectClass=groupOfNames)(member={dn}))"

	// ServerName is the extra DNS name of the server certificate (besides localhost, 127.0.0.1 and ::1).
	ServerName = "ldap.example.test"

	servicePassword = "svc-Pa55-0f-the-service" //nolint:gosec // G101: password of a throw-away test container
	adminPassword   = "admin-Pa55-container"    //nolint:gosec // G101: password of a throw-away test container
)

// User is a person in the directory.
type User struct {
	Login, DN, CN, Mail, Password string
}

// The people of the tree. Dup's login is shared by two entries (the second under ou=contractors). The passwords are
// those of a throw-away test container.
//
//nolint:gosec // G101: fixed passwords of a throw-away test container
var (
	Ada    = User{Login: "ada", DN: "uid=ada," + PeopleDN, CN: "Ada Lovelace", Mail: "ada@example.test", Password: "ada-Analytical-1843"}
	Cigdem = User{Login: "çiğdem", DN: "uid=çiğdem," + PeopleDN, CN: "Çiğdem Öztürk", Mail: "cigdem@example.test", Password: "çiğ-Şifre-2026"}
	Grace  = User{Login: "grace", DN: "uid=grace," + PeopleDN, CN: "Grace Hopper", Mail: "grace@example.test", Password: "grace-COBOL-1959"}
	Dup    = User{Login: "dup", DN: "uid=dup," + PeopleDN, CN: "Dup One", Mail: "dup@example.test", Password: "dup-Twice-1"}
	Dup2   = User{Login: "dup", DN: "uid=dup," + ContractorsDN, CN: "Dup Two", Mail: "dup2@example.test", Password: "dup-Twice-2"}
)

// Server is the running directory.
type Server struct {
	Host    string // the address tests dial (normally localhost)
	Port    int    // the mapped ldaps port
	Address string // ldaps://Host:Port
	CAPEM   []byte // the root of the server certificate's chain

	ctr testcontainers.Container
}

// ServicePassword is the service account's password.
func (s *Server) ServicePassword() string { return servicePassword }

// Endpoint is host:port of the ldaps listener.
func (s *Server) Endpoint() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

var (
	once    sync.Once
	shared  *Server
	errOnce error
)

// Start returns the process's directory, starting it on the first call.
func Start(t testing.TB) *Server {
	t.Helper()
	once.Do(func() { shared, errOnce = start() })
	if errOnce != nil {
		t.Fatalf("fakeldap: %v", errOnce)
	}
	return shared
}

// Stop removes the container (call it after the tests, from TestMain).
func Stop() {
	if shared != nil && shared.ctr != nil {
		_ = testcontainers.TerminateContainer(shared.ctr)
	}
}

func start() (*Server, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	now := clock.Real{}.Now()
	ca := pki.NewCA("fakeldap", pki.RSA2048, now)
	leaf := ca.Issue(pki.Opts{CommonName: ServerName, SANs: []string{ServerName, "localhost", "127.0.0.1", "::1"}, KeyType: pki.RSA2048}, now)
	certs := "/container/service/slapd/assets/certs/"
	req := testcontainers.ContainerRequest{
		Image: "osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28",
		Env: map[string]string{
			"LDAP_ORGANISATION": "Example", "LDAP_DOMAIN": "example.test", "LDAP_ADMIN_PASSWORD": adminPassword,
			"LDAP_TLS": "true", "LDAP_TLS_CRT_FILENAME": "ldap.crt", "LDAP_TLS_KEY_FILENAME": "ldap.key",
			"LDAP_TLS_CA_CRT_FILENAME": "ca.crt", "LDAP_TLS_VERIFY_CLIENT": "never", "LDAP_TLS_ENFORCE": "false",
		},
		Files: []testcontainers.ContainerFile{
			{Reader: strings.NewReader(string(leaf.FullchainPEM)), ContainerFilePath: certs + "ldap.crt", FileMode: 0o644},
			{Reader: strings.NewReader(string(leaf.KeyPEM)), ContainerFilePath: certs + "ldap.key", FileMode: 0o644},
			{Reader: strings.NewReader(string(ca.RootPEM)), ContainerFilePath: certs + "ca.crt", FileMode: 0o644},
			{Reader: strings.NewReader(configLDIF), ContainerFilePath: "/tmp/alice-config.ldif", FileMode: 0o644},
		},
		ExposedPorts: []string{"636/tcp"},
		WaitingFor: wait.ForAll(wait.ForLog("slapd starting").WithOccurrence(1), wait.ForListeningPort("636/tcp")).
			WithDeadline(2 * time.Minute),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		if ctr != nil {
			_ = testcontainers.TerminateContainer(ctr)
		}
		return nil, fmt.Errorf("start the OpenLDAP container: %w", err)
	}
	s := &Server{CAPEM: ca.RootPEM, ctr: ctr}
	fail := func(err error) (*Server, error) {
		_ = testcontainers.TerminateContainer(ctr)
		return nil, err
	}
	if s.Host, err = ctr.Host(ctx); err != nil {
		return fail(err)
	}
	if err := leaf.Cert.VerifyHostname(s.Host); err != nil {
		return fail(fmt.Errorf("the docker host %q is not in the test certificate: %w", s.Host, err))
	}
	endpoint, err := ctr.PortEndpoint(ctx, "636/tcp", "")
	if err != nil {
		return fail(err)
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fail(err)
	}
	if s.Port, err = strconv.Atoi(port); err != nil {
		return fail(err)
	}
	s.Address = "ldaps://" + s.Endpoint()
	if err := s.configure(ctx); err != nil {
		return fail(err)
	}
	if err := s.seed(ctx); err != nil {
		return fail(err)
	}
	return s, nil
}

// configLDIF moves the memberOf overlay to groupOfNames/member and lets the service account read the tree.
const configLDIF = `dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcMemberOfGroupOC
olcMemberOfGroupOC: groupOfNames
-
replace: olcMemberOfMemberAD
olcMemberOfMemberAD: member

dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {2}
-
add: olcAccess
olcAccess: {2}to * by self read by dn.exact="cn=admin,dc=example,dc=test" write by dn.exact="cn=alice-svc,ou=services,dc=example,dc=test" read by * none
`

// configure applies configLDIF through the container's ldapi socket, retrying while slapd finishes its first start.
func (s *Server) configure(ctx context.Context) error {
	var last string
	for range 60 {
		code, r, err := s.ctr.Exec(ctx, []string{"ldapmodify", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/tmp/alice-config.ldif"})
		if err == nil && code == 0 {
			return nil
		}
		if r != nil {
			b := new(strings.Builder)
			buf := make([]byte, 4096)
			n, _ := r.Read(buf)
			b.Write(buf[:n])
			last = b.String()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("configure slapd: %s", last)
}

// TLSConfig trusts the server's CA.
func (s *Server) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CAPEM)
	return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

// admin connects as the directory's administrator, retrying while slapd starts.
func (s *Server) admin(ctx context.Context) (*ldap.Conn, error) {
	var last error
	for range 60 {
		l, err := ldap.DialURL(s.Address, ldap.DialWithTLSConfig(s.TLSConfig()))
		if err == nil {
			if err = l.Bind(AdminDN, adminPassword); err == nil {
				return l, nil
			}
			_ = l.Close()
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("bind as the administrator: %w", last)
}

// Admin is a connection bound as the administrator, closed when the test ends.
func (s *Server) Admin(t testing.TB) *ldap.Conn {
	t.Helper()
	l, err := s.admin(context.Background())
	if err != nil {
		t.Fatalf("fakeldap: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// Add adds one entry as the administrator; an entry that exists already is left as it is.
func (s *Server) Add(t testing.TB, dn string, attrs map[string][]string) {
	t.Helper()
	if err := add(s.Admin(t), dn, attrs); err != nil {
		t.Fatalf("fakeldap: add %s: %v", dn, err)
	}
}

func add(l *ldap.Conn, dn string, attrs map[string][]string) error {
	r := ldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		r.Attribute(k, v)
	}
	err := l.Add(r)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return nil
	}
	return err
}

type entry struct {
	dn    string
	attrs map[string][]string
}

func person(u User, sn string) entry {
	return entry{u.DN, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {u.Login}, "cn": {u.CN}, "sn": {sn},
		"mail": {u.Mail}, "userPassword": {u.Password}}}
}

func ou(dn, name string) entry {
	return entry{dn, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {name}}}
}

// Entries is the fixed tree, parents first.
func entries() []entry {
	return []entry{
		ou(PeopleDN, "people"), ou(ContractorsDN, "contractors"), ou(GroupsDN, "groups"), ou(ServicesDN, "services"),
		{ServiceDN, map[string][]string{"objectClass": {"organizationalRole", "simpleSecurityObject"}, "cn": {"alice-svc"},
			"userPassword": {servicePassword}}},
		person(Ada, "Lovelace"), person(Cigdem, "Öztürk"), person(Grace, "Hopper"), person(Dup, "One"), person(Dup2, "Two"),
		{AuditorsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"alice-auditors"}, "member": {Cigdem.DN}}},
		{OpsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"alice-ops"}, "member": {Ada.DN, AuditorsDN}}},
		{PosixDN, map[string][]string{"objectClass": {"posixGroup"}, "cn": {"alice-posix"}, "gidNumber": {"5000"},
			"memberUid": {Ada.Login}}},
	}
}

func (s *Server) seed(ctx context.Context) error {
	l, err := s.admin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	for _, e := range entries() {
		if err := add(l, e.dn, e.attrs); err != nil {
			return fmt.Errorf("add %s: %w", e.dn, err)
		}
	}
	return nil
}

// EntryUUID reads an entry's entryUUID as the administrator.
func (s *Server) EntryUUID(t testing.TB, dn string) string {
	t.Helper()
	res, err := s.Admin(t).Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
		"(objectClass=*)", []string{"entryUUID"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("fakeldap: read the entryUUID of %s: %v", dn, err)
	}
	return res.Entries[0].GetAttributeValue("entryUUID")
}
