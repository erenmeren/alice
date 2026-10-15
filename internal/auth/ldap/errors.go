package ldap

import "errors"

// Errors of the service.
var (
	ErrNotFound             = errors.New("ldap: not found")
	ErrVersion              = errors.New("ldap: the version does not match")
	ErrTooMany              = errors.New("ldap: too many directories or group mappings")
	ErrDirectoryInUse       = errors.New("ldap: people have signed in through the directory")
	ErrAdminMappingDisabled = errors.New("ldap: groups cannot be mapped to Administrator while SSO users may not be Admin")
	// ErrNoConnectionTest is returned by TestConnection when the client (a test double) cannot check a connection.
	ErrNoConnectionTest = errors.New("ldap: the client cannot test a connection")
)

// The closed set of LoginError reasons. The person signing in sees one generic answer for most of them; the audit
// record carries the reason.
const (
	ReasonBadCredentials = "bad_credentials"         // unknown user, wrong password, empty password
	ReasonAmbiguousUser  = "ambiguous_user"          // the user search found more than one entry
	ReasonUnreachable    = "directory_unreachable"   // no address answered in time
	ReasonMisconfigured  = "directory_misconfigured" // TLS, the service account, a base DN, a filter or an attribute
	ReasonDisabled       = "provider_disabled"       // the directory does not allow sign-in
	ReasonLoginInvalid   = "login_invalid"           // the sign-in name cannot be sent to a directory
)

// Details of a LoginError: where the attempt stopped. They never carry the server's text.
const (
	DetailConnect      = "connect"       // no address could be connected (refused, unreachable, refused by netaddr)
	DetailTimeout      = "timeout"       // an address or an operation took too long
	DetailTLS          = "tls"           // the certificate or the host name was not trusted
	DetailServiceBind  = "service_bind"  // the service account was refused
	DetailUserSearch   = "user_search"   // the user search failed (base DN, filter, permissions)
	DetailUserBind     = "user_bind"     // the user's bind failed other than with wrong credentials
	DetailGroupSearch  = "group_search"  // the group search failed
	DetailSizeLimit    = "size_limit"    // the group search returned more entries, or an attribute more values, than allowed
	DetailResponseSize = "response_size" // the directory sent more than MaxResponseBytes on one connection
	DetailUniqueID     = "unique_id"     // the entry has no usable unique id attribute
	DetailNoSecret     = "bind_unset"    // no service account password is stored
	DetailNotFound     = "not_found"     // the user search found no entry
	DetailPassword     = "password"      // the password was refused before any traffic (empty or too long)
	DetailLoginName    = "login_name"    // the sign-in name was refused before any traffic
)

// LoginError is a refused directory sign-in, connection test or sign-in test with its closed Reason and a Detail
// saying where it stopped. Error() names only the reason; the wrapped cause (a network or LDAP error, never a
// password) is for errors.Is and the server log.
type LoginError struct {
	Reason string
	Detail string
	cause  error
}

func (e *LoginError) Error() string {
	return "ldap: the directory sign-in was refused (" + e.Reason + ")"
}

// Unwrap returns the cause, so that errors.Is sees a context deadline.
func (e *LoginError) Unwrap() error { return e.cause }

func refuse(reason, detail string, cause error) *LoginError {
	return &LoginError{Reason: reason, Detail: detail, cause: cause}
}
