package ldap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/auth/ldap/ldapx"
	"alice/internal/platform/db"
	"alice/internal/platform/pemca"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// Filter templates Alice offers (the UI's defaults; plan ruling 8, spec section 3).
const (
	DefaultGroupFilter = "(member={dn})"
	// ADGroupFilter returns nested groups too (LDAP_MATCHING_RULE_IN_CHAIN); OpenLDAP does not implement the rule.
	ADGroupFilter = "(member:1.2.840.113556.1.4.1941:={dn})"
)

// Validation limits of a directory, the same as migrations/00015_ldap.sql.
const (
	maxNameRunes     = 60
	maxAddresses     = 3
	maxAddressBytes  = 255
	maxDNRunes       = 1024
	maxFilterBytes   = 1024
	maxBindPassBytes = 1024
	maxHostBytes     = 253
	addressScheme    = "ldaps://"
	nameIndex        = "ldap_directories_name"
	foreignKeyCode   = "23503"
	directoriesLock  = "alice.ldap.directories"
)

var (
	attributeRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]{0,99}|[0-9]{1,10}(\.[0-9]{1,10}){1,30})$`)
	hostLabelRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// Directory is a configured directory; it never carries the service account password.
type Directory struct {
	ID                   uuid.UUID
	Name                 string
	Addresses            []string // 1 to 3 ldaps://host[:port], tried in order
	UserBaseDN           string
	UserFilter           string // holds {login} once
	LoginAttribute       string
	UniqueIDAttribute    string
	DisplayNameAttribute string // "": none
	EmailAttribute       string // "": none
	BindDN               string
	BindPasswordSet      bool
	GroupBaseDN          string
	GroupFilter          string // holds {dn} or {login}
	GroupNameAttribute   string // "": the group entry's DN is the group value
	CAPEM                string
	MFARequired          bool
	Enabled              bool
	Version              int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// DirectoryInput creates a directory. The caller owns and zeroes BindPassword.
type DirectoryInput struct {
	Name                 string
	Addresses            []string
	UserBaseDN           string
	UserFilter           string
	LoginAttribute       string
	UniqueIDAttribute    string
	DisplayNameAttribute string
	EmailAttribute       string
	BindDN               string
	BindPassword         secrets.Plaintext // required
	GroupBaseDN          string
	GroupFilter          string // "": DefaultGroupFilter
	GroupNameAttribute   string
	CAPEM                string
	MFARequired          *bool // nil: on (the default)
	Enabled              bool  // false: created switched off
}

// DirectoryPatch changes selected fields; nil fields stay. The caller owns and zeroes BindPassword. A patch that adds
// an address or changes the bind DN or the unique id attribute needs BindPassword again, so the stored password is
// never sent to another server or account.
type DirectoryPatch struct {
	Name                 *string
	Addresses            *[]string
	UserBaseDN           *string
	UserFilter           *string
	LoginAttribute       *string
	UniqueIDAttribute    *string
	DisplayNameAttribute *string
	EmailAttribute       *string
	BindDN               *string
	BindPassword         *secrets.Plaintext
	GroupBaseDN          *string
	GroupFilter          *string
	GroupNameAttribute   *string
	CAPEM                *string
	MFARequired          *bool
	Enabled              *bool
}

// PublicDirectory is what the sign-in page's "Sign in to" list shows.
type PublicDirectory struct {
	ID   uuid.UUID
	Name string
}

const directoryColumns = `d.id, d.name, d.addresses, d.user_base_dn, d.user_filter, d.login_attribute, d.unique_id_attribute,
d.display_name_attribute, d.email_attribute, d.bind_dn, d.group_base_dn, d.group_filter, d.group_name_attribute, d.ca_pem,
d.mfa_required, d.enabled, d.version, d.created_at, d.updated_at,
EXISTS (SELECT 1 FROM setting_secrets s WHERE s.key = 'ldap.directory.' || d.id::text || '.bind_password')`

func scanDirectory(row pgx.Row) (Directory, error) {
	var d Directory
	err := row.Scan(&d.ID, &d.Name, &d.Addresses, &d.UserBaseDN, &d.UserFilter, &d.LoginAttribute, &d.UniqueIDAttribute,
		&d.DisplayNameAttribute, &d.EmailAttribute, &d.BindDN, &d.GroupBaseDN, &d.GroupFilter, &d.GroupNameAttribute, &d.CAPEM,
		&d.MFARequired, &d.Enabled, &d.Version, &d.CreatedAt, &d.UpdatedAt, &d.BindPasswordSet)
	if errors.Is(err, pgx.ErrNoRows) {
		return Directory{}, ErrNotFound
	}
	if err != nil {
		return Directory{}, fmt.Errorf("ldap: read the directory: %w", err)
	}
	d.CreatedAt, d.UpdatedAt = d.CreatedAt.UTC(), d.UpdatedAt.UTC()
	return d, nil
}

func loadDirectory(ctx context.Context, q db.Querier, id uuid.UUID) (Directory, error) {
	return scanDirectory(q.QueryRow(ctx, "SELECT "+directoryColumns+" FROM ldap_directories d WHERE d.id = $1", id))
}

// Directory returns one directory.
func (s *Service) Directory(ctx context.Context, id uuid.UUID) (Directory, error) {
	return loadDirectory(ctx, s.pool, id)
}

// Directories lists the configured directories by name.
func (s *Service) Directories(ctx context.Context) ([]Directory, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+directoryColumns+" FROM ldap_directories d ORDER BY lower(d.name)")
	if err != nil {
		return nil, fmt.Errorf("ldap: list directories: %w", err)
	}
	defer rows.Close()
	out := []Directory{}
	for rows.Next() {
		d, err := scanDirectory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ldap: list directories: %w", err)
	}
	return out, nil
}

// PublicDirectories lists the enabled directories by name, for the sign-in page.
func (s *Service) PublicDirectories(ctx context.Context) ([]PublicDirectory, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name FROM ldap_directories WHERE enabled ORDER BY lower(name)")
	if err != nil {
		return nil, fmt.Errorf("ldap: list directories: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PublicDirectory, error) {
		var d PublicDirectory
		return d, r.Scan(&d.ID, &d.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("ldap: list directories: %w", err)
	}
	return out, nil
}

// fields are a directory's values under validation.
type fields struct {
	d          Directory
	bind       []byte
	bindNeeded bool // a password must be given (create, or a change that would send the stored one elsewhere)
	bindGiven  bool
}

func plainText(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}

// validate checks a directory's values in the order of the API body. The database CHECKs only check shapes; this
// parses the DNs and filters with go-ldap and the addresses' hosts and ports.
func (f fields) validate() error {
	var v validate.Errors
	d := f.d
	switch n := utf8.RuneCountInString(d.Name); {
	case strings.TrimSpace(d.Name) == "":
		v.Add("name", validate.Required, nil)
	case n > maxNameRunes:
		v.Add("name", validate.TooLong, map[string]string{"max": strconv.Itoa(maxNameRunes)})
	case !plainText(d.Name):
		v.Add("name", validate.Pattern, nil)
	}
	validateAddresses(&v, d.Addresses)
	validateDN(&v, "user_base_dn", d.UserBaseDN)
	validateFilter(&v, "user_filter", d.UserFilter, false)
	validateAttribute(&v, "login_attribute", d.LoginAttribute, true)
	validateAttribute(&v, "unique_id_attribute", d.UniqueIDAttribute, true)
	validateAttribute(&v, "display_name_attribute", d.DisplayNameAttribute, false)
	validateAttribute(&v, "email_attribute", d.EmailAttribute, false)
	validateDN(&v, "bind_dn", d.BindDN)
	switch {
	case (f.bindNeeded || f.bindGiven) && len(f.bind) == 0:
		v.Add("bind_password", validate.Required, nil)
	case len(f.bind) > maxBindPassBytes:
		v.Add("bind_password", validate.TooLong, map[string]string{"max": strconv.Itoa(maxBindPassBytes)})
	}
	validateDN(&v, "group_base_dn", d.GroupBaseDN)
	validateFilter(&v, "group_filter", d.GroupFilter, true)
	validateAttribute(&v, "group_name_attribute", d.GroupNameAttribute, false)
	if !pemca.Valid(d.CAPEM) {
		v.Add("ca_pem", validate.Pattern, nil)
	}
	return v.Err()
}

func validateAddresses(v *validate.Errors, addrs []string) {
	if len(addrs) == 0 || len(addrs) > maxAddresses {
		v.Add("addresses", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxAddresses)})
		return
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if _, _, ok := splitAddress(a); !ok {
			v.Add("addresses", validate.Pattern, nil)
			return
		}
		if seen[a] {
			v.Add("addresses", validate.Duplicate, nil)
			return
		}
		seen[a] = true
	}
}

// splitAddress parses ldaps://host[:port] exactly: the scheme in lower case (an upper-case scheme is refused, never
// rewritten), a DNS name (letters, digits and hyphens in dot-separated labels), an IPv4 address or an IPv6 address in
// brackets (no zone), and an optional decimal port 1 to 65535 without a leading zero. The port defaults to 636. No
// user part, path, query, fragment, space or control character; at most 255 bytes.
func splitAddress(a string) (host string, port int, ok bool) {
	if len(a) > maxAddressBytes || !strings.HasPrefix(a, addressScheme) {
		return "", 0, false
	}
	hp, portText := a[len(addressScheme):], ""
	if strings.HasPrefix(hp, "[") {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return "", 0, false
		}
		host = hp[1:end]
		switch rest := hp[end+1:]; {
		case rest == "":
		case rest[0] == ':':
			portText = rest[1:]
			if portText == "" {
				return "", 0, false
			}
		default:
			return "", 0, false
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" || ip.Is4In6() {
			return "", 0, false
		}
	} else {
		host = hp
		if i := strings.LastIndexByte(hp, ':'); i >= 0 {
			host, portText = hp[:i], hp[i+1:]
			if portText == "" {
				return "", 0, false
			}
		}
		if !validHost(host) {
			return "", 0, false
		}
	}
	port = 636
	if portText != "" {
		if len(portText) > 5 || portText[0] == '0' || strings.Trim(portText, "0123456789") != "" {
			return "", 0, false
		}
		port, _ = strconv.Atoi(portText)
		if port < 1 || port > 65535 {
			return "", 0, false
		}
	}
	return host, port, true
}

// validHost accepts an IPv4 address or a DNS name of letter-digit-hyphen labels (no trailing dot).
func validHost(h string) bool {
	if h == "" || len(h) > maxHostBytes {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Is4()
	}
	for _, label := range strings.Split(h, ".") {
		if !hostLabelRE.MatchString(label) {
			return false
		}
	}
	// A name whose last label is all digits reads as a malformed IPv4 address (1.2.3.999): refused.
	labels := strings.Split(h, ".")
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func validateDN(v *validate.Errors, field, dn string) {
	switch {
	case dn == "":
		v.Add(field, validate.Required, nil)
	case utf8.RuneCountInString(dn) > maxDNRunes:
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(maxDNRunes)})
	case !plainText(dn) || strings.TrimSpace(dn) != dn:
		v.Add(field, validate.Pattern, nil)
	default:
		if p, err := goldap.ParseDN(dn); err != nil || len(p.RDNs) == 0 {
			v.Add(field, validate.Pattern, nil)
		}
	}
}

func validateAttribute(v *validate.Errors, field, attr string, required bool) {
	switch {
	case attr == "" && required:
		v.Add(field, validate.Required, nil)
	case attr != "" && !attributeRE.MatchString(attr):
		v.Add(field, validate.Pattern, nil)
	}
}

// Probe values stand in for the placeholders while a template is checked: harmless, with a letter and a digit.
const (
	probeLogin = "probe1"
	probeDN    = "cn=probe1,dc=example,dc=test"
)

// validateFilter checks a template as ExpandFilter will use it (the placeholder rules of ldapx, see its package
// documentation) and compiles the expansion with go-ldap. A user filter holds {login} exactly once; a group filter
// holds {dn} or {login} (or both).
func validateFilter(v *validate.Errors, field, tmpl string, group bool) {
	if tmpl == "" {
		v.Add(field, validate.Required, nil)
		return
	}
	if len(tmpl) > maxFilterBytes {
		v.Add(field, validate.TooLong, map[string]string{"max": strconv.Itoa(maxFilterBytes)})
		return
	}
	login, dn := "{"+ldapx.PlaceholderLogin+"}", "{"+ldapx.PlaceholderDN+"}"
	vals := map[string]string{ldapx.PlaceholderLogin: probeLogin}
	ok := strings.Count(tmpl, login) == 1
	if group {
		vals[ldapx.PlaceholderDN] = probeDN
		ok = strings.Contains(tmpl, login) || strings.Contains(tmpl, dn)
	}
	if !ok || !plainText(tmpl) {
		v.Add(field, validate.Pattern, nil)
		return
	}
	expanded, err := ldapx.ExpandFilter(tmpl, vals)
	if err != nil {
		v.Add(field, validate.Pattern, nil)
		return
	}
	if _, err := goldap.CompileFilter(expanded); err != nil {
		v.Add(field, validate.Pattern, nil)
	}
}

// validLogin is the sign-in name rule, checked before a name is put in a filter (ldapx.ValidLoginName).
func validLogin(login string) bool { return ldapx.ValidLoginName(login) }

// uniqueError turns the violated name index into the field it names.
func uniqueError(err error) error {
	if db.IsUniqueViolationOn(err, nameIndex) {
		return validate.Errors{{Field: "name", Code: validate.Duplicate}}
	}
	return err
}

func directoryDetails(d Directory) map[string]string {
	return map[string]string{"directory_id": d.ID.String(), "name": d.Name, "addresses": strings.Join(d.Addresses, " "),
		"user_base_dn": d.UserBaseDN, "user_filter": d.UserFilter, "login_attribute": d.LoginAttribute,
		"unique_id_attribute": d.UniqueIDAttribute, "display_name_attribute": d.DisplayNameAttribute,
		"email_attribute": d.EmailAttribute, "bind_dn": d.BindDN, "group_base_dn": d.GroupBaseDN, "group_filter": d.GroupFilter,
		"group_name_attribute": d.GroupNameAttribute, "ca_set": strconv.FormatBool(d.CAPEM != ""),
		"mfa_required": strconv.FormatBool(d.MFARequired), "enabled": strconv.FormatBool(d.Enabled),
		"bind_set": strconv.FormatBool(d.BindPasswordSet)}
}

// lockDirectories serializes the creations (the count of MaxDirectories) in the caller's transaction.
func lockDirectories(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, directoriesLock); err != nil {
		return fmt.Errorf("ldap: lock the directories: %w", err)
	}
	return nil
}

// CreateDirectory validates the input and stores the directory (switched off unless Enabled) with its service
// account password as a settings secret, in one transaction audited as ldap.directory_created. No network traffic:
// Test connection checks the settings. At most MaxDirectories exist (ErrTooMany), counted under a lock.
func (s *Service) CreateDirectory(ctx context.Context, a audit.Actor, in DirectoryInput) (Directory, error) {
	groupFilter := in.GroupFilter
	if groupFilter == "" {
		groupFilter = DefaultGroupFilter
	}
	mfa := true
	if in.MFARequired != nil {
		mfa = *in.MFARequired
	}
	now := s.clock.Now().UTC()
	d := Directory{ID: uuid.Must(uuid.NewV7()), Name: in.Name, Addresses: slices.Clone(in.Addresses), UserBaseDN: in.UserBaseDN,
		UserFilter: in.UserFilter, LoginAttribute: in.LoginAttribute, UniqueIDAttribute: in.UniqueIDAttribute,
		DisplayNameAttribute: in.DisplayNameAttribute, EmailAttribute: in.EmailAttribute, BindDN: in.BindDN, BindPasswordSet: true,
		GroupBaseDN: in.GroupBaseDN, GroupFilter: groupFilter, GroupNameAttribute: in.GroupNameAttribute, CAPEM: in.CAPEM,
		MFARequired: mfa, Enabled: in.Enabled, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := (fields{d: d, bind: in.BindPassword.Bytes(), bindNeeded: true}).validate(); err != nil {
		return Directory{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDirectories(ctx, tx); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ldap_directories").Scan(&n); err != nil {
			return fmt.Errorf("ldap: count directories: %w", err)
		}
		if n >= MaxDirectories {
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ldap_directories (id, name, addresses, user_base_dn, user_filter, login_attribute,
unique_id_attribute, display_name_attribute, email_attribute, bind_dn, group_base_dn, group_filter, group_name_attribute, ca_pem,
mfa_required, enabled, version, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 1, $17, $18, $18)`, d.ID, d.Name, d.Addresses,
			d.UserBaseDN, d.UserFilter, d.LoginAttribute, d.UniqueIDAttribute, d.DisplayNameAttribute, d.EmailAttribute, d.BindDN,
			d.GroupBaseDN, d.GroupFilter, d.GroupNameAttribute, d.CAPEM, d.MFARequired, d.Enabled, userID(a), now); err != nil {
			return uniqueError(fmt.Errorf("ldap: store the directory: %w", err))
		}
		if err := s.keyring.PutSetting(ctx, tx, secretKey(d.ID), in.BindPassword, now); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.directory_created", ObjectType: "ldap_directory",
			ObjectID: d.ID.String(), Result: audit.Success, Details: directoryDetails(d)})
		return err
	})
	if err != nil {
		return Directory{}, err
	}
	return d, nil
}

// addedAddress reports whether next names an address cur does not: removing or reordering addresses sends nothing
// to a new server.
func addedAddress(cur, next []string) bool {
	for _, a := range next {
		if !slices.Contains(cur, a) {
			return true
		}
	}
	return false
}

// hasUsers reports whether a directory has users.
func hasUsers(ctx context.Context, q db.Querier, id uuid.UUID) (bool, error) {
	var inUse bool
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE ldap_directory_id = $1)", id).Scan(&inUse); err != nil {
		return false, fmt.Errorf("ldap: read the directory's users: %w", err)
	}
	return inUse, nil
}

// UpdateDirectory changes a directory at the given version, audited as ldap.directory_changed. A given
// BindPassword replaces the stored one. Adding an address or changing the bind DN or the unique id attribute needs
// the password again (a 422 on bind_password), so the stored one is never sent to another server or account. While
// the directory has users, its addresses and its unique id attribute cannot change (ErrDirectoryInUse): its users
// are matched by that attribute's value on that server.
func (s *Service) UpdateDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p DirectoryPatch) (Directory, error) {
	cur, err := loadDirectory(ctx, s.pool, id)
	if err != nil {
		return Directory{}, err
	}
	if cur.Version != version {
		return Directory{}, ErrVersion
	}
	d := cur
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&d.Name, p.Name)
	set(&d.UserBaseDN, p.UserBaseDN)
	set(&d.UserFilter, p.UserFilter)
	set(&d.LoginAttribute, p.LoginAttribute)
	set(&d.UniqueIDAttribute, p.UniqueIDAttribute)
	set(&d.DisplayNameAttribute, p.DisplayNameAttribute)
	set(&d.EmailAttribute, p.EmailAttribute)
	set(&d.BindDN, p.BindDN)
	set(&d.GroupBaseDN, p.GroupBaseDN)
	set(&d.GroupFilter, p.GroupFilter)
	set(&d.GroupNameAttribute, p.GroupNameAttribute)
	set(&d.CAPEM, p.CAPEM)
	if p.Addresses != nil {
		d.Addresses = slices.Clone(*p.Addresses)
	}
	if p.MFARequired != nil {
		d.MFARequired = *p.MFARequired
	}
	if p.Enabled != nil {
		d.Enabled = *p.Enabled
	}
	newServer := addedAddress(cur.Addresses, d.Addresses)
	uniqueChanged := d.UniqueIDAttribute != cur.UniqueIDAttribute
	inUseCheck := uniqueChanged || !slices.Equal(cur.Addresses, d.Addresses)
	f := fields{d: d, bindNeeded: newServer || d.BindDN != cur.BindDN || uniqueChanged}
	if p.BindPassword != nil {
		f.bind, f.bindGiven = p.BindPassword.Bytes(), true
	}
	if err := f.validate(); err != nil {
		return Directory{}, err
	}
	if inUseCheck {
		inUse, err := hasUsers(ctx, s.pool, id)
		if err != nil {
			return Directory{}, err
		}
		if inUse {
			return Directory{}, ErrDirectoryInUse
		}
	}
	now := s.clock.Now().UTC()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if inUseCheck {
			// Checked again under the directory's row lock: a first sign-in's user insert takes FOR KEY SHARE on this
			// row (the foreign key), so it cannot slip in between. Two statements: the EXISTS must run with a snapshot
			// taken after the lock was granted.
			if _, err := tx.Exec(ctx, "SELECT 1 FROM ldap_directories WHERE id = $1 FOR UPDATE", id); err != nil {
				return fmt.Errorf("ldap: lock the directory: %w", err)
			}
			inUse, err := hasUsers(ctx, tx, id)
			if err != nil {
				return err
			}
			if inUse {
				return ErrDirectoryInUse
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE ldap_directories SET name = $3, addresses = $4, user_base_dn = $5, user_filter = $6,
login_attribute = $7, unique_id_attribute = $8, display_name_attribute = $9, email_attribute = $10, bind_dn = $11, group_base_dn = $12,
group_filter = $13, group_name_attribute = $14, ca_pem = $15, mfa_required = $16, enabled = $17, version = version + 1, updated_at = $18
WHERE id = $1 AND version = $2`, id, version, d.Name, d.Addresses, d.UserBaseDN, d.UserFilter, d.LoginAttribute, d.UniqueIDAttribute,
			d.DisplayNameAttribute, d.EmailAttribute, d.BindDN, d.GroupBaseDN, d.GroupFilter, d.GroupNameAttribute, d.CAPEM, d.MFARequired,
			d.Enabled, now)
		if err != nil {
			return uniqueError(fmt.Errorf("ldap: update the directory: %w", err))
		}
		if tag.RowsAffected() == 0 {
			return ErrVersion
		}
		if p.BindPassword != nil {
			if err := s.keyring.PutSetting(ctx, tx, secretKey(id), *p.BindPassword, now); err != nil {
				return err
			}
		}
		details := directoryDetails(d)
		details["bind_replaced"] = strconv.FormatBool(p.BindPassword != nil)
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.directory_changed", ObjectType: "ldap_directory",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return Directory{}, err
	}
	return s.Directory(ctx, id)
}

// DeleteDirectory removes a directory at the given version with its mappings and its service account password, in
// one transaction audited as ldap.directory_deleted. A directory people have signed in through cannot be deleted
// (ErrDirectoryInUse; switch it off instead).
func (s *Service) DeleteDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, "DELETE FROM ldap_directories WHERE id = $1 AND version = $2 RETURNING name", id, version).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, lerr := loadDirectory(ctx, tx, id); lerr != nil {
				return lerr
			}
			return ErrVersion
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == foreignKeyCode {
			return ErrDirectoryInUse
		}
		if err != nil {
			return fmt.Errorf("ldap: delete the directory: %w", err)
		}
		if err := secrets.DeleteSetting(ctx, tx, secretKey(id)); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "ldap.directory_deleted", ObjectType: "ldap_directory",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"directory_id": id.String(), "name": name}})
		return err
	})
}
