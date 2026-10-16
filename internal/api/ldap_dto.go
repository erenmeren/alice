package api

import (
	"time"

	"github.com/google/uuid"

	"alice/internal/auth/ldap"
)

// The directory sign-in answers (LDAP and Active Directory, Task 5). A directory never carries its service account
// password: bind_password_set says one is stored.

type directoryDTO struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	Addresses            []string  `json:"addresses"`
	UserBaseDN           string    `json:"user_base_dn"`
	UserFilter           string    `json:"user_filter"`
	LoginAttribute       string    `json:"login_attribute"`
	UniqueIDAttribute    string    `json:"unique_id_attribute"`
	DisplayNameAttribute string    `json:"display_name_attribute"`
	EmailAttribute       string    `json:"email_attribute"`
	BindDN               string    `json:"bind_dn"`
	BindPasswordSet      bool      `json:"bind_password_set"`
	GroupBaseDN          string    `json:"group_base_dn"`
	GroupFilter          string    `json:"group_filter"`
	GroupNameAttribute   string    `json:"group_name_attribute"`
	CAPEM                string    `json:"ca_pem"`
	MFARequired          bool      `json:"mfa_required"`
	Enabled              bool      `json:"enabled"`
	Version              int       `json:"version"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func directoryJSON(d ldap.Directory) directoryDTO {
	return directoryDTO{ID: d.ID, Name: d.Name, Addresses: nonNil(d.Addresses), UserBaseDN: d.UserBaseDN, UserFilter: d.UserFilter,
		LoginAttribute: d.LoginAttribute, UniqueIDAttribute: d.UniqueIDAttribute, DisplayNameAttribute: d.DisplayNameAttribute,
		EmailAttribute: d.EmailAttribute, BindDN: d.BindDN, BindPasswordSet: d.BindPasswordSet, GroupBaseDN: d.GroupBaseDN,
		GroupFilter: d.GroupFilter, GroupNameAttribute: d.GroupNameAttribute, CAPEM: d.CAPEM, MFARequired: d.MFARequired,
		Enabled: d.Enabled, Version: d.Version, CreatedAt: d.CreatedAt.UTC(), UpdatedAt: d.UpdatedAt.UTC()}
}

// publicDirectoryDTO is an entry of the sign-in page's "Sign in to" list: no address, no setting.
type publicDirectoryDTO struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type directoryMappingDTO struct {
	ID          uuid.UUID `json:"id"`
	DirectoryID uuid.UUID `json:"directory_id"`
	Group       string    `json:"group"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

func directoryMappingJSON(m ldap.Mapping) directoryMappingDTO {
	return directoryMappingDTO{ID: m.ID, DirectoryID: m.DirectoryID, Group: m.Group, Role: string(m.Role), CreatedAt: m.CreatedAt.UTC()}
}

// directoryTestDTO is what Test sign-in shows: who the directory says the person is, the groups the group search found
// and the role the mappings would give (null when no group is mapped). Nothing is stored.
type directoryTestDTO struct {
	Login       string   `json:"login"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	UniqueID    string   `json:"unique_id"`
	Groups      []string `json:"groups"`
	Role        *string  `json:"role"`
}

func directoryTestJSON(r ldap.TestResult) directoryTestDTO {
	out := directoryTestDTO{Login: r.Identity.Login, DisplayName: r.Identity.DisplayName, Email: r.Identity.Email,
		UniqueID: r.Identity.UniqueID, Groups: nonNil(r.Identity.Groups)}
	if r.Role != "" {
		role := string(r.Role)
		out.Role = &role
	}
	return out
}

// directoryBody is a directory's create or change body. bind_password is a secretField the handler zeroes on every
// path; null is refused for every field (400), as for the identity providers.
type directoryBody struct {
	Name                 opt[string]   `json:"name"`
	Addresses            opt[[]string] `json:"addresses"`
	UserBaseDN           opt[string]   `json:"user_base_dn"`
	UserFilter           opt[string]   `json:"user_filter"`
	LoginAttribute       opt[string]   `json:"login_attribute"`
	UniqueIDAttribute    opt[string]   `json:"unique_id_attribute"`
	DisplayNameAttribute opt[string]   `json:"display_name_attribute"`
	EmailAttribute       opt[string]   `json:"email_attribute"`
	BindDN               opt[string]   `json:"bind_dn"`
	BindPassword         secretField   `json:"bind_password"`
	GroupBaseDN          opt[string]   `json:"group_base_dn"`
	GroupFilter          opt[string]   `json:"group_filter"`
	GroupNameAttribute   opt[string]   `json:"group_name_attribute"`
	CAPEM                opt[string]   `json:"ca_pem"`
	MFARequired          opt[bool]     `json:"mfa_required"`
	Enabled              opt[bool]     `json:"enabled"`
}

var directoryKeys = []string{"name", "addresses", "user_base_dn", "user_filter", "login_attribute", "unique_id_attribute",
	"display_name_attribute", "email_attribute", "bind_dn", "bind_password", "group_base_dn", "group_filter",
	"group_name_attribute", "ca_pem", "mfa_required", "enabled"}

func (b *directoryBody) zero() { b.BindPassword.zero() }

// directoryPasswordBody is a body with a person's directory password: a sign-in, a step-up or a Test sign-in.
// password is a secretText the handler zeroes on every path.
type directoryPasswordBody struct {
	Username string     `json:"username"`
	Password secretText `json:"password"`
	Code     string     `json:"code"`
}

func (b *directoryPasswordBody) zero() { b.Password.zero() }
