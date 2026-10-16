package api

import (
	"context"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

func (f *fakeAuth) SignInLDAP(ctx context.Context, id auth.LDAPIdentity, role rbac.Role, mfaRequired bool, m auth.Meta) (auth.LoginResult, error) {
	if f.SignInLDAPFn != nil {
		return f.SignInLDAPFn(ctx, id, role, mfaRequired, m)
	}
	return auth.LoginResult{}, errNotConfigured
}

func (f *fakeAuth) StepUpLDAP(ctx context.Context, p auth.Principal, id auth.LDAPIdentity, role rbac.Role, code string, mfaRequired bool,
	m auth.Meta,
) (auth.SessionResult, error) {
	if f.StepUpLDAPFn != nil {
		return f.StepUpLDAPFn(ctx, p, id, role, code, mfaRequired, m)
	}
	return auth.SessionResult{}, errNotConfigured
}

func (f *fakeAuth) RefuseLDAP(ctx context.Context, id auth.LDAPIdentity, reason string, m auth.Meta) error {
	if f.RefuseLDAPFn != nil {
		return f.RefuseLDAPFn(ctx, id, reason, m)
	}
	return nil
}

// fakeLDAP implements LDAPService: one function field per method (errNotConfigured when nil), a call counter. The
// public list answers empty by default (testDeps).
type fakeLDAP struct {
	phase7Fake
	DirectoriesFn       func(ctx context.Context) ([]ldap.Directory, error)
	DirectoryFn         func(ctx context.Context, id uuid.UUID) (ldap.Directory, error)
	PublicDirectoriesFn func(ctx context.Context) ([]ldap.PublicDirectory, error)
	CreateDirectoryFn   func(ctx context.Context, a audit.Actor, in ldap.DirectoryInput) (ldap.Directory, error)
	UpdateDirectoryFn   func(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p ldap.DirectoryPatch) (ldap.Directory, error)
	DeleteDirectoryFn   func(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error
	MappingsFn          func(ctx context.Context, directoryID uuid.UUID) ([]ldap.Mapping, error)
	CreateMappingFn     func(ctx context.Context, a audit.Actor, directoryID uuid.UUID, group string, role rbac.Role) (ldap.Mapping, error)
	DeleteMappingFn     func(ctx context.Context, a audit.Actor, id uuid.UUID) error
	TestConnectionFn    func(ctx context.Context, a audit.Actor, id uuid.UUID) error
	TestSignInFn        func(ctx context.Context, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext) (ldap.TestResult, error)
	VerifyFn            func(ctx context.Context, directoryID uuid.UUID, login string, password secrets.Plaintext) (ldap.Identity, ldap.Directory, error)
	ResolveRoleFn       func(ctx context.Context, directoryID uuid.UUID, groups []string) (rbac.Role, bool, error)
}

func newFakeLDAP() *fakeLDAP {
	f := &fakeLDAP{}
	f.PublicDirectoriesFn = func(context.Context) ([]ldap.PublicDirectory, error) { return nil, nil }
	return f
}

func (f *fakeLDAP) Directories(ctx context.Context) ([]ldap.Directory, error) {
	f.record()
	if f.DirectoriesFn != nil {
		return f.DirectoriesFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeLDAP) Directory(ctx context.Context, id uuid.UUID) (ldap.Directory, error) {
	f.record()
	if f.DirectoryFn != nil {
		return f.DirectoryFn(ctx, id)
	}
	return ldap.Directory{}, errNotConfigured
}

func (f *fakeLDAP) PublicDirectories(ctx context.Context) ([]ldap.PublicDirectory, error) {
	f.record()
	if f.PublicDirectoriesFn != nil {
		return f.PublicDirectoriesFn(ctx)
	}
	return nil, errNotConfigured
}

func (f *fakeLDAP) CreateDirectory(ctx context.Context, a audit.Actor, in ldap.DirectoryInput) (ldap.Directory, error) {
	f.record()
	if f.CreateDirectoryFn != nil {
		return f.CreateDirectoryFn(ctx, a, in)
	}
	return ldap.Directory{}, errNotConfigured
}

func (f *fakeLDAP) UpdateDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p ldap.DirectoryPatch) (ldap.Directory, error) {
	f.record()
	if f.UpdateDirectoryFn != nil {
		return f.UpdateDirectoryFn(ctx, a, id, version, p)
	}
	return ldap.Directory{}, errNotConfigured
}

func (f *fakeLDAP) DeleteDirectory(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error {
	f.record()
	if f.DeleteDirectoryFn != nil {
		return f.DeleteDirectoryFn(ctx, a, id, version)
	}
	return errNotConfigured
}

func (f *fakeLDAP) Mappings(ctx context.Context, directoryID uuid.UUID) ([]ldap.Mapping, error) {
	f.record()
	if f.MappingsFn != nil {
		return f.MappingsFn(ctx, directoryID)
	}
	return nil, errNotConfigured
}

func (f *fakeLDAP) CreateMapping(ctx context.Context, a audit.Actor, directoryID uuid.UUID, group string, role rbac.Role) (ldap.Mapping, error) {
	f.record()
	if f.CreateMappingFn != nil {
		return f.CreateMappingFn(ctx, a, directoryID, group, role)
	}
	return ldap.Mapping{}, errNotConfigured
}

func (f *fakeLDAP) DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error {
	f.record()
	if f.DeleteMappingFn != nil {
		return f.DeleteMappingFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeLDAP) TestConnection(ctx context.Context, a audit.Actor, id uuid.UUID) error {
	f.record()
	if f.TestConnectionFn != nil {
		return f.TestConnectionFn(ctx, a, id)
	}
	return errNotConfigured
}

func (f *fakeLDAP) TestSignIn(ctx context.Context, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext) (ldap.TestResult, error) {
	f.record()
	if f.TestSignInFn != nil {
		return f.TestSignInFn(ctx, a, id, login, password)
	}
	return ldap.TestResult{}, errNotConfigured
}

func (f *fakeLDAP) VerifyGated(ctx context.Context, directoryID uuid.UUID, login string, password secrets.Plaintext, gate ldap.Gate) (ldap.Identity, ldap.Directory, error) {
	f.record()
	if f.VerifyFn != nil {
		id, d, err := f.VerifyFn(ctx, directoryID, login, password)
		if gate != nil && id.UniqueID != "" {
			if gerr := gate(id.UniqueID); gerr != nil {
				return ldap.Identity{UniqueID: id.UniqueID, Login: id.Login}, d, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailLocked}
			}
		}
		return id, d, err
	}
	return ldap.Identity{}, ldap.Directory{}, errNotConfigured
}

func (f *fakeLDAP) ResolveRole(ctx context.Context, directoryID uuid.UUID, groups []string) (rbac.Role, bool, error) {
	f.record()
	if f.ResolveRoleFn != nil {
		return f.ResolveRoleFn(ctx, directoryID, groups)
	}
	return "", false, errNotConfigured
}
