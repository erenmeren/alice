import { globalSession, scopedSession, sessionFor, SERVICE_ID } from '../test/fixtures';
import { adminOn, can, canIn, canOn, canPlatform, hasNoAccess, sessionAccess } from './permissions';

describe('permissions', () => {
  it('reads a session without access as the global role everywhere (an older server, the older fixtures)', () => {
    const op = sessionFor('operator');
    expect(sessionAccess(op).global_role).toBe('operator');
    expect(can(op, 'certificates.operate')).toBe(true);
    expect(can(op, 'targets.manage')).toBe(false);
    expect(canPlatform(sessionFor('auditor'), 'audit.read')).toBe(true);
    expect(canPlatform(op, 'audit.read')).toBe(false);
    expect(canPlatform(sessionFor('admin'), 'access.manage')).toBe(true);
    expect(can(null, 'read')).toBe(false);
  });

  it('gives a global role the same rights through the server answer', () => {
    for (const role of ['admin', 'operator', 'auditor'] as const) {
      const old = sessionFor(role);
      const now = globalSession(role);
      for (const p of ['read', 'audit.read', 'users.read', 'certificates.operate', 'targets.manage', 'acme.manage', 'access.manage'] as const) {
        expect([role, p, can(now, p), canPlatform(now, p)]).toEqual([role, p, can(old, p), canPlatform(old, p)]);
      }
    }
  });

  it('keeps platform pages from a person whose only rights are on a service', () => {
    const adminB = scopedSession(['admin']);
    expect(can(adminB, 'targets.manage')).toBe(true);
    expect(can(adminB, 'users.read')).toBe(true); // held on the service: never a platform page
    expect(canPlatform(adminB, 'users.read')).toBe(false);
    expect(canPlatform(adminB, 'settings.manage')).toBe(false);
  });

  it('decides a row by its allowed_actions, and falls back to can without them', () => {
    const op = scopedSession(['operator']);
    expect(canOn(op, { allowed_actions: ['read', 'certificates.operate'] }, 'certificates.operate')).toBe(true);
    expect(canOn(op, { allowed_actions: ['read'] }, 'certificates.operate')).toBe(false);
    // The server leaves out an empty allowed_actions: a row it sends without one allows nothing.
    expect(canOn(op, {}, 'read')).toBe(false);
    // An older session (no access) with a row without the field: the role decides.
    expect(canOn(sessionFor('operator'), {}, 'certificates.operate')).toBe(true);
    expect(canOn(sessionFor('auditor'), {}, 'certificates.operate')).toBe(false);
    // No row yet (still loading): the permission held anywhere.
    expect(canOn(op, undefined, 'certificates.operate')).toBe(true);
    expect(adminOn(op, { allowed_actions: ['read', 'certificates.operate'] })).toBe(false);
    expect(adminOn(scopedSession(['admin']), { allowed_actions: ['read', 'targets.manage'] })).toBe(true);
  });

  it('decides one service by the roles held on it', () => {
    const adminB = scopedSession(['admin']);
    expect(canIn(adminB, SERVICE_ID, 'services.assign')).toBe(true);
    expect(canIn(adminB, 'another-service', 'services.assign')).toBe(false);
    expect(canIn(globalSession('admin'), 'another-service', 'services.assign')).toBe(true);
    expect(canIn(sessionFor('operator'), SERVICE_ID, 'services.assign')).toBe(false);
  });

  it('finds the person who may reach nothing', () => {
    expect(hasNoAccess(scopedSession([]))).toBe(true);
    expect(hasNoAccess(scopedSession(['auditor']))).toBe(false);
    expect(hasNoAccess(globalSession('auditor'))).toBe(false);
    expect(hasNoAccess(sessionFor('operator'))).toBe(false);
    expect(hasNoAccess({ ...sessionFor('operator'), user: { ...sessionFor('operator').user, role: null } })).toBe(true);
    expect(hasNoAccess(null)).toBe(false);
  });
});
