import { http, HttpResponse } from 'msw';
import type { Role, SessionInfo, SetupStatus, User } from '../api/types';

export function userFor(role: Role, locale = 'en'): User {
  return {
    id: `00000000-0000-7000-8000-00000000000${role === 'admin' ? 1 : role === 'operator' ? 2 : 3}`,
    username: role,
    display_name: { admin: 'Ayşe Yılmaz', operator: 'Olcay Öztürk', auditor: 'Ilgın Işık' }[role],
    email: `${role}@example.com`,
    role,
    locale,
    disabled: false,
    mfa_enrolled: true,
    last_login_at: null,
    created_at: '2026-09-30T08:00:00Z',
  };
}

export function sessionFor(role: Role, locale = 'en'): SessionInfo {
  return {
    user: userFor(role, locale),
    csrf_token: `csrf-${role}`,
    expires_at: '2026-09-30T20:00:00Z',
    idle_expires_at: '2026-09-30T08:30:00Z',
    stepup_until: null,
  };
}

export const adminSession = sessionFor('admin');
export const operatorSession = sessionFor('operator');
export const auditorSession = sessionFor('auditor');

export const installedStatus: SetupStatus = {
  admin_exists: true,
  recovery_passphrase_set: true,
  completed: true,
  default_locale: 'en',
};

export const freshStatus: SetupStatus = {
  admin_exists: false,
  recovery_passphrase_set: false,
  completed: false,
  default_locale: 'en',
};

// errorResponse builds an error body shaped like the server's (spec §9.3).
export function errorResponse(
  status: number,
  code: string,
  reason: string,
  extra: { params?: Record<string, string>; details?: { field: string; code: string; params?: Record<string, string> }[] } = {},
) {
  return HttpResponse.json(
    {
      error: {
        code,
        reason,
        message_key: `errors.${reason}`,
        message: `server text for ${reason}`,
        request_id: 'req-1',
        retryable: status === 429,
        ...extra,
      },
    },
    { status },
  );
}

// sessionHandlers installs handlers for a signed-in user (or none) and the setup status.
export function sessionHandlers(session: SessionInfo | null, status: SetupStatus = installedStatus) {
  return [
    http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
    http.get('/api/v1/auth/session', () =>
      session ? HttpResponse.json(session) : errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated'),
    ),
  ];
}
