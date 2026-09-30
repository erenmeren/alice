// Wire types for the Alice REST API (snake_case, see api/openapi.yaml).

export type Role = 'admin' | 'operator' | 'auditor';
export type TokenScope = 'read' | 'operate';

export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
}

export interface User {
  id: string;
  username: string;
  display_name: string;
  email: string;
  role: Role;
  locale: string;
  disabled: boolean;
  mfa_enrolled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_expires_at: string;
  stepup_until: string | null;
}

export interface SessionWithCodes extends SessionInfo {
  recovery_codes?: string[];
}

export interface LoginResponse {
  status: 'mfa_required' | 'mfa_enrollment_required';
  csrf_token: string;
}

export interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
  qr_png: string;
}

export type MfaInput = { code: string } | { recovery_code: string };

export interface SetupStatus {
  admin_exists: boolean;
  recovery_passphrase_set: boolean;
  completed: boolean;
  default_locale: string;
}

export interface SetupSessionResponse {
  csrf_token: string;
}

export interface AdminEnrollmentRequest {
  username: string;
  display_name: string;
  email: string;
  password: string;
}

export interface UserCreateRequest {
  username: string;
  display_name: string;
  email: string;
  role: Role;
  password: string;
}

export interface UserUpdateRequest {
  display_name?: string;
  email?: string;
  role?: Role;
  disabled?: boolean;
}

export interface ApiToken {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  scope: TokenScope;
  expires_at: string;
  last_used_at: string | null;
  created_at: string;
}

export interface TokenCreateRequest {
  name: string;
  scope: TokenScope;
  expires_in_days: number;
}

export interface CreatedToken {
  token: string;
  item: ApiToken;
}

export type AuditResult = 'success' | 'failure' | 'denied';

export interface AuditEntry {
  seq: number;
  at: string;
  actor_type: string;
  actor_id: string | null;
  actor_name: string;
  ip: string | null;
  action: string;
  object_type: string;
  object_id: string;
  result: AuditResult;
  details: Record<string, string>;
  request_id: string;
  hash: string;
}

export interface AuditQuery {
  limit?: number;
  cursor?: string | null;
  action?: string;
  actor?: string;
  result?: AuditResult | '';
}

export interface AuditPage {
  items: AuditEntry[];
  next_cursor: string | null;
}

export interface AuditReport {
  intact: boolean;
  checked: number;
  head_seq: number;
  head_hash: string;
  first_bad_seq: number | null;
  problem: string | null;
}

export interface FieldError {
  field: string;
  code: string;
  params?: Record<string, string>;
}

export interface ApiErrorBody {
  error: {
    code: string;
    reason: string;
    message_key: string;
    message: string;
    request_id: string;
    retryable: boolean;
    params?: Record<string, string>;
    details?: FieldError[];
  };
}
