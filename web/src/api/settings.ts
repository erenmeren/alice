import { apiFetch } from './client';

// Settings (contract C13). Every PUT and action sends the version the form was loaded with as If-Match; a 412 means somebody
// else changed it, and the form is read again. A password never appears in an answer (has_password only).

export type TlsMode = 'starttls' | 'tls';
export type Locale = 'en' | 'tr';

export interface TrustedCertificate {
  fingerprint: string;
  subject: string;
  not_after: string;
  trusted_by: string;
  trusted_at: string;
}

export interface SMTPSettings {
  configured: boolean;
  host: string;
  port: number;
  tls_mode: TlsMode;
  from: string;
  username: string;
  has_password: boolean;
  ca_pem: string;
  trusted_certificate: TrustedCertificate | null;
  version: number;
  updated_at: string | null;
}

// password: absent keeps the stored one, "" removes it.
export interface SMTPInput {
  host: string;
  port: number;
  tls_mode: TlsMode;
  from: string;
  username: string;
  ca_pem: string;
  password?: string;
}

export interface Recipients {
  administrators: boolean;
  addresses: { email: string; locale: Locale }[];
  version: number;
}

export interface AlertThresholds {
  thresholds_days: number[];
  version: number;
}

export interface GeneralSettings {
  public_url: string;
  retired_key_retention_days: number;
  version: number;
}

const v1 = '/api/v1/settings';
export const ifMatch = (version: number) => ({ 'If-Match': `"${version}"` });

export const getSMTP = () => apiFetch<SMTPSettings>(`${v1}/smtp`);
export const saveSMTP = (version: number, body: SMTPInput) => apiFetch<SMTPSettings>(`${v1}/smtp`, { method: 'PUT', body, headers: ifMatch(version) });
export const sendTestMail = (to: string) => apiFetch<{ sent: boolean }>(`${v1}/smtp/actions/test`, { method: 'POST', body: { to } });
export const trustSMTPCertificate = (version: number, fingerprint: string) =>
  apiFetch<SMTPSettings>(`${v1}/smtp/actions/trust`, { method: 'POST', body: { fingerprint }, headers: ifMatch(version) });
export const untrustSMTPCertificate = (version: number) => apiFetch<SMTPSettings>(`${v1}/smtp/actions/untrust`, { method: 'POST', headers: ifMatch(version) });

export const getRecipients = () => apiFetch<Recipients>(`${v1}/notifications`);
export const saveRecipients = (version: number, body: Pick<Recipients, 'administrators' | 'addresses'>) =>
  apiFetch<Recipients>(`${v1}/notifications`, { method: 'PUT', body, headers: ifMatch(version) });

export const getThresholds = () => apiFetch<AlertThresholds>(`${v1}/alerts`);
export const saveThresholds = (version: number, thresholds_days: number[]) =>
  apiFetch<AlertThresholds>(`${v1}/alerts`, { method: 'PUT', body: { thresholds_days }, headers: ifMatch(version) });

export const getGeneral = () => apiFetch<GeneralSettings>(`${v1}/general`);
export const saveGeneral = (version: number, body: Omit<GeneralSettings, 'version'>) =>
  apiFetch<GeneralSettings>(`${v1}/general`, { method: 'PUT', body, headers: ifMatch(version) });
