import type { SetupStatus } from '../api/types';

// adminExists reports whether the installation has its first administrator. After setup is complete an anonymous
// caller gets only {completed, default_locale} (S-18, R43 row 47): completed implies an administrator exists.
export function adminExists(status: SetupStatus): boolean {
  return status.completed || status.admin_exists === true;
}
