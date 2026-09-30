import { isApiError } from '../../api/client';

// isGone is true when a setup route answers 404: the installation is already set up,
// so the wizard has nothing left to do and the user belongs on the sign-in page.
export function isGone(e: unknown): boolean {
  return isApiError(e) && e.status === 404;
}
