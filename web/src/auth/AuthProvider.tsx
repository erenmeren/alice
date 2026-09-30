import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { onUnauthorized, setCsrfToken } from '../api/client';
import { getSession, getSetupStatus, logout } from '../api/endpoints';
import type { SessionInfo, SetupStatus } from '../api/types';
import { isSupported, setLanguage } from '../i18n';

export interface AuthState {
  session: SessionInfo | null;
  setupStatus: SetupStatus | null;
  loading: boolean;
  // sessionEnded is true after the server said the session expired or was revoked.
  sessionEnded: boolean;
  refresh: () => Promise<void>;
  refreshSetupStatus: () => Promise<SetupStatus | null>;
  setSession: (s: SessionInfo | null) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

async function loadSession(): Promise<SessionInfo | null> {
  try {
    return await getSession();
  } catch {
    return null; // 401 = signed out; server trouble also shows the sign-in page, which reports errors
  }
}

async function loadSetupStatus(): Promise<SetupStatus | null> {
  try {
    return await getSetupStatus();
  } catch {
    return null; // treat as "installed"; the sign-in page then shows any server problem
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const { i18n } = useTranslation();
  const [session, setSessionState] = useState<SessionInfo | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionEnded, setSessionEnded] = useState(false);

  const setSession = useCallback((s: SessionInfo | null) => {
    setCsrfToken(s?.csrf_token ?? null);
    setSessionState(s);
    if (s) setSessionEnded(false);
  }, []);

  // The signed-in user's saved language wins over the browser language (spec §10.2).
  // It is applied once per sign-in so a later switch in the header is not undone.
  const userLocale = session?.user.locale ?? null;
  const appliedLocale = useRef<string | null>(null);
  useEffect(() => {
    if (!userLocale || appliedLocale.current === userLocale) return;
    appliedLocale.current = userLocale;
    if (userLocale !== i18n.language && isSupported(userLocale)) void setLanguage(i18n, userLocale);
  }, [userLocale, i18n]);

  const refreshSetupStatus = useCallback(async () => {
    const st = await loadSetupStatus();
    setSetupStatus(st);
    return st;
  }, []);

  const refresh = useCallback(async () => {
    const [st, s] = await Promise.all([loadSetupStatus(), loadSession()]);
    setSetupStatus(st);
    setSession(s);
  }, [setSession]);

  useEffect(() => {
    let active = true;
    void Promise.all([loadSetupStatus(), loadSession()]).then(([st, s]) => {
      if (!active) return;
      setSetupStatus(st);
      setSession(s);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [setSession]);

  useEffect(
    () =>
      onUnauthorized(() => {
        // RequireAuth sees the missing session and sends the user to /login?ended=1.
        setCsrfToken(null);
        setSessionState(null);
        setSessionEnded(true);
      }),
    [],
  );

  const signOut = useCallback(async () => {
    try {
      await logout();
    } catch {
      // The session may already be gone; signing out locally is still correct.
    }
    appliedLocale.current = null;
    setSession(null);
    navigate('/login', { replace: true });
  }, [navigate, setSession]);

  const value = useMemo<AuthState>(
    () => ({ session, setupStatus, loading, sessionEnded, refresh, refreshSetupStatus, setSession, signOut }),
    [session, setupStatus, loading, sessionEnded, refresh, refreshSetupStatus, setSession, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
