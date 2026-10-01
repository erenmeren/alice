import type { SessionInfo, SetupStatus } from '../api/types';
import { freshStatus, installedStatus, sessionFor } from './fixtures';

export interface Screen {
  path: string;
  session: SessionInfo | null;
  status: SetupStatus;
  // text proves the screen finished loading; a function of the language
  ready: { en: string; tr: string };
}

// SCREENS lists every routed screen. Later tasks append their pages here.
export const SCREENS: Screen[] = [
  { path: '/', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Home', tr: 'Ana sayfa' } },
  { path: '/login', session: null, status: installedStatus, ready: { en: 'Sign in to Alice', tr: "Alice'e giriş yapın" } },
  { path: '/setup', session: null, status: freshStatus, ready: { en: 'Set up Alice', tr: 'Alice kurulumu' } },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, recovery_passphrase_set: false },
    ready: { en: 'Choose a recovery passphrase', tr: 'Kurtarma parolası belirleyin' },
  },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false },
    ready: { en: 'Alice is ready', tr: 'Alice hazır' },
  },
  { path: '/account', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Change password', tr: 'Parolayı değiştir' } },
  { path: '/users', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Operator', tr: 'Operatör' } },
  { path: '/tokens', session: sessionFor('operator'), status: installedStatus, ready: { en: 'Read only', tr: 'Salt okunur' } },
  { path: '/audit', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'User created', tr: 'Kullanıcı oluşturuldu' } },
  { path: '/license', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Upload a license', tr: 'Lisans yükle' } },
  { path: '/license', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'Installation ID', tr: 'Kurulum Kimliği' } },
  { path: '/missing', session: null, status: installedStatus, ready: { en: 'Page not found', tr: 'Sayfa bulunamadı' } },
];
