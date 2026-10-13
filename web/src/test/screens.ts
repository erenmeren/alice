import type { SessionInfo, SetupStatus } from '../api/types';
import { freshStatus, installedStatus, nginxTargetFixture, sessionFor, targetFixture, vaultFixture } from './fixtures';

export interface Screen {
  path: string;
  session: SessionInfo | null;
  status: SetupStatus;
  // text proves the screen finished loading; a function of the language
  ready: { en: string; tr: string };
}

// SCREENS lists every routed screen. Later tasks append their pages here.
export const SCREENS: Screen[] = [
  { path: '/', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Expiration horizon', tr: 'Sertifika bitiş takvimi' } },
  { path: '/login', session: null, status: installedStatus, ready: { en: 'Sign in to Alice', tr: "Alice'e giriş yapın" } },
  { path: '/setup', session: null, status: freshStatus, ready: { en: 'Set up Alice', tr: 'Alice kurulumu' } },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, recovery_passphrase_set: false, license_chosen: false },
    ready: { en: 'Choose a recovery passphrase', tr: 'Kurtarma parolası belirleyin' },
  },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, license_chosen: false },
    ready: { en: 'Add a license', tr: 'Lisans ekleyin' },
  },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false },
    ready: { en: 'Connect your servers', tr: 'Sunucularınızı bağlayın' },
  },
  // Phase 8: the wizard's HTTPS certificate and mail server steps, and the three new Settings tabs.
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, license_chosen: false, https_chosen: false, mail_chosen: false, next_step: 'https' },
    ready: { en: 'Keep the temporary certificate', tr: 'Geçici sertifikayı kullanmaya devam et' },
  },
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, license_chosen: false, https_chosen: true, mail_chosen: false, next_step: 'mail' },
    ready: { en: 'Save mail settings', tr: 'Posta ayarlarını kaydet' },
  },
  { path: '/settings?tab=backups', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Save backup schedule', tr: 'Yedekleme zamanlamasını kaydet' } },
  { path: '/settings?tab=https', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Certificate in use', tr: 'Kullanılan sertifika' } },
  // The ACME work: Settings → Certificate authorities.
  { path: '/settings?tab=acme', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Authorities and accounts', tr: 'Yetkililer ve hesaplar' } },
  { path: '/settings?tab=forwarding', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Save forwarding settings', tr: 'İletim ayarlarını kaydet' } },
  { path: '/account', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Change password', tr: 'Parolayı değiştir' } },
  { path: '/users', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Sign-in method', tr: 'Giriş yöntemi' } },
  { path: '/tokens', session: sessionFor('operator'), status: installedStatus, ready: { en: 'Read only', tr: 'Salt okunur' } },
  { path: '/audit', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'User created', tr: 'Kullanıcı oluşturuldu' } },
  { path: '/license', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Upload a license', tr: 'Lisans yükle' } },
  { path: '/license', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'Installation ID', tr: 'Kurulum Kimliği' } },
  {
    path: '/servers',
    session: sessionFor('admin'),
    status: installedStatus,
    ready: { en: 'Prepare a server for Alice', tr: 'Sunucuyu Alice için hazırlayın' },
  },
  { path: `/servers/${targetFixture.id}`, session: sessionFor('operator'), status: installedStatus, ready: { en: 'deploy@laptop', tr: 'deploy@laptop' } },
  { path: '/key-vaults', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Add Key Vault', tr: 'Key Vault ekle' } },
  { path: `/key-vaults/${vaultFixture.id}`, session: sessionFor('operator'), status: installedStatus, ready: { en: 'Roles Alice needs', tr: "Alice'in ihtiyaç duyduğu roller" } },
  {
    path: `/key-vaults/${vaultFixture.id}/certificates/0192d000-0000-7000-8000-0000000000c1`,
    session: sessionFor('operator'),
    status: installedStatus,
    ready: { en: 'Version history', tr: 'Sürüm geçmişi' },
  },
  { path: '/ssh-keys', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'deploy@laptop', tr: 'deploy@laptop' } },
  {
    path: '/ssh-keys/0192b000-0000-7000-8000-0000000000k1',
    session: sessionFor('admin'),
    status: installedStatus,
    ready: { en: 'Where this key is used', tr: 'Bu anahtarın kullanıldığı yerler' },
  },
  { path: '/rotations', session: sessionFor('admin'), status: installedStatus, ready: { en: 'No rotation is running.', tr: 'Çalışan rotasyon yok.' } },
  { path: '/rotations', session: sessionFor('operator'), status: installedStatus, ready: { en: 'No rotation is running.', tr: 'Çalışan rotasyon yok.' } },
  { path: '/rotations', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'No rotation is running.', tr: 'Çalışan rotasyon yok.' } },
  {
    path: '/rotation/runs/0192e000-0000-7000-8000-0000000000r1',
    session: sessionFor('admin'),
    status: installedStatus,
    ready: { en: 'Key rotation', tr: 'Anahtar yenileme' },
  },
  {
    path: '/certificates',
    session: sessionFor('operator'),
    status: installedStatus,
    ready: { en: 'Open signing requests', tr: 'Açık imzalama istekleri' },
  },
  { path: '/certificates', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'www.example.test', tr: 'www.example.test' } },
  {
    path: '/certificates/0192c000-0000-7000-8000-0000000000c1',
    session: sessionFor('operator'),
    status: installedStatus,
    ready: { en: 'Where this certificate is used', tr: 'Bu sertifika nerede kullanılıyor?' },
  },
  {
    path: `/servers/${nginxTargetFixture.id}`,
    session: sessionFor('operator'),
    status: installedStatus,
    ready: { en: 'Websites on this server', tr: 'Bu sunucudaki web siteleri' },
  },
  { path: '/deployments', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'Needs attention', tr: 'İlgilenilmesi gerekiyor' } },
  {
    path: '/deployments/0192c000-0000-7000-8000-0000000000d1',
    session: sessionFor('operator'),
    status: installedStatus,
    ready: { en: 'Deployment sequence', tr: 'Dağıtım adımları' },
  },
  { path: '/missing', session: null, status: installedStatus, ready: { en: 'Page not found', tr: 'Sayfa bulunamadı' } },
];
