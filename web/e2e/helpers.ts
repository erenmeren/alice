import { execFileSync } from 'node:child_process';
import { createHmac, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import AxeBuilder from '@axe-core/playwright';
import { test as base, expect, type APIRequestContext, type APIResponse, type Download, type Locator, type Page } from '@playwright/test';

declare global {
  interface Window {
    __aliceCspViolation?: (report: string) => void;
  }
}

// networkChangedMarker is where a failed attempt records that Chromium aborted requests with
// net::ERR_NETWORK_CHANGED; the next attempt of the same test looks for it.
function networkChangedMarker(testInfo: { project: { outputDir: string }; testId: string }): string {
  return join(testInfo.project.outputDir, '.network-changed', testInfo.testId);
}

// unexpectedCutOffs records every drain that cut off a running job while the test did not mean to
// interrupt one (drainJobs, drainUntil, settle). A cut-off fails at once where it happens, but a
// caller's toPass would retry past that failure; the cutOffGuard fixture fails the test at its end
// whenever one was recorded, so a cut-off can never be swallowed.
const unexpectedCutOffs: string[] = [];

function recordCutOff(where: string): void {
  unexpectedCutOffs.push(where);
}

// test is Playwright's test with three automatic fixtures (cutOffGuard: see unexpectedCutOffs above).
//
// cspGuard: a Content Security Policy violation on any page the test visits fails the test (the SPA
// must run under the strict CSP). It watches both the console ("… violates the following Content
// Security Policy directive …") and the DOM securitypolicyviolation event, which also fires for
// violations Chromium does not log.
//
// networkChangeGuard: a MITIGATION, not a fix (docs/dev/getting-started.md, "net::ERR_NETWORK_CHANGED").
// Chromium on Linux aborts every in-flight request with net::ERR_NETWORK_CHANGED when any host
// interface gains or loses an IP address, including requests to localhost; no Chromium switch turns
// this off. On a developer laptop that happens without the suite's involvement (an IPv6 address on
// Wi-Fi expiring and coming back, a container started by another process adding a veth). The guard
// records such aborts and annotates the test. A test is retried only when its failed attempt saw
// such an abort: playwright.config.ts allows one retry, and a retry of an attempt that
// failed without one fails at once with the reason, so no other failure is retried, locally and in
// CI alike (a real flake is never hidden by a retry).
export const test = base.extend<{ cspGuard: void; networkChangeGuard: void; cutOffGuard: void }>({
  cutOffGuard: [
    // Playwright reads a fixture's dependencies from this pattern: it needs none.
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      unexpectedCutOffs.length = 0;
      await use();
      expect(unexpectedCutOffs, 'a drain cut off a running job (it goes to recovery) although the test did not mean to interrupt one').toEqual([]);
    },
    { auto: true },
  ],
  networkChangeGuard: [
    async ({ context }, use, testInfo) => {
      const marker = networkChangedMarker(testInfo);
      if (testInfo.retry > 0) {
        if (!existsSync(marker)) {
          throw new Error(
            'not retried: the previous attempt failed without net::ERR_NETWORK_CHANGED; only failures caused by a ' +
              'host network change are retried (see the error of the previous attempt above)',
          );
        }
        testInfo.annotations.push({
          type: 'retried after network change',
          description: `the previous attempt failed while Chromium aborted: ${readFileSync(marker, 'utf8')}`,
        });
      }
      const aborted: string[] = [];
      context.on('requestfailed', (r) => {
        if (r.failure()?.errorText === 'net::ERR_NETWORK_CHANGED') aborted.push(`${r.method()} ${new URL(r.url()).pathname}`);
      });
      await use();
      if (aborted.length === 0) return;
      testInfo.annotations.push({ type: 'net::ERR_NETWORK_CHANGED', description: aborted.join(', ') });
      if (testInfo.status !== testInfo.expectedStatus) {
        mkdirSync(join(marker, '..'), { recursive: true });
        writeFileSync(marker, aborted.join(', '));
      }
    },
    { auto: true },
  ],
  cspGuard: [
    async ({ page }, use) => {
      const violations: string[] = [];
      page.on('console', (m) => {
        if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) violations.push(`console on ${page.url()}: ${m.text()}`);
      });
      await page.exposeFunction('__aliceCspViolation', (report: string) => violations.push(`event: ${report}`));
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (e) => {
          window.__aliceCspViolation?.(`${e.effectiveDirective} blocked ${e.blockedURI || 'inline'} on ${e.documentURI}`);
        });
      });
      await use();
      expect(violations, 'CSP violations').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

export type Lang = 'en' | 'tr';

// UI copy from the Phase 1 and Phase 2 plans (exact strings shown by the web app).
export const COPY = {
  en: {
    wizardHeading: 'Set up Alice',
    setupCode: 'Setup code',
    continue: 'Continue',
    languageHeading: 'Choose your language',
    adminHeading: 'Create the administrator account',
    username: 'Username',
    fullName: 'Full name',
    email: 'Email (optional)',
    password: 'Password',
    repeatPassword: 'Repeat password',
    totpHeading: 'Set up your authenticator app',
    code: '6-digit code',
    verify: 'Verify',
    recoveryHeading: 'Save your recovery codes',
    savedCodes: 'I saved these codes in a safe place',
    passphraseHeading: 'Choose a recovery passphrase',
    passphrase: 'Recovery passphrase',
    repeatPassphrase: 'Repeat the passphrase',
    storedPassphrase: 'I stored the passphrase safely',
    savePassphrase: 'Save passphrase',
    licenseHeading: 'Add a license',
    startEvaluation: 'Start 30-day evaluation (up to 5 targets)',
    licenseFile: 'License file',
    checkFile: 'Check the file',
    confirmLicense: 'Confirm the license',
    installLicense: 'Install license',
    doneHeading: 'Alice is ready',
    platformHeading: 'Connect your servers',
    toDashboard: 'Go to the dashboard',
    loginHeading: 'Sign in to Alice',
    signIn: 'Sign in',
    mfaHeading: 'Enter your verification code',
    invalidCredentials: 'Incorrect username or password.',
    mfaInvalid: 'The verification code is not correct.',
    sessionEnded: 'Your session ended. Please sign in again.',
    navHome: 'Home',
    navUsers: 'People & access',
    navAudit: 'Audit trail',
    navTokens: 'API tokens',
    navAccount: 'Your account',
    signOut: 'Sign out',
    noAccess: 'You do not have access to this page.',
    usersHeading: 'People & access',
    addUser: 'Add user',
    role: 'Role',
    initialPassword: 'Initial password',
    createUser: 'Create user',
    stepUpHeading: "Confirm it's you",
    stepUpConfirm: 'Confirm',
    auditHeading: 'Audit trail',
    verifyIntegrity: 'Verify integrity',
    intact: 'The audit log is intact.',
    userCreatedAction: 'User created',
    tokensHeading: 'API tokens',
    accountHeading: 'Your account',
    navLabel: 'Main navigation',
    openNav: 'Open navigation',
    closeNav: 'Close navigation',
    createToken: 'Create token',
    tokenName: 'Name',
    tokenSubmit: 'Create',
    tokenCreatedTitle: 'Your new token',
    tokenDone: 'Done',
    revokeNamed: (name: string) => `Revoke token ${name}`,
    revokeTitle: (name: string) => `Revoke the token ${name}?`,
    revokeConfirm: 'Revoke token',
    manageNamed: (name: string) => `Manage ${name}`,
    manageTitle: (name: string) => `Manage ${name}`,
    edit: 'Edit',
    editTitle: (name: string) => `Edit ${name}`,
    setNewPassword: 'Set a new password',
    setPasswordTitle: (name: string) => `Set a new password for ${name}`,
    resetMfa: 'Reset two-factor sign-in',
    resetMfaTitle: (name: string) => `Reset two-factor sign-in for ${name}?`,
    cancel: 'Cancel',
    newRecoveryCodes: 'Create new recovery codes',
    recoveryCodesActive: 'Your new recovery codes are active.',
    useRecovery: 'Use a recovery code',
    recoveryCode: 'Recovery code',
    notFoundTitle: 'Page not found',
    // Phase 5 (Key Vault): the contract's UI copy, pinned in both languages; the other texts of the
    // journeys are read from the locale files (translator).
    kv: {
      title: 'Key Vaults',
      add: 'Add Key Vault',
      added: 'Key Vault added.',
      openVault: 'Open the vault',
      checkNow: 'Check now',
      finished: 'Finished.',
      monitorOnly: 'Monitor only',
      newVersion: 'New version found',
      held: 'Held',
      connect: 'Connect websites',
      autoDeployment: 'Automatic deployment',
      switchOn: 'Switch on',
      deployNow: 'Deploy now',
      release: 'Release',
      importAction: 'Import into Key Vault',
      imported: 'Imported',
      removeVault: 'Remove Key Vault',
      removeVaultAndConnections: 'Remove the connections and the vault',
      deleteConnection: 'Delete connection',
      sourceNamed: (name: string) => `From Key Vault: ${name}`,
      readStep: 'Read the certificate from Key Vault',
      deployedVersion: 'Deployed: version',
      missingPermission: 'Missing permission in the vault',
      secretsUser: 'Key Vault Secrets User',
      degraded: 'Partly working',
      degradedHelp: 'Alice reaches this vault only in part. The reason is shown below.',
      releaseMay: 'Automatic deployment is on, so Alice may deploy this version to the connected websites by itself, usually within a minute.',
      releasedMay: 'Version released. Alice may deploy it by itself, usually within a minute.',
      releaseManual: 'Nothing is deployed. Use Deploy now when you want this version on a website.',
      heldText:
        'This version is waiting for an administrator: the license was not available at some point since the version appeared. Alice does not deploy it by itself; an administrator can deploy or release it.',
      releasedManual: 'Version released. Nothing is deployed; use Deploy now when you want it on a website.',
      heldChain: 'Held because its certificate chain is incomplete. An administrator can deploy it after confirming the chain, or release it.',
      releaseChain:
        'Automatic deployment never deploys an incomplete chain: if the chain is still incomplete, Alice holds this version again. To deploy it as it is, use Deploy now and confirm the chain.',
      releasedChain: 'Version released. Automatic deployment will not deploy an incomplete chain; use Deploy now and confirm the chain.',
      releaseChainManual: 'Nothing is deployed. Deploy now asks for the chain confirmation again when you deploy this version.',
      releasedChainManual: 'Version released. Nothing is deployed; Deploy now asks for the chain confirmation again.',
      confirmChain: 'I confirm that this incomplete chain is intended',
      firewall: 'Vault firewall blocks Alice',
      firewallAddress: "Alice's address as the vault saw it",
      throttled: 'Azure asked Alice to slow down',
      autoFollows: 'Automatic deployment is on for it, so Alice may deploy the new version to those websites by itself.',
      boundNote: 'Websites are connected to this vault certificate.',
    },
    // Phase 6 (SSH key lifecycle and rotation): the contract's key texts (C14), pinned in both languages; the other
    // texts of the journeys are read from the locale files (translator).
    ssh: {
      generate: 'Generate key',
      ed25519: 'Ed25519 (recommended)',
      managedBadge: 'Generated by Alice',
      deploy: 'Deploy to a server',
      verified: 'Alice added the key and verified a login with it.',
      unverified: 'Alice added the key but could not test a login with it.',
      download: 'Download private key',
      createPolicy: 'Create rotation policy',
      offHelp: 'The policy is off. Alice plans no run until you switch it on.',
      preview: 'Preview next run',
      runNow: 'Run now',
      runConfirm: 'Start rotation',
      willChange: 'Will change',
      continueRun: 'Continue',
      finishNow: 'Finish now',
      keepOld: 'Keep the old key on these servers',
      abort: 'Stop and undo',
    },
  },
  tr: {
    wizardHeading: 'Alice kurulumu',
    setupCode: 'Kurulum kodu',
    continue: 'Devam',
    languageHeading: 'Dilinizi seçin',
    adminHeading: 'Yönetici hesabını oluşturun',
    username: 'Kullanıcı adı',
    fullName: 'Ad soyad',
    email: 'E-posta (isteğe bağlı)',
    password: 'Parola',
    repeatPassword: 'Parolayı tekrar girin',
    totpHeading: 'Doğrulama uygulamanızı kurun',
    code: '6 haneli kod',
    verify: 'Doğrula',
    recoveryHeading: 'Kurtarma kodlarınızı kaydedin',
    savedCodes: 'Bu kodları güvenli bir yere kaydettim',
    passphraseHeading: 'Kurtarma parolası belirleyin',
    passphrase: 'Kurtarma parolası',
    repeatPassphrase: 'Kurtarma parolasını tekrar girin',
    storedPassphrase: 'Kurtarma parolasını güvenli bir yerde sakladım',
    savePassphrase: 'Parolayı kaydet',
    licenseHeading: 'Lisans ekleyin',
    startEvaluation: '30 günlük denemeyi başlat (en fazla 5 hedef)',
    licenseFile: 'Lisans dosyası',
    checkFile: 'Dosyayı denetle',
    confirmLicense: 'Lisansı onaylayın',
    installLicense: 'Lisansı yükle',
    doneHeading: 'Alice hazır',
    platformHeading: 'Sunucularınızı bağlayın',
    toDashboard: 'Ana sayfaya git',
    loginHeading: "Alice'e giriş yapın",
    signIn: 'Giriş yap',
    mfaHeading: 'Doğrulama kodunuzu girin',
    invalidCredentials: 'Kullanıcı adı veya parola hatalı.',
    mfaInvalid: 'Doğrulama kodu hatalı.',
    sessionEnded: 'Oturumunuz sona erdi. Lütfen yeniden giriş yapın.',
    navHome: 'Ana sayfa',
    navUsers: 'Kişiler ve erişim',
    navAudit: 'Denetim kaydı',
    navTokens: 'API anahtarları',
    navAccount: 'Hesabınız',
    signOut: 'Çıkış yap',
    noAccess: 'Bu sayfaya erişim yetkiniz yok.',
    usersHeading: 'Kişiler ve erişim',
    addUser: 'Kullanıcı ekle',
    role: 'Rol',
    initialPassword: 'İlk parola',
    createUser: 'Kullanıcıyı oluştur',
    stepUpHeading: 'Kimliğinizi doğrulayın',
    stepUpConfirm: 'Onayla',
    auditHeading: 'Denetim kaydı',
    verifyIntegrity: 'Bütünlüğü doğrula',
    intact: 'Denetim kaydı sağlam.',
    userCreatedAction: 'Kullanıcı oluşturuldu',
    tokensHeading: 'API anahtarları',
    accountHeading: 'Hesabınız',
    navLabel: 'Ana gezinme',
    openNav: 'Gezinmeyi aç',
    closeNav: 'Gezinmeyi kapat',
    createToken: 'Anahtar oluştur',
    tokenName: 'Ad',
    tokenSubmit: 'Oluştur',
    tokenCreatedTitle: 'Yeni anahtarınız',
    tokenDone: 'Tamam',
    revokeNamed: (name: string) => `İptal et: ${name}`,
    revokeTitle: (name: string) => `İptal edilecek anahtar: ${name}`,
    revokeConfirm: 'Anahtarı iptal et',
    manageNamed: (name: string) => `Yönet: ${name}`,
    manageTitle: (name: string) => `Yönetilen kullanıcı: ${name}`,
    edit: 'Düzenle',
    editTitle: (name: string) => `Düzenlenen kullanıcı: ${name}`,
    setNewPassword: 'Yeni parola belirle',
    setPasswordTitle: (name: string) => `Yeni parola belirlenecek kullanıcı: ${name}`,
    resetMfa: 'İki adımlı girişi sıfırla',
    resetMfaTitle: (name: string) => `İki adımlı giriş sıfırlanacak kullanıcı: ${name}`,
    cancel: 'Vazgeç',
    newRecoveryCodes: 'Yeni kurtarma kodları oluştur',
    recoveryCodesActive: 'Yeni kurtarma kodlarınız etkin.',
    useRecovery: 'Kurtarma kodu kullan',
    recoveryCode: 'Kurtarma kodu',
    notFoundTitle: 'Sayfa bulunamadı',
    kv: {
      title: 'Key Vault kasaları',
      add: 'Key Vault ekle',
      added: 'Key Vault eklendi.',
      openVault: 'Kasayı aç',
      checkNow: 'Şimdi denetle',
      finished: 'Tamamlandı.',
      monitorOnly: 'Yalnızca izleme',
      newVersion: 'Yeni sürüm bulundu',
      held: 'Bekletiliyor',
      connect: 'Web sitelerine bağla',
      autoDeployment: 'Otomatik dağıtım',
      switchOn: 'Aç',
      deployNow: 'Şimdi dağıt',
      release: 'Serbest bırak',
      importAction: "Key Vault'a aktar",
      imported: 'İçe aktarıldı',
      removeVault: "Key Vault'u kaldır",
      removeVaultAndConnections: 'Bağlantıları ve kasayı kaldır',
      deleteConnection: 'Bağlantıyı sil',
      sourceNamed: (name: string) => `Key Vault'tan: ${name}`,
      readStep: "Sertifikayı Key Vault'tan okuma",
      deployedVersion: 'Dağıtıldı: sürüm',
      missingPermission: 'Kasada eksik izin',
      secretsUser: 'Key Vault Secrets User',
      degraded: 'Kısmen çalışıyor',
      degradedHelp: 'Alice bu kasaya yalnızca kısmen ulaşabiliyor. Nedeni aşağıda gösterilir.',
      releaseMay: 'Otomatik dağıtım açık; Alice bu sürümü bağlı web sitelerine kendiliğinden dağıtabilir, genellikle bir dakika içinde.',
      releasedMay: 'Sürüm serbest bırakıldı. Alice bu sürümü kendiliğinden dağıtabilir, genellikle bir dakika içinde.',
      releaseManual: 'Hiçbir şey dağıtılmaz. Bu sürümü bir web sitesinde istediğinizde Şimdi dağıt düğmesini kullanın.',
      heldText:
        'Bu sürüm bir yöneticiyi bekliyor: sürüm ortaya çıktıktan sonra bir süre lisans kullanılamadı. Alice bu sürümü kendiliğinden dağıtmaz; bir yönetici dağıtabilir veya serbest bırakabilir.',
      releasedManual: 'Sürüm serbest bırakıldı. Hiçbir şey dağıtılmaz; istediğinizde Şimdi dağıt düğmesini kullanın.',
      heldChain: 'Sertifika zinciri eksik olduğu için bekletiliyor. Bir yönetici zinciri onaylayarak dağıtabilir ya da serbest bırakabilir.',
      releaseChain:
        'Otomatik dağıtım eksik bir zinciri hiçbir zaman dağıtmaz: zincir hâlâ eksikse Alice bu sürümü yeniden bekletir. Olduğu gibi dağıtmak için Şimdi dağıt düğmesini kullanın ve zinciri onaylayın.',
      releasedChain: 'Sürüm serbest bırakıldı. Otomatik dağıtım eksik bir zinciri dağıtmaz; Şimdi dağıt düğmesini kullanın ve zinciri onaylayın.',
      releaseChainManual: 'Hiçbir şey dağıtılmaz. Bu sürümü dağıttığınızda Şimdi dağıt zincir onayını yeniden ister.',
      releasedChainManual: 'Sürüm serbest bırakıldı. Hiçbir şey dağıtılmaz; Şimdi dağıt zincir onayını yeniden ister.',
      confirmChain: 'Bu eksik zincirin bilerek kullanıldığını onaylıyorum',
      firewall: "Kasanın güvenlik duvarı Alice'i engelliyor",
      firewallAddress: 'Kasanın gördüğü Alice adresi',
      throttled: "Azure, Alice'ten yavaşlamasını istedi",
      autoFollows: 'Bunun için otomatik dağıtım açık; bu yüzden Alice yeni sürümü bu web sitelerine kendiliğinden dağıtabilir.',
      boundNote: 'Bu kasa sertifikasına web siteleri bağlı.',
    },
    ssh: {
      generate: 'Anahtar oluştur',
      ed25519: 'Ed25519 (önerilir)',
      managedBadge: 'Alice tarafından oluşturuldu',
      deploy: 'Sunucuya dağıt',
      verified: 'Alice anahtarı ekledi ve anahtarla oturum açılabildiğini doğruladı.',
      unverified: 'Alice anahtarı ekledi ancak anahtarla oturum açmayı deneyemedi.',
      download: 'Özel anahtarı indir',
      createPolicy: 'Yenileme kuralı oluştur',
      offHelp: 'Kural kapalı. Siz açana kadar Alice hiçbir çalıştırma planlamaz.',
      preview: 'Sonraki çalıştırmayı önizle',
      runNow: 'Şimdi çalıştır',
      runConfirm: 'Yenilemeyi başlat',
      willChange: 'Değişecek',
      continueRun: 'Devam et',
      finishNow: 'Şimdi bitir',
      keepOld: 'Bu sunucularda eski anahtarı tut',
      abort: 'Durdur ve geri al',
    },
  },
} as const;

export type Copy = (typeof COPY)[Lang];

export function browserLocale(lang: Lang): string {
  return lang === 'tr' ? 'tr-TR' : 'en-US';
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// field finds an input by its exact label; Mantine appends " *" to required labels.
export function field(scope: Page | Locator, label: string): Locator {
  return scope.getByLabel(new RegExp(`^${escapeRegExp(label)}( \\*)?$`));
}

// either matches a copy string in English or Turkish (substring), for screens reached before the
// language is known or after a user's own language setting may have switched it.
export function either(key: 'loginHeading' | 'noAccess' | 'sessionEnded' | 'wizardHeading' | 'signOut'): RegExp {
  return new RegExp(`${escapeRegExp(COPY.en[key])}|${escapeRegExp(COPY.tr[key])}`);
}

// uiLang reads the language the app is currently rendered in (<html lang>).
export async function uiLang(page: Page): Promise<Lang> {
  return (await page.locator('html').getAttribute('lang')) === 'tr' ? 'tr' : 'en';
}

// expectSignedInAs proves who is signed in after a sign-in or the wizard: the Overview heading and the sidebar's name
// (the design has no personal "Welcome" heading; label change 2 of docs/superpowers/plans/2026-10-12-phase-9-design.md).
// The heading matches either language: the account's language is applied after the shell first renders, so reading the
// page language once could pick the one that is about to change (a new account starts in English on a Turkish run).
export async function expectSignedInAs(page: Page, name: string): Promise<void> {
  const title = (lang: Lang) => escapeRegExp(translator(lang)('dashboard.title'));
  await expect(page.getByRole('heading', { level: 1, name: new RegExp(`${title('en')}|${title('tr')}`) })).toBeVisible();
  await expect(page.getByTestId('current-user')).toHaveText(name);
}

export async function resetInstall(request: APIRequestContext): Promise<void> {
  const res = await request.post('/test/reset');
  expect(res.status(), 'POST /test/reset (is this the e2e build? run make e2e-up)').toBe(204);
}

export async function serverNow(request: APIRequestContext): Promise<number> {
  const res = await request.get('/test/clock');
  expect(res.ok()).toBe(true);
  const { now } = (await res.json()) as { now: string };
  return Date.parse(now.replace(/(\.\d{3})\d+/, '$1'));
}

export async function advanceClock(request: APIRequestContext, seconds: number): Promise<void> {
  const res = await request.post('/test/clock', { data: { advance_seconds: seconds } });
  expect(res.ok()).toBe(true);
}

export async function setupCode(request: APIRequestContext): Promise<string> {
  const res = await request.post('/test/setup-token');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { code: string }).code;
}

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.replace(/[\s=]/g, '')) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// totp computes the RFC 6238 code (SHA-1, 6 digits, 30 s) for the given instant.
export function totp(secretBase32: string, atMs: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / 30)));
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}

// freshCode moves the server clock past the last used 30 s step, so a code is never replayed,
// and returns the code for the server's current time.
export async function freshCode(request: APIRequestContext, secret: string): Promise<string> {
  await advanceClock(request, 31);
  return totp(secret, await serverNow(request));
}

// enrollTotp completes the "Set up your authenticator app" and recovery-code screens.
// With a11y set, each screen is also checked with axe (expectAccessible).
export async function enrollTotp(
  page: Page,
  request: APIRequestContext,
  c: Copy,
  a11y = false,
): Promise<{ totpSecret: string; recoveryCodes: string[] }> {
  await expect(page.getByRole('heading', { name: c.totpHeading })).toBeVisible();
  await expect(page.locator('img[src^="data:image/png;base64,"]')).toBeVisible();
  if (a11y) await expectAccessible(page, 'authenticator setup');
  const totpSecret = ((await page.getByTestId('totp-secret').textContent()) ?? '').replace(/\s/g, '');
  expect(totpSecret).toMatch(/^[A-Z2-7]{32}$/);
  await field(page, c.code).fill(totp(totpSecret, await serverNow(request)));
  await page.getByRole('button', { name: c.verify }).click();
  await expect(page.getByRole('heading', { name: c.recoveryHeading })).toBeVisible();
  const text = (await page.getByTestId('recovery-codes').textContent()) ?? '';
  const recoveryCodes = text.match(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/g) ?? [];
  expect(recoveryCodes).toHaveLength(10);
  if (a11y) await expectAccessible(page, 'recovery codes');
  await page.getByLabel(c.savedCodes).check();
  await page.getByRole('button', { name: c.continue }).click();
  return { totpSecret, recoveryCodes };
}

export interface Account {
  username: string;
  fullName: string;
  email?: string;
  password: string;
}

export const ADMIN: Account = { username: 'admin', fullName: 'Ada Yılmaz', password: 'correct-horse-battery-2026' };
export const PASSPHRASE = 'kırmızı-kedi-mavi-deniz-2026';

// runWizard installs Alice from scratch through every setup wizard step, including the Phase 2
// license step: it starts the evaluation, or uploads opts.license (a license file's text). The
// Phase 8 HTTPS and mail steps keep the temporary certificate and skip the mail server.
// With opts.a11y, every wizard screen is also checked with axe (expectAccessible).
export async function runWizard(
  page: Page,
  request: APIRequestContext,
  lang: Lang,
  admin: Account = ADMIN,
  opts: { a11y?: boolean; license?: 'evaluation' | string } = {},
): Promise<{ totpSecret: string; recoveryCodes: string[] }> {
  const c = COPY[lang];
  const code = await setupCode(request);
  await page.goto('/');
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole('heading', { name: c.wizardHeading })).toBeVisible();
  await field(page, c.setupCode).fill(code);
  await page.getByRole('button', { name: c.continue }).click();

  await expect(page.getByRole('heading', { name: c.languageHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard language');
  await page.getByRole('button', { name: c.continue }).click(); // keeps the preselected (current) language

  await expect(page.getByRole('heading', { name: c.adminHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard administrator');
  await field(page, c.username).fill(admin.username);
  await field(page, c.fullName).fill(admin.fullName);
  if (admin.email) await field(page, c.email).fill(admin.email);
  await field(page, c.password).fill('too-short11');
  await field(page, c.repeatPassword).fill('too-short11');
  await page.getByRole('button', { name: c.continue }).click();
  // Alice refuses a password shorter than 12 characters and says why (the minimum is shown).
  await expect(page.getByRole('alert').or(page.locator('input[aria-invalid="true"]')).first()).toBeVisible();
  await expect(page.getByText(/\b12\b/).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: c.totpHeading })).toHaveCount(0);
  if (opts.a11y) await expectAccessible(page, 'wizard administrator with error');

  await field(page, c.password).fill(admin.password);
  await field(page, c.repeatPassword).fill(admin.password);
  await page.getByRole('button', { name: c.continue }).click();
  const enrolled = await enrollTotp(page, request, c, opts.a11y);

  await expect(page.getByRole('heading', { name: c.passphraseHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard passphrase');
  await field(page, c.passphrase).fill(PASSPHRASE);
  await field(page, c.repeatPassphrase).fill(PASSPHRASE);
  await page.getByLabel(c.storedPassphrase).check();
  await page.getByRole('button', { name: c.savePassphrase }).click();

  // Phase 8 wizard steps (R43 row 16) with their default choices: keep the temporary HTTPS certificate, skip the mail
  // server. The dashboard's "Finish setting up" list keeps both open.
  await keepTemporaryCertificateStep(page, lang, opts.a11y);
  await skipMailStep(page, lang, opts.a11y);

  await expect(page.getByRole('heading', { name: c.licenseHeading })).toBeVisible();
  await expect(page.getByTestId('installation-id')).toHaveText(/^ALICE(-[0-9A-Z]{4}){4}$/);
  if (opts.a11y) await expectAccessible(page, 'wizard license');
  if (opts.license && opts.license !== 'evaluation') {
    await uploadLicense(page, c, opts.license);
  } else {
    await page.getByRole('button', { name: c.startEvaluation }).click();
  }

  // Phase 3 wizard step 7: Alice's public key and the server preparation commands; adding a server is optional.
  await expect(page.getByRole('heading', { name: c.platformHeading })).toBeVisible();
  await expect(page.getByTestId('platform-public-key')).toContainText('ssh-ed25519 ');
  if (opts.a11y) await expectAccessible(page, 'wizard platform key');
  await page.getByRole('button', { name: c.continue, exact: true }).click();

  await expect(page.getByRole('heading', { name: c.doneHeading })).toBeVisible();
  if (opts.a11y) await expectAccessible(page, 'wizard done');
  await page.getByRole('button', { name: c.toDashboard }).click();
  await expectSignedInAs(page, admin.fullName);
  return enrolled;
}

// keepTemporaryCertificateStep answers the wizard's HTTPS step with "Keep the temporary certificate".
export async function keepTemporaryCertificateStep(page: Page, lang: Lang, a11y = false): Promise<void> {
  const t = translator(lang);
  await expect(page.getByRole('heading', { name: t('setup.https.title'), exact: true })).toBeVisible();
  const keep = page.getByTestId('https-keep-temporary');
  await expect(keep).toHaveText(t('https.keepTemporary'));
  if (a11y) await expectAccessible(page, 'wizard HTTPS certificate');
  await keep.click();
}

// skipMailStep answers the wizard's mail server step with Skip.
export async function skipMailStep(page: Page, lang: Lang, a11y = false): Promise<void> {
  const t = translator(lang);
  await expect(page.getByRole('heading', { name: t('setup.mail.title'), exact: true })).toBeVisible();
  const skip = page.getByTestId('setup-skip');
  await expect(skip).toHaveText(t('setup.skip'));
  if (a11y) await expectAccessible(page, 'wizard mail server');
  await skip.click();
}

// uploadHttpsPair chooses a PEM certificate and key file in the HTTPS upload form inside scope (the wizard step or
// Settings → HTTPS certificate) and uploads them. The files exist only in memory; the caller answers a step-up prompt
// if one may appear.
export async function uploadHttpsPair(scope: Page | Locator, lang: Lang, pair: PemPair): Promise<void> {
  const t = translator(lang);
  const form = scope.getByTestId('https-upload-form');
  await form.getByRole('radio', { name: t('https.formatPem'), exact: true }).check();
  await form.getByLabel(t('https.certFile'), { exact: true }).setInputFiles({ name: 'alice.crt', mimeType: 'application/x-pem-file', buffer: Buffer.from(pair.cert) });
  await form.getByLabel(t('https.keyFile'), { exact: true }).setInputFiles({ name: 'alice.key', mimeType: 'application/x-pem-file', buffer: Buffer.from(pair.key) });
  await form.getByRole('button', { name: t('https.upload'), exact: true }).click();
}

// uploadLicense chooses a license file, checks it and confirms the preview dialog. The caller
// answers a step-up prompt first if one may appear (see confirmWithStepUp in the specs).
export async function uploadLicense(page: Page, c: Copy, fileText: string, a11y = false): Promise<void> {
  await field(page, c.licenseFile).setInputFiles({ name: 'alice-license.alicelic', mimeType: 'application/json', buffer: Buffer.from(fileText) });
  await page.getByRole('button', { name: c.checkFile }).click();
  const dialog = page.getByRole('dialog', { name: c.confirmLicense });
  await expect(dialog).toBeVisible();
  if (a11y) await expectAccessible(page, 'license preview dialog');
  await dialog.getByRole('button', { name: c.installLicense }).click();
  await expect(dialog).toHaveCount(0);
}

// submitLogin fills the sign-in form and returns the HTTP status of POST /auth/login.
export async function submitLogin(page: Page, c: Copy, username: string, password: string): Promise<number> {
  await expect(page.getByRole('heading', { name: c.loginHeading })).toBeVisible();
  await field(page, c.username).fill(username);
  await field(page, c.password).fill(password);
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/api/v1/auth/login') && r.request().method() === 'POST'),
    page.getByRole('button', { name: c.signIn, exact: true }).click(), // not "Sign in with <identity provider>"
  ]);
  return res.status();
}

// signIn signs an enrolled user in with password and a fresh TOTP code.
export async function signIn(page: Page, request: APIRequestContext, account: Account, totpSecret: string): Promise<void> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  const c = COPY[await uiLang(page)];
  expect(await submitLogin(page, c, account.username, account.password)).toBe(200);
  await expect(page.getByRole('heading', { name: c.mfaHeading })).toBeVisible();
  await field(page, c.code).fill(await freshCode(request, totpSecret));
  await page.getByRole('button', { name: c.verify }).click();
  // The app switches to the user's own language once signed in, which may differ from the sign-in page's.
  await expect(page.getByRole('button', { name: either('signOut') })).toBeVisible();
}

// firstSignIn signs in a user created by an administrator; they enroll TOTP at the first sign-in.
export async function firstSignIn(page: Page, request: APIRequestContext, account: Account): Promise<string> {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  const c = COPY[await uiLang(page)];
  expect(await submitLogin(page, c, account.username, account.password)).toBe(200);
  const { totpSecret } = await enrollTotp(page, request, c);
  await expect(page.getByRole('button', { name: COPY[await uiLang(page)].signOut })).toBeVisible();
  return totpSecret;
}

// tabTo presses Tab (and nothing else) until the target has keyboard focus.
export async function tabTo(page: Page, target: Locator, maxPresses = 25): Promise<void> {
  for (let i = 0; i < maxPresses; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return;
    await page.keyboard.press('Tab');
  }
  await expect(target, `reachable with Tab within ${maxPresses} presses`).toBeFocused({ timeout: 1 });
}

// signOut signs out and proves the server session ended: reloading the app shows the sign-in page.
export async function signOut(page: Page): Promise<void> {
  const c = COPY[await uiLang(page)];
  await page.getByRole('button', { name: c.signOut }).click();
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
  await expect(page.getByRole('button', { name: c.signOut })).toHaveCount(0);
}

// AXE_WIDTHS are the widths every screen must work at: the desktop widths of spec §26.1 item 9,
// plus 640 px (a narrow window or tablet), where the navigation collapses behind a menu button.
export const AXE_WIDTHS = [640, 1280, 1920] as const;

// AxeOptions: soft records a finding and lets the test go on (it still fails at its end), so one run
// lists every violation of every screen instead of the first; dialog is a dialog the screen shows,
// awaited before the scan (an opening dialog that is not on screen yet would not be checked at all).
export interface AxeOptions {
  soft?: boolean;
  dialog?: Locator;
  // only limits the scan to this part of the screen (a dialog over a page whose own finding a separate test reports);
  // the width check still covers the whole screen.
  only?: Locator;
}

// expectAccessible checks the current screen at each width in AXE_WIDTHS and restores the viewport.
export async function expectAccessible(page: Page, screen: string, opts: AxeOptions = {}): Promise<void> {
  await checkWidths(page, screen, AXE_WIDTHS, opts);
}

// expectAccessibleAt checks the current screen at the given widths (the Phase 6 screens: a phone, a tablet and the
// desktop widths) and restores the viewport.
export async function expectAccessibleAt(page: Page, screen: string, widths: readonly number[], opts: AxeOptions = {}): Promise<void> {
  await checkWidths(page, screen, widths, opts);
}

async function checkWidths(page: Page, screen: string, widths: readonly number[], opts: AxeOptions): Promise<void> {
  const check = opts.soft ? expect.soft : expect;
  if (opts.dialog) await expect(opts.dialog, `${screen}: the dialog is on screen`).toBeVisible();
  const original = page.viewportSize();
  try {
    for (const width of widths) {
      await page.setViewportSize({ width, height: original?.height ?? 720 });
      check(await seriousViolations(page, opts.only), `axe: ${screen} at ${width} px`).toEqual([]);
      // The screen fits the width: no horizontal scrolling.
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      check(overflow, `horizontal overflow: ${screen} at ${width} px`).toBeLessThanOrEqual(0);
    }
  } finally {
    if (original) await page.setViewportSize(original);
  }
}

export async function seriousViolations(page: Page, only?: Locator): Promise<string[]> {
  // Let opening dialogs finish their fade-in first: axe measures colors mid-transition as
  // too pale. Endless animations (loaders) never finish, so they are not waited for.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getComputedTiming().iterations !== Infinity)
        .map((a) => a.finished.catch(() => undefined)),
    ),
  );
  const axe = new AxeBuilder({ page });
  if (only) {
    await only.evaluate((el) => el.setAttribute('data-axe-only', ''));
    axe.include('[data-axe-only]');
  }
  let results;
  try {
    results = await axe.analyze();
  } finally {
    if (only) await only.evaluate((el) => el.removeAttribute('data-axe-only'));
  }
  return results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.impact}: ${v.id} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`);
}

// --- Phase 3: the e2e SSH target, background jobs and API calls as the signed-in browser user ---

// E2E_PROJECT is the compose project of the e2e stack (make e2e-up; the Makefile passes it as
// ALICE_E2E_PROJECT). The owner's own stack is the project "alice"; tests never address it, and
// targetExec insists on a project name starting with alice-e2e.
const E2E_PROJECT = process.env.ALICE_E2E_PROJECT || 'alice-e2e';

// COMPOSE addresses the e2e stack of this repository; tests run from web/.
const COMPOSE = [
  'compose',
  '-p',
  E2E_PROJECT,
  '-f',
  '../deploy/docker-compose.yml',
  '-f',
  '../deploy/docker-compose.e2e.yml',
  '--env-file',
  '../deploy/.env',
];

// composeExec runs a command in one service of the e2e stack and returns its standard output. It
// never addresses another compose project: only projects named alice-e2e* are e2e stacks (never the
// owner stack "alice").
function composeExec(service: string, args: string[], input?: string): string {
  if (!E2E_PROJECT.startsWith('alice-e2e')) {
    throw new Error(`${service} exec refuses the compose project "${E2E_PROJECT}": only projects named alice-e2e* are e2e stacks (never the owner stack "alice")`);
  }
  return execFileSync('docker', [...COMPOSE, 'exec', '-T', service, ...args], {
    input,
    encoding: 'utf8',
    timeout: 120_000,
  });
}

// targetExec runs a command as root in the e2e SSH target service "sshtarget" and returns its
// standard output. It never addresses any other service or compose project.
export function targetExec(args: string[], input?: string): string {
  return composeExec('sshtarget', args, input);
}

export interface DrainResult {
  ran: number;
  cut_off?: boolean;
}

// DRAIN_RUNNING is the body of the drain endpoint's 409 while another drain runs (cmd/alice
// testapi_e2e.go); only that answer is waited out. Its other 409 ("no job runner"), a 5xx or a
// failed request fail the step at once.
const DRAIN_RUNNING = 'a drain is already running';

// drainJobs runs every due background job now (e2e build: serve starts no job workers). The server
// claims jobs for 20 s and lets the last one run until 50 s, so the request waits up to 60 s (the
// default 30 s would give up while a deployment still runs). The answer is {"ran": n}, plus
// "cut_off": true when the server's budget ended with a job still running. Only one drain runs at a
// time: while another one runs (for example one whose client gave up) the server answers 409 "a
// drain is already running", and only that answer is retried.
// A cut-off fails the test unless opts.allowCutOff (a journey that means to interrupt a job).
export async function drainJobs(request: APIRequestContext, opts: { allowCutOff?: boolean } = {}): Promise<DrainResult> {
  let status = 0;
  let body = '';
  let failure = '';
  await expect
    .poll(
      async () => {
        try {
          const res = await request.post('/test/jobs/drain', { timeout: 60_000 });
          status = res.status();
          body = await res.text();
        } catch (e) {
          failure = String(e);
          return 'answered';
        }
        return status === 409 && body.includes(DRAIN_RUNNING) ? 'another drain runs' : 'answered';
      },
      { message: 'POST /test/jobs/drain: another drain is still running', timeout: 120_000, intervals: [250, 500, 1_000] },
    )
    .toBe('answered');
  expect(failure, 'POST /test/jobs/drain failed').toBe('');
  expect(status, `POST /test/jobs/drain (is this the e2e build?): ${body}`).toBe(200);
  const result = JSON.parse(body) as DrainResult;
  if (result.cut_off && !opts.allowCutOff) {
    recordCutOff('drainJobs');
    expect(result.cut_off, 'a drain cut off a running job (it goes to recovery)').toBe(false);
  }
  return result;
}

// drainUntil runs due jobs until check passes (a job finishes, then the page or the API shows its
// result). A drain that cuts a job off ends the wait with a failure (toPass would otherwise retry
// past it) and is recorded, so it fails the test even when drainUntil runs inside a caller's toPass.
export async function drainUntil(request: APIRequestContext, check: () => Promise<void>, timeout = 90_000): Promise<void> {
  let cutOff = false;
  await expect(async () => {
    cutOff = (await drainJobs(request, { allowCutOff: true })).cut_off ?? false;
    if (cutOff) return; // stop waiting: reported below
    await check();
  }).toPass({ timeout });
  if (cutOff) recordCutOff('drainUntil');
  expect(cutOff, 'a drain cut off a running job (it goes to recovery)').toBe(false);
}

// settle runs due jobs until done is visible: a job finishes, then the page's polling shows its result.
export async function settle(request: APIRequestContext, done: Locator): Promise<void> {
  await drainUntil(request, () => expect(done).toBeVisible({ timeout: 1_500 }));
}

// fingerprintOf extracts "SHA256:…" from the output of ssh-keygen -lf.
export function fingerprintOf(sshKeygenOutput: string): string {
  const m = sshKeygenOutput.match(/SHA256:[A-Za-z0-9+/]+/);
  expect(m, `fingerprint in: ${sshKeygenOutput}`).not.toBeNull();
  return m![0];
}

export interface Api {
  get(path: string): Promise<APIResponse>;
  post(path: string, data?: unknown, headers?: Record<string, string>): Promise<APIResponse>;
  put(path: string, data: unknown, headers?: Record<string, string>): Promise<APIResponse>;
  del(path: string): Promise<APIResponse>;
  // stepUp confirms the session with a fresh code. The server rotates the session cookie and so the
  // CSRF token; reload the page afterwards before using the UI (the SPA keeps the old token in memory).
  stepUp(totpSecret: string): Promise<void>;
}

// apiAs calls the API as the user signed in on page (same cookies), with the session's CSRF token.
export async function apiAs(page: Page): Promise<Api> {
  const session = await page.request.get('/api/v1/auth/session');
  expect(session.ok(), 'GET /api/v1/auth/session (signed in?)').toBe(true);
  let csrf = ((await session.json()) as { csrf_token: string }).csrf_token;
  const api: Api = {
    get: (path) => page.request.get(path, { headers: { 'X-CSRF-Token': csrf } }),
    post: (path, data, headers = {}) => page.request.post(path, { headers: { 'X-CSRF-Token': csrf, ...headers }, data: data ?? {} }),
    del: (path) => page.request.delete(path, { headers: { 'X-CSRF-Token': csrf } }),
    put: (path, data, headers = {}) => page.request.put(path, { headers: { 'X-CSRF-Token': csrf, ...headers }, data }),
    stepUp: async (totpSecret) => {
      const res = await api.post('/api/v1/auth/stepup', { code: await freshCode(page.request, totpSecret) });
      expect(res.ok(), await res.text()).toBe(true);
      csrf = ((await res.json()) as { csrf_token: string }).csrf_token;
    },
  };
  return api;
}

// PHONE_WIDTH is the narrowest width the Servers and SSH keys screens must work at.
export const PHONE_WIDTH = 375;

// expectWide checks a screen with axe and for horizontal overflow on a 375 px phone and at every
// width of expectAccessible (tables scroll inside their own container, never the page).
export async function expectWide(page: Page, screen: string, opts: AxeOptions = {}): Promise<void> {
  await checkWidths(page, screen, [PHONE_WIDTH, ...AXE_WIDTHS], opts);
}

// --- Phase 4: certificates and Nginx on the e2e target, and the UI texts read from the locale files ---

export interface PemPair {
  cert: string;
  key: string;
}

// newCert asks the e2e target for a fresh certificate (leaf + test CA) and key for name (several
// names separated by commas give one certificate for all of them); broken returns a key of another
// certificate (owner step 4). Nothing is written to disk on this side.
export function newCert(name: string, broken = false): PemPair {
  const out = targetExec(['/usr/local/sbin/alice-e2e-newcert', name, ...(broken ? ['--broken'] : [])]);
  const m = out.match(/-----ALICE CERT-----\n([\s\S]+?)-----ALICE KEY-----\n([\s\S]+?)-----ALICE END-----/);
  expect(m, 'alice-e2e-newcert output').not.toBeNull();
  return { cert: m![1], key: m![2] };
}

// signRequest has the target's test CA sign a certificate signing request for names (comma
// separated; the request's own names are ignored) and returns the certificate and the CA certificate.
export function signRequest(csrPem: string, names: string): string {
  return targetExec(['/usr/local/sbin/alice-e2e-pki', 'sign', names], csrPem);
}

// reloadMode arms the target's "systemctl reload nginx" shim; arm it right before the drain that
// runs the deployment (any reload consumes a "-once" mode).
export function reloadMode(mode: 'ok' | 'fail-once' | 'fail' | 'noop' | 'drop-once'): void {
  targetExec(['/usr/local/sbin/alice-e2e-reload-mode', mode]);
}

// testMode arms the target's "nginx -t" wrapper; any nginx -t consumes fail-once.
export function testMode(mode: 'ok' | 'fail-once' | 'fail'): void {
  targetExec(['/usr/local/sbin/alice-e2e-test-mode', mode]);
}

// configMode breaks (or repairs) the target's Nginx configuration with a file holding a syntax error.
export function configMode(mode: 'broken' | 'ok'): void {
  targetExec(['/usr/local/sbin/alice-e2e-config-mode', mode]);
}

// nginxReset puts the target's Nginx back to its start state (fresh pairs, no faults, reloaded).
// POST /test/reset resets only Alice, so every Phase 4 test calls this too.
export function nginxReset(): void {
  targetExec(['/usr/local/sbin/alice-e2e-nginx-reset']);
}

// served is the SHA-256 (lower-case hex) of the certificate the target's Nginx serves for name,
// read on the target with openssl s_client: proof independent of Alice.
export function served(name: string): string {
  return targetExec(['/usr/local/sbin/alice-e2e-served', name]).trim();
}

// fingerprintHex is the SHA-256 of the first certificate's DER in pem (lower-case hex, no colons).
export function fingerprintHex(pem: string): string {
  return new X509Certificate(pem).fingerprint256.replace(/:/g, '').toLocaleLowerCase('en-US');
}

// runScheduled runs one periodic task of the server now (POST /test/scheduler/run), for example
// the deployment recovery sweep, which never ticks by itself in the e2e build.
export async function runScheduled(request: APIRequestContext, task: string): Promise<void> {
  const res = await request.post('/test/scheduler/run', { data: { task } });
  expect(res.ok(), `POST /test/scheduler/run ${task}: ${await res.text()}`).toBe(true);
}

// setOverlapMinutes sets a rotation policy's overlap in minutes (POST /test/rotation/overlap, e2e build only): the
// UI offers whole days, a journey needs a run whose overlap ends within minutes. A run keeps the overlap it was
// created with.
export async function setOverlapMinutes(request: APIRequestContext, policyId: string, minutes: number): Promise<void> {
  const res = await request.post('/test/rotation/overlap', { data: { policy_id: policyId, minutes } });
  expect(res.ok(), `POST /test/rotation/overlap: ${await res.text()}`).toBe(true);
  expect(((await res.json()) as { overlap_minutes: number }).overlap_minutes).toBe(minutes);
}

type Tree = { [key: string]: string | Tree };

function readTree(path: string): Tree {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8')) as Tree;
}

const LOCALES: Record<Lang, Tree[]> = {
  en: [readTree('../src/locales/en.json'), readTree('../../locales/common/en.json')],
  tr: [readTree('../src/locales/tr.json'), readTree('../../locales/common/tr.json')],
};

function lookup(tree: Tree, key: string): string | undefined {
  let node: string | Tree | undefined = tree;
  for (const part of key.split('.')) {
    if (typeof node !== 'object') return undefined;
    node = node[part];
  }
  return typeof node === 'string' ? node : undefined;
}

// Translate is the web app's text for a key in one language, read from the same locale files the
// app bundles (web/src/locales and locales/common), with {{name}} parameters and _one/_other plurals.
// Tests read the copy at run time instead of repeating sentences that may be reworded.
export type Translate = (key: string, params?: Record<string, string | number>) => string;

export function translator(lang: Lang): Translate {
  return (key, params = {}) => {
    const plural = typeof params.count === 'number' ? `${key}_${params.count === 1 ? 'one' : 'other'}` : undefined;
    let text: string | undefined;
    for (const tree of LOCALES[lang]) text ??= (plural && lookup(tree, plural)) || lookup(tree, key);
    if (text === undefined) throw new Error(`no ${lang} text for ${key}`);
    return text.replace(/\{\{(\w+)\}\}/g, (_, name: string) => {
      if (!(name in params)) throw new Error(`${lang} text ${key} needs {{${name}}}`);
      return String(params[name]);
    });
  };
}

// --- Phase 5: the fake Azure service (compose service fakeazure, cmd/alice-fakeazure) ---

// azureExec runs the fake Azure tool in the e2e stack's service "fakeazure" and returns its standard
// output. The same alice-e2e* project guard as targetExec: never the owner stack.
export function azureExec(args: string[]): string {
  return composeExec('fakeazure', ['/alice-fakeazure', ...args]);
}

// azureCtl runs "alice-fakeazure ctl ..." and parses the one JSON object it prints.
function azureCtl<T = Record<string, unknown>>(...args: string[]): T {
  return JSON.parse(azureExec(['ctl', ...args])) as T;
}

export interface AzureCredentials {
  tenant_id: string;
  client_id: string;
  client_secret: string;
  vault_url: string;
}

// azureCredentials are the fake's tenant, application, client secret and vault address, generated
// when the fake started (and again by azureReset); nothing of it is committed.
export function azureCredentials(): AzureCredentials {
  return azureCtl<AzureCredentials>('credentials');
}

// azureReset reseeds the fake (web-cert, monitor-only, signing-key, db-password; every fault, role
// change and request log cleared) with a new client secret, and returns the new credentials.
// POST /test/reset resets only Alice, so every Phase 5 test calls this too.
export function azureReset(): AzureCredentials {
  return azureCtl<AzureCredentials>('reset');
}

// azureRenew makes the fake issue a new version of the certificate and returns its version id.
export function azureRenew(name: string): string {
  return azureCtl<{ version: string }>('renew', name).version;
}

// azureLeafFingerprint is the SHA-256 (lower-case hex) of the leaf of the certificate's current version
// (or of version): what Nginx must serve after the deployment of that version.
export function azureLeafFingerprint(name: string, version?: string): string {
  return azureCtl<{ fingerprint: string }>('leaf', name, ...(version ? ['--version', version] : [])).fingerprint;
}

// azureSyncClock puts the fake's clock on Alice's (the e2e clock the journeys move with the step-up
// windows and the license lock), two seconds ahead. Alice's planner deploys a version by itself only
// when Azure created it strictly after automatic deployment was switched on, it compares Azure's
// creation time (whole seconds, cut down) with its own clock, and the e2e clock runs ahead of the
// real one: without this a version renewed "now" would look older than that moment.
export async function azureSyncClock(request: APIRequestContext): Promise<void> {
  azureCtl('clock', new Date(Math.floor((await serverNow(request)) / 1000) * 1000 + 2_000).toISOString().replace(/\.\d{3}Z$/, 'Z'));
}

// azureRole takes a data action away from the application's roles (revoke) or gives it back.
export function azureRole(change: 'revoke' | 'grant', action: string): void {
  azureCtl(`${change}-role`, action);
}

// azureFault controls what the fake answers to every vault call: throttling (429 with a Retry-After
// above Alice's longest wait, so a cycle ends at once), the vault's firewall (the address it names), or
// nothing wrong (unfault; firewall off).
export function azureFault(change: { throttle: number } | { firewall: string } | 'clear'): void {
  if (change === 'clear') {
    azureCtl('unfault');
    azureCtl('firewall', 'off');
  } else if ('throttle' in change) azureCtl('throttle', '--retry-after', String(change.throttle));
  else azureCtl('firewall', change.firewall);
}

// azureRequests counts what the fake has been sent since its last reset (or clear-requests): every
// request, those to the sign-in host and to the vault, and the vault calls it answered 429 (throttled).
export function azureRequests(): { count: number; login: number; vault: number; throttled: number } {
  return azureCtl<{ count: number; login: number; vault: number; throttled: number }>('requests');
}

// azureAddCertificate makes the fake create a certificate; without root its chain stops at the
// intermediate CA (an incomplete chain). Returns its first version id.
export function azureAddCertificate(name: string, opts: { cn: string; root: boolean }): string {
  return azureCtl<{ version: string }>('add-cert', name, '--cn', opts.cn, '--root', String(opts.root)).version;
}

// --- Shared screen helpers (moved here from phase6.spec.ts; Phase 7 uses them too) ---

// answerStepUp confirms the step-up dialog with a fresh code if the server asks for one before done appears.
export async function answerStepUp(page: Page, request: APIRequestContext, lang: Lang, secret: string, done: Locator): Promise<void> {
  const c = COPY[lang];
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, secret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
    await expect(stepUp).toHaveCount(0);
  }
  await expect(done).toBeVisible();
}

// selectByKeyboard picks an option of the focused native select with the arrow keys only.
export async function selectByKeyboard(page: Page, select: Locator, value: string): Promise<void> {
  await expect(select).toBeFocused();
  const options = await select.locator('option').evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
  const target = options.indexOf(value);
  expect(target, `${value} is offered`).toBeGreaterThanOrEqual(0);
  for (let i = 0; i < options.length && (await select.inputValue()) !== value; i++) {
    const before = await select.inputValue();
    await page.keyboard.press(options.indexOf(before) < target ? 'ArrowDown' : 'ArrowUp');
    // A page that keeps the choice in its address draws again after each step: wait for it before the next key.
    await expect(select, 'the select keeps the focus while it is operated').toBeFocused();
    await expect(select).not.toHaveValue(before);
  }
  await expect(select).toHaveValue(value);
}

// readDownload reads a download into memory from its stream (the caller deletes the file in a finally block).
export function readDownload(download: Download): Promise<string> {
  return (async () => {
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString('utf8');
  })();
}

// --- Phase 7: the fake SMTP server (compose service fakesmtp) and the fake identity provider (fakeidp) ---

// smtpCtl runs "alice-fakesmtp ctl ..." in the e2e stack (the same alice-e2e* project guard as targetExec) and parses
// the one JSON object it prints. The admin address is the in-container default (127.0.0.1:8025).
export function smtpCtl<T = Record<string, unknown>>(...args: string[]): T {
  return JSON.parse(composeExec('fakesmtp', ['/alice-fakesmtp', 'ctl', ...args])) as T;
}

// MailHogMessage is the part of a MailHog v2 message the journeys read: the decoded subject and body, the recipients.
export interface MailHogMessage {
  Content: { Headers: { Subject: string[] }; Body: string };
  Raw: { To: string[] };
}

// smtpMessages are the messages the fake SMTP server accepted since it started or was last cleared.
export function smtpMessages(): MailHogMessage[] {
  return smtpCtl<{ items: MailHogMessage[] }>('messages').items;
}

// idpCtl runs "alice-fakeidp ctl ..." in the e2e stack and parses the one JSON object it prints.
export function idpCtl<T = Record<string, unknown>>(...args: string[]): T {
  return JSON.parse(composeExec('fakeidp', ['/alice-fakeidp', 'ctl', ...args])) as T;
}

// idpCA is the fake identity provider's CA certificate (PEM), generated when it started; pasted into the provider form.
export function idpCA(): string {
  return composeExec('fakeidp', ['/alice-fakeidp', 'ctl', 'ca']);
}

// SeedAnswer is what the seeded data set must show (C17; internal/testutil/seed.DashboardAnswer). The certificate counts
// are cumulative windows: each equals the rows its link opens.
export interface SeedAnswer {
  certificates: Record<'monitored' | 'expired' | 'within_7' | 'within_30' | 'within_60', number>;
  targets: Record<string, number>;
  deployments: { failed_7d: number };
  expiring_30: string[];
  server_filter: { target: string; expiry_30: string[] };
}

// seedDashboard inserts C17's data set (POST /test/seed/dashboard, e2e build only) and returns what it must show.
export async function seedDashboard(request: APIRequestContext): Promise<SeedAnswer> {
  const res = await request.post('/test/seed/dashboard', { data: {} });
  expect(res.ok(), `POST /test/seed/dashboard: ${await res.text()}`).toBe(true);
  return (await res.json()) as SeedAnswer;
}
