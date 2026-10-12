import type { Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  apiAs,
  browserLocale,
  expect,
  expectAccessible,
  expectWide,
  field,
  fingerprintOf,
  firstSignIn,
  freshCode,
  resetInstall,
  runWizard,
  settle,
  signIn,
  signOut,
  targetExec,
  test,
  type Account,
  type Lang,
  uiLang,
} from './helpers';

const OPERATOR: Account = { username: 'olcay', fullName: 'Olcay Öztürk', password: 'operator-password-2026' };
const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const DEPLOY_KEYS = '/home/deploy/.ssh/authorized_keys';
const LANGUAGE_NAMES: Record<Lang, string> = { en: 'English', tr: 'Türkçe' };
const DAY_SECONDS = 24 * 3600;
// linuxssh.IdleTimeout: an idle SSH connection is reused for at most this long.
const SSH_IDLE_SECONDS = 60;
// auth.StepUpWindow: a sign-in or step-up confirms the session for this long.
const STEP_UP_SECONDS = 5 * 60;

// Exact UI copy of Tasks 20–21 (web/src/locales, locales/common) and the shared error and banner texts.
const P = {
  en: {
    navServers: 'Servers',
    navSshKeys: 'SSH keys',
    empty: 'No servers yet. Prepare a server with the command below, then add it.',
    addServer: 'Add server',
    name: 'Name',
    address: 'Address',
    connect: 'Connect',
    confirmTitle: 'Is this your server?',
    yes: 'Yes, this is my server',
    added: 'Server added. Alice is reading its SSH keys.',
    connected: 'Connected',
    identityChanged: 'Server identity changed',
    hostKeyChanged: "The server's identity has changed, so Alice stopped all work on it.",
    aliceKey: "Alice's key",
    removeNamed: (user: string) => `Remove key from ${user}`,
    removeTitle: 'Remove this key from the server?',
    removeConfirm: 'Remove key',
    cancel: 'Cancel',
    ownKey: 'Alice needs this key to connect to this server and will not remove it.',
    test: 'Test connection',
    review: 'Review the new fingerprint',
    repinTitle: 'Accept the new server fingerprint',
    reason: 'Reason',
    accept: 'Accept new fingerprint',
    keep: 'The server still shows the previous fingerprint',
    dismissed: 'Server identity change dismissed',
    usedWhere: 'Where this key is used',
    // An empty inventory (no filter) says so; "No SSH keys match these filters." is the no-match state (Phase 9, Task 9).
    noKeys: 'No SSH keys yet',
    limit: (n: number) => `Your license allows ${n} targets.`,
    locked: 'Not available while the license is expired.',
    limitReached: (n: number) => `You are using all ${n} licensed targets.`,
    overLimit: (used: number, max: number) => `You use ${used} of ${max} licensed targets.`,
    tampered: 'License data was changed outside Alice',
  },
  tr: {
    navServers: 'Sunucular',
    navSshKeys: 'SSH anahtarları',
    empty: 'Henüz sunucu yok. Bir sunucuyu aşağıdaki komutla hazırlayın, sonra ekleyin.',
    addServer: 'Sunucu ekle',
    name: 'Ad',
    address: 'Adres',
    connect: 'Bağlan',
    confirmTitle: 'Bu sizin sunucunuz mu?',
    yes: 'Evet, bu benim sunucum',
    added: 'Sunucu eklendi. Alice SSH anahtarlarını okuyor.',
    connected: 'Bağlı',
    identityChanged: 'Sunucu kimliği değişti',
    hostKeyChanged: 'Sunucunun kimliği değişti, bu yüzden Alice bu sunucudaki tüm işleri durdurdu.',
    aliceKey: "Alice'in anahtarı",
    removeNamed: (user: string) => `Anahtarı kaldır: ${user}`,
    removeTitle: 'Bu anahtar sunucudan kaldırılsın mı?',
    removeConfirm: 'Anahtarı kaldır',
    cancel: 'Vazgeç',
    ownKey: 'Alice bu sunucuya bağlanmak için bu anahtara ihtiyaç duyar ve onu kaldırmaz.',
    test: 'Bağlantıyı sına',
    review: 'Yeni parmak izini incele',
    repinTitle: 'Yeni sunucu parmak izini kabul et',
    reason: 'Gerekçe',
    accept: 'Yeni parmak izini kabul et',
    keep: 'Sunucu hâlâ önceki parmak izini gösteriyor',
    dismissed: 'Sunucu kimlik değişikliği yok sayıldı',
    usedWhere: 'Bu anahtarın kullanıldığı yerler',
    noKeys: 'Henüz SSH anahtarı yok',
    limit: (n: number) => `Lisansınız en fazla ${n} hedefe izin veriyor.`,
    locked: 'Lisans süresi dolduğu için bu işlem kullanılamıyor.',
    limitReached: (n: number) => `Lisanslı ${n} hedefin tamamını kullanıyorsunuz.`,
    overLimit: (used: number, max: number) => `Kullanımdaki hedef sayısı ${used}, lisanslı hedef sayısı ${max}.`,
    tampered: 'Lisans verileri Alice dışında değiştirildi',
  },
} as const;

type PCopy = (typeof P)[Lang];

// chooseLanguage switches the signed-in user's UI language with the top bar's toggle, named by the other language (saved on the account).
async function chooseLanguage(page: Page, lang: Lang): Promise<void> {
  if ((await uiLang(page)) === lang) return;
  await page.getByRole('button', { name: LANGUAGE_NAMES[lang], exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', lang);
}

async function openServers(page: Page, p: PCopy): Promise<void> {
  await page.getByRole('link', { name: p.navServers, exact: true }).click();
  await expect(page.getByRole('heading', { name: p.navServers, level: 1 })).toBeVisible();
}

// addServerInDialog opens "Add server", fills the form and submits it. With a11y, the empty form
// is first checked with axe (expectAccessible).
async function addServerInDialog(page: Page, p: PCopy, name: string, address: string, a11y = false) {
  await page.getByRole('button', { name: p.addServer }).click();
  const dialog = page.getByRole('dialog', { name: p.addServer });
  await expect(field(dialog, p.name)).toBeVisible();
  if (a11y) await expectAccessible(page, 'add server form');
  await field(dialog, p.name).fill(name);
  await field(dialog, p.address).fill(address);
  await dialog.getByRole('button', { name: p.connect }).click();
  return dialog;
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const c = COPY[lang];
  const p = P[lang];

  test.describe(`Phase 3 servers and SSH keys (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('owner journey: prepare, add, confirm, inventory, own key, removal, changed host key', async ({ page, request }) => {
      // The fixture file of the shared target is restored afterwards, so both languages start alike.
      const deployKeys = targetExec(['cat', DEPLOY_KEYS]);
      try {
        const { totpSecret } = await runWizard(page, request, lang, ADMIN, { a11y: true });

        // Owner step 1: Alice's public key and the commands; run them on the test server.
        await openServers(page, p);
        await expect(page.getByText(p.empty)).toBeVisible();
        const publicKey = ((await page.getByTestId('platform-public-key').textContent()) ?? '').trim();
        const script = (await page.getByTestId('setup-script').textContent()) ?? '';
        expect(publicKey).toMatch(/^ssh-ed25519 /);
        expect(script).toContain('alice-svc');
        expect(script).toContain(publicKey.split(' ')[1]);
        await expectWide(page, 'servers page with the preparation commands');
        targetExec(['/usr/local/sbin/alice-e2e-prepare'], script);

        // Owner step 2: add the server and compare the fingerprint with the one the server shows.
        await addServerInDialog(page, p, 'e2e-target', 'sshtarget', true);
        const confirm = page.getByRole('dialog', { name: p.confirmTitle });
        await settle(request, confirm);
        const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
        await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
        await expect(confirm.getByTestId('host-key-command')).toHaveText(`ssh-keygen -lf ${HOST_KEY_PUB}`);
        await expectAccessible(page, 'fingerprint confirmation');
        await confirm.getByRole('button', { name: p.yes }).click();
        await settle(request, page.getByText(p.added));
        await expect(page.getByTestId('target-status')).toHaveText(p.connected);
        const targetId = new URL(page.url()).pathname.split('/').pop() ?? '';

        // Owner step 3: the keys with their users; open one and see where it is used.
        const keys = page.getByTestId('target-keys');
        const row = (text: string) => keys.getByRole('row').filter({ hasText: text });
        const userOf = (text: string) => row(text).getByRole('cell').first();
        await settle(request, keys.getByText('deploy@laptop'));
        await expect(userOf('deploy@laptop')).toHaveText('deploy');
        await expect(userOf('ci@build')).toHaveText('deploy');
        await expect(userOf('root@bastion')).toHaveText('root');
        await expect(userOf(p.aliceKey)).toHaveText('alice-svc');
        await expect(row(p.aliceKey)).toHaveCount(1);
        await expectWide(page, 'server page with its keys');

        await page.getByRole('link', { name: p.navSshKeys, exact: true }).click();
        await expect(page.getByRole('heading', { name: p.navSshKeys, level: 1 })).toBeVisible();
        const inventory = page.getByTestId('ssh-keys-table');
        await expect(inventory.getByText('deploy@laptop')).toBeVisible();
        await expect(inventory.getByText('root@bastion')).toBeVisible();
        await expectWide(page, 'SSH key inventory');
        await inventory.getByRole('row').filter({ hasText: 'deploy@laptop' }).getByRole('link').click();
        await expect(page.getByRole('heading', { name: p.usedWhere })).toBeVisible();
        const locations = page.getByTestId('key-locations');
        await expect(locations).toContainText(DEPLOY_KEYS);
        await expectWide(page, 'SSH key detail');

        // Owner step 4: Alice refuses to remove its own key and says why.
        await locations.getByRole('link', { name: 'e2e-target' }).click();
        await row(p.aliceKey).getByRole('button', { name: p.removeNamed('alice-svc') }).click();
        const ownKey = page.getByRole('dialog', { name: p.removeTitle });
        await expectAccessible(page, 'remove key dialog');
        await ownKey.getByRole('button', { name: p.removeConfirm }).click();
        await expect(ownKey.getByRole('alert')).toContainText(p.ownKey);
        await expectAccessible(page, 'remove key dialog with the own-key refusal');
        await ownKey.getByRole('button', { name: p.cancel }).click();
        await expect(ownKey).toHaveCount(0);
        await expect(row(p.aliceKey)).toBeVisible();

        // Another key is removed; only its line leaves the file.
        await row('ci@build').getByRole('button', { name: p.removeNamed('deploy') }).click();
        const removal = page.getByRole('dialog', { name: p.removeTitle });
        await removal.getByRole('button', { name: p.removeConfirm }).click();
        await expect(async () => {
          await settle(request, keys.getByText('deploy@laptop'));
          await expect(removal).toHaveCount(0, { timeout: 1_500 });
          await expect(row('ci@build')).toHaveCount(0, { timeout: 1_500 });
        }).toPass({ timeout: 90_000 });
        const after = targetExec(['cat', DEPLOY_KEYS]);
        expect(after).toContain('deploy@laptop');
        expect(after).not.toContain('ci@build');
        expect(after.trim().split('\n')).toHaveLength(deployKeys.trim().split('\n').length - 1);

        // Owner step 5: the server gets a new host key; Alice stops and shows a red warning.
        targetExec(['/usr/local/sbin/alice-e2e-rotate-hostkey']);
        const rotated = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
        expect(rotated).not.toBe(onServer);
        // An idle pooled connection opened with the old key stays usable for up to 60 s (R37 item 21);
        // the change is seen on the next new connection, so move the demo clock past the idle time.
        await advanceClock(request, SSH_IDLE_SECONDS + 1);
        await page.getByRole('button', { name: p.test }).click();
        await settle(request, page.getByTestId('host-key-changed'));
        await expect(page.getByTestId('host-key-changed')).toContainText(p.hostKeyChanged);
        await expect(page.getByTestId('target-status')).toHaveText(p.identityChanged);
        await expectWide(page, 'server with a changed identity');

        // Operators can see the warning but cannot accept the new key (F-33).
        const admin = await apiAs(page);
        await admin.stepUp(totpSecret);
        const created = await admin.post('/api/v1/users', {
          username: OPERATOR.username,
          display_name: OPERATOR.fullName,
          email: '',
          role: 'operator',
          password: OPERATOR.password,
        });
        expect(created.status(), await created.text()).toBe(201);
        await page.reload();
        await signOut(page);
        await firstSignIn(page, request, OPERATOR);
        await chooseLanguage(page, lang); // a new account starts in English; the check reads the test language
        await page.goto(`/servers/${targetId}`);
        await expect(page.getByTestId('host-key-changed')).toBeVisible();
        await expect(page.getByRole('button', { name: p.review })).toHaveCount(0);
        const operator = await apiAs(page);
        const hostKeys = (await (await operator.get(`/api/v1/targets/${targetId}/host-keys`)).json()) as {
          items: { id: string; status: string; fingerprint: string }[];
        };
        const observed = hostKeys.items.find((k) => k.status === 'observed');
        expect(observed?.fingerprint).toBe(rotated);
        const denied = await operator.post(`/api/v1/targets/${targetId}/host-keys/${observed?.id}/actions/repin`, {
          fingerprint: rotated,
          reason: 'operators may not accept host keys',
        });
        expect(denied.status()).toBe(403);
        await signOut(page);

        // An Administrator accepts it with a reason and a fresh code; work resumes (F-32).
        await signIn(page, request, ADMIN, totpSecret);
        await page.goto(`/servers/${targetId}`);
        await page.getByRole('button', { name: p.review }).click();
        const repin = page.getByRole('dialog', { name: p.repinTitle });
        await expect(repin.getByTestId('repin-new-fingerprint')).toHaveText(rotated);
        await expect(repin).toContainText(onServer);
        await field(repin, p.reason).fill('CHG-2026-0412 server reinstalled');
        await expectAccessible(page, 're-pin dialog');
        // The step-up window of the sign-in has closed, so accepting asks for a fresh code (§25.1).
        await advanceClock(request, STEP_UP_SECONDS + 1);
        await repin.getByRole('button', { name: p.accept }).click();
        const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
        await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
        await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
        await expect(stepUp).toHaveCount(0);
        await expect(repin).toHaveCount(0);
        await settle(request, page.getByTestId('target-status').filter({ hasText: p.connected }));
        await expect(page.getByTestId('host-key-changed')).toHaveCount(0);
      } finally {
        // Restoring must not hide the failure that got us here, so a failed restore is only logged.
        // The suite leaves "sshtarget" with its rotated host key; make e2e-up starts it fresh.
        try {
          targetExec(['sh', '-c', `cat > ${DEPLOY_KEYS}`], deployKeys);
        } catch (e) {
          console.error('could not restore the deploy user authorized_keys on sshtarget:', e);
        }
      }
    });

    test('a dismissed identity change: the server still shows the previous fingerprint', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openServers(page, p);
      targetExec(['/usr/local/sbin/alice-e2e-prepare'], (await page.getByTestId('setup-script').textContent()) ?? '');
      await addServerInDialog(page, p, 'e2e-target', 'sshtarget');
      const confirm = page.getByRole('dialog', { name: p.confirmTitle });
      await settle(request, confirm);
      const onServer = fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]));
      await expect(confirm.getByTestId('host-key-fingerprint')).toHaveText(onServer);
      await confirm.getByRole('button', { name: p.yes }).click();
      await settle(request, page.getByTestId('target-status').filter({ hasText: p.connected }));
      const targetId = new URL(page.url()).pathname.split('/').pop() ?? '';

      // The server shows another key for a while (for example a connection that reached another
      // machine), then its previous key again.
      targetExec(['/usr/local/sbin/alice-e2e-rotate-hostkey']);
      await advanceClock(request, SSH_IDLE_SECONDS + 1);
      await page.getByRole('button', { name: p.test }).click();
      await settle(request, page.getByTestId('host-key-changed'));
      await expect(page.getByTestId('target-status')).toHaveText(p.identityChanged);
      targetExec(['/usr/local/sbin/alice-e2e-restore-hostkey']);
      expect(fingerprintOf(targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]))).toBe(onServer);

      // An Administrator keeps the previous fingerprint with a reason and a fresh code; work resumes.
      await page.getByRole('button', { name: p.review }).click();
      const repin = page.getByRole('dialog', { name: p.repinTitle });
      await expect(repin).toContainText(onServer);
      await field(repin, p.reason).fill('False alarm: the load balancer briefly routed to the standby');
      await expectAccessible(page, 're-pin dialog with the keep choice');
      await advanceClock(request, STEP_UP_SECONDS + 1);
      await repin.getByRole('button', { name: p.keep }).click();
      const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
      await field(stepUp, c.code).fill(await freshCode(request, totpSecret));
      await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
      await expect(stepUp).toHaveCount(0);
      await expect(repin).toHaveCount(0);
      await settle(request, page.getByTestId('target-status').filter({ hasText: p.connected }));
      await expect(page.getByTestId('host-key-changed')).toHaveCount(0);
      await expect(page.getByRole('button', { name: p.review })).toHaveCount(0);

      // The previous fingerprint stays confirmed and the other key is no candidate any more.
      const hostKeys = (await (await (await apiAs(page)).get(`/api/v1/targets/${targetId}/host-keys`)).json()) as {
        items: { status: string; fingerprint: string }[];
      };
      expect(hostKeys.items.filter((k) => k.status === 'pinned').map((k) => k.fingerprint)).toEqual([onServer]);
      expect(hostKeys.items.filter((k) => k.status === 'observed')).toEqual([]);
      await page.getByRole('link', { name: c.navAudit, exact: true }).click();
      await expect(page.getByRole('heading', { name: c.auditHeading })).toBeVisible();
      await expect(page.getByText(p.dismissed, { exact: true }).first()).toBeVisible();
    });

    test('license limit, over-limit and damaged license banners (owner step 6, carry 5)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      // The evaluation allows 5 targets; servers count when they are added, reachable or not.
      for (const n of [1, 2, 3, 4, 5]) {
        const res = await api.post('/api/v1/targets', { name: `web-${n}`, type: 'linux', host: `web-${n}.invalid`, port: 22, username: 'alice-svc' });
        expect(res.status(), await res.text()).toBe(201);
      }
      await page.goto('/servers');
      await expect(page.getByTestId('license-banner-limit_reached')).toContainText(p.limitReached(5));
      await expectWide(page, 'servers page with the limit reached banner');

      const dialog = await addServerInDialog(page, p, 'web-6', 'web-6.invalid');
      await expect(dialog.getByRole('alert')).toContainText(p.limit(5));
      await expectAccessible(page, 'add server dialog with the license limit');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('targets-table').getByRole('row')).toHaveCount(6); // header + 5 servers, web-6 refused

      // A smaller license keeps every server and shows the over-limit banner (L-75, R30).
      const issued = await request.post('/test/license', { data: { max_targets: 3 } });
      expect(issued.ok(), await issued.text()).toBe(true);
      await api.stepUp(totpSecret);
      const installed = await api.post('/api/v1/license', { license: ((await issued.json()) as { license: string }).license });
      expect(installed.ok(), await installed.text()).toBe(true);
      await page.reload();
      await expect(page.getByTestId('license-banner-over_limit')).toContainText(p.overLimit(5, 3));
      await expect(page.getByTestId('targets-table').getByRole('row')).toHaveCount(6); // header + 5 servers, none removed
      await expectWide(page, 'servers page over the license limit');

      // License data changed outside Alice (L-49).
      expect((await request.post('/test/license/tamper')).ok()).toBe(true);
      await page.reload();
      await expect(page.getByTestId('license-banner-tampered')).toContainText(p.tampered);
      await expectWide(page, 'servers page with damaged license data');
    });

    test('an expired evaluation refuses a new server and keeps the inventory readable (L-26, R9)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      const api = await apiAs(page);
      const res = await api.post('/api/v1/targets', { name: 'web-1', type: 'linux', host: 'web-1.invalid', port: 22, username: 'alice-svc' });
      expect(res.status(), await res.text()).toBe(201);
      await advanceClock(request, 31 * DAY_SECONDS);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(page.getByTestId('license-banner-evaluation_ended')).toBeVisible();
      await openServers(page, p);
      await expect(page.getByTestId('targets-table').getByRole('link', { name: 'web-1', exact: true })).toBeVisible();
      const dialog = await addServerInDialog(page, p, 'web-2', 'web-2.invalid');
      await expect(dialog.getByRole('alert')).toContainText(p.locked);
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(page.getByTestId('targets-table').getByRole('row')).toHaveCount(2); // header + web-1, web-2 refused
      // The server's own page stays readable while the license is locked.
      await page.getByTestId('targets-table').getByRole('link', { name: 'web-1', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'web-1', level: 1 })).toBeVisible();
      await expect(page.getByTestId('target-status')).toBeVisible();
      await page.getByRole('link', { name: p.navSshKeys, exact: true }).click();
      await expect(page.getByRole('heading', { name: p.navSshKeys, level: 1 })).toBeVisible();
      await expect(page.getByText(p.noKeys)).toBeVisible();
      await expectWide(page, 'SSH key inventory with the license locked');
    });
  });
}
