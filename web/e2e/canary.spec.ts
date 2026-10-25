import type { APIRequestContext, APIResponse, Page } from '@playwright/test';
import {
  COPY,
  advanceClock,
  answerStepUp,
  apiAs,
  browserLocale,
  drainUntil,
  expect,
  field,
  fingerprintHex,
  newCert,
  nginxReset,
  resetInstall,
  runScheduled,
  runWizard,
  served,
  targetExec,
  test,
  translator,
  type Api,
  type Lang,
  type PemPair,
  type Translate,
} from './helpers';

// Canary deployment (R65, CAN-32) on the e2e stack: the Default service's policy deploys to one website first, observes
// it (a hold with application checks of /healthz on the real Nginx of the SSH target) and only then deploys to the
// others. The journeys pass, fail a check, abort, skip the canary with a step-up, and pass again in Turkish. Every
// visible text is read from the locale files at run time.
//
// A certificate's page deploys only to the websites that already use it, so each journey first puts the certificate
// WITHOUT its chain on s1..s3 (canary off), then completes the stored chain and deploys it again from the UI: a real
// write that adds the CA certificate. Which websites have the new files is proven on the target by the length of the
// chain Nginx sends (1 before, 2 after), and the leaf by its fingerprint.

const SITES = [1, 2, 3].map((n) => `s${n}.example.test`);
const SERVER = 'e2e-nginx';
const HOST_KEY_PUB = '/etc/ssh/ssh_host_ed25519_key.pub';
const JOURNEY_TIMEOUT = 8 * 60_000;
// The interval between two rounds of checks (the policy's minimum) and one more second for the clock.
const ROUND_SECONDS = 16;

interface Rollout {
  id: string;
  state: string;
  reason: string;
  waves: { wave: number; locations: { location_id: string; deployment_id: string | null; canary: { rounds: number; last_result: string } | null }[] }[];
}

interface DeployAnswer {
  deployments: { id: string; location_id: string }[];
  rollout: { id: string; wave1: string[]; wave2: string[] } | null;
}

async function json<T>(res: APIResponse, status?: number): Promise<T> {
  const text = await res.text();
  if (status !== undefined) expect(res.status(), text).toBe(status);
  else expect(res.ok(), `${res.status()} ${text}`).toBe(true);
  return (text ? JSON.parse(text) : {}) as T;
}

function leafOf(pem: string): string {
  const end = '-----END CERTIFICATE-----';
  return pem.slice(0, pem.indexOf(end) + end.length) + '\n';
}

// servedChainLength is how many certificates Nginx sends for name: the leaf alone is 1, leaf and CA 2.
function servedChainLength(name: string): number {
  return Number(
    targetExec(['sh', '-c', 'openssl s_client -connect 127.0.0.1:443 -servername "$1" -showcerts </dev/null 2>/dev/null | grep -c "BEGIN CERTIFICATE" || true', 'sh', name]).trim(),
  );
}

// prepareAndAdd prepares the target with the real nginx profile script, adds the server, confirms its host key after
// comparing it with the server's own and waits for the websites.
async function prepareAndAdd(api: Api, request: APIRequestContext): Promise<string> {
  const key = await json<{ profiles: { nginx: { script: string } } }>(await api.get('/api/v1/ssh-keys/platform-key'));
  targetExec(['/usr/local/sbin/alice-e2e-prepare'], key.profiles.nginx.script);
  const created = await json<{ target: { id: string } }>(
    await api.post('/api/v1/targets', { type: 'nginx', name: SERVER, host: 'sshtarget', port: 22, username: 'alice-svc' }),
    201,
  );
  const id = created.target.id;
  const onServer = (targetExec(['ssh-keygen', '-lf', HOST_KEY_PUB]).match(/SHA256:[A-Za-z0-9+/]+/) ?? [''])[0];
  let hostKey: { id: string; fingerprint: string } | undefined;
  await drainUntil(request, async () => {
    const keys = await json<{ items: { id: string; status: string; fingerprint: string }[] }>(await api.get(`/api/v1/targets/${id}/host-keys`));
    hostKey = keys.items.find((k) => k.status === 'observed' && k.fingerprint === onServer);
    expect(hostKey).toBeDefined();
  });
  await json(await api.post(`/api/v1/targets/${id}/host-keys/${hostKey!.id}/actions/confirm`, { fingerprint: hostKey!.fingerprint }), 202);
  await drainUntil(request, async () => {
    const locs = await json<{ items: { servers: { names: string[] }[] }[] }>(await api.get(`/api/v1/targets/${id}/certificate-locations`));
    expect(locs.items.flatMap((l) => l.servers.flatMap((s) => s.names))).toEqual(expect.arrayContaining(SITES));
  });
  return id;
}

async function locationIds(api: Api, targetId: string): Promise<Record<string, string>> {
  const locs = await json<{ items: { id: string; servers: { names: string[] }[] }[] }>(await api.get(`/api/v1/targets/${targetId}/certificate-locations`));
  const out: Record<string, string> = {};
  for (const l of locs.items) for (const s of l.servers) for (const n of s.names) out[n] = l.id;
  return out;
}

async function deploymentOf(api: Api, id: string): Promise<{ status: string; state: string; error: { code: string; reason: string } | null }> {
  return json(await api.get(`/api/v1/deployments/${id}`));
}

async function rolloutOf(api: Api, id: string): Promise<Rollout> {
  return json(await api.get(`/api/v1/deployment-rollouts/${id}`));
}

interface Stage {
  totpSecret: string;
  api: Api;
  pair: PemPair;
  certId: string;
  site: Record<string, string>; // location id → website name
}

// stage runs the wizard, adds the server, puts the certificate without its chain on s1..s3 (no canary yet), completes
// the stored chain and saves the Default service's canary policy in the UI (one website first, a hold of one minute,
// rounds every 15 s, two failures, the check of path).
async function stage(page: Page, request: APIRequestContext, lang: Lang, t: Translate, path: string): Promise<Stage> {
  const { totpSecret } = await runWizard(page, request, lang);
  const api = await apiAs(page);
  await api.stepUp(totpSecret);
  const targetId = await prepareAndAdd(api, request);
  const ids = await locationIds(api, targetId);
  const site: Record<string, string> = {};
  for (const s of SITES) site[ids[s]] = s;

  const pair = newCert(SITES.join(','));
  const up = await json<{ certificate: { id: string } }>(
    await api.post('/api/v1/certificates/upload', { label: 'canary', certificate_pem: leafOf(pair.cert), private_key_pem: pair.key }),
    201,
  );
  const certId = up.certificate.id;
  const first = await json<DeployAnswer>(
    await api.post(`/api/v1/certificates/${certId}/deploy`, { location_ids: SITES.map((s) => ids[s]), confirm_incomplete_chain: true }),
    202,
  );
  expect(first.rollout ?? null, 'no canary before the policy asks for one').toBeNull();
  await drainUntil(request, async () => {
    for (const d of first.deployments) expect((await deploymentOf(api, d.id)).status).toBe('succeeded');
  }, 120_000);
  for (const s of SITES) expect(servedChainLength(s), `${s}: the leaf alone`).toBe(1);
  // The same certificate with its full chain: Alice completes the stored chain (200).
  await json(await api.post('/api/v1/certificates/upload', { label: 'canary', certificate_pem: pair.cert, private_key_pem: pair.key }), 200);

  const services = await json<{ items: { id: string; is_default: boolean }[] }>(await api.get('/api/v1/services'));
  const def = services.items.find((s) => s.is_default);
  expect(def).toBeDefined();
  await page.goto(`/services/${def!.id}`);
  await page.getByRole('tab', { name: t('services.tabs.policy') }).click();
  const section = page.getByTestId('policy-canary');
  await section.getByTestId('canary-enabled').check({ force: true });
  await section.getByTestId('canary-count').fill('1');
  await section.getByTestId('canary-hold').fill('1m');
  await section.getByTestId('canary-interval').fill('15s');
  await field(section, t('services.policyForm.canary.failures')).fill('2');
  await section.getByTestId('canary-check').check({ force: true });
  await section.getByTestId('canary-path').fill(path);
  await page.getByTestId('policy-save').click();
  const saved = page.getByTestId('policy-saved');
  await answerStepUp(page, request, lang, totpSecret, saved);
  await expect(page.getByTestId('policy-history')).toContainText(t('services.policyForm.keys.canary'));
  return { totpSecret, api, pair, certId, site };
}

// deployFromUI opens the certificate's Deploy dialog, chooses s1..s3 and returns the dialog with the server's answer.
async function deployFromUI(page: Page, t: Translate, s: Stage, opts: { override?: boolean; lang: Lang; request: APIRequestContext }) {
  await page.goto(`/certificates/${s.certId}`);
  await page.getByRole('button', { name: t('certificates.detail.deploy'), exact: true }).click();
  const dialog = page.getByRole('dialog', { name: t('deploy.title') });
  const choices = dialog.getByRole('group', { name: t('deploy.websites') }).getByRole('checkbox');
  await expect(choices).toHaveCount(SITES.length);
  for (const box of await choices.all()) await box.check();
  await expect(dialog.getByTestId('canary-note')).toHaveText(t('canary.note', { count: 1, hold: '1m' }));
  if (opts.override) {
    await dialog.getByRole('checkbox', { name: t('canary.override') }).check();
    await expect(dialog.getByTestId('canary-note')).toHaveCount(0);
  }
  const answered = page.waitForResponse((r) => r.request().method() === 'POST' && r.url().endsWith(`/api/v1/certificates/${s.certId}/deploy`) && r.status() === 202);
  await dialog.getByRole('button', { name: t('deploy.submit'), exact: true }).click();
  if (opts.override) await answerStepUp(page, opts.request, opts.lang, s.totpSecret, dialog.getByTestId('deployment-run').first());
  const answer = (await (await answered).json()) as DeployAnswer;
  return { dialog, answer };
}

// waitForHold drains until the wave-1 deployment is verified and holding, then runs the advance once: the rollout
// starts its observation (state hold) and queues the first round.
async function waitForHold(request: APIRequestContext, api: Api, deploymentId: string): Promise<void> {
  await drainUntil(request, async () => {
    const d = await deploymentOf(api, deploymentId);
    expect(d.state, JSON.stringify(d)).toBe('holding');
  }, 120_000);
  await runScheduled(request, 'canary.advance');
}

// passJourney is journey 1 (and 5 in Turkish): the canary passes, wave 2 follows, every website has the new files.
async function passJourney(page: Page, request: APIRequestContext, lang: Lang): Promise<void> {
  const t = translator(lang);
  const s = await stage(page, request, lang, t, '/healthz');
  const { dialog, answer } = await deployFromUI(page, t, s, { lang, request });
  expect(answer.rollout, 'the request became a canary rollout').not.toBeNull();
  const rollout = answer.rollout!;
  expect(rollout.wave1).toHaveLength(1);
  expect(rollout.wave2).toHaveLength(2);
  expect(answer.deployments.map((d) => d.location_id)).toEqual(rollout.wave1);
  await expect(dialog.getByTestId('canary-started')).toHaveText(t('canary.started', { count: 2 }));
  const wave1 = answer.deployments[0].id;
  const canarySite = s.site[rollout.wave1[0]];
  const others = rollout.wave2.map((id) => s.site[id]);

  await waitForHold(request, s.api, wave1);
  expect(servedChainLength(canarySite), `${canarySite}: wave 1 has the new files`).toBe(2);
  for (const o of others) expect(servedChainLength(o), `${o}: wave 2 waits`).toBe(1);

  // The deployment page: in place, under observation, the rollout with its countdown.
  await page.goto(`/deployments/${wave1}`);
  await expect(page.getByText(t('canary.observing'))).toBeVisible();
  const panel = page.getByTestId('rollout-panel');
  await expect(panel.getByTestId('rollout-state')).toHaveText(t('canary.state.hold'));
  await expect(panel.getByTestId('rollout-countdown')).toBeVisible();
  await expect(panel.getByTestId('rollout-wave-2').getByText(t('canary.notDeployed'))).toHaveCount(2);
  // The history marks the wave and the state.
  await page.goto('/deployments');
  const row = page.getByTestId('deployment-row').filter({ hasText: t('canary.waveBadge', { wave: 1 }) });
  await expect(row).toHaveCount(1);
  await expect(row.getByText(t('enum.deploymentState.holding'))).toBeVisible();

  // Rounds every 15 s; the hold of one minute ends; wave 2 is deployed and verified; the rollout completes.
  await drainUntil(
    request,
    async () => {
      await advanceClock(request, ROUND_SECONDS);
      await runScheduled(request, 'canary.advance');
      expect((await rolloutOf(s.api, rollout.id)).state).toBe('completed');
    },
    240_000,
  );
  const done = await rolloutOf(s.api, rollout.id);
  const w1 = done.waves.find((w) => w.wave === 1)!.locations[0];
  expect(w1.canary?.rounds ?? 0, 'the canary ran rounds').toBeGreaterThanOrEqual(2);
  expect(w1.canary?.last_result).toBe('pass');
  expect((await deploymentOf(s.api, wave1)).status).toBe('succeeded');
  for (const l of done.waves.find((w) => w.wave === 2)!.locations) {
    expect(l.deployment_id).not.toBeNull();
    expect((await deploymentOf(s.api, l.deployment_id!)).status).toBe('succeeded');
  }
  for (const site of SITES) {
    expect(served(site), site).toBe(fingerprintHex(s.pair.cert));
    expect(servedChainLength(site), `${site}: the new files`).toBe(2);
  }
  await page.goto(`/deployments/${wave1}`);
  await expect(page.getByTestId('rollout-state')).toHaveText(t('canary.state.completed'));
}

for (const lang of ['en'] as Lang[]) {
  test.describe(`Canary deployment (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request }) => {
      nginxReset();
      await resetInstall(request);
    });
    test.afterEach(() => {
      nginxReset();
    });

    test('the first website passes its observation, then the others follow', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      await passJourney(page, request, lang);
    });

    test('a failing application check puts the first website back and the others never get the certificate', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      const s = await stage(page, request, lang, t, '/canary-fail');
      const { answer } = await deployFromUI(page, t, s, { lang, request });
      const rollout = answer.rollout!;
      const wave1 = answer.deployments[0].id;
      await waitForHold(request, s.api, wave1);

      // Two failed rounds: the rollout fails and wave 1 is reverted.
      await drainUntil(
        request,
        async () => {
          const r = await rolloutOf(s.api, rollout.id);
          if (r.state !== 'failed') {
            await advanceClock(request, ROUND_SECONDS);
            await runScheduled(request, 'canary.advance');
          }
          expect(r.state).toBe('failed');
          expect((await deploymentOf(s.api, wave1)).status).toBe('rolled_back');
        },
        180_000,
      );
      const d = await deploymentOf(s.api, wave1);
      expect(d.error?.reason).toBe('deployment.canary_check_failed');
      expect((await rolloutOf(s.api, rollout.id)).reason).toBe('canary.check_failed');
      // No wave-2 deployment exists; every website keeps the previous files.
      const all = await json<{ items: { id: string }[] }>(await s.api.get(`/api/v1/deployments?rollout_id=${rollout.id}`));
      expect(all.items.map((i) => i.id)).toEqual([wave1]);
      for (const site of SITES) expect(servedChainLength(site), `${site}: the previous files`).toBe(1);

      await page.goto(`/deployments/${wave1}`);
      await expect(page.getByTestId('rollout-state')).toHaveText(t('canary.state.failed'));
      await expect(page.getByTestId('rollout-reason')).toHaveText(t('canary.reason.canary_check_failed'));
      await expect(page.getByText(t('errors.deployment.canary_check_failed.title')).first()).toBeVisible();
    });

    test('Abort during the observation puts the first website back', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      const s = await stage(page, request, lang, t, '/healthz');
      const { answer } = await deployFromUI(page, t, s, { lang, request });
      const rollout = answer.rollout!;
      const wave1 = answer.deployments[0].id;
      await waitForHold(request, s.api, wave1);

      await page.goto(`/deployments/${wave1}`);
      await page.getByTestId('rollout-abort').click();
      await page.getByTestId('rollout-abort-confirm').click();
      await expect(page.getByTestId('rollout-state')).toHaveText(t('canary.state.aborted'));
      await drainUntil(request, async () => expect((await deploymentOf(s.api, wave1)).status).toBe('rolled_back'), 120_000);
      expect((await deploymentOf(s.api, wave1)).error?.reason).toBe('deployment.canary_aborted');
      expect((await rolloutOf(s.api, rollout.id)).state).toBe('aborted');
      for (const site of SITES) expect(servedChainLength(site), `${site}: the previous files`).toBe(1);
    });

    test('"Deploy to all at once" asks for a step-up, deploys everywhere and is audited', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      const t = translator(lang);
      const s = await stage(page, request, lang, t, '/healthz');
      const { dialog, answer } = await deployFromUI(page, t, s, { override: true, lang, request });
      expect(answer.rollout ?? null, 'no rollout').toBeNull();
      expect(answer.deployments).toHaveLength(SITES.length);
      await expect(dialog.getByTestId('deployment-run')).toHaveCount(SITES.length);
      await expect(dialog.getByTestId('canary-started')).toHaveCount(0);
      await drainUntil(request, async () => {
        for (const d of answer.deployments) expect((await deploymentOf(s.api, d.id)).status).toBe('succeeded');
      }, 120_000);
      for (const site of SITES) expect(servedChainLength(site), `${site}: the new files`).toBe(2);

      await page.keyboard.press('Escape');
      await page.getByRole('link', { name: COPY[lang].navAudit, exact: true }).click();
      await expect(page.getByRole('heading', { name: COPY[lang].auditHeading })).toBeVisible();
      await field(page, t('audit.filters.action')).fill('deployment.canary');
      await page.getByRole('button', { name: t('audit.filters.apply'), exact: true }).click();
      await expect(page.getByRole('row').filter({ hasText: t('audit.actions.deployment_canary_overridden') }).first()).toBeVisible();
    });
  });
}

test.describe('Canary deployment (tr)', () => {
  test.use({ locale: browserLocale('tr'), actionTimeout: 30_000 });
  test.beforeEach(async ({ request }) => {
    nginxReset();
    await resetInstall(request);
  });
  test.afterEach(() => {
    nginxReset();
  });

  test('ilk web sitesi gözlemden geçer, sonra diğerleri izler', async ({ page, request }) => {
    test.setTimeout(JOURNEY_TIMEOUT);
    await passJourney(page, request, 'tr');
  });
});
