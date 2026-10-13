import { DEFAULT_THEME, mergeMantineTheme } from '@mantine/core';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { ApiToken, AuditEntry } from './api/types';
import {
  aliceKeyLocation,
  certificateDetailFixture,
  certificateFixture,
  csrFixture,
  deploymentDetailFixture,
  deploymentFixture,
  hostKeyFixture,
  keyLocationFixture,
  managedKeyFixture,
  locationFixture,
  nginxTargetFixture,
  platformKeyFixture,
  installedStatus,
  jobFixture,
  policyFixture,
  POLICY_ID,
  previewFixture,
  runFixture,
  runLocationFixture,
  sessionFor,
  sessionHandlers,
  sshKeyFixture,
  stepFixture,
  targetFixture,
  userFor,
  vaultFixture,
  VAULT_ID,
  KV_CERT_ID,
  BINDING_ID,
  bindingFixture,
  kvCertificateDetailFixture,
  kvCertificateFixture,
  kvVersionFixture,
  emptyDashboardSummary,
  backupStateFixture,
  acmeAccountFixture,
  acmeCertificateFixture,
  acmeHookFixture,
  acmeProviderFixture,
} from './test/fixtures';
import { expectNoRawKeys } from './test/i18nAssert';
import { renderRoute } from './test/render';
import { SCREENS } from './test/screens';
import { server } from './test/server';
import { appTheme, cssVariablesResolver } from './theme';

const token: ApiToken = {
  id: '0192a000-0000-7000-8000-0000000000a1',
  user_id: userFor('operator').id,
  name: 'backup script',
  prefix: 'alice_Ab12Cd',
  scope: 'read',
  expires_at: '2026-12-29T08:00:00Z',
  last_used_at: null,
  created_at: '2026-09-30T08:00:00Z',
};

const auditEntry: AuditEntry = {
  seq: 1,
  at: '2026-09-30T08:00:00Z',
  actor_type: 'user',
  actor_id: userFor('admin').id,
  actor_name: 'admin',
  ip: '10.0.0.7',
  action: 'user.created',
  object_type: 'user',
  object_id: 'x',
  result: 'success',
  details: {},
  request_id: 'req-1',
  hash: 'ab'.repeat(32),
};

// Data for the list screens, so the sweep also covers rendered rows, not only the page chrome.
const dataHandlers = [
  http.get('/api/v1/users', () => HttpResponse.json({ items: [userFor('admin'), userFor('operator'), userFor('auditor')] })),
  http.get('/api/v1/tokens', () => HttpResponse.json({ items: [token] })),
  http.get('/api/v1/targets', ({ request }) => HttpResponse.json({ items: new URL(request.url).searchParams.get('type') === 'azure_key_vault' ? [vaultFixture] : [targetFixture], next_cursor: null })),
  http.get('/api/v1/targets/:id', ({ params }) => HttpResponse.json(params.id === nginxTargetFixture.id ? nginxTargetFixture : params.id === vaultFixture.id ? vaultFixture : targetFixture)),
  http.get('/api/v1/targets/:id/certificate-locations', () =>
    HttpResponse.json({
      items: [
        locationFixture({ warnings: ['symlinked', 'key_mode_open', 'san_mismatch'], key_mode: '0644', changed_outside_at: '2026-10-02T09:00:00Z' }),
        locationFixture({ id: 'l2', supported: false, unsupported_reason: 'file_problem', problem: 'hard_linked', key_problem: 'unreadable' }),
        locationFixture({ id: 'l3', missing_since: '2026-10-01T00:00:00Z', active_deployment_id: 'x' }),
      ],
      truncated: true,
    }),
  ),
  http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [hostKeyFixture()] })),
  http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [keyLocationFixture(), aliceKeyLocation] })),
  http.get('/api/v1/rotation/runs/:id', () =>
    HttpResponse.json(
      runFixture({
        status: 'verifying_new',
        paused_license: true,
        awaiting_decision: true,
        decision_due_at: '2026-10-20T08:00:00Z',
        kept_count: 1,
        actions_allowed: ['continue', 'finish_now', 'keep_old', 'abort'],
        result: { code: 'ALC-ROT-0010', reason: 'rotation.decision_timeout' },
        locations: [
          runLocationFixture({ state: 'unverifiable', verify_note: 'from_option', backup: '/b' }),
          runLocationFixture({ id: 's', n: 2, state: 'skipped', skip_reason: 'duplicate_lines' }),
          runLocationFixture({ id: 'u', n: 3, state: 'undo_failed', error: { code: 'ALC-ROT-0018', reason: 'rotation.old_key_gone' } }),
        ],
        steps: [
          { n: 1, location_id: null, name: 'paused', status: 'ok', at: '2026-10-06T08:00:00Z', params: {} },
          { n: 2, location_id: 'rl1', name: 'late_result', status: 'ok', at: '2026-10-06T08:00:00Z', params: {} },
        ],
      }),
    ),
  ),
  http.get('/api/v1/ssh-keys', () =>
    HttpResponse.json({
      items: [sshKeyFixture(), sshKeyFixture({ id: 'k9', fingerprint: 'SHA256:aliceAliceAlice', is_platform_key: true, comment: 'alice-platform' })],
      next_cursor: 'next',
    }),
  ),
  // Declared before /ssh-keys/:id, which would otherwise answer the platform key request too.
  http.get('/api/v1/ssh-keys/platform-key', () => HttpResponse.json(platformKeyFixture)),
  http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json({ ...sshKeyFixture(), locations: [keyLocationFixture(), aliceKeyLocation] })),
  http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [csrFixture()] })),
  http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture(), certificateFixture({ id: 'c2', has_private_key: false, not_after: '2020-01-01T00:00:00Z' })], next_cursor: 'next' })),
  http.get('/api/v1/certificates/:id', () => HttpResponse.json(certificateDetailFixture({ id: '0192c000-0000-7000-8000-0000000000c1', chain_complete: false }))),
  http.get('/api/v1/deployments', () => HttpResponse.json({ items: [deploymentFixture(), deploymentFixture({ id: 'd2', status: 'needs_attention' })], next_cursor: null })),
  http.get('/api/v1/deployments/:id', () =>
    HttpResponse.json(
      deploymentDetailFixture({
        status: 'rollback_failed',
        state: 'recovering',
        recovery_attempts: 2,
        recover_after: '2026-10-04T13:00:00Z',
        backup_dir: '/var/lib/alice-helper/backups/x',
        failed_step: 'verify_current',
        helper_error: 'file_changed',
        error: { code: 'ALC-DEP-0020', reason: 'deployment.rollback_file_changed' },
        verify_failed: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        steps: [stepFixture(1, 'verify_current'), stepFixture(2, 'backup'), stepFixture(3, 'journal', 'failed', { error: 'file_changed' }), stepFixture(4, 'restore')],
      }),
    ),
  ),
  http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}`, () =>
    HttpResponse.json(
      kvCertificateDetailFixture({
        bound: true,
        binding: { id: BINDING_ID, auto_deploy: true, auto_since: '2026-10-04T08:00:00Z', stopped_version: '', location_count: 1, version: 2, created_at: '' },
        versions: [kvVersionFixture({ held: true, held_reason: 'license' }), kvVersionFixture({ id: 'v0', version: 'bbbbbbbb22222222bbbbbbbb22222222', held: true, held_reason: 'incomplete_chain' })],
      }),
    ),
  ),
  http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, () => HttpResponse.json({ items: [kvCertificateFixture({ bound: true, exportable: false, missing_since: '2026-10-01T00:00:00Z' })], next_cursor: null })),
  http.get(`/api/v1/bindings/${BINDING_ID}`, () => HttpResponse.json(bindingFixture({ auto_deploy: true }))),
  http.get('/api/v1/audit', () => HttpResponse.json({ items: [auditEntry], next_cursor: null })),
  // The ACME work: an authority with an unsettled key change and one without names or account, a hook without names.
  http.get('/api/v1/acme/providers', () =>
    HttpResponse.json({ items: [acmeProviderFixture({ eab_configured: true, pending_rollover: true }), acmeProviderFixture({ id: 'p2', name: 'Corp CA', preset: 'custom', active_account_id: null, allowed_suffixes: [] })] }),
  ),
  http.get('/api/v1/acme/providers/:id', ({ params }) =>
    HttpResponse.json(
      params.id === 'p2'
        ? { ...acmeProviderFixture({ id: 'p2', active_account_id: null }), accounts: [acmeAccountFixture({ state: 'deactivated', tos_url: '', tos_accepted_at: null, contact_email: '' })] }
        : { ...acmeProviderFixture({ pending_rollover: true }), accounts: [acmeAccountFixture({ state: 'pending_rollover' })] },
    ),
  ),
  http.get('/api/v1/acme/hooks', () => HttpResponse.json({ items: [acmeHookFixture(), acmeHookFixture({ id: 'h2', name: 'Other DNS', allowed_suffixes: [], secret_configured: false })] })),
  http.get('/api/v1/acme/certificates', () => HttpResponse.json({ items: [acmeCertificateFixture()], next_cursor: null })),
  http.post('/api/v1/acme/providers/:id/preview', () =>
    HttpResponse.json({ terms_of_service_url: 'https://ca.example.com/terms', terms_url_unsafe: false, external_account_required: true, key_change_supported: true, renewal_info_supported: true, website: '' }),
  ),
  // The dashboard with every widget filled, so the sweep covers their texts too.
  http.get('/api/v1/dashboard/summary', () =>
    HttpResponse.json({
      ...emptyDashboardSummary,
      certificates: { monitored: 8, expired: 1, within_7: 3, within_30: 6, within_60: 7, kv_expired: 1, kv_within_30: 3 },
      deployments: { failed_7d: 1, recent: [{ id: 'd1', certificate_name: 'api.seed.test', target_id: 't1', target_name: 'seed-web-1', status: 'failed', error_code: '', at: '2026-10-06T09:00:00Z' }] },
      targets: { total: 3, by_status: { ok: 2, host_key_changed: 1 } },
      license: { expired: false, phase: 'grace', ends_at: '2026-11-16T09:00:00Z', days_left: 40 },
      rotation: { upcoming: [{ policy_id: 'p1', ssh_key_id: 'k1', key_label: 'ci-deploy', next_run_at: '2026-10-10T09:00:00Z' }], running: 1, needs_attention: 1 },
      audit: { head_seq: 42, head_hash: 'ab'.repeat(32), checked_at: '2026-10-07T03:00:00Z', intact: false },
      attention: 5,
      // Phase 8: the backup card with the alarm (and so the banner), and the setup checklist.
      backup: backupStateFixture({ failing: true, alarm: true, age_hours: 49 }),
      setup_checklist: [
        { item: 'passphrase', done: true, required: true },
        { item: 'https', done: false, required: true },
        { item: 'mail', done: false, required: false },
        { item: 'license', done: true, required: false },
        { item: 'target', done: false, required: false },
      ],
    }),
  ),
  http.get('/api/v1/dashboard/expiring', () =>
    HttpResponse.json({
      items: [
        { kind: 'certificate_expiry', object_id: 'c1', name: 'www.seed.test', expires_at: '2026-10-14T08:00:00Z', days_left: 7, expired: false, fingerprint: 'f', websites: [], servers: ['seed-web-1'], target_ids: ['t1'], vault: '', vault_id: null },
        { kind: 'kv_key_expiry', object_id: 'k1', name: 'signing-key', expires_at: '2020-10-14T08:00:00Z', days_left: 0, expired: true, fingerprint: '', websites: [], servers: [], target_ids: [], vault: 'prod-vault', vault_id: 'v1' },
      ],
    }),
  ),
  http.get('/api/v1/alerts', () =>
    HttpResponse.json({
      items: ['host_key_changed', 'auth_failed', 'deployment_failed', 'audit_broken', 'notifications_failing'].map((kind) => ({ kind, object_id: 'x1', name: 'seed-web-3', since: '2026-10-06T09:00:00Z', error_code: '' })),
    }),
  ),
];

describe.each(['en', 'tr'] as const)('every screen in %s', (lang) => {
  it.each(SCREENS.map((s) => [s.path, s] as const))('%s has no untranslated keys', async (_path, s) => {
    const session = s.session ? { ...s.session, user: { ...s.session.user, locale: lang } } : null;
    server.use(...sessionHandlers(session, s.status), ...dataHandlers);
    await renderRoute(s.path, { languages: [lang] });
    await waitFor(() => expect(screen.getAllByText(s.ready[lang]).length).toBeGreaterThan(0));
    expectNoRawKeys();
  });
});

// The dark scheme: every screen renders with the scheme set on <html>, its ready text shown and no raw key. jsdom
// cannot measure contrast (Task 18's axe run does, in browsers); what it can see is a color written into the page
// itself: an inline literal color, or a Mantine color variable the theme does not map onto a token, would ignore the
// scheme's tokens.
const DARK_VARIABLES: Record<string, string> = cssVariablesResolver(mergeMantineTheme(DEFAULT_THEME, appTheme(''))).dark;
function untokenedColors(style: string): string[] {
  const literal = style.match(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/gi) ?? [];
  const mantine = [...style.matchAll(/var\((--mantine-color-[a-z0-9-]+)\)/g)]
    .map(([, name]) => name)
    .filter((name) => !DARK_VARIABLES[name]?.startsWith('var(--alice-'));
  return [...literal, ...mantine];
}

describe.each(['en', 'tr'] as const)('the dark scheme in %s', (lang) => {
  it.each(SCREENS.map((s) => [s.path, s] as const))('%s renders from the tokens', async (_path, s) => {
    const session = s.session ? { ...s.session, user: { ...s.session.user, locale: lang } } : null;
    server.use(...sessionHandlers(session, s.status), ...dataHandlers);
    await renderRoute(s.path, { languages: [lang], colorScheme: 'dark' });
    await waitFor(() => expect(screen.getAllByText(s.ready[lang]).length).toBeGreaterThan(0));
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
    expect(screen.getAllByText(s.ready[lang])[0]).toBeVisible();
    expectNoRawKeys();
    const inline = [...document.body.querySelectorAll('[style]')].flatMap((el) => untokenedColors(el.getAttribute('style') ?? ''));
    expect(inline).toEqual([]);
  });
});

it('finds an inline color the dark scheme would not draw from the tokens', () => {
  expect(untokenedColors('--checkbox-color: var(--mantine-color-forest-filled);')).toEqual([]);
  expect(untokenedColors('--text-color: var(--alice-danger);')).toEqual([]);
  expect(untokenedColors('--text-color: var(--mantine-color-red-9); color: #000')).toEqual(['#000', '--mantine-color-red-9']);
  expect(untokenedColors('--progress-section-color: var(--mantine-color-yellow-filled)')).toEqual(['--mantine-color-yellow-filled']);
});

describe.each(['en', 'tr'] as const)('the SSH key dialogs in %s', (lang) => {
  it('render with no untranslated keys', async () => {
    const admin = sessionFor('admin');
    const session = { ...admin, user: { ...admin.user, locale: lang } };
    const key = { ...sshKeyFixture(), managed: true, managed_key: managedKeyFixture({ download_count: 2, last_downloaded_at: '2026-10-06T08:00:00Z', rotated_from: 'old' }), locations: [] };
    server.use(
      ...sessionHandlers(session, installedStatus),
      http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json(key)),
      http.post('/api/v1/ssh-keys/:id/actions/deploy', () => HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-d', type: 'sshkey.add', result: { result: 'verified' } }))),
      http.get('/api/v1/targets/:id/key-files', () => HttpResponse.json({ items: [{ os_user: 'deploy', files: ['/home/deploy/.ssh/authorized_keys'], default_file: '/home/deploy/.ssh/authorized_keys' }], scanned_at: null, refusal: null })),
      ...dataHandlers,
    );
    await renderRoute(`/ssh-keys/${key.id}`, { languages: [lang] });
    const t = (en: string, tr: string) => (lang === 'en' ? en : tr);
    await screen.findByText(t('Generated by Alice', 'Alice tarafından oluşturuldu'));
    expectNoRawKeys();
    await userEvent.click(screen.getByRole('button', { name: t('Download private key', 'Özel anahtarı indir') }));
    await screen.findByRole('dialog', { name: t('Download the private key', 'Özel anahtarı indir') });
    expectNoRawKeys();
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: t('Cancel', 'İptal') }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: t('Deploy to a server', 'Sunucuya dağıt') }));
    const deploy = await screen.findByRole('dialog', { name: t('Deploy this key', 'Bu anahtarı dağıt') });
    await within(deploy).findByRole('option', { name: 'deploy' });
    expectNoRawKeys();
    await userEvent.click(within(deploy).getByRole('button', { name: t('Deploy', 'Dağıt') }));
    await within(deploy).findByText(t('Alice added the key and verified a login with it.', 'Alice anahtarı ekledi ve anahtarla oturum açılabildiğini doğruladı.'));
    expectNoRawKeys();
  });

  it('render the generate dialog', async () => {
    const operator = sessionFor('operator');
    server.use(...sessionHandlers({ ...operator, user: { ...operator.user, locale: lang } }, installedStatus), ...dataHandlers);
    await renderRoute('/ssh-keys', { languages: [lang] });
    await userEvent.click(await screen.findByRole('button', { name: lang === 'en' ? 'Generate key' : 'Anahtar oluştur' }));
    await screen.findByRole('radio', { name: lang === 'en' ? 'Ed25519 (recommended)' : 'Ed25519 (önerilir)' });
    expectNoRawKeys();
  });
});

describe.each(['en', 'tr'] as const)('the rotation panel and its dialogs in %s', (lang) => {
  it('open the create, edit, preview and delete dialogs with no untranslated keys', async () => {
    const admin = sessionFor('admin');
    const key = { ...sshKeyFixture(), managed: true, managed_key: managedKeyFixture({ policy_id: POLICY_ID }), locations: [] };
    server.use(
      ...sessionHandlers({ ...admin, user: { ...admin.user, locale: lang } }, installedStatus),
      http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json(key)),
      http.get(`/api/v1/rotation/policies/${POLICY_ID}`, () => HttpResponse.json(policyFixture({ enabled: true, next_run_at: '2026-12-01T08:00:00Z', last_run_id: 'r9', last_run_status: 'cancelled', last_run_result: { code: 'ALC-ROT-0017', reason: 'rotation.notice_undelivered' } }))),
      http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ status: 'completed' })], next_cursor: null })),
      http.post(`/api/v1/rotation/policies/${POLICY_ID}/actions/preview`, () => HttpResponse.json(previewFixture())),
      ...dataHandlers,
    );
    const t = (en: string, tr: string) => (lang === 'en' ? en : tr);
    await renderRoute(`/ssh-keys/${key.id}`, { languages: [lang] });
    await screen.findByText(t('Automatic rotation', 'Otomatik yenileme'));
    expectNoRawKeys();
    const cancel = t('Cancel', 'İptal');
    const closeTop = async () => {
      await userEvent.click(within(screen.getAllByRole('dialog').at(-1) as HTMLElement).getByRole('button', { name: cancel }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    };
    await userEvent.click(await screen.findByRole('button', { name: t('Edit', 'Düzenle') }));
    await screen.findByRole('dialog', { name: t('Edit the rotation policy', 'Yenileme kuralını düzenle') });
    expectNoRawKeys();
    await closeTop();
    await userEvent.click(screen.getByRole('button', { name: t('Delete policy', 'Kuralı sil') }));
    await screen.findByRole('dialog');
    expectNoRawKeys();
    await closeTop();
    await userEvent.click(screen.getByRole('button', { name: t('Preview next run', 'Sonraki çalıştırmayı önizle') }));
    const preview = await screen.findByRole('dialog', { name: t('Preview of the next run', 'Sonraki çalıştırmanın önizlemesi') });
    await within(preview).findByText(t('Places that will change: 1', 'Değişecek yer sayısı: 1'));
    expectNoRawKeys();
    await userEvent.click(within(preview).getByRole('button', { name: t('Run now', 'Şimdi çalıştır') }));
    await screen.findByRole('dialog', { name: t('Start this rotation now?', 'Bu yenilemeyi şimdi başlatmak istiyor musunuz?') });
    expectNoRawKeys();
  });

  it('opens the create dialog on a key without a policy', async () => {
    const admin = sessionFor('admin');
    const key = { ...sshKeyFixture(), managed: true, managed_key: managedKeyFixture(), locations: [] };
    server.use(
      ...sessionHandlers({ ...admin, user: { ...admin.user, locale: lang } }, installedStatus),
      http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json(key)),
      http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [], next_cursor: null })),
      ...dataHandlers,
    );
    await renderRoute(`/ssh-keys/${key.id}`, { languages: [lang] });
    await userEvent.click(await screen.findByRole('button', { name: lang === 'en' ? 'Create rotation policy' : 'Yenileme kuralı oluştur' }));
    await screen.findByRole('dialog', { name: lang === 'en' ? 'Create a rotation policy' : 'Yenileme kuralı oluştur' });
    expectNoRawKeys();
  });
});

describe.each(['en', 'tr'] as const)('the certificate authority dialogs in %s', (lang) => {
  it('open the provider, account, hook and removal dialogs with no untranslated keys', async () => {
    const admin = sessionFor('admin');
    server.use(
      ...sessionHandlers({ ...admin, user: { ...admin.user, locale: lang }, stepup_until: '2099-01-01T00:00:00Z' }, installedStatus),
      http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [acmeProviderFixture({ eab_configured: true }), acmeProviderFixture({ id: 'p2', name: 'Corp CA', active_account_id: null })] })),
      http.get('/api/v1/acme/providers/:id', ({ params }) =>
        HttpResponse.json(params.id === 'p2' ? { ...acmeProviderFixture({ id: 'p2', active_account_id: null }), accounts: [] } : { ...acmeProviderFixture(), accounts: [acmeAccountFixture()] }),
      ),
      ...dataHandlers,
    );
    const t = (en: string, tr: string) => (lang === 'en' ? en : tr);
    await renderRoute('/settings?tab=acme', { languages: [lang] });
    await screen.findByText(t('Authorities and accounts', 'Yetkililer ve hesaplar'));
    const cancel = t('Cancel', 'İptal');
    const openAndClose = async (button: HTMLElement) => {
      await userEvent.click(button);
      const dialog = await screen.findByRole('dialog');
      // Nothing still loading or contacting the authority (the registration's preview).
      await waitFor(() => expect(within(dialog).queryAllByRole('status')).toEqual([]));
      expectNoRawKeys();
      await userEvent.click(within(dialog).getByRole('button', { name: cancel }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    };
    await openAndClose(screen.getByRole('button', { name: t('Add certificate authority', 'Sertifika yetkilisi ekle') }));
    await openAndClose(screen.getByRole('button', { name: t('Edit LE staging', 'LE staging öğesini düzenle') }));
    await openAndClose(screen.getByRole('button', { name: t('Remove LE staging', 'LE staging öğesini kaldır') }));
    await openAndClose(await screen.findByRole('button', { name: t('Rotate account key', 'Hesap anahtarını yenile') }));
    await openAndClose(screen.getByRole('button', { name: t('Deactivate account', 'Hesabı devre dışı bırak') }));
    await openAndClose(await screen.findByRole('button', { name: t('Register account', 'Hesap kaydet') }));
    await openAndClose(screen.getByRole('button', { name: t('Add DNS hook', 'DNS kancası ekle') }));
    await openAndClose(screen.getAllByRole('button', { name: t('Edit Internal DNS', 'Internal DNS öğesini düzenle') })[0]);
    await openAndClose(screen.getAllByRole('button', { name: t('Remove Internal DNS', 'Internal DNS öğesini kaldır') })[0]);
  });
});
