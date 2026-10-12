import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  bindingFixture,
  BINDING_ID,
  errorResponse,
  kvCertificateDetailFixture,
  KV_CERT_ID,
  kvVersionFixture,
  sessionFor,
  sessionHandlers,
  VAULT_ID,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const PATH = `/key-vaults/${VAULT_ID}/certificates/${KV_CERT_ID}`;
type Role = 'admin' | 'operator' | 'auditor';
const SUMMARY = { id: BINDING_ID, auto_deploy: false, auto_since: null, stopped_version: '', location_count: 1, version: 2, created_at: '' };

const V1 = kvVersionFixture({ id: 'v1', version: 'aaaaaaaa11111111aaaaaaaa11111111', thumbprint: 'a1'.repeat(20), detected_at: '2026-10-04T00:00:00Z', kv_created_at: new Date(Date.now() - 86_400_000).toISOString() });
const V0 = kvVersionFixture({ id: 'v0', version: 'bbbbbbbb22222222bbbbbbbb22222222', thumbprint: 'b2'.repeat(20), detected_at: '2026-09-02T00:00:00Z', expires: '2020-01-01T00:00:00Z' });

function setup(role: Role, cert = kvCertificateDetailFixture(), lang = 'en') {
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}`, () => HttpResponse.json(cert)),
    http.get(`/api/v1/bindings/${BINDING_ID}`, () => HttpResponse.json(bindingFixture())),
  );
}

describe('KVCertificatePage', () => {
  it('shows the policy: exportable, key type and size, issuer, renews itself', async () => {
    setup('operator', kvCertificateDetailFixture({ exportable: true, key_type: 'RSA', key_size: 3072, issuer_name: 'Contoso CA', auto_renew: true }));
    await renderRoute(PATH);
    expect(await screen.findByRole('heading', { name: 'web-cert', level: 1 })).toBeInTheDocument();
    const policy = screen.getByLabelText('Policy');
    expect(policy).toHaveTextContent('Private key exportable');
    expect(policy).toHaveTextContent('Yes');
    expect(within(policy).getByText('Key type').tagName).toBe('DT');
    expect(within(policy).getByText('RSA').tagName).toBe('CODE');
    expect(policy).toHaveTextContent('3072 bits');
    expect(policy).toHaveTextContent('Contoso CA');
    expect(policy).toHaveTextContent('Key Vault renews this certificate itself.');
  });

  it('says Monitor only for a key that is not exportable and offers no connection', async () => {
    setup('operator', kvCertificateDetailFixture({ exportable: false, versions: [kvVersionFixture({ exportable: false })] }));
    await renderRoute(PATH);
    expect(await screen.findByText(/Monitor only: this certificate's private key cannot be exported/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect websites' })).toBeDisabled();
  });

  it('lists the versions newest first with thumbprint, validity, enabled, found on and the New version found badge', async () => {
    setup('operator', kvCertificateDetailFixture({ versions: [V1, V0], current_version: V1.version }));
    await renderRoute(PATH);
    const table = await screen.findByRole('table', { name: 'Versions' });
    const rows = within(table).getAllByTestId('kv-version-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText('aaaaaaaa').tagName).toBe('CODE');
    expect(within(rows[0]).getByText('a1'.repeat(20)).tagName).toBe('CODE');
    expect(rows[0]).toHaveTextContent('Current');
    expect(rows[0]).toHaveTextContent('New version found');
    expect(rows[1]).toHaveTextContent('Expired');
    expect(rows[1]).not.toHaveTextContent('New version found');
    for (const h of ['Version', 'Thumbprint', 'Valid from', 'Valid until', 'Enabled', 'Found on', 'State', 'Actions']) expect(within(table).getByRole('columnheader', { name: h })).toBeInTheDocument();
  });

  it('shows a held version with why and who can release it, true for every license hold', async () => {
    setup('operator', kvCertificateDetailFixture({ versions: [{ ...V1, held: true, held_reason: 'license' }, { ...V0, held: true, held_reason: 'incomplete_chain', expires: '2030-01-01T00:00:00Z' }], binding: SUMMARY, bound: true }));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    const license = within(rows[0]).getByTestId('held-text');
    expect(license).toHaveTextContent('This version is waiting for an administrator: the license was not available at some point since the version appeared. Alice does not deploy it by itself; an administrator can deploy or release it.');
    expect(license.textContent).not.toMatch(/while the license was expired/);
    expect(within(rows[1]).getByTestId('held-text')).toHaveTextContent('Held because its certificate chain is incomplete.');
    expect(within(rows[0]).getByText('Held')).toBeInTheDocument();
    expect(within(rows[0]).getByText('Only an administrator can deploy or release it.')).toBeInTheDocument();
    expect(within(rows[0]).queryByRole('button', { name: /Release/ })).not.toBeInTheDocument();
    expect(within(rows[0]).getByRole('button', { name: /Deploy now: version aaaaaaaa/ })).toBeDisabled();
  });

  it('offers Deploy now per version that has details; the others are disabled with the reason', async () => {
    const noLeaf = kvVersionFixture({ id: 'v2', version: 'cccccccc33333333cccccccc33333333', certificate_id: null });
    const off = kvVersionFixture({ id: 'v3', version: 'dddddddd44444444dddddddd44444444', enabled: false });
    setup('operator', kvCertificateDetailFixture({ versions: [V1, noLeaf, off, V0], binding: SUMMARY, bound: true, current_version: V1.version }));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    expect(within(rows[0]).getByRole('button', { name: /Deploy now/ })).toBeEnabled();
    expect(within(rows[1]).getByRole('button', { name: /Deploy now/ })).toBeDisabled();
    expect(rows[1]).toHaveTextContent('Alice has not read the details of this version yet.');
    expect(within(rows[2]).getByRole('button', { name: /Deploy now/ })).toBeDisabled();
    expect(rows[2]).toHaveTextContent('This version is disabled in Key Vault.');
    expect(within(rows[3]).getByRole('button', { name: /Deploy now/ })).toBeDisabled();
    expect(rows[3]).toHaveTextContent('This version has expired.');
  });

  it('tells an Operator on the row that a version whose chain is known incomplete needs an administrator', async () => {
    const chain = { ...V1, chain_incomplete: true };
    setup('operator', kvCertificateDetailFixture({ versions: [chain, V0], binding: SUMMARY, bound: true, current_version: V1.version }));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    expect(within(rows[0]).getByRole('button', { name: /Deploy now/ })).toBeDisabled();
    expect(rows[0]).toHaveTextContent('The chain of this version is incomplete. Only an administrator can deploy it.');
  });

  it('lets an Administrator open Deploy now for a version whose chain is known incomplete', async () => {
    const chain = { ...V1, chain_incomplete: true };
    setup('admin', kvCertificateDetailFixture({ versions: [chain], binding: SUMMARY, bound: true, current_version: V1.version }));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    expect(within(rows[0]).getByRole('button', { name: /Deploy now/ })).toBeEnabled();
    expect(rows[0]).not.toHaveTextContent('Only an administrator can deploy it.');
  });

  it('offers no version actions without a connection or to an Auditor', async () => {
    setup('operator');
    const v = await renderRoute(PATH);
    await screen.findAllByTestId('kv-version-row');
    expect(screen.queryByRole('button', { name: /Deploy now/ })).not.toBeInTheDocument();
    v.unmount();
    setup('auditor', kvCertificateDetailFixture({ binding: SUMMARY, bound: true }));
    await renderRoute(PATH);
    await screen.findAllByTestId('kv-version-row');
    await screen.findAllByTestId('binding-location');
    for (const name of [/Deploy now/, /Release/, /Connect websites/, /Add websites/, /Delete connection/, /Check deploy access/]) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
  });

  it('opens Deploy now for a version with the connection\'s websites', async () => {
    setup('operator', kvCertificateDetailFixture({ versions: [V1, V0], binding: SUMMARY, bound: true, current_version: V1.version }));
    server.use(http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}`, () => HttpResponse.json(kvCertificateDetailFixture({ versions: [V1, V0], binding: SUMMARY, bound: true, current_version: V1.version }))));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    await userEvent.click(within(rows[0]).getByRole('button', { name: /Deploy now: version aaaaaaaa/ }));
    const dialog = await screen.findByRole('dialog');
    expect((within(dialog).getByLabelText('Version') as HTMLSelectElement).value).toBe('v1');
    expect(within(dialog).getByRole('checkbox', { name: /web-01/ })).toBeChecked();
  });

  it('lets an Administrator release a held version after a step-up; without automatic deployment it says nothing is deployed', async () => {
    const held = { ...V1, held: true, held_reason: 'license' as const };
    setup('admin', kvCertificateDetailFixture({ versions: [held], binding: SUMMARY, bound: true }));
    let calls = 0;
    let body: unknown = 'unset';
    server.use(
      http.post(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}/versions/v1/actions/release`, async ({ request }) => {
        body = await request.json();
        return ++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({ ...held, held: false, held_reason: '' });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const user = userEvent.setup();
    await renderRoute(PATH);
    await user.click(await screen.findByRole('button', { name: 'Release version aaaaaaaa' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('Nothing is deployed. Use Deploy now when you want this version on a website.');
    expect(dialog).not.toHaveTextContent('Releasing deploys nothing');
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('Version released. Nothing is deployed; use Deploy now when you want it on a website.')).toBeInTheDocument();
    expect(calls).toBe(2);
    expect(body).toEqual({});
  });

  it('needs the chain confirmation to release a version held for its incomplete chain', async () => {
    const held = { ...V1, held: true, held_reason: 'incomplete_chain' as const };
    setup('admin', kvCertificateDetailFixture({ versions: [held], binding: SUMMARY, bound: true }));
    let body: unknown = null;
    server.use(http.post(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}/versions/v1/actions/release`, async ({ request }) => { body = await request.json(); return HttpResponse.json({ ...held, held: false, held_reason: '' }); }));
    const user = userEvent.setup();
    await renderRoute(PATH);
    await user.click(await screen.findByRole('button', { name: 'Release version aaaaaaaa' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('button', { name: 'Release' })).toBeDisabled();
    await user.click(within(dialog).getByLabelText('I confirm that this incomplete chain is intended'));
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    await screen.findByText(/^Version released\./);
    expect(body).toEqual({ confirm_incomplete_chain: true });
  });

  const RELEASE = `/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}/versions/v1/actions/release`;
  const TEXT = {
    chain: ['Automatic deployment never deploys an incomplete chain: if the chain is still incomplete, Alice holds this version again. To deploy it as it is, use Deploy now and confirm the chain.', 'Version released. Automatic deployment will not deploy an incomplete chain; use Deploy now and confirm the chain.'],
    may: ['Automatic deployment is on, so Alice may deploy this version to the connected websites by itself, usually within a minute.', 'Version released. Alice may deploy it by itself, usually within a minute.'],
    manual: ['Nothing is deployed. Use Deploy now when you want this version on a website.', 'Version released. Nothing is deployed; use Deploy now when you want it on a website.'],
    chainManual: [
      'Nothing is deployed. Deploy now asks for the chain confirmation again when you deploy this version.',
      'Version released. Nothing is deployed; Deploy now asks for the chain confirmation again.',
    ],
  };
  const TEXT_TR = {
    chain: ['Otomatik dağıtım eksik bir zinciri hiçbir zaman dağıtmaz: zincir hâlâ eksikse Alice bu sürümü yeniden bekletir. Olduğu gibi dağıtmak için Şimdi dağıt düğmesini kullanın ve zinciri onaylayın.', 'Sürüm serbest bırakıldı. Otomatik dağıtım eksik bir zinciri dağıtmaz; Şimdi dağıt düğmesini kullanın ve zinciri onaylayın.'],
    may: ['Otomatik dağıtım açık; Alice bu sürümü bağlı web sitelerine kendiliğinden dağıtabilir, genellikle bir dakika içinde.', 'Sürüm serbest bırakıldı. Alice bu sürümü kendiliğinden dağıtabilir, genellikle bir dakika içinde.'],
    manual: ['Hiçbir şey dağıtılmaz. Bu sürümü bir web sitesinde istediğinizde Şimdi dağıt düğmesini kullanın.', 'Sürüm serbest bırakıldı. Hiçbir şey dağıtılmaz; istediğinizde Şimdi dağıt düğmesini kullanın.'],
    chainManual: [
      'Hiçbir şey dağıtılmaz. Bu sürümü dağıttığınızda Şimdi dağıt zincir onayını yeniden ister.',
      'Sürüm serbest bırakıldı. Hiçbir şey dağıtılmaz; Şimdi dağıt zincir onayını yeniden ister.',
    ],
  };

  // Each case: [the version's hold reason, is it the current version, automatic deployment on, which text].
  const CASES = [
    ['a chain hold with automatic deployment on', 'incomplete_chain', true, true, 'chain'],
    ['a chain hold that is not the current version', 'incomplete_chain', false, true, 'chain'],
    ['a license hold on the current version with automatic deployment on', 'license', true, true, 'may'],
    ['a license hold on a version that is not the current one', 'license', false, true, 'manual'],
    ['a license hold with automatic deployment off', 'license', true, false, 'manual'],
    ['a chain hold with automatic deployment off', 'incomplete_chain', true, false, 'chainManual'],
  ] as const;

  it.each(CASES)('releasing %s says the right thing before and after, in English', async (_n, reason, current, auto, kind) => {
    const held = { ...V1, held: true, held_reason: reason };
    setup('admin', kvCertificateDetailFixture({ versions: [held], current_version: current ? V1.version : 'cccccccc33333333cccccccc33333333', binding: { ...SUMMARY, auto_deploy: auto }, bound: true }));
    server.use(http.post(RELEASE, () => HttpResponse.json({ ...held, held: false, held_reason: '' })));
    const user = userEvent.setup();
    await renderRoute(PATH);
    await user.click(await screen.findByRole('button', { name: 'Release version aaaaaaaa' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(TEXT[kind][0]);
    for (const other of ['chain', 'may', 'manual', 'chainManual'] as const) if (other !== kind) expect(dialog.textContent).not.toContain(TEXT[other][0]);
    if (kind !== 'may') expect(dialog.textContent).not.toMatch(/minute/);
    if (reason === 'incomplete_chain') await user.click(within(dialog).getByLabelText('I confirm that this incomplete chain is intended'));
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    const done = await screen.findByText(/^Version released\./);
    expect(done.textContent).toBe(TEXT[kind][1]);
    if (kind !== 'may') expect(done.textContent).not.toMatch(/minute/);
  });

  it.each(CASES)('releasing %s says the right thing before and after, in Turkish', async (_n, reason, current, auto, kind) => {
    const held = { ...V1, held: true, held_reason: reason };
    setup('admin', kvCertificateDetailFixture({ versions: [held], current_version: current ? V1.version : 'cccccccc33333333cccccccc33333333', binding: { ...SUMMARY, auto_deploy: auto }, bound: true }), 'tr');
    server.use(http.post(RELEASE, () => HttpResponse.json({ ...held, held: false, held_reason: '' })));
    const user = userEvent.setup();
    await renderRoute(PATH, { languages: ['tr-TR'] });
    await user.click(await screen.findByRole('button', { name: 'aaaaaaaa sürümünü serbest bırak' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(TEXT_TR[kind][0]);
    if (kind !== 'may') expect(dialog.textContent).not.toMatch(/dakika/);
    if (reason === 'incomplete_chain') await user.click(within(dialog).getByRole('checkbox'));
    await user.click(within(dialog).getByRole('button', { name: 'Serbest bırak' }));
    const done = await screen.findByText(/^Sürüm serbest bırakıldı\./);
    expect(done.textContent).toBe(TEXT_TR[kind][1]);
  });

  it('shows no key size for a key whose size is unknown (an EC curve)', async () => {
    setup('operator', kvCertificateDetailFixture({ key_type: 'EC', key_size: 0 }));
    await renderRoute(PATH);
    const policy = await screen.findByLabelText('Policy');
    expect(within(policy).getByText('EC').tagName).toBe('CODE');
    expect(policy).not.toHaveTextContent('0 bits');
  });

  it('shows the error when the connection cannot be read for Deploy now', async () => {
    setup('operator', kvCertificateDetailFixture({ versions: [V1], binding: SUMMARY, bound: true, current_version: V1.version }));
    server.use(http.get(`/api/v1/bindings/${BINDING_ID}`, () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute(PATH);
    const rows = await screen.findAllByTestId('kv-version-row');
    await userEvent.click(within(rows[0]).getByRole('button', { name: /Deploy now/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('alert')).toBeInTheDocument();
  });

  it('shows the binding panel with Connect websites for a certificate without a connection', async () => {
    setup('operator');
    await renderRoute(PATH);
    expect(await screen.findByRole('heading', { name: 'Connected websites', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect websites' })).toBeEnabled();
  });

  it('shows the error of an unknown certificate with a way back', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates/${KV_CERT_ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await renderRoute(PATH);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the vault' })).toHaveAttribute('href', `/key-vaults/${VAULT_ID}`);
  });

  it('shows what the vault owner wrote as text only', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    setup('operator', kvCertificateDetailFixture({ name: evil, issuer_name: 'javascript:alert(1)', content_type: `${'long-'.repeat(60)}end`, key_type: '‮rev‬' }));
    await renderRoute(PATH);
    await screen.findByRole('heading', { level: 1 });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(evil);
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('a[href^="javascript"]')).toBeNull();
    const policy = screen.getByLabelText('Policy');
    expect(policy).toHaveTextContent('javascript:alert(1)');
    expect((within(policy).getByText(/long-long/) as HTMLElement).style.overflowWrap).toBe('anywhere');
  });

  it('is complete in Turkish', async () => {
    setup('admin', kvCertificateDetailFixture({ versions: [{ ...V1, held: true, held_reason: 'license' }], binding: SUMMARY, bound: true, exportable: true }), 'tr');
    await renderRoute(PATH, { languages: ['tr-TR'] });
    expect(await screen.findByText('Sürüm geçmişi')).toBeInTheDocument();
    expect(screen.getByTestId('held-text')).toHaveTextContent('Bu sürüm bir yöneticiyi bekliyor: sürüm ortaya çıktıktan sonra bir süre lisans kullanılamadı.');
    expect(screen.getByRole('button', { name: 'aaaaaaaa sürümünü serbest bırak' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Şimdi dağıt' })).toBeInTheDocument());
    expectNoRawKeys(screen.getByRole('heading', { level: 1 }).parentElement as HTMLElement);
  });

  describe('in the design', () => {
    it('has the detail header: back to the vault, the name as the only h1, the design subtitle and the chips as status badges', async () => {
      setup('operator', kvCertificateDetailFixture({ exportable: false, binding: SUMMARY, bound: true }));
      await renderRoute(PATH);
      const h1 = await screen.findByRole('heading', { name: 'web-cert', level: 1 });
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
      expect(screen.getByRole('link', { name: 'Back to the vault' })).toHaveAttribute('href', `/key-vaults/${VAULT_ID}`);
      const header = h1.closest('header')!;
      expect(header).toHaveTextContent('Certificate versions and deployment connections');
      expect(within(header).getByText('Monitor only').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
      expect(within(header).getByText('Connected websites: 1').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    });

    it('shows the versions in the Version history panel, the connected websites below them, the policy and the auto-deploy notice beside them', async () => {
      setup('admin', kvCertificateDetailFixture({ versions: [{ ...V1, held: true, held_reason: 'license' }, V0], binding: SUMMARY, bound: true, current_version: V1.version }));
      await renderRoute(PATH);
      const versions = (await screen.findByRole('heading', { name: 'Version history', level: 2 })).closest('section')!;
      expect(versions).toHaveTextContent('A new version is reviewed before it reaches a website.');
      const table = within(versions).getByRole('table', { name: 'Versions' });
      const rows = within(table).getAllByTestId('kv-version-row');
      expect(rows).toHaveLength(2);
      expect(rows[0]).toHaveAttribute('data-held', 'true');
      expect(rows[1]).not.toHaveAttribute('data-held');
      expect(within(rows[0]).getByTestId('held-text')).toBeInTheDocument();
      expect(within(rows[0]).getByText('Held').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
      expect(within(rows[0]).getByRole('button', { name: 'Release version aaaaaaaa' })).toBeInTheDocument();
      const binding = await screen.findByTestId('binding-panel');
      expect(binding.tagName).toBe('SECTION');
      const policy = screen.getByRole('heading', { name: 'Certificate policy', level: 2 }).closest('section')!;
      expect(within(policy).getByLabelText('Policy')).toHaveTextContent('Rotation in AliceKey Vault keys: inventory only');
      const auto = screen.getByText('Automatic deployment is an administrator decision').closest('[role="note"]')!;
      expect(auto).toHaveTextContent('Changing this setting requires fresh identity verification.');
      const follows = (a: Node, b: Node) => (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
      expect(follows(versions, binding)).toBe(true);
      expect(follows(binding, policy)).toBe(true);
      expect(follows(policy, auto)).toBe(true);
    });

    it('shows the websites state as a status badge that keeps data-state', async () => {
      setup('operator', kvCertificateDetailFixture({ versions: [V1], binding: SUMMARY, bound: true, current_version: V1.version }));
      await renderRoute(PATH);
      const location = await screen.findByTestId('binding-location');
      const state = location.querySelector('[data-state]')!;
      expect(state.closest('.mantine-Badge-root')).not.toBeNull();
      expect(state).toHaveAttribute('data-tone');
    });
  });
});
