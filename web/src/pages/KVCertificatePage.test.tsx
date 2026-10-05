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
    expect(policy).toHaveTextContent('Key: RSA, 3072 bits');
    expect(within(policy).getByText('RSA').tagName).toBe('CODE');
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
    expect(license).toHaveTextContent('New version found around a license expiry. Alice does not deploy it by itself; an administrator can deploy or release it.');
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

  it('lets an Administrator release a held version after a step-up, and says nothing was deployed', async () => {
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
    expect(dialog).toHaveTextContent('Releasing deploys nothing.');
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('Version released.')).toBeInTheDocument();
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
    await screen.findByText('Version released.');
    expect(body).toEqual({ confirm_incomplete_chain: true });
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
    expect(await screen.findByText('Sürümler')).toBeInTheDocument();
    expect(screen.getByTestId('held-text')).toHaveTextContent('Lisans süresinin dolduğu dönemde yeni sürüm bulundu.');
    expect(screen.getByRole('button', { name: 'aaaaaaaa sürümünü serbest bırak' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Şimdi dağıt' })).toBeInTheDocument());
    expectNoRawKeys(screen.getByRole('heading', { level: 1 }).parentElement as HTMLElement);
  });
});
