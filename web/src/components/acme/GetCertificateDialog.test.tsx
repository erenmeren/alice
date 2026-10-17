import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { ACMEProvider } from '../../api/acme';
import { ACME_CERT_ID, ACME_HOOK_ID, ACME_ORDER_ID, ACME_PROVIDER_ID, acmeCertificateFixture, acmeHookFixture, acmeOrderFixture, acmeProviderFixture, adminSession, errorResponse, apacheTargetFixture, nginxTargetFixture, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderWithStepUp } from '../../test/render';
import { server } from '../../test/server';
import { GetCertificateDialog } from './GetCertificateDialog';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const NO_ACCOUNT = '0192f000-0000-7000-8000-0000000000b1';
const ROLLOVER = '0192f000-0000-7000-8000-0000000000b2';

function base(opts: { providers?: ACMEProvider[]; hooks?: ReturnType<typeof acmeHookFixture>[]; extra?: Parameters<typeof server.use>; session?: typeof adminSession } = {}) {
  server.use(
    ...((opts.extra ?? []) as Parameters<typeof server.use>),
    ...sessionHandlers(opts.session ?? steppedUp),
    http.get('/api/v1/acme/providers', () =>
      HttpResponse.json({
        items: opts.providers ?? [
          acmeProviderFixture({ allowed_suffixes: ['example.com'] }),
          acmeProviderFixture({ id: NO_ACCOUNT, name: 'Corp CA', active_account_id: null }),
          acmeProviderFixture({ id: ROLLOVER, name: 'Other CA', pending_rollover: true }),
        ],
      }),
    ),
    http.get('/api/v1/acme/hooks', () => HttpResponse.json({ items: opts.hooks ?? [acmeHookFixture({ allowed_suffixes: ['www.example.com'] })] })),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [nginxTargetFixture], next_cursor: null })),
  );
}

function setup(languages?: string[]) {
  const onOpen = vi.fn();
  const onClose = vi.fn();
  return { onOpen, onClose, view: renderWithStepUp(<GetCertificateDialog onClose={onClose} onOpen={onOpen} />, languages) };
}

const dialog = () => screen.getByRole('dialog', { name: 'Get a certificate' });
const next = () => userEvent.click(within(dialog()).getByRole('button', { name: 'Next' }));
const heading = (name: string) => within(dialog()).getByRole('heading', { level: 2, name });

async function pickAuthority() {
  await userEvent.click(await within(await screen.findByRole('dialog', { name: 'Get a certificate' })).findByRole('radio', { name: 'LE staging' }));
  await next();
}

async function addName(name: string) {
  await userEvent.type(within(dialog()).getByRole('textbox', { name: 'Name' }), `${name}{Enter}`);
}

describe('Get a certificate', () => {
  it('walks through the four steps and the review, saves after a fresh step-up and runs a test first', async () => {
    let creates = 0;
    let body: unknown;
    let tests = 0;
    base({
      extra: [
        http.post('/api/v1/acme/certificates', async ({ request }) => {
          creates++;
          if (creates === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
          body = await request.json();
          return HttpResponse.json(acmeCertificateFixture({ state: 'pending' }), { status: 201 });
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
        http.post(`/api/v1/acme/certificates/${ACME_CERT_ID}/test`, () => (tests++, HttpResponse.json(acmeOrderFixture({ kind: 'test', state: 'running' }), { status: 202 }))),
      ],
    });
    const { onOpen, view } = setup();
    const { client } = await view;
    client.setQueryData(['acme', 'certificates', 'list', {}], { pages: [], pageParams: [] });
    const d = await screen.findByRole('dialog', { name: 'Get a certificate' });
    const rail = within(d).getByRole('list', { name: 'Steps' });
    expect(within(rail).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['1Authority', '2Names', '3Proof method', '4Websites and options', '5Review']);
    expect(within(rail).getByText('Authority').closest('li')).toHaveAttribute('aria-current', 'step');
    expect(heading('Which certificate authority?')).toBeInTheDocument();
    // Authorities without an active account (or with an unsettled key change) are listed, disabled, with the reason.
    expect(await within(d).findByRole('radio', { name: 'Corp CA' })).toBeDisabled();
    expect(within(d).getByText('No account is registered with this authority yet.')).toBeInTheDocument();
    expect(within(d).getByRole('radio', { name: 'Other CA' })).toBeDisabled();
    expect(within(d).getByText('The account key change of this authority is not settled yet.')).toBeInTheDocument();
    await pickAuthority();
    // The new step's heading takes the focus.
    await waitFor(() => expect(heading('Which names should the certificate cover?')).toHaveFocus());
    expect(within(rail).getByText('Names').closest('li')).toHaveAttribute('aria-current', 'step');
    await addName('www.example.com');
    await addName('Example.COM');
    expect(within(d).getByRole('list', { name: 'Names of the certificate' })).toHaveTextContent('www.example.comexample.com');
    await next();
    await waitFor(() => expect(heading('How does Alice prove that you control the names?')).toHaveFocus());
    await userEvent.selectOptions(within(d).getByLabelText('DNS hook'), ACME_HOOK_ID);
    // The hook allows only www.example.com: example.com is flagged early (the server decides).
    expect(within(d).getByTestId('names-not-allowed-hook')).toHaveTextContent('example.com');
    await next();
    await waitFor(() => expect(heading('Key, renewal and deployment')).toHaveFocus());
    expect(within(d).getByLabelText(/^Key type/)).toHaveValue('ecdsa_p256');
    expect(within(d).getByLabelText(/^Renew how many days/)).toHaveValue('30');
    expect(within(d).getByRole('switch', { name: /Renew automatically/ })).toBeChecked();
    await userEvent.selectOptions(within(d).getByLabelText(/^Key type/), 'rsa_3072');
    await userEvent.click(within(d).getByRole('checkbox', { name: /Deploy new certificates automatically/ }));
    expect(within(d).getByText(/You connect the websites on the certificate's page/)).toBeInTheDocument();
    await next();
    await waitFor(() => expect(heading('Check and save')).toHaveFocus());
    expect(d).toHaveTextContent('LE staging');
    expect(d).toHaveTextContent('DNS proof (DNS hook): Internal DNS');
    expect(d).toHaveTextContent('RSA 3072');
    expect(d).toHaveTextContent('Renews 30 days before it expires');
    await userEvent.click(within(d).getByRole('button', { name: 'Save certificate' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    expect(await within(d).findByText('The certificate is saved')).toBeInTheDocument();
    expect(body).toEqual({
      provider_id: ACME_PROVIDER_ID,
      names: ['www.example.com', 'example.com'],
      key_type: 'rsa_3072',
      challenge: 'dns01',
      hook_id: ACME_HOOK_ID,
      renew_before_days: 30,
      auto_renew: true,
      auto_deploy: true,
    });
    expect(creates).toBe(2);
    expect(client.getQueryState(['acme', 'certificates', 'list', {}])?.isInvalidated).toBe(true);
    await userEvent.click(within(d).getByRole('button', { name: 'Run a test first' }));
    await waitFor(() => expect(onOpen).toHaveBeenCalledWith(ACME_CERT_ID, ACME_ORDER_ID));
    expect(tests).toBe(1);
  });

  it('gets the certificate now from the done step', async () => {
    let orders = 0;
    base({
      providers: [acmeProviderFixture()],
      extra: [
        http.post('/api/v1/acme/certificates', () => HttpResponse.json(acmeCertificateFixture(), { status: 201 })),
        http.post(`/api/v1/acme/certificates/${ACME_CERT_ID}/order`, () => (orders++, HttpResponse.json(acmeOrderFixture({ state: 'running' }), { status: 202 }))),
      ],
    });
    const { onOpen } = setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.selectOptions(within(dialog()).getByLabelText('DNS hook'), ACME_HOOK_ID);
    await next();
    await next();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    await userEvent.click(await within(dialog()).findByRole('button', { name: 'Get certificate now' }));
    await waitFor(() => expect(onOpen).toHaveBeenCalledWith(ACME_CERT_ID, null));
    expect(orders).toBe(1);
  });

  it('shows a refusal of the order on the done step and still opens the certificate', async () => {
    base({
      providers: [acmeProviderFixture()],
      extra: [
        http.post('/api/v1/acme/certificates', () => HttpResponse.json(acmeCertificateFixture(), { status: 201 })),
        http.post(`/api/v1/acme/certificates/${ACME_CERT_ID}/test`, () => errorResponse(403, 'ALC-LIC-0001', 'license.locked')),
      ],
    });
    const { onOpen } = setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.selectOptions(within(dialog()).getByLabelText('DNS hook'), ACME_HOOK_ID);
    await next();
    await next();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    await userEvent.click(await within(dialog()).findByRole('button', { name: 'Run a test first' }));
    expect(await within(dialog()).findByRole('alert')).toHaveTextContent('ALC-LIC-0001');
    expect(onOpen).not.toHaveBeenCalled();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Open the certificate' }));
    expect(onOpen).toHaveBeenCalledWith(ACME_CERT_ID, null);
  });

  it('asks for an authority before going on', async () => {
    base();
    setup();
    await screen.findByRole('dialog', { name: 'Get a certificate' });
    await within(dialog()).findByRole('radio', { name: 'LE staging' });
    await next();
    expect(within(dialog()).getByText('Choose a certificate authority.')).toBeInTheDocument();
    expect(heading('Which certificate authority?')).toBeInTheDocument();
  });

  it('explains how to add an authority when none is ready', async () => {
    base({ providers: [acmeProviderFixture({ active_account_id: null }), acmeProviderFixture({ id: 'x', name: 'Empty CA', allowed_suffixes: [] })] });
    setup();
    const d = await screen.findByRole('dialog', { name: 'Get a certificate' });
    expect(await within(d).findByText('No certificate authority is ready')).toBeInTheDocument();
    expect(within(d).getByRole('link', { name: 'Settings → Certificate authorities' })).toHaveAttribute('href', '/settings?tab=acme');
    expect(within(d).getByText('No names are allowed for this authority yet.')).toBeInTheDocument();
  });

  it.each([
    ['bad_name.example.com', 'Use only letters, digits, hyphens and dots. A part cannot start or end with a hyphen.'],
    ['com', 'Use a full name with at least two parts, such as "www.example.com".'],
    ['10.0.0.1', 'Use a name, not an IP address.'],
    ['www.*.example.com', 'A wildcard (*) can only be the whole first part, such as "*.example.com".'],
  ])('refuses the name %s before sending anything', async (name, problem) => {
    base();
    setup();
    await pickAuthority();
    await addName(name);
    expect(within(dialog()).getByText(problem)).toBeInTheDocument();
    expect(within(dialog()).queryByRole('list', { name: 'Names of the certificate' })).not.toBeInTheDocument();
  });

  it('needs one name, refuses a duplicate and adds a typed name with Next', async () => {
    base();
    setup();
    await pickAuthority();
    await next();
    expect(within(dialog()).getByText('Add at least one name.')).toBeInTheDocument();
    await addName('www.example.com');
    await addName('WWW.example.com');
    expect(within(dialog()).getByText('This name is already in the list.')).toBeInTheDocument();
    await userEvent.clear(within(dialog()).getByRole('textbox', { name: 'Name' }));
    await userEvent.type(within(dialog()).getByRole('textbox', { name: 'Name' }), 'api.example.com');
    await next();
    expect(heading('How does Alice prove that you control the names?')).toBeInTheDocument();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Back' }));
    expect(within(dialog()).getByRole('list', { name: 'Names of the certificate' })).toHaveTextContent('www.example.comapi.example.com');
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Remove "api.example.com"' }));
    expect(within(dialog()).getByRole('list', { name: 'Names of the certificate' })).toHaveTextContent('www.example.com');
  });

  it('warns early about names outside the authority’s allowed endings', async () => {
    base();
    setup();
    await pickAuthority();
    await addName('www.other.org');
    const warning = within(dialog()).getByTestId('names-not-allowed');
    expect(warning).toHaveTextContent('These names are outside the domain endings allowed for LE staging');
    expect(warning).toHaveTextContent('www.other.org');
  });

  it('needs the DNS proof for a wildcard name', async () => {
    base();
    setup();
    await pickAuthority();
    await addName('*.example.com');
    expect(within(dialog()).getByText('A wildcard name (*.example.com) can only be proven with the DNS proof.')).toBeInTheDocument();
    await next();
    const web = within(dialog()).getByRole('radio', { name: 'Web proof (file on the web server)' });
    expect(web).toBeDisabled();
    expect(within(dialog()).getByText('A wildcard name needs the DNS proof.')).toBeInTheDocument();
  });

  it('shows a web server without the web proof disabled with the note', async () => {
    base({
      extra: [http.get('/api/v1/targets', () => HttpResponse.json({ items: [nginxTargetFixture, { ...nginxTargetFixture, id: '0192b000-0000-7000-8000-0000000000a9', name: 'web-2', capabilities: ['test_connection'] }], next_cursor: null }))],
    });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.click(within(dialog()).getByRole('radio', { name: 'Web proof (file on the web server)' }));
    await next();
    const select = await within(dialog()).findByLabelText(/^Web server/);
    const two = await within(select).findByRole('option', { name: /web-2/ });
    expect(two).toBeDisabled();
    expect(two).toHaveTextContent('Not available for Nginx servers yet');
    expect(within(select).getByRole('option', { name: 'web-nginx' })).toBeEnabled();
  });

  it('shows an Apache server in the web proof list disabled with the note', async () => {
    base({ extra: [http.get('/api/v1/targets', () => HttpResponse.json({ items: [nginxTargetFixture, apacheTargetFixture], next_cursor: null }))] });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.click(within(dialog()).getByRole('radio', { name: 'Web proof (file on the web server)' }));
    await next();
    const select = await within(dialog()).findByLabelText(/^Web server/);
    const apache = await within(select).findByRole('option', { name: /web-apache/ });
    expect(apache).toBeDisabled();
    expect(apache).toHaveTextContent('Not available for Apache servers yet');
    expect(within(select).getByRole('option', { name: 'web-nginx' })).toBeEnabled();
  });

  it('takes the web proof with a managed Nginx server and explains the one-time preparation', async () => {
    let body: unknown;
    base({ extra: [http.post('/api/v1/acme/certificates', async ({ request }) => ((body = await request.json()), HttpResponse.json(acmeCertificateFixture(), { status: 201 })))] });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.click(within(dialog()).getByRole('radio', { name: 'Web proof (file on the web server)' }));
    expect(within(dialog()).getByText(/Web site file proof \(HTTP-01\)/)).toBeInTheDocument();
    await next();
    expect(within(dialog()).getByText('Choose the web server.')).toBeInTheDocument();
    await userEvent.selectOptions(await within(dialog()).findByLabelText(/^Web server/), nginxTargetFixture.id);
    const prep = within(dialog()).getByText('Prepare the server once');
    await userEvent.click(prep);
    expect(within(dialog()).getByText(/root \/var\/www\/alice-acme;/)).toBeInTheDocument();
    expect(within(dialog()).getByText(/copy alice-helper from the current Alice bundle/)).toBeInTheDocument();
    await next();
    await next();
    expect(dialog()).toHaveTextContent('Web proof (file on the web server): web-nginx');
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    await within(dialog()).findByText('The certificate is saved');
    expect(body).toMatchObject({ challenge: 'http01', http_target_id: nginxTargetFixture.id });
    expect(body).not.toHaveProperty('hook_id');
  });

  it('asks for a hook and explains how to get one when there is none', async () => {
    base({ hooks: [] });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    expect(await within(dialog()).findByText('No DNS hook yet')).toBeInTheDocument();
    await next();
    expect(heading('How does Alice prove that you control the names?')).toBeInTheDocument();
  });

  it('keeps the renewal window between 1 and 60 days and a name at most 253 characters', async () => {
    base();
    setup();
    await pickAuthority();
    const name = within(dialog()).getByRole('textbox', { name: 'Name' });
    expect(name).toHaveAttribute('maxlength', '253');
    await addName('www.example.com');
    await next();
    await userEvent.selectOptions(within(dialog()).getByLabelText('DNS hook'), ACME_HOOK_ID);
    await next();
    const field = within(dialog()).getByLabelText(/^Renew how many days/);
    await userEvent.clear(field);
    await userEvent.type(field, '61');
    await userEvent.tab();
    expect(field).toHaveValue('60');
    await userEvent.clear(field);
    await next();
    expect(within(dialog()).getByText('Use a whole number from 1 to 60.')).toBeInTheDocument();
    await userEvent.type(field, '0');
    await userEvent.tab();
    expect(field).toHaveValue('1');
  });

  it('keeps every answer when the step-up is cancelled, and saves on the second try', async () => {
    let creates = 0;
    base({
      extra: [
        http.post('/api/v1/acme/certificates', () => {
          creates++;
          return creates === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(acmeCertificateFixture(), { status: 201 });
        }),
      ],
      session: { ...adminSession, stepup_until: null },
    });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.selectOptions(within(dialog()).getByLabelText('DNS hook'), ACME_HOOK_ID);
    await next();
    await next();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: "Confirm it's you" })).not.toBeInTheDocument());
    expect(heading('Check and save')).toBeInTheDocument();
    expect(dialog()).toHaveTextContent('www.example.com');
    expect(dialog()).toHaveTextContent('Internal DNS');
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    expect(await within(dialog()).findByText('The certificate is saved')).toBeInTheDocument();
  });

  it('shows the server’s refusal on the review (a name not allowed) and keeps the answers', async () => {
    base({ extra: [http.post('/api/v1/acme/certificates', () => errorResponse(422, 'ALC-ACM-0015', 'acme.name_not_allowed'))] });
    setup();
    await pickAuthority();
    await addName('www.example.com');
    await next();
    await userEvent.selectOptions(within(dialog()).getByLabelText('DNS hook'), ACME_HOOK_ID);
    await next();
    await next();
    await userEvent.click(within(dialog()).getByRole('button', { name: 'Save certificate' }));
    const alert = await within(dialog()).findByRole('alert');
    expect(alert).toHaveTextContent('This name is not allowed.');
    expect(alert).toHaveTextContent('ALC-ACM-0015');
    expect(heading('Check and save')).toBeInTheDocument();
  });

  it('is operated from the keyboard: Enter adds a name, Enter on the form goes on', async () => {
    base();
    setup();
    const d = await screen.findByRole('dialog', { name: 'Get a certificate' });
    const radio = await within(d).findByRole('radio', { name: 'LE staging' });
    radio.focus();
    await userEvent.keyboard(' ');
    expect(radio).toBeChecked();
    await userEvent.keyboard('{Enter}');
    await waitFor(() => expect(heading('Which names should the certificate cover?')).toHaveFocus());
    await userEvent.tab();
    expect(within(d).getByRole('textbox', { name: 'Name' })).toHaveFocus();
    await userEvent.keyboard('www.example.com{Enter}');
    expect(within(d).getByRole('list', { name: 'Names of the certificate' })).toHaveTextContent('www.example.com');
    expect(heading('Which names should the certificate cover?')).toBeInTheDocument();
  });

  it('renders in Turkish with the glosses and no raw keys', async () => {
    base({ session: { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' } });
    setup(['tr']);
    const d = await screen.findByRole('dialog', { name: 'Sertifika al' });
    await userEvent.click(await within(d).findByRole('radio', { name: 'LE staging' }));
    await userEvent.click(within(d).getByRole('button', { name: 'İleri' }));
    await userEvent.type(within(d).getByRole('textbox', { name: 'Ad' }), 'www.example.com{Enter}');
    await userEvent.click(within(d).getByRole('button', { name: 'İleri' }));
    await userEvent.click(within(d).getByRole('radio', { name: 'Web kanıtı (web sunucusunda bir dosya)' }));
    expect(within(d).getByText(/Web sitesi dosyası ile doğrulama \(HTTP-01\)/)).toBeInTheDocument();
    expectNoRawKeys();
  });
});
