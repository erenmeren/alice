import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  bindingFixture,
  BINDING_ID,
  deployableLocationFixture,
  errorResponse,
  kvCertificateDetailFixture,
  KV_CERT_ID,
  sessionFor,
  sessionHandlers,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { ConnectWebsitesDialog } from './ConnectWebsitesDialog';
import deploy from './deploy.module.css';

const L1 = deployableLocationFixture({ id: 'l1', target_name: 'web-01', cert_path: '/etc/nginx/ssl/a.crt', server_names: ['a.example.test'] });
const L2 = deployableLocationFixture({ id: 'l2', target_name: 'web-02', cert_path: '/etc/nginx/ssl/b.crt', server_names: ['b.example.test'] });

function asRole(role: 'admin' | 'operator', lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)));
}

function locations(items = [L1, L2], seen: string[] = []) {
  server.use(
    http.get('/api/v1/certificate-locations', ({ request }) => {
      seen.push(new URL(request.url).search);
      return HttpResponse.json({ items, next_cursor: null });
    }),
  );
  return seen;
}

describe('ConnectWebsitesDialog', () => {
  it('loads the websites of the certificate\'s key type that are not connected, with server name and path in <code>', async () => {
    asRole('operator');
    const seen = locations();
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture({ key_type: 'RSA' })} onClose={vi.fn()} onDone={vi.fn()} />);
    expect(await screen.findByText('web-01')).toBeInTheDocument();
    expect(seen[0]).toContain('key_type=rsa');
    expect(seen[0]).toContain('unbound=true');
    expect(seen[0]).toContain('limit=50');
    expect(screen.getByText('/etc/nginx/ssl/a.crt').tagName).toBe('CODE');
    expect(screen.getByText('a.example.test').tagName).toBe('CODE');
    expect(screen.getByRole('button', { name: 'Connect websites' })).toBeDisabled();
  });

  it('searches with q', async () => {
    asRole('operator');
    const seen = locations();
    const user = userEvent.setup();
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={vi.fn()} />);
    await screen.findByText('web-01');
    await user.type(screen.getByLabelText('Search servers and websites'), 'web-02');
    await waitFor(() => expect(seen.some((s) => s.includes('q=web-02'))).toBe(true));
  });

  it('pages with Show more', async () => {
    asRole('operator');
    server.use(
      http.get('/api/v1/certificate-locations', ({ request }) => {
        const c = new URL(request.url).searchParams.get('cursor');
        return HttpResponse.json(c ? { items: [L2], next_cursor: null } : { items: [L1], next_cursor: 'c2' });
      }),
    );
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={vi.fn()} />);
    await screen.findByText('web-01');
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText('web-02')).toBeInTheDocument();
    expect(screen.getByText('web-01')).toBeInTheDocument();
  });

  it('selects several websites and posts /bindings', async () => {
    asRole('operator');
    locations();
    let body: unknown = null;
    server.use(http.post('/api/v1/bindings', async ({ request }) => { body = await request.json(); return HttpResponse.json(bindingFixture(), { status: 201 }); }));
    const onDone = vi.fn();
    const user = userEvent.setup();
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={onDone} />);
    await screen.findByText('web-01');
    const boxes = screen.getAllByRole('checkbox');
    await user.click(boxes[0]);
    await user.click(boxes[1]);
    expect(screen.getByText('Selected: 2')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Connect websites' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(body).toEqual({ kv_certificate_id: KV_CERT_ID, location_ids: ['l1', 'l2'] });
  });

  it('highlights the website a refusal names and keeps the dialog', async () => {
    asRole('operator');
    locations();
    server.use(http.post('/api/v1/bindings', () => errorResponse(409, 'ALC-AKV-0018', 'kv.location_bound', { params: { location_id: 'l2' } })));
    const user = userEvent.setup();
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={vi.fn()} />);
    await screen.findByText('web-01');
    for (const b of screen.getAllByRole('checkbox')) await user.click(b);
    await user.click(screen.getByRole('button', { name: 'Connect websites' }));
    const alerts = await screen.findAllByRole('alert');
    expect(alerts.some((a) => a.textContent?.includes('Website already connected'))).toBe(true);
    const bad = document.querySelector('[data-refused="true"]') as HTMLElement;
    expect(bad).toHaveTextContent('web-02');
    expect(document.querySelectorAll('[data-refused="true"]')).toHaveLength(1);
    expect(within(bad).getByText(/Alice stopped here/)).toBeInTheDocument();
    expect(bad).toHaveClass(deploy.refused);
    expect(bad?.getAttribute('style') ?? '').not.toMatch(/border/);
  });

  it('shows nothing selectable when no website fits', async () => {
    asRole('operator');
    locations([]);
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={vi.fn()} />);
    expect(await screen.findByText("No website is available for this certificate's key type.")).toBeInTheDocument();
  });

  describe('adding to an existing connection', () => {
    it('sends the old and new websites with If-Match, warns that automatic deployment follows, and asks for step-up when needed', async () => {
      asRole('admin');
      locations([L2]);
      const bodies: unknown[] = [];
      let ifMatch: string | null = null;
      server.use(
        http.patch(`/api/v1/bindings/${BINDING_ID}`, async ({ request }) => {
          bodies.push(await request.json());
          ifMatch = request.headers.get('If-Match');
          return bodies.length === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(bindingFixture());
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      );
      const onDone = vi.fn();
      const user = userEvent.setup();
      await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} binding={bindingFixture({ auto_deploy: true })} onClose={vi.fn()} onDone={onDone} />);
      expect(await screen.findByText(/deploys automatically, so the added websites are put under automatic deployment too/)).toBeInTheDocument();
      await screen.findByText('web-02');
      await user.click(screen.getByRole('checkbox'));
      await user.click(screen.getByRole('button', { name: 'Add websites' }));
      await user.type(await screen.findByLabelText('6-digit code'), '123456');
      await user.click(screen.getByRole('button', { name: 'Confirm' }));
      await waitFor(() => expect(onDone).toHaveBeenCalled());
      expect(bodies).toEqual([{ location_ids: ['0192d000-0000-7000-8000-0000000000f1', 'l2'] }, { location_ids: ['0192d000-0000-7000-8000-0000000000f1', 'l2'] }]);
      expect(ifMatch).toBe('"2"');
    });

    it('says the connection moved when the server answers 412', async () => {
      asRole('operator');
      locations([L2]);
      server.use(http.patch(`/api/v1/bindings/${BINDING_ID}`, () => errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed')));
      const user = userEvent.setup();
      await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} binding={bindingFixture()} onClose={vi.fn()} onDone={vi.fn()} />);
      await screen.findByText('web-02');
      await user.click(screen.getByRole('checkbox'));
      await user.click(screen.getByRole('button', { name: 'Add websites' }));
      expect(await screen.findByText(/This connection changed meanwhile/)).toBeInTheDocument();
    });
  });

  it('is complete in Turkish', async () => {
    asRole('operator', 'tr');
    locations();
    await renderWithStepUp(<ConnectWebsitesDialog certificate={kvCertificateDetailFixture()} onClose={vi.fn()} onDone={vi.fn()} />, ['tr-TR']);
    expect(await screen.findByText('Sunucularda ve web sitelerinde ara')).toBeInTheDocument();
    expect(screen.getByText('Seçilen: 0')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Web sitelerine bağla' })).toBeInTheDocument();
    expectNoRawKeys(screen.getByRole('dialog'));
  });
});
