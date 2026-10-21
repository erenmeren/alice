import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { certificateDetailFixture, certificateFixture, certificateImpactFixture, deploymentFixture, scopedSession, sessionHandlers, targetFixture } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderApp, renderRoute } from '../../test/render';
import { server } from '../../test/server';
import { HiddenCount, ServiceBadge } from './shared';

const ID = '0192c000-0000-7000-8000-0000000000c1';

describe('rows outside the reader’s services', () => {
  it('says a row is outside the reader’s services, never naming the service', async () => {
    await renderApp(<ServiceBadge service={{ outside: true }} link />);
    expect(screen.getByTestId('service-outside')).toHaveTextContent('outside your services');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('is Turkish in Turkish', async () => {
    await renderApp(
      <>
        <ServiceBadge service={{ outside: true }} />
        <HiddenCount count={3} />
      </>,
      ['tr'],
    );
    expect(screen.getByTestId('service-outside')).toHaveTextContent('hizmetlerinizin dışında');
    expect(screen.getByTestId('hidden-count')).toHaveTextContent('ve hizmetlerinizin dışında 3 tane daha');
    expectNoRawKeys(document.body);
  });

  it('says nothing when no related row was left out', async () => {
    await renderApp(<HiddenCount count={0} />);
    expect(screen.queryByTestId('hidden-count')).not.toBeInTheDocument();
  });

  it('counts the related rows left out', async () => {
    await renderApp(<HiddenCount count={1} />);
    expect(screen.getByTestId('hidden-count')).toHaveTextContent('and 1 more outside your services');
  });
});

function certPage(detail: object) {
  server.use(
    ...sessionHandlers(scopedSession(['operator'])),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get(`/api/v1/certificates/${ID}`, () => HttpResponse.json(detail)),
    http.get(`/api/v1/certificate-impact/${ID}`, () => HttpResponse.json({ ...certificateImpactFixture(), hidden_count: 4 })),
    http.get('/api/v1/deployments', () => HttpResponse.json({ items: [deploymentFixture()], next_cursor: null })),
  );
}

describe('a certificate seen from another service', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-03T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('shows the outside badge and the hidden locations, and offers no action the reader does not hold on it', async () => {
    certPage({ ...certificateDetailFixture({ id: ID }), service: { outside: true }, allowed_actions: ['read'], hidden_count: 2 });
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('heading', { name: 'www.example.test', level: 1 })).toBeInTheDocument();
    expect(screen.getByTestId('service-outside')).toHaveTextContent('outside your services');
    const used = screen.getByRole('table', { name: 'Where this certificate is used' }).closest('section') as HTMLElement;
    expect(within(used).getByTestId('hidden-count')).toHaveTextContent('and 2 more outside your services');
    expect(await within(screen.getByTestId('impact-panel')).findByTestId('hidden-count')).toHaveTextContent('and 4 more outside your services');
    expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Move to service' })).not.toBeInTheDocument();
  });

  it('offers Deploy when the reader operates certificates on its service', async () => {
    certPage({ ...certificateDetailFixture({ id: ID }), allowed_actions: ['read', 'certificates.operate'], hidden_count: 0 });
    await renderRoute(`/certificates/${ID}`);
    expect(await screen.findByRole('button', { name: 'Deploy' })).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'Where this certificate is used' }).closest('section') as HTMLElement).queryByTestId('hidden-count')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Move to service' })).not.toBeInTheDocument();
  });
});

describe('a list row outside the reader’s services', () => {
  it('shows the outside badge in the certificate list', async () => {
    server.use(
      ...sessionHandlers(scopedSession(['operator'])),
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null })),
      http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', () => HttpResponse.json({ items: [{ ...certificateFixture(), service: { outside: true }, allowed_actions: ['read'] }], next_cursor: null })),
    );
    await renderRoute('/certificates');
    expect(await screen.findByTestId('service-outside')).toHaveTextContent('outside your services');
  });
});
