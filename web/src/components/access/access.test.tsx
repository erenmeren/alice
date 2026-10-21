import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { User } from '../../api/types';
import {
  adminSession,
  defaultServiceFixture,
  environmentBindingFixture,
  environmentFixture,
  errorResponse,
  PRODUCTION_ID,
  ROLE_BINDING_ID,
  roleBindingFixture,
  SERVICE_ID,
  serviceFixture,
  servicePolicyFixture,
  serviceRef,
  sessionFor,
  sessionHandlers,
  userFor,
} from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const operator = userFor('operator');

interface Seen {
  method: string;
  path: string;
  body: unknown;
}

// people installs People & access with one operator, their two bindings and the step-up exchange: the first POST and
// DELETE ask for a fresh code, the retry passes.
function people(opts: { bindings?: unknown[]; users?: User[] } = {}) {
  const seen: Seen[] = [];
  const asked = { post: false, del: false };
  server.use(
    ...sessionHandlers(adminSession),
    http.get('/api/v1/users', () => HttpResponse.json({ items: opts.users ?? [adminSession.user, operator] })),
    http.get('/api/v1/services', () => HttpResponse.json({ items: [defaultServiceFixture, serviceFixture()] })),
    http.get('/api/v1/environments', () => HttpResponse.json({ items: [environmentFixture()] })),
    http.get('/api/v1/role-bindings', ({ request }) => {
      seen.push({ method: 'GET', path: new URL(request.url).search, body: null });
      return HttpResponse.json({ items: opts.bindings ?? [roleBindingFixture(), environmentBindingFixture] });
    }),
    http.post('/api/v1/role-bindings', async ({ request }) => {
      const body = await request.json();
      seen.push({ method: 'POST', path: '', body });
      if (!asked.post) {
        asked.post = true;
        return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
      }
      return HttpResponse.json(roleBindingFixture({ id: 'new' }), { status: 201 });
    }),
    http.delete('/api/v1/role-bindings/:id', ({ params }) => {
      seen.push({ method: 'DELETE', path: String(params.id), body: null });
      if (!asked.del) {
        asked.del = true;
        return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
      }
      return new HttpResponse(null, { status: 204 });
    }),
    http.post('/api/v1/auth/stepup', () => HttpResponse.json({ ...adminSession, stepup_until: '2099-01-01T00:00:00Z' })),
  );
  return seen;
}

async function openAccess(username = 'operator') {
  await userEvent.click(await screen.findByRole('button', { name: `Manage ${username}` }));
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Access' }));
  return screen.findByTestId('user-access');
}

async function stepUp() {
  await userEvent.type(await screen.findByLabelText(/code/i), '123456');
  await userEvent.keyboard('{Enter}');
}

describe('People & access: Access', () => {
  it('shows the global role first as All services, then each binding with where, what it covers and who added it', async () => {
    const seen = people();
    await renderRoute('/users');
    const access = await openAccess();
    expect(within(within(access).getByTestId('global-role')).getByRole('rowheader', { name: 'All services' })).toBeInTheDocument();
    expect(within(access).getByTestId('global-role')).toHaveTextContent('Operator');
    const rows = await within(access).findAllByTestId('binding-row');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Operator');
    expect(rows[0]).toHaveTextContent('Payments');
    expect(within(rows[0]).getByText('Production').closest('[data-environment]')).toHaveAttribute('data-environment', 'production');
    expect(rows[0]).toHaveTextContent('by Ayşe Yılmaz');
    expect(rows[1]).toHaveTextContent('Auditor');
    expect(rows[1]).toHaveTextContent('Every service in Production');
    expect(rows[1]).toHaveTextContent('Payments');
    expect(seen[0]).toEqual({ method: 'GET', path: `?user_id=${operator.id}`, body: null });
  });

  it('adds a binding on an environment with a fresh step-up', async () => {
    const seen = people({ bindings: [] });
    await renderRoute('/users');
    const access = await openAccess();
    expect(await within(access).findByTestId('user-bindings-empty')).toHaveTextContent('No role on a single service or environment.');
    await userEvent.selectOptions(within(access).getByLabelText('Role'), 'auditor');
    const where = within(access).getByLabelText('Service or environment');
    await within(access).findByRole('option', { name: 'Every service in Production' });
    await userEvent.selectOptions(where, `e:${PRODUCTION_ID}`);
    await userEvent.click(within(access).getByRole('button', { name: 'Add' }));
    await stepUp();
    await waitFor(() => expect(seen.filter((s) => s.method === 'POST')).toHaveLength(2));
    expect(seen.filter((s) => s.method === 'POST')[1].body).toEqual({ user_id: operator.id, role: 'auditor', environment_id: PRODUCTION_ID });
  });

  it('adds a binding on one service', async () => {
    const seen = people({ bindings: [] });
    await renderRoute('/users');
    const access = await openAccess();
    await within(access).findByRole('option', { name: 'Payments (Production)' });
    await userEvent.selectOptions(within(access).getByLabelText('Service or environment'), `s:${SERVICE_ID}`);
    await userEvent.click(within(access).getByRole('button', { name: 'Add' }));
    await stepUp();
    await waitFor(() => expect(seen.filter((s) => s.method === 'POST')).toHaveLength(2));
    expect(seen.filter((s) => s.method === 'POST')[1].body).toEqual({ user_id: operator.id, role: 'operator', service_id: SERVICE_ID });
  });

  it('shows a refused binding with its reason', async () => {
    people({ bindings: [] });
    server.use(http.post('/api/v1/role-bindings', () => errorResponse(409, 'ALC-ACC-0001', 'binding.duplicate')));
    await renderRoute('/users');
    const access = await openAccess();
    await within(access).findByRole('option', { name: 'Payments (Production)' });
    await userEvent.selectOptions(within(access).getByLabelText('Service or environment'), `s:${SERVICE_ID}`);
    await userEvent.click(within(access).getByRole('button', { name: 'Add' }));
    expect(await within(access).findByRole('alert')).toBeInTheDocument();
    expectNoRawKeys(access);
  });

  it('removes a binding with a fresh step-up', async () => {
    const seen = people();
    await renderRoute('/users');
    const access = await openAccess();
    await userEvent.click(await within(access).findByRole('button', { name: 'Remove Operator on Payments' }));
    await stepUp();
    await waitFor(() => expect(seen.filter((s) => s.method === 'DELETE')).toHaveLength(2));
    expect(seen.filter((s) => s.method === 'DELETE')[1].path).toBe(ROLE_BINDING_ID);
  });

  it('explains the effective access and says when an Administrator binding is capped', async () => {
    people();
    server.use(
      http.get(`/api/v1/users/${operator.id}/access`, () =>
        HttpResponse.json({ global_role: 'operator', bindings: [roleBindingFixture()], grants: [{ role: 'admin', services: [serviceRef] }], admin_capped: true }),
      ),
    );
    await renderRoute('/users');
    const access = await openAccess();
    await userEvent.click(within(access).getByRole('button', { name: 'Explain' }));
    const explain = await within(access).findByTestId('access-explain');
    expect(await within(explain).findByText('Operator on all services')).toBeInTheDocument();
    expect(explain).toHaveTextContent('Administrator on: Payments');
    expect(within(explain).getByTestId('admin-capped')).toHaveTextContent('An Administrator role counts as Operator');
  });

  it('is Turkish in Turkish', async () => {
    people();
    server.use(...sessionHandlers({ ...adminSession, user: { ...adminSession.user, locale: 'tr' } }));
    await renderRoute('/users', { languages: ['tr'] });
    await userEvent.click(await screen.findByRole('button', { name: 'Yönet: operator' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Erişim' }));
    const access = await screen.findByTestId('user-access');
    expect(within(access).getByRole('rowheader', { name: 'Tüm hizmetler' })).toBeInTheDocument();
    const rows = await within(access).findAllByTestId('binding-row');
    expect(rows[1]).toHaveTextContent('Üretim ortamındaki her hizmet');
    expectNoRawKeys(access);
  });
});

describe('People & access: no global role', () => {
  it('creates a person without a global role', async () => {
    let body: unknown = null;
    people();
    server.use(
      http.post('/api/v1/users', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ ...operator, id: 'u-new', role: null }, { status: 201 });
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Add user' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Username/), 'deniz');
    await userEvent.type(within(dialog).getByLabelText(/Full name/), 'Deniz Kaya');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Role/), '');
    await userEvent.type(within(dialog).getByLabelText(/Initial password/), 'correct horse battery');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create user' }));
    await waitFor(() => expect(body).toMatchObject({ username: 'deniz', role: null }));
  });

  it('lists a person without a global role and removes the global role, showing the refusal for the setup account', async () => {
    let body: unknown = null;
    people({ users: [adminSession.user, { ...operator, role: null }] });
    server.use(
      http.patch('/api/v1/users/:id', async ({ request }) => {
        body = await request.json();
        return errorResponse(409, 'ALC-USR-0004', 'user.break_glass_global_role');
      }),
    );
    await renderRoute('/users');
    const row = (await screen.findByText('Olcay Öztürk')).closest('tr')!;
    expect(within(row).getByText('No role on all services')).toBeInTheDocument();
    await userEvent.click(within(row).getByRole('button', { name: 'Manage operator' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText(/^Role/)).toHaveValue('');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(body).toMatchObject({ role: null }));
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
    expectNoRawKeys(dialog);
  });
});

describe('Service page: Access', () => {
  function servicePage() {
    const seen: Seen[] = [];
    server.use(
      ...sessionHandlers(adminSession),
      http.get(`/api/v1/services/${SERVICE_ID}`, () => HttpResponse.json(serviceFixture())),
      http.get('/api/v1/services/:id/policy', () => HttpResponse.json(servicePolicyFixture())),
      http.get('/api/v1/users', () => HttpResponse.json({ items: [adminSession.user, operator] })),
      http.get('/api/v1/role-bindings', ({ request }) => {
        seen.push({ method: 'GET', path: new URL(request.url).search, body: null });
        return HttpResponse.json({ items: [roleBindingFixture(), environmentBindingFixture] });
      }),
      http.post('/api/v1/role-bindings', async ({ request }) => {
        seen.push({ method: 'POST', path: '', body: await request.json() });
        return HttpResponse.json(roleBindingFixture({ id: 'new' }), { status: 201 });
      }),
      http.delete('/api/v1/role-bindings/:id', ({ params }) => {
        seen.push({ method: 'DELETE', path: String(params.id), body: null });
        return new HttpResponse(null, { status: 204 });
      }),
    );
    return seen;
  }

  it('lists who reaches the service directly and through its environment, with the All services note', async () => {
    const seen = servicePage();
    await renderRoute(`/services/${SERVICE_ID}?tab=access`);
    const tab = await screen.findByTestId('service-access');
    expect(within(tab).getByTestId('service-access-global')).toHaveTextContent('Everyone with a role on all services');
    const direct = await within(tab).findByTestId('service-bindings');
    expect(within(direct).getAllByTestId('binding-row')).toHaveLength(1);
    expect(direct).toHaveTextContent('Olcay Öztürk');
    expect(within(tab).getByTestId('service-env-bindings')).toHaveTextContent('Every service in Production');
    expect(seen[0].path).toBe(`?service_id=${SERVICE_ID}`);
  });

  it('adds a person on the service and removes a binding', async () => {
    const seen = servicePage();
    await renderRoute(`/services/${SERVICE_ID}?tab=access`);
    const tab = await screen.findByTestId('service-access');
    await within(tab).findByRole('option', { name: 'Olcay Öztürk (operator)' });
    await userEvent.selectOptions(within(tab).getByLabelText('Person'), operator.id);
    await userEvent.selectOptions(within(tab).getByLabelText('Role'), 'admin');
    await userEvent.click(within(tab).getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(seen.find((s) => s.method === 'POST')?.body).toEqual({ user_id: operator.id, role: 'admin', service_id: SERVICE_ID }));
    await userEvent.click(within(tab).getByRole('button', { name: 'Remove Operator on Payments' }));
    await waitFor(() => expect(seen.find((s) => s.method === 'DELETE')?.path).toBe(ROLE_BINDING_ID));
  });

  it('has no Access tab for a person outside the people administration', async () => {
    servicePage();
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute(`/services/${SERVICE_ID}`);
    await screen.findByRole('tab', { name: 'Overview' });
    expect(screen.queryByRole('tab', { name: 'Access' })).not.toBeInTheDocument();
  });
});
