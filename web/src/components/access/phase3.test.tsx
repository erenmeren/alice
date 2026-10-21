import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { AutomationAccount, DirectoryGroup } from '../../api/access';
import type { User } from '../../api/types';
import { adminSession, defaultServiceFixture, environmentFixture, errorResponse, roleBindingFixture, SERVICE_ID, serviceFixture, serviceRef, sessionHandlers, userFor } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

// People & access, Phase 3 (R54): the Groups and Automation accounts tabs, a person's rights through groups and the
// tokens of an automation account. Every change asks for a fresh code: the first try of each request is refused with
// auth.stepup_required, the retry after the code passes.

const PROVIDER_ID = '0192f300-0000-7000-8000-0000000000p1';
const GROUP_ID = '0192f300-0000-7000-8000-0000000000g1';
const ROBOT_ID = '0192f300-0000-7000-8000-0000000000r1';

const groupFixture: DirectoryGroup = {
  id: GROUP_ID,
  source: 'oidc',
  provider_id: PROVIDER_ID,
  directory_id: null,
  source_name: 'Corp IdP',
  value: 'pay-ops',
  label: 'Ödeme ekibi',
  members: 3,
  bindings: 1,
  created_by: null,
  created_by_name: '',
  created_at: '2026-10-21T08:00:00Z',
};

const robotFixture: AutomationAccount = {
  id: ROBOT_ID,
  username: 'ci-deployer',
  display_name: 'CI deployer',
  description: 'Deploys the payments site',
  role: null,
  disabled: false,
  tokens: 1,
  last_used_at: null,
  created_at: '2026-10-21T08:00:00Z',
  updated_at: '2026-10-21T08:00:00Z',
};

interface Seen {
  method: string;
  path: string;
  body: unknown;
}

// stepUpOnce answers the first request of a key with a step-up refusal and every later one with answer.
function stepUpOnce(asked: Set<string>, key: string, answer: () => Response | Promise<Response>) {
  if (!asked.has(key)) {
    asked.add(key);
    return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
  }
  return answer();
}

function phase3(opts: { groups?: DirectoryGroup[]; accounts?: AutomationAccount[]; users?: User[] } = {}) {
  const seen: Seen[] = [];
  const asked = new Set<string>();
  const record = async (request: Request, path: string) => {
    const text = await request.text();
    seen.push({ method: request.method, path, body: text ? JSON.parse(text) : null });
  };
  server.use(
    ...sessionHandlers(adminSession),
    http.get('/api/v1/users', () => HttpResponse.json({ items: opts.users ?? [adminSession.user] })),
    http.get('/api/v1/services', () => HttpResponse.json({ items: [defaultServiceFixture, serviceFixture()] })),
    http.get('/api/v1/environments', () => HttpResponse.json({ items: [environmentFixture()] })),
    http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [{ id: PROVIDER_ID, name: 'Corp IdP' }] })),
    http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [] })),
    http.get('/api/v1/directory-groups', () =>
      HttpResponse.json({
        items: opts.groups ?? [groupFixture],
        seen: [
          { source: 'oidc', provider_id: PROVIDER_ID, directory_id: null, source_name: 'Corp IdP', value: 'pay-ops', users: 3, directory_group_id: GROUP_ID },
          { source: 'oidc', provider_id: PROVIDER_ID, directory_id: null, source_name: 'Corp IdP', value: 'billing', users: 2, directory_group_id: null },
        ],
      }),
    ),
    http.post('/api/v1/directory-groups', async ({ request }) => {
      await record(request, 'groups');
      return stepUpOnce(asked, 'post-group', () => HttpResponse.json({ ...groupFixture, id: 'new', value: 'billing' }, { status: 201 }));
    }),
    http.delete('/api/v1/directory-groups/:id', async ({ request, params }) => {
      await record(request, `groups/${String(params.id)}`);
      return stepUpOnce(asked, 'delete-group', () => HttpResponse.json({ bindings_removed: 1, owners_removed: 0 }));
    }),
    http.get('/api/v1/role-bindings', ({ request }) => {
      const q = new URL(request.url).searchParams;
      if (q.get('directory_group_id')) return HttpResponse.json({ items: [roleBindingFixture({ user_id: null, directory_group_id: GROUP_ID })] });
      return HttpResponse.json({ items: [] });
    }),
    http.post('/api/v1/role-bindings', async ({ request }) => {
      await record(request, 'bindings');
      return stepUpOnce(asked, 'post-binding', () => HttpResponse.json(roleBindingFixture({ id: 'new' }), { status: 201 }));
    }),
    http.get('/api/v1/automation-accounts', () => HttpResponse.json({ items: opts.accounts ?? [robotFixture] })),
    http.post('/api/v1/automation-accounts', async ({ request }) => {
      await record(request, 'automation');
      return stepUpOnce(asked, 'post-account', () => HttpResponse.json({ ...robotFixture, id: 'new' }, { status: 201 }));
    }),
    http.patch('/api/v1/automation-accounts/:id', async ({ request, params }) => {
      await record(request, `automation/${String(params.id)}`);
      return stepUpOnce(asked, 'patch-account', () => HttpResponse.json({ ...robotFixture, disabled: true, tokens: 0 }));
    }),
    http.get('/api/v1/automation-accounts/:id/tokens', () =>
      HttpResponse.json({
        items: [
          { id: 't1', user_id: ROBOT_ID, name: 'pipeline', prefix: 'alice_Pp12Qq', scope: 'operate', service_ids: [SERVICE_ID], expires_at: '2026-12-29T08:00:00Z', last_used_at: null, created_at: '2026-10-21T08:00:00Z' },
        ],
      }),
    ),
    http.post('/api/v1/automation-accounts/:id/tokens', async ({ request, params }) => {
      await record(request, `automation/${String(params.id)}/tokens`);
      return stepUpOnce(asked, 'post-token', () =>
        HttpResponse.json({ token: 'alice_ROBOT-SECRET', item: { id: 't2', user_id: ROBOT_ID, name: 'deploy', prefix: 'alice_Rr', scope: 'read', service_ids: null, expires_at: '2026-12-29T08:00:00Z', last_used_at: null, created_at: '2026-10-21T08:00:00Z' } }, { status: 201 }),
      );
    }),
    http.post('/api/v1/auth/stepup', () => HttpResponse.json({ ...adminSession, stepup_until: '2099-01-01T00:00:00Z' })),
  );
  return seen;
}

async function stepUp() {
  await userEvent.type(await screen.findByLabelText(/code/i), '123456');
  await userEvent.keyboard('{Enter}');
}

const posts = (seen: Seen[], path: string) => seen.filter((s) => s.path === path);

describe('People & access: Groups (R54)', () => {
  it('lists the declared groups with their source, members and roles', async () => {
    phase3();
    await renderRoute('/users?tab=groups');
    const row = await screen.findByTestId('group-row');
    expect(row).toHaveTextContent('Ödeme ekibi');
    expect(row).toHaveTextContent('pay-ops');
    expect(row).toHaveTextContent('Single sign-on');
    expect(row).toHaveTextContent('Corp IdP');
    expect(row).toHaveTextContent('3 people');
    expectNoRawKeys(screen.getByTestId('groups-tab'));
  });

  it('adds a group from a value seen at sign-in, with a fresh step-up', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=groups');
    await userEvent.click(await screen.findByRole('button', { name: 'Add group' }));
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByRole('option', { name: 'Corp IdP' });
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Identity provider or directory/), `o:${PROVIDER_ID}`);
    // A value already declared is not offered again.
    const offered = within(dialog).getByLabelText(/^Seen at sign-in/);
    expect(within(offered).queryByRole('option', { name: /pay-ops/ })).not.toBeInTheDocument();
    await userEvent.selectOptions(offered, 'billing');
    expect(within(dialog).getByLabelText(/^Group value/)).toHaveValue('billing');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add group' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, 'groups')).toHaveLength(2));
    expect(posts(seen, 'groups')[1].body).toEqual({ source: 'oidc', provider_id: PROVIDER_ID, value: 'billing', label: '' });
  });

  it('gives a group a role on a service', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=groups');
    await userEvent.click(await screen.findByRole('button', { name: 'Roles of Ödeme ekibi' }));
    const access = await screen.findByTestId('group-access');
    expect(await within(access).findAllByTestId('binding-row')).toHaveLength(1);
    await within(access).findByRole('option', { name: 'Payments (Production)' });
    await userEvent.selectOptions(within(access).getByLabelText('Service or environment'), `s:${SERVICE_ID}`);
    await userEvent.click(within(access).getByRole('button', { name: 'Add' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, 'bindings')).toHaveLength(2));
    expect(posts(seen, 'bindings')[1].body).toEqual({ directory_group_id: GROUP_ID, role: 'operator', service_id: SERVICE_ID });
  });

  it('removes a group and says what went with it', async () => {
    phase3();
    await renderRoute('/users?tab=groups');
    await userEvent.click(await screen.findByRole('button', { name: 'Remove Ödeme ekibi' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('its 1 role are removed');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await stepUp();
    expect(await screen.findByTestId('group-deleted')).toHaveTextContent('Role bindings removed with it: 1; owner entries: 0.');
  });

  it('adds a group of a directory with a typed value and label', async () => {
    const seen = phase3();
    server.use(http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [{ id: 'dir-1', name: 'Corp AD' }] })));
    await renderRoute('/users?tab=groups');
    await userEvent.click(await screen.findByRole('button', { name: 'Add group' }));
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByRole('option', { name: 'Corp AD' });
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Identity provider or directory/), 'l:dir-1');
    // Nothing was seen at sign-in for this directory: only the typed value.
    expect(within(dialog).queryByLabelText(/^Seen at sign-in/)).not.toBeInTheDocument();
    const submit = within(dialog).getByRole('button', { name: 'Add group' });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/^Group value/), 'CN=Pay Ops,OU=Groups');
    await userEvent.type(within(dialog).getByLabelText(/^Label/), 'Pay ops');
    await userEvent.click(submit);
    await stepUp();
    await waitFor(() => expect(posts(seen, 'groups')).toHaveLength(2));
    expect(posts(seen, 'groups')[1].body).toEqual({ source: 'ldap', directory_id: 'dir-1', value: 'CN=Pay Ops,OU=Groups', label: 'Pay ops' });
  });

  it('closes the roles and the remove dialogs without a change', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=groups');
    await userEvent.click(await screen.findByRole('button', { name: 'Roles of Ödeme ekibi' }));
    await screen.findByTestId('group-access');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Remove Ödeme ekibi' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(seen).toEqual([]);
  });

  it('is in Turkish', async () => {
    phase3();
    server.use(...sessionHandlers({ ...adminSession, user: { ...adminSession.user, locale: 'tr' } }));
    await renderRoute('/users?tab=groups', { languages: ['tr-TR'] });
    expect(await screen.findByRole('tab', { name: 'Gruplar' })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByTestId('group-row')).toHaveTextContent('Çoklu oturum açma');
    expectNoRawKeys(screen.getByTestId('groups-tab'));
  });
});

describe('People & access: Automation accounts (R54)', () => {
  it('lists the accounts and creates one without a role on all services', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=automation');
    const row = await screen.findByTestId('automation-row');
    expect(row).toHaveTextContent('CI deployer');
    expect(row).toHaveTextContent('ci-deployer');
    expect(row).toHaveTextContent('No role on all services');
    await userEvent.click(screen.getByRole('button', { name: 'Add automation account' }));
    const dialog = await screen.findByRole('dialog');
    // Never Administrator on all services.
    expect(within(within(dialog).getByLabelText(/^Role/)).getAllByRole('option').map((o) => o.textContent)).toEqual(['No role on all services', 'Operator', 'Auditor']);
    await userEvent.type(within(dialog).getByLabelText(/^Username/), 'backup-bot');
    await userEvent.type(within(dialog).getByLabelText(/^Display name/), 'Backup bot');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, 'automation')).toHaveLength(2));
    expect(posts(seen, 'automation')[1].body).toEqual({ username: 'backup-bot', display_name: 'Backup bot', description: '', role: null });
  });

  it('makes a token limited to a service and shows its secret once', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=automation');
    await userEvent.click(await screen.findByRole('button', { name: 'Tokens of ci-deployer' }));
    const tokens = await screen.findByTestId('automation-tokens');
    const row = await within(tokens).findByTestId('automation-token-row');
    await waitFor(() => expect(row).toHaveTextContent('Payments'));
    await userEvent.type(within(tokens).getByLabelText(/^Name/), 'deploy');
    await userEvent.click(await within(tokens).findByRole('checkbox', { name: 'Payments (Production)' }));
    await userEvent.click(within(tokens).getByRole('button', { name: 'Create' }));
    await stepUp();
    expect(await within(tokens).findByTestId('new-automation-token')).toHaveTextContent('alice_ROBOT-SECRET');
    expect(window.location.href).not.toContain('SECRET');
    const made = posts(seen, `automation/${ROBOT_ID}/tokens`);
    expect(made[made.length - 1].body).toEqual({ name: 'deploy', scope: 'read', expires_in_days: 90, service_ids: [SERVICE_ID] });
  });

  it('warns that disabling revokes the tokens, then disables', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=automation');
    await userEvent.click(await screen.findByRole('button', { name: 'Disable ci-deployer' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('Its 1 token is revoked for good');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, `automation/${ROBOT_ID}`)).toHaveLength(2));
    expect(posts(seen, `automation/${ROBOT_ID}`)[1].body).toEqual({ disabled: true });
  });

  it('changes an account: its display name, description and role on all services', async () => {
    const seen = phase3();
    await renderRoute('/users?tab=automation');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit ci-deployer' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit ci-deployer' });
    // The username is fixed once the account exists.
    expect(within(dialog).queryByLabelText(/^Username/)).not.toBeInTheDocument();
    const name = within(dialog).getByLabelText(/^Display name/);
    await userEvent.clear(name);
    await userEvent.type(name, 'CI');
    const description = within(dialog).getByLabelText(/^Description/);
    await userEvent.clear(description);
    await userEvent.type(description, 'Runs the pipeline');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Role/), 'auditor');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, `automation/${ROBOT_ID}`)).toHaveLength(2));
    expect(posts(seen, `automation/${ROBOT_ID}`)[1].body).toEqual({ display_name: 'CI', description: 'Runs the pipeline', role: 'auditor' });
  });

  it('enables a disabled account again; its tokens dialog makes no new token', async () => {
    const seen = phase3({ accounts: [{ ...robotFixture, disabled: true, tokens: 0, description: '', last_used_at: '2026-10-20T08:00:00Z' }] });
    await renderRoute('/users?tab=automation');
    const row = await screen.findByTestId('automation-row');
    expect(row).toHaveTextContent('Disabled');
    await userEvent.click(screen.getByRole('button', { name: 'Tokens of ci-deployer' }));
    const tokens = await screen.findByTestId('automation-tokens');
    expect(within(tokens).getByText('Disabled')).toBeInTheDocument();
    expect(within(tokens).queryByRole('button', { name: 'Create' })).not.toBeInTheDocument();
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Enable ci-deployer' }));
    const dialog = await screen.findByRole('dialog', { name: 'Enable ci-deployer?' });
    expect(dialog).toHaveTextContent('Its old tokens stay revoked.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Enable' }));
    await stepUp();
    await waitFor(() => expect(posts(seen, `automation/${ROBOT_ID}`)).toHaveLength(2));
    expect(posts(seen, `automation/${ROBOT_ID}`)[1].body).toEqual({ disabled: false });
  });

  it('revokes a token and hides the new secret once Done is pressed', async () => {
    const seen = phase3();
    server.use(
      http.delete('/api/v1/automation-accounts/:id/tokens/:token', ({ request, params }) => {
        seen.push({ method: request.method, path: `automation/${String(params.id)}/tokens/${String(params.token)}`, body: null });
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/users?tab=automation');
    await userEvent.click(await screen.findByRole('button', { name: 'Tokens of ci-deployer' }));
    const tokens = await screen.findByTestId('automation-tokens');
    await userEvent.type(await within(tokens).findByLabelText(/^Name/), 'deploy');
    await userEvent.click(within(tokens).getByRole('button', { name: 'Create' }));
    await stepUp();
    expect(await within(tokens).findByTestId('new-automation-token')).toBeInTheDocument();
    await userEvent.click(within(tokens).getByRole('button', { name: 'Done' }));
    expect(within(tokens).queryByTestId('new-automation-token')).not.toBeInTheDocument();
    await userEvent.click(within(tokens).getByRole('button', { name: 'Revoke token pipeline' }));
    await waitFor(() => expect(posts(seen, `automation/${ROBOT_ID}/tokens/t1`)).toHaveLength(1));
  });

  it("opens an account's access and says when it has no tokens", async () => {
    phase3();
    server.use(http.get('/api/v1/automation-accounts/:id/tokens', () => HttpResponse.json({ items: [] })));
    await renderRoute('/users?tab=automation');
    await userEvent.click(await screen.findByRole('button', { name: 'Access of ci-deployer' }));
    const access = await screen.findByRole('dialog');
    expect(await within(access).findByText('No role on all services')).toBeInTheDocument();
    await userEvent.click(within(access).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Tokens of ci-deployer' }));
    expect(await within(await screen.findByTestId('automation-tokens')).findByText('You have no API tokens.')).toBeInTheDocument();
  });

  it('says when there is no automation account yet', async () => {
    phase3({ accounts: [] });
    await renderRoute('/users?tab=automation');
    expect(await screen.findByTestId('automation-empty')).toBeInTheDocument();
  });
});

describe('People & access: rights through groups (R54)', () => {
  it('shows an SSO person the roles their groups give them, read-only', async () => {
    const sso: User = { ...userFor('operator'), role: null, auth_source: 'oidc', sso_provider_id: PROVIDER_ID };
    phase3({ users: [adminSession.user, sso] });
    server.use(
      http.get(`/api/v1/users/${sso.id}/access`, () =>
        HttpResponse.json({
          global_role: null,
          bindings: [],
          group_bindings: [roleBindingFixture({ id: 'g', user_id: null, directory_group_id: GROUP_ID, group: { source: 'oidc', source_name: 'Corp IdP', value: 'pay-ops', label: '' } })],
          grants: [{ role: 'operator', services: [serviceRef] }],
          admin_capped: false,
        }),
      ),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: `Manage ${sso.username}` }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Access' }));
    const rights = await screen.findByTestId('group-rights');
    expect(await within(rights).findByTestId('group-right')).toHaveTextContent('pay-ops: Operator on Payments');
    expect(within(rights).queryByRole('button')).not.toBeInTheDocument();
  });
});
