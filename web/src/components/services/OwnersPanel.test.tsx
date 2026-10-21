import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { DirectoryGroup } from '../../api/access';
import type { ServiceOwner, ServiceOwners } from '../../api/services';
import type { SessionInfo, User } from '../../api/types';
import { errorResponse, globalSession, SERVICE_ID, serviceFixture, sessionHandlers, scopedSession, userFor } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

// The owner team on a service's Overview (R56, design §7.1, §9): people and directory groups who receive the service's
// e-mails, the warning for an owner without a role on the service, and the editor of a global Administrator, whose save
// asks for a fresh code and sends the service's version with the whole list.

const GROUP_ID = '0192f300-0000-7000-8000-0000000000g1';
const PROVIDER_ID = '0192f300-0000-7000-8000-0000000000p1';
const operator: User = { ...userFor('operator'), display_name: 'Olcay Öztürk' };
const auditor: User = { ...userFor('auditor'), id: '00000000-0000-7000-8000-0000000000a7', username: 'aylin', display_name: 'Aylin Aksoy' };

const personOwner = (o: Partial<ServiceOwner> = {}): ServiceOwner => ({
  id: 'o1',
  kind: 'person',
  user_id: operator.id,
  username: operator.username,
  display_name: operator.display_name,
  disabled: false,
  receives_email: true,
  directory_group_id: null,
  members: 0,
  reaches_service: true,
  created_at: '2026-10-21T08:00:00Z',
  ...o,
});

const groupOwner = (o: Partial<ServiceOwner> = {}): ServiceOwner => ({
  id: 'o2',
  kind: 'group',
  user_id: null,
  disabled: false,
  receives_email: false,
  directory_group_id: GROUP_ID,
  group: { source: 'oidc', source_name: 'Corp IdP', value: 'pay-ops', label: 'Payments team' },
  members: 3,
  reaches_service: false,
  created_at: '2026-10-21T08:00:00Z',
  ...o,
});

const groupFixture: DirectoryGroup = {
  id: GROUP_ID,
  source: 'oidc',
  provider_id: PROVIDER_ID,
  directory_id: null,
  source_name: 'Corp IdP',
  value: 'pay-ops',
  label: 'Payments team',
  members: 3,
  bindings: 0,
  created_by: null,
  created_by_name: '',
  created_at: '2026-10-21T08:00:00Z',
};

interface World {
  session?: SessionInfo;
  owners?: ServiceOwners;
  // put answers each PUT after the first, which always asks for a fresh code.
  put?: (body: unknown, n: number, replace: (next: ServiceOwners) => void) => Response;
}

function ownersWorld({ session = globalSession('admin'), owners = { version: 4, items: [] }, put }: World = {}) {
  const puts: unknown[] = [];
  let current = owners;
  server.use(
    ...sessionHandlers(session),
    http.get(`/api/v1/services/${SERVICE_ID}`, () => HttpResponse.json(serviceFixture({ version: current.version }))),
    http.get(`/api/v1/services/${SERVICE_ID}/owners`, () => HttpResponse.json(current)),
    http.get('/api/v1/users', () => HttpResponse.json({ items: [session.user, operator, auditor] })),
    http.get('/api/v1/directory-groups', () => HttpResponse.json({ items: [groupFixture], seen: [] })),
    http.put(`/api/v1/services/${SERVICE_ID}/owners`, async ({ request }) => {
      const body = await request.json();
      puts.push(body);
      if (puts.length === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
      if (put)
        return put(body, puts.length, (next) => {
          current = next;
        });
      current = { version: current.version + 1, items: [personOwner({ user_id: auditor.id, username: auditor.username, display_name: auditor.display_name })] };
      return HttpResponse.json(current);
    }),
    http.post('/api/v1/auth/stepup', () => HttpResponse.json({ ...session, stepup_until: '2099-01-01T00:00:00Z' })),
  );
  return { puts };
}

async function stepUp() {
  await userEvent.type(await screen.findByLabelText(/code/i), '123456');
  await userEvent.keyboard('{Enter}');
}

describe('OwnersPanel', () => {
  it('lists people and groups with their notes and the warning for owners who cannot open the service', async () => {
    ownersWorld({
      owners: {
        version: 4,
        items: [
          personOwner(),
          personOwner({ id: 'o3', user_id: auditor.id, username: 'aylin', display_name: 'Aylin Aksoy', receives_email: false, reaches_service: false }),
          personOwner({ id: 'o4', user_id: 'u-off', username: 'eski', display_name: 'Eski Çalışan', disabled: true, receives_email: false }),
          groupOwner(),
        ],
      },
    });
    await renderRoute(`/services/${SERVICE_ID}`);
    const table = await screen.findByTestId('service-owners-table');
    const rows = within(table).getAllByTestId('owner-row');
    expect(rows).toHaveLength(4);
    expect(rows[0]).toHaveTextContent('Olcay Öztürk');
    expect(rows[0]).toHaveTextContent('operator');
    expect(within(rows[0]).queryByTestId('owner-no-reach')).not.toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('No e-mail address');
    expect(within(rows[1]).getByTestId('owner-no-reach')).toHaveTextContent('Receives e-mails but cannot open this service');
    expect(rows[2]).toHaveTextContent('Disabled');
    expect(rows[2]).not.toHaveTextContent('No e-mail address');
    expect(rows[3]).toHaveTextContent('Payments team');
    expect(rows[3]).toHaveTextContent('Single sign-on · Corp IdP');
    expect(rows[3]).toHaveTextContent('3 members seen at sign-in');
    expect(within(rows[3]).getByTestId('owner-no-reach')).toHaveTextContent('Its members get no access to this service through it');
    expect(screen.getByRole('button', { name: 'Edit owners' })).toBeInTheDocument();
    expectNoRawKeys(screen.getByTestId('service-owners'));
  });

  it('says where the e-mails go when the service has no owner', async () => {
    ownersWorld();
    await renderRoute(`/services/${SERVICE_ID}`);
    expect(await screen.findByTestId('service-owners-empty')).toHaveTextContent("No owners yet. This service's e-mails go to the Administrators and to the extra addresses of its policy.");
  });

  it('shows no warning when the answer leaves out whether owners reach the service, and no editor without services.manage', async () => {
    ownersWorld({ session: scopedSession(['admin']), owners: { version: 4, items: [personOwner({ reaches_service: undefined })] } });
    await renderRoute(`/services/${SERVICE_ID}`);
    const table = await screen.findByTestId('service-owners-table');
    expect(table).toHaveTextContent('Olcay Öztürk');
    expect(within(table).queryByTestId('owner-no-reach')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit owners' })).not.toBeInTheDocument();
  });

  it('lets a global Administrator add a person and a group, remove one, and save the list with the version read after a fresh code', async () => {
    const world = ownersWorld({ owners: { version: 4, items: [personOwner()] } });
    await renderRoute(`/services/${SERVICE_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Edit owners' }));
    const dialog = await screen.findByRole('dialog', { name: 'Owners of Payments' });
    // A person already an owner is not offered again.
    await within(dialog).findByRole('option', { name: 'Aylin Aksoy (aylin)' });
    expect(within(dialog).queryByRole('option', { name: /Olcay Öztürk/ })).not.toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText('Person'), auditor.id);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add person' }));
    await within(dialog).findByRole('option', { name: 'Payments team (Single sign-on · Corp IdP)' });
    await userEvent.selectOptions(within(dialog).getByLabelText('Directory group'), GROUP_ID);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add group' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove Olcay Öztürk' }));
    expect(within(within(dialog).getByTestId('owners-draft')).getAllByTestId('owner-row')).toHaveLength(2);
    await userEvent.click(within(dialog).getByTestId('owners-save'));
    await stepUp();
    await waitFor(() => expect(world.puts).toHaveLength(2));
    expect(world.puts[1]).toEqual({ version: 4, owners: [{ user_id: auditor.id }, { directory_group_id: GROUP_ID }] });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Owners of Payments' })).not.toBeInTheDocument());
    expect(await screen.findByTestId('service-owners-table')).toHaveTextContent('Aylin Aksoy');
  });

  it('saves an empty list', async () => {
    const world = ownersWorld({ owners: { version: 2, items: [personOwner()] } });
    await renderRoute(`/services/${SERVICE_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Edit owners' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove Olcay Öztürk' }));
    expect(within(dialog).getByTestId('owners-draft-empty')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByTestId('owners-save'));
    await stepUp();
    await waitFor(() => expect(world.puts).toHaveLength(2));
    expect(world.puts[1]).toEqual({ version: 2, owners: [] });
  });

  it('shows the refusal of a stale version and reloads the owners, then saves with the new version', async () => {
    const world = ownersWorld({
      owners: { version: 4, items: [personOwner()] },
      put: (_body, n, replace) => {
        if (n === 2) {
          replace({ version: 5, items: [personOwner(), groupOwner()] });
          return errorResponse(409, 'ALC-SVC-0010', 'service.version_conflict');
        }
        return HttpResponse.json({ version: 6, items: [] });
      },
    });
    await renderRoute(`/services/${SERVICE_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Edit owners' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByTestId('owners-save'));
    await stepUp();
    expect(await within(dialog).findByText('The policy or the owners changed since you opened them.')).toBeInTheDocument();
    expect(await within(dialog).findByTestId('owners-reloaded')).toBeInTheDocument();
    expect(within(within(dialog).getByTestId('owners-draft')).getAllByTestId('owner-row')).toHaveLength(2);
    expect(within(dialog).getByTestId('owners-draft')).toHaveTextContent('Payments team');
    await userEvent.click(within(dialog).getByTestId('owners-save'));
    await waitFor(() => expect(world.puts).toHaveLength(3));
    expect(world.puts[2]).toEqual({ version: 5, owners: [{ user_id: operator.id }, { directory_group_id: GROUP_ID }] });
  });

  it('shows the refusal of an automation account', async () => {
    ownersWorld({
      owners: { version: 4, items: [personOwner()] },
      put: () => errorResponse(422, 'ALC-SVC-0019', 'service.owner_not_a_person', { details: [{ field: 'owners.0.user_id', code: 'invalid' }] }),
    });
    await renderRoute(`/services/${SERVICE_ID}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Edit owners' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByTestId('owners-save'));
    await stepUp();
    expect(await within(dialog).findByText('An automation account cannot own a service.')).toBeInTheDocument();
  });

  it('is in Turkish', async () => {
    ownersWorld({ session: globalSession('admin', 'tr'), owners: { version: 4, items: [personOwner({ reaches_service: false }), groupOwner()] } });
    await renderRoute(`/services/${SERVICE_ID}`, { languages: ['tr-TR'] });
    const panel = await screen.findByTestId('service-owners');
    await within(panel).findByTestId('service-owners-table');
    expect(within(panel).getByRole('heading', { name: 'Sorumlular' })).toBeInTheDocument();
    expect(panel).toHaveTextContent('E-postaları alır ama bu hizmeti açamaz');
    expect(panel).toHaveTextContent('Oturum açarken görülen 3 üye');
    await userEvent.click(within(panel).getByRole('button', { name: 'Sorumluları düzenle' }));
    const dialog = await screen.findByRole('dialog');
    expectNoRawKeys(dialog);
    expectNoRawKeys(panel);
  });
});
