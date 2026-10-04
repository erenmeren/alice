import { useQuery } from '@tanstack/react-query';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { listLocations } from '../api/endpoints';
import { locationsKey } from '../api/queryKeys';
import type { CertificateLocation } from '../api/types';
import { errorResponse, locationFixture, targetFixture } from '../test/fixtures';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { LocationSettingsDialog } from './LocationSettingsDialog';

const LID = '0192c000-0000-7000-8000-0000000000e1';

// Harness: the dialog gets its location from the list, as the websites panel does.
function Harness({ canEdit = true }: { canEdit?: boolean }) {
  const list = useQuery({ queryKey: locationsKey(targetFixture.id), queryFn: () => listLocations(targetFixture.id) });
  const loc = list.data?.items.find((l) => l.id === LID);
  if (!loc) return null;
  return <LocationSettingsDialog location={loc} site="www.example.test" canEdit={canEdit} onClose={() => {}} />;
}

function listServer(initial: CertificateLocation) {
  let current = initial;
  server.use(http.get(`/api/v1/targets/${targetFixture.id}/certificate-locations`, () => HttpResponse.json({ items: [current], truncated: false })));
  return { set: (l: CertificateLocation) => (current = l) };
}

describe('LocationSettingsDialog', () => {
  it('sends only the changed fields with the version as If-Match, and tells that it saved', async () => {
    const list = listServer(locationFixture({ id: LID, version: 3, verify_port: 8443, verify_sni: 'lb.example.test' }));
    let headers: Headers | null = null;
    let body: unknown = null;
    server.use(
      http.patch(`/api/v1/locations/${LID}`, async ({ request }) => {
        headers = request.headers;
        body = await request.json();
        list.set(locationFixture({ id: LID, version: 4, verify_port: 9443, verify_sni: 'lb.example.test' }));
        return HttpResponse.json(locationFixture({ id: LID, version: 4, verify_port: 9443 }));
      }),
    );
    await renderApp(<Harness />);
    const port = await screen.findByLabelText('Port to check (empty: the port from the configuration)');
    expect(port).toHaveValue('8443');
    expect(screen.getByLabelText('Name to check (empty: from the configuration)')).toHaveValue('lb.example.test');
    await userEvent.clear(port);
    await userEvent.type(port, '9443');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Settings saved.')).toBeInTheDocument();
    expect(headers!.get('If-Match')).toBe('"3"');
    expect(body).toEqual({ verify_port: 9443 });
  });

  it('clears the port and the name with an empty field (0 and "")', async () => {
    listServer(locationFixture({ id: LID, version: 2, verify_port: 8443, verify_sni: 'lb.example.test' }));
    let body: unknown = null;
    server.use(http.patch(`/api/v1/locations/${LID}`, async ({ request }) => ((body = await request.json()), HttpResponse.json(locationFixture({ id: LID })))));
    await renderApp(<Harness />);
    await userEvent.clear(await screen.findByLabelText(/Port to check/));
    await userEvent.clear(screen.getByLabelText(/Name to check/));
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(body).toEqual({ verify_port: 0, verify_sni: '' }));
  });

  it('shows the warning of the skip switch and sends skip_verify', async () => {
    listServer(locationFixture({ id: LID }));
    let body: unknown = null;
    server.use(http.patch(`/api/v1/locations/${LID}`, async ({ request }) => ((body = await request.json()), HttpResponse.json(locationFixture({ id: LID })))));
    await renderApp(<Harness />);
    expect(await screen.findByText('Not recommended: a wrong certificate would not be noticed or restored automatically.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Skip the check for this website' }));
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(body).toEqual({ skip_verify: true }));
  });

  it('refuses an IP address, a wildcard, a bad name and a bad port before sending anything', async () => {
    listServer(locationFixture({ id: LID }));
    let sent = 0;
    server.use(http.patch(`/api/v1/locations/${LID}`, () => ((sent += 1), HttpResponse.json(locationFixture({ id: LID })))));
    await renderApp(<Harness />);
    const sni = await screen.findByLabelText(/Name to check/);
    const save = screen.getByRole('button', { name: 'Save' });
    for (const [value, message] of [
      ['203.0.113.7', 'Enter a domain name, not an IP address.'],
      ['2001:db8::1', 'Enter a domain name, not an IP address.'],
      ['*.example.test', 'Enter one domain name without a wildcard (*).'],
      ['-bad.example.test', /letters, digits, dots and hyphens only/],
      ['bad..example.test', /letters, digits, dots and hyphens only/],
      ['sp ace.example.test', /letters, digits, dots and hyphens only/],
    ] as const) {
      await userEvent.clear(sni);
      await userEvent.type(sni, value);
      await userEvent.click(save);
      expect(await screen.findByText(message)).toBeInTheDocument();
    }
    await userEvent.clear(sni);
    await userEvent.type(await screen.findByLabelText(/Port to check/), '70000');
    await userEvent.click(save);
    expect(await screen.findByText('Enter a port from 1 to 65535, or leave the field empty.')).toBeInTheDocument();
    expect(sent).toBe(0);
  });

  it('accepts a name in capitals, as the server folds it', async () => {
    listServer(locationFixture({ id: LID }));
    let body: unknown = null;
    server.use(http.patch(`/api/v1/locations/${LID}`, async ({ request }) => ((body = await request.json()), HttpResponse.json(locationFixture({ id: LID })))));
    await renderApp(<Harness />);
    await userEvent.type(await screen.findByLabelText(/Name to check/), ' WWW.Example.test ');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(body).toEqual({ verify_sni: 'WWW.Example.test' }));
  });

  it('keeps the form as typed after a server error', async () => {
    listServer(locationFixture({ id: LID }));
    server.use(http.patch(`/api/v1/locations/${LID}`, () => errorResponse(403, 'ALC-AUTH-0004', 'auth.forbidden')));
    await renderApp(<Harness />);
    const port = await screen.findByLabelText(/Port to check/);
    await userEvent.type(port, '8443');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(port).toHaveValue('8443');
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
    expect(screen.queryByText('Settings saved.')).not.toBeInTheDocument();
  });

  it('reloads the current values after a 412 and says the change was not saved', async () => {
    const list = listServer(locationFixture({ id: LID, version: 3, verify_port: null }));
    server.use(
      http.patch(`/api/v1/locations/${LID}`, () => {
        // Somebody else saved first.
        list.set(locationFixture({ id: LID, version: 4, verify_port: 9000 }));
        return errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed');
      }),
    );
    await renderApp(<Harness />);
    const port = await screen.findByLabelText(/Port to check/);
    await userEvent.type(port, '8443');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Your change was not saved because this website changed in the meantime/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Someone changed this item while you were editing it.');
    await waitFor(() => expect(screen.getByLabelText(/Port to check/)).toHaveValue('9000'));
  });

  it('is read-only for someone who cannot change it', async () => {
    listServer(locationFixture({ id: LID, verify_port: 8443 }));
    await renderApp(<Harness canEdit={false} />);
    expect(await screen.findByText('Only an administrator can change these settings.')).toBeInTheDocument();
    expect(screen.getByLabelText(/Port to check/)).toBeDisabled();
    expect(screen.getByLabelText(/Port to check/)).toHaveValue('8443');
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Close' })).toHaveLength(2);
  });
});
