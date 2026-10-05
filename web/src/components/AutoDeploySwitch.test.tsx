import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { bindingFixture, BINDING_ID, errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { AutoDeploySwitch } from './AutoDeploySwitch';

function asRole(role: 'admin' | 'operator' | 'auditor', lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)));
}

describe('AutoDeploySwitch', () => {
  it('shows an Administrator the switch and confirms before switching on, with If-Match and the help text', async () => {
    asRole('admin');
    let body: unknown = null;
    let ifMatch: string | null = null;
    server.use(
      http.put(`/api/v1/bindings/${BINDING_ID}/auto-deploy`, async ({ request }) => {
        body = await request.json();
        ifMatch = request.headers.get('If-Match');
        return HttpResponse.json(bindingFixture({ auto_deploy: true }));
      }),
    );
    const onChanged = vi.fn();
    const user = userEvent.setup();
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture()} admin exportable onChanged={onChanged} />);
    await user.click(screen.getByRole('switch', { name: /Automatic deployment/ }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('When Key Vault renews this certificate, Alice deploys the new version to these websites.');
    expect(dialog).toHaveTextContent('Only versions found after you switch it on are deployed by themselves.');
    expect(body).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Switch on' }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(body).toEqual({ enabled: true });
    expect(ifMatch).toBe('"2"');
  });

  it('switches off at once, without a dialog', async () => {
    asRole('admin');
    let body: unknown = null;
    server.use(http.put(`/api/v1/bindings/${BINDING_ID}/auto-deploy`, async ({ request }) => { body = await request.json(); return HttpResponse.json(bindingFixture()); }));
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture({ auto_deploy: true, auto_since: '2026-10-04T08:00:00Z' })} admin exportable onChanged={vi.fn()} />);
    expect(screen.getByText(/^On since/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('switch', { name: /Automatic deployment/ }));
    await waitFor(() => expect(body).toEqual({ enabled: false }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('asks for step-up and sends the same request again', async () => {
    asRole('admin');
    let calls = 0;
    server.use(
      http.put(`/api/v1/bindings/${BINDING_ID}/auto-deploy`, () => (++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(bindingFixture({ auto_deploy: true })))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const onChanged = vi.fn();
    const user = userEvent.setup();
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture()} admin exportable onChanged={onChanged} />);
    await user.click(screen.getByRole('switch'));
    await user.click(screen.getByRole('button', { name: 'Switch on' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(calls).toBe(2));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it('shows a refusal (the license is locked) in the dialog and stays', async () => {
    asRole('admin');
    server.use(http.put(`/api/v1/bindings/${BINDING_ID}/auto-deploy`, () => errorResponse(422, 'ALC-AKV-0013', 'kv.not_exportable')));
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture()} admin exportable onChanged={vi.fn()} />);
    await userEvent.click(screen.getByRole('switch'));
    await userEvent.click(screen.getByRole('button', { name: 'Switch on' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Private key not exportable');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('cannot be switched on for a key that is not exportable', async () => {
    asRole('admin');
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture()} admin exportable={false} onChanged={vi.fn()} />);
    expect(screen.getByRole('switch')).toBeDisabled();
  });

  it('shows everybody else the state read-only and who can change it', async () => {
    for (const role of ['operator', 'auditor'] as const) {
      asRole(role);
      const view = await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture({ auto_deploy: true })} admin={false} exportable onChanged={vi.fn()} />);
      expect(screen.queryByRole('switch')).not.toBeInTheDocument();
      expect(screen.getByTestId('auto-deploy-state')).toHaveTextContent('On');
      expect(screen.getByText('Only an administrator can change this.')).toBeInTheDocument();
      view.unmount();
    }
  });

  it('is complete in Turkish', async () => {
    asRole('admin', 'tr');
    await renderWithStepUp(<AutoDeploySwitch binding={bindingFixture()} admin exportable onChanged={vi.fn()} />, ['tr-TR']);
    await userEvent.click(screen.getByRole('switch', { name: /Otomatik dağıtım/ }));
    expect(await screen.findByText('Otomatik dağıtım açılsın mı?')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Aç' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
