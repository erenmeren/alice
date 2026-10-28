import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import type { Target } from '../api/types';
import { setCCSPassword } from '../api/endpoints';
import { formatDateTime } from '../datetime';
import { errorResponse, sessionFor, sessionHandlers, windowsCCSTargetFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { CCSPasswordPanel } from './CCSPasswordPanel';

// The endpoint is counted, not replaced: two submits in one tick must send one request (W5-12b, R70).
vi.mock('../api/endpoints', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../api/endpoints')>();
  return { ...mod, setCCSPassword: vi.fn(mod.setCCSPassword) };
});

const SET_AT = '2026-10-27T09:30:00Z';
const PUT_URL = `/api/v1/targets/${windowsCCSTargetFixture.id}/ccs-password`;
// The password is built at run time (never a literal a secret scanner flags).
const secret = (n: number) => Array.from({ length: n }, (_, i) => String.fromCharCode(0x41 + (i % 26))).join('');

interface Seen {
  url: string;
  body: string;
}

// onPut answers the PUT with the target and records every request the page sends, with its body.
function onPut(answers: (() => Response)[] = []) {
  const puts: { body: unknown; ifMatch: string | null }[] = [];
  const seen: Seen[] = [];
  server.use(
    ...sessionHandlers(sessionFor('admin')),
    http.put(PUT_URL, async ({ request }) => {
      puts.push({ body: await request.json(), ifMatch: request.headers.get('If-Match') });
      const next = answers[puts.length - 1];
      return next ? next() : HttpResponse.json({ ...windowsCCSTargetFixture, ccs_password_set_at: SET_AT, version: windowsCCSTargetFixture.version + 1 });
    }),
    http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
  );
  server.events.on('request:start', async ({ request }) => {
    seen.push({ url: request.url, body: await request.clone().text() });
  });
  return { puts, seen };
}

afterEach(() => server.events.removeAllListeners());

const field = () => screen.getByLabelText(/^CCS password/);

describe('CCSPasswordPanel', () => {
  it('says "Not set" before and the date after, with an empty field', async () => {
    const { puts } = onPut();
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    expect(screen.getByText('Not set')).toBeInTheDocument();
    expect(screen.getByText(/Centralized Certificate Store/, { selector: 'p' })).toHaveTextContent(/sealed on the Alice server/);
    await user.type(field(), secret(20));
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(await screen.findByText(formatDateTime(SET_AT, 'en-US'))).toBeInTheDocument();
    expect(screen.queryByText('Not set')).not.toBeInTheDocument();
    expect(field()).toHaveValue('');
    expect(screen.getByRole('status')).toHaveTextContent('Choose Discover');
    expect(screen.getByRole('button', { name: 'Replace password' })).toBeInTheDocument();
  });

  it('refuses 11 characters before sending, with the server\'s text, and keeps nothing', async () => {
    const { puts } = onPut();
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    await user.type(field(), secret(11));
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByText(commonEn.errors.windows.ccs_password_invalid.cause)).toBeInTheDocument();
    expect(field()).toHaveValue('');
    expect(field()).toHaveAccessibleDescription(expect.stringContaining(commonEn.errors.windows.ccs_password_invalid.cause));
    expect(puts).toHaveLength(0);
    // A space is outside the alphabet too.
    await user.type(field(), `${secret(10)} ${secret(5)}`);
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    expect(puts).toHaveLength(0);
  });

  it('asks for step-up when the server answers it and sends the same request again', async () => {
    const { puts } = onPut([() => errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')]);
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    const pw = secret(16);
    await user.type(field(), pw);
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(puts).toHaveLength(2));
    expect(puts[1]).toEqual(puts[0]);
    expect(await screen.findByText(formatDateTime(SET_AT, 'en-US'))).toBeInTheDocument();
  });

  it('sends the value in the request body only, with the version, and in no other request', async () => {
    const { puts, seen } = onPut();
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    const pw = secret(24);
    await user.type(field(), pw);
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    await screen.findByText(formatDateTime(SET_AT, 'en-US'));
    expect(puts).toEqual([{ body: { password: pw }, ifMatch: `"${windowsCCSTargetFixture.version}"` }]);
    const carrying = seen.filter((r) => r.url.includes(pw) || r.body.includes(pw));
    expect(carrying.map((r) => new URL(r.url).pathname)).toEqual([PUT_URL]);
    expect(document.body.innerHTML).not.toContain(pw);
  });

  it('sends one request when the form is submitted twice in the same tick (W5-12b, R70)', async () => {
    const { puts } = onPut();
    vi.mocked(setCCSPassword).mockClear();
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    await user.type(field(), secret(20));
    const form = field().closest('form');
    if (!form) throw new Error('no form');
    // One act: the second submit runs before React renders the first's busy state (Enter and a click in one turn).
    act(() => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
    expect(setCCSPassword).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(formatDateTime(SET_AT, 'en-US'))).toBeInTheDocument();
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(field()).toHaveValue('');
  });

  it('shows the server\'s refusal and an empty field', async () => {
    onPut([() => errorResponse(422, 'ALC-WIN-0019', 'windows.ccs_password_invalid')]);
    const user = userEvent.setup();
    await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />);
    await user.type(field(), secret(14));
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(commonEn.errors.windows.ccs_password_invalid.title);
    expect(field()).toHaveValue('');
    expect(screen.getByText('Not set')).toBeInTheDocument();
  });

  it('shows the state without a field to a person who cannot manage credentials', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    const target: Target = { ...windowsCCSTargetFixture, ccs_password_set_at: SET_AT };
    await renderWithStepUp(<CCSPasswordPanel target={target} canSet={false} />);
    expect(screen.getByText(formatDateTime(SET_AT, 'en-US'))).toBeInTheDocument();
    expect(screen.queryByLabelText(/^CCS password/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /password/ })).not.toBeInTheDocument();
  });

  it('is worded in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    const view = await renderWithStepUp(<CCSPasswordPanel target={windowsCCSTargetFixture} canSet />, ['tr-TR']);
    expect(screen.getByText('Ayarlanmadı')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Parolayı ayarla' })).toBeInTheDocument();
    expectNoRawKeys(view.container);
  });
});
