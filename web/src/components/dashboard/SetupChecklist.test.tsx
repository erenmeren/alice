import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ChecklistItem } from '../../api/types';
import { adminSession, emptyDashboardSummary, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const ITEMS: ChecklistItem[] = [
  { item: 'passphrase', done: true, required: true },
  { item: 'https', done: false, required: true },
  { item: 'mail', done: false, required: false },
  { item: 'license', done: false, required: false },
  { item: 'target', done: false, required: false },
];
const withChecklist = (items: ChecklistItem[] | null | undefined) =>
  http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ ...emptyDashboardSummary, setup_checklist: items }));

describe('SetupChecklist', () => {
  it('lists the items, marks the required ones and the finished ones, and links each to its page', async () => {
    server.use(...sessionHandlers(adminSession), withChecklist(ITEMS));
    await renderRoute('/');
    const list = await screen.findByTestId('setup-checklist');
    expect(within(list).getByRole('heading', { name: 'Finish setting up' })).toBeInTheDocument();
    const link = (name: string) => within(list).getByRole('link', { name: new RegExp(`^${name}`) });
    expect(link('Set the recovery passphrase')).toHaveAttribute('href', '/setup');
    expect(link('Install your HTTPS certificate')).toHaveAttribute('href', '/settings?tab=https');
    expect(link('Set up the mail server')).toHaveAttribute('href', '/settings?tab=mail');
    expect(link('Add a license')).toHaveAttribute('href', '/license');
    expect(link('Add your first server')).toHaveAttribute('href', '/servers');

    const https = link('Install your HTTPS certificate').closest('li') as HTMLElement;
    expect(within(https).getByText('Required')).toBeInTheDocument();
    const mail = link('Set up the mail server').closest('li') as HTMLElement;
    expect(within(mail).queryByText('Required')).not.toBeInTheDocument();
    const passphrase = link('Set the recovery passphrase').closest('li') as HTMLElement;
    expect(within(passphrase).getByText('Done')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('is gone when everything is done, or when the summary has no checklist', async () => {
    server.use(...sessionHandlers(adminSession), withChecklist(ITEMS.map((i) => ({ ...i, done: true }))));
    const first = await renderRoute('/');
    await screen.findByText('Nothing expires within 30 days.');
    expect(screen.queryByTestId('setup-checklist')).not.toBeInTheDocument();
    first.unmount();

    server.use(withChecklist(null));
    await renderRoute('/');
    await screen.findByText('Nothing expires within 30 days.');
    expect(screen.queryByTestId('setup-checklist')).not.toBeInTheDocument();
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), withChecklist(ITEMS));
    await renderRoute('/', { languages: ['tr-TR'] });
    const list = await screen.findByTestId('setup-checklist');
    expect(within(list).getByRole('heading', { name: 'Kurulumu tamamlayın' })).toBeInTheDocument();
    expect(within(list).getAllByText('Gerekli')).toHaveLength(1);
    expectNoRawKeys();
  });
});
