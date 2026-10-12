import { readFileSync } from 'node:fs';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { Table } from '@mantine/core';
import { renderApp } from '../../test/render';
import { AttentionItem, CursorFooter, DialogActions, EmptyState, FactList, LinkTabs, MetricStrip, Notice, OperationTimeline, PageHeader, Panel, ResourceTable, StatusBadge } from '.';

const css = readFileSync('src/components/ui/ui.module.css', 'utf8');

describe('PageHeader', () => {
  it('is the page’s only level-1 heading, with eyebrow, description, actions and a back link', async () => {
    await renderApp(<MemoryRouter><PageHeader title="Certificates" eyebrow="Monday" description="Every certificate." actions={<button>Export</button>} back={{ to: '/certificates', label: 'All certificates' }} /></MemoryRouter>);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 1, name: 'Certificates' })).toBeVisible();
    expect(screen.getByText('Monday')).toBeVisible();
    expect(screen.getByRole('link', { name: 'All certificates' })).toHaveAttribute('href', '/certificates');
    expect(screen.getByRole('button', { name: 'Export' })).toBeVisible();
  });
});

describe('Panel', () => {
  it('heads its content with a level-2 title and is a region only when named', async () => {
    const { unmount } = await renderApp(<Panel title="Validity">body</Panel>);
    expect(screen.getByRole('heading', { level: 2, name: 'Validity' })).toBeVisible();
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
    // renderApp's rerender would drop the providers: render the named variant afresh.
    unmount();
    await renderApp(<Panel title="Validity" aria-label="Validity" headingOrder={3}>body</Panel>);
    expect(screen.getByRole('region', { name: 'Validity' })).toBeVisible();
    expect(screen.getByRole('heading', { level: 3 })).toBeVisible();
  });
});

describe('ResourceTable', () => {
  it('keeps the table name, its test id, the focusable scroll region and the toolbar and footer slots', async () => {
    await renderApp(
      <ResourceTable label="Certificate inventory" testId="certificates-table" toolbar={<input aria-label="Search" />} footer={<span>2 shown</span>}>
        <Table.Thead><Table.Tr><Table.Th>Name</Table.Th></Table.Tr></Table.Thead>
        <Table.Tbody><Table.Tr><Table.Td>a</Table.Td></Table.Tr></Table.Tbody>
      </ResourceTable>,
    );
    const table = screen.getByRole('table', { name: 'Certificate inventory' });
    expect(table).toHaveAttribute('data-testid', 'certificates-table');
    expect(within(table).getAllByRole('row')).toHaveLength(2);
    expect(screen.getByRole('group', { name: 'Table, scrolls sideways' })).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('textbox', { name: 'Search' })).toBeVisible();
    expect(screen.getByText('2 shown')).toBeVisible();
  });
});

describe('CursorFooter', () => {
  it('states how many rows are shown, never a total, and offers Load more only while the server has more', async () => {
    const more = vi.fn();
    const { unmount } = await renderApp(<CursorFooter shown={50} hasMore loading={false} onMore={more} moreLabel="Load more" />);
    expect(screen.getByText('50 shown')).toBeVisible();
    expect(screen.queryByText(/ of /)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(more).toHaveBeenCalledOnce();
    unmount();
    await renderApp(<CursorFooter shown={51} hasMore={false} loading={false} onMore={more} moreLabel="Load more" />);
    expect(screen.getByText('51 shown')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });
});

describe('StatusBadge', () => {
  it('is a Mantine badge (rotation e2e reads .mantine-Badge-root) with text, tone and passed-through attributes', async () => {
    const { container } = await renderApp(<StatusBadge tone="danger" icon="Fingerprint" data-status="host_key_changed" testId="target-status">Identity changed</StatusBadge>);
    const badge = container.querySelector('.mantine-Badge-root')!;
    expect(badge).toHaveTextContent('Identity changed');
    expect(badge).toHaveAttribute('data-tone', 'danger');
    expect(badge).toHaveAttribute('data-status', 'host_key_changed');
    expect(screen.getByTestId('target-status')).toBe(badge);
  });
});

describe('FactList', () => {
  it('is a description list whose values break long tokens such as fingerprints', async () => {
    await renderApp(<FactList label="Certificate details" facts={[{ label: 'SHA-256', value: 'AB:CD', testId: 'fp' }]} />);
    expect(screen.getByRole('term')).toHaveTextContent('SHA-256');
    expect(screen.getByRole('definition')).toHaveTextContent('AB:CD');
    expect(screen.getByTestId('fp').tagName).toBe('DD');
    expect(css).toMatch(/\.factValue\s*\{[^}]*overflow-wrap:\s*anywhere/);
  });
});

describe('OperationTimeline', () => {
  it('is a named ordered list whose steps carry their state in text and the caller’s data attributes', async () => {
    await renderApp(<OperationTimeline label="Steps" steps={[
      { id: 'backup', title: 'Back up current files', state: 'done', stateLabel: 'Done', dataAttrs: { 'data-step': 'backup', 'data-status': 'ok' } },
      { id: 'reload', title: 'Reload Nginx', state: 'notRun', stateLabel: 'Not run' },
    ]} />);
    const list = screen.getByRole('list', { name: 'Steps' });
    const items = within(list).getAllByRole('listitem');
    expect(items[0]).toHaveAttribute('data-step', 'backup');
    expect(items[0].querySelector('[data-role="step-status"]')).toHaveTextContent('Done');
    expect(items[1]).toHaveTextContent('Not run');
  });
});

describe('AttentionItem', () => {
  it('links to where the condition is handled, with the name as its own text', async () => {
    await renderApp(<MemoryRouter><AttentionItem tone="danger" icon="Fingerprint" title="Server identity changed" detail={<code>seed-web-3</code>} to="/servers/1" /></MemoryRouter>);
    const link = screen.getByRole('link', { name: /Server identity changed/ });
    expect(link).toHaveAttribute('href', '/servers/1');
    expect(screen.getByText('seed-web-3', { exact: true })).toBeVisible();
  });
});

describe('EmptyState, Notice, MetricStrip, LinkTabs, DialogActions', () => {
  it('render their parts with the roles the pages rely on', async () => {
    await renderApp(
      <MemoryRouter initialEntries={['/rotations']}>
        <EmptyState title="No matching certificates" description="Clear your filters." action={<button>Clear filters</button>} />
        <Notice tone="warning" title="Renewal due">Review the locations.</Notice>
        <Notice tone="danger" title="Locked" role="alert" />
        <MetricStrip label="Summary" items={[{ label: 'Monitored certificates', value: 8, icon: 'FileKey2', to: '/certificates' }]} />
        <LinkTabs label="SSH keys sections" items={[{ to: '/ssh-keys', label: 'Inventory' }, { to: '/rotations', label: 'Key rotations', match: ['/rotation/'] }]} />
        <DialogActions note="Changes affect selected locations only."><button>Start</button></DialogActions>
      </MemoryRouter>,
    );
    expect(screen.getByText('No matching certificates')).toBeVisible();
    expect(screen.getByRole('note')).toHaveTextContent('Renewal due');
    expect(screen.getByRole('alert')).toHaveTextContent('Locked');
    expect(screen.getByRole('link', { name: /Monitored certificates/ })).toHaveAttribute('href', '/certificates');
    expect(screen.getByRole('link', { name: 'Key rotations' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current');
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument(); // the shell's nav must stay the only one
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    expect(screen.getByText('Changes affect selected locations only.')).toBeVisible();
  });
});

describe('the optional parts', () => {
  it('PageHeader shows the resource tile and a status next to the title, and leaves out what is not given', async () => {
    const { container } = await renderApp(<PageHeader title="seed-web-3" icon="Server" status={<span>Connected</span>} />);
    expect(screen.getByRole('heading', { level: 1, name: 'seed-web-3' })).toBeVisible();
    expect(screen.getByText('Connected')).toBeVisible();
    expect(container.querySelectorAll('svg')).toHaveLength(1);
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('Panel has a description, a corner action and a footer, flush content, and no head without title or action', async () => {
    const { unmount } = await renderApp(
      <Panel title="Locations" description="Where it is used." action={<button>Add</button>} footer={<span>3 shown</span>} padded={false} testId="p">
        rows
      </Panel>,
    );
    expect(screen.getByText('Where it is used.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Add' })).toBeVisible();
    expect(screen.getByText('3 shown').closest('footer')).not.toBeNull();
    expect(screen.getByTestId('p')).toHaveTextContent('rows');
    unmount();
    const { container } = await renderApp(<Panel>only body</Panel>);
    expect(container.querySelector('header')).toBeNull();
    expect(screen.queryByRole('heading')).not.toBeInTheDocument();
  });

  it('ResourceTable without toolbar and footer is just the named table in its scroll region', async () => {
    await renderApp(
      <ResourceTable label="Keys" striped>
        <Table.Tbody><Table.Tr><Table.Td>k</Table.Td></Table.Tr></Table.Tbody>
      </ResourceTable>,
    );
    expect(screen.getByRole('table', { name: 'Keys' })).toBeVisible();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('StatusBadge without an icon shows a dot, never color alone', async () => {
    const { container } = await renderApp(<StatusBadge tone="success" size="sm">Valid</StatusBadge>);
    const badge = container.querySelector('.mantine-Badge-root')!;
    expect(badge).toHaveTextContent('Valid');
    expect(badge.querySelector('svg')).toBeNull();
    expect(badge.querySelector('span[aria-hidden="true"]')).not.toBeNull();
  });

  it('OperationTimeline marks every state, spins for a running step and shows detail and time', async () => {
    const states = ['done', 'failed', 'running', 'waiting', 'skipped', 'notRun', 'unknown'] as const;
    const { container } = await renderApp(
      <OperationTimeline label="Steps" steps={states.map((s) => ({ id: s, title: `Step ${s}`, state: s, stateLabel: `State ${s}`, detail: s === 'failed' ? 'Permission denied' : undefined, time: s === 'done' ? '09:41' : undefined }))} />,
    );
    const markers = container.querySelectorAll('[data-state]');
    expect([...markers].map((m) => m.getAttribute('data-state'))).toEqual([...states]);
    expect(markers[2].querySelector('svg')).toBeNull(); // the running step shows a loader, not an icon
    for (const i of [0, 1, 3, 4, 5, 6]) expect(markers[i].querySelector('svg')).not.toBeNull();
    expect(screen.getByText('Permission denied')).toBeVisible();
    expect(screen.getByText('09:41')).toBeVisible();
    for (const s of states) expect(screen.getByText(`State ${s}`)).toBeVisible();
  });

  it('AttentionItem is a button with onClick, plain text without a target, and shows its meta line', async () => {
    const click = vi.fn();
    const { unmount } = await renderApp(<AttentionItem tone="warning" icon="Clock3" title="Expires soon" meta="2 days" onClick={click} testId="a" />);
    await userEvent.click(screen.getByRole('button', { name: /Expires soon/ }));
    expect(click).toHaveBeenCalledOnce();
    expect(screen.getByText('2 days')).toBeVisible();
    unmount();
    await renderApp(<AttentionItem tone="info" icon="Clock3" title="Checking" testId="b" />);
    expect(screen.getByTestId('b').tagName).toBe('DIV');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('MetricStrip shows an unlinked metric with its footnote; EmptyState and Notice with only their required parts', async () => {
    await renderApp(
      <>
        <MetricStrip label="Summary" items={[{ label: 'Needs attention', value: 3, icon: 'CircleAlert', foot: '1 urgent', tone: 'danger', testId: 'm' }]} />
        <EmptyState title="Nothing here yet" icon="Server" testId="e" />
        <Notice tone="info" title="Heads up" action={<button>Review</button>} testId="n" />
      </>,
    );
    expect(screen.getByTestId('m').tagName).toBe('DIV');
    expect(screen.getByText('1 urgent')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByTestId('e')).toHaveTextContent('Nothing here yet');
    expect(screen.getByRole('note')).toHaveTextContent('Heads up');
    expect(screen.getByRole('button', { name: 'Review' })).toBeVisible();
  });

  it('LinkTabs marks a tab active on its own address and below it', async () => {
    await renderApp(
      <MemoryRouter initialEntries={['/ssh-keys/42']}>
        <LinkTabs label="SSH keys sections" items={[{ to: '/ssh-keys', label: 'Inventory' }, { to: '/rotations', label: 'Key rotations' }]} />
      </MemoryRouter>,
    );
    expect(screen.getByRole('link', { name: 'Inventory' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Key rotations' })).not.toHaveAttribute('aria-current');
  });

  it('LinkTabs marks a tab active on one of its extra address prefixes', async () => {
    await renderApp(
      <MemoryRouter initialEntries={['/rotation/runs/7']}>
        <LinkTabs label="SSH keys sections" items={[{ to: '/ssh-keys', label: 'Inventory' }, { to: '/rotations', label: 'Key rotations', match: ['/rotation/'] }]} />
      </MemoryRouter>,
    );
    expect(screen.getByRole('link', { name: 'Key rotations' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current');
  });

  it('DialogActions without a note holds only the buttons', async () => {
    const { container } = await renderApp(<DialogActions><button>Close</button></DialogActions>);
    expect((container.querySelector('button')!.parentElement as HTMLElement).children).toHaveLength(1);
  });
});
