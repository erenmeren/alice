import { screen, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { renderApp } from '../../test/render';
import { hasRotationPath, RotationPath } from './RotationPath';

const NAMES = ['Generate new key', 'Deploy & verify', 'Overlap period', 'Retire old key'];

// phases returns each phase's state text in order (Complete / In progress / Not started).
function phases(): string[] {
  const path = screen.getByRole('list', { name: 'Rotation progress' });
  return within(path)
    .getAllByRole('listitem')
    .map((li, i) => {
      expect(li).toHaveTextContent(`0${i + 1}`);
      expect(li).toHaveTextContent(NAMES[i]);
      return li.getAttribute('data-state') ?? '';
    });
}

describe('RotationPath', () => {
  it.each([
    ['dry_run_notified', ['current', 'next', 'next', 'next']],
    ['adding_new', ['done', 'current', 'next', 'next']],
    ['verifying_new', ['done', 'current', 'next', 'next']],
    ['overlap', ['done', 'done', 'current', 'next']],
    ['removing_old', ['done', 'done', 'done', 'current']],
    ['completed', ['done', 'done', 'done', 'done']],
  ])('draws %s as %j', async (status, states) => {
    await renderApp(<RotationPath status={status} />);
    expect(phases()).toEqual(states);
    const text = { done: 'Complete', current: 'In progress', next: 'Not started' } as const;
    within(screen.getByRole('list', { name: 'Rotation progress' }))
      .getAllByRole('listitem')
      .forEach((li, i) => expect(li).toHaveTextContent(text[states[i] as keyof typeof text]));
  });

  it('is a list to assistive technology despite list-style: none, and marks the current phase as the step', async () => {
    await renderApp(<RotationPath status="overlap" />);
    const path = screen.getByRole('list', { name: 'Rotation progress' });
    expect(path).toHaveAttribute('role', 'list');
    const items = within(path).getAllByRole('listitem');
    expect(items.map((li) => li.getAttribute('aria-current'))).toEqual([null, null, 'step', null]);
  });

  it('marks no step current once the run completed', async () => {
    await renderApp(<RotationPath status="completed" />);
    expect(screen.getByRole('list', { name: 'Rotation progress' }).querySelector('[aria-current]')).toBeNull();
  });

  it('says Paused for the current phase of a paused run, never In progress', async () => {
    await renderApp(<RotationPath status="adding_new" paused />);
    const items = within(screen.getByRole('list', { name: 'Rotation progress' })).getAllByRole('listitem');
    expect(items[1]).toHaveTextContent('Paused');
    expect(items[1]).toHaveAttribute('data-state', 'current');
    expect(items.some((li) => li.textContent?.includes('In progress'))).toBe(false);
  });

  it('names the path after its run when given a name, so several paths on a page are told apart', async () => {
    await renderApp(<RotationPath status="overlap" name="deploy-production" />);
    expect(screen.getByRole('list', { name: 'Rotation progress: deploy-production' })).toBeInTheDocument();
  });

  it.each([
    ['dry_run_notified', true],
    ['completed', true],
    ['rolling_back', false],
    ['from_the_future', false],
  ])('hasRotationPath(%s) is %s, the same statuses the path draws', (status, drawn) => {
    expect(hasRotationPath(status)).toBe(drawn);
  });

  it.each(['rolling_back', 'aborted', 'needs_attention', 'cancelled', 'unknown', 'from_the_future'])('draws no path for %s: a stopped run is never shown as progress', async (status) => {
    await renderApp(<RotationPath status={status} />);
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('states each phase in Turkish', async () => {
    await renderApp(<RotationPath status="overlap" />, ['tr-TR']);
    const path = screen.getByRole('list', { name: 'Rotasyon ilerlemesi' });
    expect(path).toHaveTextContent('Geçiş süresi');
    expect(path).toHaveTextContent('Devam ediyor');
    expect(path).toHaveTextContent('Tamamlandı');
    expect(path).toHaveTextContent('Başlamadı');
  });

  it('uses the design tokens for the phase rule: brand done, warning current, border next', () => {
    const css = readFileSync('src/pages/Rotations.module.css', 'utf8');
    expect(css).toMatch(/\.phase \{[^}]*border-top: 3px solid var\(--alice-border\)/);
    expect(css).toMatch(/\.phase\[data-state='done'\] \{[^}]*var\(--alice-brand\)/);
    expect(css).toMatch(/\.phase\[data-state='current'\] \{[^}]*var\(--alice-warning\)/);
  });
});
