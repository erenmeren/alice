import { screen, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { renderApp } from '../../test/render';
import { RotationPath } from './RotationPath';

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
