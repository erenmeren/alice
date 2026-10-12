import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { renderApp } from '../../test/render';
import type { WizardStep } from '../SetupPage';
import { SetupRail, railIndex } from './SetupRail';
import { SetupShell, StepHeading } from './SetupShell';

function Walk() {
  const [step, setStep] = useState<WizardStep>('https');
  return (
    <SetupShell current={step}>
      {step !== 'license' && <StepHeading title={`Title of ${step}`} />}
      <button type="button" onClick={() => setStep(step === 'https' ? 'mail' : 'license')}>
        Next
      </button>
    </SetupShell>
  );
}

describe('SetupRail', () => {
  it('maps every wizard step to its rail item', () => {
    const steps: WizardStep[] = ['code', 'language', 'admin', 'totp', 'codes', 'passphrase', 'https', 'mail', 'license', 'platform', 'done'];
    expect(steps.map((s) => railIndex(s))).toEqual([0, 0, 1, 1, 1, 2, 3, 4, 5, 6, 7]);
  });

  it('is not interactive: no links, no buttons, nothing focusable', async () => {
    const { container } = await renderApp(<SetupRail current="mail" />);
    const rail = screen.getByRole('list', { name: 'Setup progress' });
    expect(within(rail).queryAllByRole('link')).toHaveLength(0);
    expect(within(rail).queryAllByRole('button')).toHaveLength(0);
    expect(container.querySelectorAll('[tabindex]')).toHaveLength(0);
    await userEvent.click(within(rail).getByText('HTTPS certificate'));
    expect(within(rail).getByText('Mail server').closest('li')).toHaveAttribute('aria-current', 'step');
  });

  it('marks earlier items done and later items not started, in text', async () => {
    await renderApp(<SetupRail current="mail" />);
    const items = within(screen.getByRole('list', { name: 'Setup progress' })).getAllByRole('listitem');
    expect(items).toHaveLength(7);
    expect(items[3]).toHaveTextContent('Done');
    expect(items[4]).toHaveAttribute('aria-current', 'step');
    expect(items[4]).toHaveTextContent('Current step');
    expect(items[5]).toHaveTextContent('Not started');
    expect(items.filter((li) => li.hasAttribute('aria-current'))).toHaveLength(1);
    // The phone layout shows "Step 5 of 7" instead of the full list.
    expect(screen.getByText('Step 5 of 7')).toBeInTheDocument();
  });

  it('shows every item done on the last screen', async () => {
    await renderApp(<SetupRail current="done" />);
    const items = within(screen.getByRole('list', { name: 'Setup progress' })).getAllByRole('listitem');
    for (const li of items) {
      expect(li).toHaveTextContent('Done');
      expect(li).not.toHaveAttribute('aria-current');
    }
    expect(screen.getByText('Step 7 of 7')).toBeInTheDocument();
  });

  it('marks the language step as part of the first item and speaks Turkish', async () => {
    await renderApp(<SetupRail current="language" />, ['tr-TR']);
    const rail = screen.getByRole('list', { name: 'Kurulum adımları' });
    expect(within(rail).getByText('Kurulum kodu ve dil').closest('li')).toHaveAttribute('aria-current', 'step');
    expect(screen.getByText('Adım 1 / 7')).toBeInTheDocument();
    expect(screen.getByText('Size ait çalışma alanı')).toBeInTheDocument();
  });

  it('moves focus to the new step title and announces the step politely, never on the first screen', async () => {
    await renderApp(<Walk />);
    const first = screen.getByRole('heading', { level: 2, name: 'Title of https' });
    expect(first).not.toHaveFocus();
    const live = document.querySelector('[aria-live="polite"]');
    expect(live).toHaveTextContent(/^$/);
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('heading', { level: 2, name: 'Title of mail' })).toHaveFocus();
    expect(live).toHaveTextContent('Step 5 of 7');
    // A step whose title is not drawn yet: the content area itself takes the focus.
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(document.activeElement?.tagName).toBe('SECTION');
    expect(live).toHaveTextContent('Step 6 of 7');
  });
});
