import { Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { LanguageToggle, StatusBadge, ThemeToggle } from '../../components/ui';
import type { WizardStep } from '../SetupPage';
import { SetupRail } from './SetupRail';
import classes from './setup.module.css';

// SetupShell is the design's setup layout (setupPage): the brand row with the page's only <h1> and a "Setup" badge,
// then the shell with the progress rail and the step's content. The language toggle is offered only before the setup
// code is accepted: the language step owns the choice afterwards, and once the administrator exists the account's
// language applies. The color mode toggle is a per-device preference and stays on every step.
export function SetupShell({ current, children }: { current: WizardStep; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <main className={classes.layout}>
      <div className={classes.top}>
        <div className={classes.brand}>
          <img src="/favicon.svg" alt="" className={classes.brandMark} />
          <Title order={1} className={classes.title}>
            {t('setup.title')}
          </Title>
        </div>
        <div className={classes.toggles}>
          <StatusBadge tone="neutral">{t('setup.shell.badge')}</StatusBadge>
          <ThemeToggle />
          {current === 'code' && <LanguageToggle signedIn={false} />}
        </div>
      </div>
      <div className={classes.shell}>
        <SetupRail current={current} />
        <section className={classes.content}>{children}</section>
      </div>
    </main>
  );
}

// StepActions is a step's actions row (design .form-actions): Back first where the wizard allows it, then the step's
// own buttons on the right.
export function StepActions({ back, children }: { back?: ReactNode; children: ReactNode }) {
  return (
    <div className={classes.formActions}>
      {back}
      <span className={classes.spacer} />
      {children}
    </div>
  );
}

// StepHeading is a step's title (the design's step title, an <h2> under the page's "Set up Alice") and its intro.
export function StepHeading({ title, intro }: { title: ReactNode; intro?: ReactNode }) {
  return (
    <div>
      <Title order={2} className={classes.stepTitle}>
        {title}
      </Title>
      {intro && <p className={classes.intro}>{intro}</p>}
    </div>
  );
}
