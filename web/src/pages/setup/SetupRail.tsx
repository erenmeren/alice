import { useTranslation } from 'react-i18next';
import { Icon } from '../../design/Icon';
import type { WizardStep } from '../SetupPage';
import classes from './setup.module.css';

const ITEMS = ['code', 'admin', 'passphrase', 'https', 'mail', 'license', 'platform'] as const;
const INDEX: Record<WizardStep, number> = {
  code: 0,
  language: 0,
  admin: 1,
  totp: 1,
  codes: 1,
  passphrase: 2,
  https: 3,
  mail: 4,
  license: 5,
  platform: 6,
  done: 7,
};

// railIndex is the rail item a wizard step belongs to; "done" (7) lies past the last item, so every item shows done.
export function railIndex(step: WizardStep): number {
  return INDEX[step];
}

// SetupRail shows where the person is in the real installer. It never navigates: the wizard's own buttons (and Back
// where BACK allows it) are the only way between steps, so no check can be skipped (IMPLEMENTATION §7, R18).
export function SetupRail({ current }: { current: WizardStep }) {
  const { t } = useTranslation();
  const at = railIndex(current);
  return (
    <div className={classes.rail}>
      <p className={classes.railTitle}>{t('setup.rail.title')}</p>
      <p className={classes.counter}>{t('setup.rail.counter', { n: Math.min(at + 1, ITEMS.length), total: ITEMS.length })}</p>
      <ol className={classes.railList} aria-label={t('setup.rail.label')}>
        {ITEMS.map((item, i) => {
          const state = i < at ? 'done' : i === at ? 'current' : 'next';
          return (
            <li key={item} className={classes.railItem} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
              <span className={classes.railNumber} aria-hidden="true">
                {state === 'done' ? <Icon name="Check" size={13} /> : i + 1}
              </span>
              <span className={classes.railText}>
                <span>{t(`setup.rail.${item}`)}</span>
                <span className={classes.railState}>
                  {t(state === 'done' ? 'setup.rail.done' : state === 'current' ? 'setup.rail.current' : 'setup.rail.next')}
                </span>
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
