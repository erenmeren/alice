import { Anchor } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { ChecklistItem, ChecklistItemName } from '../../api/types';
import { StatusBadge } from '../ui';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// Where each item is finished. The recovery passphrase belongs to the wizard; the rest have their own pages.
const TARGETS: Record<ChecklistItemName, string> = {
  passphrase: '/setup',
  https: '/settings?tab=https',
  mail: '/settings?tab=mail',
  license: '/license',
  target: '/servers',
};

// SetupChecklist is "Finish setting up" (§18.5, R43 row 18): what the wizard skipped or left open, for Administrators, in
// the design's attention-row language. Required items are marked; finished ones stay listed as done. It is gone once
// everything is done.
export function SetupChecklist({ items }: { items: ChecklistItem[] }) {
  const { t } = useTranslation();
  const known = items.filter((i) => i.item in TARGETS);
  if (known.every((i) => i.done)) return null;
  return (
    <Widget title={t('dashboard.checklist.title')} description={t('dashboard.checklist.help')} testId="setup-checklist" padded={false} className={classes.checklistPanel}>
      <ul role="list" className={classes.checklist}>
        {known.map((i) => (
          <li key={i.item} className={classes.checklistItem}>
            <Anchor component={Link} to={TARGETS[i.item]} size="sm">
              {t(`dashboard.checklist.${i.item}`)}
            </Anchor>
            {i.required && !i.done && (
              <StatusBadge tone="danger" icon="CircleAlert">
                {t('dashboard.checklist.required')}
              </StatusBadge>
            )}
            {i.done && (
              <StatusBadge tone="success" icon="CircleCheck">
                {t('dashboard.checklist.done')}
              </StatusBadge>
            )}
          </li>
        ))}
      </ul>
    </Widget>
  );
}
