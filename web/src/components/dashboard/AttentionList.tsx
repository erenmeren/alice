import { Code } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { Condition } from '../../api/phase7';
import { AttentionItem, cx, EmptyState, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import { WRAP } from '../wrap';
import { useConditionItems } from './conditions';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// AttentionList is "Needs attention": each known condition as the design's attention item (what happened, the resource
// as its own text, since when, where to act), in the server's order. The "N open" badge counts the server's conditions
// (GET /alerts for the caller), the same number as the Overview's "Needs attention" metric (summary.attention); a
// condition of a kind this version cannot show is counted and named as such, never dropped silently.
export function AttentionList({ items }: { items: Condition[] }) {
  const { t } = useTranslation();
  const shown = useConditionItems(items);
  const unshown = items.length - shown.length;
  return (
    <Widget
      title={t('dashboard.needsAttention')}
      description={t('dashboard.panels.attentionSub')}
      testId="attention-list"
      padded={false}
      action={
        items.length > 0 && (
          <StatusBadge tone="warning" className={classes.attentionCount}>
            {t('dashboard.panels.open', { count: items.length })}
          </StatusBadge>
        )
      }
    >
      {items.length === 0 && <EmptyState icon="ShieldCheck" title={t('dashboard.noAttention')} />}
      {shown.length > 0 && (
        <ul role="list" className={cx(ui.attentionList, classes.attentionList)}>
          {shown.map((c) => (
            <li key={c.key}>
              <AttentionItem
                tone={c.tone}
                icon={c.icon}
                title={c.title}
                detail={
                  c.name ? (
                    <Code translate="no" style={WRAP}>
                      {c.name}
                    </Code>
                  ) : undefined
                }
                meta={c.since}
                to={c.to ?? undefined}
              />
            </li>
          ))}
        </ul>
      )}
      {unshown > 0 && <p className={classes.unshown}>{t('dashboard.panels.unshown', { count: unshown })}</p>}
    </Widget>
  );
}
