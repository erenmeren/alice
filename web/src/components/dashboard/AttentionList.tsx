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
// as its own text, since when, where to act), in the server's order.
export function AttentionList({ items }: { items: Condition[] }) {
  const { t } = useTranslation();
  const shown = useConditionItems(items);
  return (
    <Widget
      title={t('dashboard.needsAttention')}
      description={t('dashboard.panels.attentionSub')}
      testId="attention-list"
      padded={false}
      action={
        shown.length > 0 && (
          <StatusBadge tone="warning" className={classes.attentionCount}>
            {t('dashboard.panels.open', { count: shown.length })}
          </StatusBadge>
        )
      }
    >
      {shown.length === 0 ? (
        <EmptyState icon="ShieldCheck" title={t('dashboard.noAttention')} />
      ) : (
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
    </Widget>
  );
}
