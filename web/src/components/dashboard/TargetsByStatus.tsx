import { Anchor } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import type { TargetStatus } from '../../api/types';
import { EmptyState, TARGET_TONE, type Tone } from '../ui';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

const toneOf = (status: string): Tone => TARGET_TONE[status as TargetStatus] ?? 'neutral';

// TargetsByStatus is the design's "Target connectivity": how many targets were last seen connected, a health track with
// one segment per status (its width by count; text in its label and in the links below, never color alone), and the
// statuses that have at least one target, labelled by the existing target status texts.
export function TargetsByStatus({ targets }: { targets: DashboardSummary['targets'] }) {
  const { t, i18n } = useTranslation();
  const rows = Object.entries(targets.by_status)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => a.localeCompare(b));
  const text = (status: string, n: number) =>
    t('dashboard.statusCount', { status: i18n.exists(`enum.targetStatus.${status}`) ? t(`enum.targetStatus.${status}`) : status, count: n });
  const list = new Intl.ListFormat(i18n.language, { style: 'long', type: 'unit' });
  return (
    <Widget
      title={t('dashboard.panels.connectivity')}
      description={t('dashboard.panels.connectivitySub')}
      testId="targets-by-status"
      footer={
        <Anchor component={Link} to="/servers" size="xs">
          {t('dashboard.panels.openServers')}
        </Anchor>
      }
    >
      {rows.length === 0 ? (
        <EmptyState icon="Server" title={t('dashboard.noTargets')} />
      ) : (
        <>
          <div className={classes.valueRow}>
            <span>
              <span className={classes.largeValue}>{targets.by_status.ok ?? 0}</span> <span className={classes.valueNote}>{t('dashboard.panels.connectedOf', { total: targets.total })}</span>
            </span>
          </div>
          <div className={classes.healthTrack} role="img" aria-label={list.format(rows.map(([s, n]) => text(s, n)))}>
            {rows.map(([status, n]) => (
              <i key={status} data-tone={toneOf(status)} style={{ flexGrow: n }} />
            ))}
          </div>
          <ul role="list" className={classes.statusLinks}>
            {rows.map(([status, n]) => (
              <li key={status}>
                <Anchor component={Link} to="/servers" size="xs">
                  {text(status, n)}
                </Anchor>
              </li>
            ))}
          </ul>
        </>
      )}
    </Widget>
  );
}
