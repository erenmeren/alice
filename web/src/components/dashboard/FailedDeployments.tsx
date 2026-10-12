import { Anchor, Code } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { Icon, type IconName } from '../../design/Icon';
import { EmptyState, StatusBadge, type Tone } from '../ui';
import { WRAP } from '../wrap';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// The summary lists only deployments that did not end well: failed, rolled_back, rollback_failed, needs_attention.
const TONE: Record<string, Tone> = { failed: 'danger', rollback_failed: 'danger', rolled_back: 'warning', needs_attention: 'warning' };
const ICON: Record<string, IconName> = { failed: 'CircleX', rollback_failed: 'CircleAlert', rolled_back: 'RotateCw', needs_attention: 'Unplug' };

// FailedDeployments is the design's recent-deployments activity list, holding what the summary has: the five newest
// deployments of the last 7 days that did not end well, each linked to its step-by-step result. Its title keeps saying
// "failed": a list of only failures under "Recent deployments" would read as if nothing else had happened.
export function FailedDeployments({ deployments }: { deployments: DashboardSummary['deployments'] }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget
      title={t('dashboard.failedDeployments')}
      description={t('dashboard.panels.deploymentsSub')}
      testId="failed-deployments"
      padded={false}
      action={
        <StatusBadge tone={deployments.failed_7d > 0 ? 'danger' : 'success'} icon={deployments.failed_7d > 0 ? 'CircleX' : 'CircleCheck'}>
          {t('dashboard.failedCount', { count: deployments.failed_7d })}
        </StatusBadge>
      }
      footer={
        <Anchor component={Link} to="/deployments" size="xs">
          {t('dashboard.panels.viewHistory')}
        </Anchor>
      }
    >
      {deployments.recent.length === 0 ? (
        <EmptyState icon="CircleCheck" title={t('dashboard.noFailed')} />
      ) : (
        <ul role="list" className={classes.activityList}>
          {deployments.recent.map((d) => {
            // A status this version does not know gets no badge (never a raw value) and the neutral mark.
            const known = Object.hasOwn(TONE, d.status);
            const tone = known ? TONE[d.status] : 'neutral';
            return (
              <li key={d.id} className={classes.activityItem}>
                <span className={classes.activityIcon} data-tone={tone}>
                  <Icon name={known ? ICON[d.status] : 'CircleDot'} size={15} />
                </span>
                <div className={classes.activityText}>
                  <Anchor component={Link} to={`/deployments/${encodeURIComponent(d.id)}`} size="xs" fw={600}>
                    <Code translate="no" style={WRAP}>
                      {d.certificate_name}
                    </Code>
                  </Anchor>
                  <p>
                    <Code translate="no" style={WRAP}>
                      {d.target_name}
                    </Code>
                  </p>
                  {known && (
                    <StatusBadge tone={tone} size="sm">
                      {t(`enum.deploymentStatus.${d.status}`)}
                    </StatusBadge>
                  )}
                </div>
                <time className={classes.activityTime} dateTime={d.at}>
                  {formatDateTime(d.at, i18n.language)}
                </time>
              </li>
            );
          })}
        </ul>
      )}
    </Widget>
  );
}
