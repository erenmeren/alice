import { Anchor, Code } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { EmptyState, StatusBadge } from '../ui';
import { WRAP } from '../wrap';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// RotationUpcoming is the design's "Key rotation" panel: the next scheduled rotations (each linked to its key), how many
// run now and how many wait for a decision, and the way to the rotations page.
export function RotationUpcoming({ rotation }: { rotation: DashboardSummary['rotation'] }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget
      title={t('dashboard.panels.rotation')}
      description={t('dashboard.panels.rotationSub')}
      testId="rotation-upcoming"
      footer={
        <Anchor component={Link} to="/rotations" size="xs">
          {t('dashboard.panels.openRotations')}
        </Anchor>
      }
    >
      {rotation.upcoming.length === 0 ? (
        <EmptyState icon="RotateCw" title={t('dashboard.noUpcoming')} />
      ) : (
        <ul role="list" className={classes.rotationList} aria-label={t('dashboard.rotationUpcoming')}>
          {rotation.upcoming.map((r) => (
            <li key={r.policy_id} className={classes.rotationItem}>
              <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(r.ssh_key_id)}`} size="xs">
                <Code translate="no" style={WRAP}>
                  {r.key_label}
                </Code>
              </Anchor>
              <time dateTime={r.next_run_at}>{formatDateTime(r.next_run_at, i18n.language)}</time>
            </li>
          ))}
        </ul>
      )}
      <div className={classes.badges}>
        <StatusBadge tone={rotation.running > 0 ? 'info' : 'neutral'} icon="RefreshCw">
          {t('dashboard.rotationRunning', { count: rotation.running })}
        </StatusBadge>
        <StatusBadge tone={rotation.needs_attention > 0 ? 'warning' : 'neutral'} icon={rotation.needs_attention > 0 ? 'CircleAlert' : 'CircleCheck'}>
          {t('dashboard.rotationAttention', { count: rotation.needs_attention })}
        </StatusBadge>
      </div>
    </Widget>
  );
}
