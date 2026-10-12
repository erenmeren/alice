import { Anchor } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { BackupSummary } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { FactList, Notice, StatusBadge } from '../ui';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// BackupCard is the design's "Recovery readiness" (R43 row 18): the last successful backup and its age, the alarm and a
// failed last run, and — as the design insists — that a backup checksum does not establish that a restore works. No
// health score is derived. The server sends it to Administrators and Auditors only; only Administrators get the link to
// Settings → Backups, which only they may open.
export function BackupCard({ backup, admin }: { backup: BackupSummary; admin: boolean }) {
  const { t, i18n } = useTranslation();
  const healthy = !!backup.last_success_at && !backup.alarm && !backup.failing;
  return (
    <Widget
      title={t('dashboard.assurance.recovery')}
      description={t('dashboard.assurance.recoverySub')}
      testId="backup-card"
      action={
        healthy && (
          <StatusBadge tone="success" icon="DatabaseBackup">
            {t('dashboard.assurance.backupOk')}
          </StatusBadge>
        )
      }
      footer={
        admin && (
          <Anchor component={Link} to="/settings?tab=backups" size="xs">
            {t('dashboard.backup.open')}
          </Anchor>
        )
      }
    >
      {backup.alarm && <Notice tone="danger" title={t('backups.alarm')} />}
      {backup.failing && <Notice tone="warning" title={t('backups.failing')} />}
      <div className={backup.alarm || backup.failing ? classes.section : undefined}>
        {!backup.configured && <p className={classes.caption}>{t('backups.notConfigured')}</p>}
        {backup.last_success_at ? (
          <>
            {backup.age_hours !== null && <span className={classes.largeValue}>{t('dashboard.backup.age', { count: backup.age_hours })}</span>}
            <p className={classes.caption}>{t('backups.lastSuccess', { time: formatDateTime(backup.last_success_at, i18n.language) })}</p>
          </>
        ) : (
          backup.configured && <p className={classes.caption}>{t('backups.never')}</p>
        )}
      </div>
      <div className={classes.section}>
        <FactList facts={[{ key: 'drill', label: t('dashboard.assurance.restoreDrill'), value: t('dashboard.assurance.restoreNote') }]} />
      </div>
    </Widget>
  );
}
