import { Anchor, Badge, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { BackupSummary } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { Widget } from './Widget';

// BackupCard shows the last successful backup and its age (R43 row 18). The server sends it to Administrators and
// Auditors only; only Administrators get the link to Settings → Backups, which only they may open.
export function BackupCard({ backup, admin }: { backup: BackupSummary; admin: boolean }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget title={t('dashboard.backup.title')} testId="backup-card">
      <Stack gap="xs">
        {backup.alarm && (
          <Badge variant="light" color="red" tt="none" style={{ whiteSpace: 'normal', height: 'auto' }}>
            {t('backups.alarm')}
          </Badge>
        )}
        {!backup.configured && <Text size="sm">{t('backups.notConfigured')}</Text>}
        {backup.last_success_at ? (
          <>
            <Text size="sm">{t('backups.lastSuccess', { time: formatDateTime(backup.last_success_at, i18n.language) })}</Text>
            {backup.age_hours !== null && <Text size="sm">{t('dashboard.backup.age', { count: backup.age_hours })}</Text>}
          </>
        ) : (
          backup.configured && <Text size="sm">{t('backups.never')}</Text>
        )}
        {backup.failing && (
          <Text size="sm" c="red.9">
            {t('backups.failing')}
          </Text>
        )}
        {admin && (
          <Anchor component={Link} to="/settings?tab=backups" size="sm">
            {t('dashboard.backup.open')}
          </Anchor>
        )}
      </Stack>
    </Widget>
  );
}
