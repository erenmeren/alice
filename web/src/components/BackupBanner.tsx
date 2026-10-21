import { Alert, Anchor } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getDashboardSummary } from '../api/phase7';
import { DASHBOARD_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { canPlatform } from '../auth/permissions';
import { Icon } from '../design/Icon';

// BackupBanner is the red banner of §20.2 for Administrators: no successful backup for 48 hours. It reads the
// dashboard summary (the same query as the dashboard, so the dashboard adds no request); the query is not made for
// other roles.
export function BackupBanner() {
  const { t } = useTranslation();
  const { session } = useAuth();
  // The backups are the installation's: a global Administrator's (backup.manage).
  const admin = canPlatform(session, 'backup.manage');
  const summary = useQuery({ queryKey: DASHBOARD_KEY, queryFn: getDashboardSummary, enabled: admin, refetchInterval: 60_000 });
  if (!admin || !summary.data?.backup?.alarm) return null;
  return (
    <Alert color="red" role="alert" data-testid="backup-alarm-banner" icon={<Icon name="ShieldAlert" />}>
      <Anchor component={Link} to="/settings?tab=backups" c="inherit" fw={600} underline="always">
        {t('backups.alarm')}
      </Anchor>
    </Alert>
  );
}
