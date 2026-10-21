import { Alert, Anchor } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getNotificationStatus } from '../api/phase7';
import { NOTIFICATIONS_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { canPlatform } from '../auth/permissions';
import { Icon } from '../design/Icon';
import { CodeText } from './CodeText';

// NotificationsBanner tells Administrators that e-mails could not be sent (owner step 4). The server answers
// { failing: false } to everyone else, and the query is not even made for them.
export function NotificationsBanner() {
  const { t } = useTranslation();
  const { session } = useAuth();
  // The notification settings are the installation's: a global Administrator's (settings.manage).
  const admin = canPlatform(session, 'settings.manage');
  const status = useQuery({ queryKey: NOTIFICATIONS_KEY, queryFn: getNotificationStatus, enabled: admin, refetchInterval: 60_000 });
  if (!admin || !status.data?.failing) return null;
  return (
    <Alert color="red" role="alert" data-testid="notifications-banner" icon={<Icon name="ShieldAlert" />} title={t('notifications.failingTitle')} style={{ overflowWrap: 'anywhere' }}>
      <CodeText i18nKey="notifications.failingBody" param="code" value={status.data.last_failure_code ?? ''} params={{ count: status.data.consecutive_failures ?? 0 }} />{' '}
      <Anchor component={Link} to="/settings?tab=mail" c="inherit" fw={600} underline="always">
        {t('notifications.openSettings')}
      </Anchor>
    </Alert>
  );
}
