import { SimpleGrid, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getVersion } from '../api/endpoints';
import { getAlerts, getDashboardSummary, getExpiring } from '../api/phase7';
import { ALERTS_KEY, DASHBOARD_KEY, EXPIRING_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { AttentionList } from '../components/dashboard/AttentionList';
import { AuditHead } from '../components/dashboard/AuditHead';
import { CertificateCounts } from '../components/dashboard/CertificateCounts';
import { ExpiringList } from '../components/dashboard/ExpiringList';
import { FailedDeployments } from '../components/dashboard/FailedDeployments';
import { LicenseCard } from '../components/dashboard/LicenseCard';
import { RotationUpcoming } from '../components/dashboard/RotationUpcoming';
import { TargetsByStatus } from '../components/dashboard/TargetsByStatus';
import { ErrorAlert } from '../components/ErrorAlert';

// Background reads: they are polling, so they do not carry the activity mark (R39 item 1).
const REFRESH_MS = 60_000;

// DashboardPage is the landing page: what expires, what failed, what needs attention. The parts the server leaves out
// for a role (audit head, notification state) are null in the summary and not drawn.
export function DashboardPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const role = session?.user.role;
  const version = useQuery({ queryKey: ['version'], queryFn: getVersion });
  const summary = useQuery({ queryKey: DASHBOARD_KEY, queryFn: getDashboardSummary, refetchInterval: REFRESH_MS });
  const expiring = useQuery({ queryKey: EXPIRING_KEY, queryFn: () => getExpiring(30, 10), refetchInterval: REFRESH_MS });
  const alerts = useQuery({ queryKey: ALERTS_KEY, queryFn: getAlerts, refetchInterval: REFRESH_MS });

  let status = t('home.serverChecking');
  if (version.isSuccess) status = t('home.serverVersion', { version: version.data.version });
  if (version.isError) status = t('home.serverUnreachable');

  const s = summary.data;
  return (
    <Stack gap="md">
      <div>
        <Title order={1}>{t('dashboard.welcome', { name: session?.user.display_name ?? '' })}</Title>
        <Title order={2} size="h3" mt="xs">
          {t('dashboard.title')}
        </Title>
      </div>
      <Text size="sm" c="gray.7" data-testid="server-status" aria-live="polite">
        {status}
      </Text>
      <ErrorAlert error={summary.error ?? expiring.error ?? alerts.error} />
      <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}>
        {s && <CertificateCounts counts={s.certificates} />}
        {expiring.data && <ExpiringList items={expiring.data.items} />}
        {s && <FailedDeployments deployments={s.deployments} />}
        {s && <TargetsByStatus targets={s.targets} />}
        {s && <LicenseCard license={s.license} detailed={role === 'admin' || role === 'auditor'} />}
        {s && <RotationUpcoming rotation={s.rotation} />}
        {s?.audit && <AuditHead audit={s.audit} />}
        {alerts.data && <AttentionList items={alerts.data.items} />}
      </SimpleGrid>
    </Stack>
  );
}
