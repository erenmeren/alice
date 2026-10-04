import { Alert, Anchor, Box, Card, Code, Group, Stack, Text, Title } from '@mantine/core';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { deploymentView } from '../api/deployments';
import { getDeployment } from '../api/endpoints';
import { configErrorKey, deploymentStateKey, stepNameKey, verifiedKey } from '../api/enums';
import { deploymentKey } from '../api/queryKeys';
import type { DeploymentDetail } from '../api/types';
import { PageLoader } from '../auth/guards';
import { DeploymentSteps } from '../components/DeploymentSteps';
import { DeploymentOutcome, DeploymentStatusBadge } from '../components/DeploymentView';
import { ErrorAlert } from '../components/ErrorAlert';
import { LabelledCode } from '../components/LabelledCode';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

// How often the page reads the deployment while it can still change: a running deployment moves in
// seconds, one being recovered or held for the license only when Alice retries or an Administrator
// acts. A settled deployment is read once.
function refetchEvery(d: DeploymentDetail | undefined): number | false {
  if (!d) return false;
  switch (deploymentView(d)) {
    case 'working':
      return 2_000;
    case 'recovering':
      return 10_000;
    case 'held':
      return 30_000;
    default:
      return false;
  }
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Box component="li" style={{ listStyle: 'none' }}>
      <Text size="sm" fw={600} component="span" display="block">
        {label}
      </Text>
      <Box component="div">{children}</Box>
    </Box>
  );
}

// DeploymentDetailPage is one deployment: its status and state first (in words), what to do about
// it, then the steps, the files and fingerprints. It follows a deployment that can still change.
export function DeploymentDetailPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const dep = useQuery({
    queryKey: deploymentKey(id),
    queryFn: () => getDeployment(id),
    refetchInterval: (q) => refetchEvery(q.state.data),
    placeholderData: keepPreviousData,
  });

  if (dep.isPending) return <PageLoader />;
  if (!dep.data) {
    return (
      <Stack gap="md">
        <ErrorAlert error={dep.error} />
        <Anchor component={Link} to="/deployments" w="fit-content">
          {t('deployments.backToList')}
        </Anchor>
      </Stack>
    );
  }
  const d = dep.data;
  const view = deploymentView(d);
  const time = (v: string | null) => (v ? formatDateTime(v, i18n.language) : '');
  const showRecovery = view === 'recovering' || d.recovery_attempts > 0 || d.state === 'recovering';

  return (
    <Stack gap="md">
      <Anchor component={Link} to="/deployments" w="fit-content" size="sm">
        {t('deployments.backToList')}
      </Anchor>
      <Title order={1}>{t('deployments.detailTitle')}</Title>
      {/* The headline: status and state in words; assistive technology hears changes (polite). */}
      <Group gap="md" role="status" aria-live="polite" data-testid="deployment-headline">
        <Group gap={6}>
          <Text size="sm" fw={600}>
            {t('deployments.statusLabel')}
          </Text>
          <DeploymentStatusBadge status={d.status} testId="deployment-status" />
        </Group>
        <Group gap={6}>
          <Text size="sm" fw={600}>
            {t('deployments.stateLabel')}
          </Text>
          <Text size="sm" data-testid="deployment-state">
            {t(deploymentStateKey(d.state))}
          </Text>
        </Group>
        {view === 'held' && (
          <Text size="sm" fw={600}>
            {t('deployments.held')}
          </Text>
        )}
      </Group>
      <ErrorAlert error={dep.error} />
      <DeploymentOutcome d={d} />
      {view === 'working' && (
        <Alert color="blue" role="status">
          {t('deploy.working')}
        </Alert>
      )}
      {showRecovery && (
        <Card withBorder padding="sm" data-testid="recovery">
          <Stack gap={4}>
            <Title order={2} size="h4">
              {t('deployments.recovery.title')}
            </Title>
            <Text size="sm">{t('deployments.recovery.attempts', { attempts: d.recovery_attempts })}</Text>
            {d.recover_after && <Text size="sm">{t('deployments.recovery.next', { time: time(d.recover_after) })}</Text>}
            <Text size="sm">{t(d.status === 'needs_attention' ? 'deployments.recovery.needsAttention' : 'deployments.recovery.running')}</Text>
          </Stack>
        </Card>
      )}
      {d.backup_dir !== '' && <LabelledCode text={t('deployments.backup', { path: '' })} value={d.backup_dir} />}

      <Title order={2} size="h3">
        {t('deployments.stepsTitle')}
      </Title>
      <DeploymentSteps steps={d.steps} status={d.status} detailed />

      {d.previous_fingerprint !== '' && <LabelledCode text={t('deployments.previous', { fingerprint: '' })} value={d.previous_fingerprint} />}
      {d.new_fingerprint !== '' && <LabelledCode text={t('deployments.new', { fingerprint: '' })} value={d.new_fingerprint} />}

      <Box component="ul" m={0} p={0} style={{ display: 'grid', gap: 12 }} aria-label={t('deployments.detailTitle')}>
        <Fact label={t('deployments.certificateLabel')}>
          <Anchor component={Link} to={`/certificates/${d.certificate_id}`} translate="no" style={WRAP}>
            {d.certificate_name}
          </Anchor>
        </Fact>
        <Fact label={t('deployments.serverLabel')}>
          <Anchor component={Link} to={`/servers/${d.target_id}`} translate="no" style={WRAP}>
            {d.target_name}
          </Anchor>
        </Fact>
        <Fact label={t('deployments.fileLabel')}>
          <Code translate="no" style={WRAP}>
            {d.cert_path}
          </Code>
        </Fact>
        <Fact label={t('deployments.keyFileLabel')}>
          <Code translate="no" style={WRAP}>
            {d.key_path}
          </Code>
        </Fact>
        <Fact label={t('deployments.createdLabel')}>
          <Text size="sm">{time(d.created_at)}</Text>
          <Text size="sm">{d.requested_by_name ? t('deployments.requestedBy', { name: d.requested_by_name }) : t('deployments.requestedBySystem')}</Text>
        </Fact>
        {d.started_at && (
          <Fact label={t('deployments.startedLabel')}>
            <Text size="sm">{time(d.started_at)}</Text>
          </Fact>
        )}
        {d.finished_at && (
          <Fact label={t('deployments.finishedLabel')}>
            <Text size="sm">{time(d.finished_at)}</Text>
          </Fact>
        )}
        <Fact label={t('deployments.verifiedLabel')}>
          <Text size="sm">{t(verifiedKey(d.verified))}</Text>
        </Fact>
      </Box>

      {(d.failed_step || d.cause_step || d.helper_error) && (
        <Stack gap={2}>
          <Title order={2} size="h4">
            {t('deployments.technical')}
          </Title>
          {d.failed_step && <Text size="sm">{t('deployments.failedStep', { step: t(stepNameKey(d.failed_step)) })}</Text>}
          {d.cause_step && <Text size="sm">{t('deployments.causeStep', { step: t(stepNameKey(d.cause_step)) })}</Text>}
          {d.helper_error && <Text size="sm">{t('deployments.stepDetail.error', { reason: t(configErrorKey(d.helper_error)) })}</Text>}
        </Stack>
      )}
    </Stack>
  );
}
