import { Anchor, Code, Stack, Text, VisuallyHidden } from '@mantine/core';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { deploymentView, rollbackForbidden } from '../api/deployments';
import { getDeployment } from '../api/endpoints';
import { configErrorKey, deploymentStateKey, stepNameKey, verifiedKey } from '../api/enums';
import { deploymentKey } from '../api/queryKeys';
import type { DeploymentDetail, DeploymentStep } from '../api/types';
import { PageLoader } from '../auth/guards';
import { DeploymentSteps } from '../components/DeploymentSteps';
import { DeploymentOutcome, DeploymentStatusBadge } from '../components/DeploymentView';
import { ErrorAlert } from '../components/ErrorAlert';
import { LabelledCode } from '../components/LabelledCode';
import { FactList, Notice, PageHeader, Panel, type Fact } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import classes from './Deployments.module.css';

// The label of a deployment's source (an unknown value reads as an upload).
const SOURCE_LABEL: Record<DeploymentDetail['source'], string> = {
  upload: 'deployments.source.upload',
  key_vault: 'deployments.source.key_vault',
  acme: 'deployments.source.acme',
};

// How often the page reads the deployment while it can still change: a running deployment moves in
// seconds, one being recovered or held for the license only when Alice retries or an Administrator
// acts. A settled deployment is read once.
function refetchEvery(d: DeploymentDetail | undefined, updates: number): number | false {
  if (!d) return false;
  // A job that ended or a status this version does not know is read a few more times, slowly, and
  // then left: nothing is expected to change on its own.
  const view = deploymentView(d);
  if ((view === 'stopped' || view === 'unknown' || view === 'finishing') && updates > 20) return false;
  switch (view) {
    case 'working':
      return 2_000;
    case 'recovering':
      return 10_000;
    case 'finishing':
      return 3_000;
    case 'stopped':
    case 'unknown':
      return 15_000;
    case 'held':
      return 30_000;
    default:
      return false;
  }
}

// servedFingerprint is the fingerprint the website served when Alice verified this deployment, only
// when the verification step reported one (never inferred from a green step).
function servedFingerprint(d: DeploymentDetail): string {
  let last: DeploymentStep | undefined;
  for (const s of d.steps) if (s.name === 'verify' && s.params?.served && (!last || s.n > last.n)) last = s;
  return last?.params.served ?? '';
}

// DeploymentDetailPage is one deployment: its status and state first (in words), what happened (the
// outcome notice), then the sequence of steps and the recovery card, the operation details and the
// evidence (fingerprints, backup folder). It follows a deployment that can still change.
export function DeploymentDetailPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const dep = useQuery({
    queryKey: deploymentKey(id),
    queryFn: () => getDeployment(id),
    refetchInterval: (q) => refetchEvery(q.state.data, q.state.dataUpdateCount),
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
  // Ongoing recovery is described only while the deployment is not final; a finished one that went
  // through recovery says only that its outcome was confirmed, and after how many attempts.
  const recoveringNow = view !== 'final' && (d.state === 'recovering' || d.status === 'needs_attention');
  const recoveredEarlier = view === 'final' && d.recovery_attempts > 0;
  const served = servedFingerprint(d);
  const link = (to: string, name: string) => (
    <Anchor component={Link} to={to} translate="no" style={WRAP}>
      {name}
    </Anchor>
  );
  const code = (v: string) => (
    <Code translate="no" style={WRAP}>
      {v}
    </Code>
  );
  const facts: Fact[] = [
    { key: 'certificate', label: t('deployments.certificateLabel'), value: link(`/certificates/${d.certificate_id}`, d.certificate_name) },
    { key: 'server', label: t('deployments.serverLabel'), value: link(`/servers/${d.target_id}`, d.target_name) },
    { key: 'source', label: t('deployments.sourceLabel'), value: t(SOURCE_LABEL[d.source] ?? 'deployments.source.upload') },
    ...(d.source === 'key_vault'
      ? [
          {
            key: 'vault',
            label: t('deployments.vaultLabel'),
            value: (
              <span translate="no" style={WRAP}>
                {d.vault_name}
              </span>
            ),
          },
          ...(d.kv_version ? [{ key: 'version', label: t('deployments.versionLabel'), value: code(d.kv_version) }] : []),
        ]
      : []),
    { key: 'file', label: t('deployments.fileLabel'), value: code(d.cert_path) },
    { key: 'keyFile', label: t('deployments.keyFileLabel'), value: code(d.key_path) },
    {
      key: 'requested',
      label: t('deployments.createdLabel'),
      value: (
        <>
          <span className={classes.mono}>{time(d.created_at)}</span>
          <br />
          {d.requested_by_name ? t('deployments.requestedBy', { name: d.requested_by_name }) : t('deployments.requestedBySystem')}
        </>
      ),
    },
    ...(d.started_at ? [{ key: 'started', label: t('deployments.startedLabel'), value: <span className={classes.mono}>{time(d.started_at)}</span> }] : []),
    ...(d.finished_at ? [{ key: 'finished', label: t('deployments.finishedLabel'), value: <span className={classes.mono}>{time(d.finished_at)}</span> }] : []),
    { key: 'verified', label: t('deployments.verifiedLabel'), value: t(verifiedKey(d.verified)), testId: 'deployment-verified' },
  ];
  const evidence = d.new_fingerprint !== '' || d.previous_fingerprint !== '' || served !== '' || d.backup_dir !== '';

  return (
    <Stack gap="md">
      <PageHeader
        back={{ to: '/deployments', label: t('deployments.backToList') }}
        title={t('deployments.detailTitle')}
        description={
          <span translate="no" style={WRAP}>
            {d.certificate_name} → {d.target_name}
          </span>
        }
        status={
          // The headline: status and state in words; assistive technology hears changes (polite).
          <div role="status" aria-live="polite" data-testid="deployment-headline" className={classes.headline}>
            <VisuallyHidden>{t('deployments.statusLabel')}</VisuallyHidden>
            <DeploymentStatusBadge d={d} testId="deployment-status" />
            <span>
              <span className={classes.headlineLabel}>{t('deployments.stateLabel')}</span>{' '}
              <span data-testid="deployment-state">{t(deploymentStateKey(d.state))}</span>
            </span>
            {view === 'held' && <strong>{t('deployments.held')}</strong>}
          </div>
        }
      />
      <ErrorAlert error={dep.error} />
      <DeploymentOutcome d={d} />
      {view === 'working' && <Notice tone="info" role="status" title={t('deploy.working')} />}

      <div className={classes.detailGrid}>
        <div className={classes.stack}>
          <Panel title={t('deployments.page.sequence')} description={t('deployments.page.sequenceSub')} padded={false}>
            <DeploymentSteps steps={d.steps} status={d.status} detailed vault={d.source === 'key_vault'} />
          </Panel>
          {(recoveringNow || recoveredEarlier) && (
            <Panel title={t('deployments.recovery.title')} testId="recovery">
              <Stack gap={4}>
                {recoveringNow ? (
                  <>
                    <Text size="sm">{t('deployments.recovery.attempts', { attempts: d.recovery_attempts })}</Text>
                    {d.recover_after && <Text size="sm">{t('deployments.recovery.next', { time: time(d.recover_after) })}</Text>}
                    <Text size="sm">{t(d.status === 'needs_attention' ? 'deployments.recovery.needsAttention' : 'deployments.recovery.running')}</Text>
                  </>
                ) : (
                  <Text size="sm">
                    {t(d.status === 'rollback_failed' ? 'deployments.recovery.ended' : 'deployments.recovery.confirmed', { count: d.recovery_attempts })}
                  </Text>
                )}
              </Stack>
            </Panel>
          )}
        </div>
        <div className={`${classes.stack} ${classes.side}`}>
          <Panel title={t('deployments.page.details')}>
            <FactList facts={facts} label={t('deployments.page.details')} />
          </Panel>
          {evidence && (
            <Panel title={t('deployments.page.evidence')}>
              <div className={classes.evidence}>
                {d.new_fingerprint !== '' && <LabelledCode text={t('deployments.new', { fingerprint: '' })} value={d.new_fingerprint} />}
                {served !== '' && <LabelledCode text={t('deployments.stepDetail.served', { fingerprint: '' })} value={served} />}
                {d.previous_fingerprint !== '' && <LabelledCode text={t('deployments.previous', { fingerprint: '' })} value={d.previous_fingerprint} />}
                {d.backup_dir !== '' && (
                  <LabelledCode text={t(rollbackForbidden(d) ? 'deployments.backupForbidden' : 'deployments.backup', { path: '' })} value={d.backup_dir} />
                )}
              </div>
            </Panel>
          )}
          {(d.failed_step || d.cause_step || d.helper_error) && (
            <Panel title={t('deployments.technical')}>
              <Stack gap={2}>
                {d.failed_step && <Text size="sm">{t('deployments.failedStep', { step: t(stepNameKey(d.failed_step)) })}</Text>}
                {d.cause_step && <Text size="sm">{t('deployments.causeStep', { step: t(stepNameKey(d.cause_step)) })}</Text>}
                {d.helper_error && <Text size="sm">{t('deployments.stepDetail.error', { reason: t(configErrorKey(d.helper_error)) })}</Text>}
              </Stack>
            </Panel>
          )}
        </div>
      </div>
    </Stack>
  );
}
