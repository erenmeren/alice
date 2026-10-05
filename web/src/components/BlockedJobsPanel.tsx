import { Button, Card, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useInfiniteQuery, useQueries, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { wasSent } from '../api/deployments';
import { confirmJob, discardJob, getDeployment, listDeployments, listJobs } from '../api/endpoints';
import { BLOCKED_JOBS_KEY, deploymentKey, DEPLOYMENTS_KEY, SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { Deployment, Job } from '../api/types';
import { formatDateTime } from '../datetime';
import { ErrorAlert } from './ErrorAlert';
import { InternalLink } from './InternalLink';

// DEPLOY_JOB is the job type of a deployment (internal/inventory/jobs.go JobCertificateDeploy).
const DEPLOY_JOB = 'certificate.deploy';
// IMPORT_JOB is the job type of an import into a vault (JobKVImport); its target is the vault.
const IMPORT_JOB = 'kv.import';
// The deployments of a server read to find the one a held job belongs to (the newest first; a held
// job's deployment is among the recent ones).
const DEPLOYMENTS_PER_SERVER = 200;

// BlockedJobsPanel lists changes that were paused while the license was expired. After a renewal
// they never start on their own: an Administrator runs or discards each one (R29, L-81). Every held
// job can be reached (AUD-25 d): the list is read a page at a time (the API's default page size)
// and "Show more" reads the next page while the server reports one.
export function BlockedJobsPanel() {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const jobs = useInfiniteQuery({
    queryKey: BLOCKED_JOBS_KEY,
    queryFn: ({ pageParam }) => listJobs({ status: 'blocked_license', cursor: pageParam ?? undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const items = jobs.data?.pages.flatMap((p) => p.items) ?? [];
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // A held deployment job may belong to a deployment that was already sent and is being recovered
  // by a job of its own (the API reports the original job's status): discarding it then undoes
  // nothing, so the row says so. The job does not name its deployment; the deployments of its server
  // do (job_id).
  // A job that names its deployment (deployment_id) needs no search: that deployment is read by its id.
  const deployTargets = [...new Set(items.filter((j) => j.type === DEPLOY_JOB && j.target_id && !j.deployment_id).map((j) => j.target_id as string))];
  const namedIds = [...new Set(items.filter((j) => j.type === DEPLOY_JOB && j.deployment_id).map((j) => j.deployment_id as string))];
  const named = useQueries({
    queries: namedIds.map((id) => ({ queryKey: deploymentKey(id), queryFn: () => getDeployment(id), retry: false })),
  });
  const deployments = useQueries({
    queries: deployTargets.map((target) => ({
      queryKey: [...DEPLOYMENTS_KEY, { target_id: target, limit: DEPLOYMENTS_PER_SERVER }],
      queryFn: () => listDeployments({ target_id: target, limit: DEPLOYMENTS_PER_SERVER }),
    })),
  });
  const deploymentOf = (job: Job): Deployment | undefined => {
    if (job.deployment_id) return named[namedIds.indexOf(job.deployment_id)]?.data;
    for (const q of deployments) {
      const d = q.data?.items.find((x) => x.job_id === job.id);
      if (d) return d;
    }
    return undefined;
  };

  const typeLabel = (job: Job) => (i18n.exists(`jobs.types.${job.type}`) ? t(`jobs.types.${job.type}`) : job.type);
  const act = async (job: Job, fn: (id: string) => Promise<Job>) => {
    setBusy(job.id);
    setError(null);
    try {
      await fn(job.id);
      // Running or discarding a change moves a server or a key, so those lists are read again too.
      await Promise.all([BLOCKED_JOBS_KEY, TARGETS_KEY, SSH_KEYS_KEY, DEPLOYMENTS_KEY].map((queryKey) => client.invalidateQueries({ queryKey })));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  if (items.length === 0) return null;
  return (
    <Card withBorder padding="md" data-testid="blocked-jobs">
      <Stack gap="xs">
        <Title order={2} size="h3">
          {t('jobs.blockedTitle')}
        </Title>
        <Text size="sm">{t('jobs.blockedHelp')}</Text>
        <ErrorAlert error={error} />
        <Table.ScrollContainer minWidth={480}>
          <Table>
            <Table.Tbody>
              {items.map((job) => {
                const dep = job.type === DEPLOY_JOB ? deploymentOf(job) : undefined;
                const depId = dep?.id ?? (job.type === DEPLOY_JOB ? job.deployment_id : null);
                const vault = job.type === IMPORT_JOB && job.import_id ? job.target_id : null;
                return (
                <Table.Tr key={job.id} data-testid="blocked-job">
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="sm">{typeLabel(job)}</Text>
                      {dep && (
                        <Text size="xs" data-sent={wasSent(dep) ? 'true' : 'false'}>
                          {t(wasSent(dep) ? 'jobs.deploymentSent' : 'jobs.deploymentNotSent')}
                        </Text>
                      )}
                      {depId && (
                        <InternalLink to={`/deployments/${depId}`} size="xs">
                          {t('deploy.openDeployment')}
                        </InternalLink>
                      )}
                      {vault && (
                        <InternalLink to={`/key-vaults/${vault}`} size="xs">
                          {t('vaults.openVault')}
                        </InternalLink>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>{t('jobs.created', { time: formatDateTime(job.created_at, i18n.language) })}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" wrap="nowrap">
                      <Button size="xs" loading={busy === job.id} onClick={() => void act(job, confirmJob)} aria-label={t('jobs.runNowNamed', { job: typeLabel(job) })}>
                        {t('jobs.runNow')}
                      </Button>
                      <Button size="xs" variant="default" disabled={busy === job.id} onClick={() => void act(job, discardJob)} aria-label={t('jobs.discardNamed', { job: typeLabel(job) })}>
                        {t('jobs.discard')}
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {jobs.hasNextPage && (
          <Button variant="default" w="fit-content" onClick={() => void jobs.fetchNextPage()} loading={jobs.isFetchingNextPage}>
            {t('jobs.blockedShowMore')}
          </Button>
        )}
      </Stack>
    </Card>
  );
}
