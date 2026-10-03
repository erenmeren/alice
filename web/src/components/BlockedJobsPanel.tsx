import { Button, Card, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { confirmJob, discardJob, listJobs } from '../api/endpoints';
import { BLOCKED_JOBS_KEY, SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { Job } from '../api/types';
import { formatDateTime } from '../datetime';
import { ErrorAlert } from './ErrorAlert';

// BlockedJobsPanel lists changes that were paused while the license was expired. After a renewal
// they never start on their own: an Administrator runs or discards each one (R29, L-81).
export function BlockedJobsPanel() {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const jobs = useQuery({ queryKey: BLOCKED_JOBS_KEY, queryFn: () => listJobs({ status: 'blocked_license' }) });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const typeLabel = (job: Job) => (i18n.exists(`jobs.types.${job.type}`) ? t(`jobs.types.${job.type}`) : job.type);
  const act = async (job: Job, fn: (id: string) => Promise<Job>) => {
    setBusy(job.id);
    setError(null);
    try {
      await fn(job.id);
      // Running or discarding a change moves a server or a key, so those lists are read again too.
      await Promise.all([BLOCKED_JOBS_KEY, TARGETS_KEY, SSH_KEYS_KEY].map((queryKey) => client.invalidateQueries({ queryKey })));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  if (!jobs.data || jobs.data.items.length === 0) return null;
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
              {jobs.data.items.map((job) => (
                <Table.Tr key={job.id}>
                  <Table.Td>{typeLabel(job)}</Table.Td>
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
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Stack>
    </Card>
  );
}
