import { Button, Checkbox, Group, Loader, NativeSelect, Stack, Table, Text } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listKVCertificates, runAccessCheck, type AccessCheckRow, type AccessResult, type AzureRole, type VaultAccess } from '../api/keyvault';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { KV_CERTIFICATES_KEY, kvListKey, TARGETS_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { JobError } from '../api/types';
import { formatDateTime } from '../datetime';
import { CodeText } from './CodeText';
import { ErrorAlert } from './ErrorAlert';
import { LoadingIndicator } from './LoadingIndicator';
import { BlockedJobAlert, JobErrorAlert, reasonTitle, StillWorkingAlert, StoppedJobAlert } from './JobErrorAlert';
import { ROLE_CERTIFICATES_OFFICER, ROLE_READER, ROLE_SECRETS_USER } from './roleCommands';
import { Icon } from '../design/Icon';
import { Panel, StatusBadge } from './ui';

export type RowId = 'monitor' | 'deploy' | 'import';
export interface CheckRow {
  id: RowId;
  result: AccessResult;
  role: AzureRole;
  error: AccessCheckRow['error'];
}

const DEFAULT_ROLE: Record<RowId, AzureRole> = { monitor: ROLE_READER, deploy: ROLE_SECRETS_USER, import: ROLE_CERTIFICATES_OFFICER };
const ORDER = ['forbidden', 'failed', 'ok', 'not_checked'] as const;

// accessRows folds the access check into the three questions people ask: can Alice monitor the vault
// (list certificates, keys and secrets), deploy from it (read a certificate's secret) and import into it.
// Monitoring is as good as its worst answer; an unanswered question is "not checked".
export function accessRows(access: VaultAccess | null): CheckRow[] {
  const find = (names: string[]) => (access?.checks ?? []).filter((c) => names.includes(c.name));
  const fold = (id: RowId, rows: AccessCheckRow[]): CheckRow => {
    if (rows.length === 0) return { id, result: 'not_checked', role: '', error: null };
    for (const r of ORDER) {
      const hit = rows.find((c) => c.result === r);
      if (hit) {
        const allOk = r === 'ok' && rows.some((c) => c.result === 'not_checked');
        const result = allOk ? 'not_checked' : r;
        return { id, result, role: result === 'forbidden' ? hit.role || DEFAULT_ROLE[id] : '', error: hit.error };
      }
    }
    return { id, result: 'not_checked', role: '', error: null };
  };
  return [fold('monitor', find(['list_certificates', 'list_keys', 'list_secrets'])), fold('deploy', find(['read_secret'])), fold('import', find(['import']))];
}

function Result({ row }: { row: CheckRow }) {
  const { t, i18n } = useTranslation();
  if (row.result === 'ok')
    return (
      <StatusBadge tone="success" icon="CircleCheck">
        {t('vaults.access.ok')}
      </StatusBadge>
    );
  if (row.result === 'forbidden')
    return (
      <Text size="sm">
        <CodeText i18nKey="vaults.access.forbidden" param="role" value={row.role || DEFAULT_ROLE[row.id]} />
      </Text>
    );
  if (row.result === 'failed')
    return (
      <Stack gap={4} align="flex-start">
        <StatusBadge tone="danger" icon="CircleAlert">
          {t('vaults.access.failed')}
        </StatusBadge>
        {row.error && <Text size="xs">{reasonTitle(t, i18n, row.error.reason, row.error.params ?? {})}</Text>}
      </Stack>
    );
  return (
    <Text size="sm" c="dimmed">
      {t(row.id === 'import' ? 'vaults.access.importNote' : 'vaults.access.notChecked')}
    </Text>
  );
}

// AccessChecklist is the three rows (monitor, deploy, import) with what Alice may do.
export function AccessChecklist({ access }: { access: VaultAccess | null }) {
  const { t, i18n } = useTranslation();
  const rows = accessRows(access);
  return (
    <Stack gap="xs">
      {!access && <Text size="sm">{t('vaults.access.none')}</Text>}
      <Table.ScrollContainer minWidth={420}>
        <Table aria-label={t('vaults.access.title')}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('vaults.access.what')}</Table.Th>
              <Table.Th>{t('vaults.access.result')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.id} data-access-row={r.id} data-result={r.result}>
                <Table.Td>{t(`vaults.roles.${r.id}`)}</Table.Td>
                <Table.Td>
                  <Result row={r} />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {access && (
        <Text size="xs" c="dimmed">
          {t('vaults.access.checkedAt', { time: formatDateTime(access.checked_at, i18n.language) })}
        </Text>
      )}
    </Stack>
  );
}

// AccessCheckPanel is the "Access check" panel of a vault: the checklist, and for Administrators and
// Operators "Check again" (a job; the panel waits for it) with the option to also read one
// certificate's secret once, which is what proves the deploy role.
export function AccessCheckPanel({ vaultId, access, canOperate, certificateId }: { vaultId: string; access: VaultAccess | null; canOperate: boolean; certificateId?: string }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const abort = useAbort();
  const [deployToo, setDeployToo] = useState(certificateId !== undefined);
  const [picked, setPicked] = useState(certificateId ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [done, setDone] = useState(false);

  const certs = useQuery({
    queryKey: [...kvListKey(vaultId, 'certificates'), 'access-check'],
    queryFn: () => listKVCertificates(vaultId, { limit: 200 }),
    enabled: deployToo && certificateId === undefined,
  });
  const usable = (certs.data?.items ?? []).filter((c) => c.exportable !== false && c.current_version !== '' && c.missing_since === null);

  const run = async () => {
    setBusy(true);
    setError(null);
    setJobError(null);
    setBlocked(false);
    setStopped(false);
    setDone(false);
    try {
      const accepted = await runAccessCheck(vaultId, deployToo && picked ? picked : undefined);
      const job = await waitForJob(accepted.job_id, { signal: abort.signal() });
      if (job.status === 'succeeded') setDone(true);
      else if (job.status === 'blocked_license') setBlocked(true);
      else if (job.error) setJobError(job.error);
      else setStopped(true);
    } catch (e) {
      if (!isAbort(e)) setError(e);
    }
    setBusy(false);
    await Promise.all([client.invalidateQueries({ queryKey: TARGETS_KEY }), client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY })]);
  };

  return (
    <Panel title={t('vaults.access.title')} testId="access-check">
      <Stack gap="sm">
        <AccessChecklist access={access} />
        {canOperate && (
          <Stack gap="xs">
            {certificateId === undefined && <Checkbox label={t('vaults.access.deployToo')} checked={deployToo} onChange={(e) => setDeployToo(e.currentTarget.checked)} disabled={busy} />}
            {deployToo && certificateId === undefined && (
              <>
                {certs.isPending && <LoadingIndicator />}
                <ErrorAlert error={certs.error} />
                {certs.isSuccess && usable.length === 0 && <Text size="sm">{t('vaults.access.noExportable')}</Text>}
                {usable.length > 0 && (
                  <NativeSelect
                    label={t('vaults.access.pickCertificate')}
                    value={picked}
                    onChange={(e) => setPicked(e.currentTarget.value)}
                    data={[{ value: '', label: t('vaults.access.chooseCertificate') }, ...usable.map((c) => ({ value: c.id, label: c.name }))]}
                    disabled={busy}
                  />
                )}
              </>
            )}
            <Group>
              <Button variant="default" leftSection={<Icon name="RefreshCw" size={15} />} loading={busy} disabled={deployToo && picked === ''} onClick={() => void run()}>
                {t('vaults.access.run')}
              </Button>
            </Group>
          </Stack>
        )}
        {busy && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('vaults.access.working')}</Text>
          </Group>
        )}
        {done && (
          <Text size="sm" role="status">
            {t('targets.jobDone')}
          </Text>
        )}
        {error instanceof JobTimeoutError ? <StillWorkingAlert textKey="vaults.stillWorking" /> : <ErrorAlert error={error} />}
        {blocked && <BlockedJobAlert />}
        {stopped && <StoppedJobAlert />}
        <JobErrorAlert error={jobError} />
      </Stack>
    </Panel>
  );
}
