import { Anchor, Badge, Button, Group, Stack, Switch, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { policyKey, ROTATION_RUNS_KEY, sshKey } from '../api/queryKeys';
import { deletePolicy, disablePolicy, enablePolicy, getPolicy, listRuns, type Policy } from '../api/rotation';
import { formatDateTime } from '../datetime';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { ReasonAlert, durationText, labelOf } from './rotationText';
import { RotationPolicyDialog } from './RotationPolicyDialog';
import { RotationPreviewDialog } from './RotationPreviewDialog';
import { useStepUp } from './StepUpProvider';

type Dialog = 'create' | 'edit' | 'preview' | 'delete' | null;

// RotationPolicyPanel is the automatic rotation of one generated key: its policy (or the offer to create one), the
// switch, the preview, Run now, and the earlier runs. Administrators change things; everybody else reads. Switching a
// policy on needs the Administrator's fresh code (the enable route), switching it off does not.
export function RotationPolicyPanel({ keyId, policyId, isAdmin }: { keyId: string; policyId: string | null; isAdmin: boolean }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const navigate = useNavigate();
  const { run } = useStepUp();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const policy = useQuery({ queryKey: policyKey(policyId ?? ''), queryFn: () => getPolicy(policyId as string), enabled: policyId !== null });
  const runs = useQuery({ queryKey: [...ROTATION_RUNS_KEY, 'key', keyId], queryFn: () => listRuns({ ssh_key_id: keyId, limit: 10 }) });
  const p = policy.data;
  // A previewed (planned) run is started by Run now; only a run that is already going blocks it.
  const open = p?.open_rotation_id ? runs.data?.items.find((r) => r.id === p.open_rotation_id) : undefined;
  const started = open !== undefined && open.status !== 'dry_run_notified';
  const [deleting, setDeleting] = useState(false);

  const refresh = () => {
    if (policyId) void client.invalidateQueries({ queryKey: policyKey(policyId) });
    void client.invalidateQueries({ queryKey: sshKey(keyId) });
    // Switching off or editing cancels a planned run, so the runs are read again.
    void client.invalidateQueries({ queryKey: ROTATION_RUNS_KEY });
  };

  const toggle = async (p: Policy, on: boolean) => {
    setSwitching(true);
    setError(null);
    try {
      await (on ? run(() => enablePolicy(p.id, p.version)) : disablePolicy(p.id, p.version));
    } catch (e) {
      setError(e);
    }
    refresh();
    setSwitching(false);
  };

  const remove = async (p: Policy) => {
    setError(null);
    setDeleting(true);
    try {
      await deletePolicy(p.id, p.version);
      setDialog(null);
      void client.invalidateQueries({ queryKey: sshKey(keyId) });
      void client.invalidateQueries({ queryKey: ROTATION_RUNS_KEY });
    } catch (e) {
      setError(e);
      setDialog(null);
      refresh();
    }
    setDeleting(false);
  };

  return (
    <Stack gap="sm" data-testid="rotation-panel">
      <Title order={2} size="h4">
        {t('rotation.title')}
      </Title>
      {policyId === null && (
        <>
          <Text size="sm">{t('rotation.none')}</Text>
          {isAdmin && (
            <Button w="fit-content" size="xs" onClick={() => setDialog('create')}>
              {t('rotation.create')}
            </Button>
          )}
        </>
      )}
      {policyId !== null && policy.isError && <ErrorAlert error={policy.error} />}
      {p && (
        <Stack gap="xs">
          <Text size="sm" fw={600} translate="no">
            {p.name}
          </Text>
          <Text size="sm">{p.interval_days === 1 ? t('rotation.everyDay') : t('rotation.every', { count: p.interval_days })}</Text>
          <Text size="sm">{t('rotation.overlap', { duration: durationText(t, p.overlap_minutes) })}</Text>
          <Text size="sm">{t('rotation.notifyBefore', { hours: p.notify_before_hours })}</Text>
          <Switch
            label={t('rotation.switch')}
            checked={p.enabled}
            onChange={(e) => void toggle(p, e.currentTarget.checked)}
            disabled={!isAdmin || switching}
            onLabel={t('rotation.on')}
            offLabel={t('rotation.off')}
          />
          {!p.enabled && <Text size="sm">{t('rotation.offHelp')}</Text>}
          {p.enabled && p.next_run_at && <Text size="sm">{t('rotation.nextRun', { date: formatDateTime(p.next_run_at, i18n.language) })}</Text>}
          {p.last_run_status && (
            <Stack gap={4}>
              <Text size="xs" c="gray.7">
                {t('rotation.lastRunHelp')}
              </Text>
              <Text size="sm">{t('rotation.lastRun', { status: labelOf(t, i18n, 'rotation.status', p.last_run_status) })}</Text>
              {p.last_run_result && <ReasonAlert error={p.last_run_result} color="yellow" />}
              {p.last_run_id && (
                <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(p.last_run_id)}`} size="sm" w="fit-content">
                  {t('rotation.openLastRun')}
                </Anchor>
              )}
            </Stack>
          )}
          {p.open_rotation_id && (
            <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(p.open_rotation_id)}`} size="sm" w="fit-content">
              {t('rotation.openRun')}
            </Anchor>
          )}
          {isAdmin && (
            <Group gap="sm">
              <Button size="xs" variant="default" onClick={() => setDialog('preview')}>
                {t('rotation.preview')}
              </Button>
              <Button size="xs" onClick={() => setDialog('preview')} disabled={started}>
                {t('rotation.runNow')}
              </Button>
              <Button size="xs" variant="default" onClick={() => setDialog('edit')}>
                {t('rotation.edit')}
              </Button>
              <Button size="xs" variant="light" color="red.9" onClick={() => setDialog('delete')}>
                {t('rotation.delete')}
              </Button>
            </Group>
          )}
        </Stack>
      )}
      <ErrorAlert error={error} />
      {runs.data && runs.data.items.length > 0 && (
        <Stack gap="xs">
          <Title order={3} size="h5">
            {t('rotation.history')}
          </Title>
          <Table.ScrollContainer minWidth={360}>
            <Table aria-label={t('rotation.history')}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('rotation.col.planned')}</Table.Th>
                  <Table.Th>{t('rotation.col.state')}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {runs.data.items.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>{formatDateTime(r.planned_for, i18n.language)}</Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={r.status === 'completed' ? 'green' : r.status === 'needs_attention' ? 'orange' : 'gray'} tt="none">
                        {labelOf(t, i18n, 'rotation.status', r.status)}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(r.id)}`}>
                        {t('rotation.openRunLink')}
                      </Anchor>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}
      {dialog === 'create' && <RotationPolicyDialog keyId={keyId} policy={null} onClose={() => setDialog(null)} />}
      {dialog === 'edit' && p && <RotationPolicyDialog keyId={keyId} policy={p} onClose={() => setDialog(null)} />}
      {dialog === 'preview' && p && (
        <RotationPreviewDialog
          policy={p}
          onClose={() => setDialog(null)}
          onStarted={(id) => {
            setDialog(null);
            refresh();
            void client.invalidateQueries({ queryKey: ROTATION_RUNS_KEY });
            void navigate(`/rotation/runs/${encodeURIComponent(id)}`);
          }}
        />
      )}
      {dialog === 'delete' && p && (
        <AppModal opened onClose={() => setDialog(null)} title={t('rotation.delete')}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.deleteConfirm')}</Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setDialog(null)}>
                {t('ui.cancel')}
              </Button>
              <Button color="red.9" loading={deleting} onClick={() => void remove(p)}>
                {t('rotation.delete')}
              </Button>
            </Group>
          </Stack>
        </AppModal>
      )}
    </Stack>
  );
}
