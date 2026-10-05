import { Alert, Anchor, Button, Code, Group, Stack, Table, Text, Title, VisuallyHidden } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { deleteBinding, getBinding, runAccessCheck, updateBindingLocations, type Binding, type KVCertificateDetail } from '../api/keyvault';
import { BINDINGS_KEY, bindingKey, KV_CERTIFICATES_KEY, TARGETS_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { JobError } from '../api/types';
import { AppModal } from './AppModal';
import { LoadingIndicator } from './LoadingIndicator';
import { AutoDeploySwitch } from './AutoDeploySwitch';
import { CodeText } from './CodeText';
import { ConnectWebsitesDialog } from './ConnectWebsitesDialog';
import { ErrorAlert } from './ErrorAlert';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert, StoppedJobAlert } from './JobErrorAlert';
import { KVDeployDialog } from './KVDeployDialog';
import { ROLE_SECRETS_USER } from './roleCommands';
import { shortVersion } from './vaultText';
import { WRAP } from './wrap';

// BindingPanel is "Connected websites" of a vault certificate: which websites follow it and their
// state, automatic deployment, whether Alice may read the certificate's secret, and Deploy now.
// Operators and Administrators connect, add, remove and deploy; only an Administrator switches
// automatic deployment (and adds websites to a connection that deploys by itself).
export function BindingPanel({ vaultId, certificate, canOperate, admin }: { vaultId: string; certificate: KVCertificateDetail; canOperate: boolean; admin: boolean }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const summary = certificate.binding;
  const [connecting, setConnecting] = useState(false);
  const [adding, setAdding] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const binding = useQuery({ queryKey: bindingKey(summary?.id ?? ''), queryFn: () => getBinding(summary?.id ?? ''), enabled: summary !== null });
  const refresh = () => {
    void client.invalidateQueries({ queryKey: BINDINGS_KEY });
    void client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY });
  };

  const heading = (
    <Title order={2} size="h3">
      {t('bindings.title')}
    </Title>
  );

  if (summary === null) {
    const monitorOnly = certificate.exportable === false;
    return (
      <Stack gap="sm" data-testid="binding-panel">
        {heading}
        <Text size="sm">{t('bindings.none')}</Text>
        {monitorOnly && <Text size="sm">{t('bindings.connectNeedsExport')}</Text>}
        {canOperate && (
          <Button w="fit-content" disabled={monitorOnly || certificate.missing_since !== null} onClick={() => setConnecting(true)}>
            {t('bindings.connect')}
          </Button>
        )}
        {connecting && (
          <ConnectWebsitesDialog
            certificate={certificate}
            onClose={() => setConnecting(false)}
            onDone={() => {
              setConnecting(false);
              refresh();
            }}
          />
        )}
      </Stack>
    );
  }

  if (binding.isPending) return <LoadingIndicator />;
  if (!binding.data)
    return (
      <Stack gap="sm">
        {heading}
        <ErrorAlert error={binding.error} />
      </Stack>
    );
  const b = binding.data;
  return (
    <Stack gap="sm" data-testid="binding-panel">
      {heading}
      <Table.ScrollContainer minWidth={560}>
        <Table striped aria-label={t('bindings.title')}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('bindings.columns.server')}</Table.Th>
              <Table.Th>{t('bindings.columns.path')}</Table.Th>
              <Table.Th>{t('bindings.columns.state')}</Table.Th>
              {canOperate && (
                <Table.Th>
                  <VisuallyHidden>{t('bindings.columns.actions')}</VisuallyHidden>
                </Table.Th>
              )}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {b.locations.map((l) => (
              <Table.Tr key={l.location_id} data-testid="binding-location">
                <Table.Td style={WRAP}>
                  <Anchor component={Link} to={`/servers/${l.target_id}`} translate="no">
                    {l.target_name}
                  </Anchor>
                </Table.Td>
                <Table.Td>
                  <Code translate="no" style={WRAP}>
                    {l.cert_path}
                  </Code>
                </Table.Td>
                <Table.Td>
                  <Stack gap={2}>
                    <Text size="sm" data-state={l.state}>
                      {l.state === 'deployed' ? <CodeText i18nKey="bindings.state.deployed" param="version" value={shortVersion(l.version)} /> : t(`bindings.state.${l.state}`)}
                    </Text>
                    {l.deployment_id && (
                      <Anchor component={Link} to={`/deployments/${l.deployment_id}`} size="xs">
                        {t('deploy.openDeployment')}
                      </Anchor>
                    )}
                  </Stack>
                </Table.Td>
                {canOperate && (
                  <Table.Td>
                    <RemoveWebsite binding={b} locationId={l.location_id} name={l.target_name} onDone={refresh} />
                  </Table.Td>
                )}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {b.stopped_version !== '' && (
        <Alert color="orange" role="status" data-testid="stopped-help">
          <CodeText i18nKey="bindings.stoppedHelp" param="version" value={shortVersion(b.stopped_version)} />
        </Alert>
      )}
      <AutoDeploySwitch binding={b} admin={admin} exportable={certificate.exportable} onChanged={refresh} />
      <DeployAccess vaultId={vaultId} certificate={certificate} canOperate={canOperate} />
      {canOperate && (
        <Group gap="sm">
          <Button onClick={() => setDeploying(true)}>{t('bindings.deployNow')}</Button>
          <Button variant="default" disabled={b.auto_deploy && !admin} onClick={() => setAdding(true)}>
            {t('bindings.addWebsites')}
          </Button>
          <Button variant="light" color="red.9" onClick={() => setDeleting(true)}>
            {t('bindings.delete')}
          </Button>
        </Group>
      )}
      {b.auto_deploy && !admin && <Text size="sm">{t('bindings.addAdminOnly')}</Text>}
      {deploying && <KVDeployDialog binding={b} certificate={certificate} onClose={() => setDeploying(false)} />}
      {adding && (
        <ConnectWebsitesDialog
          certificate={certificate}
          binding={b}
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            refresh();
          }}
        />
      )}
      {deleting && (
        <DeleteBindingDialog
          binding={b}
          onClose={() => setDeleting(false)}
          onDeleted={() => {
            setDeleting(false);
            refresh();
          }}
        />
      )}
    </Stack>
  );
}

// DeployAccess says whether Alice may read this certificate's secret (the role Key Vault Secrets User);
// until something proved it, one button runs the access check with this certificate.
function DeployAccess({ vaultId, certificate, canOperate }: { vaultId: string; certificate: KVCertificateDetail; canOperate: boolean }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const abort = useAbort();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const run = async () => {
    setBusy(true);
    setError(null);
    setJobError(null);
    setBlocked(false);
    setStopped(false);
    try {
      const job = await waitForJob((await runAccessCheck(vaultId, certificate.id)).job_id, { signal: abort.signal() });
      if (job.status === 'blocked_license') setBlocked(true);
      else if (job.status !== 'succeeded') {
        if (job.error) setJobError(job.error);
        else setStopped(true);
      }
    } catch (e) {
      if (!isAbort(e)) setError(e);
    }
    setBusy(false);
    await Promise.all([client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY }), client.invalidateQueries({ queryKey: TARGETS_KEY })]);
  };
  return (
    <Stack gap={4} data-testid="deploy-access">
      {certificate.deploy_access === 'ok' && <Text size="sm">{t('bindings.deployAccessOk')}</Text>}
      {certificate.deploy_access === 'forbidden' && (
        <Text size="sm">
          <CodeText i18nKey="vaults.access.forbidden" param="role" value={ROLE_SECRETS_USER} />
        </Text>
      )}
      {certificate.deploy_access === 'not_checked' && <Text size="sm">{t('bindings.deployAccessUnchecked')}</Text>}
      {canOperate && certificate.deploy_access !== 'ok' && (
        <Button size="xs" variant="default" w="fit-content" loading={busy} onClick={() => void run()}>
          {t('bindings.checkDeployAccess')}
        </Button>
      )}
      {error instanceof JobTimeoutError ? <StillWorkingAlert textKey="vaults.stillWorking" /> : <ErrorAlert error={error} />}
      {blocked && <BlockedJobAlert />}
      {stopped && <StoppedJobAlert />}
      <JobErrorAlert error={jobError} />
    </Stack>
  );
}

function RemoveWebsite({ binding, locationId, name, onDone }: { binding: Binding; locationId: string; name: string; onDone: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const last = binding.locations.length <= 1;
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await updateBindingLocations(binding.id, binding.version, binding.locations.filter((l) => l.location_id !== locationId).map((l) => l.location_id));
      onDone();
    } catch (e) {
      setError(e);
      onDone();
    }
    setBusy(false);
  };
  return (
    <Stack gap={2}>
      <Button size="xs" variant="light" color="red.9" loading={busy} disabled={last} aria-label={t('bindings.removeNamed', { site: name })} onClick={() => void remove()}>
        {t('bindings.removeWebsite')}
      </Button>
      {last && <Text size="xs">{t('bindings.lastWebsite')}</Text>}
      <ErrorAlert error={error} />
    </Stack>
  );
}

function DeleteBindingDialog({ binding, onClose, onDeleted }: { binding: Binding; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await deleteBinding(binding.id);
      onDeleted();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={onClose} title={t('bindings.deleteTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('bindings.deleteHelp')}</Text>
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red.9" loading={busy} onClick={() => void confirm()}>
            {t('bindings.delete')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
