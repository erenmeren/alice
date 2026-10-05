import { Alert, Anchor, Button, Code, Group, Loader, NumberInput, Stack, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useNavigate, useParams } from 'react-router';
import { getTarget } from '../api/endpoints';
import { isApiError } from '../api/client';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { checkVaultNow, deleteVault, updateVaultInterval } from '../api/keyvault';
import { KV_CERTIFICATES_KEY, TARGETS_KEY, targetKey } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { JobError, Target } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { AccessCheckPanel } from '../components/AccessCheckPanel';
import { AppModal } from '../components/AppModal';
import { CodeText } from '../components/CodeText';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry, expiryState, useNow } from '../components/Expiry';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert, StoppedJobAlert } from '../components/JobErrorAlert';
import { ReplaceCredentialsDialog } from '../components/ReplaceCredentialsDialog';
import { RoleGuide } from '../components/RoleGuide';
import { useStepUp } from '../components/StepUpProvider';
import { VaultInventory } from '../components/VaultInventory';
import { warningKey } from '../api/warnings';
import { authKey } from '../components/vaultText';
import { VaultStatusBadge } from '../components/VaultStatusBadge';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Group gap="xs" align="baseline" wrap="wrap">
      <Text size="sm" fw={600}>
        {label}
      </Text>
      {children}
    </Group>
  );
}

// KeyVaultDetailPage is one vault: its status in words, how Alice signs in, the access check with the
// roles to grant, and the actions people may run (Check now for Administrators and Operators; replace
// the credentials, the check interval and removal for Administrators).
export function KeyVaultDetailPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const navigate = useNavigate();
  const client = useQueryClient();
  const now = useNow();
  const role = session?.user.role;
  const admin = role === 'admin';
  const canOperate = admin || role === 'operator';
  const abort = useAbort();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [replacing, setReplacing] = useState(false);
  const [replaced, setReplaced] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const target = useQuery({
    queryKey: targetKey(id),
    queryFn: () => getTarget(id),
    // Follow a vault only while it is being checked or a job started here is pending.
    refetchInterval: (q) => (q.state.data?.status === 'checking' || busy ? 3000 : false),
  });

  const refresh = async () => {
    await Promise.all([client.invalidateQueries({ queryKey: TARGETS_KEY }), client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY }), client.invalidateQueries({ queryKey: ['kv'] })]);
  };

  const checkNow = async () => {
    setBusy(true);
    setError(null);
    setJobError(null);
    setDone(false);
    setBlocked(false);
    setStopped(false);
    try {
      const job = await waitForJob((await checkVaultNow(id)).job_id, { signal: abort.signal() });
      if (job.status === 'succeeded') setDone(true);
      else if (job.status === 'blocked_license') setBlocked(true);
      else if (job.error) setJobError(job.error);
      else setStopped(true);
    } catch (e) {
      if (!isAbort(e)) setError(e);
    }
    setBusy(false);
    await refresh();
  };

  if (target.isPending) return <PageLoader />;
  if (target.isError || !target.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={target.error} />
        <Anchor component={Link} to="/key-vaults" w="fit-content">
          {t('vaults.backToList')}
        </Anchor>
      </Stack>
    );
  const tg: Target = target.data;
  if (tg.type !== 'azure_key_vault' || !tg.vault) return <Navigate to={`/servers/${id}`} replace />;
  const v = tg.vault;
  const credentialsEnd = v.auth === 'client_secret' ? v.secret_expires_on : v.auth === 'certificate' ? v.cert_not_after : null;
  const endState = credentialsEnd ? expiryState(credentialsEnd, now) : 'ok';
  const statusHelp = ['degraded', 'auth_failed', 'unreachable', 'checking', 'disabled'].includes(tg.status) ? `vaults.statusHelp.${tg.status}` : null;

  return (
    <Stack gap="md">
      <Anchor component={Link} to="/key-vaults" w="fit-content" size="sm">
        {t('vaults.backToList')}
      </Anchor>
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Title order={1} style={WRAP}>
            {tg.name}
          </Title>
          <Code translate="no" style={WRAP}>
            {v.url}
          </Code>
        </Stack>
        <VaultStatusBadge target={tg} testId="vault-status" />
      </Group>
      {statusHelp && (
        <Text size="sm" data-testid="vault-status-help">
          {t(statusHelp)}
        </Text>
      )}
      {tg.last_error && <JobErrorAlert error={tg.last_error} />}
      {credentialsEnd && endState !== 'ok' && endState !== 'within60' && (
        <Alert color={endState === 'expired' ? 'red' : 'yellow'} role="status" data-testid="credentials-expiry">
          {t(endState === 'expired' ? 'vaults.credentialsExpiredNow' : 'vaults.credentialsExpireSoon')}
        </Alert>
      )}
      <Stack gap={4} role="group" aria-label={t('vaults.title')}>
        <Fact label={t('vaults.fields.auth')}>
          <Text size="sm">{t(authKey(v.auth))}</Text>
        </Fact>
        {v.tenant_id !== '' && (
          <Fact label={t('vaults.fields.tenant_id')}>
            <Code translate="no" style={WRAP}>
              {v.tenant_id}
            </Code>
          </Fact>
        )}
        {v.client_id !== '' && (
          <Fact label={t('vaults.fields.client_id')}>
            <Code translate="no" style={WRAP}>
              {v.client_id}
            </Code>
          </Fact>
        )}
        {v.auth === 'certificate' && v.cert_thumbprint !== '' && (
          <Fact label={t('vaults.certThumbprint')}>
            <Code translate="no" style={WRAP}>
              {v.cert_thumbprint}
            </Code>
          </Fact>
        )}
        {v.auth === 'certificate' && v.cert_not_after && (
          <Fact label={t('vaults.certExpires')}>
            <Expiry notAfter={v.cert_not_after} />
          </Fact>
        )}
        {v.auth === 'client_secret' && v.secret_expires_on && (
          <Fact label={t('vaults.secretExpires')}>
            <Expiry notAfter={v.secret_expires_on} />
          </Fact>
        )}
        {v.access && v.access.object_id !== '' && (
          <Text size="sm">
            <CodeText i18nKey="vaults.signsInAs" param="objectId" value={v.access.object_id} />
          </Text>
        )}
        <Text size="sm">{tg.last_success_at ? t('vaults.lastChecked', { time: formatDateTime(tg.last_success_at, i18n.language) }) : t('vaults.neverChecked')}</Text>
      </Stack>
      <PollInterval target={tg} editable={admin} />
      {canOperate && (
        <Group gap="sm">
          <Button variant="default" disabled={busy} onClick={() => void checkNow()}>
            {t('vaults.checkNow')}
          </Button>
          {admin && (
            <Button variant="default" disabled={busy} onClick={() => setReplacing(true)}>
              {t('vaults.replaceCredentials')}
            </Button>
          )}
          {admin && (
            <Button variant="light" color="red.9" disabled={busy} onClick={() => setDeleting(true)}>
              {t('vaults.delete')}
            </Button>
          )}
        </Group>
      )}
      {busy && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('targets.working')}</Text>
        </Group>
      )}
      {done && (
        <Text size="sm" role="status">
          {t('targets.jobDone')}
        </Text>
      )}
      {replaced && (
        <Alert color="green" role="status">
          {t('vaults.replaced')}
        </Alert>
      )}
      {error instanceof JobTimeoutError ? <StillWorkingAlert textKey="vaults.stillWorking" /> : <ErrorAlert error={error} />}
      {blocked && <BlockedJobAlert />}
      {stopped && <StoppedJobAlert />}
      <JobErrorAlert error={jobError} />

      {tg.facts.warnings.map((w) => (
        <Alert key={`${w.code}-${JSON.stringify(w.params)}`} color="yellow" style={WRAP} data-testid="vault-warning">
          {t(warningKey(w), { ...w.params, ...(w.params.object ? { object: i18n.exists(`vaults.kind.${w.params.object}`) ? t(`vaults.kind.${w.params.object}`) : t('enum.unknown') } : {}) })}
          {warningKey(w) === 'warnings.unknown' || warningKey(w) === 'warnings.incomplete' ? <Code ml="xs">{w.code}</Code> : null}
        </Alert>
      ))}
      <VaultInventory vaultId={tg.id} />

      <AccessCheckPanel vaultId={tg.id} access={v.access} canOperate={canOperate} />
      <RoleGuide clientId={v.client_id || undefined} vaultName={v.name} openPolicies={v.access?.permission_model === 'access_policy'} />

      {replacing && (
        <ReplaceCredentialsDialog
          vault={tg}
          onClose={() => setReplacing(false)}
          onReplaced={() => {
            setReplacing(false);
            setReplaced(true);
            void refresh();
          }}
        />
      )}
      {deleting && (
        <DeleteVaultDialog
          vault={tg}
          onClose={() => setDeleting(false)}
          onDeleted={() => {
            void refresh();
            navigate('/key-vaults');
          }}
        />
      )}
    </Stack>
  );
}

// PollInterval says how often Alice checks the vault; an Administrator changes it (5 to 1440 minutes).
function PollInterval({ target, editable }: { target: Target; editable: boolean }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const minutes = target.vault?.poll_interval_minutes ?? 15;
  const [value, setValue] = useState<number | string>(minutes);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const save = async () => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await updateVaultInterval(target.id, target.version, Number(value));
      setSaved(true);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
    await client.invalidateQueries({ queryKey: TARGETS_KEY });
  };
  if (!editable) return <Text size="sm">{t('vaults.pollInterval', { minutes })}</Text>;
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <Stack gap="xs">
        <Group align="flex-end" gap="sm">
          <NumberInput label={t('vaults.fields.poll_interval')} value={value} onChange={setValue} min={5} max={1440} allowDecimal={false} w={200} />
          <Button type="submit" variant="default" loading={busy} disabled={Number(value) === minutes || Number(value) < 5 || Number(value) > 1440}>
            {t('vaults.pollSave')}
          </Button>
        </Group>
        {saved && (
          <Text size="sm" role="status">
            {t('vaults.pollSaved')}
          </Text>
        )}
        <ErrorAlert error={error} />
      </Stack>
    </form>
  );
}

// DeleteVaultDialog removes a vault from Alice. A vault with connected websites is refused first;
// the dialog then offers to remove the connections too, which needs a fresh step-up.
function DeleteVaultDialog({ vault, onClose, onDeleted }: { vault: Target; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [hasBindings, setHasBindings] = useState(false);
  const confirm = async (removeBindings: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await run(() => deleteVault(vault.id, removeBindings));
      onDeleted();
    } catch (e) {
      if (isApiError(e, 'kv.vault_has_bindings')) setHasBindings(true);
      else setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={onClose} title={t('vaults.deleteTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('vaults.deleteHelp')}</Text>
        {hasBindings && (
          <Alert color="yellow" role="alert">
            {t('vaults.hasBindings')}
          </Alert>
        )}
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red.9" loading={busy} onClick={() => void confirm(hasBindings)}>
            {t(hasBindings ? 'vaults.deleteWithBindings' : 'vaults.delete')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
