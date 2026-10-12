import { Alert, Button, Checkbox, Group, Loader, NativeSelect, Stack, Text, TextInput } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { listAllTargets } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { getKVImport, importToKeyVault, type KVImport } from '../api/keyvault';
import { KV_IMPORTS_KEY, VAULTS_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { Certificate } from '../api/types';
import { AppModal } from './AppModal';
import { CodeText } from './CodeText';
import { DeploymentErrorAlert } from './DeploymentView';
import { ErrorAlert } from './ErrorAlert';
import { DialogActions } from './ui';
import { InternalLink } from './InternalLink';
import { LoadingIndicator } from './LoadingIndicator';
import { BlockedJobAlert, StillWorkingAlert } from './JobErrorAlert';
import { useStepUp } from './StepUpProvider';

const NAME_OK = /^[0-9A-Za-z-]{1,127}$/;

// importName turns a certificate's common name into a vault certificate name: every character outside
// letters, digits and hyphen becomes a hyphen, at most 127 characters.
export function importName(commonName: string): string {
  return commonName.replace(/[^0-9A-Za-z-]/g, '-').slice(0, 127);
}

interface Confirm {
  name: string;
  bound: boolean;
  autoFollows: boolean;
}

// ImportToKeyVaultDialog sends a certificate Alice holds, with its private key, into a vault. Only an
// Administrator may (the private key leaves Alice; a fresh step-up is asked for when the server wants
// one). A name the vault already has is refused until the person confirms adding a new version, and the
// dialog then says what that means, including whether automatic deployment follows. After 202 it waits
// for the job and shows what the import became: Imported, Not confirmed yet (never sent again; a later
// check of the vault confirms it), Outcome unknown, or the error.
export function ImportToKeyVaultDialog({ certificate, onClose }: { certificate: Certificate; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const abort = useAbort();
  const vaults = useQuery({ queryKey: [...VAULTS_KEY, 'import'], queryFn: () => listAllTargets('azure_key_vault') });
  const usable = (vaults.data?.items ?? []).filter((v) => v.status !== 'disabled');
  const [vaultId, setVaultId] = useState('');
  const [name, setName] = useState(() => importName(certificate.subject_cn || certificate.label));
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [agreed, setAgreed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<KVImport | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [waiting, setWaiting] = useState(false);
  // late: the import was accepted but waiting for it or reading it failed. The form never comes back
  // then (a second send is refused while the first is open); the dialog only reports and closes.
  const [late, setLate] = useState<unknown>(null);
  const [lateTimeout, setLateTimeout] = useState(false);
  const chosen = vaultId || usable[0]?.id || '';
  const valid = NAME_OK.test(name);

  const send = async () => {
    if (!valid || chosen === '') return;
    setBusy(true);
    setError(null);
    setBlocked(false);
    let sent = false;
    try {
      const accepted = await run(() => importToKeyVault(certificate.id, chosen, name, confirm !== null && agreed));
      sent = true;
      setConfirm(null);
      setBusy(false);
      setWaiting(true);
      void client.invalidateQueries({ queryKey: KV_IMPORTS_KEY });
      const job = await waitForJob(accepted.job_id, { signal: abort.signal() });
      if (job.status === 'blocked_license') {
        setBlocked(true);
      } else {
        // The import itself says what happened, whatever became of its job.
        setResult(await getKVImport(chosen, accepted.import.id));
      }
      void client.invalidateQueries({ queryKey: KV_IMPORTS_KEY });
    } catch (e) {
      if (isAbort(e)) return;
      if (sent) {
        if (e instanceof JobTimeoutError) setLateTimeout(true);
        else setLate(e);
      } else if (isApiError(e, 'kv.import_confirm_needed')) {
        setConfirm({ name: e.params.certificate_name || name, bound: e.params.bound === 'true', autoFollows: e.params.auto_deploy_follows === 'true' });
        setAgreed(false);
      } else setError(e);
    }
    setBusy(false);
    setWaiting(false);
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setConfirm(null);
    setAgreed(false);
  };

  const done = result !== null || blocked || late !== null || lateTimeout;
  const locked = busy || waiting;
  return (
    <AppModal opened onClose={() => !locked && onClose()} title={t('imports.action')} size="lg" closeOnClickOutside={!locked} closeOnEscape={!locked} withCloseButton={!locked}>
      {waiting ? (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('imports.working')}</Text>
        </Group>
      ) : done ? (
        <Stack gap="sm">
          {blocked && <BlockedJobAlert />}
          {lateTimeout && <StillWorkingAlert textKey="imports.stillWorking" />}
          {late !== null && <ErrorAlert error={late} />}
          {result && <ImportOutcome result={result} />}
          <DialogActions>
            {result?.state === 'failed' && result.can_retry && (
              <Button variant="default" onClick={reset}>
                {t('imports.retry')}
              </Button>
            )}
            <Button onClick={onClose}>{t('ui.close')}</Button>
          </DialogActions>
        </Stack>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <Stack gap="sm">
            <Text size="sm" c="dimmed">
              {t('imports.privateKeyNote')}
            </Text>
            {vaults.isPending && <LoadingIndicator />}
            <ErrorAlert error={vaults.error} />
            {vaults.isSuccess && usable.length === 0 && (
              <Stack gap={4}>
                <Text size="sm">{t('imports.noVaults')}</Text>
                <InternalLink to="/key-vaults" size="sm">
                  {t('imports.openVaults')}
                </InternalLink>
              </Stack>
            )}
            {usable.length > 0 && (
              <NativeSelect
                label={t('imports.vault')}
                value={chosen}
                onChange={(e) => {
                  setVaultId(e.currentTarget.value);
                  setConfirm(null);
                }}
                data={usable.map((v) => ({ value: v.id, label: v.name }))}
              />
            )}
            <TextInput
              label={t('imports.name')}
              description={t('imports.nameHelp')}
              value={name}
              onChange={(e) => {
                setName(e.currentTarget.value);
                setConfirm(null);
              }}
              error={name !== '' && !valid ? t('imports.nameInvalid') : undefined}
              required
              maxLength={127}
              autoComplete="off"
              spellCheck={false}
            />
            <Text size="sm">{t('imports.noAutoRenew')}</Text>
            {confirm && (
              <Alert color="yellow" role="alert" data-testid="import-confirm">
                <Stack gap="xs">
                  <Text size="sm" fw={600}>
                    <CodeText i18nKey="imports.newVersionWarning" param="name" value={confirm.name} />
                  </Text>
                  <Text size="sm">{t('imports.policyWarning')}</Text>
                  {confirm.bound && <Text size="sm">{t('imports.boundNote')}</Text>}
                  {confirm.bound && <Text size="sm">{t(confirm.autoFollows ? 'imports.autoDeployFollows' : 'imports.autoDeployNot')}</Text>}
                  <Checkbox label={t('imports.confirmNewVersion')} checked={agreed} onChange={(e) => setAgreed(e.currentTarget.checked)} />
                </Stack>
              </Alert>
            )}
            <ErrorAlert error={error} />
          </Stack>
          <DialogActions>
            <Button variant="default" disabled={busy} onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={busy} disabled={!valid || chosen === '' || (confirm !== null && !agreed)}>
              {t('imports.action')}
            </Button>
          </DialogActions>
        </form>
      )}
    </AppModal>
  );
}

// ImportOutcome says what an import became, in the words of its state.
export function ImportOutcome({ result }: { result: KVImport }) {
  const { t } = useTranslation();
  const unknown = result.state === 'failed' && result.error?.reason === 'kv.import_outcome_unknown';
  const label = unknown ? 'imports.state.unknown' : result.state === '' ? 'enum.unknown' : `imports.state.${result.state}`;
  if (result.state === 'queued' || result.state === 'running') return <StillWorkingAlert textKey="imports.stillWorking" />;
  return (
    <Stack gap="xs" data-testid="import-outcome" data-state={unknown ? 'unknown' : result.state}>
      <Alert color={result.state === 'succeeded' ? 'green' : result.state === 'uncertain' ? 'yellow' : 'red'} role="status" title={t(label)}>
        <Stack gap={4}>
          {result.state === 'succeeded' && result.version && (
            <Text size="sm">
              <CodeText i18nKey="imports.importedVersion" param="version" value={result.version} />
            </Text>
          )}
          {result.state === 'uncertain' && <Text size="sm">{t('imports.explain.uncertain')}</Text>}
          {unknown && <Text size="sm">{t('imports.explain.unknown')}</Text>}
          {result.state === 'failed' && result.can_retry && <Text size="sm">{t('imports.canRetry')}</Text>}
        </Stack>
      </Alert>
      {result.state === 'failed' && <DeploymentErrorAlert error={result.error} />}
    </Stack>
  );
}
