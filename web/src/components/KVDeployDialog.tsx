import { Alert, Box, Button, Checkbox, Code, Group, Loader, NativeSelect, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { deploymentView, isSettled, watchDeployments } from '../api/deployments';
import { isAbort } from '../api/jobs';
import { deployBinding, type Binding, type BindingDeployResult, type KVCertificateDetail } from '../api/keyvault';
import { BINDINGS_KEY, DEPLOYMENTS_KEY, KV_CERTIFICATES_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { DeploymentDetail } from '../api/types';
import { formatDate } from '../datetime';
import { AppModal } from './AppModal';
import { currentStep, DeploymentSteps } from './DeploymentSteps';
import { DeploymentOutcome } from './DeploymentView';
import { ErrorAlert } from './ErrorAlert';
import { useNow } from './Expiry';
import { InternalLink } from './InternalLink';
import { useStepUp } from './StepUpProvider';
import { shortVersion, versionBlock } from './vaultText';
import { useAuth } from '../auth/AuthProvider';
import { WRAP } from './wrap';

interface Run {
  id: string;
  locationId: string;
  deployment: DeploymentDetail | null;
  timedOut: boolean;
  connectionLost: boolean;
  failed: unknown;
}

// KVDeployDialog is "Deploy now" of a connection: one stored version of the vault certificate (never
// "the latest") to some or all of the connection's websites. All or nothing; after 202 every
// deployment is followed until it settles. A held version is deployed by an Administrator only (fresh
// step-up, asked for when the server wants it); holding stays. An incomplete chain needs the
// Administrator's confirmation, offered only for a version held for it or after the server asked for it.
export function KVDeployDialog({ binding, certificate, versionId, onClose }: { binding: Binding; certificate: KVCertificateDetail; versionId?: string; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const { run } = useStepUp();
  const client = useQueryClient();
  const abort = useAbort();
  const now = useNow();
  const admin = session?.user.role === 'admin';
  const versions = certificate.versions;
  const deployable = versions.filter((v) => v.certificate_id !== null);
  const firstId = versionId ?? versions.find((v) => v.version === certificate.current_version)?.id ?? versions[0]?.id ?? '';
  const [chosenId, setChosenId] = useState(firstId);
  const [picked, setPicked] = useState<string[]>(binding.locations.map((l) => l.location_id));
  const [confirmChain, setConfirmChain] = useState(false);
  const [chainAsked, setChainAsked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const runsRef = useRef<HTMLDivElement>(null);
  const started = runs !== null;
  useEffect(() => {
    if (started) runsRef.current?.focus();
  }, [started]);

  const version = versions.find((v) => v.id === chosenId);
  const block = version ? versionBlock(version, now) : 'noDetails';
  const heldBlocked = version?.held === true && !admin;
  const chainHeld = version?.held === true && version.held_reason === 'incomplete_chain';
  const chainOffer = admin && (chainHeld || chainAsked);
  const ready = version !== undefined && block === null && !heldBlocked && picked.length > 0 && !busy && (!chainOffer || confirmChain);

  const refresh = () => {
    void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
    void client.invalidateQueries({ queryKey: BINDINGS_KEY });
    void client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY });
  };
  const patch = (id: string, change: Partial<Run>) => setRuns((rs) => (rs ? rs.map((r) => (r.id === id ? { ...r, ...change } : r)) : rs));

  const follow = (res: BindingDeployResult) => {
    setRuns(res.deployments.map((d) => ({ id: d.id, locationId: d.location_id, deployment: null, timedOut: false, connectionLost: false, failed: null })));
    watchDeployments(
      res.deployments.map((d) => d.id),
      {
        signal: abort.signal(),
        onUpdate: (id, dep) => patch(id, { deployment: dep }),
        onDone: (id, r) => {
          patch(id, { deployment: r.deployment, timedOut: r.timedOut, connectionLost: r.connectionLost, failed: r.error ?? null });
          refresh();
        },
      },
    ).catch((e: unknown) => {
      if (!isAbort(e)) setRuns((rs) => (rs ? rs.map((r) => (r.deployment !== null && isSettled(r.deployment) ? r : { ...r, failed: e })) : rs));
    });
  };

  const submit = async () => {
    if (!version || !ready) return;
    setBusy(true);
    setError(null);
    setRefused(null);
    try {
      const res = await run(() => deployBinding(binding.id, version.id, picked, chainOffer && confirmChain));
      refresh();
      follow(res);
    } catch (e) {
      setError(e);
      if (isApiError(e) && e.params.location_id) setRefused(e.params.location_id);
      if (isApiError(e, 'certificate.chain_unconfirmed')) setChainAsked(true);
    }
    setBusy(false);
  };

  const close = () => {
    abort.abort();
    if (runs) refresh();
    onClose();
  };
  const siteOf = (id: string) => binding.locations.find((l) => l.location_id === id);

  return (
    <AppModal opened onClose={close} title={t('bindings.deployTitle')} size="lg" closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}>
      {runs ? (
        <Stack gap="md" ref={runsRef} tabIndex={-1} role="group" aria-label={t('bindings.deployTitle')} style={{ outline: 'none' }}>
          {runs.some((r) => !r.failed && !r.timedOut && (r.deployment === null || !isSettled(r.deployment))) && (
            <Group gap="sm" role="status" aria-live="polite">
              <Loader size="sm" aria-hidden />
              <Text size="sm">{t('deploy.working')}</Text>
            </Group>
          )}
          {runs.map((r) => {
            const dep = r.deployment;
            const step = dep ? currentStep(dep.steps) : null;
            const site = siteOf(r.locationId);
            return (
              <Box key={r.id} data-testid="deployment-run" style={{ borderTop: runs.length > 1 ? '1px solid var(--mantine-color-gray-4)' : undefined, paddingTop: runs.length > 1 ? 8 : 0 }}>
                <Stack gap="xs">
                  {site && (
                    <Text size="sm" fw={600} style={WRAP}>
                      <span translate="no">{site.target_name}</span> <Code translate="no">{site.cert_path}</Code>
                    </Text>
                  )}
                  <DeploymentSteps steps={dep?.steps ?? []} status={dep?.status ?? 'pending'} vault />
                  {step && dep && !isSettled(dep) && (
                    <Text size="xs" c="gray.7" aria-live="polite">
                      {t('deployments.currentStep', { step: t(step) })}
                    </Text>
                  )}
                  {dep && <DeploymentOutcome d={dep} />}
                  {r.failed !== null && <ErrorAlert error={r.failed} />}
                  {r.timedOut && (
                    <Alert color="yellow" role="status">
                      {r.connectionLost ? t('deploy.connectionLost') : t('deploy.stillWorking')}
                    </Alert>
                  )}
                  {dep && (
                    <InternalLink to={`/deployments/${r.id}`} size="sm">
                      {t('deploy.openDeployment')}
                    </InternalLink>
                  )}
                </Stack>
              </Box>
            );
          })}
          {runs.length > 1 && runs.every((r) => r.deployment && deploymentView(r.deployment) === 'final') && (
            <Text size="sm" fw={600} role="status">
              {t('deploy.partial', { ok: runs.filter((r) => r.deployment?.status === 'succeeded').length, total: runs.length })}
            </Text>
          )}
          <Group justify="space-between">
            <InternalLink to="/deployments" size="sm">
              {t('deploy.openHistory')}
            </InternalLink>
            <Button onClick={close}>{t('deploy.close')}</Button>
          </Group>
        </Stack>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Stack gap="md">
            {deployable.length === 0 && <Text size="sm">{t('bindings.noVersions')}</Text>}
            <NativeSelect
              label={t('bindings.version')}
              value={chosenId}
              onChange={(e) => {
                setChosenId(e.currentTarget.value);
                setConfirmChain(false);
              }}
              data={versions.map((v) => ({ value: v.id, label: t('bindings.versionOption', { version: shortVersion(v.version), date: formatDate(v.detected_at, i18n.language) }) }))}
            />
            {version && (
              <Text size="xs" style={WRAP}>
                <Code translate="no">{version.version}</Code>
              </Text>
            )}
            {block && (
              <Alert color="red" role="alert">
                {t(`bindings.cannot.${block}`)}
              </Alert>
            )}
            {heldBlocked && (
              <Alert color="yellow" role="status">
                {t('bindings.cannot.heldAdmin')}
              </Alert>
            )}
            {version?.held === true && admin && <Text size="sm">{t('bindings.heldDeployNote')}</Text>}
            <Checkbox.Group value={picked} onChange={setPicked} label={t('bindings.websites')}>
              <Stack gap="xs" mt="xs">
                {binding.locations.map((l) => {
                  const bad = refused === l.location_id;
                  return (
                    <Box key={l.location_id} data-refused={bad ? 'true' : undefined} p="xs" style={bad ? { border: '2px solid var(--mantine-color-red-9)', borderRadius: 4 } : undefined}>
                      <Checkbox
                        value={l.location_id}
                        error={bad ? t('bindings.refused') : undefined}
                        label={
                          <span style={WRAP}>
                            <span translate="no">{l.target_name}</span> <Code translate="no">{l.cert_path}</Code>
                          </span>
                        }
                      />
                    </Box>
                  );
                })}
              </Stack>
            </Checkbox.Group>
            {chainAsked && !admin && (
              <Alert color="yellow" role="status">
                {t('bindings.confirmChainNeeded')}
              </Alert>
            )}
            {chainOffer && <Checkbox label={t('deploy.confirmChain')} checked={confirmChain} onChange={(e) => setConfirmChain(e.currentTarget.checked)} />}
            <ErrorAlert error={error} />
            <Group justify="flex-end">
              <Button variant="default" disabled={busy} onClick={close}>
                {t('deploy.cancel')}
              </Button>
              <Button type="submit" loading={busy} disabled={!ready}>
                {t('bindings.deploySubmit')}
              </Button>
            </Group>
          </Stack>
        </form>
      )}
    </AppModal>
  );
}
