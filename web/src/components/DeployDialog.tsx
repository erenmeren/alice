import { Alert, Badge, Box, Button, Checkbox, Code, Group, Loader, NativeSelect, Stack, Text } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { certificateBlock, deployCandidates, listAllCertificates, MAX_CERTIFICATES, MAX_DEPLOY_LOCATIONS } from '../api/deployable';
import { deploymentView, isSettled, watchDeployments } from '../api/deployments';
import { deployCertificate, getCertificate } from '../api/endpoints';
import { keyAlgorithmKey, unsupportedReasonKey, fileProblemKey } from '../api/enums';
import { isApiError } from '../api/client';
import { isAbort } from '../api/jobs';
import { canDeployTo } from '../api/nginx';
import { CERTIFICATES_KEY, certificateKey, DEPLOYMENTS_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { Certificate, CertificateLocation, DeployResult, DeploymentDetail } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { formatDate } from '../datetime';
import { AppModal } from './AppModal';
import { DeploymentOutcome } from './DeploymentView';
import { currentStep, DeploymentSteps } from './DeploymentSteps';
import { ErrorAlert } from './ErrorAlert';
import { useNow } from './Expiry';
import { InternalLink } from './InternalLink';
import { LocationWarning } from './LocationWarning';
import { SiteName } from './SiteName';
import { useSiteLabel } from './useSiteLabel';
import { WRAP } from './wrap';

export interface DeployDialogProps {
  opened: boolean;
  onClose: () => void;
  // certificate: deploy this certificate (choose websites, unless location is given too).
  certificate?: Certificate;
  // location: deploy to this website (choose a certificate, unless certificate is given too).
  location?: CertificateLocation;
}

// DeployDialog deploys one certificate to one or several websites. All or nothing: the server
// queues every deployment or none, and names only the first website that stops the request. After
// "202" each deployment is followed by polling until it settles; success is announced only when a
// deployment says succeeded.
export function DeployDialog({ opened, onClose, certificate, location }: DeployDialogProps) {
  const { t } = useTranslation();
  // While the request is on its way the dialog cannot be closed: closing then would orphan
  // deployments the person has not seen.
  const [sending, setSending] = useState(false);
  return (
    <AppModal
      opened={opened}
      onClose={onClose}
      title={t('deploy.title')}
      size="lg"
      closeOnClickOutside={!sending}
      closeOnEscape={!sending}
      withCloseButton={!sending}
    >
      {opened && <DeployForm certificate={certificate} location={location} onClose={onClose} onSending={setSending} />}
    </AppModal>
  );
}

interface Run {
  id: string;
  locationId: string;
  warnings: string[];
  deployment: DeploymentDetail | null;
  timedOut: boolean;
  connectionLost: boolean;
  failed: unknown;
}

function DeployForm({
  certificate,
  location,
  onClose,
  onSending,
}: {
  certificate?: Certificate;
  location?: CertificateLocation;
  onClose: () => void;
  onSending: (sending: boolean) => void;
}) {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const client = useQueryClient();
  const abort = useAbort();
  const now = useNow();
  const siteLabel = useSiteLabel();
  const admin = session?.user.role === 'admin';

  const detail = useQuery({
    queryKey: certificateKey(certificate?.id ?? ''),
    queryFn: () => getCertificate(certificate?.id ?? ''),
    enabled: certificate !== undefined && location === undefined,
  });
  const certs = useQuery({ queryKey: [...CERTIFICATES_KEY, 'deploy-candidates'], queryFn: listAllCertificates, enabled: certificate === undefined });

  const [chosenId, setChosenId] = useState('');
  const [picked, setPicked] = useState<string[]>([]);
  const [confirmChain, setConfirmChain] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const runsRef = useRef<HTMLDivElement>(null);
  const started = runs !== null;
  // The runs view replaces the form: focus moves to it so keyboard and screen reader users follow.
  useEffect(() => {
    if (started) runsRef.current?.focus();
  }, [started]);

  const candidates = certs.data && location ? deployCandidates(certs.data.items, location, now) : [];
  const chosen: Certificate | undefined = certificate ?? candidates.find((c) => c.id === chosenId);
  const block = chosen ? certificateBlock(chosen, now) : null;
  const incompleteChain = chosen !== undefined && !chosen.chain_complete;
  const chainBlocked = incompleteChain && !admin;

  const places = detail.data?.locations ?? [];
  const targets: CertificateLocation[] = location ? [location] : places.filter((p) => picked.includes(p.id));
  const tooMany = targets.length > MAX_DEPLOY_LOCATIONS;
  const knownLocations = location ? [location] : places;

  const ready =
    chosen !== undefined && block === null && !chainBlocked && (!incompleteChain || confirmChain) && targets.length > 0 && !tooMany && !busy;

  const refresh = () => {
    void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
    // The paged list of deploy candidates is left alone: refetching up to 50 pages at each settle
    // would defeat the request budget.
    void client.invalidateQueries({ queryKey: CERTIFICATES_KEY, predicate: (q) => q.queryKey[1] !== 'deploy-candidates' });
    void client.invalidateQueries({ queryKey: ['locations'] });
  };

  const patch = (id: string, change: Partial<Run>) => setRuns((rs) => (rs ? rs.map((r) => (r.id === id ? { ...r, ...change } : r)) : rs));

  // follow reads the whole batch with ONE loop (see watchDeployments): the request rate does not
  // grow with the number of websites.
  const follow = (res: DeployResult) => {
    setRuns(res.deployments.map((d) => ({ id: d.id, locationId: d.location_id, warnings: d.warnings, deployment: null, timedOut: false, connectionLost: false, failed: null })));
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
      if (isAbort(e)) return;
      // A read that cannot succeed (not a dropped connection): the runs still open show the error.
      setRuns((rs) => (rs ? rs.map((r) => (r.deployment !== null && isSettled(r.deployment) ? r : { ...r, failed: e })) : rs));
    });
  };

  const submit = async () => {
    if (!chosen || !ready) return;
    setBusy(true);
    onSending(true);
    setError(null);
    setRefused(null);
    try {
      const res = await deployCertificate(
        chosen.id,
        targets.map((l) => l.id),
        incompleteChain && admin && confirmChain,
      );
      refresh();
      follow(res);
    } catch (e) {
      setError(e);
      if (isApiError(e) && e.params.location_id) setRefused(e.params.location_id);
    }
    setBusy(false);
    onSending(false);
  };

  const close = () => {
    abort.abort();
    if (runs) refresh();
    onClose();
  };

  if (runs) {
    const anyWorking = runs.some((r) => !r.failed && !r.timedOut && (r.deployment === null || !isSettled(r.deployment)));
    const views = runs.map((r) => (r.deployment ? deploymentView(r.deployment) : null));
    const allFinal = views.every((v) => v === 'final');
    // Runs that are settled for polling but not over (recovering, held, stopped, unknown) or that the
    // screen stopped following are still open.
    const open = runs.length - views.filter((v) => v === 'final').length;
    const ok = runs.filter((r) => r.deployment?.status === 'succeeded').length;
    const multi = runs.length > 1;
    return (
      <Stack gap="md" ref={runsRef} tabIndex={-1} aria-label={t('deploy.title')} style={{ outline: 'none' }}>
        {anyWorking && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('deploy.working')}</Text>
          </Group>
        )}
        {runs.map((r) => {
          const loc = knownLocations.find((l) => l.id === r.locationId);
          const dep = r.deployment;
          const step = dep ? currentStep(dep.steps) : null;
          return (
            <Box key={r.id} data-testid="deployment-run" style={{ borderTop: multi ? '1px solid var(--mantine-color-gray-4)' : undefined, paddingTop: multi ? 8 : 0 }}>
              <Stack gap="xs">
                {multi && loc && (
                  <Group gap="xs">
                    <Text size="sm" fw={600}>
                      <SiteName loc={loc} />
                    </Text>
                    <Text size="sm" c="gray.7" translate="no">
                      {loc.target_name}
                    </Text>
                  </Group>
                )}
                {r.warnings.map((w) => (
                  <Alert key={w} color="yellow" role="status">
                    <LocationWarning code={w} site={loc ? siteLabel(loc) : ''} mode={loc?.key_mode ?? ''} size="sm" />
                  </Alert>
                ))}
                <DeploymentSteps steps={dep?.steps ?? []} status={dep?.status ?? 'pending'} />
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
        {multi && !anyWorking && (
          <Stack gap={2} role="status">
            <Text size="sm" fw={600}>
              {t('deploy.partial', { ok, total: runs.length })}
            </Text>
            {!allFinal && <Text size="sm">{t('deploy.partialOpen', { open })}</Text>}
          </Stack>
        )}
        <Group justify="space-between">
          <InternalLink to="/deployments" size="sm">
            {t('deploy.openHistory')}
          </InternalLink>
          <Button onClick={close}>{t('deploy.close')}</Button>
        </Group>
      </Stack>
    );
  }

  const refusedText = t('deploy.refused');
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <Stack gap="md">
        <Text size="sm">{t('deploy.summary')}</Text>

        {certificate === undefined && (
          <>
            {certs.isPending && <Loader size="sm" aria-label={t('ui.loading')} />}
            <ErrorAlert error={certs.error} />
            {certs.data?.cut && <Alert color="yellow" role="status">{t('deploy.listCut', { count: MAX_CERTIFICATES })}</Alert>}
            {certs.isSuccess && candidates.length === 0 && <Text size="sm">{t('deploy.noCandidates')}</Text>}
            {candidates.length > 0 && (
              <NativeSelect
                label={t('deploy.certificate')}
                value={chosenId}
                onChange={(e) => {
                  setChosenId(e.currentTarget.value);
                  setConfirmChain(false);
                }}
                data={[
                  { value: '', label: t('deploy.chooseCertificate') },
                  ...candidates.map((c) => ({
                    value: c.id,
                    label: t('deploy.option', {
                      name: c.label || c.subject_cn || t('certificates.noName'),
                      keyType: t(keyAlgorithmKey(c.key_algorithm)),
                      date: formatDate(c.not_after, i18n.language),
                    }),
                  })),
                ]}
              />
            )}
          </>
        )}

        {certificate !== undefined && block !== null && (
          <Alert color="red" role="alert">
            {t(block === 'no_key' ? 'certificates.detail.noKey' : block === 'expired' ? 'certificates.detail.expiredNoDeploy' : 'deploy.notYetValid')}
          </Alert>
        )}

        {location !== undefined && (
          <Stack gap={2}>
            <Text size="sm" fw={600}>
              {t('deploy.website')}
            </Text>
            <Box
              data-refused={refused === location.id ? 'true' : undefined}
              p="xs"
              style={refused === location.id ? { border: '2px solid var(--mantine-color-red-9)', borderRadius: 4 } : undefined}
            >
              <Text size="sm">
                <SiteName loc={location} />{' '}
                <Text span c="gray.7" translate="no">
                  {location.target_name}
                </Text>
              </Text>
              <Code translate="no" style={WRAP}>
                {location.cert_path}
              </Code>
              {refused === location.id && (
                <Text size="sm" c="red.9" role="alert" mt={4}>
                  {refusedText}
                </Text>
              )}
            </Box>
          </Stack>
        )}

        {certificate !== undefined && location === undefined && (
          <Checkbox.Group value={picked} onChange={setPicked} label={t('deploy.websites')}>
            <Stack gap="xs" mt="xs">
              {detail.isPending && <Loader size="sm" aria-label={t('ui.loading')} />}
              <ErrorAlert error={detail.error} />
              {detail.isSuccess && places.length === 0 && <Text size="sm">{t('deploy.noWebsites')}</Text>}
              {places.map((p) => (
                <WebsiteChoice key={p.id} place={p} refused={refused === p.id} refusedText={refusedText} disabled={!canDeployTo(p)} />
              ))}
            </Stack>
          </Checkbox.Group>
        )}

        {tooMany && (
          <Alert color="red" role="alert">
            {t('deploy.limit', { max: MAX_DEPLOY_LOCATIONS })}
          </Alert>
        )}

        {chainBlocked && (
          <Alert color="yellow" role="status">
            {t('deploy.chainAdminOnly')}
          </Alert>
        )}
        {incompleteChain && admin && <Checkbox label={t('deploy.confirmChain')} checked={confirmChain} onChange={(e) => setConfirmChain(e.currentTarget.checked)} />}

        <ErrorAlert error={error} />

        <Group justify="flex-end">
          <Button variant="default" onClick={close} disabled={busy}>
            {t('deploy.cancel')}
          </Button>
          <Button type="submit" loading={busy} disabled={!ready}>
            {t('deploy.submit')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

// WebsiteChoice is one tickable website of a certificate: where it is, why it cannot be chosen, and
// (after a refusal) that the server stopped here.
function WebsiteChoice({ place, refused, refusedText, disabled }: { place: CertificateLocation; refused: boolean; refusedText: string; disabled: boolean }) {
  const { t } = useTranslation();
  const reason = !place.supported
    ? t(unsupportedReasonKey(place.unsupported_reason))
    : place.missing_since !== null
      ? t('locations.rowUnavailable.missing')
      : place.active_deployment_id !== null
        ? t('locations.rowUnavailable.deploying')
        : '';
  const problem =
    !place.supported && place.unsupported_reason === 'file_problem' ? [place.problem && t(fileProblemKey(place.problem)), place.key_problem && t(fileProblemKey(place.key_problem))].filter(Boolean) : [];
  return (
    <Box data-refused={refused ? 'true' : undefined} p="xs" style={refused ? { border: '2px solid var(--mantine-color-red-9)', borderRadius: 4 } : undefined}>
      <Checkbox
        value={place.id}
        disabled={disabled}
        error={refused ? refusedText : undefined}
        label={
          <span>
            <SiteName loc={place} />{' '}
            <Text span c="gray.7" translate="no">
              {place.target_name}
            </Text>{' '}
            <Code translate="no">{place.cert_path}</Code>
          </span>
        }
      />
      {reason && (
        <Group gap="xs" ml={28} mt={2}>
          <Badge variant="light" color="gray" tt="none">
            {t('locations.notSupported')}
          </Badge>
          <Text size="xs">{reason}</Text>
          {problem.map((p) => (
            <Text size="xs" key={p}>
              {p}
            </Text>
          ))}
        </Group>
      )}
    </Box>
  );
}
