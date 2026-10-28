import { Alert, Badge, Box, Button, Checkbox, Code, Group, Loader, NativeSelect, Stack, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { certificateBlock, deployCandidates, listAllCertificates, MAX_CERTIFICATES, MAX_DEPLOY_LOCATIONS } from '../api/deployable';
import { deploymentView, isCCSDeployment, isRDPDeployment, isSettled, isWindowsDeployment, watchDeployments } from '../api/deployments';
import { deployCertificate, getCertificate } from '../api/endpoints';
import { keyAlgorithmKey, unsupportedReasonKey, fileProblemKey } from '../api/enums';
import { isApiError } from '../api/client';
import { isAbort } from '../api/jobs';
import { canDeployTo, certificateGroups, certificateSubject, isWindows } from '../api/webServer';
import { unavailableNote } from './DisabledFeature';
import { CERTIFICATES_KEY, certificateKey, DEPLOYMENTS_KEY } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { Certificate, CertificateLocation, DeployResult, DeploymentDetail } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { adminOn } from '../auth/permissions';
import { formatDate } from '../datetime';
import { Icon } from '../design/Icon';
import { AppModal } from './AppModal';
import { DeploymentOutcome } from './DeploymentView';
import { currentStep, DeploymentSteps } from './DeploymentSteps';
import { ErrorAlert } from './ErrorAlert';
import { useNow } from './Expiry';
import { InternalLink } from './InternalLink';
import { LocationWarning } from './LocationWarning';
import { SiteName } from './SiteName';
import { useSiteLabel } from './useSiteLabel';
import deploy from './deploy.module.css';
import { DialogActions, Notice } from './ui';
import { CanaryChoice, serviceIdOf } from './CanaryChoice';
import { useOptionalStepUp } from './StepUpProvider';
import { WRAP } from './wrap';

export interface DeployDialogProps {
  opened: boolean;
  onClose: () => void;
  // certificate: deploy this certificate (choose websites, unless location is given too).
  certificate?: Certificate;
  // location: deploy to this website (choose a certificate, unless certificate is given too).
  location?: CertificateLocation;
  // siblings: with the location of a Windows server, the server's bindings: the dialog then picks among them, grouped
  // by the certificate they serve, starting with the location (R61, design §15 Q5). Ignored for any other server.
  siblings?: CertificateLocation[];
}

// DeployDialog deploys one certificate to one or several websites. All or nothing: the server
// queues every deployment or none, and names only the first website that stops the request. After
// "202" each deployment is followed by polling until it settles; success is announced only when a
// deployment says succeeded.
export function DeployDialog({ opened, onClose, certificate, location, siblings }: DeployDialogProps) {
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
      {opened && <DeployForm certificate={certificate} location={location} siblings={siblings} onClose={onClose} onSending={setSending} />}
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
  siblings,
  onClose,
  onSending,
}: {
  certificate?: Certificate;
  location?: CertificateLocation;
  siblings?: CertificateLocation[];
  onClose: () => void;
  onSending: (sending: boolean) => void;
}) {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const client = useQueryClient();
  const abort = useAbort();
  const now = useNow();
  const siteLabel = useSiteLabel();
  // An incomplete chain is confirmed by an Administrator of the certificate's service.
  const admin = adminOn(session, certificate);

  const detail = useQuery({
    queryKey: certificateKey(certificate?.id ?? ''),
    queryFn: () => getCertificate(certificate?.id ?? ''),
    enabled: certificate !== undefined && location === undefined,
  });
  const certs = useQuery({ queryKey: [...CERTIFICATES_KEY, 'deploy-candidates'], queryFn: listAllCertificates, enabled: certificate === undefined });

  // bindings: the Windows server's bindings to pick from (the location among them), or null for one website.
  const bindings =
    location !== undefined && siblings !== undefined && isWindows(location.target_type)
      ? siblings.some((l) => l.id === location.id)
        ? siblings
        : [location, ...siblings]
      : null;
  const windows = location !== undefined && isWindows(location.target_type);
  // R68: a file of the server's Centralized Certificate Store is written in place, not bound.
  const ccs = location?.kind === 'win_ccs_file';
  // R69: the Remote Desktop listener is picked like a binding; the summary names the listener.
  const rdp = location?.kind === 'win_rdp';
  const [chosenId, setChosenId] = useState('');
  const [picked, setPicked] = useState<string[]>(bindings && location ? [location.id] : []);
  const [confirmChain, setConfirmChain] = useState(false);
  const [override, setOverride] = useState(false);
  const { run } = useOptionalStepUp();
  const [rollout, setRollout] = useState<DeployResult['rollout']>(null);
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

  // groups: the bindings by the certificate they serve; the picked ones are deployed in the order shown.
  const groups = bindings ? certificateGroups(bindings) : [];
  const pickedBindings = groups.flatMap((g) => g.items).filter((l) => picked.includes(l.id));
  // A certificate is offered when it fits every picked binding (the location alone before any is picked).
  const fitting = bindings ? (pickedBindings.length > 0 ? pickedBindings : location ? [location] : []) : location ? [location] : [];
  const candidates = certs.data && location ? fitting.reduce((cs, l) => deployCandidates(cs, l, now), certs.data.items) : [];
  const chosen: Certificate | undefined = certificate ?? candidates.find((c) => c.id === chosenId);
  const block = chosen ? certificateBlock(chosen, now) : null;
  // A certificate chosen for the bindings picked then that does not fit one ticked since (another key type).
  const noLongerFits = bindings !== null && certificate === undefined && chosenId !== '' && chosen === undefined && certs.isSuccess;
  const incompleteChain = chosen !== undefined && !chosen.chain_complete;
  const chainBlocked = incompleteChain && !admin;

  const places = detail.data?.locations ?? [];
  const targets: CertificateLocation[] = bindings ? pickedBindings : location ? [location] : places.filter((p) => picked.includes(p.id));
  const tooMany = targets.length > MAX_DEPLOY_LOCATIONS;
  const knownLocations = bindings ?? (location ? [location] : places);

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
      const send = () =>
        deployCertificate(
          chosen.id,
          targets.map((l) => l.id),
          incompleteChain && admin && confirmChain,
          override,
        );
      // R65: deploying to all at once needs a fresh step-up (asked for when the server wants it).
      const res = override ? await run(send) : await send();
      refresh();
      setRollout(res.rollout ?? null);
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
    // Runs that found the certificate already in place changed nothing: said apart, so a batch of
    // them does not read as "0 updated" only.
    const unchanged = runs.filter((r) => r.deployment?.status === 'unchanged').length;
    const multi = runs.length > 1;
    return (
      <Stack gap="md" ref={runsRef} tabIndex={-1} aria-label={t('deploy.title')} style={{ outline: 'none' }}>
        {anyWorking && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('deploy.working')}</Text>
          </Group>
        )}
        {rollout && <Notice tone="info" role="status" testId="canary-started" title={t('canary.started', { count: rollout.wave2.length })} />}
        {runs.map((r) => {
          const loc = knownLocations.find((l) => l.id === r.locationId);
          const dep = r.deployment;
          const step = dep ? currentStep(dep.steps) : null;
          return (
            <Box key={r.id} data-testid="deployment-run" className={multi ? deploy.separated : undefined}>
              <Stack gap="xs">
                {multi && loc && (
                  <Group gap="xs">
                    <Text size="sm" fw={600}>
                      <SiteName loc={loc} />
                    </Text>
                    <Text size="sm" c="dimmed" translate="no">
                      {loc.target_name}
                    </Text>
                  </Group>
                )}
                {r.warnings.map((w) => (
                  <Alert key={w} color="yellow" role="status">
                    <LocationWarning code={w} site={loc ? siteLabel(loc) : ''} mode={loc?.key_mode ?? ''} size="sm" />
                  </Alert>
                ))}
                <DeploymentSteps
                  steps={dep?.steps ?? []}
                  status={dep?.status ?? 'pending'}
                  windows={(loc !== undefined && isWindows(loc.target_type) && loc.kind !== 'win_ccs_file' && loc.kind !== 'win_rdp') || (dep !== null && isWindowsDeployment(dep))}
                  ccs={loc?.kind === 'win_ccs_file' || (dep !== null && isCCSDeployment(dep))}
                  rdp={loc?.kind === 'win_rdp' || (dep !== null && isRDPDeployment(dep))}
                />
                {step && dep && !isSettled(dep) && (
                  <Text size="xs" c="dimmed" aria-live="polite">
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
            {unchanged > 0 && <Text size="sm">{t('deploy.partialUnchanged', { count: unchanged })}</Text>}
            {!allFinal && <Text size="sm">{t('deploy.partialOpen', { open })}</Text>}
          </Stack>
        )}
        <DialogActions
          note={
            <InternalLink to="/deployments" size="sm">
              {t('deploy.openHistory')}
            </InternalLink>
          }
        >
          <Button onClick={close}>{t('deploy.close')}</Button>
        </DialogActions>
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
        <Text size="sm">{t(rdp ? 'deploy.summaryRDP' : ccs ? 'deploy.summaryCCS' : windows ? 'deploy.summaryWindows' : 'deploy.summary')}</Text>

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

        {noLongerFits && (
          <Alert color="yellow" role="status">
            {t('deploy.chosenNoLongerFits')}
          </Alert>
        )}

        {certificate !== undefined && block !== null && (
          <Alert color="red" role="alert">
            {t(block === 'no_key' ? 'certificates.detail.noKey' : block === 'expired' ? 'certificates.detail.expiredNoDeploy' : 'deploy.notYetValid')}
          </Alert>
        )}

        {bindings && (
          <Checkbox.Group value={picked} onChange={setPicked} label={t(bindings.some((l) => l.kind === 'win_rdp') ? 'deploy.places' : bindings.some((l) => l.kind === 'win_ccs_file') ? 'deploy.bindingsOrFiles' : 'deploy.bindings')}>
            <Stack gap="sm" mt="xs">
              {groups.map((g) => {
                const name = g.cert ? certificateSubject(g.cert) : '';
                const choosable = g.items.filter((p) => p.deployable && canDeployTo(p)).map((p) => p.id);
                const headingId = `deploy-group-${g.key || 'none'}`;
                return (
                  // A group per certificate, named by its heading (level 3: the dialog's title is the h2).
                  <Box key={g.key} data-testid="deploy-certificate-group" role="group" aria-labelledby={headingId}>
                    <Group gap="xs" justify="space-between">
                      <Title order={3} size="sm" id={headingId} translate={g.cert ? 'no' : undefined}>
                        {g.cert ? name : t('locations.group.noCertificate')}
                      </Title>
                      {g.cert && choosable.length > 0 && (
                        <Button size="xs" variant="subtle" aria-label={t('deploy.selectGroupNamed', { name })} onClick={() => setPicked(choosable)}>
                          {t('deploy.selectGroup')}
                        </Button>
                      )}
                    </Group>
                    {g.items.map((p) => (
                      <WebsiteChoice key={p.id} place={p} refused={refused === p.id} refusedText={refusedText} disabled={!p.deployable || !canDeployTo(p)} />
                    ))}
                  </Box>
                );
              })}
            </Stack>
          </Checkbox.Group>
        )}

        {location !== undefined && !bindings && (
          <Stack gap={2}>
            <Text size="sm" fw={600}>
              {t('deploy.website')}
            </Text>
            <Box
              data-refused={refused === location.id ? 'true' : undefined}
              p="xs"
              className={refused === location.id ? deploy.refused : undefined}
            >
              <Text size="sm">
                <SiteName loc={location} />{' '}
                <Text span c="dimmed" translate="no">
                  {location.target_name}
                </Text>
              </Text>
              <Code translate="no" style={WRAP}>
                {location.cert_path}
              </Code>
              {refused === location.id && (
                <Text size="sm" c="var(--alice-danger)" role="alert" mt={4}>
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
                <WebsiteChoice key={p.id} place={p} refused={refused === p.id} refusedText={refusedText} disabled={!p.deployable || !canDeployTo(p)} />
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

        <CanaryChoice serviceId={serviceIdOf(chosen?.service)} destinations={targets.length} override={override} onOverride={setOverride} disabled={busy} />

        <ErrorAlert error={error} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={close} disabled={busy}>
          {t('deploy.cancel')}
        </Button>
        <Button type="submit" loading={busy} disabled={!ready} leftSection={<Icon name="Rocket" size={15} />}>
          {t('deploy.submit')}
        </Button>
      </DialogActions>
    </form>
  );
}

// WebsiteChoice is one tickable website of a certificate: where it is, why it cannot be chosen, and
// (after a refusal) that the server stopped here. A place whose server's software cannot deploy (the
// server-computed deployable, from the deploy_certificate capability) is listed disabled with the
// "not available yet" note, not hidden.
function WebsiteChoice({ place, refused, refusedText, disabled }: { place: CertificateLocation; refused: boolean; refusedText: string; disabled: boolean }) {
  const { t } = useTranslation();
  const unavailable = place.deployable ? '' : unavailableNote(t, { type: place.target_type });
  const reason = unavailable
    ? ''
    : !place.supported
    ? t(unsupportedReasonKey(place.unsupported_reason))
    : place.missing_since !== null
      ? t('locations.rowUnavailable.missing')
      : place.active_deployment_id !== null
        ? t('locations.rowUnavailable.deploying')
        : '';
  const problem =
    !place.supported && place.unsupported_reason === 'file_problem' ? [place.problem && t(fileProblemKey(place.problem)), place.key_problem && t(fileProblemKey(place.key_problem))].filter(Boolean) : [];
  return (
    <Box data-refused={refused ? 'true' : undefined} p="xs" className={refused ? deploy.refused : undefined}>
      <Checkbox
        value={place.id}
        disabled={disabled}
        error={refused ? refusedText : undefined}
        label={
          <span>
            <SiteName loc={place} />{' '}
            <Text span c="dimmed" translate="no">
              {place.target_name}
            </Text>{' '}
            <Code translate="no">{place.cert_path}</Code>
          </span>
        }
      />
      {unavailable && (
        <Text size="xs" ml={28} mt={2} data-testid="deploy-unavailable">
          {unavailable}
        </Text>
      )}
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
