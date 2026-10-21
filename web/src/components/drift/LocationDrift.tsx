import { Box, Button, Code, Group, NativeSelect, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { driftSummary, healthKey, modeKey, repairDrift, setDriftMode, DRIFT_MODE_SETTINGS, type DriftModeSetting, type LocationObservation } from '../../api/drift';
import { DEPLOYMENTS_KEY } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import type { IconName } from '../../design/Icon';
import { ErrorAlert } from '../ErrorAlert';
import { useNow } from '../Expiry';
import { InternalLink } from '../InternalLink';
import { useStepUp } from '../StepUpProvider';
import { Notice, StatusBadge, type Tone } from '../ui';

// What a bound location should have, what Alice last deployed there and what is observed today (R52), shown where the
// location is listed: on the issued certificate's page (its websites) and on the server's page (its certificate files).

const HEALTH_TONE: Record<string, Tone> = { in_sync: 'success', drifted: 'danger', pending: 'info', unreachable: 'warning', stale: 'neutral', unmanaged: 'neutral' };
const HEALTH_ICON: Record<string, IconName> = { in_sync: 'CircleCheck', drifted: 'CircleX', pending: 'Clock3', unreachable: 'Unplug', stale: 'CircleHelp', unmanaged: 'CircleOff' };

// shortFingerprint is the first 16 hex digits of a leaf's fingerprint (how the deployment pages name one).
const shortFingerprint = (fp: string) => fp.slice(0, 16);

export function HealthBadge({ observation: o }: { observation: LocationObservation }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={HEALTH_TONE[o.health] ?? 'neutral'} icon={HEALTH_ICON[o.health] ?? 'CircleDot'} size="sm" data-health={o.health}>
      {t(healthKey(o.health))}
    </StatusBadge>
  );
}

// ObservationFacts lists the four facts, each with its own time: the certificate the location should have, the one
// Alice last deployed, the one in the file at the last scan that read it, and the one the website served at the last
// probe (from Alice or from the server itself, with the trust of the served chain).
export function ObservationFacts({ observation: o }: { observation: LocationObservation }) {
  const { t, i18n } = useTranslation();
  const time = (iso: string | null) => (iso ? formatDateTime(iso, i18n.language) : '');
  const cert = (fp: string) => {
    if (fp === '') return t('drift.facts.none');
    return fp === o.desired?.fingerprint ? t('drift.facts.desiredOne') : t('drift.facts.other', { fp: shortFingerprint(fp) });
  };
  return (
    <Stack gap={2} data-testid="observation-facts">
      <Text size="xs">
        {t('drift.facts.desired')}{' '}
        {o.desired ? (
          <Code translate="no">{shortFingerprint(o.desired.fingerprint)}</Code>
        ) : (
          t('drift.facts.none')
        )}
      </Text>
      <Text size="xs">
        {o.last_deployment ? (
          <>
            {t('drift.facts.lastDeployed', { cert: cert(o.last_deployment.fingerprint), time: time(o.last_deployment.finished_at) })}{' '}
            <InternalLink to={`/deployments/${o.last_deployment.deployment_id}`} size="xs">
              {t('drift.facts.openDeployment')}
            </InternalLink>
          </>
        ) : (
          t('drift.facts.neverDeployed')
        )}
      </Text>
      <Text size="xs" data-testid="fact-file">
        {o.file ? t('drift.facts.file', { cert: cert(o.file.fingerprint), time: time(o.file.observed_at) }) : t('drift.facts.fileNever')}
      </Text>
      <Text size="xs" data-testid="fact-tls">
        {o.tls
          ? t(o.tls.probe === 'helper' ? 'drift.facts.tlsHelper' : 'drift.facts.tlsAlice', { cert: cert(o.tls.fingerprint), time: time(o.tls.observed_at) })
          : t('drift.facts.tlsNever')}
        {o.tls?.trust === 'untrusted' && ` ${t('drift.facts.untrusted')}`}
      </Text>
      {o.tls_error && o.tls_attempted_at && (
        <Text size="xs" data-testid="fact-unreachable">
          {t('drift.facts.lastProbeFailed', { time: time(o.tls_attempted_at) })}
        </Text>
      )}
      {o.drift_since && <Text size="xs">{t('drift.facts.driftSince', { time: time(o.drift_since) })}</Text>}
    </Stack>
  );
}

// DriftControls is the location's repair mode and, when it drifted, the one-action repair. Observe and approve change
// nothing on a server; automatic repair is switching unattended deployment on (an Administrator's, with a fresh
// step-up: the server applies the rule). The repair is a person's deployment of the certificate the location should
// have.
export function DriftControls({ locationId, label, observation: o, admin, canOperate, locked, onChanged }: { locationId: string; label: string; observation: LocationObservation; admin: boolean; canOperate: boolean; locked: boolean; onChanged: () => void }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [repaired, setRepaired] = useState<string | null>(null);
  const autoNow = o.mode === 'auto' && o.backed_off_at === null;
  const choose = async (mode: DriftModeSetting) => {
    setBusy(true);
    setError(null);
    try {
      const turnsAuto = mode === 'auto' || (mode === 'default' && o.default_mode === 'auto');
      await (turnsAuto && !autoNow ? run(() => setDriftMode(locationId, mode)) : setDriftMode(locationId, mode));
    } catch (e) {
      setError(e);
    }
    setBusy(false);
    onChanged();
  };
  const repair = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await repairDrift(locationId);
      setRepaired(res.deployments[0]?.id ?? null);
      void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
    } catch (e) {
      setError(e);
    }
    setBusy(false);
    onChanged();
  };
  const options = DRIFT_MODE_SETTINGS.map((m) => ({
    value: m,
    label: m === 'default' ? t('drift.mode.defaultIs', { mode: t(modeKey(o.default_mode)) }) : t(modeKey(m)),
    // An Operator chooses observe or approve; automatic repair is an Administrator's.
    disabled: !admin && (m === 'auto' || (m === 'default' && o.default_mode === 'auto')) && !autoNow,
  }));
  return (
    <Stack gap={4} data-testid="drift-controls">
      {/* The accessible names carry the website, which is data: they sit in hidden translate="no" elements. */}
      <span id={`drift-mode-${locationId}`} hidden translate="no">
        {t('drift.mode.named', { site: label })}
      </span>
      <span id={`drift-repair-${locationId}`} hidden translate="no">
        {t('drift.repairNamed', { site: label })}
      </span>
      {canOperate ? (
        <NativeSelect size="xs" label={t('drift.mode.label')} aria-labelledby={`drift-mode-${locationId}`} value={o.mode_setting} disabled={locked || busy} data={options} onChange={(e) => void choose(e.currentTarget.value as DriftModeSetting)} />
      ) : (
        <Text size="xs">{t('drift.mode.current', { mode: t(modeKey(o.mode)) })}</Text>
      )}
      {o.backoff_reason !== '' && (
        <Text size="xs" c="dimmed" data-testid="drift-backoff">
          {t(`drift.backoff.${o.backoff_reason}`)}
        </Text>
      )}
      {canOperate && o.repair_available && (
        <Button size="xs" color="red" variant="light" loading={busy} disabled={locked} aria-labelledby={`drift-repair-${locationId}`} onClick={() => void repair()}>
          {t('drift.repair')}
        </Button>
      )}
      {repaired && (
        <InternalLink to={`/deployments/${repaired}`} size="xs">
          {t('drift.repairQueued')}
        </InternalLink>
      )}
      <ErrorAlert error={error} />
    </Stack>
  );
}

// DriftSummaryLine sums the observed places up: "Live and verified on 17 of 20 places; 2 not reachable; 1 serves
// another certificate (it ends in 18 hours)".
export function DriftSummaryLine({ observations }: { observations: (LocationObservation | null | undefined)[] }) {
  const { t } = useTranslation();
  const now = useNow();
  const s = driftSummary(observations);
  if (s.total === 0) return null;
  const parts = [t('drift.summary.inSync', { n: s.inSync, count: s.total })];
  if (s.unreachable > 0) parts.push(t('drift.summary.unreachable', { count: s.unreachable }));
  if (s.drifted > 0) {
    const hours = s.driftedExpires ? Math.max(0, Math.round((Date.parse(s.driftedExpires) - now) / 3_600_000)) : null;
    parts.push(hours === null ? t('drift.summary.drifted', { count: s.drifted }) : t('drift.summary.driftedEnds', { count: s.drifted, hours }));
  }
  if (s.other > 0) parts.push(t('drift.summary.other', { count: s.other }));
  return (
    <Box data-testid="drift-summary">
      {s.drifted > 0 ? (
        <Notice tone="danger" title={parts.join('; ')} testId="drift-summary-notice">
          {t('drift.summary.driftedHelp')}
        </Notice>
      ) : (
        <Group gap="xs">
          <Text size="sm" fw={600}>
            {parts.join('; ')}
          </Text>
        </Group>
      )}
    </Box>
  );
}
