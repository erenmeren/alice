import { Anchor, Button, Code, Group, Loader, NativeSelect, Stack, Table, Text } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { listCertificates } from '../api/endpoints';
import {
  chooseIncidentReplacement,
  closeIncident,
  getIncident,
  INCIDENT_POLL_MS,
  incidentBusy,
  incidentOpen,
  retryIncident,
  revokeIncidentNow,
  type Incident,
  type IncidentLocationStatus,
} from '../api/incidents';
import { CERTIFICATES_KEY, INCIDENTS_KEY, incidentKey } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { Problem, useChangesLocked } from '../components/acme/issued';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { useNow } from '../components/Expiry';
import { useStepUp } from '../components/StepUpProvider';
import { DialogActions, FactList, Notice, PageHeader, Panel, StatusBadge, type Fact, type Tone } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import type { IconName } from '../design/Icon';
import { Icon } from '../design/Icon';

const STATE_TONE: Record<Incident['state'], Tone> = {
  awaiting_replacement: 'warning',
  ordering: 'info',
  deploying: 'info',
  revoking: 'info',
  needs_attention: 'danger',
  completed: 'success',
  closed: 'neutral',
};
const STATE_ICON: Record<Incident['state'], IconName> = {
  awaiting_replacement: 'Clock3',
  ordering: 'RefreshCw',
  deploying: 'Rocket',
  revoking: 'ShieldAlert',
  needs_attention: 'CircleAlert',
  completed: 'CircleCheck',
  closed: 'CircleDot',
};
const LOCATION_TONE: Record<IncidentLocationStatus, Tone> = {
  pending: 'neutral',
  deploying: 'info',
  verified: 'success',
  unverified: 'warning',
  failed: 'danger',
  skipped: 'neutral',
};

type Action = 'retry' | 'revokeNow' | 'close' | 'replacement';

// IncidentPage follows one key compromise incident: what Alice does now, every affected place with how its replacement
// went, whether the compromised certificate is revoked, and the actions an Administrator has (retry, revoke now
// regardless, choose the replacement, close). It refreshes itself while Alice works on the incident.
export function IncidentPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const admin = session?.user.role === 'admin';
  const locked = useChangesLocked();
  const client = useQueryClient();
  const { run } = useStepUp();
  const q = useQuery({
    queryKey: incidentKey(id),
    queryFn: ({ signal }) => getIncident(id, signal),
    refetchInterval: (s) => (s.state.data && incidentBusy(s.state.data) ? INCIDENT_POLL_MS : false),
  });
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (q.isPending) return <PageLoader />;
  if (q.isError || !q.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={q.error} />
        <Anchor component={Link} to="/certificates" w="fit-content" size="sm">
          {t('certificates.detail.backToList')}
        </Anchor>
      </Stack>
    );
  const i = q.data;
  const open = incidentOpen(i);
  const acme = i.acme_certificate_id !== null;
  const lang = i18n.language;
  const act = async (fn: () => Promise<Incident>) => {
    setBusy(true);
    setError(null);
    try {
      const next = await run(fn);
      client.setQueryData(incidentKey(id), next);
      void client.invalidateQueries({ queryKey: INCIDENTS_KEY });
      void client.invalidateQueries({ queryKey: CERTIFICATES_KEY });
      setConfirm(null);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };

  const facts: Fact[] = [
    {
      key: 'certificate',
      label: t('incidents.facts.certificate'),
      value: (
        <Anchor component={Link} to={`/certificates/${i.certificate_id}`} translate="no">
          {i.certificate_name}
        </Anchor>
      ),
    },
    { key: 'started', label: t('incidents.facts.started'), value: `${formatDateTime(i.created_at, lang)}${i.started_by_name ? ` · ${i.started_by_name}` : ''}` },
    {
      key: 'replacement',
      label: t('incidents.facts.replacement'),
      value: i.replacement_certificate_id ? (
        <Anchor component={Link} to={`/certificates/${i.replacement_certificate_id}`}>
          <Code translate="no">{i.replacement_fingerprint.slice(0, 16)}…</Code>
        </Anchor>
      ) : (
        t(acme ? 'incidents.facts.replacementOrdering' : 'incidents.facts.replacementNone')
      ),
      testId: 'replacement',
    },
    { key: 'revocation', label: t('incidents.facts.revocation'), value: t(`incidents.revocation.${i.revocation}`), testId: 'revocation' },
    { key: 'mode', label: t('incidents.facts.revokeMode'), value: t(`incidents.revokeMode.${i.revoke_mode}`) },
    ...(i.revoked_at ? [{ key: 'revokedAt', label: t('incidents.facts.revokedAt'), value: formatDateTime(i.revoked_at, lang) }] : []),
    ...(i.next_attempt_at && i.revocation === 'pending'
      ? [{ key: 'next', label: t('incidents.facts.nextRevoke'), value: t('incidents.facts.nextRevokeValue', { time: formatDateTime(i.next_attempt_at, lang), count: i.revoke_attempts }) }]
      : []),
    ...(i.finished_at ? [{ key: 'finished', label: t('incidents.facts.finished'), value: formatDateTime(i.finished_at, lang) }] : []),
  ];
  const canRevokeNow = open && acme && (i.revocation === 'pending' || i.revocation === 'failed') && i.revoke_mode !== 'now';
  const canChoose = open && !acme && (i.state === 'awaiting_replacement' || (i.state === 'needs_attention' && i.replacement_certificate_id === null));
  const locations = i.locations ?? [];

  return (
    <Stack gap="md">
      <PageHeader
        back={{ to: `/certificates/${i.certificate_id}`, label: t('incidents.backToCertificate') }}
        icon="ShieldAlert"
        title={t('incidents.title')}
        description={
          <>
            {t('incidents.description')} <span translate="no">{i.certificate_name}</span>
          </>
        }
        status={
          <StatusBadge tone={STATE_TONE[i.state]} icon={STATE_ICON[i.state]} testId="incident-state" data-state={i.state}>
            {t(`incidents.states.${i.state}`)}
          </StatusBadge>
        }
        actions={
          admin && open ? (
            <>
              {i.state === 'needs_attention' && (
                <Button leftSection={<Icon name="RotateCw" size={15} />} disabled={locked || busy} onClick={() => void act(() => retryIncident(id))}>
                  {t('incidents.actions.retry')}
                </Button>
              )}
              {canChoose && (
                <Button leftSection={<Icon name="FileKey2" size={15} />} disabled={locked || busy} onClick={() => setConfirm('replacement')}>
                  {t('incidents.actions.choose')}
                </Button>
              )}
              {canRevokeNow && (
                <Button variant="light" color="red" leftSection={<Icon name="ShieldAlert" size={15} />} disabled={locked || busy} onClick={() => setConfirm('revokeNow')}>
                  {t('incidents.actions.revokeNow')}
                </Button>
              )}
              <Button variant="default" disabled={busy} onClick={() => setConfirm('close')}>
                {t('incidents.actions.close')}
              </Button>
            </>
          ) : undefined
        }
      />
      {incidentBusy(i) && (
        <Group gap="sm" role="status" aria-live="polite" data-testid="incident-busy">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t(`incidents.busy.${i.state}`)}</Text>
        </Group>
      )}
      <StateNotice i={i} />
      {!acme && open && (
        <Notice tone="warning" title={t('incidents.notRevocableTitle')} testId="not-revocable">
          {t('incidents.notRevocableText')}
        </Notice>
      )}
      <ErrorAlert error={error} />
      {!admin && open && <Text size="sm">{t('incidents.adminOnly')}</Text>}
      <Panel title={t('incidents.summary')}>
        <FactList facts={facts} label={t('incidents.summary')} />
      </Panel>
      <Panel title={t('incidents.locations.title')} description={t('incidents.locations.description')} padded={locations.length === 0}>
        {locations.length === 0 ? (
          <Text size="sm">{t('incidents.locations.none')}</Text>
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table aria-label={t('incidents.locations.title')} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('certificates.detail.columns.server')}</Table.Th>
                  <Table.Th>{t('certificates.detail.columns.file')}</Table.Th>
                  <Table.Th>{t('incidents.locations.status')}</Table.Th>
                  <Table.Th>{t('incidents.locations.detail')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {locations.map((l) => (
                  <Table.Tr key={l.location_id} data-testid="incident-location" data-status={l.status}>
                    <Table.Td>
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
                      {l.outcome_uncertain ? (
                        <StatusBadge tone="warning" size="sm" testId="location-uncertain">
                          {t('incidents.locationStatus.uncertain')}
                        </StatusBadge>
                      ) : (
                        <StatusBadge tone={LOCATION_TONE[l.status]} size="sm">
                          {t(`incidents.locationStatus.${l.status}`)}
                        </StatusBadge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {l.error && <Problem error={l.error} />}
                      {l.deployment_id && (
                        <Anchor component={Link} to={`/deployments/${l.deployment_id}`} size="sm">
                          {t('incidents.locations.deployment')}
                        </Anchor>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Panel>
      {(confirm === 'close' || confirm === 'revokeNow') && (
        <AppModal opened onClose={() => !busy && setConfirm(null)} title={t(confirm === 'close' ? 'incidents.close.title' : 'incidents.revokeNow.title')}>
          <Stack gap="sm">
            <Text size="sm">{t(confirm === 'close' ? 'incidents.close.text' : 'incidents.revokeNow.text')}</Text>
            <ErrorAlert error={error} />
            <DialogActions>
              <Button variant="default" disabled={busy} onClick={() => setConfirm(null)}>
                {t('ui.cancel')}
              </Button>
              <Button
                color="red"
                loading={busy}
                onClick={() => void (confirm === 'close' ? act(() => closeIncident(id)) : act(() => revokeIncidentNow(id)))}
              >
                {t(confirm === 'close' ? 'incidents.close.confirm' : 'incidents.revokeNow.confirm')}
              </Button>
            </DialogActions>
          </Stack>
        </AppModal>
      )}
      {confirm === 'replacement' && (
        <ReplacementDialog
          incident={i}
          busy={busy}
          error={error}
          onClose={() => setConfirm(null)}
          onChoose={(cert) => void act(() => chooseIncidentReplacement(id, cert))}
        />
      )}
    </Stack>
  );
}

// StateNotice says, in one notice, what the incident's state means for the person.
function StateNotice({ i }: { i: Incident }) {
  const { t } = useTranslation();
  if (i.state === 'needs_attention')
    return (
      <Notice tone="danger" role="alert" title={t('incidents.notice.needs_attention')} testId="incident-attention">
        {i.attention && <Problem error={i.attention} />}
      </Notice>
    );
  return (
    <Notice tone={STATE_TONE[i.state]} title={t(`incidents.notice.${i.state}`)} testId="incident-notice">
      {t(`incidents.noticeText.${i.state}`)}
    </Notice>
  );
}

// ReplacementDialog chooses the replacement of a certificate from another source: a certificate Alice holds the key
// of, made with another key, neither revoked nor compromised. The server checks it again.
function ReplacementDialog({ incident, busy, error, onClose, onChoose }: { incident: Incident; busy: boolean; error: unknown; onClose: () => void; onChoose: (id: string) => void }) {
  const { t } = useTranslation();
  const list = useQuery({ queryKey: [...CERTIFICATES_KEY, 'replacements'], queryFn: () => listCertificates({ limit: 200 }) });
  const now = useNow();
  const candidates = (list.data?.items ?? []).filter(
    (c) =>
      c.has_private_key &&
      c.id !== incident.certificate_id &&
      c.public_key_sha256 !== incident.public_key_sha256 &&
      c.revoked_at === null &&
      c.compromised_at === null &&
      Date.parse(c.not_after) > now,
  );
  const [choice, setChoice] = useState('');
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('incidents.replacement.title')}>
      <Stack gap="sm">
        <Text size="sm">{t('incidents.replacement.text')}</Text>
        <ErrorAlert error={list.error} />
        <NativeSelect
          label={t('incidents.replacement.certificate')}
          data={[
            { value: '', label: candidates.length === 0 ? t('incidents.replacement.none') : t('incidents.replacement.placeholder') },
            ...candidates.map((c) => ({ value: c.id, label: `${c.label || c.subject_cn || c.fingerprint.slice(0, 16)} (${c.fingerprint.slice(0, 8)})` })),
          ]}
          value={choice}
          onChange={(e) => setChoice(e.currentTarget.value)}
        />
        <Text size="xs" c="dimmed">
          {t('incidents.replacement.uploadHint')}{' '}
          <Anchor component={Link} to="/certificates" size="xs">
            {t('incidents.replacement.openCertificates')}
          </Anchor>
        </Text>
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button loading={busy} disabled={!choice} onClick={() => choice && onChoose(choice)}>
            {t('incidents.replacement.confirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
