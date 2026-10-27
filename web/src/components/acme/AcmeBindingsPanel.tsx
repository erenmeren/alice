import { Alert, Anchor, Box, Button, Checkbox, Code, Group, Stack, Switch, Table, Text, TextInput, VisuallyHidden } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CanaryChoice, serviceIdOf } from '../CanaryChoice';
import { Link } from 'react-router';
import { bindingStateKey, deleteACMEBinding, deployACMECertificate, listACMEBindings, putACMEBinding, releaseACMEHold, updateACMECertificate, type ACMEBinding, type ACMECertificate } from '../../api/acme';
import { isApiError } from '../../api/client';
import { listDeployableLocations, type DeployableLocation } from '../../api/keyvault';
import { ACME_CERTIFICATES_KEY, acmeBindingsKey, acmeCertificateKey, DEPLOYMENTS_KEY } from '../../api/queryKeys';
import type { DeployResult } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import deploy from '../deploy.module.css';
import { ErrorAlert } from '../ErrorAlert';
import { DriftControls, DriftSummaryLine, HealthBadge, ObservationFacts } from '../drift/LocationDrift';
import { InternalLink } from '../InternalLink';
import { LoadingIndicator } from '../LoadingIndicator';
import { HiddenCount } from '../services/shared';
import { useOptionalStepUp, useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, Notice, Panel, StatusBadge, type Tone } from '../ui';
import { WRAP } from '../wrap';
import { keyFamily, MAX_DEPLOY, Problem } from './issued';

const STATE_TONE: Record<string, Tone> = { current: 'success', pending: 'info', attention: 'warning', drifted: 'danger' };
const STATE_ICON = { current: 'CircleCheck', pending: 'Clock3', attention: 'CircleAlert', drifted: 'CircleX' } as const;

// placeColumnKey names the place column by the kinds it lists (R66): Binding when every row is a Windows binding,
// Certificate file when none is, both when they are mixed. Any other kind counts as a file, a Windows server's CCS file too (R68).
function placeColumnKey(items: Pick<ACMEBinding, 'location_kind'>[]): string {
  const bindings = items.filter((b) => b.location_kind === 'win_sslbinding').length;
  if (bindings === 0) return 'acme.issued.bindings.columns.file';
  return bindings === items.length ? 'acme.issued.bindings.columns.binding' : 'acme.issued.bindings.columns.place';
}

// AcmeBindingsPanel is "Websites using this certificate": the websites that follow an issued certificate, what each
// serves, automatic deployment (the certificate's and each website's), the hold and stop marks of automatic deployment,
// Add websites and Deploy now. Operators connect, remove, deploy and switch automatic deployment off; switching it on is
// an Administrator's, with a fresh step-up (the server applies the rule inside the change).
export function AcmeBindingsPanel({ certificate: c, admin, canOperate, locked }: { certificate: ACMECertificate; admin: boolean; canOperate: boolean; locked: boolean }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const bindings = useQuery({ queryKey: acmeBindingsKey(c.id), queryFn: () => listACMEBindings(c.id) });
  const [adding, setAdding] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [removing, setRemoving] = useState<ACMEBinding | null>(null);
  const [confirmAuto, setConfirmAuto] = useState<{ binding: ACMEBinding | null } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const items = bindings.data?.items ?? [];
  const issued = c.current !== null;

  const refresh = () => {
    void client.invalidateQueries({ queryKey: acmeCertificateKey(c.id) });
    void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY, predicate: (q) => q.queryKey[2] === 'list' });
    void client.invalidateQueries({ queryKey: ['locations'] });
  };
  const change = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await run(fn);
      setConfirmAuto(null);
    } catch (e) {
      setError(e);
    }
    setBusy(null);
    refresh();
  };
  // Switching off is immediate; switching on first says what it means.
  const setBindingAuto = (b: ACMEBinding, on: boolean) => (on ? setConfirmAuto({ binding: b }) : void change(b.location_id, () => putACMEBinding(c.id, b.location_id, false)));
  const setCertAuto = (on: boolean) => (on ? setConfirmAuto({ binding: null }) : void change('cert', () => updateACMECertificate(c.id, { auto_deploy: false })));

  return (
    <Panel title={t('acme.issued.bindings.title')} description={t('acme.issued.bindings.description')} testId="acme-bindings">
      <Stack gap="md">
        {!issued && <EmptyState icon="Server" title={t('acme.issued.bindings.notIssued')} description={t('acme.issued.bindings.notIssuedText')} />}
        {issued && c.deploy_held_reason === 'license' && <HeldNotice c={c} admin={admin} locked={locked} onDone={refresh} />}
        {issued && c.deploy_held_reason === 'chain_incomplete' && (
          <Notice tone="warning" title={t('acme.issued.bindings.heldChainTitle')} testId="held-chain">
            {t(admin ? 'acme.issued.bindings.heldChainAdmin' : 'acme.issued.bindings.heldChainOther')}
          </Notice>
        )}
        {issued && c.deploy_stopped && (
          <Notice tone="warning" title={t('acme.issued.bindings.stoppedTitle')} testId="deploy-stopped">
            {t('acme.issued.bindings.stoppedText')}
          </Notice>
        )}
        <Stack gap={4} data-testid="cert-auto-deploy">
          <Group gap="sm">
            <Text size="sm" fw={600} id={`auto-cert-${c.id}`}>
              {t('acme.issued.bindings.certAuto')}
            </Text>
            {admin ? (
              <Switch
                aria-labelledby={`auto-cert-${c.id}`}
                checked={c.auto_deploy}
                disabled={locked || busy !== null}
                label={t(c.auto_deploy ? 'acme.issued.on' : 'acme.issued.off')}
                onChange={(e) => setCertAuto(e.currentTarget.checked)}
              />
            ) : (
              <Text size="sm">{t(c.auto_deploy ? 'acme.issued.on' : 'acme.issued.off')}</Text>
            )}
          </Group>
          <Text size="sm">{t(c.auto_deploy ? 'acme.issued.bindings.certAutoOn' : 'acme.issued.bindings.certAutoOff')}</Text>
          {!admin && <Text size="xs" c="dimmed">{t('acme.issued.adminOnly')}</Text>}
        </Stack>
        {issued && bindings.isSuccess && items.length > 0 && <AutoSummary c={c} items={items} />}
        {issued && bindings.isSuccess && items.length > 0 && <DriftSummaryLine observations={items.map((b) => b.observation)} />}
        {bindings.isPending && <LoadingIndicator />}
        <ErrorAlert error={bindings.error} />
        {issued && bindings.isSuccess && items.length === 0 && <Text size="sm">{t('acme.issued.bindings.none')}</Text>}
        {items.length > 0 && (
          <Table.ScrollContainer minWidth={1100}>
            <Table aria-label={t('acme.issued.bindings.title')} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('acme.issued.bindings.columns.server')}</Table.Th>
                  <Table.Th>{t(placeColumnKey(items))}</Table.Th>
                  <Table.Th>{t('acme.issued.bindings.columns.state')}</Table.Th>
                  <Table.Th>{t('drift.columns.observed')}</Table.Th>
                  <Table.Th>{t('acme.issued.bindings.columns.auto')}</Table.Th>
                  <Table.Th>{t('drift.columns.repair')}</Table.Th>
                  {canOperate && (
                    <Table.Th>
                      <VisuallyHidden>{t('acme.issued.bindings.columns.actions')}</VisuallyHidden>
                    </Table.Th>
                  )}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((b) => (
                  <Table.Tr key={b.location_id} data-testid="acme-binding" data-state={b.state}>
                    <Table.Td style={WRAP}>
                      <Anchor component={Link} to={`/servers/${b.target_id}`} translate="no">
                        {b.target_name}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <Code translate="no" style={WRAP}>
                        {b.cert_path}
                      </Code>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={4} align="flex-start">
                        <StatusBadge tone={STATE_TONE[b.state] ?? 'neutral'} icon={STATE_ICON[b.state] ?? 'CircleDot'} size="sm">
                          {t(bindingStateKey(b.state))}
                        </StatusBadge>
                        <Text size="xs">{t(servedKey(b, c))}</Text>
                        {b.attention && (
                          <Box data-testid="attention">
                            {b.attention_at && (
                              <Text size="xs" c="dimmed">
                                {t('acme.issued.bindings.attentionAt', { time: formatDateTime(b.attention_at, i18n.language) })}
                              </Text>
                            )}
                            <Problem error={b.attention} />
                          </Box>
                        )}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      {b.observation && (
                        <Stack gap={4} align="flex-start">
                          <HealthBadge observation={b.observation} />
                          <ObservationFacts observation={b.observation} windows={b.location_kind === 'win_sslbinding'} />
                        </Stack>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <BindingAuto b={b} admin={admin} canOperate={canOperate} locked={locked} busy={busy !== null} onChange={(on) => setBindingAuto(b, on)} />
                    </Table.Td>
                    <Table.Td>
                      {b.observation && (
                        <DriftControls
                          locationId={b.location_id}
                          label={`"${b.target_name}" ${b.cert_path}`}
                          observation={b.observation}
                          admin={admin}
                          canOperate={canOperate}
                          locked={locked}
                          onChanged={() => {
                            void client.invalidateQueries({ queryKey: acmeBindingsKey(c.id) });
                            refresh();
                          }}
                        />
                      )}
                    </Table.Td>
                    {canOperate && (
                      <Table.Td>
                        <Button size="xs" variant="light" color="red" aria-label={t('acme.issued.bindings.removeNamed', { site: `"${b.target_name}" ${b.cert_path}` })} onClick={() => setRemoving(b)}>
                          {t('acme.issued.bindings.remove')}
                        </Button>
                      </Table.Td>
                    )}
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {items.length > 0 && (
          <Notice tone="neutral" title={t('acme.issued.bindings.byHandTitle')}>
            {t('acme.issued.bindings.byHand')}
          </Notice>
        )}
        <HiddenCount count={bindings.data?.hidden_count} />
        {!admin && items.some((b) => !b.auto_deploy) && <Text size="xs" c="dimmed">{t('acme.issued.bindings.autoAdminOnly')}</Text>}
        {!confirmAuto && <ErrorAlert error={error} />}
        {canOperate && issued && (
          <Group gap="sm">
            <Button leftSection={<Icon name="Rocket" size={15} />} disabled={locked || items.length === 0} onClick={() => setDeploying(true)}>
              {t('acme.issued.deployNow')}
            </Button>
            <Button variant="default" leftSection={<Icon name="Plus" size={15} />} disabled={locked} onClick={() => setAdding(true)}>
              {t('acme.issued.bindings.add')}
            </Button>
          </Group>
        )}
        {adding && (
          <AddWebsitesDialog
            c={c}
            bound={items}
            onClose={() => setAdding(false)}
            onDone={() => {
              setAdding(false);
              refresh();
            }}
            onChanged={refresh}
          />
        )}
        {deploying && <DeployNowDialog c={c} bindings={items} admin={admin} onClose={() => setDeploying(false)} onDone={refresh} />}
        {removing && (
          <RemoveDialog
            c={c}
            b={removing}
            onClose={() => setRemoving(null)}
            onDone={() => {
              setRemoving(null);
              refresh();
            }}
          />
        )}
        {confirmAuto && (
          <AppModal opened onClose={() => busy === null && setConfirmAuto(null)} title={t('acme.issued.bindings.autoConfirmTitle')}>
            <Stack gap="sm">
              <Text size="sm">{t(confirmAuto.binding ? 'acme.issued.bindings.autoConfirmSite' : 'acme.issued.bindings.autoConfirmCert')}</Text>
              {confirmAuto.binding && (
                <Text size="sm">
                  <Text span translate="no" fw={600}>
                    {confirmAuto.binding.target_name}
                  </Text>{' '}
                  <Code translate="no">{confirmAuto.binding.cert_path}</Code>
                </Text>
              )}
              <Text size="sm">{t('acme.issued.bindings.autoConfirmStepUp')}</Text>
              <ErrorAlert error={error} />
              <DialogActions>
                <Button variant="default" disabled={busy !== null} onClick={() => setConfirmAuto(null)}>
                  {t('ui.cancel')}
                </Button>
                <Button
                  loading={busy !== null}
                  onClick={() => {
                    const b = confirmAuto.binding;
                    void (b ? change(b.location_id, () => putACMEBinding(c.id, b.location_id, true)) : change('cert', () => updateACMECertificate(c.id, { auto_deploy: true })));
                  }}
                >
                  {t('acme.issued.bindings.autoConfirm')}
                </Button>
              </DialogActions>
            </Stack>
          </AppModal>
        )}
      </Stack>
    </Panel>
  );
}

// AutoSummary puts the two switches together: how many websites receive a new certificate by themselves (both the
// certificate's and the website's automatic deployment on), with a warning when only one of the two is on.
function AutoSummary({ c, items }: { c: ACMECertificate; items: ACMEBinding[] }) {
  const { t } = useTranslation();
  const sitesOn = items.filter((b) => b.auto_deploy).length;
  const n = c.auto_deploy ? sitesOn : 0;
  return (
    <Stack gap={4} data-testid="auto-summary">
      <Text size="sm" fw={600}>
        {t('acme.issued.bindings.autoSummary', { n, count: items.length })}
      </Text>
      {c.auto_deploy && sitesOn === 0 && (
        <Notice tone="warning" title={t('acme.issued.bindings.autoCertOnly')} testId="auto-cert-only" />
      )}
      {!c.auto_deploy && sitesOn > 0 && (
        <Notice tone="warning" title={t('acme.issued.bindings.autoSitesOnly', { count: sitesOn })} testId="auto-sites-only" />
      )}
    </Stack>
  );
}

// servedKey says what a website serves compared with the current certificate.
function servedKey(b: ACMEBinding, c: ACMECertificate): string {
  if (b.served_certificate_id === null) return 'acme.issued.bindings.servedNone';
  if (c.current && b.served_certificate_id === c.current.id) return 'acme.issued.bindings.servedCurrent';
  return 'acme.issued.bindings.servedOlder';
}

function BindingAuto({ b, admin, canOperate, locked, busy, onChange }: { b: ACMEBinding; admin: boolean; canOperate: boolean; locked: boolean; busy: boolean; onChange: (on: boolean) => void }) {
  const { t } = useTranslation();
  const label = t('acme.issued.bindings.autoNamed', { site: `"${b.target_name}" ${b.cert_path}` });
  if (!canOperate) return <Text size="sm">{t(b.auto_deploy ? 'acme.issued.on' : 'acme.issued.off')}</Text>;
  // An Operator may switch it off, never on.
  const disabled = locked || busy || (!admin && !b.auto_deploy);
  return <Switch checked={b.auto_deploy} disabled={disabled} aria-label={label} label={t(b.auto_deploy ? 'acme.issued.on' : 'acme.issued.off')} onChange={(e) => onChange(e.currentTarget.checked)} />;
}

function HeldNotice({ c, admin, locked, onDone }: { c: ACMECertificate; admin: boolean; locked: boolean; onDone: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const release = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(() => releaseACMEHold(c.id));
    } catch (e) {
      setError(e);
    }
    setBusy(false);
    onDone();
  };
  return (
    <Notice
      tone="warning"
      title={t('acme.issued.bindings.heldTitle')}
      testId="held-license"
      action={
        admin ? (
          <Button size="xs" loading={busy} disabled={locked} onClick={() => void release()}>
            {t('acme.issued.bindings.release')}
          </Button>
        ) : undefined
      }
    >
      <Text size="sm">{t(admin ? 'acme.issued.bindings.heldAdmin' : 'acme.issued.bindings.heldOther')}</Text>
      <ErrorAlert error={error} />
    </Notice>
  );
}

function RemoveDialog({ c, b, onClose, onDone }: { c: ACMECertificate; b: ACMEBinding; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await deleteACMEBinding(c.id, b.location_id);
      onDone();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.bindings.removeTitle')}>
      <Stack gap="sm">
        <Text size="sm">
          <Text span translate="no" fw={600}>
            {b.target_name}
          </Text>{' '}
          <Code translate="no">{b.cert_path}</Code>
        </Text>
        <Text size="sm">{t('acme.issued.bindings.removeText')}</Text>
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={busy} onClick={() => void go()}>
            {t('acme.issued.bindings.remove')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}

// AddWebsitesDialog connects websites to the certificate, one request per website in the chosen order: the list holds
// the Nginx websites whose key type fits and that do not follow this certificate yet; a website that follows a Key Vault
// certificate cannot be chosen. A refusal (another certificate, the key type, an unsupported website) stops at that
// website, which is marked; the ones before it stay connected.
function AddWebsitesDialog({ c, bound, onClose, onDone, onChanged }: { c: ACMECertificate; bound: ACMEBinding[]; onClose: () => void; onDone: () => void; onChanged: () => void }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [q] = useDebouncedValue(search.trim(), 250);
  const [picked, setPicked] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [added, setAdded] = useState(0);
  const family = keyFamily(c.key_type);
  const boundIds = new Set(bound.map((b) => b.location_id));
  const list = useInfiniteQuery({
    queryKey: ['locations', 'deployable', 'acme', family, q],
    queryFn: ({ pageParam }) => listDeployableLocations({ key_type: family || undefined, q: q || undefined, cursor: pageParam, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const items = (list.data?.pages.flatMap((p) => p.items) ?? []).filter((l) => !boundIds.has(l.id));

  const submit = async () => {
    setBusy(true);
    setError(null);
    setRefused(null);
    let done = 0;
    for (const id of picked) {
      try {
        await putACMEBinding(c.id, id, false);
        done++;
      } catch (e) {
        setError(e);
        setRefused(isApiError(e) && e.params.location_id ? e.params.location_id : id);
        // The connected ones leave the choice; the refused one and the rest (not tried) stay chosen.
        setPicked(picked.slice(done));
        setAdded((a) => a + done);
        setBusy(false);
        if (done > 0) onChanged();
        return;
      }
    }
    onDone();
  };

  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.bindings.addTitle')} size="lg">
      <Stack gap="sm">
        <Text size="sm">{t('acme.issued.bindings.addHelp')}</Text>
        <TextInput label={t('bindings.search')} value={search} onChange={(e) => setSearch(e.currentTarget.value)} maxLength={200} autoComplete="off" />
        {list.isPending && <LoadingIndicator />}
        <ErrorAlert error={list.error} />
        {list.isSuccess && items.length === 0 && <Text size="sm">{t('acme.issued.bindings.noLocations')}</Text>}
        <Checkbox.Group value={picked} onChange={setPicked} label={t('bindings.websites')}>
          <Stack gap="xs" mt="xs">
            {items.map((l) => (
              <Choice key={l.id} l={l} refused={refused === l.id} disabled={busy} />
            ))}
          </Stack>
        </Checkbox.Group>
        {list.hasNextPage && (
          <Button variant="default" w="fit-content" loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {t('vaults.showMore')}
          </Button>
        )}
        <Text size="sm" role="status">
          {t('bindings.selectedCount', { count: picked.length })}
        </Text>
        {added > 0 && (
          <Alert color="yellow" role="status">
            {t('acme.issued.bindings.partlyAdded', { count: added })}
          </Alert>
        )}
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={added > 0 ? onDone : onClose}>
            {t(added > 0 ? 'ui.close' : 'ui.cancel')}
          </Button>
          <Button loading={busy} disabled={picked.length === 0} onClick={() => void submit()}>
            {t('acme.issued.bindings.add')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}

function Choice({ l, refused, disabled }: { l: DeployableLocation; refused: boolean; disabled: boolean }) {
  const { t } = useTranslation();
  const vault = l.binding_id !== null;
  return (
    <Box data-refused={refused ? 'true' : undefined} p="xs" className={refused ? deploy.refused : undefined}>
      <Checkbox
        value={l.id}
        disabled={disabled || vault}
        error={refused ? t('bindings.refused') : undefined}
        description={vault ? t('acme.issued.bindings.followsVault') : undefined}
        label={
          <span style={WRAP}>
            <Text span translate="no" fw={600}>
              {l.target_name}
            </Text>{' '}
            {l.server_names.map((n) => (
              <Code key={n} translate="no" mr={4}>
                {n}
              </Code>
            ))}
            <Code translate="no">{l.cert_path}</Code>
          </span>
        }
      />
    </Box>
  );
}

// DeployNowDialog deploys the current certificate to the chosen websites (at most 20 at a time) with one request: all
// or nothing; a refusal names the website that stopped it. An incomplete chain needs an Administrator's confirmation.
function DeployNowDialog({ c, bindings, admin, onClose, onDone }: { c: ACMECertificate; bindings: ACMEBinding[]; admin: boolean; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [picked, setPicked] = useState<string[]>(() => (bindings.length <= MAX_DEPLOY ? bindings.map((b) => b.location_id) : []));
  const [confirmChain, setConfirmChain] = useState(false);
  const [override, setOverride] = useState(false);
  const { run } = useOptionalStepUp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [result, setResult] = useState<DeployResult | null>(null);
  const incomplete = c.current !== null && !c.current.chain_complete;
  const tooMany = picked.length > MAX_DEPLOY;
  const ready = picked.length > 0 && !tooMany && (!incomplete || (admin && confirmChain)) && !busy;

  const submit = async () => {
    if (!ready) return;
    setBusy(true);
    setError(null);
    setRefused(null);
    try {
      const send = () =>
        deployACMECertificate(c.id, {
          location_ids: picked,
          ...(incomplete && admin ? { confirm_incomplete_chain: true } : {}),
          ...(override ? { canary_override: true } : {}),
        });
      const res = override ? await run(send) : await send();
      setResult(res);
      void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
      onDone();
    } catch (e) {
      setError(e);
      if (isApiError(e) && e.params.location_id) setRefused(e.params.location_id);
    }
    setBusy(false);
  };

  const name = (locationId: string) => bindings.find((b) => b.location_id === locationId);
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.deployTitle')} size="lg">
      {result ? (
        <Stack gap="sm">
          <Notice tone="success" role="status" title={t('acme.issued.deployQueued', { count: result.deployments.length })} />
          {result.rollout && <Notice tone="info" role="status" testId="canary-started" title={t('canary.started', { count: result.rollout.wave2.length })} />}
          <Stack gap={4}>
            {result.deployments.map((d) => {
              const b = name(d.location_id);
              return (
                <Group key={d.id} gap="xs">
                  {b && (
                    <Text size="sm" translate="no">
                      {b.target_name}
                    </Text>
                  )}
                  <InternalLink to={`/deployments/${d.id}`} size="sm">
                    {t('deploy.openDeployment')}
                  </InternalLink>
                </Group>
              );
            })}
          </Stack>
          <DialogActions>
            <Button onClick={onClose}>{t('ui.close')}</Button>
          </DialogActions>
        </Stack>
      ) : (
        <Stack gap="sm">
          <Text size="sm">{t('acme.issued.deployHelp', { max: MAX_DEPLOY })}</Text>
          <Checkbox.Group value={picked} onChange={setPicked} label={t('bindings.websites')}>
            <Stack gap="xs" mt="xs">
              {bindings.map((b) => (
                <Box key={b.location_id} data-refused={refused === b.location_id ? 'true' : undefined} p="xs" className={refused === b.location_id ? deploy.refused : undefined}>
                  <Checkbox
                    value={b.location_id}
                    disabled={busy}
                    error={refused === b.location_id ? t('deploy.refused') : undefined}
                    label={
                      <span style={WRAP}>
                        <Text span translate="no" fw={600}>
                          {b.target_name}
                        </Text>{' '}
                        <Code translate="no">{b.cert_path}</Code>
                      </span>
                    }
                  />
                </Box>
              ))}
            </Stack>
          </Checkbox.Group>
          <Text size="sm" role="status">
            {t('bindings.selectedCount', { count: picked.length })}
          </Text>
          {tooMany && (
            <Alert color="red" role="alert">
              {t('deploy.limit', { max: MAX_DEPLOY })}
            </Alert>
          )}
          {incomplete && !admin && (
            <Alert color="yellow" role="status">
              {t('deploy.chainAdminOnly')}
            </Alert>
          )}
          {incomplete && admin && <Checkbox label={t('deploy.confirmChain')} checked={confirmChain} onChange={(e) => setConfirmChain(e.currentTarget.checked)} />}
          <CanaryChoice serviceId={serviceIdOf(c.service)} destinations={picked.length} override={override} onOverride={setOverride} disabled={busy} />
          <ErrorAlert error={error} />
          <DialogActions>
            <Button variant="default" disabled={busy} onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button loading={busy} disabled={!ready} leftSection={<Icon name="Rocket" size={15} />} onClick={() => void submit()}>
              {t('acme.issued.deployNow')}
            </Button>
          </DialogActions>
        </Stack>
      )}
    </AppModal>
  );
}
