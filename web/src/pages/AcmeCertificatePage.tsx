import { Anchor, Button, Code, Group, Loader, Stack, Switch, Table, Text } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import {
  certificateStateKey,
  challengeKey,
  deleteACMECertificate,
  getACMECertificate,
  keyTypeKey,
  listACMEOrders,
  orderACMECertificate,
  orderStateKey,
  rearmACMECertificate,
  testACMECertificate,
  updateACMECertificate,
  type ACMECertificate,
  type ACMEOrder,
} from '../api/acme';
import { getCertificate } from '../api/endpoints';
import { ACME_CERTIFICATES_KEY, acmeCertificateKey, acmeOrdersKey, CERTIFICATES_KEY, certificateKey, DEPLOYMENTS_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { AcmeBindingsPanel } from '../components/acme/AcmeBindingsPanel';
import { hookName, ORDER_POLL_MS, Problem, providerName, renewal, stateIcon, stateTone, useChangesLocked, useHooks, useWebServers, useProviders } from '../components/acme/issued';
import { AppModal } from '../components/AppModal';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry } from '../components/Expiry';
import { useStepUp } from '../components/StepUpProvider';
import { DialogActions, EmptyState, FactList, Notice, PageHeader, Panel, StatusBadge, type Fact } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDate, formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './KeyVaults.module.css';

const ORDERS_SHOWN = 20;

// AcmeCertificatePage is the status page of one issued certificate (ACME): what is ordered, the current certificate,
// when it renews and why it failed, the last orders, the Test run, and the websites that use it. Operators order, test,
// deploy and connect websites; only an Administrator changes the definition (renewal, automatic deployment, Renew now,
// release, delete), with a fresh step-up. The server decides every action; the buttons only follow its rules.
export function AcmeCertificatePage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const { run } = useStepUp();
  const role = session?.user.role;
  const admin = role === 'admin';
  const canOperate = admin || role === 'operator';
  const locked = useChangesLocked();
  const providers = useProviders();
  const hooks = useHooks();

  const cert = useQuery({
    queryKey: acmeCertificateKey(id),
    queryFn: () => getACMECertificate(id),
    refetchInterval: (q) => (q.state.data?.running_order_id || q.state.data?.state === 'issuing' ? ORDER_POLL_MS : false),
  });
  const orders = useQuery({
    queryKey: acmeOrdersKey(id),
    queryFn: () => listACMEOrders(id, ORDERS_SHOWN),
    refetchInterval: (q) => (q.state.data?.items.some((o) => o.state === 'running') ? ORDER_POLL_MS : false),
  });
  const c = cert.data;
  const servers = useWebServers(c?.challenge === 'http01');
  const running = !!c?.running_order_id || (orders.data?.items.some((o) => o.state === 'running') ?? false);

  // When an order starts or ends, the other reads follow: the orders list, the certificate (its new current
  // certificate and state), the websites and, when an order ended, the certificate inventory, the deployments (an
  // automatic deployment may follow a new certificate) and the website lists.
  const lastRunning = useRef<string | null | undefined>(undefined);
  const runningId = c?.running_order_id;
  useEffect(() => {
    if (runningId === undefined) return;
    const before = lastRunning.current;
    lastRunning.current = runningId;
    if (before === undefined || before === runningId) return;
    void client.invalidateQueries({ queryKey: acmeCertificateKey(id) });
    void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY, predicate: (q) => q.queryKey[2] === 'list' });
    if (before === null) return;
    void client.invalidateQueries({ queryKey: CERTIFICATES_KEY });
    void client.invalidateQueries({ queryKey: DEPLOYMENTS_KEY });
    void client.invalidateQueries({ queryKey: ['locations'] });
  }, [runningId, client, id]);

  const [busy, setBusy] = useState<'test' | 'order' | 'rearm' | 'autoRenew' | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  // A Test run started by the wizard's "Run a test first" arrives in the navigation state: its result is shown here too.
  const location = useLocation();
  const started = (location.state as { testOrderId?: unknown } | null)?.testOrderId;
  const [testId, setTestId] = useState<string | null>(typeof started === 'string' ? started : null);
  // Read once: the state leaves the history entry at once, so a reload or a way back never shows that result again.
  const hadState = location.state !== null && location.state !== undefined;
  const { pathname } = location;
  useEffect(() => {
    if (hadState) void navigate(pathname, { replace: true, state: null });
  }, [hadState, pathname, navigate]);
  // A deleted certificate's reads are forgotten once this page has gone (while it is mounted, its own queries would
  // read the deleted certificate again).
  const deleted = useRef(false);
  useEffect(
    () => () => {
      if (deleted.current) client.removeQueries({ queryKey: acmeCertificateKey(id) });
    },
    [client, id],
  );
  const [deleting, setDeleting] = useState(false);
  // After Check again and resume: 'ordered' when an order started at once, 'armed' when only renewal was re-armed.
  const [rearmed, setRearmed] = useState<'ordered' | 'armed' | null>(null);

  const refresh = () => {
    void client.invalidateQueries({ queryKey: acmeCertificateKey(id) });
    void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY, predicate: (q) => q.queryKey[2] === 'list' });
  };
  const act = async (kind: 'test' | 'order' | 'rearm' | 'autoRenew', fn: () => Promise<unknown>) => {
    setBusy(kind);
    setActionError(null);
    try {
      const res = await fn();
      if (kind === 'test') setTestId((res as ACMEOrder).id);
      if (kind === 'rearm') setRearmed((res as ACMECertificate | undefined)?.running_order_id ? 'ordered' : 'armed');
    } catch (e) {
      setActionError(e);
    }
    setBusy(null);
    refresh();
  };

  const back = { to: '/acme', label: t('acme.issued.title') };
  if (cert.isPending) return <PageLoader />;
  if (cert.isError || !c)
    return (
      <Stack gap="md">
        <ErrorAlert error={cert.error} />
        <Anchor component={Link} to="/acme" w="fit-content" size="sm">
          {t('acme.issued.title')}
        </Anchor>
      </Stack>
    );

  const issued = c.current !== null;
  const lockReason = locked ? t('acme.issued.lockedShort') : '';
  const proofTarget = c.challenge === 'dns01' ? hookName(hooks.data?.items, c.hook_id) : (servers.data?.items.find((s) => s.id === c.http_target_id)?.name ?? '');
  const summary: Fact[] = [
    {
      key: 'names',
      label: t('acme.issued.facts.names'),
      value: (
        <ul className={classes.chips} style={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t('acme.issued.facts.names')}>
          {c.names.map((n) => (
            <li key={n}>
              <Code translate="no" style={WRAP}>
                {n}
              </Code>
            </li>
          ))}
        </ul>
      ),
    },
    { key: 'authority', label: t('acme.issued.facts.authority'), value: <span translate="no">{providerName(providers.data?.items, c.provider_id)}</span> },
    { key: 'key', label: t('acme.issued.facts.keyType'), value: t(keyTypeKey(c.key_type)) },
    { key: 'proof', label: t('acme.issued.facts.proof'), value: t(challengeKey(c.challenge)) },
    {
      key: 'proofTarget',
      label: t(c.challenge === 'dns01' ? 'acme.issued.facts.hook' : 'acme.issued.facts.server'),
      value: c.challenge === 'http01' && c.http_target_id && proofTarget ? (
        <Anchor component={Link} to={`/servers/${c.http_target_id}`} translate="no">
          {proofTarget}
        </Anchor>
      ) : (
        <span translate="no">{proofTarget || t('acme.issued.facts.unknown')}</span>
      ),
    },
    { key: 'window', label: t('acme.issued.facts.window'), value: t('acme.issued.renewal.beforeExpiry', { count: c.renew_before_days }) },
    { key: 'created', label: t('acme.issued.facts.created'), value: formatDateTime(c.created_at, i18n.language) },
  ];

  const orderLabel = issued ? t('acme.issued.orderNow') : t('acme.issued.getNow');
  return (
    <Stack gap={0}>
      <PageHeader
        back={back}
        title={<span translate="no">{c.names[0] ?? ''}</span>}
        description={t('acme.issued.detailDescription')}
        status={
          <StatusBadge tone={stateTone(c.state)} icon={stateIcon(c.state)} data-state={c.state} testId="acme-state">
            {t(certificateStateKey(c.state))}
          </StatusBadge>
        }
        actions={
          <>
            {canOperate && (
              <Button variant="default" leftSection={<Icon name="CirclePlay" size={15} />} loading={busy === 'test'} disabled={locked || running || busy !== null} onClick={() => void act('test', () => testACMECertificate(id))}>
                {t('acme.issued.testRun')}
              </Button>
            )}
            {canOperate && (
              <Button leftSection={<Icon name="RefreshCw" size={15} />} loading={busy === 'order'} disabled={locked || running || busy !== null} onClick={() => void act('order', () => orderACMECertificate(id))}>
                {orderLabel}
              </Button>
            )}
            {admin && (
              <Button variant="light" color="red" leftSection={<Icon name="X" size={15} />} onClick={() => setDeleting(true)}>
                {t('acme.issued.delete')}
              </Button>
            )}
          </>
        }
      />
      <Stack gap="md">
        {locked && canOperate && (
          <Notice tone="warning" title={t('acme.issued.lockedTitle')}>
            {t('acme.issued.lockedText')}
          </Notice>
        )}
        {role === 'auditor' && <Notice tone="neutral" title={t('acme.issued.readOnly')} />}
        {canOperate && <Text size="sm">{t('acme.issued.testRunHelp')}</Text>}
        {running && (
          <Group gap="sm" role="status" aria-live="polite" data-testid="order-running">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('acme.issued.orderRunning')}</Text>
          </Group>
        )}
        <TestResult orderId={testId} orders={orders.data?.items} running={running} />
        <ErrorAlert error={actionError} />
        {rearmed && <Notice tone="success" role="status" title={t(rearmed === 'ordered' ? 'acme.issued.rearmedOrdered' : 'acme.issued.rearmed', { order: orderLabel })} />}
      </Stack>

      <div className={classes.grid}>
        <div className={classes.column}>
          <RenewalPanel c={c} admin={admin} canOperate={canOperate} locked={locked} busy={busy} lockReason={lockReason} orderLabel={orderLabel}
            onRearm={() => void act('rearm', () => run(() => rearmACMECertificate(id)))}
            onAutoRenew={(on) => void act('autoRenew', () => run(() => updateACMECertificate(id, { auto_renew: on })))}
          />
          <OrdersPanel orders={orders.data?.items} error={orders.error} pending={orders.isPending} />
          <AcmeBindingsPanel certificate={c} admin={admin} canOperate={canOperate} locked={locked} />
        </div>
        <div className={classes.side}>
          <Panel title={t('acme.issued.summary')}>
            <FactList facts={summary} label={t('acme.issued.summary')} />
          </Panel>
          <CurrentPanel c={c} />
        </div>
      </div>
      {deleting && (
        <DeleteDialog
          c={c}
          onClose={() => setDeleting(false)}
          onDeleted={() => {
            // Leave and refresh the lists; this certificate's reads are forgotten when the page unmounts.
            deleted.current = true;
            void navigate('/acme');
            void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY, predicate: (q) => q.queryKey[2] === 'list' });
          }}
        />
      )}
    </Stack>
  );
}

// TestResult follows the Test run started from this page: still running, the names verified, or why not.
function TestResult({ orderId, orders, running }: { orderId: string | null; orders: ACMEOrder[] | undefined; running: boolean }) {
  const { t } = useTranslation();
  if (!orderId) return null;
  const o = orders?.find((x) => x.id === orderId);
  // Not listed (yet): in progress while the orders are read or an order runs; otherwise nothing is known to show.
  if (!o && orders !== undefined && !running) return null;
  if (!o || o.state === 'running')
    return (
      <Notice tone="info" role="status" title={t('acme.issued.test.running')} testId="test-result">
        {t('acme.issued.testRunHelp')}
      </Notice>
    );
  if (o.state === 'succeeded')
    return (
      <Notice tone="success" role="status" title={t('acme.issued.test.ok')} testId="test-result">
        {t('acme.issued.test.okText')}
      </Notice>
    );
  return (
    <Notice tone="danger" role="alert" title={t('acme.issued.test.failed')} testId="test-result">
      {o.error ? <Problem error={o.error} /> : t('acme.issued.test.failedNoReason')}
    </Notice>
  );
}

function RenewalPanel({
  c,
  admin,
  canOperate,
  locked,
  busy,
  lockReason,
  orderLabel,
  onRearm,
  onAutoRenew,
}: {
  c: ACMECertificate;
  admin: boolean;
  canOperate: boolean;
  locked: boolean;
  busy: string | null;
  lockReason: string;
  orderLabel: string;
  onRearm: () => void;
  onAutoRenew: (on: boolean) => void;
}) {
  const { t, i18n } = useTranslation();
  const r = renewal(c);
  const lang = i18n.language;
  // How the newest renewal e-mail was delivered, in one line.
  const noticeText = (n: NonNullable<ACMECertificate['last_notice']>) => {
    const at = formatDateTime(n.sent_at ?? n.queued_at, lang);
    if (n.skipped > 0 && n.sent === 0) return t('acme.issued.renewal.notice.noServer', { time: at });
    if (n.failed > 0) return t('acme.issued.renewal.notice.failed', { failed: n.failed, count: n.recipients, code: n.last_failure_code || '-', time: at });
    if (n.pending > 0) return t('acme.issued.renewal.notice.pending', { pending: n.pending, count: n.recipients, code: n.last_failure_code || '-', time: at });
    return t('acme.issued.renewal.notice.sent', { sent: n.sent, count: n.recipients, time: at });
  };
  const resume = admin ? (
    <Button size="xs" loading={busy === 'rearm'} disabled={locked || busy !== null} onClick={onRearm}>
      {t('acme.issued.renewNow')}
    </Button>
  ) : undefined;
  let renews: ReactNode;
  switch (r.kind) {
    case 'attempt':
      renews = t('acme.issued.renewal.attemptAt', { time: formatDateTime(r.at, lang) });
      break;
    case 'planned':
      renews = r.ari ? t('acme.issued.renewal.plannedAri', { date: formatDate(r.at, lang) }) : t('acme.issued.renewal.planned', { date: formatDate(r.at, lang), count: c.renew_before_days });
      break;
    case 'none':
      renews = t('acme.issued.renewal.afterFirst');
      break;
    case 'stopped':
      renews = t('acme.issued.renewal.stoppedShort');
      break;
    default:
      renews = t('acme.issued.renewal.off');
  }
  const facts: Fact[] = [
    { key: 'renews', label: t('acme.issued.renewal.renews'), value: renews, testId: 'renews' },
    {
      key: 'auto',
      label: t('acme.issued.renewal.auto'),
      value: admin ? (
        <Switch
          checked={c.auto_renew}
          disabled={locked || busy !== null}
          label={t(c.auto_renew ? 'acme.issued.on' : 'acme.issued.off')}
          aria-label={t('acme.issued.renewal.auto')}
          onChange={(e) => onAutoRenew(e.currentTarget.checked)}
        />
      ) : (
        t(c.auto_renew ? 'acme.issued.on' : 'acme.issued.off')
      ),
    },
    { key: 'failures', label: t('acme.issued.renewal.failures'), value: String(c.failures), testId: 'failures' },
    ...(c.failures > 0 && c.last_failure_class
      ? [{ key: 'class', label: t('acme.issued.renewal.failureClass'), value: t(`acme.issued.renewal.class.${c.last_failure_class}`), testId: 'failure-class' }]
      : []),
    ...(c.last_attempt_at ? [{ key: 'last', label: t('acme.issued.renewal.lastAttempt'), value: formatDateTime(c.last_attempt_at, lang) }] : []),
    ...(c.next_attempt_at && (c.state !== 'stopped' || c.recovering) ? [{ key: 'next', label: t('acme.issued.renewal.nextAttempt'), value: formatDateTime(c.next_attempt_at, lang), testId: 'next-attempt' }] : []),
    ...(c.last_notice ? [{ key: 'notice', label: t('acme.issued.renewal.lastNotice'), value: noticeText(c.last_notice), testId: 'last-notice' }] : []),
    ...(c.ari_window
      ? [{ key: 'ari', label: t('acme.issued.renewal.ari'), value: t('acme.issued.renewal.ariWindow', { start: formatDateTime(c.ari_window.start, lang), end: formatDateTime(c.ari_window.end, lang) }) }]
      : []),
  ];
  return (
    <Panel title={t('acme.issued.renewal.title')} testId="renewal-panel">
      <Stack gap="sm">
        <FactList facts={facts} label={t('acme.issued.renewal.title')} />
        <Text size="sm">{t(c.auto_renew ? 'acme.issued.renewal.autoHelpOn' : 'acme.issued.renewal.autoHelpOff')}</Text>
        {!admin && <Text size="xs" c="dimmed">{t('acme.issued.adminOnly')}</Text>}
        {c.state === 'failing' && (
          <Notice tone="warning" title={t('acme.issued.renewal.failingTitle')} testId="failing" action={resume}>
            <Text size="sm">
              {c.next_attempt_at ? t('acme.issued.renewal.failingNext', { count: c.failures, time: formatDateTime(c.next_attempt_at, lang) }) : t('acme.issued.renewal.failingText', { count: c.failures })}
            </Text>
            {c.last_failure_class === 'transient' && <Text size="sm">{t('acme.issued.renewal.transientText')}</Text>}
            {c.last_failure_class === 'permanent' && <Text size="sm">{t('acme.issued.renewal.permanentText', { count: Math.max(1, 5 - c.permanent_failures) })}</Text>}
            {admin && lockReason && <Text size="xs">{lockReason}</Text>}
          </Notice>
        )}
        {c.state === 'stopped' && (
          <Notice tone={c.recovering ? 'warning' : 'danger'} title={t('acme.issued.renewal.stoppedTitle')} testId="stopped" action={resume}>
            <Text size="sm">{t(c.recovering ? 'acme.issued.renewal.recoveringText' : 'acme.issued.renewal.stoppedText', { count: c.failures })}</Text>
            <Text size="sm">{t(admin ? 'acme.issued.renewal.stoppedAdmin' : canOperate ? 'acme.issued.renewal.stoppedOperator' : 'acme.issued.renewal.stoppedAuditor', { order: orderLabel })}</Text>
            {admin && lockReason && <Text size="xs">{lockReason}</Text>}
          </Notice>
        )}
        {c.last_error && (
          <div data-testid="last-error">
            <Text size="xs" fw={600} c="dimmed">
              {t('acme.issued.renewal.lastError')}
            </Text>
            <Problem error={c.last_error} />
          </div>
        )}
      </Stack>
    </Panel>
  );
}

function OrdersPanel({ orders, error, pending }: { orders: ACMEOrder[] | undefined; error: unknown; pending: boolean }) {
  const { t, i18n } = useTranslation();
  const tone = (s: string) => (s === 'succeeded' ? 'success' : s === 'failed' ? 'danger' : 'info');
  const icon = (s: string) => (s === 'succeeded' ? 'CircleCheck' : s === 'failed' ? 'CircleX' : 'RefreshCw');
  return (
    <Panel title={t('acme.issued.orders.title')} description={t('acme.issued.orders.description')} padded={false} testId="orders-panel">
      <ErrorAlert error={error} />
      {pending && (
        <Group p="md">
          <Loader size="sm" aria-label={t('ui.loading')} />
        </Group>
      )}
      {orders && orders.length === 0 && <EmptyState icon="CircleDot" title={t('acme.issued.orders.none')} />}
      {orders && orders.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table aria-label={t('acme.issued.orders.title')} highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                {(['started', 'kind', 'result', 'error', 'trigger'] as const).map((k) => (
                  <Table.Th key={k}>{t(`acme.issued.orders.columns.${k}`)}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {orders.map((o) => (
                <Table.Tr key={o.id} data-testid="acme-order" data-state={o.state}>
                  <Table.Td>
                    <span className={classes.mono}>{formatDateTime(o.started_at, i18n.language)}</span>
                  </Table.Td>
                  <Table.Td>{t(o.kind === 'test' ? 'acme.issued.orders.test' : 'acme.issued.orders.issue')}</Table.Td>
                  <Table.Td>
                    <StatusBadge tone={tone(o.state)} icon={icon(o.state)} size="sm">
                      {t(orderStateKey(o.state))}
                    </StatusBadge>
                  </Table.Td>
                  <Table.Td>{o.error ? <Problem error={o.error} /> : o.cleanup_error ? <Problem error={o.cleanup_error} /> : ''}</Table.Td>
                  <Table.Td>{t(o.trigger === 'renewal' ? 'acme.issued.orders.renewal' : 'acme.issued.orders.manual')}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Panel>
  );
}

// CurrentPanel is the certificate Alice holds now: its fingerprint, issuer, validity and the way to its own page.
function CurrentPanel({ c }: { c: ACMECertificate }) {
  const { t, i18n } = useTranslation();
  const cur = c.current;
  const detail = useQuery({ queryKey: certificateKey(cur?.id ?? ''), queryFn: () => getCertificate(cur?.id ?? ''), enabled: cur !== null });
  if (!cur)
    return (
      <Panel title={t('acme.issued.current.title')} testId="current-panel">
        <EmptyState icon="FileKey2" title={t('acme.issued.current.none')} description={t('acme.issued.current.noneText')} />
      </Panel>
    );
  const facts: Fact[] = [
    {
      key: 'fp',
      label: t('acme.issued.current.fingerprint'),
      value: (
        <Code translate="no" title={cur.fingerprint_sha256}>
          {cur.fingerprint_sha256.slice(0, 16)}…
        </Code>
      ),
    },
    ...(detail.data?.issuer ? [{ key: 'issuer', label: t('acme.issued.current.issuer'), value: <span translate="no" style={WRAP}>{detail.data.issuer}</span> }] : []),
    { key: 'from', label: t('acme.issued.current.validFrom'), value: formatDate(cur.not_before, i18n.language) },
    { key: 'until', label: t('acme.issued.current.validUntil'), value: <Expiry notAfter={cur.not_after} /> },
    { key: 'chain', label: t('acme.issued.current.chain'), value: t(cur.chain_complete ? 'acme.issued.current.chainComplete' : 'acme.issued.current.chainIncomplete') },
  ];
  return (
    <Panel title={t('acme.issued.current.title')} testId="current-panel">
      <Stack gap="sm">
        <FactList facts={facts} label={t('acme.issued.current.title')} />
        <Anchor component={Link} to={`/certificates/${cur.id}`} size="sm">
          {t('acme.issued.current.open')}
        </Anchor>
      </Stack>
    </Panel>
  );
}

function DeleteDialog({ c, onClose, onDeleted }: { c: ACMECertificate; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(() => deleteACMECertificate(c.id));
      onDeleted();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.deleteTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('acme.issued.deleteText')}</Text>
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={busy} onClick={() => void go()}>
            {t('acme.issued.deleteConfirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
