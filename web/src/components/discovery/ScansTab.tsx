import { Button, Stack, Table, Text } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MAX_ACTIVE_SCANS, cancelDiscoveryScan, isActiveScan, listDiscoveryScans, scanTriggerKey, type DiscoveryScan, type DiscoveryScope, type Page } from '../../api/discovery';
import { DISCOVERY_SCANS_KEY, DISCOVERY_SCOPES_KEY, discoveryScanListKey } from '../../api/queryKeys';
import { useAbort } from '../../api/useAbort';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { CursorFooter, EmptyState, Panel } from '../ui';
import ui from '../ui/ui.module.css';
import classes from './discovery.module.css';
import { durationText, SCAN_POLL_MS, ScanProblem, ScanStateBadge, startBlock, useDiscoveryRole, type StartBlock } from './shared';
import { blockKey, STARTED_MESSAGE_MS, StartScanDialog, type StartContext } from './StartScan';

// ScansTab is every scan, newest first: its scope, how it started, its state and counts, how long it ran and why it
// ended early. The first page reads itself again only while a scan on it is queued or running.
export function ScansTab({ scopes, ctx }: { scopes: DiscoveryScope[] | undefined; ctx: StartContext }) {
  const { t, i18n } = useTranslation();
  const { canOperate, admin } = useDiscoveryRole();
  const client = useQueryClient();
  // The first page is the one that changes (newest first; at most two scans run, and they are the newest): only it is
  // read again, every few seconds while a scan on it is queued or running. Older pages are read once, on Load more.
  const list = useQuery({
    queryKey: discoveryScanListKey({}),
    queryFn: ({ signal }) => listDiscoveryScans({}, signal),
    refetchInterval: (q) => (q.state.data?.items.some((s) => isActiveScan(s.state)) ? SCAN_POLL_MS : false),
  });
  const [older, setOlder] = useState<Page<DiscoveryScan>[]>([]);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<unknown>(null);
  const abort = useAbort();
  const next = older.length > 0 ? older[older.length - 1].next_cursor : (list.data?.next_cursor ?? null);
  const loadMore = async () => {
    if (!next) return;
    const signal = abort.signal();
    setLoadingMore(true);
    setMoreError(null);
    try {
      const page = await listDiscoveryScans({ cursor: next }, signal);
      if (!signal.aborted) setOlder((o) => [...o, page]);
    } catch (e) {
      if (!signal.aborted) setMoreError(e);
    }
    if (!signal.aborted) setLoadingMore(false);
  };
  // A scan on both the first page and an older one (the first page moved on) is shown once, as the first page has it.
  const firstIds = new Set((list.data?.items ?? []).map((s) => s.id));
  const items = [...(list.data?.items ?? []), ...older.flatMap((p) => p.items).filter((s) => !firstIds.has(s.id))];
  const polling = (list.data?.items ?? []).some((s) => isActiveScan(s.state));
  const [starting, setStarting] = useState(false);
  // "The scan has started" stays a few seconds, and goes when that scan is over.
  const [message, setMessage] = useState<{ text: string; scanId: string } | null>(null);
  useEffect(() => {
    if (!message) return;
    const timer = window.setTimeout(() => setMessage(null), STARTED_MESSAGE_MS);
    return () => window.clearTimeout(timer);
  }, [message]);
  const startedOver = message !== null && items.some((s) => s.id === message.scanId && !isActiveScan(s.state));
  const cancel = useMutation({
    mutationFn: (id: string) => cancelDiscoveryScan(id),
    onSettled: () => {
      void client.invalidateQueries({ queryKey: DISCOVERY_SCANS_KEY });
      void client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY });
    },
  });
  const all = scopes ?? [];
  const anyFree = all.some((s) => startBlock(s, ctx) === '');
  // The one reason every scope shares (the license, no allowed network, two scans running), said beside the button.
  const shared: StartBlock = all.length === 0 ? '' : ctx.locked ? 'locked' : !ctx.scanningEnabled ? 'noNetworks' : ctx.activeCount >= MAX_ACTIVE_SCANS ? 'tooMany' : '';

  return (
    <Panel
      title={t('discovery.scans.title')}
      description={polling ? t('discovery.scans.polling') : t('discovery.scans.description')}
      action={
        canOperate && (
          <Stack gap={2} align="flex-end">
            <Button leftSection={<Icon name="CirclePlay" size={15} />} disabled={!anyFree} aria-describedby={!anyFree ? 'start-scan-reason' : undefined} onClick={() => setStarting(true)}>
              {t('discovery.scans.start')}
            </Button>
            {!anyFree && (
              <p className={classes.reason} id="start-scan-reason">
                {all.length === 0 ? (admin ? t('discovery.scans.noScopes') : t('discovery.scans.noScopesOther')) : shared ? t(blockKey(shared)) : t('discovery.block.noneReady')}
              </p>
            )}
          </Stack>
        )
      }
      testId="discovery-scans"
    >
      <Stack gap="sm">
        {message && !startedOver && (
          <Text size="sm" role="status">
            {message.text}
          </Text>
        )}
        <ErrorAlert error={cancel.error} />
        <ErrorAlert error={list.error} />
        <ErrorAlert error={moreError} />
        {list.isPending && <LoadingIndicator />}
        {list.isSuccess && items.length === 0 && <EmptyState icon="ScanLine" title={t('discovery.scans.empty')} description={t('discovery.scans.emptyText')} />}
        {items.length > 0 && (
          <div className={ui.tablePanel}>
            <Table.ScrollContainer minWidth={1040}>
              <Table aria-label={t('discovery.scans.title')} data-testid="discovery-scans-table">
                <Table.Thead>
                  <Table.Tr>
                    {(['scope', 'trigger', 'state', 'endpoints', 'started', 'finished', 'duration', 'problem', 'actions'] as const).map((k) => (
                      <Table.Th key={k}>{t(`discovery.scans.columns.${k}`)}</Table.Th>
                    ))}
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {items.map((s) => (
                    <ScanRow key={s.id} s={s} lang={i18n.language} canOperate={canOperate} cancelling={cancel.isPending && cancel.variables === s.id} onCancel={() => cancel.mutate(s.id)} />
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
            <div className={ui.tableBottom}>
              <CursorFooter shown={items.length} hasMore={next !== null} loading={loadingMore} onMore={() => void loadMore()} moreLabel={t('discovery.scans.more')} />
            </div>
          </div>
        )}
        {items.length > 0 && <p className={classes.help}>{t('discovery.scans.countsHelp')}</p>}
      </Stack>
      {starting && (
        <StartScanDialog
          scopes={all}
          ctx={ctx}
          onClose={() => setStarting(false)}
          onStarted={(scan) => {
            setStarting(false);
            setMessage({ text: t('discovery.scans.started', { name: scan.scope_name }), scanId: scan.id });
          }}
        />
      )}
    </Panel>
  );
}

function ScanRow({ s, lang, canOperate, cancelling, onCancel }: { s: DiscoveryScan; lang: string; canOperate: boolean; cancelling: boolean; onCancel: () => void }) {
  const { t } = useTranslation();
  const active = isActiveScan(s.state);
  return (
    <Table.Tr data-testid="discovery-scan-row" data-state={s.state}>
      <Table.Td>
        <span className={classes.name} translate="no">
          {s.scope_name}
        </span>
      </Table.Td>
      <Table.Td className={classes.small}>{t(scanTriggerKey(s.trigger))}</Table.Td>
      <Table.Td>
        <Stack gap={4} align="flex-start">
          <ScanStateBadge state={s.state} />
          {active && s.cancel_requested && <span className={classes.secondary}>{t('discovery.scans.stopping')}</span>}
        </Stack>
      </Table.Td>
      <Table.Td className={classes.small}>
        {t('discovery.scans.counts', { answered: s.endpoints_answered, failed: s.endpoints_failed, total: s.endpoints_total })}
        {s.certificates_new > 0 && <p className={classes.secondary}>{t('discovery.scans.newCertificates', { count: s.certificates_new })}</p>}
      </Table.Td>
      <Table.Td className={classes.small}>{s.started_at ? formatDateTime(s.started_at, lang) : t('discovery.scans.notStarted')}</Table.Td>
      <Table.Td className={classes.small}>{s.finished_at ? formatDateTime(s.finished_at, lang) : active ? t('discovery.scans.stillRunning') : '–'}</Table.Td>
      <Table.Td className={classes.small}>{durationText(t, s.started_at, s.finished_at)}</Table.Td>
      <Table.Td>{s.state === 'done' || active ? '–' : <ScanProblem scan={s} />}</Table.Td>
      <Table.Td>
        {canOperate && active && !s.cancel_requested ? (
          <Button size="xs" variant="default" color="red" loading={cancelling} aria-label={t('discovery.scans.cancelLabel', { name: s.scope_name })} onClick={onCancel}>
            {t('discovery.scans.cancel')}
          </Button>
        ) : (
          <span className={classes.small}>–</span>
        )}
      </Table.Td>
    </Table.Tr>
  );
}
