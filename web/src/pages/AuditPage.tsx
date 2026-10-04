import { useId, useState, type FormEvent } from 'react';
import { Alert, Badge, Button, Code, Group, NativeSelect, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useInfiniteQuery, useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { auditExportUrl, listAudit, verifyAudit } from '../api/endpoints';
import type { AuditEntry, AuditResult } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { formatDateTime } from '../datetime';

const PAGE_SIZE = 50;
const RESULT_COLORS: Record<AuditResult, string> = { success: 'green', failure: 'orange', denied: 'red' };

interface Filters {
  action: string;
  result: '' | AuditResult;
}

// actionKey maps a stored action ("auth.login") to its label key ("audit.actions.auth_login").
export function actionKey(action: string): string {
  return `audit.actions.${action.replace(/\./g, '_')}`;
}

// Details whose value is an instant; they are shown in the reader's language and time zone.
const TIME_DETAILS = new Set(['at', 'window_start', 'window_end', 'valid_from', 'valid_until', 'ends_at', 'locks_at', 'system_time', 'last_seen']);
// A detail key or value is looked up in the catalog only when it is a plain identifier: anything else
// (a dot or a colon would be read as a path or a namespace) is shown as data.
const PLAIN = /^[a-z][a-z0-9_]*$/;

// catalogLookup finds a string at a dotted path through own properties only (i18next's own lookup
// also finds inherited ones: a detail named "constructor" would "exist").
function catalogLookup(bundle: unknown, key: string): string | undefined {
  let node = bundle;
  for (const part of key.split('.')) {
    if (!node || typeof node !== 'object' || !Object.prototype.hasOwnProperty.call(node, part)) return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return typeof node === 'string' ? node : undefined;
}

// useCatalogText returns the text of a key built from server data, or null when neither the active
// language nor English (the fallback) has a text there.
function useCatalogText(): (key: string) => string | null {
  const { t, i18n } = useTranslation();
  return (key: string) =>
    catalogLookup(i18n.getResourceBundle(i18n.language, 'web'), key) !== undefined || catalogLookup(i18n.getResourceBundle('en', 'web'), key) !== undefined
      ? t(key)
      : null;
}

// AuditDetails shows the details of one entry behind a disclosure (AUD-25 d): each key with its
// label, or the key itself as data when this version has no label for it; each value as data, a
// known value (a reason, a problem) in words and an instant in the reader's time zone. Values are
// text, never markup.
function AuditDetails({ details }: { details: Record<string, string> }) {
  const { t, i18n } = useTranslation();
  const text = useCatalogText();
  const [open, setOpen] = useState(false);
  const id = useId();
  const pairs = Object.entries(details).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (pairs.length === 0) return null;
  // A summary row of coalesced refusals (AUD-06) says how many more there were, and when.
  const summary =
    details.suppressed_count && details.window_start && details.window_end
      ? t('audit.summary', {
          n: details.suppressed_count,
          from: formatDateTime(details.window_start, i18n.language),
          to: formatDateTime(details.window_end, i18n.language),
        })
      : null;
  const keyLabel = (k: string) => (PLAIN.test(k) ? text(`audit.detailKeys.${k}`) : null);
  const valueText = (k: string, v: string) => {
    if (TIME_DETAILS.has(k)) return formatDateTime(v, i18n.language);
    return PLAIN.test(k) && PLAIN.test(v) ? text(`audit.detailValues.${k}.${v}`) : null;
  };
  return (
    <Stack gap={4}>
      {summary && <Text size="xs">{summary}</Text>}
      <Button variant="subtle" size="compact-xs" w="fit-content" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        {t('audit.detailsToggle', { n: pairs.length })}
      </Button>
      {open && (
        <div id={id} role="group" aria-label={t('audit.columns.details')}>
          <dl style={{ margin: 0 }}>
            {pairs.map(([k, v]) => {
              const label = keyLabel(k);
              const value = valueText(k, v);
              return (
                <div key={k} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <Text component="dt" size="xs" fw={600}>
                    {label ?? (
                      <Code translate="no">{k}</Code>
                    )}
                  </Text>
                  <Text component="dd" size="xs" m={0} style={{ overflowWrap: 'anywhere' }}>
                    {value ?? (
                      <Code translate="no">{v}</Code>
                    )}
                  </Text>
                </div>
              );
            })}
          </dl>
        </div>
      )}
    </Stack>
  );
}

export function AuditPage() {
  const { t, i18n } = useTranslation();
  const [draft, setDraft] = useState<Filters>({ action: '', result: '' });
  const [filters, setFilters] = useState<Filters>({ action: '', result: '' });

  const entries = useInfiniteQuery({
    queryKey: ['audit', filters],
    queryFn: ({ pageParam }) =>
      listAudit({ limit: PAGE_SIZE, cursor: pageParam, action: filters.action || undefined, result: filters.result || undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const verify = useMutation({ mutationFn: verifyAudit });

  const text = useCatalogText();
  // An action from a newer server is shown as the data it is.
  const label = (e: AuditEntry) => {
    if (!/^[a-z][a-z0-9_.]*$/.test(e.action)) return <Code translate="no">{e.action}</Code>;
    // An export or a verification refused because another one was running is written with the
    // action of the real one (result denied, reason busy): it gets its own label (AUD-06).
    const busy = e.result === 'denied' && e.details?.reason === 'busy' ? text(`${actionKey(e.action)}_busy`) : null;
    return busy ?? text(actionKey(e.action)) ?? <Code translate="no">{e.action}</Code>;
  };
  const actor = (e: AuditEntry) => (e.actor_type === 'system' ? t('audit.systemActor', { name: e.actor_name }) : e.actor_name);
  const apply = (ev: FormEvent) => {
    ev.preventDefault();
    setFilters({ action: draft.action.trim(), result: draft.result });
  };
  const items = entries.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('audit.title')}</Title>
        <Group gap="xs">
          <Button onClick={() => verify.mutate()} loading={verify.isPending}>
            {t('audit.verify')}
          </Button>
          <Button component="a" href={auditExportUrl('csv')} download variant="default">
            {t('audit.exportCsv')}
          </Button>
          <Button component="a" href={auditExportUrl('json')} download variant="default">
            {t('audit.exportJson')}
          </Button>
        </Group>
      </Group>

      {/* The exports are plain downloads (a stream may be large); when another check or export is
          running the server refuses with ALC-AUD-0001 and the browser reports a failed download. */}
      <Text size="sm" c="gray.7">
        {t('audit.exportHint')}
      </Text>
      {verify.isError && <ErrorAlert error={verify.error} />}
      {verify.isSuccess && (
        <Alert
          color={verify.data.intact ? 'green' : 'red'}
          role="status"
          title={verify.data.intact ? t('audit.intact') : t('audit.broken', { seq: verify.data.first_bad_seq ?? 0 })}
        >
          <Stack gap={4}>
            <Text size="sm">
              {t('audit.checked', { count: verify.data.checked, formatted: new Intl.NumberFormat(i18n.language).format(verify.data.checked) })}
            </Text>
            {verify.data.intact && (
              <Text size="sm">
                {t('audit.headHash')} <Code>{verify.data.head_hash}</Code>
              </Text>
            )}
            {!verify.data.intact && <Text size="sm">{t('audit.brokenHelp')}</Text>}
          </Stack>
        </Alert>
      )}

      <form onSubmit={apply}>
        <Group align="flex-end" gap="sm">
          <TextInput
            label={t('audit.filters.action')}
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.currentTarget.value })}
          />
          <NativeSelect
            label={t('audit.filters.result')}
            value={draft.result}
            onChange={(e) => setDraft({ ...draft, result: e.currentTarget.value as Filters['result'] })}
            data={[
              { value: '', label: t('audit.filters.anyResult') },
              { value: 'success', label: t('audit.result.success') },
              { value: 'failure', label: t('audit.result.failure') },
              { value: 'denied', label: t('audit.result.denied') },
            ]}
          />
          <Button type="submit" variant="light">
            {t('audit.filters.apply')}
          </Button>
        </Group>
      </form>

      {entries.isError && <ErrorAlert error={entries.error} />}
      {entries.isSuccess && items.length === 0 && <Text c="gray.7">{t('audit.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('audit.columns.time')}</Table.Th>
              <Table.Th>{t('audit.columns.user')}</Table.Th>
              <Table.Th>{t('audit.columns.action')}</Table.Th>
              <Table.Th>{t('audit.columns.object')}</Table.Th>
              <Table.Th>{t('audit.columns.result')}</Table.Th>
              <Table.Th>{t('audit.columns.ip')}</Table.Th>
              <Table.Th>{t('audit.columns.details')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((e) => (
              <Table.Tr key={e.seq}>
                <Table.Td>{formatDateTime(e.at, i18n.language)}</Table.Td>
                <Table.Td>{actor(e)}</Table.Td>
                <Table.Td>{label(e)}</Table.Td>
                <Table.Td>
                  {(e.object_type || e.object_id) && (
                    <Group gap={4} wrap="wrap">
                      {e.object_type && <Code translate="no">{e.object_type}</Code>}
                      {e.object_id && (
                        <Code translate="no" style={{ overflowWrap: 'anywhere' }}>
                          {e.object_id}
                        </Code>
                      )}
                    </Group>
                  )}
                </Table.Td>
                <Table.Td>
                  <Badge color={RESULT_COLORS[e.result]} variant="light">
                    {t(`audit.result.${e.result}`)}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {e.ip ?? ''}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <AuditDetails details={e.details ?? {}} />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        </Table.ScrollContainer>
      )}
      {entries.hasNextPage && (
        <Button variant="default" onClick={() => void entries.fetchNextPage()} loading={entries.isFetchingNextPage}>
          {t('audit.loadMore')}
        </Button>
      )}
    </Stack>
  );
}
