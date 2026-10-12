import { useId, useState, type FormEvent } from 'react';
import { Anchor, Button, Code, Group, NativeSelect, Stack, Table, Text, TextInput } from '@mantine/core';
import { useInfiniteQuery, useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { auditExportUrl, listAudit, verifyAudit } from '../api/endpoints';
import type { AuditEntry, AuditResult } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { CursorFooter, EmptyState, Notice, PageHeader, StatusBadge, type Tone } from '../components/ui';
import ui from '../components/ui/ui.module.css';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './AuditPage.module.css';

const PAGE_SIZE = 50;
// A refusal (denied) is the stronger signal than a failed attempt, as the product's colors had it (red vs orange).
const RESULT_TONES: Record<AuditResult, Tone> = { success: 'success', failure: 'warning', denied: 'danger' };

// initials are the avatar letters of a display name (two words at most), upper-cased in the reader's language.
function initials(name: string, lang: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => [...w][0])
    .join('')
    .toLocaleUpperCase(lang);
}

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
          // count picks the plural form; n is shown as written (a count may read "256+").
          count: /^\d+$/.test(details.suppressed_count) ? Number(details.suppressed_count) : 2,
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
      <Button
        variant="subtle"
        size="compact-xs"
        w="fit-content"
        aria-expanded={open}
        aria-controls={id}
        leftSection={<Icon name={open ? 'ChevronDown' : 'ChevronRight'} size={13} />}
        onClick={() => setOpen((o) => !o)}
      >
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
  const { session } = useAuth();
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
  const report = verify.data;

  return (
    <Stack gap="lg">
      <PageHeader
        title={t('audit.title')}
        description={t('audit.page.description')}
        actions={
          <>
            {/* The exports are plain downloads of the whole log (a stream may be large); when another check or
                export is running the server refuses with ALC-AUD-0001 and the browser reports a failed download. */}
            <Button component="a" href={auditExportUrl('csv')} download variant="default" leftSection={<Icon name="Download" size={15} />}>
              {t('audit.exportCsv')}
            </Button>
            <Button component="a" href={auditExportUrl('json')} download variant="default" leftSection={<Icon name="Download" size={15} />}>
              {t('audit.exportJson')}
            </Button>
            <Button variant="filled" onClick={() => verify.mutate()} loading={verify.isPending} leftSection={<Icon name="ShieldCheck" size={15} />}>
              {t('audit.verify')}
            </Button>
          </>
        }
      />
      <Text size="sm" c="dimmed">
        {t('audit.exportHint')}
      </Text>
      {/* GET /audit/export takes only the format: the filters below never narrow a download. */}
      <Text size="sm" c="dimmed">
        {t('audit.page.exportScope')}
      </Text>

      {verify.isError && <ErrorAlert error={verify.error} />}
      {report && (
        <Notice
          tone={report.intact ? 'brand' : 'danger'}
          // A broken chain is the result that must be heard: alert interrupts, status waits.
          role={report.intact ? 'status' : 'alert'}
          title={report.intact ? t('audit.intact') : t('audit.broken', { seq: report.first_bad_seq ?? 0 })}
          action={
            // Only Administrators can open Settings; the forwarding state itself needs a step-up there.
            session?.user.role === 'admin' && (
              <Anchor component={Link} to="/settings?tab=forwarding" size="sm" c="inherit" fw={600} underline="always">
                {t('audit.page.forwarding')}
              </Anchor>
            )
          }
        >
          <div className={classes.notice}>
            <Text size="sm">
              {t('audit.checked', { count: report.checked, formatted: new Intl.NumberFormat(i18n.language).format(report.checked) })}
            </Text>
            {/* The design's "verified through #N": the last entry the intact chain reached (head_seq). */}
            {report.intact && <Text size="sm">{t('audit.page.verifiedThrough', { seq: report.head_seq })}</Text>}
            {report.intact && (
              <Text size="sm" style={{ overflowWrap: 'anywhere' }}>
                {t('audit.headHash')} <Code translate="no">{report.head_hash}</Code>
              </Text>
            )}
            {!report.intact && <Text size="sm">{t('audit.brokenHelp')}</Text>}
            {/* What the check proves and what it does not (design: "Scope"). */}
            <Text size="sm">{t('audit.page.scope')}</Text>
          </div>
        </Notice>
      )}

      {entries.isError && <ErrorAlert error={entries.error} />}

      {/* The ResourceTable look, built here so the filter form stays mounted when a filter matches nothing. */}
      <div className={ui.tablePanel}>
        <div className={ui.toolbar}>
          <form onSubmit={apply} className={classes.filters}>
            <TextInput label={t('audit.filters.action')} value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.currentTarget.value })} />
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
          </form>
        </div>
        {entries.isSuccess && items.length === 0 && <EmptyState icon="ScrollText" title={t('audit.empty')} />}
        {items.length > 0 && (
          <Table.ScrollContainer minWidth={900}>
            <Table aria-label={t('audit.page.tableLabel')} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('audit.columns.time')}</Table.Th>
                  <Table.Th>{t('audit.columns.user')}</Table.Th>
                  <Table.Th>{t('audit.columns.action')}</Table.Th>
                  <Table.Th>{t('audit.columns.object')}</Table.Th>
                  <Table.Th>{t('audit.columns.result')}</Table.Th>
                  <Table.Th>{t('audit.columns.details')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((e) => (
                  <Table.Tr key={e.seq}>
                    <Table.Td>
                      <span className={classes.time}>{formatDateTime(e.at, i18n.language)}</span>
                      <p className={classes.secondaryMono} translate="no">
                        #{e.seq}
                      </p>
                    </Table.Td>
                    <Table.Td>
                      <div className={classes.actor}>
                        <span className={classes.avatar} aria-hidden="true">
                          {e.actor_type === 'system' ? <Icon name="Settings2" size={13} /> : initials(e.actor_name, i18n.language)}
                        </span>
                        <div>
                          <span className={classes.actorName}>{actor(e)}</span>
                          {e.ip && (
                            <p className={classes.secondaryMono}>
                              {/* The design has no IP column; the address sits under the actor, named for screen readers. */}
                              <span className={ui.visuallyHidden}>{t('audit.columns.ip')} </span>
                              <span translate="no">{e.ip}</span>
                            </p>
                          )}
                        </div>
                      </div>
                    </Table.Td>
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
                      <StatusBadge tone={RESULT_TONES[e.result] ?? 'neutral'}>{t(`audit.result.${e.result}`)}</StatusBadge>
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
        {items.length > 0 && (
          <div className={ui.tableBottom}>
            <span className={classes.footNote}>{t('audit.page.newestFirst')}</span>
            <div className={classes.footRight}>
              <CursorFooter
                shown={items.length}
                hasMore={entries.hasNextPage}
                loading={entries.isFetchingNextPage}
                onMore={() => void entries.fetchNextPage()}
                moreLabel={t('audit.loadMore')}
              />
            </div>
          </div>
        )}
      </div>
    </Stack>
  );
}
