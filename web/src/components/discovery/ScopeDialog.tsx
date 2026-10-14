import { Button, Checkbox, NativeSelect, NumberInput, Stack, Switch, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import {
  DEFAULT_CONCURRENCY,
  DEFAULT_RATE,
  MAX_CONCURRENCY,
  MAX_ENDPOINTS,
  MAX_ENTRIES,
  MAX_PORTS,
  MAX_RATE,
  MAX_SCHEDULE_HOURS,
  MAX_SCOPE_NAME,
  createDiscoveryScope,
  elementProblem,
  lines,
  parsePorts,
  previewDiscoveryScope,
  updateDiscoveryScope,
  type DiscoveryPreview,
  type DiscoveryScope,
  type DiscoveryScopeCreate,
  type DiscoveryScopePatch,
} from '../../api/discovery';
import { DISCOVERY_SCOPES_KEY, DISCOVERY_SUMMARY_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { reasonTitle } from '../JobErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';
import classes from './discovery.module.css';
import { formatNumber } from './shared';

// How long the form waits after the last keystroke before it asks for the size again.
export const PREVIEW_DEBOUNCE_MS = 800;
// A form larger than this is not sent for its size (the server refuses it anyway); its own problem is shown at once.
export const PREVIEW_MAX_CHARS = 70_000;
// The wait after a refused size check (429) when the server sends no Retry-After.
const PREVIEW_RETRY_S = 60;

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

// timeZones is the IANA zones this browser knows (with UTC and the scope's own zone), sorted.
export function timeZones(current: string): string[] {
  let zones: string[];
  try {
    zones = (Intl as unknown as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.('timeZone') ?? [];
  } catch {
    zones = [];
  }
  const all = new Set(zones);
  all.add('UTC');
  if (current) all.add(current);
  return [...all].sort();
}

const asInt = (v: number | string) => (typeof v === 'number' ? v : v.trim() === '' ? 0 : Number(v));
const sameList = (a: readonly (string | number)[], b: readonly (string | number)[]) => a.length === b.length && a.every((x, i) => x === b[i]);

type Preview = { kind: 'idle' } | { kind: 'checking' } | { kind: 'ok'; data: DiscoveryPreview } | { kind: 'error'; error: unknown } | { kind: 'stepup' } | { kind: 'limited' };

// ScopeDialog adds or changes a scan scope (an Administrator, with a fresh step-up). While the person types, the scope's
// size is asked from the server (debounced, the previous request cancelled): no name is looked up and nothing is dialed
// for it. A refusal that names one line (ALC-DSC-0001/0002/0003/0010) marks that line under its field. The server judges
// every rule again on save.
export function ScopeDialog({ scope, scanningEnabled, onClose, onSaved }: { scope: DiscoveryScope | null; scanningEnabled: boolean; onClose: () => void; onSaved?: (s: DiscoveryScope) => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [name, setName] = useState(scope?.name ?? '');
  const [entries, setEntries] = useState(scope?.entries.join('\n') ?? '');
  const [ports, setPorts] = useState(scope ? scope.ports.join(', ') : '443');
  const [sni, setSni] = useState(scope?.sni_names.join('\n') ?? '');
  const [exclusions, setExclusions] = useState(scope?.exclusions.join('\n') ?? '');
  const [rate, setRate] = useState<number | string>(scope?.rate_per_sec || '');
  const [concurrency, setConcurrency] = useState<number | string>(scope?.concurrency || '');
  const [hours, setHours] = useState<number | string>(scope?.schedule_hours || '');
  const [useWindow, setUseWindow] = useState(!!scope?.window_start);
  const [windowStart, setWindowStart] = useState(scope?.window_start || '01:00');
  const [windowEnd, setWindowEnd] = useState(scope?.window_end || '05:00');
  const [tz, setTz] = useState(scope?.window_tz && scope.window_start ? scope.window_tz : browserTimeZone());
  const [alert, setAlert] = useState(scope?.alert_on_expiry ?? false);
  const [enabled, setEnabled] = useState(scope?.enabled ?? true);
  const [local, setLocal] = useState<Record<string, string>>({});
  const zones = useMemo(() => timeZones(tz), [tz]);

  // The parts of the form that decide the size.
  const entryList = lines(entries);
  const portParse = parsePorts(ports);
  const sniList = lines(sni);
  const exclusionList = lines(exclusions);
  const tooLarge = entryList.length > MAX_ENTRIES || entries.length + sni.length + exclusions.length > PREVIEW_MAX_CHARS;
  const sizeBody: DiscoveryScopePatch | null =
    entryList.length > 0 && !tooLarge && portParse.problem === '' ? { entries: entryList, ports: portParse.ports, sni_names: sniList, exclusions: exclusionList } : null;
  const sizeKey = sizeBody ? JSON.stringify(sizeBody) : '';

  // The answer for the size now typed; while it is on its way (the pause after typing included) it is "checking".
  // announced is the last real answer (never "checking"): the one live region reads it, so it changes only on an answer.
  const [answer, setAnswer] = useState<{ key: string; result: Preview }>({ key: '', result: { kind: 'idle' } });
  const [announced, setAnnounced] = useState<Preview>({ kind: 'idle' });
  const answered = (key: string, result: Preview) => {
    setAnswer({ key, result });
    setAnnounced(result);
  };
  const preview: Preview = !sizeKey ? { kind: 'idle' } : answer.key === sizeKey ? answer.result : { kind: 'checking' };
  // A refused size check (429) is asked again once the server's wait is over.
  const [retry, setRetry] = useState(0);
  const retryTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(retryTimer.current), []);
  useEffect(() => {
    if (!sizeKey) return;
    const body = JSON.parse(sizeKey) as DiscoveryScopePatch;
    const ctl = new AbortController();
    const timer = window.setTimeout(() => {
      previewDiscoveryScope(body, ctl.signal).then(
        (data) => {
          // An answer that arrives after the form changed is not this form's size.
          if (!ctl.signal.aborted) answered(sizeKey, { kind: 'ok', data });
        },
        (error: unknown) => {
          if (ctl.signal.aborted) return;
          if (isApiError(error) && error.status === 429) {
            answered(sizeKey, { kind: 'limited' });
            window.clearTimeout(retryTimer.current);
            retryTimer.current = window.setTimeout(() => setRetry((n) => n + 1), (error.retryAfter ?? PREVIEW_RETRY_S) * 1000);
            return;
          }
          // The size is never worth a code prompt while someone types: it waits for a click.
          answered(sizeKey, isApiError(error, 'auth.stepup_required') ? { kind: 'stepup' } : { kind: 'error', error });
        },
      );
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      ctl.abort();
    };
  }, [sizeKey, retry]);

  const previewWithStepUp = async () => {
    const key = sizeKey;
    if (!key) return;
    setAnswer({ key, result: { kind: 'checking' } });
    try {
      const data = await run(() => previewDiscoveryScope(JSON.parse(key) as DiscoveryScopePatch));
      answered(key, { kind: 'ok', data });
    } catch (error) {
      answered(key, { kind: 'error', error });
    }
  };

  const schedule = () => {
    const h = asInt(hours);
    return useWindow && h > 0 ? { schedule_hours: h, window_start: windowStart, window_end: windowEnd, window_tz: tz } : { schedule_hours: h, window_start: '', window_end: '', window_tz: '' };
  };
  const fullBody = (): DiscoveryScopeCreate => ({
    name: name.trim(),
    entries: entryList,
    ports: portParse.ports,
    sni_names: sniList,
    exclusions: exclusionList,
    enabled,
    alert_on_expiry: alert,
    rate_per_sec: asInt(rate),
    concurrency: asInt(concurrency),
    ...schedule(),
  });
  // patchOf is what changed; the four schedule fields go together (the API replaces the whole schedule).
  const patchOf = (s: DiscoveryScope, b: DiscoveryScopeCreate): DiscoveryScopePatch => {
    const p: DiscoveryScopePatch = {};
    if (b.name !== s.name) p.name = b.name;
    if (!sameList(b.entries, s.entries)) p.entries = b.entries;
    if (!sameList(b.ports, s.ports)) p.ports = b.ports;
    if (!sameList(b.sni_names ?? [], s.sni_names)) p.sni_names = b.sni_names;
    if (!sameList(b.exclusions ?? [], s.exclusions)) p.exclusions = b.exclusions;
    if (b.enabled !== s.enabled) p.enabled = b.enabled;
    if (b.alert_on_expiry !== s.alert_on_expiry) p.alert_on_expiry = b.alert_on_expiry;
    if (b.rate_per_sec !== s.rate_per_sec) p.rate_per_sec = b.rate_per_sec;
    if (b.concurrency !== s.concurrency) p.concurrency = b.concurrency;
    const sameTz = (b.window_tz || 'UTC') === (s.window_tz || 'UTC') || b.window_start === '';
    if (b.schedule_hours !== s.schedule_hours || b.window_start !== s.window_start || b.window_end !== s.window_end || !sameTz) {
      p.schedule_hours = b.schedule_hours;
      p.window_start = b.window_start;
      p.window_end = b.window_end;
      p.window_tz = b.window_tz;
    }
    return p;
  };

  const save = useMutation({
    mutationFn: (body: DiscoveryScopeCreate) => run(() => (scope ? updateDiscoveryScope(scope.id, patchOf(scope, body), scope.version) : createDiscoveryScope(body))),
    onSuccess: async (saved) => {
      await client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY });
      void client.invalidateQueries({ queryKey: DISCOVERY_SUMMARY_KEY });
      onSaved?.(saved);
      onClose();
    },
  });

  const unchanged = scope !== null && Object.keys(patchOf(scope, fullBody())).length === 0;

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (save.isPending) return;
    const problems: Record<string, string> = {};
    if (name.trim() === '') problems.name = t('discovery.scope.nameRequired');
    if (entryList.length === 0) problems.entries = t('discovery.scope.entriesRequired');
    else if (entryList.length > MAX_ENTRIES) problems.entries = t('discovery.scope.entriesTooMany', { max: MAX_ENTRIES });
    if (portParse.problem) problems.ports = t(portParse.problem, { max: MAX_PORTS });
    const r = asInt(rate);
    const c = asInt(concurrency);
    const h = asInt(hours);
    if (!Number.isInteger(r) || r < 0 || r > MAX_RATE) problems.rate_per_sec = t('discovery.scope.rangeProblem', { max: MAX_RATE });
    if (!Number.isInteger(c) || c < 0 || c > MAX_CONCURRENCY) problems.concurrency = t('discovery.scope.rangeProblem', { max: MAX_CONCURRENCY });
    if (!Number.isInteger(h) || h < 0 || h > MAX_SCHEDULE_HOURS) problems.schedule_hours = t('discovery.scope.hoursRange', { max: MAX_SCHEDULE_HOURS });
    else if (useWindow && h === 0) problems.schedule_hours = t('discovery.scope.windowNeedsSchedule');
    if (useWindow && (!/^\d{2}:\d{2}$/.test(windowStart) || !/^\d{2}:\d{2}$/.test(windowEnd) || windowStart === windowEnd)) problems.window = t('discovery.scope.windowRequired');
    setLocal(problems);
    if (Object.keys(problems).length > 0) return;
    save.mutate(fullBody());
  };

  // The server's word on a field: a refusal naming a line (the save's, else the size check's) and the field problems of
  // a validation error.
  const lineError = (error: unknown): Record<string, string> => {
    const p = elementProblem(error);
    if (!p) return {};
    const title = reasonTitle(t, i18n, p.reason);
    return { [p.field || 'entries']: p.index === null ? title : t('discovery.scope.line', { line: p.index + 1, problem: title }) };
  };
  const previewError = preview.kind === 'error' ? preview.error : null;
  const live: Record<string, string> = tooLarge ? { entries: t('discovery.scope.entriesTooMany', { max: MAX_ENTRIES }) } : {};
  const fieldErrors = { ...lineError(previewError), ...fieldErrorsOf(save.error, t, i18n), ...lineError(save.error), ...live, ...local };
  const title = scope ? t('discovery.scope.editTitle', { name: scope.name }) : t('discovery.scope.addTitle');

  return (
    <AppModal opened onClose={onClose} title={title} size="lg">
      <form onSubmit={submit} noValidate>
        <Stack gap="sm">
          {!scanningEnabled && <Notice tone="warning" title={t('discovery.settings.emptyTitle')}>{t('discovery.scope.noNetworks')}</Notice>}
          {scope?.active_scan_id && <Notice tone="info" title={t('discovery.scope.runningTitle')}>{t('discovery.scope.runningText')}</Notice>}
          <TextInput label={t('discovery.scope.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={MAX_SCOPE_NAME} error={fieldErrors.name} data-autofocus />
          <Textarea
            label={t('discovery.scope.entries')}
            description={t('discovery.scope.entriesHelp', { max: MAX_ENTRIES })}
            value={entries}
            onChange={(e) => setEntries(e.currentTarget.value)}
            required
            autosize
            minRows={3}
            maxRows={10}
            spellCheck={false}
            autoComplete="off"
            translate="no"
            error={fieldErrors.entries}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          />
          <TextInput label={t('discovery.scope.ports')} description={t('discovery.scope.portsHelp', { max: MAX_PORTS })} value={ports} onChange={(e) => setPorts(e.currentTarget.value)} required autoComplete="off" error={fieldErrors.ports} />
          <Textarea
            label={t('discovery.scope.sni')}
            description={t('discovery.scope.sniHelp')}
            value={sni}
            onChange={(e) => setSni(e.currentTarget.value)}
            autosize
            minRows={1}
            maxRows={6}
            spellCheck={false}
            autoComplete="off"
            translate="no"
            error={fieldErrors.sni_names}
          />
          <Textarea
            label={t('discovery.scope.exclusions')}
            description={t('discovery.scope.exclusionsHelp')}
            value={exclusions}
            onChange={(e) => setExclusions(e.currentTarget.value)}
            autosize
            minRows={1}
            maxRows={6}
            spellCheck={false}
            autoComplete="off"
            translate="no"
            error={fieldErrors.exclusions}
          />
          <SizePreview preview={preview} announced={announced} onStepUp={() => void previewWithStepUp()} lang={i18n.language} />
          <div className={classes.windowRow}>
            <NumberInput
              label={t('discovery.scope.rate')}
              description={t('discovery.scope.rateHelp', { def: DEFAULT_RATE, max: MAX_RATE })}
              value={rate}
              onChange={setRate}
              min={0}
              max={MAX_RATE}
              allowDecimal={false}
              placeholder={String(DEFAULT_RATE)}
              error={fieldErrors.rate_per_sec}
            />
            <NumberInput
              label={t('discovery.scope.concurrency')}
              description={t('discovery.scope.concurrencyHelp', { def: DEFAULT_CONCURRENCY, max: MAX_CONCURRENCY })}
              value={concurrency}
              onChange={setConcurrency}
              min={0}
              max={MAX_CONCURRENCY}
              allowDecimal={false}
              placeholder={String(DEFAULT_CONCURRENCY)}
              error={fieldErrors.concurrency}
            />
          </div>
          <NumberInput
            label={t('discovery.scope.hours')}
            description={t('discovery.scope.hoursHelp', { max: MAX_SCHEDULE_HOURS })}
            value={hours}
            onChange={setHours}
            min={0}
            max={MAX_SCHEDULE_HOURS}
            allowDecimal={false}
            error={fieldErrors.schedule_hours}
          />
          <Checkbox label={t('discovery.scope.useWindow')} checked={useWindow} onChange={(e) => setUseWindow(e.currentTarget.checked)} />
          {useWindow && (
            <Stack gap="xs">
              <fieldset className={classes.fieldset} aria-describedby={fieldErrors.window ? 'scope-window-error' : 'scope-window-help'}>
                <legend className={classes.legend}>{t('discovery.scope.windowLegend')}</legend>
                <div className={classes.windowRow}>
                  <TextInput type="time" label={t('discovery.scope.windowStart')} value={windowStart} onChange={(e) => setWindowStart(e.currentTarget.value)} error={!!fieldErrors.window} />
                  <TextInput type="time" label={t('discovery.scope.windowEnd')} value={windowEnd} onChange={(e) => setWindowEnd(e.currentTarget.value)} error={!!fieldErrors.window} />
                </div>
                {fieldErrors.window && (
                  <p className={classes.fieldError} id="scope-window-error">
                    {fieldErrors.window}
                  </p>
                )}
              </fieldset>
              <NativeSelect label={t('discovery.scope.windowTz')} value={tz} onChange={(e) => setTz(e.currentTarget.value)} data={zones} error={fieldErrors.window_tz} />
              <p className={classes.help} id="scope-window-help">
                {t('discovery.scope.windowHelp')}
              </p>
            </Stack>
          )}
          <Switch label={t('discovery.scope.alert')} description={t('discovery.scope.alertHelp')} checked={alert} onChange={(e) => setAlert(e.currentTarget.checked)} />
          <Switch label={t('discovery.scope.enabled')} description={t('discovery.scope.enabledHelp')} checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
          <ErrorAlert error={save.error} />
        </Stack>
        <DialogActions note={unchanged ? t('discovery.scope.unchanged') : undefined}>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={save.isPending} disabled={unchanged}>
            {t('discovery.scope.save')}
          </Button>
        </DialogActions>
      </form>
    </AppModal>
  );
}

// SizePreview is the scope's size as the server counts it, and the ranges Alice always leaves out of it. The box is
// aria-busy while a size is asked; one live line holds the last answer, so a screen reader hears each answer once and
// nothing while the person types.
function SizePreview({ preview, announced, onStepUp, lang }: { preview: Preview; announced: Preview; onStepUp: () => void; lang: string }) {
  const { t, i18n } = useTranslation();
  const n = (v: number) => formatNumber(v, lang);
  const main = (p: Preview): string => {
    switch (p.kind) {
      case 'ok':
        return t('discovery.scope.preview.covers', {
          addresses:
            p.data.hostnames > 0
              ? t('discovery.scope.preview.withHosts', {
                  addresses: t('discovery.scope.preview.addresses', { count: p.data.addresses, n: n(p.data.addresses) }),
                  hostnames: t('discovery.scope.preview.hostnames', { count: p.data.hostnames, n: n(p.data.hostnames) }),
                })
              : t('discovery.scope.preview.addresses', { count: p.data.addresses, n: n(p.data.addresses) }),
          ports: t('discovery.scope.preview.ports', { count: p.data.ports, n: n(p.data.ports) }),
        });
      case 'stepup':
        return t('discovery.scope.preview.stepUp');
      case 'limited':
        return t('discovery.scope.preview.tooMany');
      case 'error':
        return isApiError(p.error) ? reasonTitle(t, i18n, p.error.reason) : t('ui.unexpectedError');
      default:
        return '';
    }
  };
  return (
    <section className={classes.preview} aria-busy={preview.kind === 'checking'} aria-labelledby="scope-size-title" data-testid="scope-preview">
      <h3 className={classes.previewTitle} id="scope-size-title">
        {t('discovery.scope.preview.title')}
      </h3>
      {preview.kind === 'idle' && <p className={classes.previewLine}>{t('discovery.scope.preview.waiting')}</p>}
      {preview.kind === 'checking' && <p className={classes.previewLine}>{t('discovery.scope.preview.checking')}</p>}
      {/* The one live line: the last answer. It changes when an answer arrives, never while the person types. */}
      <p aria-live="polite" data-testid="scope-preview-live" className={announced.kind === 'ok' ? classes.previewMain : classes.previewLine}>
        {preview.kind === 'idle' ? '' : main(announced)}
      </p>
      {preview.kind === 'stepup' && (
        <Button size="xs" variant="default" w="fit-content" onClick={onStepUp}>
          {t('discovery.scope.preview.stepUpButton')}
        </Button>
      )}
      {preview.kind === 'ok' && (
        <>
          <p className={classes.previewLine}>{t('discovery.scope.preview.endpoints', { count: preview.data.endpoints, n: n(preview.data.endpoints), max: n(MAX_ENDPOINTS) })}</p>
          {preview.data.excluded_addresses > 0 && <p className={classes.previewLine}>{t('discovery.scope.preview.excluded', { count: preview.data.excluded_addresses, n: n(preview.data.excluded_addresses) })}</p>}
          {preview.data.builtin_exclusions.length > 0 && (
            <p className={classes.previewLine}>
              {t('discovery.scope.preview.builtin')}{' '}
              <span translate="no">{preview.data.builtin_exclusions.join(', ')}</span>
            </p>
          )}
        </>
      )}
    </section>
  );
}
