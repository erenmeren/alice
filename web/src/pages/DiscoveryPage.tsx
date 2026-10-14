import { Stack, Tabs } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router';
import { getDiscoverySettings, listAllDiscoveryScopes, type DiscoveryScope } from '../api/discovery';
import { DASHBOARD_KEY, DISCOVERY_CERTIFICATES_KEY, DISCOVERY_SCANS_KEY, DISCOVERY_SCOPE_LIST_KEY, DISCOVERY_SETTINGS_KEY, DISCOVERY_SUMMARY_KEY } from '../api/queryKeys';
import { useChangesLocked } from '../components/acme/issued';
import { ResultsTab } from '../components/discovery/ResultsTab';
import { ScansTab } from '../components/discovery/ScansTab';
import { ScopeDialog } from '../components/discovery/ScopeDialog';
import { ScopesTab } from '../components/discovery/ScopesTab';
import { SettingsDialog } from '../components/discovery/SettingsDialog';
import { SCAN_POLL_MS, useDiscoveryRole } from '../components/discovery/shared';
import classes from '../components/discovery/discovery.module.css';
import { Notice, PageHeader } from '../components/ui';

const TABS = ['results', 'scopes', 'scans'] as const;
type Tab = (typeof TABS)[number];

// DiscoveryPage is Network discovery: the certificates Alice found on the addresses an Administrator listed (Results),
// what may be scanned (Scopes and the settings) and the scans themselves (Scans). Every role reads it; Operators start
// and cancel scans; Administrators define scopes and the settings. ?tab= picks the tab and ?view=unmanaged (the
// Overview's and the alert e-mails' link) starts the Results at the unmanaged certificates.
export function DiscoveryPage() {
  const { t } = useTranslation();
  const { admin, auditor } = useDiscoveryRole();
  const client = useQueryClient();
  const locked = useChangesLocked();
  const [params, setParams] = useSearchParams();
  const raw = params.get('tab') ?? '';
  const tab: Tab = (TABS as readonly string[]).includes(raw) ? (raw as Tab) : 'results';

  // The scopes are read on every tab: their scan in flight drives the polling, the scope filter and the Start buttons.
  // The list is read again every few seconds only while a scan is queued or running.
  const scopes = useQuery({
    queryKey: DISCOVERY_SCOPE_LIST_KEY,
    queryFn: ({ signal }) => listAllDiscoveryScopes(signal),
    refetchInterval: (q) => (q.state.data?.items.some((s) => s.active_scan_id) ? SCAN_POLL_MS : false),
  });
  const settings = useQuery({ queryKey: DISCOVERY_SETTINGS_KEY, queryFn: ({ signal }) => getDiscoverySettings(signal) });
  const items = scopes.data?.items;
  const activeCount = items?.filter((s) => s.active_scan_id).length ?? 0;
  const ctx = { locked, scanningEnabled: settings.data?.scanning_enabled ?? false, activeCount };

  // When a scan starts or ends, the reads that depend on it follow: the scans list (and its own polling), and after an
  // end the results, the summary and the Overview.
  const active = (items ?? [])
    .map((s) => s.active_scan_id)
    .filter((id): id is string => !!id)
    .sort()
    .join(',');
  const lastActive = useRef<string | null>(null);
  useEffect(() => {
    if (items === undefined) return;
    const before = lastActive.current;
    lastActive.current = active;
    if (before === null || before === active) return;
    void client.invalidateQueries({ queryKey: DISCOVERY_SCANS_KEY });
    const ended = before.split(',').some((id) => id !== '' && !active.split(',').includes(id));
    if (!ended) return;
    void client.invalidateQueries({ queryKey: DISCOVERY_CERTIFICATES_KEY });
    void client.invalidateQueries({ queryKey: DISCOVERY_SUMMARY_KEY });
    void client.invalidateQueries({ queryKey: DASHBOARD_KEY });
  }, [active, items, client]);

  const [editing, setEditing] = useState<{ scope: DiscoveryScope | null } | null>(null);
  const [editingSettings, setEditingSettings] = useState(false);
  // The dialogs are mounted only while open, so Mantine cannot give focus back: the element that opened one is
  // remembered, and when the dialog closes it gets focus again (or, when it left the page with a tab switch, the
  // selected tab).
  const opener = useRef<HTMLElement | null>(null);
  const remember = () => {
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  };
  const restoreFocus = () => {
    const target = opener.current;
    opener.current = null;
    window.setTimeout(() => {
      const el = target?.isConnected ? target : document.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]');
      el?.focus();
    }, 0);
  };
  const openScope = (scope: DiscoveryScope | null) => {
    remember();
    setEditing({ scope });
  };
  const closeScope = () => {
    setEditing(null);
    restoreFocus();
  };

  const setTab = (v: string | null) =>
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (!v || v === 'results') p.delete('tab');
        else p.set('tab', v);
        return p;
      },
      { replace: true },
    );

  return (
    <Stack gap="md">
      <PageHeader title={t('discovery.title')} description={t('discovery.description')} />
      {locked && (
        <Notice tone="warning" title={t('discovery.lockedTitle')}>
          {t('discovery.lockedText')}
        </Notice>
      )}
      {auditor && <Notice tone="neutral" title={t('discovery.readOnly')} />}
      <Tabs keepMounted={false} value={tab} onChange={setTab}>
        <Tabs.List aria-label={t('discovery.tabs.label')}>
          {TABS.map((k) => (
            <Tabs.Tab key={k} value={k}>
              {t(`discovery.tabs.${k}`)}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="results" className={classes.tabPanel}>
          <ResultsTab
            scopes={items}
            onAddScope={() => {
              setTab('scopes');
              openScope(null);
            }}
          />
        </Tabs.Panel>
        <Tabs.Panel value="scopes" className={classes.tabPanel}>
          <ScopesTab
            scopes={items}
            scopesError={scopes.error}
            settings={settings.data}
            settingsError={settings.error}
            ctx={ctx}
            onAdd={() => openScope(null)}
            onEdit={(scope) => openScope(scope)}
            onEditSettings={() => {
              remember();
              setEditingSettings(true);
            }}
          />
        </Tabs.Panel>
        <Tabs.Panel value="scans" className={classes.tabPanel}>
          <ScansTab scopes={items} ctx={ctx} />
        </Tabs.Panel>
      </Tabs>
      {admin && editing && <ScopeDialog scope={editing.scope} scanningEnabled={settings.data?.scanning_enabled !== false} onClose={closeScope} />}
      {admin && editingSettings && settings.data && (
        <SettingsDialog
          settings={settings.data}
          onClose={() => {
            setEditingSettings(false);
            restoreFocus();
          }}
        />
      )}
    </Stack>
  );
}
