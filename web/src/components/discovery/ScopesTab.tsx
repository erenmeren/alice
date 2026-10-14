import { Button, Code, Group, Stack, Switch, Table, Text } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { deleteDiscoveryScope, updateDiscoveryScope, type DiscoveryScope, type DiscoverySettings, type Page } from '../../api/discovery';
import { DISCOVERY_CERTIFICATES_KEY, DISCOVERY_SCOPE_LIST_KEY, DISCOVERY_SCOPES_KEY, DISCOVERY_SUMMARY_KEY } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, FactList, Notice, Panel, StatusBadge } from '../ui';
import classes from './discovery.module.css';
import { ScanStateBadge, scheduleText, useDiscoveryRole } from './shared';
import { ScanNowButton, type StartContext } from './StartScan';

// ScopesTab is what Alice may scan: the discovery settings (allowed networks, exclusions, retention) and the scan scopes.
// Administrators change them (with a step-up); Operators start scans of a scope; Auditors read.
export function ScopesTab({
  scopes,
  scopesError,
  settings,
  settingsError,
  ctx,
  onAdd,
  onEdit,
  onEditSettings,
}: {
  scopes: DiscoveryScope[] | undefined;
  scopesError: unknown;
  settings: DiscoverySettings | undefined;
  settingsError: unknown;
  ctx: StartContext;
  onAdd: () => void;
  onEdit: (s: DiscoveryScope) => void;
  onEditSettings: () => void;
}) {
  const { t } = useTranslation();
  const { admin, canOperate } = useDiscoveryRole();
  const [deleting, setDeleting] = useState<DiscoveryScope | null>(null);
  const addRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLDivElement>(null);

  const addButton = admin && (
    <Button ref={addRef} leftSection={<Icon name="Plus" size={15} />} onClick={onAdd}>
      {t('discovery.scopes.add')}
    </Button>
  );

  return (
    <Stack gap="lg">
      <SettingsPanel settings={settings} error={settingsError} onEdit={onEditSettings} />
      <div ref={headingRef} tabIndex={-1}>
        <Panel title={t('discovery.scopes.title')} description={t('discovery.scopes.description')} action={scopes && scopes.length > 0 ? addButton : undefined} testId="discovery-scopes">
          <Stack gap="sm">
            {!admin && <Text size="sm">{canOperate ? t('discovery.operatorNote') : t('discovery.readOnly')}</Text>}
            <ErrorAlert error={scopesError} />
            {!scopes && !scopesError && <LoadingIndicator />}
            {scopes && scopes.length === 0 && <EmptyState icon="Network" title={t('discovery.scopes.empty')} description={admin ? t('discovery.scopes.emptyText') : t('discovery.scopes.emptyOther')} action={addButton} />}
            {scopes && scopes.length > 0 && <ScopeTable scopes={scopes} ctx={ctx} onEdit={onEdit} onDelete={setDeleting} />}
          </Stack>
        </Panel>
      </div>
      {deleting && (
        <DeleteScopeDialog
          scope={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={() => {
            setDeleting(null);
            // The dialog's trigger left with the row: focus goes to the add button, or the list itself.
            window.setTimeout(() => (addRef.current ?? headingRef.current)?.focus(), 0);
          }}
        />
      )}
    </Stack>
  );
}

function ScopeTable({ scopes, ctx, onEdit, onDelete }: { scopes: DiscoveryScope[]; ctx: StartContext; onEdit: (s: DiscoveryScope) => void; onDelete: (s: DiscoveryScope) => void }) {
  const { t, i18n } = useTranslation();
  const { admin, canOperate } = useDiscoveryRole();
  const { run } = useStepUp();
  const client = useQueryClient();
  const toggle = useMutation({
    mutationFn: (s: DiscoveryScope) => run(() => updateDiscoveryScope(s.id, { enabled: !s.enabled }, s.version)),
    onSettled: () => client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY }),
  });
  return (
    <Stack gap="xs">
      <ErrorAlert error={toggle.error} />
      <Table.ScrollContainer minWidth={980}>
        <Table aria-label={t('discovery.scopes.title')} data-testid="discovery-scopes-table" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              {(['name', 'ports', 'schedule', 'enabled', 'alerts', 'lastScan', 'actions'] as const).map((k) => (
                <Table.Th key={k}>{t(`discovery.scopes.columns.${k}`)}</Table.Th>
              ))}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {scopes.map((s) => {
              const schedule = scheduleText(t, s);
              return (
                <Table.Tr key={s.id} data-testid="discovery-scope-row">
                  <Table.Td>
                    <span className={classes.name} translate="no">
                      {s.name}
                    </span>
                    <p className={classes.secondary}>
                      {t('discovery.scopes.entries', { count: s.entries.length })}
                      {s.sni_names.length > 0 && ` · ${t('discovery.scopes.sni', { count: s.sni_names.length })}`}
                      {s.exclusions.length > 0 && ` · ${t('discovery.scopes.exclusions', { count: s.exclusions.length })}`}
                    </p>
                  </Table.Td>
                  <Table.Td>
                    <span className={classes.small} translate="no">
                      {s.ports.join(', ')}
                    </span>
                  </Table.Td>
                  <Table.Td className={classes.small}>
                    {schedule.text}
                    {schedule.note && <p className={classes.secondary}>{schedule.note}</p>}
                  </Table.Td>
                  <Table.Td>
                    {admin ? (
                      // The switch is named by the scope (its column header says what it switches); On/Off beside it is
                      // the state in words, not part of its name.
                      <Group gap={6} wrap="nowrap">
                        <Switch checked={s.enabled} disabled={toggle.isPending} onChange={() => toggle.mutate(s)} aria-label={s.name} />
                        <span className={classes.small} aria-hidden="true">
                          {s.enabled ? t('discovery.scopes.on') : t('discovery.scopes.off')}
                        </span>
                      </Group>
                    ) : (
                      <StatusBadge tone={s.enabled ? 'success' : 'neutral'} icon={s.enabled ? 'CircleCheck' : 'Pause'} size="sm">
                        {s.enabled ? t('discovery.scopes.on') : t('discovery.scopes.off')}
                      </StatusBadge>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <StatusBadge tone={s.alert_on_expiry ? 'info' : 'neutral'} icon={s.alert_on_expiry ? 'Mail' : 'CircleOff'} size="sm">
                      {s.alert_on_expiry ? t('discovery.scopes.alertsOn') : t('discovery.scopes.alertsOff')}
                    </StatusBadge>
                  </Table.Td>
                  <Table.Td>
                    {s.active_scan_id ? (
                      <ScanStateBadge state="running" />
                    ) : s.last_scan ? (
                      <Stack gap={4} align="flex-start">
                        <ScanStateBadge state={s.last_scan.state} />
                        <span className={classes.secondary}>{formatDateTime(s.last_scan.finished_at ?? s.last_scan.queued_at, i18n.language)}</span>
                      </Stack>
                    ) : (
                      <span className={classes.small}>{t('discovery.scopes.never')}</span>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <div className={classes.actionsCell}>
                      {canOperate && <ScanNowButton scope={s} ctx={ctx} />}
                      {admin && (
                        <Group gap={4}>
                          <Button size="xs" variant="subtle" aria-label={t('discovery.scopes.editLabel', { name: s.name })} onClick={() => onEdit(s)}>
                            {t('discovery.scopes.edit')}
                          </Button>
                          <Button size="xs" variant="subtle" color="red" aria-label={t('discovery.scopes.deleteLabel', { name: s.name })} onClick={() => onDelete(s)}>
                            {t('discovery.scopes.delete')}
                          </Button>
                        </Group>
                      )}
                      {!canOperate && <span className={classes.small}>–</span>}
                    </div>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Stack>
  );
}

// SettingsPanel shows what every scope is bound by. With no allowed network nothing can be scanned: a calm but
// prominent notice says so first, with the way to change it.
function SettingsPanel({ settings, error, onEdit }: { settings: DiscoverySettings | undefined; error: unknown; onEdit: () => void }) {
  const { t } = useTranslation();
  const { admin } = useDiscoveryRole();
  const list = (items: string[] | undefined) =>
    items && items.length > 0 ? (
      <ul className={classes.codeList}>
        {items.map((i) => (
          <li key={i}>
            <Code translate="no">{i}</Code>
          </li>
        ))}
      </ul>
    ) : (
      t('discovery.settings.none')
    );
  return (
    <Stack gap="sm">
      {settings && settings.allowed_networks.length === 0 && (
        <Notice
          tone="info"
          role="status"
          testId="discovery-no-networks"
          title={t('discovery.settings.emptyTitle')}
          action={
            admin ? (
              <Button size="xs" onClick={onEdit}>
                {t('discovery.settings.emptyAdminAction')}
              </Button>
            ) : undefined
          }
        >
          {t('discovery.settings.emptyText')} {!admin && t('discovery.settings.emptyOther')}
        </Notice>
      )}
      <Panel
        title={t('discovery.settings.title')}
        action={
          admin && settings ? (
            <Button variant="default" size="xs" leftSection={<Icon name="Settings2" size={14} />} onClick={onEdit}>
              {t('discovery.settings.edit')}
            </Button>
          ) : undefined
        }
        testId="discovery-settings"
      >
        <ErrorAlert error={error} />
        {!settings && !error && <LoadingIndicator />}
        {settings && (
          <FactList
            label={t('discovery.settings.title')}
            facts={[
              { label: t('discovery.settings.allowed'), value: list(settings.allowed_networks) },
              { label: t('discovery.settings.exclusions'), value: list(settings.global_exclusions) },
              { label: t('discovery.settings.retentionShort'), value: t('discovery.settings.retentionValue', { count: settings.retention_days }) },
              {
                label: t('discovery.settings.builtin'),
                value: (
                  <>
                    {list(settings.builtin_exclusions)}
                    <p className={classes.secondary}>{t('discovery.settings.builtinHelp')}</p>
                  </>
                ),
              },
            ]}
          />
        )}
      </Panel>
    </Stack>
  );
}

// DeleteScopeDialog asks before a scope is deleted and says what happens to its results. The row leaves the list at
// once (no flash of the deleted scope while the list is read again).
function DeleteScopeDialog({ scope, onClose, onDeleted }: { scope: DiscoveryScope; onClose: () => void; onDeleted: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const del = useMutation({
    mutationFn: () => run(() => deleteDiscoveryScope(scope.id, scope.version)),
    onSuccess: () => {
      client.setQueryData<Page<DiscoveryScope>>(DISCOVERY_SCOPE_LIST_KEY, (old) => (old ? { ...old, items: old.items.filter((s) => s.id !== scope.id) } : old));
      void client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY });
      void client.invalidateQueries({ queryKey: DISCOVERY_CERTIFICATES_KEY });
      void client.invalidateQueries({ queryKey: DISCOVERY_SUMMARY_KEY });
      onDeleted();
    },
  });
  return (
    <AppModal opened onClose={onClose} title={t('discovery.delete.title', { name: scope.name })}>
      <Stack gap="sm">
        <Text size="sm">{t('discovery.delete.text')}</Text>
        <Text size="sm">{t('discovery.delete.results')}</Text>
        <ErrorAlert error={del.error} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose} data-autofocus>
          {t('ui.cancel')}
        </Button>
        <Button color="red" loading={del.isPending} onClick={() => del.mutate()}>
          {t('discovery.delete.confirm')}
        </Button>
      </DialogActions>
    </AppModal>
  );
}
