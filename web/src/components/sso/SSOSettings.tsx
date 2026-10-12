import { Button, Code, Group, Stack, Switch, Text, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SSO_PROVIDERS_KEY, SSO_SETTINGS_KEY } from '../../api/queryKeys';
import { deleteProvider, getSSOSettings, listProviders, refreshProvider, saveSSOSettings, type Provider } from '../../api/sso';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { Icon } from '../../design/Icon';
import { DialogActions, EmptyState, Notice, Panel, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import classes from '../settings/settings.module.css';
import { MappingsTable } from './MappingsTable';
import { ProviderDialog } from './ProviderDialog';

type Dialog = { kind: 'form'; provider: Provider | null } | { kind: 'delete'; provider: Provider };

// SSOSettings is the single sign-on tab: the "SSO users may be Admin" switch, the identity providers and each one's group
// mappings. Everything here needs a fresh verification, like the other settings.
export function SSOSettings() {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const helpId = useId();
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);
  const settings = useQuery({ queryKey: SSO_SETTINGS_KEY, queryFn: () => run(getSSOSettings) });
  const providers = useQuery({ queryKey: SSO_PROVIDERS_KEY, queryFn: () => run(listProviders) });
  const allow = useMutation({
    mutationFn: (value: boolean) => run(() => saveSSOSettings(settings.data?.version ?? 0, value)),
    onSuccess: (data) => client.setQueryData(SSO_SETTINGS_KEY, data),
    // A refusal or a 412 leaves the switch where the server has it.
    onError: () => void client.invalidateQueries({ queryKey: SSO_SETTINGS_KEY }),
  });

  return (
    <Stack gap="md">
      <Stack gap="xs">
        {settings.isPending && <LoadingIndicator />}
        <ErrorAlert error={settings.error} />
        {/* The design's switch row: the setting's name and help on the left, the switch on the right. */}
        <div className={ui.switchRow} style={{ paddingTop: 0 }}>
          <div>
            <div className={ui.rowTitle}>{t('sso.allowAdmin')}</div>
            <p className={ui.rowHelp} id={helpId}>
              {t('sso.allowAdminHelp')}
            </p>
          </div>
          {settings.data && (
            <Switch
              role="switch"
              aria-label={t('sso.allowAdmin')}
              aria-describedby={helpId}
              checked={settings.data.allow_admin_role}
              disabled={allow.isPending}
              onChange={(e) => (e.currentTarget.checked ? allow.mutate(true) : setConfirmOff(true))}
            />
          )}
        </div>
        <ErrorAlert error={allow.error} />
        <Text size="sm">{t('sso.mfaNote')}</Text>
      </Stack>

      <section className={classes.subSection}>
        <Group justify="space-between" align="center" mb="sm">
          <Title order={3} className={classes.subTitle} mb={0}>
            {t('sso.providers')}
          </Title>
          <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'form', provider: null })}>
            {t('sso.addProvider')}
          </Button>
        </Group>
        <Stack gap="md">
          {providers.isPending && <LoadingIndicator />}
          <ErrorAlert error={providers.error} />
          {providers.isSuccess && providers.data.items.length === 0 && (
            <div className={ui.tablePanel}>
              <EmptyState icon="Building2" title={t('sso.noProviders')} />
            </div>
          )}
          {providers.data?.items.map((p) => (
            <ProviderSection key={p.id} provider={p} onEdit={() => setDialog({ kind: 'form', provider: p })} onDelete={() => setDialog({ kind: 'delete', provider: p })} />
          ))}
        </Stack>
      </section>

      <Notice tone="brand" title={t('settings.page.breakGlassTitle')}>
        {t('settings.page.breakGlassText')}
      </Notice>

      {confirmOff && (
        <AppModal opened onClose={() => setConfirmOff(false)} title={t('sso.switchOffTitle')}>
          <Stack gap="sm">
            <Text size="sm">{t('sso.switchOffText')}</Text>
            <DialogActions>
              <Button variant="default" onClick={() => setConfirmOff(false)}>
                {t('ui.cancel')}
              </Button>
              <Button
                color="red"
                onClick={() => {
                  setConfirmOff(false);
                  allow.mutate(false);
                }}
              >
                {t('sso.switchOffConfirm')}
              </Button>
            </DialogActions>
          </Stack>
        </AppModal>
      )}
      {dialog?.kind === 'form' && <ProviderDialog provider={dialog.provider} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'delete' && <DeleteDialog provider={dialog.provider} onClose={() => setDialog(null)} />}
    </Stack>
  );
}

function ProviderSection({ provider: p, onEdit, onDelete }: { provider: Provider; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const refresh = useMutation({
    mutationFn: () => run(() => refreshProvider(p.id, p.version)),
    // The answer carries the new version: it replaces the provider in the list, so the next change sends it.
    onSuccess: (fresh) =>
      client.setQueryData<{ items: Provider[] }>(SSO_PROVIDERS_KEY, (old) => (old ? { items: old.items.map((x) => (x.id === fresh.id ? fresh : x)) } : old)),
  });
  return (
    <Panel aria-label={p.name}>
      <Stack gap="sm">
        <div className={classes.providerHead}>
          <span className={classes.providerIcon}>
            <Icon name="Building2" size={16} />
          </span>
          <div className={classes.providerText}>
            <Title order={4} className={classes.providerName}>
              {p.name}
            </Title>
            <div className={classes.providerIssuer}>
              <Code translate="no">{p.issuer_url}</Code>
            </div>
          </div>
          <StatusBadge tone={p.enabled ? 'success' : 'neutral'} icon={p.enabled ? 'CircleCheck' : undefined}>
            {p.enabled ? t('sso.status.enabled') : t('sso.status.disabled')}
          </StatusBadge>
          <div className={classes.providerActions}>
            <Button size="xs" variant="default" leftSection={<Icon name="RefreshCw" size={14} />} loading={refresh.isPending} onClick={() => refresh.mutate()}>
              {t('sso.refresh')}
            </Button>
            <Button size="xs" variant="default" onClick={onEdit} aria-label={t('sso.edit', { name: p.name })}>
              {t('users.actions.edit')}
            </Button>
            <Button size="xs" variant="default" onClick={onDelete} aria-label={t('sso.delete', { name: p.name })}>
              {t('sso.deleteShort')}
            </Button>
          </div>
        </div>
        <ErrorAlert error={refresh.error} />
        <MappingsTable providerId={p.id} />
      </Stack>
    </Panel>
  );
}

function DeleteDialog({ provider, onClose }: { provider: Provider; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const remove = useMutation({
    mutationFn: () => run(() => deleteProvider(provider.id, provider.version)),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: SSO_PROVIDERS_KEY });
      onClose();
    },
  });
  return (
    <AppModal opened onClose={onClose} title={t('sso.deleteTitle', { name: provider.name })}>
      <Stack gap="sm">
        <Text size="sm">{t('sso.deleteText')}</Text>
        <ErrorAlert error={remove.error} />
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={remove.isPending} onClick={() => remove.mutate()}>
            {t('sso.deleteConfirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
