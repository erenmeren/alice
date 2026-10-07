import { Badge, Button, Code, Group, Paper, Stack, Switch, Text, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SSO_PROVIDERS_KEY, SSO_SETTINGS_KEY } from '../../api/queryKeys';
import { deleteProvider, getSSOSettings, listProviders, refreshProvider, saveSSOSettings, type Provider } from '../../api/sso';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { WRAP } from '../wrap';
import { MappingsTable } from './MappingsTable';
import { ProviderDialog } from './ProviderDialog';

type Dialog = { kind: 'form'; provider: Provider | null } | { kind: 'delete'; provider: Provider };

// SSOSettings is the single sign-on tab: the "SSO users may be Admin" switch, the identity providers and each one's group
// mappings. Everything here needs a fresh verification, like the other settings.
export function SSOSettings() {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
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
    <Stack gap="lg">
      <Stack gap="xs">
        {settings.isPending && <LoadingIndicator />}
        <ErrorAlert error={settings.error} />
        {settings.data && (
          <Switch
            role="switch"
            label={t('sso.allowAdmin')}
            aria-describedby="sso-allow-admin-help"
            checked={settings.data.allow_admin_role}
            disabled={allow.isPending}
            onChange={(e) => (e.currentTarget.checked ? allow.mutate(true) : setConfirmOff(true))}
          />
        )}
        <Text size="sm" c="gray.7" id="sso-allow-admin-help">
          {t('sso.allowAdminHelp')}
        </Text>
        <ErrorAlert error={allow.error} />
        <Text size="sm">{t('sso.mfaNote')}</Text>
      </Stack>

      <Stack gap="sm">
        <Group justify="space-between">
          <Title order={2} size="h3">
            {t('sso.providers')}
          </Title>
          <Button onClick={() => setDialog({ kind: 'form', provider: null })}>{t('sso.addProvider')}</Button>
        </Group>
        {providers.isPending && <LoadingIndicator />}
        <ErrorAlert error={providers.error} />
        {providers.isSuccess && providers.data.items.length === 0 && <Text c="gray.7">{t('sso.noProviders')}</Text>}
        {providers.data?.items.map((p) => (
          <ProviderSection key={p.id} provider={p} onEdit={() => setDialog({ kind: 'form', provider: p })} onDelete={() => setDialog({ kind: 'delete', provider: p })} />
        ))}
      </Stack>

      {confirmOff && (
        <AppModal opened onClose={() => setConfirmOff(false)} title={t('sso.switchOffTitle')}>
          <Stack gap="sm">
            <Text size="sm">{t('sso.switchOffText')}</Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirmOff(false)}>
                {t('ui.cancel')}
              </Button>
              <Button
                color="red.9"
                onClick={() => {
                  setConfirmOff(false);
                  allow.mutate(false);
                }}
              >
                {t('sso.switchOffConfirm')}
              </Button>
            </Group>
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
    <Paper component="section" aria-label={p.name} withBorder p="md">
      <Stack gap="sm">
        <Group justify="space-between" align="flex-start">
          <div>
            <Group gap="xs">
              <Title order={3} size="h4">
                {p.name}
              </Title>
              <Badge variant="light" color={p.enabled ? 'green' : 'gray'} tt="none">
                {p.enabled ? t('sso.status.enabled') : t('sso.status.disabled')}
              </Badge>
            </Group>
            <Code translate="no" style={WRAP}>
              {p.issuer_url}
            </Code>
          </div>
          <Group gap="xs">
            <Button size="xs" variant="default" loading={refresh.isPending} onClick={() => refresh.mutate()}>
              {t('sso.refresh')}
            </Button>
            <Button size="xs" variant="default" onClick={onEdit} aria-label={t('sso.edit', { name: p.name })}>
              {t('users.actions.edit')}
            </Button>
            <Button size="xs" variant="default" onClick={onDelete} aria-label={t('sso.delete', { name: p.name })}>
              {t('sso.deleteShort')}
            </Button>
          </Group>
        </Group>
        <ErrorAlert error={refresh.error} />
        <MappingsTable providerId={p.id} />
      </Stack>
    </Paper>
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
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red.9" loading={remove.isPending} onClick={() => remove.mutate()}>
            {t('sso.deleteConfirm')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
