import { Button, Code, Group, Stack, Text, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACME_PRESETS,
  HOOK_POLL_MAX,
  HOOK_TOTAL_MAX,
  HOOK_WAIT_MAX,
  deleteACMEHook,
  deleteACMEProvider,
  directoryHost,
  listACMEHooks,
  listACMEProviders,
  presetKey,
  type ACMEHook,
  type ACMEProvider,
} from '../../api/acme';
import { ACME_CERTIFICATES_KEY, ACME_HOOKS_KEY, ACME_HOOK_LIST_KEY, ACME_PROVIDERS_KEY, ACME_PROVIDER_LIST_KEY, notACMEPreview } from '../../api/queryKeys';
import { useAuth } from '../../auth/AuthProvider';
import { canPlatform } from '../../auth/permissions';
import { Icon, type IconName } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, EmptyState, Notice, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import settings from '../settings/settings.module.css';
import { AccountPanel } from './AccountPanel';
import { HookDialog } from './HookDialog';
import { ProviderDialog } from './ProviderDialog';
import classes from './acme.module.css';

type Dialog =
  | { kind: 'provider'; provider: ACMEProvider | null }
  | { kind: 'deleteProvider'; provider: ACMEProvider }
  | { kind: 'hook'; hook: ACMEHook | null }
  | { kind: 'deleteHook'; hook: ACMEHook };

// AcmeSettings is the Certificate authorities section of Settings (design row 8): the certificate authorities (ACME
// providers) with their accounts, and the DNS hooks. Reading needs acme.view; every change needs an Administrator with a
// fresh step-up (acme.manage), so another role sees the same lists without a single action button. Nothing here
// contacts a certificate authority or a hook, except registering, rotating, checking and deactivating an account.
export function AcmeSettings() {
  const { t } = useTranslation();
  const { session } = useAuth();
  // Authorities and hooks are the installation's: a global Administrator's (acme.manage, platform).
  const canManage = canPlatform(session, 'acme.manage');
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const providers = useQuery({ queryKey: ACME_PROVIDER_LIST_KEY, queryFn: ({ signal }) => listACMEProviders(signal) });
  const hooks = useQuery({ queryKey: ACME_HOOK_LIST_KEY, queryFn: ({ signal }) => listACMEHooks(signal) });
  const close = () => setDialog(null);

  return (
    <Stack gap="md">
      <Notice tone="info" title={t('acme.settings.airGapTitle')}>
        <Text size="sm">{t('acme.settings.airGapText')}</Text>
      </Notice>
      {!canManage && (
        <Notice tone="neutral" title={t('acme.settings.readOnlyTitle')}>
          <Text size="sm">{t('acme.settings.readOnlyText')}</Text>
        </Notice>
      )}

      <section className={settings.subSection} aria-labelledby="acme-providers-title">
        <Group justify="space-between" align="center" mb="sm">
          <Title order={3} className={settings.subTitle} mb={0} id="acme-providers-title">
            {t('acme.settings.providers')}
          </Title>
          {canManage && (
            <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'provider', provider: null })}>
              {t('acme.settings.addProvider')}
            </Button>
          )}
        </Group>
        <Stack gap="md">
          {providers.isPending && <LoadingIndicator />}
          <ErrorAlert error={providers.error} />
          {providers.isSuccess && providers.data.items.length === 0 && (
            <div className={ui.tablePanel}>
              <EmptyState icon="ShieldCheck" title={t('acme.settings.noProviders')} description={t('acme.settings.noProvidersText')} />
            </div>
          )}
          {providers.data && providers.data.items.length > 0 && (
            <div>
              {providers.data.items.map((p) => (
                <ProviderSection
                  key={p.id}
                  provider={p}
                  canManage={canManage}
                  onEdit={() => setDialog({ kind: 'provider', provider: p })}
                  onDelete={() => setDialog({ kind: 'deleteProvider', provider: p })}
                />
              ))}
            </div>
          )}
        </Stack>
      </section>

      <section className={settings.subSection} aria-labelledby="acme-hooks-title">
        <Group justify="space-between" align="center" mb="sm">
          <Title order={3} className={settings.subTitle} mb={0} id="acme-hooks-title">
            {t('acme.settings.hooks')}
          </Title>
          {canManage && (
            <Button variant="default" leftSection={<Icon name="Plus" size={15} />} onClick={() => setDialog({ kind: 'hook', hook: null })}>
              {t('acme.settings.addHook')}
            </Button>
          )}
        </Group>
        <Text size="sm" mb="sm">
          {t('acme.settings.hooksText')}
        </Text>
        <Stack gap="md">
          {hooks.isPending && <LoadingIndicator />}
          <ErrorAlert error={hooks.error} />
          {hooks.isSuccess && hooks.data.items.length === 0 && (
            <div className={ui.tablePanel}>
              <EmptyState icon="Network" title={t('acme.settings.noHooks')} description={t('acme.settings.noHooksText')} />
            </div>
          )}
          {hooks.data && hooks.data.items.length > 0 && (
            <div>
              {hooks.data.items.map((h) => (
                <HookSection
                  key={h.id}
                  hook={h}
                  canManage={canManage}
                  onEdit={() => setDialog({ kind: 'hook', hook: h })}
                  onDelete={() => setDialog({ kind: 'deleteHook', hook: h })}
                />
              ))}
            </div>
          )}
        </Stack>
        <HookHelp />
      </section>

      {dialog?.kind === 'provider' && <ProviderDialog provider={dialog.provider} onClose={close} />}
      {dialog?.kind === 'hook' && <HookDialog hook={dialog.hook} onClose={close} />}
      {dialog?.kind === 'deleteProvider' && (
        <DeleteDialog
          title={t('acme.provider.deleteTitle', { name: dialog.provider.name })}
          text={t('acme.provider.deleteText')}
          confirm={t('acme.provider.deleteConfirm')}
          remove={() => deleteACMEProvider(dialog.provider.id)}
          invalidate={ACME_PROVIDERS_KEY}
          onClose={close}
        />
      )}
      {dialog?.kind === 'deleteHook' && (
        <DeleteDialog
          title={t('acme.hook.deleteTitle', { name: dialog.hook.name })}
          text={t('acme.hook.deleteText')}
          confirm={t('acme.hook.deleteConfirm')}
          remove={() => deleteACMEHook(dialog.hook.id)}
          invalidate={ACME_HOOKS_KEY}
          onClose={close}
        />
      )}
    </Stack>
  );
}

// Names lists an allow-list as code chips, or warns that an empty one allows no certificate at all.
function Names({ suffixes, empty }: { suffixes: string[]; empty: string }) {
  const { t } = useTranslation();
  if (suffixes.length === 0) {
    return (
      <div className={classes.namesLine}>
        <StatusBadge tone="warning" icon="CircleAlert">
          {t('acme.settings.noNames')}
        </StatusBadge>
        <span>{empty}</span>
      </div>
    );
  }
  return (
    <div className={classes.namesLine}>
      <span>{t('acme.settings.allowedNames')}</span>
      <ul className={classes.chips} aria-label={t('acme.settings.allowedNames')}>
        {suffixes.map((s) => (
          <li key={s}>
            <Code translate="no">{s}</Code>
          </li>
        ))}
      </ul>
    </div>
  );
}

interface HeadProps {
  icon: IconName;
  name: string;
  address: string;
  badges: ReactNode;
  canManage: boolean;
  onEdit: () => void;
  onDelete: () => void;
}

// Head is a provider's or a hook's head (the SSO tab's usage-node head): icon tile, name, host, state, actions.
function Head({ icon, name, address, badges, canManage, onEdit, onDelete }: HeadProps) {
  const { t } = useTranslation();
  return (
    <div className={settings.providerHead}>
      <span className={settings.providerIcon}>
        <Icon name={icon} size={16} />
      </span>
      <div className={settings.providerText}>
        <Title order={4} className={settings.providerName}>
          {name}
        </Title>
        <div className={settings.providerIssuer}>
          <Code translate="no">{directoryHost(address)}</Code>
        </div>
      </div>
      {badges}
      {canManage && (
        <div className={settings.providerActions}>
          <Button size="xs" variant="default" onClick={onEdit} aria-label={t('acme.settings.edit', { name })}>
            {t('users.actions.edit')}
          </Button>
          <Button size="xs" variant="default" onClick={onDelete} aria-label={t('acme.settings.delete', { name })}>
            {t('acme.settings.deleteShort')}
          </Button>
        </div>
      )}
    </div>
  );
}

function ProviderSection({ provider: p, canManage, onEdit, onDelete }: { provider: ACMEProvider; canManage: boolean; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation();
  const account = p.active_account_id ? (p.pending_rollover ? 'pending' : 'registered') : 'none';
  return (
    <section aria-label={p.name} className={settings.provider}>
      <Head
        icon="ShieldCheck"
        name={p.name}
        address={p.directory_url}
        canManage={canManage}
        onEdit={onEdit}
        onDelete={onDelete}
        badges={
          <Group gap={6}>
            {(ACME_PRESETS as readonly string[]).includes(p.preset) && (
              <StatusBadge tone="neutral" icon="Building2">
                {t(presetKey(p.preset))}
              </StatusBadge>
            )}
            {account === 'registered' && (
              <StatusBadge tone="success" icon="CircleCheck">
                {t('acme.settings.accountRegistered')}
              </StatusBadge>
            )}
            {account === 'pending' && (
              <StatusBadge tone="warning" icon="CircleAlert">
                {t('acme.settings.accountPending')}
              </StatusBadge>
            )}
            {account === 'none' && (
              <StatusBadge tone="neutral" icon="CircleOff">
                {t('acme.settings.accountNone')}
              </StatusBadge>
            )}
            {p.eab_configured && (
              <StatusBadge tone="info" icon="KeyRound">
                {t('acme.settings.eabConfigured')}
              </StatusBadge>
            )}
          </Group>
        }
      />
      <Names suffixes={p.allowed_suffixes} empty={t('acme.settings.noNamesProvider')} />
      <AccountPanel provider={p} canManage={canManage} />
    </section>
  );
}

function HookSection({ hook: h, canManage, onEdit, onDelete }: { hook: ACMEHook; canManage: boolean; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation();
  return (
    <section aria-label={h.name} className={settings.provider}>
      <Head
        icon="Network"
        name={h.name}
        address={h.url}
        canManage={canManage}
        onEdit={onEdit}
        onDelete={onDelete}
        badges={
          h.secret_configured ? (
            <StatusBadge tone="info" icon="KeyRound">
              {t('acme.settings.secretConfigured')}
            </StatusBadge>
          ) : (
            <StatusBadge tone="warning" icon="CircleAlert">
              {t('acme.settings.secretMissing')}
            </StatusBadge>
          )
        }
      />
      <Names suffixes={h.allowed_suffixes} empty={t('acme.settings.noNamesHook')} />
      <Text size="xs" c="dimmed" mt={6}>
        {t('acme.settings.waits', { wait: h.propagation_wait_seconds, poll: h.poll_timeout_seconds })}
      </Text>
    </section>
  );
}

// HookHelp is the hook's wire contract for whoever writes the hook, collapsed (a native disclosure: keyboard and
// screen readers know it).
function HookHelp() {
  const { t } = useTranslation();
  return (
    <details className={classes.help}>
      <summary>{t('acme.help.title')}</summary>
      <div className={classes.helpBody}>
        <p>{t('acme.help.request')}</p>
        <p>{t('acme.help.body')}</p>
        <p>{t('acme.help.auth')}</p>
        <p>{t('acme.help.answer')}</p>
        <p>{t('acme.help.limits', { wait: HOOK_WAIT_MAX, poll: HOOK_POLL_MAX, total: HOOK_TOTAL_MAX })}</p>
      </div>
    </details>
  );
}

interface DeleteProps {
  title: string;
  text: string;
  confirm: string;
  remove: () => Promise<void>;
  invalidate: readonly string[];
  onClose: () => void;
}

// DeleteDialog asks before a provider or a hook is removed; a refusal (still in use) is shown in the dialog.
function DeleteDialog({ title, text, confirm, remove, invalidate, onClose }: DeleteProps) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const del = useMutation({
    mutationFn: () => run(remove),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: invalidate, predicate: notACMEPreview });
      // The certificates name their provider and hook: a list of Issued certificates reads them again.
      await client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY });
      onClose();
    },
  });
  return (
    <AppModal opened onClose={onClose} title={title}>
      <Stack gap="sm">
        <Text size="sm">{text}</Text>
        <ErrorAlert error={del.error} />
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={del.isPending} onClick={() => del.mutate()}>
            {confirm}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
