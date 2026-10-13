import { Anchor, Button, Checkbox, Stack, Text, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  accountStateKey,
  deactivateACMEAccount,
  getACMEProvider,
  listACMECertificates,
  recoverACMERollover,
  registerACMEAccount,
  rolloverACMEAccount,
  type ACMEAccount,
  type ACMEProvider,
} from '../../api/acme';
import { isApiError } from '../../api/client';
import { ACME_PROVIDERS_KEY, acmeCertificateListKey, acmeProviderKey } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { safeTarget } from '../../navigation';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, FactList, Notice, StatusBadge, type Tone } from '../ui';
import type { IconName } from '../../design/Icon';
import classes from './acme.module.css';

const STATE_TONE: Record<string, { tone: Tone; icon: IconName }> = {
  active: { tone: 'success', icon: 'CircleCheck' },
  pending_rollover: { tone: 'warning', icon: 'CircleAlert' },
  retired: { tone: 'neutral', icon: 'CircleOff' },
  deactivated: { tone: 'neutral', icon: 'CircleOff' },
};

// A rollover whose outcome Alice did not learn, or another account operation still running (ALC-ACM-0024).
const ROLLOVER_PENDING = 'acme.rollover_pending';

// currentAccount is the account the panel shows: the active one (or the one whose key change is unsettled), else the
// newest, which is retired or deactivated.
function currentAccount(accounts: ACMEAccount[]): ACMEAccount | null {
  return accounts.find((a) => a.state === 'active' || a.state === 'pending_rollover') ?? accounts[0] ?? null;
}

// AccountPanel is a certificate authority's account: its state, contact and accepted terms, and, for an
// Administrator, Register account (the first contact with the authority), Rotate account key, Check key change and
// Deactivate account. Every action needs a fresh step-up (useStepUp().run).
export function AccountPanel({ provider, canManage }: { provider: ACMEProvider; canManage: boolean }) {
  const { t, i18n } = useTranslation();
  const detail = useQuery({ queryKey: acmeProviderKey(provider.id), queryFn: ({ signal }) => getACMEProvider(provider.id, signal) });
  const [dialog, setDialog] = useState<'register' | 'rollover' | 'deactivate' | null>(null);
  const account = currentAccount(detail.data?.accounts ?? []);
  const live = account !== null && (account.state === 'active' || account.state === 'pending_rollover');
  const pending = provider.pending_rollover || account?.state === 'pending_rollover';
  const tos = account?.tos_url ? safeTarget(account.tos_url) : null;

  return (
    <section className={classes.account} aria-label={t('acme.account.regionLabel', { name: provider.name })}>
      <Title order={5} className={classes.accountTitle}>
        {t('acme.account.title')}
      </Title>
      {detail.isPending && <LoadingIndicator />}
      <ErrorAlert error={detail.error} />
      {detail.isSuccess && account === null && <Text size="sm">{t('acme.account.none')}</Text>}
      {account && (
        <FactList
          facts={[
            {
              label: t('acme.account.state'),
              value: (
                <StatusBadge tone={STATE_TONE[account.state]?.tone ?? 'neutral'} icon={STATE_TONE[account.state]?.icon}>
                  {t(accountStateKey(account.state))}
                </StatusBadge>
              ),
            },
            { label: t('acme.account.contact'), value: account.contact_email || t('acme.account.noContact') },
            {
              label: t('acme.account.terms'),
              value: account.tos_url ? (
                tos ? (
                  <Anchor href={tos} target="_blank" rel="noopener noreferrer">
                    {t('acme.account.termsLink')} <Icon name="ExternalLink" size={12} />
                  </Anchor>
                ) : (
                  <span translate="no">{account.tos_url}</span>
                )
              ) : (
                t('acme.account.noTerms')
              ),
            },
            {
              label: t('acme.account.termsAccepted'),
              value: account.tos_accepted_at ? formatDateTime(account.tos_accepted_at, i18n.language) : t('acme.account.termsNotNeeded'),
            },
            { label: t('acme.account.registered'), value: formatDateTime(account.created_at, i18n.language) },
          ]}
        />
      )}
      {pending && (
        <Notice tone="warning" title={t('errors.acme.rollover_pending.title', { ns: 'common' })}>
          <Text size="sm">{t('acme.account.pendingText')}</Text>
        </Notice>
      )}
      {canManage && detail.isSuccess && (
        <div className={classes.accountActions}>
          {!live && (
            <Button size="xs" leftSection={<Icon name="Plus" size={14} />} onClick={() => setDialog('register')}>
              {t('acme.account.register')}
            </Button>
          )}
          {pending && account && <CheckKeyChange account={account} />}
          {account?.state === 'active' && !pending && (
            <>
              <Button size="xs" variant="default" leftSection={<Icon name="RotateCw" size={14} />} onClick={() => setDialog('rollover')}>
                {t('acme.account.rollover')}
              </Button>
              <Button size="xs" variant="default" color="red" onClick={() => setDialog('deactivate')}>
                {t('acme.account.deactivate')}
              </Button>
            </>
          )}
        </div>
      )}
      {dialog === 'register' && <RegisterDialog provider={provider} onClose={() => setDialog(null)} />}
      {dialog === 'rollover' && account && <RolloverDialog provider={provider} account={account} onClose={() => setDialog(null)} />}
      {dialog === 'deactivate' && account && <DeactivateDialog provider={provider} account={account} onClose={() => setDialog(null)} />}
    </section>
  );
}

// useAccountAction runs one account operation through the step-up and refreshes the providers afterwards (also after
// a refusal: an unsettled key change shows on the provider).
function useAccountAction(fn: () => Promise<ACMEAccount>) {
  const { run } = useStepUp();
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => run(fn),
    onSettled: () => client.invalidateQueries({ queryKey: ACME_PROVIDERS_KEY }),
  });
}

// CheckKeyChange asks the authority which account key it knows, to settle a key change whose answer did not arrive.
function CheckKeyChange({ account }: { account: ACMEAccount }) {
  const { t } = useTranslation();
  const check = useAccountAction(() => recoverACMERollover(account.id));
  return (
    <>
      <Button size="xs" variant="default" leftSection={<Icon name="RefreshCw" size={14} />} loading={check.isPending} onClick={() => check.mutate()}>
        {t('acme.account.checkKeyChange')}
      </Button>
      {check.isSuccess && (
        <Text role="status" size="sm" c="var(--alice-success)">
          {t('acme.account.checked')}
        </Text>
      )}
      <ErrorAlert error={check.error} />
    </>
  );
}

function RegisterDialog({ provider, onClose }: { provider: ACMEProvider; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [email, setEmail] = useState('');
  const [tos, setTos] = useState(false);
  const register = useAccountAction(() => registerACMEAccount(provider.id, { ...(email.trim() ? { contact_email: email.trim() } : {}), tos_accepted: tos }));
  const fieldErrors = fieldErrorsOf(register.error, t, i18n);
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    register.mutate();
  };
  const title = t('acme.register.title', { name: provider.name });
  if (register.isSuccess) {
    return (
      <AppModal opened onClose={onClose} title={title}>
        <Stack gap="sm">
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('acme.register.done')}
          </Text>
          <DialogActions>
            <Button onClick={onClose} data-autofocus>
              {t('ui.continue')}
            </Button>
          </DialogActions>
        </Stack>
      </AppModal>
    );
  }
  return (
    <AppModal opened onClose={onClose} title={title}>
      <form onSubmit={submit} noValidate>
        <Stack gap="sm">
          <Text size="sm">{t('acme.register.intro')}</Text>
          <TextInput
            label={t('acme.register.email')}
            description={t('acme.register.emailHelp')}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.currentTarget.value)}
            error={fieldErrors.contact_email}
            autoComplete="email"
            data-autofocus
          />
          <Checkbox label={t('acme.register.tos')} description={t('acme.register.tosHelp')} checked={tos} onChange={(e) => setTos(e.currentTarget.checked)} />
          <ErrorAlert error={register.error} />
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={register.isPending}>
              {t('acme.register.submit')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}

function RolloverDialog({ provider, account, onClose }: { provider: ACMEProvider; account: ACMEAccount; onClose: () => void }) {
  const { t } = useTranslation();
  const rollover = useAccountAction(() => rolloverACMEAccount(account.id));
  const title = t('acme.rollover.title', { name: provider.name });
  return (
    <AppModal opened onClose={onClose} title={title}>
      <Stack gap="sm">
        {rollover.isSuccess ? (
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('acme.rollover.done')}
          </Text>
        ) : (
          <Text size="sm">{t('acme.rollover.text')}</Text>
        )}
        <ErrorAlert error={rollover.error} />
        {isApiError(rollover.error, ROLLOVER_PENDING) && <CheckKeyChange account={account} />}
        <DialogActions>
          {rollover.isSuccess ? (
            <Button onClick={onClose} data-autofocus>
              {t('ui.continue')}
            </Button>
          ) : (
            <>
              <Button variant="default" onClick={onClose}>
                {t('ui.cancel')}
              </Button>
              <Button loading={rollover.isPending} onClick={() => rollover.mutate()}>
                {t('acme.rollover.confirm')}
              </Button>
            </>
          )}
        </DialogActions>
      </Stack>
    </AppModal>
  );
}

// DeactivateDialog names how many certificates of this authority stop renewing before anything is sent (if that list
// cannot be read, the refusal is shown and the deactivation stays possible).
function DeactivateDialog({ provider, account, onClose }: { provider: ACMEProvider; account: ACMEAccount; onClose: () => void }) {
  const { t } = useTranslation();
  const filters = { provider_id: provider.id, limit: 200 };
  const affected = useQuery({ queryKey: acmeCertificateListKey(filters), queryFn: ({ signal }) => listACMECertificates(filters, signal) });
  const deactivate = useAccountAction(() => deactivateACMEAccount(account.id));
  const count = affected.data?.items.length ?? 0;
  const more = affected.data?.next_cursor != null;
  return (
    <AppModal opened onClose={onClose} title={t('acme.deactivate.title', { name: provider.name })}>
      <Stack gap="sm">
        {deactivate.isSuccess ? (
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('acme.deactivate.done')}
          </Text>
        ) : (
          <>
            <Text size="sm">{t('acme.deactivate.text')}</Text>
            {affected.isPending && <LoadingIndicator />}
            <ErrorAlert error={affected.error} />
            {affected.isSuccess && (
              <Notice tone={count > 0 ? 'warning' : 'neutral'} title={more ? t('acme.deactivate.affectedMore', { count }) : t('acme.deactivate.affected', { count })}>
                {count > 0 && <Text size="sm">{t('acme.deactivate.affectedText')}</Text>}
              </Notice>
            )}
          </>
        )}
        <ErrorAlert error={deactivate.error} />
        <DialogActions>
          {deactivate.isSuccess ? (
            <Button onClick={onClose} data-autofocus>
              {t('ui.continue')}
            </Button>
          ) : (
            <>
              <Button variant="default" onClick={onClose}>
                {t('ui.cancel')}
              </Button>
              <Button color="red" loading={deactivate.isPending} disabled={affected.isPending} onClick={() => deactivate.mutate()}>
                {t('acme.deactivate.confirm')}
              </Button>
            </>
          )}
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
