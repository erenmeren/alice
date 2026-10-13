import { Anchor, Button, Checkbox, Group, Loader, Stack, Text, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  accountStateKey,
  deactivateACMEAccount,
  directoryHost,
  getACMEProvider,
  listACMECertificates,
  previewACMEProvider,
  recoverACMERollover,
  registerACMEAccount,
  rolloverACMEAccount,
  type ACMEAccount,
  type ACMEAccountRegister,
  type ACMEProvider,
} from '../../api/acme';
import { isApiError } from '../../api/client';
import { ACME_CERTIFICATES_KEY, ACME_PROVIDERS_KEY, acmeCertificateListKey, acmePreviewKey, acmeProviderKey, notACMEPreview } from '../../api/queryKeys';
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
  const tos = account?.tos_url ? httpsLink(account.tos_url) : null;

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

// useAccountAction runs one account operation through the step-up and refreshes the providers and the ACME
// certificates afterwards (also after a refusal: an unsettled key change shows on the provider). The registration
// form's directory preview is left alone: it contacts the CA.
function useAccountAction<V = void>(fn: (v: V) => Promise<ACMEAccount>) {
  const { run } = useStepUp();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (v: V) => run(() => fn(v)),
    onSettled: async () => {
      await client.invalidateQueries({ queryKey: ACME_PROVIDERS_KEY, predicate: notACMEPreview });
      await client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY });
    },
  });
}

// CheckKeyChange asks the authority which account key it knows, to settle a key change whose answer did not arrive.
function CheckKeyChange({ account, onSettled }: { account: ACMEAccount; onSettled?: () => void }) {
  const { t } = useTranslation();
  const check = useAccountAction(() => recoverACMERollover(account.id));
  return (
    <>
      <Button
        size="xs"
        variant="default"
        leftSection={<Icon name="RefreshCw" size={14} />}
        loading={check.isPending}
        onClick={() => check.mutate(undefined, { onSuccess: () => onSettled?.() })}
      >
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

// WithData writes a translated sentence with a technical value (a host name) where the language puts the placeholder,
// the value marked translate="no" (as ErrorAlert's code line does): the sentence stays the translator's.
const MARK = '\u0000';
function WithData({ text, value }: { text: string; value: string }) {
  const [before, after = ''] = text.split(MARK);
  return (
    <>
      {before}
      <span translate="no">{value}</span>
      {after}
    </>
  );
}

// httpsLink is an address that may be linked as the terms: https only (safeTarget also lets http through on an http
// page, for development), which the server checks too.
function httpsLink(url: string): string | null {
  const target = safeTarget(url);
  return target?.startsWith('https:') ? target : null;
}

// TERMS_CHANGED: the registration was refused because the CA's terms are no longer the ones shown (ALC-ACM-0003).
const TERMS_CHANGED = 'acme.terms_not_accepted';

// RegisterDialog reads the CA's directory once when it opens (the preview: an Administrator, no step-up) and shows its
// terms of service as a link BEFORE the box can be ticked. The box stays disabled until the preview has answered; no
// terms: no box, the registration goes without; terms at an unsafe address or a failed preview: no registration. The
// registration names the terms shown (accepted_terms_url): when the CA changed them meanwhile it is refused, the
// preview runs again and the new terms are shown.
function RegisterDialog({ provider, onClose }: { provider: ACMEProvider; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [email, setEmail] = useState('');
  const [tos, setTos] = useState(false);
  const [termsChanged, setTermsChanged] = useState(false);
  const preview = useQuery({
    queryKey: acmePreviewKey(provider.id),
    queryFn: ({ signal }) => previewACMEProvider(provider.id, signal),
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const register = useAccountAction((body: ACMEAccountRegister) => registerACMEAccount(provider.id, body));
  const fieldErrors = fieldErrorsOf(register.error, t, i18n);
  const info = preview.isSuccess && !preview.isFetching ? preview.data : null;
  const termsLink = info?.terms_of_service_url ? httpsLink(info.terms_of_service_url) : null;
  const unsafe = info !== null && (info.terms_url_unsafe || (info.terms_of_service_url !== '' && termsLink === null));
  const hasTerms = termsLink !== null && !unsafe;
  const ready = info !== null && !unsafe && (!hasTerms || tos);
  const host = directoryHost(provider.directory_url);

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (register.isPending || !ready || !info) return;
    setTermsChanged(false);
    const body: ACMEAccountRegister = { ...(email.trim() ? { contact_email: email.trim() } : {}), tos_accepted: hasTerms && tos };
    if (hasTerms) body.accepted_terms_url = info.terms_of_service_url;
    register.mutate(body, {
      onError: (e) => {
        if (!isApiError(e, TERMS_CHANGED)) return;
        // The terms are not the ones shown any more: read them again and ask for the consent again.
        setTermsChanged(true);
        setTos(false);
        void preview.refetch();
      },
    });
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
          {preview.isFetching && (
            <Group gap="xs" role="status">
              <Loader size="xs" aria-hidden />
              <Text size="sm">
                <WithData text={t('acme.register.contacting', { host: MARK })} value={host} />
              </Text>
            </Group>
          )}
          {preview.isError && !preview.isFetching && (
            <>
              <Text size="sm">{t('acme.register.previewFailed')}</Text>
              <ErrorAlert error={preview.error} />
              <Group>
                <Button size="xs" variant="default" leftSection={<Icon name="RefreshCw" size={14} />} onClick={() => void preview.refetch()}>
                  {t('acme.register.retry')}
                </Button>
              </Group>
            </>
          )}
          {termsChanged && (
            <Notice tone="warning" title={t('acme.register.termsChangedTitle')} role="alert">
              <Text size="sm">{t('acme.register.termsChangedText')}</Text>
            </Notice>
          )}
          {info?.external_account_required && !provider.eab_configured && (
            <Notice tone="warning" title={t('acme.register.eabRequiredTitle')}>
              <Text size="sm">{t('acme.register.eabRequiredText')}</Text>
            </Notice>
          )}
          {unsafe && (
            <Notice tone="danger" title={t('acme.register.unsafeTitle')}>
              <Text size="sm">{t('acme.register.unsafeText')}</Text>
              {info?.terms_of_service_url && (
                <Text size="sm" translate="no">
                  {info.terms_of_service_url}
                </Text>
              )}
            </Notice>
          )}
          {/* The box exists while the answer is awaited (disabled), and with terms: never without the link above it. */}
          {(info === null || hasTerms) && !unsafe && (
            <Stack gap={4}>
              {hasTerms && termsLink && (
                <Text size="sm">
                  {t('acme.register.termsAt')}{' '}
                  <Anchor href={termsLink} target="_blank" rel="noopener noreferrer" translate="no">
                    {info?.terms_of_service_url} <Icon name="ExternalLink" size={12} />
                  </Anchor>
                </Text>
              )}
              <Checkbox
                label={t('acme.register.tos')}
                description={t('acme.register.tosHelp')}
                checked={tos}
                disabled={!hasTerms}
                onChange={(e) => setTos(e.currentTarget.checked)}
              />
            </Stack>
          )}
          {info !== null && !hasTerms && !unsafe && <Text size="sm">{t('acme.register.noTerms')}</Text>}
          {!isApiError(register.error, TERMS_CHANGED) && <ErrorAlert error={register.error} />}
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={register.isPending} disabled={!ready}>
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
  // settled: Check key change answered; the earlier ALC-ACM-0024 refusal no longer applies and is hidden.
  const [settled, setSettled] = useState(false);
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
        {settled && !rollover.isSuccess && !rollover.error && (
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('acme.account.checked')}
          </Text>
        )}
        <ErrorAlert error={rollover.error} />
        {isApiError(rollover.error, ROLLOVER_PENDING) && (
          <CheckKeyChange
            account={account}
            onSettled={() => {
              setSettled(true);
              rollover.reset();
            }}
          />
        )}
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
              <Button
                loading={rollover.isPending}
                onClick={() => {
                  setSettled(false);
                  rollover.mutate();
                }}
              >
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
