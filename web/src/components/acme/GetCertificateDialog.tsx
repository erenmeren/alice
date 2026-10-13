import { Box, Button, Checkbox, CloseButton, Code, Group, Loader, NativeSelect, NumberInput, Radio, Stack, Switch, Text, TextInput, Title, VisuallyHidden } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACME_KEY_TYPES,
  challengeKey,
  createACMECertificate,
  keyTypeKey,
  orderACMECertificate,
  testACMECertificate,
  type ACMECertificate,
  type ACMECertificateCreate,
  type ACMEChallenge,
  type ACMEKeyType,
} from '../../api/acme';
import { ACME_CERTIFICATES_KEY } from '../../api/queryKeys';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { InternalLink } from '../InternalLink';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, FactList, Notice } from '../ui';
import classes from './acme.module.css';
import { dnsLower, isWildcard, nameAllowed, nameProblem, providerProblem, useHooks, useNginxServers, useProviders } from './issued';

const STEPS = ['authority', 'names', 'proof', 'options', 'review'] as const;
type Step = (typeof STEPS)[number];
const MAX_NAMES = 100;

// The three lines the person adds to the Nginx server block for the web proof (docs/nginx-host-preparation.md).
const NGINX_SNIPPET = 'location ^~ /.well-known/acme-challenge/ {\n    root /var/www/alice-acme;\n}';

// GetCertificateDialog is "Get a certificate": an Administrator defines a certificate Alice gets and renews from a
// certificate authority, in four steps (authority, names, proof method, options) and a review. It is a local state
// machine like AddKeyVaultDialog: nothing is sent before the review's button, which needs a fresh step-up (run asks
// for the code; a cancelled code keeps every answer). Saving orders nothing: the done step offers a Test run
// (recommended) or the real order. Websites are connected on the certificate's page once it is issued (the server
// binds a website only to an issued certificate).
export function GetCertificateDialog({ onClose, onOpen }: { onClose: () => void; onOpen: (id: string) => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const providers = useProviders();
  const hooks = useHooks();
  const [step, setStep] = useState<Step>('authority');
  const [providerId, setProviderId] = useState('');
  const [names, setNames] = useState<string[]>([]);
  const [draft, setDraft] = useState('');
  const [draftProblem, setDraftProblem] = useState('');
  const [challenge, setChallenge] = useState<ACMEChallenge>('dns01');
  const [hookId, setHookId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [keyType, setKeyType] = useState<ACMEKeyType>('ecdsa_p256');
  const [renewBefore, setRenewBefore] = useState<number | string>(30);
  const [autoRenew, setAutoRenew] = useState(true);
  const [autoDeploy, setAutoDeploy] = useState(false);
  const [local, setLocal] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [created, setCreated] = useState<ACMECertificate | null>(null);
  const [starting, setStarting] = useState<'test' | 'order' | null>(null);
  const [startError, setStartError] = useState<unknown>(null);
  const servers = useNginxServers(challenge === 'http01');
  const heading = useRef<HTMLHeadingElement>(null);
  const index = STEPS.indexOf(step);

  // Each step's heading takes the focus, so keyboard and screen reader users start reading the new step.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    heading.current?.focus();
  }, [step, created]);

  const provider = providers.data?.items.find((p) => p.id === providerId);
  const hook = hooks.data?.items.find((h) => h.id === hookId);
  const target = servers.data?.items.find((s) => s.id === targetId);
  const wildcard = names.some(isWildcard);
  const notByProvider = provider ? names.filter((n) => !nameAllowed(provider.allowed_suffixes, n)) : [];
  const notByHook = hook && challenge === 'dns01' ? names.filter((n) => !nameAllowed(hook.allowed_suffixes, n)) : [];
  const days = Number(renewBefore);
  const fieldErrors = fieldErrorsOf(error, t, i18n);

  const addDraft = (): string[] | null => {
    if (draft.trim() === '') return names;
    const problem = names.length >= MAX_NAMES ? 'acme.issued.names.tooMany' : nameProblem(draft, names);
    setDraftProblem(problem);
    if (problem) return null;
    const next = [...names, dnsLower(draft.trim())];
    setNames(next);
    setDraft('');
    return next;
  };

  // check answers the problem of the current step (a label key), or ''.
  const check = (s: Step, list = names): string => {
    switch (s) {
      case 'authority':
        if (!provider) return 'acme.issued.wizard.chooseAuthority';
        return providerProblem(provider);
      case 'names':
        return list.length === 0 ? 'acme.issued.wizard.needName' : '';
      case 'proof':
        if (challenge === 'dns01') return hookId ? '' : 'acme.issued.wizard.chooseHook';
        if (list.some(isWildcard)) return 'acme.issued.wizard.wildcardNeedsDns';
        return targetId ? '' : 'acme.issued.wizard.chooseServer';
      case 'options':
        return Number.isInteger(days) && days >= 1 && days <= 60 ? '' : 'acme.issued.wizard.renewRange';
      default:
        return '';
    }
  };

  const next = (e?: FormEvent) => {
    e?.preventDefault();
    if (step === 'review') {
      void save();
      return;
    }
    let list = names;
    if (step === 'names') {
      const r = addDraft();
      if (r === null) return;
      list = r;
    }
    const problem = check(step, list);
    setLocal(problem);
    if (problem) return;
    setStep(STEPS[index + 1]);
  };
  const back = () => {
    setLocal('');
    setStep(STEPS[index - 1]);
  };

  const save = async () => {
    if (saving) return;
    setSaving(true);
    setError(null);
    const body: ACMECertificateCreate = {
      provider_id: providerId,
      names,
      key_type: keyType,
      challenge,
      ...(challenge === 'dns01' ? { hook_id: hookId } : { http_target_id: targetId }),
      renew_before_days: days,
      auto_renew: autoRenew,
      auto_deploy: autoDeploy,
    };
    try {
      const c = await run(() => createACMECertificate(body));
      setCreated(c);
      void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY });
    } catch (err) {
      // The answers stay: a cancelled code or a refusal leaves the review open to correct and send again.
      setError(err);
    }
    setSaving(false);
  };

  const start = async (kind: 'test' | 'order') => {
    if (!created || starting) return;
    setStarting(kind);
    setStartError(null);
    try {
      await (kind === 'test' ? testACMECertificate(created.id) : orderACMECertificate(created.id));
      void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY });
      onOpen(created.id);
    } catch (err) {
      setStartError(err);
      setStarting(null);
    }
  };

  const onNameKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter') return;
    e.preventDefault(); // Enter adds the name; Next moves on
    addDraft();
  };

  const busy = saving || starting !== null;
  const usable = (providers.data?.items ?? []).filter((p) => providerProblem(p) === '');

  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.wizard.title')} size="lg" closeOnClickOutside={!busy} closeOnEscape={!busy}>
      {created ? (
        <Stack gap="md">
          <Title order={2} size="h4" ref={heading} tabIndex={-1} className={classes.stepTitle}>
            {t('acme.issued.wizard.doneTitle')}
          </Title>
          <Notice tone="success" role="status" title={t('acme.issued.wizard.saved')}>
            {t('acme.issued.wizard.savedText')}
          </Notice>
          <Text size="sm">{t('acme.issued.wizard.testHelp')}</Text>
          <ErrorAlert error={startError} />
          <DialogActions>
            <Button variant="default" disabled={busy} onClick={() => onOpen(created.id)}>
              {t('acme.issued.wizard.later')}
            </Button>
            <Button variant="default" loading={starting === 'order'} disabled={busy} onClick={() => void start('order')}>
              {t('acme.issued.getNow')}
            </Button>
            <Button leftSection={<Icon name="CirclePlay" size={15} />} loading={starting === 'test'} disabled={busy} onClick={() => void start('test')}>
              {t('acme.issued.wizard.testFirst')}
            </Button>
          </DialogActions>
        </Stack>
      ) : (
        <form onSubmit={next} autoComplete="off" noValidate>
          <Stack gap="md">
            <ol className={classes.rail} aria-label={t('acme.issued.wizard.steps')}>
              {STEPS.map((s, i) => {
                const state = i < index ? 'done' : i === index ? 'current' : 'next';
                return (
                  <li key={s} className={classes.railItem} data-state={state} aria-current={state === 'current' ? 'step' : undefined}>
                    <span className={classes.railNumber} aria-hidden="true">
                      {state === 'done' ? <Icon name="Check" size={12} /> : i + 1}
                    </span>
                    <span>{t(`acme.issued.wizard.step.${s}`)}</span>
                    {state === 'done' && <VisuallyHidden>{t('acme.issued.wizard.stepDone')}</VisuallyHidden>}
                  </li>
                );
              })}
            </ol>
            <Title order={2} size="h4" ref={heading} tabIndex={-1} className={classes.stepTitle}>
              {t(`acme.issued.wizard.heading.${step}`)}
            </Title>

            {step === 'authority' && (
              <Stack gap="sm">
                <Text size="sm">{t('acme.issued.wizard.authorityHelp')}</Text>
                {providers.isPending && <LoadingIndicator />}
                <ErrorAlert error={providers.error} />
                {providers.isSuccess && usable.length === 0 && (
                  <Notice tone="warning" title={t('acme.issued.wizard.noAuthorityTitle')}>
                    <Text size="sm">
                      {t('acme.issued.wizard.noAuthorityText')} <InternalLink to="/settings?tab=acme">{t('acme.issued.settingsLink')}</InternalLink>
                    </Text>
                  </Notice>
                )}
                {(providers.data?.items ?? []).length > 0 && (
                  <Radio.Group value={providerId} onChange={setProviderId} label={t('acme.issued.wizard.authority')} error={local && step === 'authority' ? t(local) : undefined}>
                    <Stack gap="xs" mt="xs">
                      {(providers.data?.items ?? []).map((p) => {
                        const why = providerProblem(p);
                        return (
                          <Box key={p.id}>
                            <Radio value={p.id} disabled={why !== ''} label={<span translate="no">{p.name}</span>} description={
                              why ? (
                                t(why)
                              ) : (
                                <>
                                  {t('acme.issued.wizard.allowedList')} <span translate="no">{p.allowed_suffixes.join(', ')}</span>
                                </>
                              )
                            } />
                          </Box>
                        );
                      })}
                    </Stack>
                  </Radio.Group>
                )}
              </Stack>
            )}

            {step === 'names' && (
              <Stack gap="sm">
                <Text size="sm">{t('acme.issued.wizard.namesHelp')}</Text>
                <div className={classes.addRow}>
                  <TextInput
                    label={t('acme.issued.wizard.name')}
                    description={t('acme.issued.wizard.nameHelp')}
                    value={draft}
                    onChange={(e) => {
                      setDraft(e.currentTarget.value);
                      if (draftProblem) setDraftProblem('');
                    }}
                    onKeyDown={onNameKey}
                    error={draftProblem ? t(draftProblem) : fieldErrors.names}
                    spellCheck={false}
                    maxLength={253}
                    data-autofocus
                  />
                  <Button variant="default" disabled={draft.trim() === ''} onClick={() => addDraft()}>
                    {t('acme.suffix.add')}
                  </Button>
                </div>
                {names.length > 0 && (
                  <ul className={classes.chips} aria-label={t('acme.issued.wizard.namesList')}>
                    {names.map((n) => (
                      <li key={n} className={classes.chip}>
                        <span className={classes.chipText} translate="no">
                          {n}
                        </span>
                        <CloseButton size="sm" aria-label={t('acme.suffix.remove', { name: n })} onClick={() => setNames(names.filter((x) => x !== n))} />
                      </li>
                    ))}
                  </ul>
                )}
                {wildcard && <Notice tone="info" title={t('acme.issued.wizard.wildcardHint')} />}
                {notByProvider.length > 0 && provider && (
                  <Notice tone="warning" title={t('acme.issued.wizard.notAllowedTitle')} testId="names-not-allowed">
                    <Text size="sm">{t('acme.issued.wizard.notAllowedProvider', { authority: provider.name })}</Text>
                    <NameList names={notByProvider} />
                  </Notice>
                )}
                {local && step === 'names' && (
                  <Text size="sm" c="var(--alice-danger)" role="alert">
                    {t(local)}
                  </Text>
                )}
              </Stack>
            )}

            {step === 'proof' && (
              <Stack gap="sm">
                <Radio.Group value={challenge} onChange={(v) => setChallenge(v as ACMEChallenge)} label={t('acme.issued.wizard.proof')}>
                  <Stack gap="xs" mt="xs">
                    <Radio value="dns01" label={t(challengeKey('dns01'))} description={t('acme.issued.wizard.dnsHelp')} />
                    <Radio value="http01" label={t(challengeKey('http01'))} description={wildcard ? t('acme.issued.wizard.wildcardNeedsDns') : t('acme.issued.wizard.httpHelp')} disabled={wildcard} />
                  </Stack>
                </Radio.Group>
                {challenge === 'dns01' && (
                  <>
                    {hooks.isPending && <LoadingIndicator />}
                    <ErrorAlert error={hooks.error} />
                    {hooks.isSuccess && hooks.data.items.length === 0 && (
                      <Notice tone="warning" title={t('acme.issued.wizard.noHookTitle')}>
                        <Text size="sm">
                          {t('acme.issued.wizard.noHookText')} <InternalLink to="/settings?tab=acme">{t('acme.issued.settingsLink')}</InternalLink>
                        </Text>
                      </Notice>
                    )}
                    {(hooks.data?.items ?? []).length > 0 && (
                      <NativeSelect
                        label={t('acme.issued.wizard.hook')}
                        value={hookId}
                        onChange={(e) => setHookId(e.currentTarget.value)}
                        error={local === 'acme.issued.wizard.chooseHook' ? t(local) : fieldErrors.hook_id}
                        data={[{ value: '', label: t('acme.issued.wizard.chooseHookOption') }, ...(hooks.data?.items ?? []).map((h) => ({ value: h.id, label: h.name }))]}
                      />
                    )}
                    {notByHook.length > 0 && hook && (
                      <Notice tone="warning" title={t('acme.issued.wizard.notAllowedTitle')} testId="names-not-allowed-hook">
                        <Text size="sm">{t('acme.issued.wizard.notAllowedHook', { hook: hook.name })}</Text>
                        <NameList names={notByHook} />
                      </Notice>
                    )}
                  </>
                )}
                {challenge === 'http01' && (
                  <>
                    {servers.isPending && <LoadingIndicator />}
                    <ErrorAlert error={servers.error} />
                    {servers.isSuccess && servers.data.items.length === 0 && <Notice tone="warning" title={t('acme.issued.wizard.noServer')} />}
                    {(servers.data?.items ?? []).length > 0 && (
                      <NativeSelect
                        label={t('acme.issued.wizard.server')}
                        description={t('acme.issued.wizard.serverHelp')}
                        value={targetId}
                        onChange={(e) => setTargetId(e.currentTarget.value)}
                        error={local === 'acme.issued.wizard.chooseServer' ? t(local) : fieldErrors.http_target_id}
                        data={[{ value: '', label: t('acme.issued.wizard.chooseServerOption') }, ...(servers.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
                      />
                    )}
                    <details className={classes.help}>
                      <summary>{t('acme.issued.wizard.prepareTitle')}</summary>
                      <div className={classes.helpBody}>
                        <p>{t('acme.issued.wizard.prepareText')}</p>
                        <Code block translate="no">
                          {NGINX_SNIPPET}
                        </Code>
                        <p>{t('acme.issued.wizard.prepareDoc')}</p>
                        <p>{t('acme.issued.wizard.helperHint')}</p>
                      </div>
                    </details>
                  </>
                )}
                {local === 'acme.issued.wizard.wildcardNeedsDns' && (
                  <Text size="sm" c="var(--alice-danger)" role="alert">
                    {t(local)}
                  </Text>
                )}
              </Stack>
            )}

            {step === 'options' && (
              <Stack gap="sm">
                <NativeSelect
                  label={t('acme.issued.wizard.keyType')}
                  description={t('acme.issued.wizard.keyTypeHelp')}
                  value={keyType}
                  onChange={(e) => setKeyType(e.currentTarget.value as ACMEKeyType)}
                  data={ACME_KEY_TYPES.map((k) => ({ value: k, label: t(keyTypeKey(k)) }))}
                />
                <NumberInput
                  label={t('acme.issued.wizard.renewBefore')}
                  description={t('acme.issued.wizard.renewBeforeHelp')}
                  value={renewBefore}
                  onChange={setRenewBefore}
                  min={1}
                  max={60}
                  allowDecimal={false}
                  error={local === 'acme.issued.wizard.renewRange' ? t(local) : fieldErrors.renew_before_days}
                />
                <Switch checked={autoRenew} onChange={(e) => setAutoRenew(e.currentTarget.checked)} label={t('acme.issued.wizard.autoRenew')} description={t('acme.issued.wizard.autoRenewHelp')} />
                <Checkbox checked={autoDeploy} onChange={(e) => setAutoDeploy(e.currentTarget.checked)} label={t('acme.issued.wizard.autoDeploy')} description={t('acme.issued.wizard.autoDeployHelp')} />
                <Notice tone="neutral" title={t('acme.issued.wizard.websitesLater')} />
              </Stack>
            )}

            {step === 'review' && (
              <Stack gap="sm">
                <FactList
                  label={t('acme.issued.wizard.heading.review')}
                  facts={[
                    { key: 'authority', label: t('acme.issued.wizard.step.authority'), value: <span translate="no">{provider?.name ?? ''}</span> },
                    { key: 'names', label: t('acme.issued.wizard.step.names'), value: <NameList names={names} /> },
                    {
                      key: 'proof',
                      label: t('acme.issued.wizard.step.proof'),
                      value: (
                        <span>
                          {t(challengeKey(challenge))}: <span translate="no">{challenge === 'dns01' ? (hook?.name ?? '') : (target?.name ?? '')}</span>
                        </span>
                      ),
                    },
                    { key: 'key', label: t('acme.issued.wizard.keyType'), value: t(keyTypeKey(keyType)) },
                    { key: 'renew', label: t('acme.issued.wizard.renewBefore'), value: t('acme.issued.renewal.beforeExpiry', { count: days }) },
                    { key: 'autoRenew', label: t('acme.issued.wizard.autoRenew'), value: t(autoRenew ? 'acme.issued.on' : 'acme.issued.off') },
                    { key: 'autoDeploy', label: t('acme.issued.wizard.autoDeploy'), value: t(autoDeploy ? 'acme.issued.on' : 'acme.issued.off') },
                  ]}
                />
                <Text size="sm">{t('acme.issued.wizard.reviewHelp')}</Text>
                <ErrorAlert error={error} />
              </Stack>
            )}

            <DialogActions note={t('acme.issued.wizard.counter', { n: index + 1, total: STEPS.length })}>
              <Button variant="default" disabled={saving} onClick={onClose}>
                {t('ui.cancel')}
              </Button>
              {index > 0 && (
                <Button variant="default" disabled={saving} leftSection={<Icon name="ArrowLeft" size={15} />} onClick={back}>
                  {t('acme.issued.wizard.back')}
                </Button>
              )}
              {step !== 'review' ? (
                <Button type="submit" rightSection={<Icon name="ArrowRight" size={15} />}>
                  {t('acme.issued.wizard.next')}
                </Button>
              ) : (
                <Button loading={saving} leftSection={<Icon name="ShieldCheck" size={15} />} onClick={() => void save()}>
                  {t('acme.issued.wizard.save')}
                </Button>
              )}
            </DialogActions>
            {saving && (
              <Group gap="xs" role="status">
                <Loader size="xs" aria-hidden />
                <Text size="sm">{t('acme.issued.wizard.saving')}</Text>
              </Group>
            )}
          </Stack>
        </form>
      )}
    </AppModal>
  );
}

function NameList({ names }: { names: string[] }) {
  return (
    <ul className={classes.chips}>
      {names.map((n) => (
        <li key={n} className={classes.chip}>
          <span className={classes.chipText} translate="no">
            {n}
          </span>
        </li>
      ))}
    </ul>
  );
}

