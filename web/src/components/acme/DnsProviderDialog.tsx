import { Button, Group, NativeSelect, NumberInput, PasswordInput, Stack, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACME_DNS_PROVIDER_KINDS,
  AWS_SECRET_MAX,
  AWS_SECRET_MIN,
  AZURE_DNS_AUTHS,
  DNS_TOKEN_MAX,
  DNS_TOKEN_MIN,
  HOOK_POLL_MAX,
  HOOK_POLL_MIN,
  HOOK_TOTAL_MAX,
  HOOK_WAIT_MAX,
  azureAuthKey,
  createACMEHook,
  hookKindKey,
  updateACMEHook,
  type ACMEDNSProviderFields,
  type ACMEDNSProviderKind,
  type ACMEHook,
  type AzureDNSAuth,
} from '../../api/acme';
import { ACME_HOOKS_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';
import { SuffixInput, takeDraft } from './SuffixInput';

// The typed credentials of one save: read by the request through a ref that it empties at once, never a mutation
// variable (no cache holds them), never read back (the server answers secret_configured).
interface Credentials {
  api_token: string;
  client_secret: string;
  certificate_pem: string;
  private_key_pem: string;
  secret_access_key: string;
}

const noCredentials: Credentials = { api_token: '', client_secret: '', certificate_pem: '', private_key_pem: '', secret_access_key: '' };

interface Sent {
  suffixes: string[];
  wait: number;
  poll: number;
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ACCESS_KEY = /^[A-Z0-9]{16,128}$/;
const ROLE_ARN = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const RESOURCE_GROUP = /^[-\w._()]{1,90}$/;
const PRINTABLE = /^[\x21-\x7e]+$/;

const asNumber = (v: number | string) => (typeof v === 'number' ? v : v.trim() === '' ? NaN : Number(v));

// DnsProviderDialog adds or changes a built-in DNS provider (R57): Cloudflare (an API token), Azure DNS (a service
// principal with a client secret or a certificate, or Alice's managed identity; the subscription and resource group of
// the zones) or Amazon Route 53 (an access key, optionally a role to assume). The kind is chosen when it is added and
// never changes. Credentials live in this form's state only, as the hook's secret does (HookDialog), and an empty
// credential field on a change keeps what is stored; the server asks for them again when the Azure sign-in method or
// the AWS access key changes. Saving contacts no one: the provider is first called when a certificate is ordered.
export function DnsProviderDialog({ hook, onClose }: { hook: ACMEHook | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const st = hook?.settings;
  const [kind, setKind] = useState<ACMEDNSProviderKind>(hook && hook.kind !== 'webhook' ? hook.kind : 'cloudflare');
  const [name, setName] = useState(hook?.name ?? '');
  const [auth, setAuth] = useState<AzureDNSAuth>((AZURE_DNS_AUTHS as readonly string[]).includes(st?.auth ?? '') ? (st?.auth as AzureDNSAuth) : 'client_secret');
  const [tenant, setTenant] = useState(st?.tenant_id ?? '');
  const [clientId, setClientId] = useState(st?.client_id ?? '');
  const [subscription, setSubscription] = useState(st?.subscription_id ?? '');
  const [group, setGroup] = useState(st?.resource_group ?? '');
  const [accessKey, setAccessKey] = useState(st?.access_key_id ?? '');
  const [role, setRole] = useState(st?.role_arn ?? '');
  const [external, setExternal] = useState(st?.external_id ?? '');
  const [cred, setCred] = useState<Credentials>(noCredentials);
  const [wait, setWait] = useState<number | string>(hook?.propagation_wait_seconds ?? 5);
  const [poll, setPoll] = useState<number | string>(hook?.poll_timeout_seconds ?? 60);
  const [suffixes, setSuffixes] = useState<string[]>(hook?.allowed_suffixes ?? []);
  const [draft, setDraft] = useState('');
  const [draftProblem, setDraftProblem] = useState('');
  const [local, setLocal] = useState<Record<string, string>>({});
  const outgoing = useRef<Credentials>(noCredentials);
  const setCredField = (field: keyof Credentials, value: string) => setCred((c) => ({ ...c, [field]: value }));

  // The settings of the kind as they would be stored (a managed identity has no tenant).
  const settingsOf = (): ACMEDNSProviderFields => {
    if (kind === 'azure_dns') {
      return { auth, tenant_id: auth === 'managed_identity' ? '' : tenant.trim(), client_id: clientId.trim(), subscription_id: subscription.trim(), resource_group: group.trim() };
    }
    if (kind === 'route53') return { access_key_id: accessKey.trim(), role_arn: role.trim(), external_id: role.trim() ? external.trim() : '' };
    return {};
  };
  const settingsChanged = (s: ACMEDNSProviderFields) =>
    hook !== null && (Object.keys(s) as (keyof ACMEDNSProviderFields)[]).some((k) => (s[k] ?? '') !== ((hook.settings as unknown as Record<string, string>)[k] ?? ''));
  // The credentials the kind and sign-in method use: the others are never sent.
  const credentialsOf = (c: Credentials): ACMEDNSProviderFields => {
    const out: ACMEDNSProviderFields = {};
    if (kind === 'cloudflare' && c.api_token) out.api_token = c.api_token;
    if (kind === 'azure_dns' && auth === 'client_secret' && c.client_secret) out.client_secret = c.client_secret;
    if (kind === 'azure_dns' && auth === 'certificate' && (c.certificate_pem || c.private_key_pem)) {
      out.certificate_pem = c.certificate_pem;
      out.private_key_pem = c.private_key_pem;
    }
    if (kind === 'route53' && c.secret_access_key) out.secret_access_key = c.secret_access_key;
    return out;
  };

  const save = useMutation({
    mutationFn: (s: Sent) => {
      const typed = outgoing.current;
      outgoing.current = noCredentials;
      const settings = settingsOf();
      const secrets = credentialsOf(typed);
      if (!hook) {
        return run(() =>
          createACMEHook({
            kind,
            name: name.trim(),
            allowed_suffixes: s.suffixes,
            propagation_wait_seconds: s.wait,
            poll_timeout_seconds: s.poll,
            ...settings,
            ...secrets,
          }),
        );
      }
      const patch: ACMEDNSProviderFields = { ...secrets };
      if (name.trim() !== hook.name) patch.name = name.trim();
      if (s.suffixes.join('\n') !== hook.allowed_suffixes.join('\n')) patch.allowed_suffixes = s.suffixes;
      if (s.wait !== hook.propagation_wait_seconds) patch.propagation_wait_seconds = s.wait;
      if (s.poll !== hook.poll_timeout_seconds) patch.poll_timeout_seconds = s.poll;
      if (settingsChanged(settings)) Object.assign(patch, settings); // the settings are replaced as a whole
      return run(() => updateACMEHook(hook.id, patch));
    },
    onSuccess: () => {
      setCred(noCredentials);
      return client.invalidateQueries({ queryKey: ACME_HOOKS_KEY });
    },
  });

  // What the form can tell before it sends anything (the server checks it all again).
  const problemsOf = (w: number, p: number): Record<string, string> => {
    const problems: Record<string, string> = {};
    const required = t('acme.dns.required');
    const creating = hook === null;
    // A change keeps the stored credentials unless what they belong to changes.
    const authChanged = hook !== null && kind === 'azure_dns' && hook.settings.auth !== auth;
    const keyChanged = hook !== null && kind === 'route53' && hook.settings.access_key_id !== accessKey.trim();
    if (name.trim() === '') problems.name = required;
    if (kind === 'cloudflare') {
      if (creating && cred.api_token === '') problems.api_token = required;
      else if (cred.api_token !== '' && (cred.api_token.length < DNS_TOKEN_MIN || cred.api_token.length > DNS_TOKEN_MAX || !PRINTABLE.test(cred.api_token)))
        problems.api_token = t('acme.dns.tokenRule', { min: DNS_TOKEN_MIN, max: DNS_TOKEN_MAX });
    }
    if (kind === 'azure_dns') {
      if (auth !== 'managed_identity' && !GUID.test(tenant.trim())) problems.tenant_id = t('acme.dns.guidRule');
      if ((auth !== 'managed_identity' || clientId.trim() !== '') && !GUID.test(clientId.trim())) problems.client_id = t('acme.dns.guidRule');
      if (!GUID.test(subscription.trim())) problems.subscription_id = t('acme.dns.guidRule');
      if (!RESOURCE_GROUP.test(group.trim()) || group.trim().endsWith('.')) problems.resource_group = t('acme.dns.groupRule');
      if (auth === 'client_secret' && (creating || authChanged) && cred.client_secret === '') problems.client_secret = required;
      if (auth === 'certificate' && (creating || authChanged || cred.certificate_pem !== '' || cred.private_key_pem !== '')) {
        if (cred.certificate_pem.trim() === '') problems.certificate = required;
        else if (cred.private_key_pem.trim() === '') problems.certificate = t('acme.dns.keyRequired');
      }
    }
    if (kind === 'route53') {
      if (!ACCESS_KEY.test(accessKey.trim())) problems.access_key_id = t('acme.dns.accessKeyRule');
      if ((creating || keyChanged) && cred.secret_access_key === '') problems.secret_access_key = required;
      else if (
        cred.secret_access_key !== '' &&
        (cred.secret_access_key.length < AWS_SECRET_MIN || cred.secret_access_key.length > AWS_SECRET_MAX || !PRINTABLE.test(cred.secret_access_key))
      )
        problems.secret_access_key = t('acme.dns.secretKeyRule', { min: AWS_SECRET_MIN, max: AWS_SECRET_MAX });
      if (role.trim() !== '' && !ROLE_ARN.test(role.trim())) problems.role_arn = t('acme.dns.roleRule');
    }
    if (!Number.isInteger(w) || w < 0 || w > HOOK_WAIT_MAX) problems.propagation_wait_seconds = t('acme.hook.waitRange', { max: HOOK_WAIT_MAX });
    if (!Number.isInteger(p) || p < HOOK_POLL_MIN || p > HOOK_POLL_MAX) problems.poll_timeout_seconds = t('acme.hook.pollRange', { min: HOOK_POLL_MIN, max: HOOK_POLL_MAX });
    else if (Number.isInteger(w) && w + p > HOOK_TOTAL_MAX) problems.poll_timeout_seconds = t('acme.hook.totalRange', { max: HOOK_TOTAL_MAX });
    return problems;
  };

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (save.isPending) return; // Enter pressed again while the request runs
    const w = asNumber(wait);
    const p = asNumber(poll);
    const problems = problemsOf(w, p);
    const drafted = takeDraft(suffixes, draft);
    if (drafted.problem) setDraftProblem(drafted.problem);
    setLocal(problems);
    if (Object.keys(problems).length > 0 || drafted.problem) return;
    setSuffixes(drafted.list);
    setDraft('');
    outgoing.current = cred;
    save.mutate({ suffixes: drafted.list, wait: w, poll: p });
  };

  const server = fieldErrorsOf(save.error, t, i18n);
  const fieldErrors = { ...server, ...local };
  const title = hook ? t('acme.hook.editTitle', { name: hook.name }) : t('acme.dns.addTitle');
  const kept = hook?.secret_configured ? t('acme.dns.kept') : undefined;

  if (save.isSuccess) {
    return (
      <AppModal opened onClose={onClose} title={title}>
        <Stack gap="sm">
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('settings.saved')}
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
    <AppModal opened onClose={onClose} title={title} size="lg">
      <form onSubmit={submit} noValidate>
        <Stack gap="sm">
          <Text size="sm">{t('acme.dns.intro')}</Text>
          {hook === null ? (
            <NativeSelect
              label={t('acme.dns.kind')}
              value={kind}
              onChange={(e) => setKind(e.currentTarget.value as ACMEDNSProviderKind)}
              data={ACME_DNS_PROVIDER_KINDS.map((k) => ({ value: k, label: t(hookKindKey(k)) }))}
            />
          ) : (
            <Text size="sm">
              {t('acme.dns.kind')}: <strong>{t(hookKindKey(kind))}</strong>
            </Text>
          )}
          <TextInput label={t('acme.hook.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={fieldErrors.name} maxLength={100} required data-autofocus />

          {kind === 'cloudflare' && (
            <PasswordInput
              label={t('acme.dns.apiToken')}
              description={kept ?? t('acme.dns.apiTokenHelp')}
              value={cred.api_token}
              onChange={(e) => setCredField('api_token', e.currentTarget.value)}
              error={fieldErrors.api_token}
              autoComplete="new-password"
              spellCheck={false}
              required={hook === null}
            />
          )}

          {kind === 'azure_dns' && (
            <>
              <NativeSelect
                label={t('acme.dns.auth')}
                value={auth}
                onChange={(e) => setAuth(e.currentTarget.value as AzureDNSAuth)}
                data={AZURE_DNS_AUTHS.map((a) => ({ value: a, label: t(azureAuthKey(a)) }))}
                error={fieldErrors.auth}
              />
              {auth !== 'managed_identity' && (
                <TextInput label={t('acme.dns.tenant')} value={tenant} onChange={(e) => setTenant(e.currentTarget.value)} error={fieldErrors.tenant_id} spellCheck={false} required />
              )}
              <TextInput
                label={auth === 'managed_identity' ? t('acme.dns.clientOptional') : t('acme.dns.client')}
                description={auth === 'managed_identity' ? t('acme.dns.clientOptionalHelp') : undefined}
                value={clientId}
                onChange={(e) => setClientId(e.currentTarget.value)}
                error={fieldErrors.client_id}
                spellCheck={false}
                required={auth !== 'managed_identity'}
              />
              {auth === 'client_secret' && (
                <PasswordInput
                  label={t('acme.dns.clientSecret')}
                  description={hook?.settings.auth === 'client_secret' ? kept : undefined}
                  value={cred.client_secret}
                  onChange={(e) => setCredField('client_secret', e.currentTarget.value)}
                  error={fieldErrors.client_secret}
                  autoComplete="new-password"
                  spellCheck={false}
                  required={hook?.settings.auth !== 'client_secret'}
                />
              )}
              {auth === 'certificate' && (
                <>
                  {hook?.settings.cert_thumbprint && hook.settings.auth === 'certificate' && (
                    <Text size="xs" c="dimmed">
                      {t('acme.dns.certStored', { thumbprint: hook.settings.cert_thumbprint })}
                    </Text>
                  )}
                  <Textarea
                    label={t('acme.dns.certificate')}
                    description={t('acme.dns.certificateHelp')}
                    placeholder="-----BEGIN CERTIFICATE-----"
                    value={cred.certificate_pem}
                    onChange={(e) => setCredField('certificate_pem', e.currentTarget.value)}
                    error={fieldErrors.certificate}
                    autosize
                    minRows={2}
                    maxRows={6}
                    spellCheck={false}
                    styles={{ input: { fontFamily: 'monospace' } }}
                  />
                  <Textarea
                    label={t('acme.dns.privateKey')}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    value={cred.private_key_pem}
                    onChange={(e) => setCredField('private_key_pem', e.currentTarget.value)}
                    error={fieldErrors.private_key_pem}
                    autosize
                    minRows={2}
                    maxRows={6}
                    spellCheck={false}
                    autoComplete="off"
                    styles={{ input: { fontFamily: 'monospace' } }}
                  />
                </>
              )}
              <TextInput label={t('acme.dns.subscription')} value={subscription} onChange={(e) => setSubscription(e.currentTarget.value)} error={fieldErrors.subscription_id} spellCheck={false} required />
              <TextInput label={t('acme.dns.resourceGroup')} value={group} onChange={(e) => setGroup(e.currentTarget.value)} error={fieldErrors.resource_group} spellCheck={false} required />
            </>
          )}

          {kind === 'route53' && (
            <>
              <TextInput label={t('acme.dns.accessKey')} value={accessKey} onChange={(e) => setAccessKey(e.currentTarget.value)} error={fieldErrors.access_key_id} spellCheck={false} required />
              <PasswordInput
                label={t('acme.dns.secretKey')}
                description={kept}
                value={cred.secret_access_key}
                onChange={(e) => setCredField('secret_access_key', e.currentTarget.value)}
                error={fieldErrors.secret_access_key}
                autoComplete="new-password"
                spellCheck={false}
                required={hook === null}
              />
              <TextInput label={t('acme.dns.role')} description={t('acme.dns.roleHelp')} value={role} onChange={(e) => setRole(e.currentTarget.value)} error={fieldErrors.role_arn} spellCheck={false} />
              {role.trim() !== '' && (
                <TextInput label={t('acme.dns.externalId')} value={external} onChange={(e) => setExternal(e.currentTarget.value)} error={fieldErrors.external_id} spellCheck={false} />
              )}
            </>
          )}

          <Notice tone="info" title={t('acme.dns.permissionsTitle')}>
            <Text size="sm">{t(`acme.dns.permissions.${kind}`)}</Text>
          </Notice>

          <Group grow align="flex-start">
            <NumberInput
              label={t('acme.hook.wait')}
              description={t('acme.dns.waitHelp', { max: HOOK_WAIT_MAX })}
              value={wait}
              onChange={setWait}
              min={0}
              max={HOOK_WAIT_MAX}
              allowDecimal={false}
              allowNegative={false}
              error={fieldErrors.propagation_wait_seconds}
            />
            <NumberInput
              label={t('acme.hook.poll')}
              description={t('acme.dns.pollHelp', { min: HOOK_POLL_MIN, max: HOOK_POLL_MAX, total: HOOK_TOTAL_MAX })}
              value={poll}
              onChange={setPoll}
              min={HOOK_POLL_MIN}
              max={HOOK_POLL_MAX}
              allowDecimal={false}
              allowNegative={false}
              error={fieldErrors.poll_timeout_seconds}
            />
          </Group>
          <SuffixInput
            value={suffixes}
            onChange={setSuffixes}
            draft={draft}
            onDraftChange={setDraft}
            problem={draftProblem}
            onProblem={setDraftProblem}
            serverError={fieldErrors.allowed_suffixes}
          />
          <Notice tone="info" title={t('acme.hook.noContactTitle')}>
            <Text size="sm">{t('acme.dns.noContactText')}</Text>
          </Notice>
          <ErrorAlert error={save.error} />
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending}>
              {t('acme.dns.save')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}
