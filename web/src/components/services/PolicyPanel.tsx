import { ActionIcon, Button, Checkbox, Group, Loader, NativeSelect, NumberInput, Stack, Table, Text, Textarea, TextInput } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { listACMEProviders } from '../../api/acme';
import { ACME_PROVIDERS_KEY, servicePolicyKey, servicePolicyVersionsKey, SERVICES_KEY } from '../../api/queryKeys';
import {
  changedPolicyKeys,
  getServicePolicy,
  listServicePolicyVersions,
  MAX_POLICY_ADDRESSES,
  MAX_POLICY_DOMAINS,
  POLICY_CHALLENGES,
  POLICY_KEY_TYPES,
  POLICY_SOURCES,
  putServicePolicy,
  type PolicyChallenge,
  type PolicyDocument,
  type PolicySource,
  type Service,
} from '../../api/services';
import { useAuth } from '../../auth/AuthProvider';
import { canIn, canPlatform } from '../../auth/permissions';
import { formatDateTime } from '../../datetime';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { Icon } from '../../design/Icon';
import { useStepUp } from '../StepUpProvider';
import { EmptyState, Panel } from '../ui';

// The form's values: lists as checkboxes, the domains one per line; '' is "not set" (Alice's default or no constraint).
interface PolicyForm {
  domains: string;
  sources: string[];
  providers: string[];
  challenges: string[];
  keyTypes: string[];
  renewDays: number | string;
  autoDeploy: '' | 'allowed' | 'forbidden';
  revokeMode: '' | 'after_verified' | 'now';
  administrators: boolean;
  addresses: { email: string; locale: string }[];
}

function formOf(p: PolicyDocument): PolicyForm {
  return {
    domains: (p.domains ?? []).join('\n'),
    sources: [...(p.certificate_sources ?? [])],
    providers: [...(p.acme?.providers ?? [])],
    challenges: [...(p.acme?.challenges ?? [])],
    keyTypes: [...(p.acme?.key_types ?? [])],
    renewDays: p.acme?.renew_before_days ?? '',
    autoDeploy: p.deployment?.auto_deploy ?? '',
    revokeMode: p.incident?.revoke_mode ?? '',
    administrators: p.notifications?.administrators ?? true,
    addresses: (p.notifications?.addresses ?? []).map((a) => ({ ...a })),
  };
}

// splitDomains reads the domains box: one entry per line (commas and spaces separate too).
export function splitDomains(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter((x) => x !== '');
}

// documentOf builds the policy document: only what is set (an empty list is no constraint, so it is left out).
export function documentOf(f: PolicyForm): PolicyDocument {
  const doc: PolicyDocument = { schema: 1 };
  const domains = splitDomains(f.domains);
  if (domains.length > 0) doc.domains = domains;
  if (f.sources.length > 0) doc.certificate_sources = f.sources as PolicySource[];
  const acme: NonNullable<PolicyDocument['acme']> = {};
  if (f.providers.length > 0) acme.providers = f.providers;
  if (f.challenges.length > 0) acme.challenges = f.challenges as PolicyChallenge[];
  if (f.keyTypes.length > 0) acme.key_types = f.keyTypes;
  if (typeof f.renewDays === 'number') acme.renew_before_days = f.renewDays;
  if (Object.keys(acme).length > 0) doc.acme = acme;
  if (f.autoDeploy) doc.deployment = { auto_deploy: f.autoDeploy };
  if (f.revokeMode) doc.incident = { revoke_mode: f.revokeMode };
  const addresses = f.addresses.filter((a) => a.email.trim() !== '').map((a) => ({ email: a.email.trim(), locale: a.locale }));
  if (!f.administrators || addresses.length > 0) {
    doc.notifications = {};
    if (!f.administrators) doc.notifications.administrators = false;
    if (addresses.length > 0) doc.notifications.addresses = addresses;
  }
  return doc;
}

// fieldsUnder is the first field error whose field is the path or below it (the server names body.domains.2).
function fieldsUnder(fields: Record<string, string>, path: string): string | undefined {
  const key = Object.keys(fields).find((k) => k === path || k.startsWith(`${path}.`));
  return key ? fields[key] : undefined;
}

// PolicyPanel is a service's policy (R55, design §7.3): the form for an Administrator of the service (the domains for an
// Administrator of all services only), read-only for everyone else, and every version with its author.
export function PolicyPanel({ service }: { service: Service }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  const canEdit = canIn(session, service.id, 'services.policy');
  const canDomains = canPlatform(session, 'services.policy');
  const policy = useQuery({ queryKey: servicePolicyKey(service.id), queryFn: ({ signal }) => getServicePolicy(service.id, signal) });
  const [saved, setSaved] = useState(0);
  return (
    <Stack gap="md">
      <Text size="sm">{t('services.policyForm.intro')}</Text>
      <ErrorAlert error={policy.error} />
      {policy.isPending && <Loader size="sm" aria-label={t('ui.loading')} />}
      {saved > 0 && policy.data?.version === saved && (
        <Text size="sm" c="dimmed" role="status" data-testid="policy-saved">
          {t('services.policyForm.saved', { version: saved })}
        </Text>
      )}
      {policy.data && (
        <PolicyEditor key={policy.data.version} service={service} version={policy.data.version} doc={policy.data.body} canEdit={canEdit} canDomains={canDomains} onSaved={setSaved} />
      )}
      <PolicyHistory service={service} />
    </Stack>
  );
}

function PolicyEditor({
  service,
  version,
  doc,
  canEdit,
  canDomains,
  onSaved,
}: {
  service: Service;
  version: number;
  doc: PolicyDocument;
  canEdit: boolean;
  canDomains: boolean;
  onSaved: (version: number) => void;
}) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [f, setF] = useState<PolicyForm>(() => formOf(doc));
  const set = (patch: Partial<PolicyForm>) => setF((cur) => ({ ...cur, ...patch }));
  const providers = useQuery({ queryKey: ACME_PROVIDERS_KEY, queryFn: ({ signal }) => listACMEProviders(signal) });
  const save = useMutation({
    mutationFn: () => run(() => putServicePolicy(service.id, version, documentOf(f))),
    onSuccess: async (p) => {
      onSaved(p.version);
      await client.invalidateQueries({ queryKey: SERVICES_KEY });
    },
  });
  const fields = fieldErrorsOf(save.error, t, i18n);
  const readOnly = !canEdit;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };
  const known = new Set((providers.data?.items ?? []).map((p) => p.id));
  const providerChoices = [...(providers.data?.items ?? []).map((p) => ({ value: p.id, label: p.name })), ...f.providers.filter((id) => !known.has(id)).map((id) => ({ value: id, label: t('services.policyForm.providerGone') }))];
  return (
    <form onSubmit={submit} aria-label={t('services.policy.title')}>
      <Stack gap="md">
        <Panel title={t('services.policyForm.names.title')} description={t('services.policyForm.names.description')}>
          <Stack gap="sm">
            <Textarea
              label={t('services.policyForm.domains')}
              description={canDomains ? t('services.policyForm.domainsHelp', { max: MAX_POLICY_DOMAINS }) : t('services.policyForm.domainsGlobalOnly')}
              value={f.domains}
              onChange={(e) => set({ domains: e.currentTarget.value })}
              readOnly={readOnly || !canDomains}
              autosize
              minRows={2}
              maxRows={10}
              spellCheck={false}
              translate="no"
              error={fieldsUnder(fields, 'body.domains')}
              data-testid="policy-domains"
            />
            <Checkbox.Group label={t('services.policyForm.sources')} description={t('services.policyForm.sourcesHelp')} value={f.sources} onChange={(v) => set({ sources: v })} error={fieldsUnder(fields, 'body.certificate_sources')}>
              <Group gap="md" mt="xs">
                {POLICY_SOURCES.map((x) => (
                  <Checkbox key={x} value={x} label={t(`services.policyForm.source.${x}`)} disabled={readOnly} />
                ))}
              </Group>
            </Checkbox.Group>
          </Stack>
        </Panel>
        <Panel title={t('services.policyForm.acme.title')} description={t('services.policyForm.acme.description')}>
          <Stack gap="sm">
            <Checkbox.Group label={t('services.policyForm.providers')} description={t('services.policyForm.anyHelp')} value={f.providers} onChange={(v) => set({ providers: v })} error={fieldsUnder(fields, 'body.acme.providers')}>
              <Stack gap={6} mt="xs">
                {providers.isPending && <Loader size="xs" aria-label={t('ui.loading')} />}
                {providerChoices.map((p) => (
                  <Checkbox key={p.value} value={p.value} label={<span translate="no">{p.label}</span>} disabled={readOnly} />
                ))}
                {providers.isSuccess && providerChoices.length === 0 && (
                  <Text size="sm" c="dimmed">
                    {t('services.policyForm.noProviders')}
                  </Text>
                )}
              </Stack>
            </Checkbox.Group>
            <Checkbox.Group label={t('services.policyForm.challenges')} description={t('services.policyForm.anyHelp')} value={f.challenges} onChange={(v) => set({ challenges: v })} error={fieldsUnder(fields, 'body.acme.challenges')}>
              <Group gap="md" mt="xs">
                {POLICY_CHALLENGES.map((x) => (
                  <Checkbox key={x} value={x} label={t(`acme.enum.challenge.${x}`)} disabled={readOnly} />
                ))}
              </Group>
            </Checkbox.Group>
            <Checkbox.Group label={t('services.policyForm.keyTypes')} description={t('services.policyForm.anyHelp')} value={f.keyTypes} onChange={(v) => set({ keyTypes: v })} error={fieldsUnder(fields, 'body.acme.key_types')}>
              <Group gap="md" mt="xs">
                {POLICY_KEY_TYPES.map((x) => (
                  <Checkbox key={x} value={x} label={t(`acme.enum.keyType.${x}`)} disabled={readOnly} />
                ))}
              </Group>
            </Checkbox.Group>
            <NumberInput
              label={t('services.policyForm.renewDays')}
              description={t('services.policyForm.renewDaysHelp')}
              value={f.renewDays}
              onChange={(v) => set({ renewDays: v })}
              min={1}
              max={60}
              allowDecimal={false}
              readOnly={readOnly}
              w={260}
              error={fields['body.acme.renew_before_days']}
            />
          </Stack>
        </Panel>
        <Panel title={t('services.policyForm.behaviour.title')}>
          <Stack gap="sm">
            <NativeSelect
              label={t('services.policyForm.autoDeploy')}
              description={t('services.policyForm.autoDeployHelp')}
              value={f.autoDeploy || 'allowed'}
              onChange={(e) => set({ autoDeploy: e.currentTarget.value === 'forbidden' ? 'forbidden' : '' })}
              disabled={readOnly}
              data={[
                { value: 'allowed', label: t('services.policyForm.autoDeployValue.allowed') },
                { value: 'forbidden', label: t('services.policyForm.autoDeployValue.forbidden') },
              ]}
              error={fields['body.deployment.auto_deploy']}
              data-testid="policy-auto-deploy"
            />
            <NativeSelect
              label={t('services.policyForm.revokeMode')}
              description={t('services.policyForm.revokeModeHelp')}
              value={f.revokeMode}
              onChange={(e) => set({ revokeMode: e.currentTarget.value as PolicyForm['revokeMode'] })}
              disabled={readOnly}
              data={[
                { value: '', label: t('services.policyForm.aliceDefault') },
                { value: 'after_verified', label: t('incidents.revokeMode.after_verified') },
                { value: 'now', label: t('incidents.revokeMode.now') },
              ]}
              error={fields['body.incident.revoke_mode']}
            />
          </Stack>
        </Panel>
        <Panel title={t('services.policyForm.notifications.title')} description={t('services.policyForm.notifications.description')}>
          <Stack gap="sm">
            <Checkbox label={t('services.policyForm.administrators')} checked={f.administrators} onChange={(e) => set({ administrators: e.currentTarget.checked })} disabled={readOnly} />
            {f.addresses.map((a, i) => (
              <Group key={i} gap="xs" align="flex-end" wrap="nowrap">
                <TextInput
                  label={i === 0 ? t('services.policyForm.address') : undefined}
                  aria-label={t('services.policyForm.address')}
                  type="email"
                  value={a.email}
                  onChange={(e) => {
                    const email = e.currentTarget.value;
                    set({ addresses: f.addresses.map((x, j) => (j === i ? { ...x, email } : x)) });
                  }}
                  readOnly={readOnly}
                  style={{ flex: 1 }}
                  error={fieldsUnder(fields, `body.notifications.addresses.${i}`)}
                />
                <NativeSelect
                  label={i === 0 ? t('services.policyForm.locale') : undefined}
                  aria-label={t('services.policyForm.locale')}
                  value={a.locale}
                  onChange={(e) => {
                    const locale = e.currentTarget.value;
                    set({ addresses: f.addresses.map((x, j) => (j === i ? { ...x, locale } : x)) });
                  }}
                  disabled={readOnly}
                  data={[
                    { value: 'en', label: 'English' },
                    { value: 'tr', label: 'Türkçe' },
                  ]}
                />
                {!readOnly && (
                  <ActionIcon variant="subtle" color="red" size="lg" aria-label={t('services.policyForm.removeAddress')} onClick={() => set({ addresses: f.addresses.filter((_, j) => j !== i) })}>
                    <Icon name="X" size={16} />
                  </ActionIcon>
                )}
              </Group>
            ))}
            {!readOnly && f.addresses.length < MAX_POLICY_ADDRESSES && (
              <Group>
                <Button variant="default" size="xs" onClick={() => set({ addresses: [...f.addresses, { email: '', locale: i18n.language === 'tr' ? 'tr' : 'en' }] })}>
                  {t('services.policyForm.addAddress')}
                </Button>
              </Group>
            )}
          </Stack>
        </Panel>
        <ErrorAlert error={save.error} />
        {canEdit && (
          <Group>
            <Button type="submit" loading={save.isPending} data-testid="policy-save">
              {t('services.policyForm.save')}
            </Button>
          </Group>
        )}
      </Stack>
    </form>
  );
}

function PolicyHistory({ service }: { service: Service }) {
  const { t, i18n } = useTranslation();
  const versions = useQuery({ queryKey: servicePolicyVersionsKey(service.id), queryFn: ({ signal }) => listServicePolicyVersions(service.id, signal) });
  const items = versions.data?.items ?? [];
  return (
    <Panel title={t('services.policyForm.history.title')} padded={items.length === 0}>
      <ErrorAlert error={versions.error} />
      {versions.isSuccess && items.length === 0 && <EmptyState icon="ScrollText" title={t('services.policyForm.history.none')} />}
      {items.length > 0 && (
        <Table data-testid="policy-history">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('services.policy.version')}</Table.Th>
              <Table.Th>{t('services.policyForm.history.changed')}</Table.Th>
              <Table.Th>{t('services.policyForm.history.by')}</Table.Th>
              <Table.Th>{t('services.policyForm.history.when')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((v, i) => {
              const keys = v.version === 1 ? [] : changedPolicyKeys(items[i + 1]?.body, v.body);
              return (
                <Table.Tr key={v.version}>
                  <Table.Td>{v.version}</Table.Td>
                  <Table.Td>{v.version === 1 ? t('services.policyForm.history.first') : keys.map((k) => t(`services.policyForm.keys.${k}`)).join(', ') || t('services.policyForm.history.nothing')}</Table.Td>
                  <Table.Td translate="no">{v.created_by_name || t('services.policyForm.history.system')}</Table.Td>
                  <Table.Td>{formatDateTime(v.created_at, i18n.language)}</Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      )}
    </Panel>
  );
}
