import { Button, Group, PasswordInput, Stack, Switch, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createDirectory, DIRECTORY_PRESETS, updateDirectory, type Directory, type DirectoryInput, type DirectoryPreset } from '../../api/ldap';
import { LDAP_DIRECTORIES_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';
import { DialogActions } from '../ui';

// The form's text fields: everything of a directory except the switches, the addresses (one per line) and the password.
type TextField = Exclude<keyof DirectoryInput, 'addresses' | 'bind_password' | 'mfa_required' | 'enabled'>;
type Form = Record<TextField, string> & { addresses: string; mfa_required: boolean; enabled: boolean };

const MONO = { input: { fontFamily: 'var(--mantine-font-family-monospace)' } };

function initial(d: Directory | null): Form {
  if (!d) {
    // A new directory: MFA on and sign-in off (the server's defaults too), the group filter of the spec.
    return {
      name: '',
      addresses: '',
      user_base_dn: '',
      user_filter: '',
      login_attribute: '',
      unique_id_attribute: '',
      display_name_attribute: '',
      email_attribute: '',
      bind_dn: '',
      group_base_dn: '',
      group_filter: '(member={dn})',
      group_name_attribute: 'cn',
      ca_pem: '',
      mfa_required: true,
      enabled: false,
    };
  }
  return {
    name: d.name,
    addresses: d.addresses.join('\n'),
    user_base_dn: d.user_base_dn,
    user_filter: d.user_filter,
    login_attribute: d.login_attribute,
    unique_id_attribute: d.unique_id_attribute,
    display_name_attribute: d.display_name_attribute,
    email_attribute: d.email_attribute,
    bind_dn: d.bind_dn,
    group_base_dn: d.group_base_dn,
    group_filter: d.group_filter,
    group_name_attribute: d.group_name_attribute,
    ca_pem: d.ca_pem,
    mfa_required: d.mfa_required,
    enabled: d.enabled,
  };
}

const splitAddresses = (s: string) =>
  s
    .split(/\r?\n/)
    .map((a) => a.trim())
    .filter((a) => a !== '');

// toInput is the request body of the form (without the password): text trimmed, the PEM as typed.
function toInput(f: Form): Omit<DirectoryInput, 'bind_password'> {
  const tr = (k: TextField) => f[k].trim();
  return {
    name: tr('name'),
    addresses: splitAddresses(f.addresses),
    user_base_dn: tr('user_base_dn'),
    user_filter: tr('user_filter'),
    login_attribute: tr('login_attribute'),
    unique_id_attribute: tr('unique_id_attribute'),
    display_name_attribute: tr('display_name_attribute'),
    email_attribute: tr('email_attribute'),
    bind_dn: tr('bind_dn'),
    group_base_dn: tr('group_base_dn'),
    group_filter: tr('group_filter'),
    group_name_attribute: tr('group_name_attribute'),
    ca_pem: f.ca_pem,
    mfa_required: f.mfa_required,
    enabled: f.enabled,
  };
}

// changedKeys is the PATCH body: only what differs from the stored directory (the server changes only the keys given).
function changedKeys(d: Directory, next: Omit<DirectoryInput, 'bind_password'>): Partial<DirectoryInput> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(next) as [keyof typeof next, unknown][]) {
    const cur = d[k];
    const same = Array.isArray(v) && Array.isArray(cur) ? v.length === cur.length && v.every((x, i) => x === cur[i]) : v === cur;
    if (!same) out[k] = v;
  }
  return out as Partial<DirectoryInput>;
}

// needsPassword says whether the change would send the stored service account password to another server or account: an
// added address, another service account, another unique ID attribute or another certificate authority. The server
// refuses such a change without the password (422 on bind_password); the form says so before.
function needsPassword(d: Directory | null, next: Omit<DirectoryInput, 'bind_password'>): boolean {
  if (!d) return false;
  return next.addresses.some((a) => !d.addresses.includes(a)) || next.bind_dn !== d.bind_dn || next.unique_id_attribute !== d.unique_id_attribute || next.ca_pem !== d.ca_pem;
}

const REQUIRED: (keyof Form)[] = ['name', 'addresses', 'user_base_dn', 'user_filter', 'login_attribute', 'unique_id_attribute', 'bind_dn', 'group_base_dn'];

// DirectoryDialog adds or edits a directory. The service account password lives only in this form's state: it is sent when
// typed, never read back (the server answers bind_password_set only), cleared when the request is sent (also when it is
// refused) and gone with the form when it closes. The presets fill the attribute and filter fields and nothing else.
export function DirectoryDialog({ directory, onClose }: { directory: Directory | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [form, setForm] = useState<Form>(() => initial(directory));
  const [password, setPassword] = useState('');
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));
  const text = (k: TextField | 'addresses') => ({ value: form[k], onChange: (e: { currentTarget: { value: string } }) => set(k, e.currentTarget.value) });

  const save = useMutation({
    gcTime: 0, // the password is a mutation variable: do not keep it in the mutation cache
    mutationFn: (secret: string) => {
      const next = toInput(form);
      const extra = secret ? { bind_password: secret } : {};
      return run(() => (directory ? updateDirectory(directory.id, directory.version, { ...changedKeys(directory, next), ...extra }) : createDirectory({ ...next, ...extra })));
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: LDAP_DIRECTORIES_KEY });
      onClose();
    },
  });

  const reenter = needsPassword(directory, toInput(form));
  const passwordRequired = !directory || reenter;
  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const secret = password;
    setPassword(''); // not kept in the page once the request is built, whatever the answer
    if (REQUIRED.some((k) => String(form[k]).trim() === '')) return;
    save.mutate(secret);
  };
  const preset = (p: DirectoryPreset) => setForm((f) => ({ ...f, ...DIRECTORY_PRESETS[p] }));
  const fe = fieldErrorsOf(save.error, t, i18n);
  let passwordHelp: string | undefined;
  if (reenter) passwordHelp = t('directories.fields.bindPasswordReenter');
  else if (directory?.bind_password_set) passwordHelp = t('directories.fields.bindPasswordStored');

  return (
    <AppModal opened onClose={onClose} title={directory ? t('directories.editTitle') : t('directories.add')} size="lg">
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Stack gap={4}>
            <Text size="sm" fw={500}>
              {t('directories.presets.label')}
            </Text>
            <Group gap="xs">
              <Button size="xs" variant="default" onClick={() => preset('ad')}>
                {t('directories.presets.ad')}
              </Button>
              <Button size="xs" variant="default" onClick={() => preset('openldap')}>
                {t('directories.presets.openldap')}
              </Button>
            </Group>
            <Text size="xs" c="dimmed">
              {t('directories.presets.help')}
            </Text>
          </Stack>
          <TextInput label={t('directories.fields.name')} {...text('name')} error={fe.name} required data-autofocus />
          <Textarea
            label={t('directories.fields.addresses')}
            description={t('directories.fields.addressesHelp')}
            {...text('addresses')}
            error={fe.addresses}
            required
            autosize
            minRows={2}
            maxRows={4}
            spellCheck={false}
            autoComplete="off"
            styles={MONO}
          />
          <TextInput label={t('directories.fields.userBaseDn')} {...text('user_base_dn')} error={fe.user_base_dn} required autoComplete="off" spellCheck={false} />
          <TextInput
            label={t('directories.fields.userFilter')}
            description={t('directories.fields.userFilterHelp')}
            {...text('user_filter')}
            error={fe.user_filter}
            required
            autoComplete="off"
            spellCheck={false}
            styles={MONO}
          />
          <TextInput label={t('directories.fields.loginAttribute')} {...text('login_attribute')} error={fe.login_attribute} required autoComplete="off" spellCheck={false} />
          <TextInput
            label={t('directories.fields.uniqueIdAttribute')}
            description={t('directories.fields.uniqueIdHelp')}
            {...text('unique_id_attribute')}
            error={fe.unique_id_attribute}
            required
            autoComplete="off"
            spellCheck={false}
          />
          <TextInput label={t('directories.fields.displayNameAttribute')} {...text('display_name_attribute')} error={fe.display_name_attribute} autoComplete="off" spellCheck={false} />
          <TextInput label={t('directories.fields.emailAttribute')} {...text('email_attribute')} error={fe.email_attribute} autoComplete="off" spellCheck={false} />
          <TextInput
            label={t('directories.fields.bindDn')}
            description={t('directories.fields.bindDnHelp')}
            {...text('bind_dn')}
            error={fe.bind_dn}
            required
            autoComplete="off"
            spellCheck={false}
          />
          <PasswordInput
            label={t('directories.fields.bindPassword')}
            description={passwordHelp}
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            error={fe.bind_password}
            autoComplete="new-password"
            required={passwordRequired}
          />
          <TextInput label={t('directories.fields.groupBaseDn')} {...text('group_base_dn')} error={fe.group_base_dn} required autoComplete="off" spellCheck={false} />
          <TextInput
            label={t('directories.fields.groupFilter')}
            description={t('directories.fields.groupFilterHelp')}
            {...text('group_filter')}
            error={fe.group_filter}
            autoComplete="off"
            spellCheck={false}
            styles={MONO}
          />
          <Text size="xs" c="dimmed">
            {t('directories.templateRules')}
          </Text>
          <TextInput
            label={t('directories.fields.groupNameAttribute')}
            description={t('directories.fields.groupNameHelp')}
            {...text('group_name_attribute')}
            error={fe.group_name_attribute}
            autoComplete="off"
            spellCheck={false}
          />
          <Textarea label={t('directories.fields.caPem')} {...text('ca_pem')} error={fe.ca_pem} autosize minRows={3} maxRows={8} spellCheck={false} styles={MONO} />
          <Switch role="switch" label={t('directories.fields.mfaRequired')} checked={form.mfa_required} onChange={(e) => set('mfa_required', e.currentTarget.checked)} />
          <Switch role="switch" label={t('directories.fields.enabled')} checked={form.enabled} onChange={(e) => set('enabled', e.currentTarget.checked)} />
          <ErrorAlert error={save.error} />
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending}>
              {t('directories.save')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}
