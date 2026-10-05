import { FileInput, Radio, Stack, Textarea, TextInput } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { VAULT_AUTHS, type VaultAuth } from '../api/keyvault';
import type { SignInState } from './signIn';

const PEM_STYLE = { fontFamily: 'var(--mantine-font-family-monospace)' };

// SignInFields are the fields of a vault's sign-in: the method (a certificate is recommended) and
// what the method needs. Secrets are held by the parent's state only; the inputs are never
// completed, spell-checked or remembered by the browser. fieldErrors are server problems shown under their fields.
export function SignInFields({
  value,
  onChange,
  fieldErrors = {},
  disabled = false,
}: {
  value: SignInState;
  onChange: (next: SignInState) => void;
  fieldErrors?: Record<string, string>;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const set = (patch: Partial<SignInState>) => onChange({ ...value, ...patch });
  const mi = value.auth === 'managed_identity';
  return (
    <Stack gap="sm">
      <Radio.Group value={value.auth} onChange={(v) => set({ auth: v as VaultAuth })} label={t('vaults.fields.auth')} description={t(`vaults.auth.help.${value.auth}`)}>
        <Stack gap={6} mt="xs">
          {VAULT_AUTHS.map((a) => (
            <Radio key={a} value={a} label={t(`vaults.auth.${a}`)} disabled={disabled} />
          ))}
        </Stack>
      </Radio.Group>
      {!mi && (
        <TextInput
          label={t('vaults.fields.tenant_id')}
          value={value.tenantId}
          onChange={(e) => set({ tenantId: e.currentTarget.value })}
          error={fieldErrors.tenant_id}
          required
          maxLength={36}
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
        />
      )}
      <TextInput
        label={t(mi ? 'vaults.fields.client_id_optional' : 'vaults.fields.client_id')}
        value={value.clientId}
        onChange={(e) => set({ clientId: e.currentTarget.value })}
        error={fieldErrors.client_id}
        required={!mi}
        maxLength={36}
        autoComplete="off"
        spellCheck={false}
        disabled={disabled}
      />
      {value.auth === 'client_secret' && (
        <>
          <TextInput
            type="password"
            label={t('vaults.fields.client_secret')}
            value={value.secret}
            onChange={(e) => set({ secret: e.currentTarget.value })}
            error={fieldErrors.client_secret}
            required
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
          />
          <TextInput
            type="date"
            label={t('vaults.fields.secret_expires')}
            value={value.secretExpires}
            onChange={(e) => set({ secretExpires: e.currentTarget.value })}
            error={fieldErrors.secret_expires_on}
            disabled={disabled}
          />
        </>
      )}
      {value.auth === 'certificate' && (
        <>
          <Radio.Group value={value.certFormat} onChange={(v) => set({ certFormat: v as 'pem' | 'pfx' })} label={t('vaults.fields.cert_format')}>
            <Stack gap={6} mt="xs">
              <Radio value="pem" label={t('vaults.certFormat.pem')} disabled={disabled} />
              <Radio value="pfx" label={t('vaults.certFormat.pfx')} disabled={disabled} />
            </Stack>
          </Radio.Group>
          {value.certFormat === 'pem' ? (
            <>
              <Textarea
                label={t('vaults.fields.certificate_pem')}
                value={value.certPem}
                onChange={(e) => set({ certPem: e.currentTarget.value })}
                error={fieldErrors.certificate_pem}
                required
                autosize
                minRows={3}
                maxRows={8}
                spellCheck={false}
                autoComplete="off"
                styles={{ input: PEM_STYLE }}
                disabled={disabled}
              />
              <Textarea
                label={t('vaults.fields.private_key_pem')}
                value={value.keyPem}
                onChange={(e) => set({ keyPem: e.currentTarget.value })}
                error={fieldErrors.private_key_pem}
                required
                autosize
                minRows={3}
                maxRows={8}
                spellCheck={false}
                autoComplete="off"
                styles={{ input: PEM_STYLE }}
                disabled={disabled}
              />
            </>
          ) : (
            <>
              <FileInput
                label={t('vaults.fields.pfx')}
                value={value.pfx}
                onChange={(f) => set({ pfx: f })}
                error={fieldErrors.pfx_base64}
                required
                accept=".pfx,.p12,application/x-pkcs12"
                clearable
                disabled={disabled}
              />
              <TextInput
                type="password"
                label={t('vaults.fields.pfx_password')}
                description={t('vaults.fields.pfx_password_help')}
                value={value.pfxPassword}
                onChange={(e) => set({ pfxPassword: e.currentTarget.value })}
                error={fieldErrors.pfx_password}
                autoComplete="off"
                spellCheck={false}
                disabled={disabled}
              />
            </>
          )}
        </>
      )}
    </Stack>
  );
}
