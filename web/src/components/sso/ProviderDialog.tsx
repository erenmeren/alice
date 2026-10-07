import { Button, CopyButton, Group, PasswordInput, Stack, Switch, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createProvider, updateProvider, type Provider } from '../../api/sso';
import { SSO_PROVIDERS_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { CodeText } from '../CodeText';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';

// ProviderDialog adds or edits an identity provider. The client secret lives only in this form's state: it is sent when typed,
// never read back (the server answers has_client_secret only), and is gone with the form once the request was sent. After a
// save the dialog shows the redirect address to register at the provider.
export function ProviderDialog({ provider, onClose }: { provider: Provider | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [name, setName] = useState(provider?.name ?? '');
  const [issuer, setIssuer] = useState(provider?.issuer_url ?? '');
  const [clientId, setClientId] = useState(provider?.client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');
  const [groupsClaim, setGroupsClaim] = useState(provider?.groups_claim ?? 'groups');
  const [caPem, setCaPem] = useState(provider?.ca_pem ?? '');
  // A new provider starts switched off (the server's default too).
  const [enabled, setEnabled] = useState(provider?.enabled ?? false);

  const save = useMutation({
    gcTime: 0, // the client secret is a mutation variable: do not keep it in the mutation cache
    mutationFn: (secret: string) => {
      const body = { name: name.trim(), issuer_url: issuer.trim(), client_id: clientId.trim(), groups_claim: groupsClaim.trim(), ca_pem: caPem, enabled, ...(secret ? { client_secret: secret } : {}) };
      return run(() => (provider ? updateProvider(provider.id, provider.version, body) : createProvider(body)));
    },
    onSuccess: () => client.invalidateQueries({ queryKey: SSO_PROVIDERS_KEY }),
  });

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const secret = clientSecret;
    setClientSecret('');
    save.mutate(secret);
  };
  const fieldErrors = fieldErrorsOf(save.error, t, i18n);
  const title = provider ? t('sso.editTitle') : t('sso.addProvider');

  if (save.isSuccess) {
    return (
      <AppModal opened onClose={onClose} title={title}>
        <Stack gap="sm">
          <Text role="status" size="sm" c="green.9">
            {t('settings.saved')}
          </Text>
          <Text size="sm">
            <CodeText i18nKey="sso.redirectUri" param="uri" value={save.data.redirect_uri} />
          </Text>
          <Group justify="flex-end">
            <CopyButton value={save.data.redirect_uri}>
              {({ copied, copy }) => (
                <Button variant="default" onClick={copy}>
                  {copied ? t('sso.copied') : t('sso.copy')}
                </Button>
              )}
            </CopyButton>
            <Button onClick={onClose} data-autofocus>
              {t('ui.continue')}
            </Button>
          </Group>
        </Stack>
      </AppModal>
    );
  }

  return (
    <AppModal opened onClose={onClose} title={title}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <TextInput label={t('sso.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={fieldErrors.name} required data-autofocus />
          <TextInput label={t('sso.issuer')} type="url" value={issuer} onChange={(e) => setIssuer(e.currentTarget.value)} error={fieldErrors.issuer_url} autoComplete="off" required />
          <TextInput label={t('sso.clientId')} value={clientId} onChange={(e) => setClientId(e.currentTarget.value)} error={fieldErrors.client_id} autoComplete="off" required />
          <PasswordInput
            label={t('sso.clientSecret')}
            description={provider?.has_client_secret ? t('sso.clientSecretKept') : undefined}
            value={clientSecret}
            onChange={(e) => setClientSecret(e.currentTarget.value)}
            error={fieldErrors.client_secret}
            autoComplete="new-password"
            required={!provider}
          />
          <TextInput label={t('sso.groupsClaim')} value={groupsClaim} onChange={(e) => setGroupsClaim(e.currentTarget.value)} error={fieldErrors.groups_claim} autoComplete="off" />
          <Textarea label={t('sso.caPem')} value={caPem} onChange={(e) => setCaPem(e.currentTarget.value)} error={fieldErrors.ca_pem} autosize minRows={3} maxRows={8} spellCheck={false} styles={{ input: { fontFamily: 'monospace' } }} />
          <Switch role="switch" label={t('sso.enabled')} checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
          <ErrorAlert error={save.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending}>
              {t('sso.save')}
            </Button>
          </Group>
        </Stack>
      </form>
    </AppModal>
  );
}
