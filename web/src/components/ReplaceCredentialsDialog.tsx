import { Alert, Button, Group, Loader, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { replaceVaultCredentials, type VaultWithAccess } from '../api/keyvault';
import { TARGETS_KEY } from '../api/queryKeys';
import type { Target } from '../api/types';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { buildSignIn, emptySignIn, PfxTooLargeError, signInReady, wipeSecrets, type SignInState } from './signIn';
import { SignInFields } from './SignInFields';
import { useStepUp } from './StepUpProvider';
import { DialogActions } from './ui';

// ReplaceCredentialsDialog replaces how Alice signs in to a vault: the fields of adding a vault
// without the name and the address. The request carries the vault's version (If-Match) and needs a
// fresh step-up. Secrets follow the rules of AddKeyVaultDialog: wiped from state as soon as the
// request is built, never shown again.
export function ReplaceCredentialsDialog({ vault, onClose, onReplaced }: { vault: Target; onClose: () => void; onReplaced: (result: VaultWithAccess) => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [signIn, setSignIn] = useState<SignInState>(() => ({ ...emptySignIn(), auth: vault.vault?.auth ?? 'certificate', tenantId: vault.vault?.tenant_id ?? '', clientId: vault.vault?.client_id ?? '' }));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [local, setLocal] = useState<Record<string, string>>({});
  const [retype, setRetype] = useState(false);
  const fieldErrors = { ...fieldErrorsOf(error, t, i18n), ...local };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!signInReady(signIn)) return;
    setError(null);
    setLocal({});
    let body;
    try {
      body = await buildSignIn(signIn);
    } catch (err) {
      setSignIn(wipeSecrets(signIn));
      if (err instanceof PfxTooLargeError) setLocal({ pfx_base64: t('vaults.fields.pfx_tooLarge') });
      else setError(err);
      return;
    }
    setSignIn(wipeSecrets(signIn));
    setBusy(true);
    try {
      const res = await run(() => replaceVaultCredentials(vault.id, vault.version, body));
      void client.invalidateQueries({ queryKey: TARGETS_KEY });
      onReplaced(res);
    } catch (err) {
      setError(err);
      setRetype(body.auth !== 'managed_identity');
      // The vault may have changed meanwhile (a stale version): read it again.
      void client.invalidateQueries({ queryKey: TARGETS_KEY });
      setBusy(false);
    }
  };

  const leave = () => {
    setSignIn(wipeSecrets(signIn));
    onClose();
  };
  return (
    <AppModal opened onClose={leave} title={t('vaults.replaceTitle')} size="lg" closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}>
      {busy ? (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('vaults.checking')}</Text>
        </Group>
      ) : (
        <form onSubmit={(e) => void submit(e)} autoComplete="off">
          <Stack gap="sm">
            <Text size="sm">{t('vaults.replaceHelp')}</Text>
            <SignInFields value={signIn} onChange={setSignIn} fieldErrors={fieldErrors} />
            {retype && <Alert color="gray">{t('vaults.retypeSecret')}</Alert>}
            <ErrorAlert error={error} />
            <DialogActions>
              <Button variant="default" onClick={leave}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" disabled={!signInReady(signIn)}>
                {t('vaults.replaceCredentials')}
              </Button>
            </DialogActions>
          </Stack>
        </form>
      )}
    </AppModal>
  );
}
