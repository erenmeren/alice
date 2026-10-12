import { Alert, Box, Button, Group, Loader, NumberInput, Stack, Text, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createVault, type VaultCreated } from '../api/keyvault';
import { TARGETS_KEY } from '../api/queryKeys';
import type { Target } from '../api/types';
import { Icon } from '../design/Icon';
import { AccessChecklist, accessRows } from './AccessCheckPanel';
import { AppModal } from './AppModal';
import { CodeText } from './CodeText';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { RoleGuide } from './RoleGuide';
import { buildSignIn, emptySignIn, PfxTooLargeError, signInReady, wipeSecrets, type SignInState } from './signIn';
import { SignInFields } from './SignInFields';
import { useStepUp } from './StepUpProvider';
import { DialogActions } from './ui';
import { vaultNameOf } from './vaultText';
import { VaultStatusBadge } from './VaultStatusBadge';

type Phase = 'form' | 'working' | 'done';

// AddKeyVaultDialog adds a vault: how Alice signs in (a certificate is recommended), then one request
// that signs in and reaches the vault before anything is stored. The request needs an Administrator's
// fresh step-up (run asks for the code). The client secret, the private key and the PFX with its
// password live in this component's state only: they are wiped as soon as the request is built, so
// they are gone after success, after any refusal and when the dialog closes, and they are never
// shown again. A refusal leaves the form open and says what to correct; the secret is typed again.
export function AddKeyVaultDialog({ onClose, onAdded }: { onClose: () => void; onAdded: (target: Target) => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [name, setName] = useState('');
  const [vaultUrl, setVaultUrl] = useState('');
  const [poll, setPoll] = useState<number | string>(15);
  const [signIn, setSignIn] = useState<SignInState>(emptySignIn);
  const [phase, setPhase] = useState<Phase>('form');
  const [error, setError] = useState<unknown>(null);
  const [local, setLocal] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<VaultCreated | null>(null);
  const [retype, setRetype] = useState(false);

  const fieldErrors = { ...fieldErrorsOf(error, t, i18n), ...local };
  const ready = name.trim() !== '' && vaultUrl.trim() !== '' && signInReady(signIn);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setError(null);
    setLocal({});
    let req;
    try {
      req = { name: name.trim(), vault_url: vaultUrl.trim(), ...(await buildSignIn(signIn)), poll_interval_minutes: Number(poll) || 15 };
    } catch (err) {
      setSignIn(wipeSecrets(signIn));
      if (err instanceof PfxTooLargeError) setLocal({ pfx_base64: t('vaults.fields.pfx_tooLarge') });
      else setError(err);
      return;
    }
    // From here the secrets exist only in req: the form state is wiped before anything is sent.
    setSignIn(wipeSecrets(signIn));
    setPhase('working');
    try {
      const res = await run(() => createVault(req));
      setCreated(res);
      setRetype(false);
      setPhase('done');
      void client.invalidateQueries({ queryKey: TARGETS_KEY });
    } catch (err) {
      setError(err);
      setRetype(req.auth !== 'managed_identity');
      setPhase('form');
    }
  };

  // Leaving the dialog wipes the secret fields first, so they are gone even if the parent keeps it mounted.
  const leave = () => {
    setSignIn(wipeSecrets(signIn));
    onClose();
  };
  const vault = created?.target.vault;
  const access = created?.access ?? vault?.access ?? null;
  // A missing role (a forbidden row) is fixed with the roles below; any other failed row (the vault's firewall,
  // say) is not, so it gets its own text and no role guide.
  const rows = created !== null ? accessRows(access) : [];
  const partly = rows.some((r) => r.result === 'forbidden');
  const failedCheck = rows.some((r) => r.result === 'failed');
  const working = phase === 'working';

  return (
    <AppModal opened onClose={leave} title={t('vaults.add')} size="lg" closeOnClickOutside={!working} closeOnEscape={!working} withCloseButton={!working}>
      {phase === 'working' && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('vaults.checking')}</Text>
        </Group>
      )}
      {phase === 'form' && (
        <form onSubmit={(e) => void submit(e)} autoComplete="off">
          <Stack gap="sm">
            <TextInput label={t('vaults.fields.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={fieldErrors.name} required maxLength={100} data-autofocus />
            <TextInput
              label={t('vaults.fields.vault_url')}
              description={t('vaults.fields.vault_url_help')}
              value={vaultUrl}
              onChange={(e) => setVaultUrl(e.currentTarget.value)}
              error={fieldErrors.vault_url}
              required
              maxLength={253}
              autoComplete="off"
              spellCheck={false}
            />
            <SignInFields value={signIn} onChange={setSignIn} fieldErrors={fieldErrors} />
            <NumberInput label={t('vaults.fields.poll_interval')} value={poll} onChange={setPoll} min={5} max={1440} allowDecimal={false} error={fieldErrors.poll_interval_minutes} />
            {retype && <Text size="sm">{t('vaults.retypeSecret')}</Text>}
            <ErrorAlert error={error} />
            <Box component="details">
              <Text component="summary" size="sm" fw={600} style={{ cursor: 'pointer' }}>
                {t('vaults.roles.title')}
              </Text>
              <Box mt="xs">
                <RoleGuide clientId={signIn.clientId.trim()} vaultName={vaultNameOf(vaultUrl)} />
              </Box>
            </Box>
            <DialogActions>
              <Button variant="default" onClick={leave}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" leftSection={<Icon name="ShieldCheck" size={15} />} disabled={!ready}>
                {t('vaults.add')}
              </Button>
            </DialogActions>
          </Stack>
        </form>
      )}
      {phase === 'done' && created && (
        <Stack gap="md">
          <Alert color="green" role="status">
            {t('vaults.added')}
          </Alert>
          <Group gap="sm">
            <VaultStatusBadge target={created.target} />
          </Group>
          {access && access.object_id !== '' && (
            <Text size="sm">
              <CodeText i18nKey="vaults.signsInAs" param="objectId" value={access.object_id} />
            </Text>
          )}
          <AccessChecklist access={access} />
          {partly && (
            <Alert color="yellow" role="status">
              {t('vaults.addedPartly')}
            </Alert>
          )}
          {failedCheck && (
            <Alert color="yellow" role="status">
              {t('vaults.addedFailedCheck')}
            </Alert>
          )}
          {partly && <RoleGuide clientId={vault?.client_id || undefined} vaultName={vault?.name} openPolicies={access?.permission_model === 'access_policy'} />}
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.close')}
            </Button>
            <Button rightSection={<Icon name="ArrowRight" size={15} />} onClick={() => onAdded(created.target)}>
              {t('vaults.openVault')}
            </Button>
          </DialogActions>
        </Stack>
      )}
    </AppModal>
  );
}
