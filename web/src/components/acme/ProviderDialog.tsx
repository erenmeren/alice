import { Button, Checkbox, NativeSelect, PasswordInput, Stack, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACME_PRESETS,
  PRESET_DIRECTORIES,
  createACMEProvider,
  presetKey,
  updateACMEProvider,
  type ACMEPreset,
  type ACMEProvider,
  type ACMEProviderPatch,
} from '../../api/acme';
import { ACME_PROVIDERS_KEY, notACMEPreview } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';
import ui from '../ui/ui.module.css';
import { SuffixInput, pemTooLarge, takeDraft } from './SuffixInput';

type Preset = Exclude<ACMEPreset, ''>;

const BUNDLE_TOO_LARGE = 'acme.provider.bundleTooLarge';


// ProviderDialog adds or changes a certificate authority. The preset only fills in the directory address; nothing is
// contacted when it is saved (the first contact is the account registration). The external account binding's secret
// key lives in this form's state only: it stays in the field until the save succeeds or the dialog closes (a local
// problem, a refusal or a cancelled step-up keep what was typed), the request reads it through a ref that it empties at
// once, so it is never a mutation variable (no cache holds it), and it is never read back (the server answers
// eab_configured). Only the fields that changed are sent on a change, so an unchanged directory address never asks to
// retire the account.
export function ProviderDialog({ provider, onClose }: { provider: ACMEProvider | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const initialPreset: Preset = (ACME_PRESETS as readonly string[]).includes(provider?.preset ?? '') ? (provider?.preset as Preset) : provider ? 'custom' : 'letsencrypt';
  const [preset, setPreset] = useState<Preset>(initialPreset);
  const [name, setName] = useState(provider?.name ?? '');
  const [directory, setDirectory] = useState(provider?.directory_url ?? PRESET_DIRECTORIES.letsencrypt);
  const [bundle, setBundle] = useState(provider?.ca_bundle_pem ?? '');
  const [kid, setKid] = useState(provider?.eab_kid ?? '');
  const [hmac, setHmac] = useState('');
  const [removeEab, setRemoveEab] = useState(false);
  const [suffixes, setSuffixes] = useState<string[]>(provider?.allowed_suffixes ?? []);
  const [draft, setDraft] = useState('');
  const [draftProblem, setDraftProblem] = useState('');
  const [confirmDirectory, setConfirmDirectory] = useState(false);
  const [local, setLocal] = useState('');
  // The typed secret key between the save and the request; the request takes it and leaves it empty.
  const outgoing = useRef('');

  const directoryChanged = provider !== null && directory.trim() !== provider.directory_url;
  const needsConfirm = directoryChanged && provider?.active_account_id != null;

  const save = useMutation({
    mutationFn: (list: string[]) => {
      const secret = outgoing.current;
      outgoing.current = '';
      const eab = secret ? { eab_kid: kid.trim(), eab_hmac: secret } : {};
      if (!provider) {
        return run(() =>
          createACMEProvider({ name: name.trim(), directory_url: directory.trim(), preset, ca_bundle_pem: bundle, allowed_suffixes: list, ...eab }),
        );
      }
      const patch: ACMEProviderPatch = { ...eab };
      if (name.trim() !== provider.name) patch.name = name.trim();
      if (directoryChanged) patch.directory_url = directory.trim();
      if (preset !== initialPreset) patch.preset = preset; // a stored '' shows as My own CA: unchanged, not sent
      if (bundle !== provider.ca_bundle_pem) patch.ca_bundle_pem = bundle;
      if (list.join('\n') !== provider.allowed_suffixes.join('\n')) patch.allowed_suffixes = list;
      if (removeEab && !secret) patch.remove_eab = true;
      if (needsConfirm && confirmDirectory) patch.confirm_directory_change = true;
      return run(() => updateACMEProvider(provider.id, patch));
    },
    onSuccess: () => {
      setHmac('');
      return client.invalidateQueries({ queryKey: ACME_PROVIDERS_KEY, predicate: notACMEPreview });
    },
  });

  const choosePreset = (value: string) => {
    const p = value as Preset;
    setPreset(p);
    if (p !== 'custom') setDirectory(PRESET_DIRECTORIES[p]);
    else if (Object.values(PRESET_DIRECTORIES).includes(directory)) setDirectory('');
  };

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (save.isPending) return; // Enter pressed again while the request runs
    const secret = hmac;
    const kidChanged = kid.trim() !== (provider?.eab_kid ?? '');
    // Both or neither: a secret key needs its key ID, and a new key ID needs its secret key.
    if ((secret && !kid.trim()) || (!secret && kid.trim() && kidChanged && !removeEab)) {
      setLocal('acme.provider.eabBoth');
      return;
    }
    if (pemTooLarge(bundle)) {
      setLocal(BUNDLE_TOO_LARGE);
      return;
    }
    const drafted = takeDraft(suffixes, draft);
    if (drafted.problem) {
      setDraftProblem(drafted.problem);
      setLocal('');
      return;
    }
    setLocal('');
    setSuffixes(drafted.list);
    setDraft('');
    outgoing.current = secret;
    save.mutate(drafted.list);
  };

  const fieldErrors = fieldErrorsOf(save.error, t, i18n);
  const title = provider ? t('acme.provider.editTitle', { name: provider.name }) : t('acme.provider.addTitle');

  if (save.isSuccess) {
    return (
      <AppModal opened onClose={onClose} title={title}>
        <Stack gap="sm">
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('settings.saved')}
          </Text>
          {!provider && <Text size="sm">{t('acme.provider.savedNext')}</Text>}
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
          <NativeSelect
            label={t('acme.provider.preset')}
            description={t('acme.provider.presetHelp')}
            value={preset}
            onChange={(e) => choosePreset(e.currentTarget.value)}
            data={ACME_PRESETS.map((p) => ({ value: p, label: t(presetKey(p)) }))}
            data-autofocus
          />
          <TextInput label={t('acme.provider.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={fieldErrors.name} maxLength={100} required />
          <TextInput
            label={t('acme.provider.directory')}
            description={t('acme.provider.directoryHelp')}
            type="url"
            value={directory}
            onChange={(e) => setDirectory(e.currentTarget.value)}
            error={fieldErrors.directory_url}
            autoComplete="off"
            spellCheck={false}
            required
          />
          {needsConfirm && (
            <Checkbox
              label={t('acme.provider.confirmDirectory')}
              description={t('acme.provider.confirmDirectoryHelp')}
              checked={confirmDirectory}
              onChange={(e) => setConfirmDirectory(e.currentTarget.checked)}
            />
          )}
          <Textarea
            label={t('acme.provider.bundle')}
            description={t('acme.provider.bundleHelp')}
            placeholder="-----BEGIN CERTIFICATE-----"
            value={bundle}
            onChange={(e) => setBundle(e.currentTarget.value)}
            error={local === BUNDLE_TOO_LARGE ? t(BUNDLE_TOO_LARGE) : fieldErrors.ca_bundle_pem}
            autosize
            minRows={3}
            maxRows={8}
            spellCheck={false}
            styles={{ input: { fontFamily: 'monospace' } }}
          />
          <fieldset className={ui.modeSet}>
            <legend className={ui.fieldLabel}>{t('acme.provider.eab')}</legend>
            <Text size="xs" c="dimmed" mb="xs">
              {t('acme.provider.eabHelp')}
            </Text>
            <Stack gap="xs">
              <TextInput label={t('acme.provider.eabKid')} value={kid} onChange={(e) => setKid(e.currentTarget.value)} error={fieldErrors.eab_kid} autoComplete="off" spellCheck={false} />
              <PasswordInput
                label={t('acme.provider.eabHmac')}
                description={provider?.eab_configured ? t('acme.provider.eabKept') : t('acme.provider.eabHmacHelp')}
                value={hmac}
                onChange={(e) => setHmac(e.currentTarget.value)}
                error={fieldErrors.eab_hmac ?? fieldErrors.eab}
                autoComplete="new-password"
                spellCheck={false}
              />
              {provider?.eab_configured && (
                <Checkbox label={t('acme.provider.removeEab')} checked={removeEab} onChange={(e) => setRemoveEab(e.currentTarget.checked)} />
              )}
            </Stack>
          </fieldset>
          <SuffixInput
            value={suffixes}
            onChange={setSuffixes}
            draft={draft}
            onDraftChange={setDraft}
            problem={draftProblem}
            onProblem={setDraftProblem}
            serverError={fieldErrors.allowed_suffixes}
          />
          <Notice tone="info" title={t('acme.provider.noContactTitle')}>
            <Text size="sm">{t('acme.provider.noContactText')}</Text>
          </Notice>
          {local && local !== BUNDLE_TOO_LARGE && (
            <Text role="alert" size="sm" c="var(--alice-danger)">
              {t(local)}
            </Text>
          )}
          <ErrorAlert error={save.error} />
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending}>
              {t('acme.provider.save')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}
