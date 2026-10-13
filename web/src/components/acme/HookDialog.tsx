import { Button, Group, NumberInput, PasswordInput, Stack, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  HOOK_POLL_MAX,
  HOOK_POLL_MIN,
  HOOK_SECRET_MAX,
  HOOK_SECRET_MIN,
  HOOK_TOTAL_MAX,
  HOOK_WAIT_MAX,
  createACMEHook,
  updateACMEHook,
  type ACMEHook,
  type ACMEHookPatch,
} from '../../api/acme';
import { ACME_HOOKS_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';
import { SuffixInput, pemTooLarge, takeDraft } from './SuffixInput';

interface Sent {
  suffixes: string[];
  wait: number;
  poll: number;
}

const asNumber = (v: number | string) => (typeof v === 'number' ? v : v.trim() === '' ? NaN : Number(v));

// HookDialog adds or changes a DNS hook. The secret lives in this form's state only: it stays in the field until the
// save succeeds or the dialog closes (a local problem, a refusal or a cancelled step-up keep what was typed), the
// request reads it through a ref that it empties at once, so it is never a mutation variable (no cache holds it), and
// it is never read back (the server answers secret_configured). The two waits are checked against their bounds before anything is sent (the server checks them again).
export function HookDialog({ hook, onClose }: { hook: ACMEHook | null; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [name, setName] = useState(hook?.name ?? '');
  const [url, setUrl] = useState(hook?.url ?? '');
  const [secret, setSecret] = useState('');
  const [bundle, setBundle] = useState(hook?.ca_bundle_pem ?? '');
  const [wait, setWait] = useState<number | string>(hook?.propagation_wait_seconds ?? 5);
  const [poll, setPoll] = useState<number | string>(hook?.poll_timeout_seconds ?? 60);
  const [suffixes, setSuffixes] = useState<string[]>(hook?.allowed_suffixes ?? []);
  const [draft, setDraft] = useState('');
  const [draftProblem, setDraftProblem] = useState('');
  const [local, setLocal] = useState<Record<string, string>>({});
  // The typed secret between the save and the request; the request takes it and leaves it empty.
  const outgoing = useRef('');

  const save = useMutation({
    mutationFn: (s: Sent) => {
      const secret = outgoing.current;
      outgoing.current = '';
      if (!hook) {
        return run(() =>
          createACMEHook({
            name: name.trim(),
            url: url.trim(),
            secret,
            ca_bundle_pem: bundle,
            allowed_suffixes: s.suffixes,
            propagation_wait_seconds: s.wait,
            poll_timeout_seconds: s.poll,
          }),
        );
      }
      const patch: ACMEHookPatch = secret ? { secret } : {};
      if (name.trim() !== hook.name) patch.name = name.trim();
      if (url.trim() !== hook.url) patch.url = url.trim();
      if (bundle !== hook.ca_bundle_pem) patch.ca_bundle_pem = bundle;
      if (s.suffixes.join('\n') !== hook.allowed_suffixes.join('\n')) patch.allowed_suffixes = s.suffixes;
      if (s.wait !== hook.propagation_wait_seconds) patch.propagation_wait_seconds = s.wait;
      if (s.poll !== hook.poll_timeout_seconds) patch.poll_timeout_seconds = s.poll;
      return run(() => updateACMEHook(hook.id, patch));
    },
    onSuccess: () => {
      setSecret('');
      return client.invalidateQueries({ queryKey: ACME_HOOKS_KEY });
    },
  });

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (save.isPending) return; // Enter pressed again while the request runs
    const typed = secret;
    const problems: Record<string, string> = {};
    const w = asNumber(wait);
    const p = asNumber(poll);
    if (!hook && typed === '') problems.secret = t('acme.hook.secretRequired');
    else if (typed !== '' && (typed.length < HOOK_SECRET_MIN || typed.length > HOOK_SECRET_MAX)) problems.secret = t('acme.hook.secretLength', { min: HOOK_SECRET_MIN, max: HOOK_SECRET_MAX });
    if (!Number.isInteger(w) || w < 0 || w > HOOK_WAIT_MAX) problems.propagation_wait_seconds = t('acme.hook.waitRange', { max: HOOK_WAIT_MAX });
    if (!Number.isInteger(p) || p < HOOK_POLL_MIN || p > HOOK_POLL_MAX) problems.poll_timeout_seconds = t('acme.hook.pollRange', { min: HOOK_POLL_MIN, max: HOOK_POLL_MAX });
    else if (Number.isInteger(w) && w + p > HOOK_TOTAL_MAX) problems.poll_timeout_seconds = t('acme.hook.totalRange', { max: HOOK_TOTAL_MAX });
    if (pemTooLarge(bundle)) problems.ca_bundle_pem = t('acme.provider.bundleTooLarge');
    const drafted = takeDraft(suffixes, draft);
    if (drafted.problem) setDraftProblem(drafted.problem);
    setLocal(problems);
    if (Object.keys(problems).length > 0 || drafted.problem) return;
    setSuffixes(drafted.list);
    setDraft('');
    outgoing.current = typed;
    save.mutate({ suffixes: drafted.list, wait: w, poll: p });
  };

  const server = fieldErrorsOf(save.error, t, i18n);
  const fieldErrors = { ...server, ...local };
  const title = hook ? t('acme.hook.editTitle', { name: hook.name }) : t('acme.hook.addTitle');

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
          <Text size="sm">{t('acme.hook.intro')}</Text>
          <TextInput label={t('acme.hook.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={fieldErrors.name} maxLength={100} required data-autofocus />
          <TextInput
            label={t('acme.hook.url')}
            description={t('acme.hook.urlHelp')}
            type="url"
            value={url}
            onChange={(e) => setUrl(e.currentTarget.value)}
            error={fieldErrors.url}
            autoComplete="off"
            spellCheck={false}
            required
          />
          <PasswordInput
            label={t('acme.hook.secret')}
            description={hook?.secret_configured ? t('acme.hook.secretKept') : t('acme.hook.secretHelp', { min: HOOK_SECRET_MIN, max: HOOK_SECRET_MAX })}
            value={secret}
            onChange={(e) => setSecret(e.currentTarget.value)}
            error={fieldErrors.secret}
            autoComplete="new-password"
            spellCheck={false}
            required={!hook}
          />
          <Textarea
            label={t('acme.hook.bundle')}
            description={t('acme.hook.bundleHelp')}
            placeholder="-----BEGIN CERTIFICATE-----"
            value={bundle}
            onChange={(e) => setBundle(e.currentTarget.value)}
            error={fieldErrors.ca_bundle_pem}
            autosize
            minRows={2}
            maxRows={8}
            spellCheck={false}
            styles={{ input: { fontFamily: 'monospace' } }}
          />
          <Group grow align="flex-start">
            <NumberInput
              label={t('acme.hook.wait')}
              description={t('acme.hook.waitHelp', { max: HOOK_WAIT_MAX })}
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
              description={t('acme.hook.pollHelp', { min: HOOK_POLL_MIN, max: HOOK_POLL_MAX, total: HOOK_TOTAL_MAX })}
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
            <Text size="sm">{t('acme.hook.noContactText')}</Text>
          </Notice>
          <ErrorAlert error={save.error} />
          <DialogActions>
            <Button variant="default" onClick={onClose}>
              {t('ui.cancel')}
            </Button>
            <Button type="submit" loading={save.isPending}>
              {t('acme.hook.save')}
            </Button>
          </DialogActions>
        </Stack>
      </form>
    </AppModal>
  );
}
