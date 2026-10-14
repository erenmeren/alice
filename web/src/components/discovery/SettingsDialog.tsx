import { Button, NumberInput, Stack, Textarea } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { MAX_EXCLUSIONS, MAX_RETENTION_DAYS, MIN_RETENTION_DAYS, elementProblem, lines, putDiscoverySettings, type DiscoverySettings } from '../../api/discovery';
import { DISCOVERY_KEY } from '../../api/queryKeys';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { reasonTitle } from '../JobErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions } from '../ui';

// SettingsDialog changes the discovery settings (an Administrator, with a fresh step-up): the allowed scan networks
// (nothing outside them is ever scanned; an empty list means nothing is), the exclusions every scope keeps and how long
// results are kept. A refusal names the line it is about.
export function SettingsDialog({ settings, onClose }: { settings: DiscoverySettings; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [allowed, setAllowed] = useState(settings.allowed_networks.join('\n'));
  const [excluded, setExcluded] = useState(settings.global_exclusions.join('\n'));
  const [retention, setRetention] = useState<number | string>(settings.retention_days);
  const [local, setLocal] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: (body: { allowed_networks: string[]; global_exclusions: string[]; retention_days: number }) => run(() => putDiscoverySettings(body)),
    onSuccess: async () => {
      // The settings decide what every scope may reach and whether a scan may start: everything is read again.
      await client.invalidateQueries({ queryKey: DISCOVERY_KEY });
      onClose();
    },
  });

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (save.isPending) return;
    const problems: Record<string, string> = {};
    const a = lines(allowed);
    const x = lines(excluded);
    const r = typeof retention === 'number' ? retention : Number(retention);
    if (a.length > MAX_EXCLUSIONS) problems.allowed_networks = t('discovery.settings.tooMany', { max: MAX_EXCLUSIONS });
    if (x.length > MAX_EXCLUSIONS) problems.global_exclusions = t('discovery.settings.tooMany', { max: MAX_EXCLUSIONS });
    if (!Number.isInteger(r) || r < MIN_RETENTION_DAYS || r > MAX_RETENTION_DAYS) problems.retention_days = t('discovery.settings.retentionRange', { min: MIN_RETENTION_DAYS, max: MAX_RETENTION_DAYS });
    setLocal(problems);
    if (Object.keys(problems).length > 0) return;
    save.mutate({ allowed_networks: a, global_exclusions: x, retention_days: r });
  };

  const named = elementProblem(save.error);
  const lineErrors: Record<string, string> = named
    ? { [named.field]: named.index === null ? reasonTitle(t, i18n, named.reason) : t('discovery.scope.line', { line: named.index + 1, problem: reasonTitle(t, i18n, named.reason) }) }
    : {};
  const errors = { ...fieldErrorsOf(save.error, t, i18n), ...lineErrors, ...local };

  return (
    <AppModal opened onClose={onClose} title={t('discovery.settings.dialogTitle')} size="lg">
      <form onSubmit={submit} noValidate>
        <Stack gap="sm">
          <Textarea
            label={t('discovery.settings.allowed')}
            description={t('discovery.settings.allowedHelp')}
            value={allowed}
            onChange={(e) => setAllowed(e.currentTarget.value)}
            autosize
            minRows={3}
            maxRows={10}
            spellCheck={false}
            autoComplete="off"
            translate="no"
            error={errors.allowed_networks}
            data-autofocus
          />
          <Textarea
            label={t('discovery.settings.exclusions')}
            description={t('discovery.settings.exclusionsHelp')}
            value={excluded}
            onChange={(e) => setExcluded(e.currentTarget.value)}
            autosize
            minRows={2}
            maxRows={10}
            spellCheck={false}
            autoComplete="off"
            translate="no"
            error={errors.global_exclusions}
          />
          <NumberInput
            label={t('discovery.settings.retention')}
            description={t('discovery.settings.retentionHelp', { min: MIN_RETENTION_DAYS, max: MAX_RETENTION_DAYS })}
            value={retention}
            onChange={setRetention}
            min={MIN_RETENTION_DAYS}
            max={MAX_RETENTION_DAYS}
            allowDecimal={false}
            required
            error={errors.retention_days}
          />
          <ErrorAlert error={save.error} />
        </Stack>
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={save.isPending}>
            {t('discovery.settings.save')}
          </Button>
        </DialogActions>
      </form>
    </AppModal>
  );
}
