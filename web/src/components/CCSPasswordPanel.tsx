import { Button, Group, PasswordInput, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { setCCSPassword, setWinRMPassword } from '../api/endpoints';
import { TARGETS_KEY, targetKey } from '../api/queryKeys';
import type { Target } from '../api/types';
import { formatDateTime } from '../datetime';
import { ErrorAlert } from './ErrorAlert';
import { useStepUp } from './StepUpProvider';
import { FactList, Panel } from './ui';

// CCS_PASSWORD is the server's rule (W5 Ruling 10): 12 to 128 characters of printable ASCII without spaces. The WinRM
// password has the same rule (R71 Ruling 7).
const CCS_PASSWORD = /^[\x21-\x7e]{12,128}$/;

// KINDS: the two passwords of a Windows server the panel sets (R71 Ruling 22): the endpoint, the answer's date field,
// the locale keys and the test ids; the step-up, the If-Match version and the "set / replace" wording are shared.
const KINDS = {
  ccs: { set: setCCSPassword, setAt: (t: Target) => t.ccs_password_set_at, keys: 'ccs', invalid: 'errors.windows.ccs_password_invalid.cause' },
  winrm: { set: setWinRMPassword, setAt: (t: Target) => t.winrm_password_set_at, keys: 'winrm', invalid: 'errors.windows.winrm_password_invalid.cause' },
} as const;

// ccsEnabled: a Windows server whose last scan says IIS uses the Centralized Certificate Store (win_ccs_enabled).
export function ccsEnabled(target: Target): boolean {
  return target.type === 'windows' && target.facts.warnings.some((w) => w.code === 'win_ccs_enabled');
}

// CCSPasswordPanel says whether Alice holds the private-key password of the server's Centralized Certificate Store and
// lets a person with credentials.manage set or replace it (PUT /targets/{id}/ccs-password, with a fresh step-up; R68).
// With kind winrm it does the same for the password Alice signs in with over WinRM (PUT /targets/{id}/winrm-password,
// R71); onSaved gets the server's answer.
// The password is taken out of the field as soon as it is submitted, sent once in the request body and never shown or
// read back: the server answers only when it was set.
export function CCSPasswordPanel({
  target,
  canSet,
  kind = 'ccs',
  onSaved,
}: {
  target: Target;
  canSet: boolean;
  kind?: keyof typeof KINDS;
  onSaved?: (target: Target) => void;
}) {
  const k = KINDS[kind];
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  // The server's answer, until the page reads a newer version of the server.
  const [answer, setAnswer] = useState<Target | null>(null);
  const current = answer && answer.version > target.version ? answer : target;
  const setAt = k.setAt(current) ?? null;

  // inFlight: two submits before React renders busy (Enter and a click in one turn) send one request (W5-12b, R70).
  const inFlight = useRef(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const password = value;
      setValue('');
      setSaved(false);
      setError(null);
      const valid = CCS_PASSWORD.test(password);
      setInvalid(!valid);
      if (!valid) return;
      setBusy(true);
      try {
        const res = await run(() => k.set(current.id, current.version, password));
        setAnswer(res);
        client.setQueryData(targetKey(current.id), res);
        setSaved(true);
        onSaved?.(res);
      } catch (err) {
        setError(err);
      }
      setBusy(false);
      void client.invalidateQueries({ queryKey: TARGETS_KEY });
    } finally {
      inFlight.current = false;
    }
  };

  return (
    <Panel title={t(`${k.keys}.title`)} testId={`${kind}-password`}>
      <Stack gap="xs">
        <Text size="sm">{t(`${k.keys}.help`)}</Text>
        <FactList facts={[{ key: 'state', label: t('ccs.state'), value: setAt ? formatDateTime(setAt, i18n.language) : t('ccs.notSet'), testId: `${kind}-password-state` }]} />
        {canSet && (
          <form onSubmit={(e) => void submit(e)} autoComplete="off">
            <Stack gap="xs">
              <PasswordInput
                label={t(`${k.keys}.field`)}
                description={t(`${k.keys}.fieldHelp`)}
                value={value}
                onChange={(e) => setValue(e.currentTarget.value)}
                error={invalid ? t(k.invalid) : undefined}
                autoComplete="new-password"
                spellCheck={false}
              />
              <Group>
                <Button type="submit" variant="default" loading={busy} disabled={value === ''}>
                  {t(setAt ? 'ccs.replace' : 'ccs.set')}
                </Button>
              </Group>
            </Stack>
          </form>
        )}
        <Text size="sm" role="status">
          {saved ? t(`${k.keys}.saved`) : ''}
        </Text>
        <ErrorAlert error={error} />
      </Stack>
    </Panel>
  );
}
