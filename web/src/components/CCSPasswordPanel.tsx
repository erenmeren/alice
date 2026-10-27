import { Button, Group, PasswordInput, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { setCCSPassword } from '../api/endpoints';
import { TARGETS_KEY, targetKey } from '../api/queryKeys';
import type { Target } from '../api/types';
import { formatDateTime } from '../datetime';
import { ErrorAlert } from './ErrorAlert';
import { useStepUp } from './StepUpProvider';
import { FactList, Panel } from './ui';

// CCS_PASSWORD is the server's rule (W5 Ruling 10): 12 to 128 characters of printable ASCII without spaces.
const CCS_PASSWORD = /^[\x21-\x7e]{12,128}$/;

// ccsEnabled: a Windows server whose last scan says IIS uses the Centralized Certificate Store (win_ccs_enabled).
export function ccsEnabled(target: Target): boolean {
  return target.type === 'windows' && target.facts.warnings.some((w) => w.code === 'win_ccs_enabled');
}

// CCSPasswordPanel says whether Alice holds the private-key password of the server's Centralized Certificate Store and
// lets a person with credentials.manage set or replace it (PUT /targets/{id}/ccs-password, with a fresh step-up; R68).
// The password is taken out of the field as soon as it is submitted, sent once in the request body and never shown or
// read back: the server answers only when it was set.
export function CCSPasswordPanel({ target, canSet }: { target: Target; canSet: boolean }) {
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
  const setAt = current.ccs_password_set_at ?? null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    const password = value;
    setValue('');
    setSaved(false);
    setError(null);
    const valid = CCS_PASSWORD.test(password);
    setInvalid(!valid);
    if (!valid) return;
    setBusy(true);
    try {
      const res = await run(() => setCCSPassword(current.id, current.version, password));
      setAnswer(res);
      client.setQueryData(targetKey(current.id), res);
      setSaved(true);
    } catch (err) {
      setError(err);
    }
    setBusy(false);
    void client.invalidateQueries({ queryKey: TARGETS_KEY });
  };

  return (
    <Panel title={t('ccs.title')} testId="ccs-password">
      <Stack gap="xs">
        <Text size="sm">{t('ccs.help')}</Text>
        <FactList facts={[{ key: 'state', label: t('ccs.state'), value: setAt ? formatDateTime(setAt, i18n.language) : t('ccs.notSet'), testId: 'ccs-password-state' }]} />
        {canSet && (
          <form onSubmit={(e) => void submit(e)} autoComplete="off">
            <Stack gap="xs">
              <PasswordInput
                label={t('ccs.field')}
                description={t('ccs.fieldHelp')}
                value={value}
                onChange={(e) => setValue(e.currentTarget.value)}
                error={invalid ? t('errors.windows.ccs_password_invalid.cause') : undefined}
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
          {saved ? t('ccs.saved') : ''}
        </Text>
        <ErrorAlert error={error} />
      </Stack>
    </Panel>
  );
}
