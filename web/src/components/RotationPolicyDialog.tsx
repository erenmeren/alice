import { Alert, Button, Group, NativeSelect, NumberInput, Stack, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { policyKey, ROTATION_RUNS_KEY, sshKey } from '../api/queryKeys';
import { createPolicy, updatePolicy, type NewKeyType, type Policy, type PolicyPatch } from '../api/rotation';
import { KEY_TYPES } from '../api/sshkeys';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';

interface Props {
  keyId: string;
  // policy is the latest copy (the panel refreshes it after a save or a 412); null creates a policy.
  policy: Policy | null;
  onClose: () => void;
}

const whole = (v: number | string) => (typeof v === 'number' && Number.isInteger(v) ? v : null);
const inRange = (v: number | null, min: number, max: number) => v !== null && v >= min && v <= max;

function PolicyForm({ keyId, policy, onClose }: Props) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const [name, setName] = useState(policy?.name ?? '');
  const [interval, setInterval_] = useState<number | string>(policy?.interval_days ?? 90);
  const [overlap, setOverlap] = useState<number | string>(policy?.overlap_days ?? 7);
  const [notify, setNotify] = useState<number | string>(policy?.notify_before_hours ?? 24);
  const [newType, setNewType] = useState<NewKeyType>(policy?.new_key_type ?? 'same');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [touched, setTouched] = useState(false);
  const [notSaved, setNotSaved] = useState(false);
  const reloadFrom = useRef<number | null>(null);

  // After a 412 the panel gives a newer copy: the form takes its values (unless the person has typed since).
  const version = policy?.version ?? 0;
  useEffect(() => {
    if (policy === null || reloadFrom.current === null || version === reloadFrom.current) return;
    reloadFrom.current = null;
    setName(policy.name);
    setInterval_(policy.interval_days);
    setOverlap(policy.overlap_days);
    setNotify(policy.notify_before_hours);
    setNewType(policy.new_key_type);
  }, [version, policy]);

  const typed = () => {
    reloadFrom.current = null;
  };
  const days = whole(interval);
  const overlapDays = whole(overlap);
  const hours = whole(notify);
  const problems = {
    name: name.trim() === '' || [...name.trim()].length > 100 ? t('rotation.invalid.name') : undefined,
    interval: inRange(days, 1, 3650) ? undefined : t('rotation.invalid.interval'),
    overlap: inRange(overlapDays, 0, 90) ? undefined : t('rotation.invalid.overlap'),
    notify: inRange(hours, 1, 168) ? undefined : t('rotation.invalid.notify'),
  };
  const valid = Object.values(problems).every((p) => p === undefined);
  const fieldErrors = fieldErrorsOf(error, t, i18n);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!valid) return;
    setBusy(true);
    setError(null);
    setNotSaved(false);
    try {
      if (policy === null) {
        const created = await createPolicy({
          ssh_key_id: keyId,
          name: name.trim(),
          interval_days: days as number,
          overlap_days: overlapDays as number,
          notify_before_hours: hours as number,
          new_key_type: newType,
        });
        void client.invalidateQueries({ queryKey: sshKey(keyId) });
        void client.invalidateQueries({ queryKey: policyKey(created.id) });
      } else {
        // Only what changed is sent.
        const patch: PolicyPatch = {};
        if (name.trim() !== policy.name) patch.name = name.trim();
        if (days !== policy.interval_days) patch.interval_days = days as number;
        if (overlapDays !== policy.overlap_days) patch.overlap_days = overlapDays as number;
        if (hours !== policy.notify_before_hours) patch.notify_before_hours = hours as number;
        if (newType !== policy.new_key_type) patch.new_key_type = newType;
        if (Object.keys(patch).length > 0) await updatePolicy(policy.id, policy.version, patch);
        void client.invalidateQueries({ queryKey: policyKey(policy.id) });
        void client.invalidateQueries({ queryKey: sshKey(keyId) });
        void client.invalidateQueries({ queryKey: ROTATION_RUNS_KEY });
      }
      onClose();
      return;
    } catch (err) {
      setError(err);
      if (policy !== null && isApiError(err) && err.status === 412) {
        reloadFrom.current = policy.version;
        setNotSaved(true);
        void client.invalidateQueries({ queryKey: policyKey(policy.id) });
      }
    }
    setBusy(false);
  };

  const show = (p: string | undefined) => (touched ? p : undefined);
  return (
    <form onSubmit={(e) => void submit(e)} noValidate>
      <Stack gap="sm">
        {policy?.enabled && (
          <Alert color="yellow" role="note">
            {t('rotation.editSwitchesOff')}
          </Alert>
        )}
        <TextInput
          data-autofocus
          label={t('rotation.name')}
          value={name}
          onChange={(e) => {
            typed();
            setName(e.currentTarget.value);
          }}
          error={show(problems.name) ?? fieldErrors.name}
          maxLength={100}
          autoComplete="off"
          required
        />
        <NumberInput label={t('rotation.intervalDays')} value={interval} onChange={(v) => { typed(); setInterval_(v); }} min={1} max={3650} allowDecimal={false} error={show(problems.interval) ?? fieldErrors.interval_days} />
        <NumberInput
          label={t('rotation.overlapDays')}
          description={t('rotation.overlapHelp')}
          value={overlap}
          onChange={(v) => {
            typed();
            setOverlap(v);
          }}
          min={0}
          max={90}
          allowDecimal={false}
          error={show(problems.overlap) ?? fieldErrors.overlap_days}
        />
        <NumberInput label={t('rotation.notifyHours')} value={notify} onChange={(v) => { typed(); setNotify(v); }} min={1} max={168} allowDecimal={false} error={show(problems.notify) ?? fieldErrors.notify_before_hours} />
        <NativeSelect
          label={t('rotation.newKeyType')}
          value={newType}
          onChange={(e) => {
            typed();
            setNewType(e.currentTarget.value as NewKeyType);
          }}
          data={[{ value: 'same', label: t('rotation.sameType') }, ...KEY_TYPES.map((k) => ({ value: k, label: t(`sshKeys.types.${k}`) }))]}
          error={fieldErrors.new_key_type}
        />
        {notSaved && (
          <Alert color="yellow" role="alert">
            {t('rotation.notSaved')}
          </Alert>
        )}
        {!notSaved && <ErrorAlert error={error} />}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('rotation.save')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

// RotationPolicyDialog creates a policy (policy null) or edits one with If-Match set to its version. Saving a change to a
// policy that is on switches it off on the server; the dialog says so before saving.
export function RotationPolicyDialog(props: Props) {
  const { t } = useTranslation();
  return (
    <AppModal opened onClose={props.onClose} title={t(props.policy === null ? 'rotation.createTitle' : 'rotation.editTitle')}>
      <PolicyForm {...props} />
    </AppModal>
  );
}
