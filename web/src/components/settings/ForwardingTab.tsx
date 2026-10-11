import { Button, Checkbox, Group, NativeSelect, NumberInput, Stack, Text, TextInput, Textarea, Title } from '@mantine/core';
import { useMutation } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { getForwarding, saveForwarding, testForwarding } from '../../api/endpoints';
import type { Forwarding, ForwardingInput, ForwardingTransport } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { SavedNote } from './SavedNote';
import { useChange, useSetting } from './useSetting';

// The forwarding error codes the server records as the last problem (C12), by their catalogue reason.
const ERROR_REASONS: Record<string, string> = {
  'ALC-AUD-0002': 'audit.forwarding_address_refused',
  'ALC-AUD-0003': 'audit.forwarding_unreachable',
  'ALC-AUD-0004': 'audit.forwarding_untrusted',
};

const MONO = { input: { fontFamily: 'monospace' } };

// ForwardingTab is Settings → Audit forwarding (SEC-073, C10, C12): where the audit log is sent and how far it got.
// The CA certificate is write-only: the field starts empty, a typed certificate replaces the stored one, "Remove the
// stored CA certificate" removes it, and the answer only says whether one is set.
export function ForwardingTab() {
  const q = useSetting('forwarding', getForwarding);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <ForwardingPanel settings={q.data} />;
}

function ForwardingPanel({ settings }: { settings: Forwarding }) {
  const { t, i18n } = useTranslation();
  const save = useChange('forwarding', settings.version, saveForwarding);
  return (
    <Stack gap="lg">
      <Text size="sm">{t('forwarding.help')}</Text>
      {/* Keyed by the version: a saved setting draws the form again, which empties the CA field. */}
      <ForwardingForm key={settings.version} settings={settings} busy={save.isPending} onSave={(b) => save.mutate(b)} fieldErrors={fieldErrorsOf(save.error, t, i18n)} />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
      <DeliveryState settings={settings} />
    </Stack>
  );
}

function DeliveryState({ settings }: { settings: Forwarding }) {
  const { t, i18n } = useTranslation();
  const reason = ERROR_REASONS[settings.last_error_code];
  const problem =
    reason && i18n.exists(`errors.${reason}.title`) ? t(`errors.${reason}.title`) : t('forwarding.unknownError', { code: settings.last_error_code });
  return (
    <Stack gap="xs">
      <Title order={2} size="h4">
        {t('forwarding.state')}
      </Title>
      <Text size="sm">{t('forwarding.backlog', { count: settings.backlog })}</Text>
      <Text size="sm">
        {settings.last_sent_at ? t('forwarding.lastSent', { time: formatDateTime(settings.last_sent_at, i18n.language) }) : t('forwarding.neverSent')}
      </Text>
      {settings.cursor_seq > 0 && <Text size="sm">{t('forwarding.cursor', { seq: settings.cursor_seq })}</Text>}
      {settings.last_error_code && (
        <Text size="sm" c="red.9">
          {t('forwarding.lastError', { time: formatDateTime(settings.last_error_at, i18n.language), problem })}
        </Text>
      )}
    </Stack>
  );
}

function ForwardingForm({
  settings,
  busy,
  onSave,
  fieldErrors,
}: {
  settings: Forwarding;
  busy: boolean;
  onSave: (b: ForwardingInput) => void;
  fieldErrors: Record<string, string>;
}) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [enabled, setEnabled] = useState(settings.enabled);
  const [host, setHost] = useState(settings.host);
  const [port, setPort] = useState<number | string>(settings.port || 6514);
  const [transport, setTransport] = useState<ForwardingTransport>(settings.transport || 'tls');
  const [caPem, setCaPem] = useState('');
  // removeCa sends ca_pem "" (C12: the stored CA bundle is removed); only offered while one is set.
  const [removeCa, setRemoveCa] = useState(false);
  // gcTime 0: the request (which may carry a CA certificate) is not kept in the mutation cache.
  const test = useMutation({ gcTime: 0, mutationFn: (body: ForwardingInput) => run(() => testForwarding(body)) });

  const input = (): ForwardingInput => ({
    enabled,
    host: host.trim(),
    port: Number(port),
    transport,
    ...(removeCa ? { ca_pem: '' } : caPem.trim() ? { ca_pem: caPem } : {}),
  });

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    onSave(input());
  };

  return (
    <form onSubmit={submit} data-testid="forwarding-form">
      <Stack gap="sm" maw={560}>
        <Checkbox label={t('forwarding.enabled')} checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        <TextInput label={t('forwarding.host')} value={host} onChange={(e) => setHost(e.currentTarget.value)} error={fieldErrors.host} autoComplete="off" spellCheck={false} />
        <NumberInput label={t('forwarding.port')} value={port} onChange={setPort} min={1} max={65535} allowDecimal={false} error={fieldErrors.port} />
        <NativeSelect
          label={t('forwarding.transport')}
          value={transport}
          onChange={(e) => setTransport(e.currentTarget.value as ForwardingTransport)}
          error={fieldErrors.transport}
          data={(['tls', 'tcp', 'udp'] as const).map((v) => ({ value: v, label: t(`forwarding.transports.${v}`) }))}
        />
        {settings.ca_set && (
          <>
            <Text size="sm" data-testid="forwarding-ca-set">
              {t('forwarding.caSet')}
            </Text>
            <Checkbox label={t('forwarding.removeCa')} checked={removeCa} onChange={(e) => setRemoveCa(e.currentTarget.checked)} />
          </>
        )}
        <Textarea
          label={t('forwarding.caPem')}
          description={t('forwarding.caPemHelp')}
          value={caPem}
          onChange={(e) => setCaPem(e.currentTarget.value)}
          error={fieldErrors.ca_pem}
          disabled={removeCa}
          autosize
          minRows={3}
          maxRows={8}
          spellCheck={false}
          autoComplete="off"
          styles={MONO}
        />
        <Group>
          <Button type="submit" loading={busy}>
            {t('forwarding.save')}
          </Button>
          <Button variant="default" loading={test.isPending} onClick={() => test.mutate(input())}>
            {t('forwarding.test')}
          </Button>
        </Group>
        {test.isSuccess && (
          <Text role="status" size="sm" c="teal.9">
            {t('forwarding.testSent')}
          </Text>
        )}
        <ErrorAlert error={test.error} />
      </Stack>
    </form>
  );
}
