import { Button, Code, Image, Stack, Text, TextInput, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { MfaEnrollment } from '../api/types';
import { ErrorAlert } from './ErrorAlert';

interface Props {
  enrollment: MfaEnrollment;
  // onVerify sends the code to the server; a rejected promise is shown as an error.
  onVerify: (code: string) => Promise<void>;
}

// TotpEnrollment shows the QR code and key for an authenticator app and asks for the first code.
export function TotpEnrollment({ enrollment, onVerify }: Props) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onVerify(code.trim());
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        <Title order={2}>{t('ui.totp.title')}</Title>
        <Text>{t('ui.totp.help')}</Text>
        <Image
          src={`data:image/png;base64,${enrollment.qr_png}`}
          alt={t('ui.totp.qrAlt')}
          w={200}
          h={200}
          fit="contain"
        />
        <Text size="sm">{t('ui.totp.manual')}</Text>
        <Code block data-testid="totp-secret">
          {enrollment.secret}
        </Code>
        <ErrorAlert error={error} />
        <TextInput
          label={t('ui.codeLabel')}
          value={code}
          onChange={(e) => setCode(e.currentTarget.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
        />
        <Button type="submit" loading={busy}>
          {t('ui.verify')}
        </Button>
      </Stack>
    </form>
  );
}
