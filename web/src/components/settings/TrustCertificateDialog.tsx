import { Button, Code, Group, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { ApiError } from '../../api/client';
import { formatDateTime } from '../../datetime';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { WRAP } from '../wrap';

// TrustCertificateDialog shows the certificate the mail server presented (ALC-NTF-0005 carries its fingerprint, subject and
// expiry) and trusts exactly that fingerprint when the Administrator confirms. The test mail is not sent again until the
// person asks for it.
export function TrustCertificateDialog({
  error,
  busy,
  trustError,
  onTrust,
  onClose,
}: {
  error: ApiError;
  busy: boolean;
  trustError: unknown;
  onTrust: (fingerprint: string) => void;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { fingerprint = '', subject = '', not_after: notAfter = '' } = error.params;
  return (
    <AppModal opened onClose={onClose} title={t('settings.mail.untrustedTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('errors.notify.smtp_untrusted.action')}</Text>
        <div>
          <Text size="sm" fw={600}>
            {t('settings.mail.fingerprint')}
          </Text>
          <Code translate="no" style={WRAP}>
            {fingerprint}
          </Code>
        </div>
        <div>
          <Text size="sm" fw={600}>
            {t('settings.mail.subject')}
          </Text>
          <Code translate="no" style={WRAP}>
            {subject}
          </Code>
        </div>
        {notAfter && (
          <div>
            <Text size="sm" fw={600}>
              {t('settings.mail.expires')}
            </Text>
            <Text size="sm">{formatDateTime(notAfter, i18n.language)}</Text>
          </div>
        )}
        <ErrorAlert error={trustError} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button loading={busy} onClick={() => onTrust(fingerprint)} data-autofocus>
            {t('settings.mail.trust')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
