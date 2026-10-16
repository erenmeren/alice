import { Alert, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Icon } from '../design/Icon';

// SSOErrorAlert tells why a single sign-on or a step-up at the identity provider was refused. The reason is one of the
// closed set of the callback (ssoErrorReason), so its texts exist: errors.<reason>.title and .action. The sign-in page
// uses it for a refused directory sign-in too (ldap.signin_refused, ldap.directory_unavailable): title and action only,
// so no answer can show a variation (no cause, code or request ID).
export function SSOErrorAlert({ reason, onClose, testId = 'sso-error' }: { reason: string; onClose?: () => void; testId?: string }) {
  const { t } = useTranslation();
  return (
    <Alert color="red" role="alert" icon={<Icon name="CircleAlert" size={17} />} title={t(`errors.${reason}.title`)} withCloseButton={!!onClose} onClose={onClose} closeButtonLabel={t('ui.close')} data-testid={testId}>
      <Text size="sm">{t(`errors.${reason}.action`)}</Text>
    </Alert>
  );
}
