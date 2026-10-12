import { Alert, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Icon } from '../design/Icon';

// SSOErrorAlert tells why a single sign-on or a step-up at the identity provider was refused. The reason is one of the
// closed set of the callback (ssoErrorReason), so its texts exist: errors.<reason>.title and .action.
export function SSOErrorAlert({ reason, onClose }: { reason: string; onClose?: () => void }) {
  const { t } = useTranslation();
  return (
    <Alert color="red" role="alert" icon={<Icon name="CircleAlert" size={17} />} title={t(`errors.${reason}.title`)} withCloseButton={!!onClose} onClose={onClose} closeButtonLabel={t('ui.close')} data-testid="sso-error">
      <Text size="sm">{t(`errors.${reason}.action`)}</Text>
    </Alert>
  );
}
