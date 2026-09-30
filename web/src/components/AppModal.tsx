import { Modal, type ModalProps } from '@mantine/core';
import { useTranslation } from 'react-i18next';

// AppModal is Mantine's Modal with a translated name on its icon-only close button
// (axe "button-name": a button without an accessible name is a critical violation).
export function AppModal({ closeButtonProps, ...props }: ModalProps) {
  const { t } = useTranslation();
  return <Modal closeButtonProps={{ 'aria-label': t('ui.close'), ...closeButtonProps }} {...props} />;
}
