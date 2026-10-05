import { Loader } from '@mantine/core';
import { useTranslation } from 'react-i18next';

// LoadingIndicator is a spinner with an accessible name: the name sits on a status wrapper (a bare
// aria-label on the spinner's span has no role to name), and the spinner itself is hidden.
export function LoadingIndicator() {
  const { t } = useTranslation();
  return (
    <span role="status" aria-label={t('ui.loading')} style={{ display: 'inline-flex' }}>
      <Loader size="sm" aria-hidden />
    </span>
  );
}
