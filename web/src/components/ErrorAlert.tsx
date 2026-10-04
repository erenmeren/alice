import { Alert, List, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { ApiError, NetworkError } from '../api/client';

// ErrorAlert shows an error in the user's language: what happened, what to do, and the request ID.
export function ErrorAlert({ error }: { error: unknown }) {
  const { t, i18n } = useTranslation();
  if (!error) return null;

  if (!(error instanceof ApiError)) {
    // fetch() rejects when the network or the server is unreachable (apiFetch wraps it in NetworkError).
    if (error instanceof NetworkError || error instanceof TypeError) {
      return (
        <Alert color="red" role="alert" title={t('ui.networkErrorTitle')}>
          {t('ui.networkErrorAction')}
        </Alert>
      );
    }
    return <Alert color="red" role="alert" title={t('ui.unexpectedError')} />;
  }

  const base = error.messageKey;
  const known = base !== '' && i18n.exists(`${base}.title`);
  // An unknown key still has the server's own text; with no key or no text there is only the generic message.
  const title = known
    ? t(`${base}.title`, error.params)
    : base !== '' && error.message
      ? error.message
      : t('ui.unexpectedError');
  const action = known && i18n.exists(`${base}.action`) ? t(`${base}.action`, error.params) : '';

  return (
    <Alert color="red" role="alert" title={title}>
      {action && <Text size="sm">{action}</Text>}
      {error.details.length > 0 && (
        <List size="sm" mt="xs">
          {error.details.map((d) => (
            <List.Item key={`${d.field}-${d.code}`}>
              {t('ui.fieldProblem', {
                field: i18n.exists(`ui.fields.${d.field}`) ? t(`ui.fields.${d.field}`) : d.field,
                problem: i18n.exists(d.code) ? t(d.code, d.params) : t('ui.unexpectedError'),
              })}
            </List.Item>
          ))}
        </List>
      )}
      {error.requestId && (
        <Text size="xs" c="gray.7" mt="xs">
          {t('ui.requestId', { id: error.requestId })}
        </Text>
      )}
    </Alert>
  );
}
