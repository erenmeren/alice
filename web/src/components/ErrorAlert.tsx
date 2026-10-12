import { Alert, Code, List, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { ApiError, NetworkError } from '../api/client';
import { keyAlgorithmKey } from '../api/enums';
import { withRoleCode } from './CodeText';

// ErrorCodeLine writes the translated "Error code: {{code}}" with the code itself in a <Code translate="no">, wherever
// the language puts the placeholder (the sentence stays the translator's; nothing is assembled from parts).
function ErrorCodeLine({ code }: { code: string }) {
  const { t } = useTranslation();
  const mark = '\u0000';
  const [before, after = ''] = t('jobs.errorCode', { code: mark }).split(mark);
  return (
    <>
      {before}
      <Code translate="no">{code}</Code>
      {after}
    </>
  );
}

// ErrorAlert shows an error in the user's language: what happened, what to do, and the request ID.
export function ErrorAlert({ error }: { error: unknown }) {
  const { t, i18n } = useTranslation();
  if (!error) return null;

  if (!(error instanceof ApiError)) {
    // apiFetch wraps a rejected fetch or a dropped body read in NetworkError.
    if (error instanceof NetworkError) {
      return (
        <Alert color="red" role="alert" title={t('ui.networkErrorTitle')}>
          {t('ui.networkErrorAction')}
        </Alert>
      );
    }
    return <Alert color="red" role="alert" title={t('ui.unexpectedError')} />;
  }

  // A refusal of a session that has since been renewed (a step-up or a password change rotated the
  // cookie while this request was on its way): the person is still signed in and nothing changed.
  if (error.staleSession) {
    return (
      <Alert color="yellow" role="alert" title={t('ui.staleSessionTitle')}>
        <Text size="sm">{t('ui.staleSessionAction')}</Text>
      </Alert>
    );
  }

  const base = error.messageKey;
  // ALC-CRT-0010 carries raw key type codes (rsa, ecdsa); the person reads display names.
  const params: Record<string, string> = { ...error.params };
  const keyTypeMismatch = error.reason === 'certificate.key_type_mismatch';
  if (keyTypeMismatch) {
    for (const k of ['expected', 'actual']) if (k in params) params[k] = t(keyAlgorithmKey(params[k]));
  }
  const known = base !== '' && i18n.exists(`${base}.title`);
  // An unknown key still has the server's own text; with no key or no text there is only the generic message.
  const title = known
    ? t(`${base}.title`, params)
    : base !== '' && error.message
      ? error.message
      : t('ui.unexpectedError');
  const action = known && i18n.exists(`${base}.action`) ? t(`${base}.action`, params) : '';

  return (
    <Alert color="red" role="alert" title={withRoleCode(title, params.role)}>
      {/* The cause names the two key types, which is what the person needs to choose again; for an identity provider that
          could not be read it names the closed reason (params.cause). */}
      {known && (keyTypeMismatch || error.reason === 'sso.discovery_failed') && i18n.exists(`${base}.cause`) && <Text size="sm">{withRoleCode(t(`${base}.cause`, params), params.role)}</Text>}
      {action && <Text size="sm">{withRoleCode(action, params.role)}</Text>}
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
      {/* The stable ALC-* code (design: a failure states a stable error code), as JobErrorAlert shows it. */}
      {error.code && (
        <Text size="xs" c="dimmed" mt="xs">
          <ErrorCodeLine code={error.code} />
        </Text>
      )}
      {error.requestId && (
        <Text size="xs" c="dimmed" mt="xs">
          {t('ui.requestId', { id: error.requestId })}
        </Text>
      )}
    </Alert>
  );
}
