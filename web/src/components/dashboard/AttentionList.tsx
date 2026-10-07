import { Anchor, Code, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { Condition } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { WRAP } from '../wrap';
import { Widget } from './Widget';

// Where the person goes to deal with a condition, by kind. A kind this version does not know is skipped, never shown raw.
function target(c: Condition): string | null {
  switch (c.kind) {
    case 'host_key_changed':
    case 'auth_failed':
      return `/servers/${encodeURIComponent(c.object_id)}`;
    case 'deployment_failed':
      return `/deployments/${encodeURIComponent(c.object_id)}`;
    case 'audit_broken':
      return '/audit';
    case 'notifications_failing':
      return '/settings?tab=mail';
    default:
      return null;
  }
}

function label(c: Condition, t: (k: string) => string): string | null {
  switch (c.kind) {
    case 'host_key_changed':
      return t('enum.targetStatus.host_key_changed');
    case 'auth_failed':
      return t('enum.targetStatus.auth_failed');
    case 'deployment_failed':
      return t('enum.deploymentStatus.failed');
    case 'audit_broken':
      return t('dashboard.auditBroken');
    case 'notifications_failing':
      return t('notifications.failingTitle');
    default:
      return null;
  }
}

export function AttentionList({ items }: { items: Condition[] }) {
  const { t, i18n } = useTranslation();
  const shown = items.filter((c) => label(c, t) !== null);
  return (
    <Widget title={t('dashboard.needsAttention')} testId="attention-list">
      {shown.length === 0 ? (
        <Text c="gray.7">{t('dashboard.noAttention')}</Text>
      ) : (
        <Stack gap="xs">
          {shown.map((c) => {
            const to = target(c);
            const text = label(c, t);
            return (
              <div key={`${c.kind}:${c.object_id}`}>
                {to ? <Anchor component={Link} to={to}>{text}</Anchor> : <Text>{text}</Text>}{' '}
                {c.name && (
                  <Code translate="no" style={WRAP}>
                    {c.name}
                  </Code>
                )}
                <Text size="xs" c="gray.7">
                  {t('dashboard.since', { time: formatDateTime(c.since, i18n.language) })}
                </Text>
              </div>
            );
          })}
        </Stack>
      )}
    </Widget>
  );
}
