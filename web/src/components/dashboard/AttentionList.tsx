import { Anchor, Code, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listAllTargets } from '../../api/endpoints';
import type { Condition } from '../../api/phase7';
import { VAULTS_KEY } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import { WRAP } from '../wrap';
import { conditionLabel as label, conditionTarget as target } from './conditions';
import { Widget } from './Widget';

export function AttentionList({ items }: { items: Condition[] }) {
  const { t, i18n } = useTranslation();
  const shown = items.filter((c) => label(c, t) !== null);
  // The vaults are read only when an authentication failure is listed: the condition does not say which kind of target it is.
  const vaults = useQuery({ queryKey: [...VAULTS_KEY, 'attention'], queryFn: () => listAllTargets('azure_key_vault'), enabled: shown.some((c) => c.kind === 'auth_failed') });
  const vaultIds = new Set((vaults.data?.items ?? []).map((v) => v.id));
  return (
    <Widget title={t('dashboard.needsAttention')} testId="attention-list">
      {shown.length === 0 ? (
        <Text c="gray.7">{t('dashboard.noAttention')}</Text>
      ) : (
        <Stack gap="xs">
          {shown.map((c) => {
            const to = target(c, vaultIds);
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
