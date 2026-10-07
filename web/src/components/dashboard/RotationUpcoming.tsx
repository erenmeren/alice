import { Anchor, Code, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { WRAP } from '../wrap';
import { Widget } from './Widget';

export function RotationUpcoming({ rotation }: { rotation: DashboardSummary['rotation'] }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget title={t('dashboard.rotationUpcoming')} testId="rotation-upcoming">
      <Stack gap="xs">
        {rotation.upcoming.length === 0 && <Text c="gray.7">{t('dashboard.noUpcoming')}</Text>}
        {rotation.upcoming.map((r) => (
          <div key={r.policy_id}>
            <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(r.ssh_key_id)}`}>
              <Code translate="no" style={WRAP}>
                {r.key_label}
              </Code>
            </Anchor>
            <Text size="xs" c="gray.7">
              {formatDateTime(r.next_run_at, i18n.language)}
            </Text>
          </div>
        ))}
        <Text size="sm">{t('dashboard.rotationRunning', { count: rotation.running })}</Text>
        <Text size="sm">{t('dashboard.rotationAttention', { count: rotation.needs_attention })}</Text>
      </Stack>
    </Widget>
  );
}
