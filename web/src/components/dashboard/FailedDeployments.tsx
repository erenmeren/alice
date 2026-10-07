import { Anchor, Code, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { WRAP } from '../wrap';
import { Widget } from './Widget';

export function FailedDeployments({ deployments }: { deployments: DashboardSummary['deployments'] }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget title={t('dashboard.failedDeployments')} testId="failed-deployments">
      <Stack gap="xs">
        <Text size="sm">{t('dashboard.failedCount', { count: deployments.failed_7d })}</Text>
        {deployments.recent.length === 0 && <Text c="gray.7">{t('dashboard.noFailed')}</Text>}
        {deployments.recent.map((d) => (
          <div key={d.id}>
            <Anchor component={Link} to={`/deployments/${encodeURIComponent(d.id)}`}>
              <Code translate="no" style={WRAP}>
                {d.certificate_name}
              </Code>
            </Anchor>{' '}
            <Code translate="no" style={WRAP}>
              {d.target_name}
            </Code>
            <Text size="xs" c="gray.7">
              {formatDateTime(d.at, i18n.language)}
            </Text>
          </div>
        ))}
      </Stack>
    </Widget>
  );
}
