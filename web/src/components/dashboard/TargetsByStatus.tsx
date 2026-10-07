import { Anchor, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { Widget } from './Widget';

// TargetsByStatus lists the statuses that have at least one target, labelled by the existing target status texts.
export function TargetsByStatus({ targets }: { targets: DashboardSummary['targets'] }) {
  const { t, i18n } = useTranslation();
  const rows = Object.entries(targets.by_status)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => a.localeCompare(b));
  return (
    <Widget title={t('dashboard.targetsByStatus')} testId="targets-by-status">
      {rows.length === 0 ? (
        <Text c="gray.7">{t('dashboard.noTargets')}</Text>
      ) : (
        <Stack gap="xs">
          {rows.map(([status, n]) => (
            <Anchor key={status} component={Link} to="/servers">
              {t('dashboard.statusCount', { status: i18n.exists(`enum.targetStatus.${status}`) ? t(`enum.targetStatus.${status}`) : status, count: n })}
            </Anchor>
          ))}
        </Stack>
      )}
    </Widget>
  );
}
