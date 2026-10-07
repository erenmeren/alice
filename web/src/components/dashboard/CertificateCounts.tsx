import { Anchor, Badge, Group, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { Widget } from './Widget';

// CertificateCounts shows cumulative windows with the list filter's own meaning (expiry=N lists everything that ends
// before now + N days, the expired included), so each count equals the rows its link opens.
export function CertificateCounts({ counts }: { counts: DashboardSummary['certificates'] }) {
  const { t } = useTranslation();
  const lines = [
    { key: 'dashboard.expired', n: counts.expired, color: 'red', to: '/certificates?expiry=expired' },
    { key: 'dashboard.within7', n: counts.within_7, color: 'orange', to: '/certificates?expiry=7' },
    { key: 'dashboard.within30', n: counts.within_30, color: 'yellow', to: '/certificates?expiry=30' },
    { key: 'dashboard.within60', n: counts.within_60, color: 'gray', to: '/certificates?expiry=60' },
  ];
  // Cumulative as well: kv_within_30 already includes the expired Key Vault items.
  const kv = counts.kv_within_30;
  return (
    <Widget title={t('nav.certificates')} testId="dashboard-counts">
      <Stack gap="xs">
        {lines.map((l) => (
          <Anchor key={l.key} component={Link} to={l.to}>
            <Group gap="xs" wrap="nowrap">
              <span>{t(l.key)}</span>
              <Badge variant="light" color={l.color} tt="none" miw={36}>
                {l.n}
              </Badge>
            </Group>
          </Anchor>
        ))}
        <Text size="sm">{t('dashboard.monitored', { count: counts.monitored })}</Text>
        {kv > 0 && (
          <Anchor component={Link} to="/key-vaults" size="sm">
            {t('dashboard.kvExpiring', { count: kv })}
          </Anchor>
        )}
      </Stack>
    </Widget>
  );
}
