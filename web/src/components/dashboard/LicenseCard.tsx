import { Anchor, Badge, Group, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { Widget } from './Widget';

// LicenseCard: Administrators and Auditors see the phase, the end date and the days left; an Operator (phase "") sees
// only that the license expired, and nothing otherwise.
export function LicenseCard({ license, detailed }: { license: DashboardSummary['license']; detailed: boolean }) {
  const { t, i18n } = useTranslation();
  if (!detailed && !license.expired) return null;
  return (
    <Widget title={t('dashboard.license')} testId="license-card">
      <Stack gap="xs">
        <Group gap="xs">
          {license.phase && i18n.exists(`license.phase.${license.phase}`) && (
            <Badge variant="light" color={license.expired ? 'red' : 'green'} tt="none">
              {t(`license.phase.${license.phase}`)}
            </Badge>
          )}
          {license.expired && !license.phase && (
            <Badge variant="light" color="red" tt="none">
              {t('dashboard.expired')}
            </Badge>
          )}
        </Group>
        {detailed && license.ends_at && <Text size="sm">{t('dashboard.licenseEnds', { date: formatDateTime(license.ends_at, i18n.language) })}</Text>}
        {detailed && license.days_left !== null && <Text size="sm">{t('dashboard.daysLeft', { count: license.days_left })}</Text>}
        {detailed && (
          <Anchor component={Link} to="/license" size="sm">
            {t('nav.license')}
          </Anchor>
        )}
      </Stack>
    </Widget>
  );
}
