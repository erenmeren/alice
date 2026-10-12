import { Anchor } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { StatusBadge } from '../ui';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// LicenseCard: Administrators and Auditors see the phase, the end date and the days left; an Operator (phase "") sees
// only that the license expired, and nothing otherwise.
export function LicenseCard({ license, detailed }: { license: DashboardSummary['license']; detailed: boolean }) {
  const { t, i18n } = useTranslation();
  if (!detailed && !license.expired) return null;
  const phase = license.phase && i18n.exists(`license.phase.${license.phase}`) ? t(`license.phase.${license.phase}`) : null;
  return (
    <Widget
      title={t('dashboard.license')}
      testId="license-card"
      action={
        phase ? (
          <StatusBadge tone={license.expired ? 'danger' : 'success'} icon={license.expired ? 'CircleAlert' : 'ShieldCheck'}>
            {phase}
          </StatusBadge>
        ) : (
          license.expired && (
            <StatusBadge tone="danger" icon="CircleAlert">
              {t('dashboard.expired')}
            </StatusBadge>
          )
        )
      }
      footer={
        detailed && (
          <Anchor component={Link} to="/license" size="xs">
            {t('nav.license')}
          </Anchor>
        )
      }
    >
      {detailed && license.days_left !== null && <span className={classes.largeValue}>{t('dashboard.daysLeft', { count: license.days_left })}</span>}
      {detailed && license.ends_at && <p className={classes.caption}>{t('dashboard.licenseEnds', { date: formatDateTime(license.ends_at, i18n.language) })}</p>}
    </Widget>
  );
}
