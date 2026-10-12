import { Anchor, SegmentedControl } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { Panel, StatusBadge } from '../ui';
import classes from './dashboard.module.css';

type Counts = DashboardSummary['certificates'];
export type BucketKey = 'expired' | 'd7' | 'd30' | 'd60';

// exclusiveBuckets turns the summary's cumulative windows (each includes the expired certificates and every shorter
// window) into mutually exclusive buckets (IMPLEMENTATION §3): expired, within_7 − expired, within_30 − within_7,
// within_60 − within_30. A window the server reports smaller than the one inside it gives 0, never a negative bar. The
// Key Vault keys and secrets (kv_*) are a different inventory and never enter these buckets.
export function exclusiveBuckets(c: Counts): { key: BucketKey; count: number }[] {
  return [
    { key: 'expired', count: c.expired },
    { key: 'd7', count: Math.max(0, c.within_7 - c.expired) },
    { key: 'd30', count: Math.max(0, c.within_30 - c.within_7) },
    { key: 'd60', count: Math.max(0, c.within_60 - c.within_30) },
  ];
}

const WINDOWS = ['7', '30', '60'] as const;
type Window = (typeof WINDOWS)[number];
const BAR_LABEL: Record<BucketKey, string> = { expired: 'dashboard.expired', d7: 'dashboard.horizon.d7', d30: 'dashboard.horizon.d30', d60: 'dashboard.horizon.d60' };
// The tallest bar's height in pixels; an empty bucket keeps the 3 px baseline mark.
const BAR_MAX = 96;
const BAR_MIN = 3;

// ExpiryHorizon is the design's "Expiration horizon" (R12): the four exclusive buckets the summary allows as bars, the
// chosen cumulative window as the headline number, and the cumulative links of the certificate list (each opens exactly
// the certificates it counts, the expired included).
export function ExpiryHorizon({ counts }: { counts: Counts }) {
  const { t } = useTranslation();
  const [days, setDays] = useState<Window>('30');
  const buckets = exclusiveBuckets(counts);
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const cumulative: Record<Window, number> = { '7': counts.within_7, '30': counts.within_30, '60': counts.within_60 };
  const byKey = Object.fromEntries(buckets.map((b) => [b.key, b.count])) as Record<BucketKey, number>;
  const links = [
    { key: 'dashboard.expired', n: counts.expired, to: '/certificates?expiry=expired' },
    { key: 'dashboard.within7', n: counts.within_7, to: '/certificates?expiry=7' },
    { key: 'dashboard.within30', n: counts.within_30, to: '/certificates?expiry=30' },
    { key: 'dashboard.within60', n: counts.within_60, to: '/certificates?expiry=60' },
  ];
  // Cumulative as well: kv_within_30 already includes the expired Key Vault items.
  const kv = counts.kv_within_30;
  return (
    <Panel
      testId="dashboard-counts"
      aria-label={t('dashboard.horizon.title')}
      title={t('dashboard.horizon.title')}
      description={t('dashboard.horizon.subtitle')}
      padded={false}
      action={
        <SegmentedControl
          size="xs"
          aria-label={t('dashboard.horizon.window')}
          value={days}
          onChange={(v) => setDays(v as Window)}
          data={WINDOWS.map((d) => ({ value: d, label: t('dashboard.horizon.days', { days: d }) }))}
        />
      }
    >
      <div className={classes.horizon}>
        <div className={classes.horizonSummary} data-testid="horizon-headline">
          <span className={classes.horizonNumber}>{cumulative[days]}</span>
          <p className={classes.horizonText}>{t('dashboard.horizon.headline', { days })}</p>
          {counts.expired > 0 && (
            <StatusBadge tone="danger" icon="CircleAlert">
              {t('dashboard.expired')} {counts.expired}
            </StatusBadge>
          )}
        </div>
        <div className={classes.horizonChart}>
          <div className={classes.bars} role="img" aria-label={t('dashboard.horizon.chart', byKey)}>
            {buckets.map((b) => (
              <div key={b.key} className={classes.barColumn}>
                <span className={classes.barNumber}>{b.count}</span>
                <span className={classes.bar} data-bucket={b.key} style={{ height: `${b.count ? Math.max(BAR_MIN, Math.round((b.count / max) * BAR_MAX)) : BAR_MIN}px` }} />
              </div>
            ))}
          </div>
          <div className={classes.chartLabels} aria-hidden="true">
            {buckets.map((b) => (
              <span key={b.key}>{t(BAR_LABEL[b.key])}</span>
            ))}
          </div>
        </div>
      </div>
      <div className={classes.horizonKey}>
        {links.map((l) => (
          <Anchor key={l.key} component={Link} to={l.to} className={classes.countLink}>
            {t(l.key)} <b>{l.n}</b>
          </Anchor>
        ))}
        <span className={classes.keyText}>{t('dashboard.monitored', { count: counts.monitored })}</span>
        {kv > 0 && (
          <Anchor component={Link} to="/key-vaults" className={classes.countLink}>
            {t('dashboard.kvExpiring', { count: kv })}
          </Anchor>
        )}
        <p className={classes.keyNote}>{t('dashboard.horizon.cumulative')}</p>
      </div>
    </Panel>
  );
}
