import { Alert, Anchor, Stack } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getLicenseStatus } from '../api/endpoints';
import type { BannerSeverity, LicenseBanner } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { formatDateTime } from '../datetime';

export const LICENSE_STATUS_KEY = ['license', 'status'] as const;

// Colors of spec §19.3: blue information, yellow warning, orange for the last days, red when expired.
const COLORS: Record<BannerSeverity, string> = { info: 'blue', warning: 'yellow', caution: 'orange', danger: 'red' };

// Banner parameters that are instants; they are shown in the reader's language and time zone.
const TIME_PARAMS = new Set(['ends_at', 'ended_at', 'valid_until', 'valid_from', 'locks_at', 'system_time', 'last_seen']);

// bannerValues turns the server's parameters into translation values. days_left and
// jump_days also become "count", so i18next picks the singular or plural sentence.
export function bannerValues(b: LicenseBanner, lang: string): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(b.params)) out[k] = TIME_PARAMS.has(k) ? formatDateTime(v, lang) : v;
  if (b.params.days_left !== undefined) out.count = Number(b.params.days_left);
  if (b.params.jump_days !== undefined) out.count = Number(b.params.jump_days);
  return out;
}

// LicenseBanners shows the license messages of spec §19.3 on every signed-in screen. The
// server decides who sees what (warnings only for Administrators, L-15). Text always comes
// from the catalog; a kind this version does not know is skipped, never shown raw.
// The status is refreshed every minute; failed refreshes follow the shared retry policy and
// keep showing the last answer.
export function LicenseBanners() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const status = useQuery({ queryKey: LICENSE_STATUS_KEY, queryFn: getLicenseStatus, refetchInterval: 60_000, enabled: !!session });
  if (!status.data) return null;
  const admin = session?.user.role === 'admin';
  const shown = status.data.banners
    .map((b) => ({ b, key: `license.banner.${b.kind}`, values: bannerValues(b, i18n.language) }))
    .filter(({ key, values }) => i18n.exists(key, values));
  if (shown.length === 0) return null;
  return (
    <Stack gap="xs" mb="md">
      {shown.map(({ b, key, values }) => (
        <Alert
          key={b.kind}
          color={COLORS[b.severity] ?? 'blue'}
          role={b.severity === 'danger' ? 'alert' : 'status'}
          data-testid={`license-banner-${b.kind}`}
          style={{ overflowWrap: 'anywhere' }}
        >
          {t(key, values)}
          {admin && (
            <>
              {' '}
              <Anchor component={Link} to="/license" c="black" underline="always">
                {t('license.banner.open')}
              </Anchor>
            </>
          )}
        </Alert>
      ))}
    </Stack>
  );
}
