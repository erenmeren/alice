import { Checkbox, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { servicePolicyKey } from '../api/queryKeys';
import { getServicePolicy, type CanaryPolicy } from '../api/services';
import { isOutside, type OwnerService } from '../api/types';

// serviceIdOf is a row's owning service id ('' when the caller does not see it).
export const serviceIdOf = (s: OwnerService | null | undefined): string | undefined => (s && !isOutside(s) ? s.id : undefined);

// MAX_CANARY_WAVE1 is the most websites a first wave holds (authz.MaxCanaryWave1, final review C2).
const MAX_CANARY_WAVE1 = 19;

// canaryFirstWave is how many websites a canary deploys first (design §7): the policy's count (default 1) or the
// ceiling of its percentage, at least 1, never all of them and at most 19.
export function canaryFirstWave(c: CanaryPolicy, destinations: number): number {
  const k = c.subset?.percent !== undefined ? Math.ceil((destinations * c.subset.percent) / 100) : (c.subset?.count ?? 1);
  return Math.max(1, Math.min(k, destinations - 1, MAX_CANARY_WAVE1));
}

// useCanary reads the source service's canary key (undefined while it is unknown, off, or the service is not known).
export function useCanary(serviceId: string | undefined): CanaryPolicy | undefined {
  const policy = useQuery({
    queryKey: servicePolicyKey(serviceId ?? ''),
    queryFn: ({ signal }) => getServicePolicy(serviceId ?? '', signal),
    enabled: serviceId !== undefined && serviceId !== '',
    retry: false,
  });
  const c = policy.data?.body.canary;
  return c?.enabled ? c : undefined;
}

// CanaryChoice is the deploy dialogs' canary note (R65, design §19): when the source service's policy asks for a canary
// and two or more websites are chosen it says how many go first and how long Alice waits, and offers "Deploy to all at
// once" unless the policy forbids it (the request then asks for a fresh step-up).
export function CanaryChoice({
  serviceId,
  destinations,
  override,
  onOverride,
  disabled,
}: {
  serviceId: string | undefined;
  destinations: number;
  override: boolean;
  onOverride: (v: boolean) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const c = useCanary(serviceId);
  if (!c || destinations < 2) return null;
  return (
    <Stack gap={4} data-testid="canary-choice">
      {!override && (
        <Text size="sm" role="note" data-testid="canary-note">
          {t('canary.note', { count: canaryFirstWave(c, destinations), hold: c.hold ?? '10m' })}
        </Text>
      )}
      {c.override !== 'forbidden' && (
        <Checkbox
          label={t('canary.override')}
          description={t('canary.overrideHelp')}
          checked={override}
          onChange={(e) => onOverride(e.currentTarget.checked)}
          disabled={disabled}
          data-testid="canary-override"
        />
      )}
    </Stack>
  );
}
