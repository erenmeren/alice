import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { listAllTargets } from '../../api/endpoints';
import type { Condition } from '../../api/phase7';
import { VAULTS_KEY } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import type { IconName } from '../../design/Icon';

// The condition → attention item mapping (plan C6), shared by the dashboard's "Needs attention" and the top bar's bell.

// conditionTarget is where the person goes to deal with a condition, by kind. A kind this version does not know is
// skipped, never shown raw. A failed sign-in can be a Key Vault's (its page is /key-vaults/<id>); a changed host key is
// always a server's.
export function conditionTarget(c: Condition, vaultIds: ReadonlySet<string>): string | null {
  switch (c.kind) {
    case 'auth_failed':
      if (vaultIds.has(c.object_id)) return `/key-vaults/${encodeURIComponent(c.object_id)}`;
      return `/servers/${encodeURIComponent(c.object_id)}`;
    case 'host_key_changed':
      return `/servers/${encodeURIComponent(c.object_id)}`;
    case 'deployment_failed':
      return `/deployments/${encodeURIComponent(c.object_id)}`;
    case 'audit_broken':
      return '/audit';
    case 'notifications_failing':
      return '/settings?tab=mail';
    default:
      return null;
  }
}

// conditionLabel is the condition's title from the catalog; null for a kind this version does not know.
export function conditionLabel(c: Condition, t: TFunction | ((k: string) => string)): string | null {
  switch (c.kind) {
    case 'host_key_changed':
      return t('enum.targetStatus.host_key_changed');
    case 'auth_failed':
      return t('enum.targetStatus.auth_failed');
    case 'deployment_failed':
      return t('enum.deploymentStatus.failed');
    case 'audit_broken':
      return t('dashboard.auditBroken');
    case 'notifications_failing':
      return t('notifications.failingTitle');
    default:
      return null;
  }
}

export const CONDITION_ICON: Record<string, IconName> = {
  host_key_changed: 'Fingerprint',
  auth_failed: 'ShieldAlert',
  deployment_failed: 'Rocket',
  audit_broken: 'ScrollText',
  notifications_failing: 'Mail',
};

const DANGER = new Set(['host_key_changed', 'auth_failed', 'audit_broken']);

// conditionTone: an identity, sign-in or integrity problem is danger; a failed deployment or failing e-mail a warning.
export function conditionTone(c: Condition): 'danger' | 'warning' {
  return DANGER.has(c.kind) ? 'danger' : 'warning';
}

export interface ConditionItem {
  key: string;
  tone: 'danger' | 'warning';
  icon: IconName;
  title: string;
  name: string;
  since: string;
  to: string | null;
}

// useConditionItems turns the known conditions into attention items. The vaults are read only when an authentication
// failure is listed: the condition does not say which kind of target it is.
export function useConditionItems(items: Condition[]): ConditionItem[] {
  const { t, i18n } = useTranslation();
  const known = items.filter((c) => conditionLabel(c, t) !== null);
  const vaults = useQuery({
    queryKey: [...VAULTS_KEY, 'attention'],
    queryFn: () => listAllTargets('azure_key_vault'),
    enabled: known.some((c) => c.kind === 'auth_failed'),
  });
  const vaultIds = new Set((vaults.data?.items ?? []).map((v) => v.id));
  return known.map((c) => ({
    key: `${c.kind}:${c.object_id}`,
    tone: conditionTone(c),
    icon: CONDITION_ICON[c.kind] ?? 'CircleAlert',
    title: conditionLabel(c, t) ?? '',
    name: c.name,
    since: t('dashboard.since', { time: formatDateTime(c.since, i18n.language) }),
    to: conditionTarget(c, vaultIds),
  }));
}
