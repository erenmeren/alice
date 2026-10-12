import { useTranslation } from 'react-i18next';
import type { Target } from '../api/types';
import { StatusBadge, TARGET_ICON, TARGET_TONE } from './ui';
import { vaultStatusKey } from './vaultText';

// VaultStatusBadge names a vault's state in its own words (vaultStatusKey): text + icon (or dot) + tone, never color alone.
export function VaultStatusBadge({ target, testId }: { target: Pick<Target, 'status' | 'last_error' | 'vault'>; testId?: string }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={TARGET_TONE[target.status] ?? 'neutral'} icon={TARGET_ICON[target.status]} testId={testId}>
      {t(vaultStatusKey(target))}
    </StatusBadge>
  );
}
