import { useTranslation } from 'react-i18next';
import type { TargetStatus } from '../api/types';
import { StatusBadge, TARGET_ICON, TARGET_TONE } from './ui';

// TargetStatusBadge names a server's connection state: text + icon (or dot) + tone, never color alone.
export function TargetStatusBadge({ status, testId }: { status: TargetStatus; testId?: string }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={TARGET_TONE[status] ?? 'neutral'} icon={TARGET_ICON[status]} testId={testId}>
      {t(`enum.targetStatus.${status}`)}
    </StatusBadge>
  );
}
