import { Badge } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { TargetStatus } from '../api/types';

// The color is a cue only; the text always names the status.
const COLORS: Record<TargetStatus, string> = {
  ok: 'green',
  checking: 'blue',
  pending_host_key: 'yellow',
  unreachable: 'orange',
  host_key_changed: 'red',
  auth_failed: 'red',
  disabled: 'gray',
};

export function TargetStatusBadge({ status, testId }: { status: TargetStatus; testId?: string }) {
  const { t } = useTranslation();
  // tt="none": no CSS upper-casing of translated text (Turkish dotted/dotless i, spec §10.5).
  return (
    <Badge variant="light" color={COLORS[status] ?? 'gray'} tt="none" data-testid={testId}>
      {t(`enum.targetStatus.${status}`)}
    </Badge>
  );
}
