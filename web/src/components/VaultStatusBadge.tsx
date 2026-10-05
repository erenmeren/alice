import { Badge } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { Target } from '../api/types';
import { vaultStatusKey } from './vaultText';

// The colour is a cue only; the text always names the status.
const COLORS: Record<string, string> = { ok: 'green', checking: 'blue', degraded: 'orange', unreachable: 'orange', auth_failed: 'red', disabled: 'gray' };

export function VaultStatusBadge({ target, testId }: { target: Pick<Target, 'status' | 'last_error' | 'vault'>; testId?: string }) {
  const { t } = useTranslation();
  // tt="none": no CSS upper-casing of translated text (Turkish dotted/dotless i).
  return (
    <Badge variant="light" color={COLORS[target.status] ?? 'gray'} tt="none" data-testid={testId}>
      {t(vaultStatusKey(target))}
    </Badge>
  );
}
