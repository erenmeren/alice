import { Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { CodeText } from '../CodeText';
import { WRAP } from '../wrap';
import { Widget } from './Widget';

// AuditHead is shown to Administrators and Auditors (audit is null for Operators and for an empty log: then hidden).
export function AuditHead({ audit }: { audit: NonNullable<DashboardSummary['audit']> }) {
  const { t, i18n } = useTranslation();
  return (
    <Widget title={t('dashboard.auditHead')} testId="audit-head">
      <Stack gap="xs">
        <Text size="sm">{t('dashboard.auditSeq', { seq: audit.head_seq })}</Text>
        <Text size="sm" style={WRAP}>
          <CodeText i18nKey="dashboard.hash" param="hash" value={audit.head_hash} />
        </Text>
        {audit.checked_at && <Text size="sm">{t('dashboard.auditChecked', { time: formatDateTime(audit.checked_at, i18n.language) })}</Text>}
        {!audit.intact && (
          <Text size="sm" c="red.8" role="alert">
            {t('dashboard.auditBroken')}
          </Text>
        )}
        <Text size="sm" c="gray.7">
          {t('dashboard.auditHeadHelp')}
        </Text>
      </Stack>
    </Widget>
  );
}
