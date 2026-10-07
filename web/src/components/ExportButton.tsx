import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { exportUrl } from '../api/phase7';

// ExportButton downloads the list as CSV with the filters now in the address. It is a plain download (the file is
// streamed by the server and never passes through the page's memory), as the audit export.
export function ExportButton({ kind, filters }: { kind: 'certificates' | 'ssh-keys'; filters: Record<string, string> }) {
  const { t } = useTranslation();
  return (
    <Button component="a" href={exportUrl(kind, filters)} download variant="default">
      {t('filters.export')}
    </Button>
  );
}
