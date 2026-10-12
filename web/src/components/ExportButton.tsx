import { Button, Stack } from '@mantine/core';
import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { exportCsv } from '../api/phase7';
import { Icon } from '../design/Icon';
import { ErrorAlert } from './ErrorAlert';
import { saveBlob } from './saveBlob';

// ExportButton downloads the list as CSV with the filters now in the address. The file is fetched first: a refusal of the
// server (too large, another export running, a rate limit) is JSON and is shown as an error, never saved as the CSV file.
// The export is capped at 50,000 rows, so the file in memory is small.
export function ExportButton({ kind, filters }: { kind: 'certificates' | 'ssh-keys'; filters: Record<string, string> }) {
  const { t } = useTranslation();
  const exporting = useMutation({
    mutationFn: () => exportCsv(kind, filters),
    onSuccess: (blob) => saveBlob(blob, `alice-${kind}-${new Date().toISOString().slice(0, 10)}.csv`),
  });
  return (
    <Stack gap="xs" align="flex-start">
      <Button variant="default" leftSection={<Icon name="Download" size={15} />} loading={exporting.isPending} onClick={() => exporting.mutate()}>
        {t('filters.export')}
      </Button>
      <ErrorAlert error={exporting.error} />
    </Stack>
  );
}
