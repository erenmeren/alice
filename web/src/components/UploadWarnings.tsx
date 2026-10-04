import { Alert, Stack } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { uploadWarningKey } from '../api/enums';

// UploadWarnings lists what did not block an upload or a signing request's completion
// (an incomplete chain, an expired chain certificate, a start date in the future, other names).
export function UploadWarnings({ warnings }: { warnings: string[] }) {
  const { t } = useTranslation();
  if (warnings.length === 0) return null;
  return (
    <Stack gap="xs">
      {warnings.map((w) => (
        <Alert key={w} color="yellow" role="status">
          {t(uploadWarningKey(w))}
        </Alert>
      ))}
    </Stack>
  );
}
