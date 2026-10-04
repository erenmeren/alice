import { Alert, Stack } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { CHAIN_COMPLETED, uploadWarningKey } from '../api/enums';

// UploadWarnings lists what did not block an upload or a signing request's completion
// (an incomplete chain, an expired chain certificate, a start date in the future, other names).
// chain_completed is not a warning but the result of the upload: the dialog says it in its place.
export function UploadWarnings({ warnings }: { warnings: string[] }) {
  const { t } = useTranslation();
  const shown = warnings.filter((w) => w !== CHAIN_COMPLETED);
  if (shown.length === 0) return null;
  return (
    <Stack gap="xs">
      {shown.map((w) => (
        <Alert key={w} color="yellow" role="status">
          {t(uploadWarningKey(w))}
        </Alert>
      ))}
    </Stack>
  );
}
