import { Button, CopyButton, Group, Stack, Textarea } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { CSR } from '../api/types';
import { Icon } from '../design/Icon';

// csrFileName is a safe file name for a request: a wildcard name has no "*", and anything outside
// letters, digits, dot, dash and underscore becomes "_" (no path separators, no leading dot).
export function csrFileName(commonName: string): string {
  const base = commonName
    .replace(/\*/g, 'wildcard')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/^\.+/, '');
  return `${base || 'request'}.csr`;
}

// downloadText saves text as a file through a temporary link (the pattern RecoveryCodes uses).
function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// CSRPem shows a signing request's PEM to copy or download. A request is public data: the key
// that belongs to it never leaves Alice.
export function CSRPem({ csr }: { csr: CSR }) {
  const { t } = useTranslation();
  return (
    <Stack gap="sm">
      <Textarea
        label={t('certificates.csr.pem')}
        value={csr.csr_pem}
        readOnly
        autosize
        minRows={4}
        maxRows={12}
        spellCheck={false}
        styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
      />
      <Group>
        <CopyButton value={csr.csr_pem}>
          {({ copied, copy }) => (
            <Button variant="light" leftSection={<Icon name={copied ? 'Check' : 'Copy'} size={15} />} onClick={copy}>
              {copied ? t('certificates.csr.copied') : t('certificates.csr.copy')}
            </Button>
          )}
        </CopyButton>
        <Button variant="default" leftSection={<Icon name="Download" size={15} />} onClick={() => downloadText(csrFileName(csr.common_name), csr.csr_pem)}>
          {t('certificates.csr.download')}
        </Button>
      </Group>
    </Stack>
  );
}
