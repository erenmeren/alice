import { Alert, Button, CopyButton, Group, NativeSelect, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createCSR } from '../api/endpoints';
import type { CSR, CSRKeyType } from '../api/types';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';

// downloadText saves text as a file through a temporary link (the pattern RecoveryCodes uses).
function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// namesOf turns "one name per line" into the list the API takes: trimmed, no empty lines.
function namesOf(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

// CSRForm makes a signing request: Alice creates the key (it never leaves Alice) and shows the
// request, which is public, to copy or download.
function CSRForm({ onClose, onCreated }: { onClose: () => void; onCreated: (csr: CSR) => void }) {
  const { t } = useTranslation();
  const [commonName, setCommonName] = useState('');
  const [others, setOthers] = useState('');
  const [keyType, setKeyType] = useState<CSRKeyType>('ecdsa-p256');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [nameProblem, setNameProblem] = useState('');
  const [created, setCreated] = useState<CSR | null>(null);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (commonName.trim() === '') {
      setNameProblem(t('validation.required'));
      return;
    }
    setNameProblem('');
    setBusy(true);
    setError(null);
    try {
      const csr = await createCSR({ common_name: commonName.trim(), sans: namesOf(others), key_type: keyType });
      setCreated(csr);
      onCreated(csr);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };

  return (
    <>
      {created ? (
        <Stack gap="sm">
          <Alert color="green" role="status">
            {t('certificates.csr.created')}
          </Alert>
          <Textarea
            label={t('certificates.csr.pem')}
            value={created.csr_pem}
            readOnly
            autosize
            minRows={4}
            maxRows={12}
            spellCheck={false}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          />
          <Group>
            <CopyButton value={created.csr_pem}>
              {({ copied, copy }) => (
                <Button variant="light" onClick={copy}>
                  {copied ? t('certificates.csr.copied') : t('certificates.csr.copy')}
                </Button>
              )}
            </CopyButton>
            <Button variant="default" onClick={() => downloadText(`${created.common_name}.csr`, created.csr_pem)}>
              {t('certificates.csr.download')}
            </Button>
          </Group>
          <Group justify="flex-end">
            <Button onClick={onClose}>{t('certificates.upload.close')}</Button>
          </Group>
        </Stack>
      ) : (
        <form onSubmit={(ev) => void submit(ev)} noValidate>
          <Stack gap="sm">
            <Text size="sm">{t('certificates.csr.help')}</Text>
            <TextInput
              data-autofocus
              label={t('certificates.csr.commonName')}
              value={commonName}
              onChange={(e) => setCommonName(e.currentTarget.value)}
              error={nameProblem || undefined}
              maxLength={64}
              spellCheck={false}
              autoComplete="off"
            />
            <Textarea
              label={t('certificates.csr.otherNames')}
              value={others}
              onChange={(e) => setOthers(e.currentTarget.value)}
              autosize
              minRows={3}
              maxRows={8}
              spellCheck={false}
              autoComplete="off"
            />
            <NativeSelect
              label={t('certificates.csr.keyType')}
              value={keyType}
              onChange={(e) => setKeyType(e.currentTarget.value as CSRKeyType)}
              data={[
                { value: 'ecdsa-p256', label: t('certificates.csr.keyEcdsa') },
                { value: 'rsa-3072', label: t('certificates.csr.keyRsa3072') },
                { value: 'rsa-4096', label: t('certificates.csr.keyRsa4096') },
              ]}
            />
            <ErrorAlert error={error} />
            <Group justify="flex-end">
              <Button variant="default" onClick={onClose}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" loading={busy}>
                {t('certificates.csr.submit')}
              </Button>
            </Group>
          </Stack>
        </form>
      )}
    </>
  );
}

// CreateCSRDialog renders the form only while it is open, so closing starts the form again.
export function CreateCSRDialog({ opened, onClose, onCreated }: { opened: boolean; onClose: () => void; onCreated: (csr: CSR) => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened={opened} onClose={onClose} title={t('certificates.csr.title')} size="lg">
      {opened && <CSRForm onClose={onClose} onCreated={onCreated} />}
    </AppModal>
  );
}
