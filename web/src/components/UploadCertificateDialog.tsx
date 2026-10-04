import { Alert, Button, FileInput, Group, PasswordInput, SegmentedControl, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { uploadCertificate } from '../api/endpoints';
import type { UploadRequest, UploadResult } from '../api/types';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { UploadWarnings } from './UploadWarnings';

// MAX_BYTES is what the API accepts for one field and for a PFX file decoded (256 KiB).
const MAX_BYTES = 256 * 1024;

type Format = 'pem' | 'pfx';
type Problems = { certificate?: string; key?: string; pfx?: string };

const MONO = { input: { fontFamily: 'var(--mantine-font-family-monospace)' } };

function tooLarge(text: string): boolean {
  return new Blob([text]).size > MAX_BYTES;
}

// readBase64 reads a file as standard base64 (the form the API's pfx_base64 expects).
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('read failed'));
    reader.onload = () => {
      const url = String(reader.result);
      resolve(url.slice(url.indexOf(',') + 1));
    };
    reader.readAsDataURL(file);
  });
}

// UploadForm uploads a certificate with its private key, as PEM text or as a PFX
// file. The private key text, the PFX bytes and the PFX password live only in this component's
// state: they are cleared as soon as the server answers (not after a retryable "busy" answer, which
// stored nothing), when the dialog closes and when it unmounts. They are never put in a query key,
// the query cache (the request is a plain call, not a mutation, so TanStack Query never holds its
// variables), the URL, web storage or the console. The key is never shown again after an upload.
function UploadForm({ onClose, onUploaded }: { onClose: () => void; onUploaded: (certificateId: string) => void }) {
  const { t } = useTranslation();
  const formatId = useId();
  const [format, setFormat] = useState<Format>('pem');
  const [certificate, setCertificate] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [label, setLabel] = useState('');
  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problems, setProblems] = useState<Problems>({});
  const [result, setResult] = useState<UploadResult | null>(null);
  // alive is false once the dialog closed: an answer that arrives later neither fills the form nor
  // shows a result (the stored certificate is still reported through onUploaded).
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const validate = (): Problems => {
    const p: Problems = {};
    if (format === 'pem') {
      if (certificate.trim() === '') p.certificate = t('certificates.upload.certificateRequired');
      else if (tooLarge(certificate)) p.certificate = t('certificates.upload.textTooLarge');
      if (privateKey.trim() === '') p.key = t('certificates.upload.keyRequired');
      else if (tooLarge(privateKey)) p.key = t('certificates.upload.textTooLarge');
    } else if (!pfxFile) p.pfx = t('certificates.upload.pfxRequired');
    else if (pfxFile.size > MAX_BYTES) p.pfx = t('certificates.upload.fileTooLarge');
    return p;
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const found = validate();
    setProblems(found);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    setError(null);
    try {
      const req: UploadRequest = label.trim() ? { label: label.trim() } : {};
      if (format === 'pem') {
        req.certificate_pem = certificate;
        req.private_key_pem = privateKey;
      } else {
        req.pfx_base64 = await readBase64(pfxFile as File);
        req.pfx_password = pfxPassword;
      }
      const res = await uploadCertificate(req);
      onUploaded(res.certificate.id);
      if (!alive.current) return;
      // The secrets are dropped as soon as the server has answered.
      setCertificate('');
      setPrivateKey('');
      setPfxFile(null);
      setPfxPassword('');
      setBusy(false);
      setResult(res);
    } catch (e) {
      if (!alive.current) return;
      setError(e);
      setBusy(false);
      // A retryable answer (Alice is busy with other PFX files) stored nothing: the form stays so
      // the person can send it again. Any other answer clears the secrets.
      if (!(isApiError(e) && e.retryable)) {
        setPrivateKey('');
        setPfxPassword('');
      }
    }
  };

  return (
    <>
      {result ? (
        <Stack gap="sm">
          <Alert color="green" role="status">
            {t('certificates.upload.uploaded')}
          </Alert>
          <UploadWarnings warnings={result.warnings} />
          <Group justify="flex-end">
            <Button onClick={onClose}>{t('certificates.upload.close')}</Button>
          </Group>
        </Stack>
      ) : (
        <form onSubmit={(ev) => void submit(ev)} noValidate>
          <Stack gap="sm">
            <Text size="sm">{t('certificates.upload.help')}</Text>
            <Stack gap={4}>
              <Text size="sm" fw={500} id={formatId}>
                {t('certificates.upload.format')}
              </Text>
              <SegmentedControl
                aria-labelledby={formatId}
                value={format}
                onChange={(v) => setFormat(v as Format)}
                data={[
                  { value: 'pem', label: t('certificates.upload.formatPem') },
                  { value: 'pfx', label: t('certificates.upload.formatPfx') },
                ]}
              />
            </Stack>
            {format === 'pem' ? (
              <>
                <Textarea
                  data-autofocus
                  label={t('certificates.upload.certificate')}
                  value={certificate}
                  onChange={(e) => setCertificate(e.currentTarget.value)}
                  error={problems.certificate}
                  autosize
                  minRows={4}
                  maxRows={10}
                  spellCheck={false}
                  autoComplete="off"
                  styles={MONO}
                />
                <Textarea
                  label={t('certificates.upload.privateKey')}
                  description={t('certificates.upload.secretWarning')}
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.currentTarget.value)}
                  error={problems.key}
                  autosize
                  minRows={4}
                  maxRows={10}
                  spellCheck={false}
                  autoComplete="off"
                  styles={MONO}
                />
              </>
            ) : (
              <>
                <FileInput
                  label={t('certificates.upload.pfxFile')}
                  placeholder={t('certificates.upload.pfxPlaceholder')}
                  accept=".pfx,.p12"
                  value={pfxFile}
                  onChange={setPfxFile}
                  error={problems.pfx}
                  clearable
                  clearButtonProps={{ 'aria-label': t('certificates.upload.clearFile') }}
                />
                <PasswordInput
                  label={t('certificates.upload.pfxPassword')}
                  value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.currentTarget.value)}
                  autoComplete="new-password"
                />
              </>
            )}
            <TextInput label={t('certificates.upload.label')} value={label} onChange={(e) => setLabel(e.currentTarget.value)} maxLength={100} />
            <ErrorAlert error={error} />
            <Group justify="flex-end">
              <Button variant="default" onClick={onClose}>
                {t('certificates.upload.cancel')}
              </Button>
              <Button type="submit" loading={busy}>
                {t('certificates.upload.submit')}
              </Button>
            </Group>
          </Stack>
        </form>
      )}
    </>
  );
}

// UploadCertificateDialog uploads a certificate with its private key. The form is rendered only
// while the dialog is open, so closing it drops everything that was typed or chosen.
export function UploadCertificateDialog({
  opened,
  onClose,
  onUploaded,
}: {
  opened: boolean;
  onClose: () => void;
  onUploaded: (certificateId: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <AppModal opened={opened} onClose={onClose} title={t('certificates.upload.title')} size="lg">
      {opened && <UploadForm onClose={onClose} onUploaded={onUploaded} />}
    </AppModal>
  );
}
