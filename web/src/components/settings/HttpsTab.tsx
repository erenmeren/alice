import { Alert, Button, Group, Input, List, PasswordInput, Radio, Stack, Text, Title } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { NetworkError } from '../../api/client';
import { getHTTPSInfo, uploadHTTPSCertificate } from '../../api/endpoints';
import { settingsKey } from '../../api/queryKeys';
import type { HTTPSInfo, HTTPSUpload } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { ErrorAlert } from '../ErrorAlert';
import { LabelledCode } from '../LabelledCode';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { useSetting } from './useSetting';

const KNOWN_WARNINGS = ['name_mismatch', 'chain_incomplete', 'expires_soon'];

// HttpsTab is Settings → HTTPS certificate: the certificate Alice serves and the upload that replaces it without a
// restart (C11, C12).
export function HttpsTab() {
  const { t } = useTranslation();
  const q = useSetting('https', getHTTPSInfo);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return (
    <Stack gap="lg">
      <CertificateInfo info={q.data} />
      <Title order={2} size="h4">
        {t('https.upload')}
      </Title>
      <HttpsUploadForm />
    </Stack>
  );
}

// CertificateInfo shows the certificate in use; its names, subject and fingerprint are data, never translated.
export function CertificateInfo({ info }: { info: HTTPSInfo }) {
  const { t, i18n } = useTranslation();
  const names = [...(info.dns_names ?? []), ...(info.ip_addresses ?? [])].join(', ');
  return (
    <Stack gap="xs">
      <Title order={2} size="h4">
        {t('https.current')}
      </Title>
      {info.temporary ? (
        <Alert color="yellow" role="note" data-testid="https-temporary">
          {t('https.temporary')}
        </Alert>
      ) : (
        <Text size="sm">{t('https.ownCertificate')}</Text>
      )}
      <LabelledCode text={t('https.subject', { value: '' })} value={info.subject} />
      {names && <LabelledCode text={t('https.names', { value: '' })} value={names} />}
      <Text size="sm">{t('https.validUntil', { date: formatDateTime(info.not_after, i18n.language) })}</Text>
      <LabelledCode text={t('https.fingerprint', { value: '' })} value={info.fingerprint_sha256} />
    </Stack>
  );
}

// ReadError is a chosen file that the browser could not read.
class ReadError extends Error {}

function readText(file: File): Promise<string> {
  return file.text().catch((e: unknown) => {
    throw new ReadError('read failed', { cause: e });
  });
}

// readBase64 reads a file as standard base64 (the form pfx_base64 takes).
function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new ReadError('read failed', { cause: reader.error }));
    reader.onload = () => {
      const url = String(reader.result);
      resolve(url.slice(url.indexOf(',') + 1));
    };
    reader.readAsDataURL(file);
  });
}

type Format = 'pem' | 'pfx';

// HttpsUploadForm uploads the certificate Alice serves, as a PEM pair or a PFX with its password. The chosen files and
// the password live only in this component's state; they are dropped as soon as the server answers (kept only after a
// dropped connection or an unreadable file, when nothing was learned), and never reach a query key, the query cache,
// the address, web storage or the console. The answer replaces the cached certificate information.
export function HttpsUploadForm({ onApplied }: { onApplied?: (info: HTTPSInfo) => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const id = useId();
  const [format, setFormat] = useState<Format>('pem');
  const [cert, setCert] = useState<File | null>(null);
  const [key, setKey] = useState<File | null>(null);
  const [pfx, setPfx] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  // inputs is bumped to empty the native file inputs, which hold the chosen files themselves.
  const [inputs, setInputs] = useState(0);
  const [missing, setMissing] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [applied, setApplied] = useState<HTTPSInfo | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const forget = () => {
    setCert(null);
    setKey(null);
    setPfx(null);
    setPassword('');
    setInputs((n) => n + 1);
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const problem = format === 'pem' ? (!cert || !key ? 'https.missingFiles' : null) : !pfx ? 'https.missingPfx' : null;
    setMissing(problem);
    if (problem) return;
    setBusy(true);
    setError(null);
    setApplied(null);
    try {
      const body: HTTPSUpload =
        format === 'pem'
          ? { cert_pem: await readText(cert as File), key_pem: await readText(key as File) }
          : { pfx_base64: await readBase64(pfx as File), pfx_password: password };
      const info = await run(() => uploadHTTPSCertificate(body));
      // The cached information is the certificate itself; the warnings belong to this upload only.
      const stored: HTTPSInfo = { ...info };
      delete stored.warnings;
      client.setQueryData(settingsKey('https'), stored);
      if (!alive.current) return;
      forget();
      setApplied(info);
      setBusy(false);
      onApplied?.(info);
    } catch (e) {
      if (!alive.current) return;
      setError(e);
      setBusy(false);
      if (!(e instanceof NetworkError || e instanceof ReadError)) forget();
    }
  };

  const warnings = applied?.warnings ?? [];
  return (
    <form onSubmit={(ev) => void submit(ev)} noValidate data-testid="https-upload-form">
      <Stack gap="sm" maw={560}>
        <Text size="sm">{t('https.uploadHelp')}</Text>
        <Radio.Group label={t('https.format')} value={format} onChange={(v) => setFormat(v as Format)}>
          <Group mt="xs">
            <Radio value="pem" label={t('https.formatPem')} />
            <Radio value="pfx" label={t('https.formatPfx')} />
          </Group>
        </Radio.Group>
        {format === 'pem' ? (
          <>
            <Input.Wrapper id={`${id}-cert`} label={t('https.certFile')} description={t('https.certFileHelp')}>
              <input
                key={`cert-${inputs}`}
                id={`${id}-cert`}
                type="file"
                accept=".pem,.crt,.cer"
                aria-describedby={`${id}-cert-description`}
                onChange={(e) => setCert(e.currentTarget.files?.[0] ?? null)}
              />
            </Input.Wrapper>
            <Input.Wrapper id={`${id}-key`} label={t('https.keyFile')}>
              <input key={`key-${inputs}`} id={`${id}-key`} type="file" accept=".pem,.key" onChange={(e) => setKey(e.currentTarget.files?.[0] ?? null)} />
            </Input.Wrapper>
          </>
        ) : (
          <>
            <Input.Wrapper id={`${id}-pfx`} label={t('https.pfxFile')}>
              <input key={`pfx-${inputs}`} id={`${id}-pfx`} type="file" accept=".pfx,.p12" onChange={(e) => setPfx(e.currentTarget.files?.[0] ?? null)} />
            </Input.Wrapper>
            <PasswordInput
              label={t('https.pfxPassword')}
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </>
        )}
        {missing && (
          <Alert color="red" role="alert">
            {t(missing)}
          </Alert>
        )}
        {error instanceof ReadError ? (
          <Alert color="red" role="alert">
            {t('https.unreadableFile')}
          </Alert>
        ) : (
          <ErrorAlert error={error} />
        )}
        {applied && (
          <Alert color="green" role="status">
            <Text size="sm">{t('https.applied')}</Text>
            {warnings.length > 0 && (
              <>
                <Text size="sm" mt="xs">
                  {t('https.warningsTitle')}
                </Text>
                <List size="sm">
                  {warnings.map((w) => (
                    <List.Item key={w}>{t(KNOWN_WARNINGS.includes(w) ? `https.warnings.${w}` : 'https.warnings.unknown')}</List.Item>
                  ))}
                </List>
              </>
            )}
          </Alert>
        )}
        <Group>
          <Button type="submit" loading={busy}>
            {t('https.upload')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
