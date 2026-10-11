import { Button, Divider, Group, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getHTTPSInfo, keepTemporaryCertificate } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { LoadingIndicator } from '../../components/LoadingIndicator';
import { CertificateInfo, HttpsUploadForm } from '../../components/settings/HttpsTab';
import { useSetting } from '../../components/settings/useSetting';
import { useStepUp } from '../../components/StepUpProvider';
import { isGone } from './gone';

// HttpsStep is the wizard's HTTPS certificate step (R43 row 16): upload the organisation's certificate (applied at
// once, without a restart) or keep the temporary one. Reached again with Back, it shows the choice made (done) and
// still allows an upload.
export function HttpsStep({ onDone, onGone, done }: { onDone: () => void; onGone: () => void; done: boolean }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const { refreshSetupStatus } = useAuth();
  const info = useSetting('https', getHTTPSInfo);
  const [uploaded, setUploaded] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const keep = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(keepTemporaryCertificate); // settings.manage: a fresh code if the step-up expired
      await refreshSetupStatus();
      onDone();
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  const chosen = done || uploaded;
  return (
    <Stack>
      <Title order={2}>{t('setup.https.title')}</Title>
      <Text>{t('setup.https.help')}</Text>
      {info.isPending && <LoadingIndicator />}
      <ErrorAlert error={info.error} />
      {info.data && <CertificateInfo info={info.data} />}
      {chosen && info.data && (
        <Group data-testid="https-done">
          <Text>{info.data.temporary ? t('setup.https.keptTemporary') : t('setup.https.uploadedDone')}</Text>
        </Group>
      )}
      {chosen && (
        <Group>
          <Button onClick={onDone}>{t('ui.continue')}</Button>
        </Group>
      )}
      <Title order={3} size="h4">
        {t('https.upload')}
      </Title>
      <HttpsUploadForm
        onApplied={() => {
          setUploaded(true);
          void refreshSetupStatus();
        }}
      />
      {!chosen && (
        <>
          <Divider
            label={
              <Text span size="sm" c="gray.8">
                {t('setup.license.or')}
              </Text>
            }
            labelPosition="center"
          />
          <ErrorAlert error={error} />
          <Group>
            <Button variant="default" data-testid="https-keep-temporary" loading={busy} onClick={() => void keep()}>
              {t('https.keepTemporary')}
            </Button>
          </Group>
        </>
      )}
    </Stack>
  );
}
