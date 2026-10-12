import { Button, Divider, Group, Stack, Text, Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getHTTPSInfo, keepTemporaryCertificate } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { LoadingIndicator } from '../../components/LoadingIndicator';
import { CertificateInfo, HttpsUploadForm } from '../../components/settings/HttpsTab';
import { useSetting } from '../../components/settings/useSetting';
import { useStepUp } from '../../components/StepUpProvider';
import { Icon } from '../../design/Icon';
import { isGone } from './gone';
import { StepActions, StepHeading } from './SetupShell';
import classes from './setup.module.css';

// HttpsStep is the wizard's HTTPS certificate step (R43 row 16): upload the organisation's certificate (applied at
// once, without a restart) or keep the temporary one. Reached again with Back, it shows the choice made (done) and
// still allows an upload. The two answers are equal choices in bordered boxes (upload first, as the design preselects
// it), "or" between them; keeping the temporary certificate is never the actions row's forward action. Continue
// exists only once a choice is made.
export function HttpsStep({
  onDone,
  onGone,
  done,
  format,
  onFormat,
  back,
}: {
  onDone: () => void;
  onGone: () => void;
  done: boolean;
  format?: 'pem' | 'pfx';
  onFormat?: (f: 'pem' | 'pfx') => void;
  back?: ReactNode;
}) {
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
      <StepHeading title={t('setup.https.title')} intro={t('setup.https.help')} />
      {info.isPending && <LoadingIndicator />}
      <ErrorAlert error={info.error} />
      {info.data && <CertificateInfo info={info.data} />}
      {chosen && info.data && (
        <Group data-testid="https-done">
          <Text>{info.data.temporary ? t('setup.https.keptTemporary') : t('setup.https.uploadedDone')}</Text>
        </Group>
      )}
      <div className={classes.choice} data-choice="upload">
        <Title order={3} className={classes.choiceTitle}>
          {t('https.upload')}
        </Title>
        <HttpsUploadForm
          plainActions
          initialFormat={format}
          onFormat={onFormat}
          onApplied={() => {
            setUploaded(true);
            void refreshSetupStatus();
          }}
        />
      </div>
      {!chosen && (
        <>
          <Divider
            label={
              <Text span size="sm" c="dimmed">
                {t('setup.license.or')}
              </Text>
            }
            labelPosition="center"
          />
          <div className={classes.choice} data-choice="keep">
            <ErrorAlert error={error} />
            <div>
              <Button variant="default" className={classes.wrapButton} data-testid="https-keep-temporary" loading={busy} onClick={() => void keep()}>
                {t('https.keepTemporary')}
              </Button>
            </div>
            <p className={classes.hint}>{t('setup.https.keepHint')}</p>
          </div>
        </>
      )}
      <StepActions back={back}>
        {chosen && (
          <Button onClick={onDone} rightSection={<Icon name="ArrowRight" size={15} />}>
            {t('ui.continue')}
          </Button>
        )}
      </StepActions>
    </Stack>
  );
}
