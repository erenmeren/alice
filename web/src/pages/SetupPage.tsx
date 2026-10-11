import { Button, Container, Group, Stack, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate } from 'react-router';
import { createAdmin } from '../api/endpoints';
import type { MfaEnrollment, SessionInfo, SetupStatus } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnrollment } from '../components/TotpEnrollment';
import { AdminStep } from './setup/AdminStep';
import { CodeStep } from './setup/CodeStep';
import { DoneStep } from './setup/DoneStep';
import { HttpsStep } from './setup/HttpsStep';
import { LanguageStep } from './setup/LanguageStep';
import { isGone } from './setup/gone';
import { LicenseStep } from './setup/LicenseStep';
import { MailStep } from './setup/MailStep';
import { PassphraseStep } from './setup/PassphraseStep';
import { PlatformStep } from './setup/PlatformStep';

export type WizardStep =
  | 'code'
  | 'language'
  | 'admin'
  | 'totp'
  | 'codes'
  | 'passphrase'
  | 'https'
  | 'mail'
  | 'license'
  | 'platform'
  | 'done';

// The steps the server can name as the place to resume (R43 row 16); "done" means setup is complete.
const RESUMABLE: readonly WizardStep[] = ['passphrase', 'https', 'mail', 'license', 'platform'];

// BACK is where Back leads from each step after the administrator exists. The recovery passphrase has nothing before
// it that can be shown again (the recovery codes are shown once), and it is itself shown only as done.
const BACK: Partial<Record<WizardStep, WizardStep>> = {
  https: 'passphrase',
  mail: 'https',
  license: 'mail',
  platform: 'license',
  done: 'platform',
};

// startOf decides where the wizard begins. Before an administrator exists everybody
// starts with the setup code; afterwards only the signed-in administrator may finish
// the remaining steps (spec §18.5), resuming at the first unfinished one (R43 row 16).
export function startOf(status: SetupStatus | null, session: SessionInfo | null): WizardStep | 'home' | 'login' {
  if (!status || !status.admin_exists) return 'code';
  if (!session) return 'login';
  if (session.user.role !== 'admin' || status.completed) return 'home';
  if (status.next_step && RESUMABLE.includes(status.next_step)) return status.next_step;
  if (!status.recovery_passphrase_set) return 'passphrase';
  // A server that reports the choices without a position: the HTTPS and mail steps come before the license.
  if (status.https_chosen === false) return 'https';
  if (status.mail_chosen === false) return 'mail';
  // Step 7 (Alice's key, first server) may be skipped and stores nothing, so it is shown again until Finish.
  return status.license_chosen ? 'platform' : 'license';
}

export function SetupPage() {
  const { t } = useTranslation();
  const { loading, setupStatus, session, setSession, refreshSetupStatus } = useAuth();
  const navigate = useNavigate();
  const [step, setStep] = useState<WizardStep | null>(null);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [codes, setCodes] = useState<string[]>([]);

  if (loading) return <PageLoader />;
  const start = startOf(setupStatus, session);
  if (step === null && start === 'home') return <Navigate to="/" replace />;
  if (step === null && start === 'login') return <Navigate to="/login" replace />;
  // The step the page opened at is kept until a step moves on: a status read later (after an upload, say) must not
  // jump the wizard past a step the person is still looking at.
  if (step === null) setStep(start as WizardStep);
  const current: WizardStep = step ?? (start as WizardStep);
  const back = BACK[current];

  // A 404 from a setup route means setup is already over; sign-in is the right place.
  const gone = () => {
    void refreshSetupStatus().then(() => navigate('/login', { replace: true }));
  };

  const verifyAdmin = async (code: string) => {
    let res;
    try {
      res = await createAdmin(code);
    } catch (e) {
      if (isGone(e)) return gone();
      throw e;
    }
    setSession(res);
    setCodes(res.recovery_codes ?? []);
    setStep('codes');
  };

  return (
    <Container size="sm" my="xl">
      <Stack>
        <Title order={1}>{t('setup.title')}</Title>
        {current === 'code' && <CodeStep onDone={() => setStep('language')} onGone={gone} />}
        {current === 'language' && <LanguageStep onDone={() => setStep('admin')} onGone={gone} />}
        {current === 'admin' && (
          <AdminStep
            onGone={gone}
            onEnrolled={(e) => {
              setEnrollment(e);
              setStep('totp');
            }}
          />
        )}
        {current === 'totp' && enrollment && <TotpEnrollment enrollment={enrollment} onVerify={verifyAdmin} />}
        {current === 'codes' && <RecoveryCodes codes={codes} onContinue={() => setStep('passphrase')} />}
        {current === 'passphrase' && (
          <PassphraseStep
            done={!!setupStatus?.recovery_passphrase_set}
            onDone={() => {
              void refreshSetupStatus();
              setStep('https');
            }}
            onGone={gone}
          />
        )}
        {current === 'https' && <HttpsStep done={!!setupStatus?.https_chosen} onDone={() => setStep('mail')} onGone={gone} />}
        {current === 'mail' && <MailStep onDone={() => setStep('license')} onGone={gone} />}
        {current === 'license' && <LicenseStep done={!!setupStatus?.license_chosen} onDone={() => setStep('platform')} onGone={gone} />}
        {current === 'platform' && <PlatformStep onDone={() => setStep('done')} />}
        {current === 'done' && <DoneStep onGone={gone} />}
        {back && (
          <Group>
            <Button variant="subtle" data-testid="setup-back" onClick={() => setStep(back)}>
              {t('setup.back')}
            </Button>
          </Group>
        )}
      </Stack>
    </Container>
  );
}
