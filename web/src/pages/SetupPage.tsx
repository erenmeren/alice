import { Button } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate } from 'react-router';
import { createAdmin } from '../api/endpoints';
import type { MfaEnrollment, SessionInfo, SetupStatus } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { adminExists } from '../auth/setupStatus';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnrollment } from '../components/TotpEnrollment';
import { Icon } from '../design/Icon';
import { AdminStep } from './setup/AdminStep';
import { CodeStep } from './setup/CodeStep';
import { DoneStep } from './setup/DoneStep';
import { HttpsStep } from './setup/HttpsStep';
import { LanguageStep } from './setup/LanguageStep';
import { isGone } from './setup/gone';
import { LicenseStep } from './setup/LicenseStep';
import type { MailDraft } from '../components/settings/MailSettings';
import { MailStep } from './setup/MailStep';
import { PassphraseStep } from './setup/PassphraseStep';
import { PlatformStep } from './setup/PlatformStep';
import { SetupShell } from './setup/SetupShell';
import classes from './setup/setup.module.css';

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
  if (!status || !adminExists(status)) return 'code';
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
  // Typed but not yet saved, kept for Back. Never a password, key, PFX or CA file.
  const [mailDraft, setMailDraft] = useState<MailDraft | null>(null);
  const [httpsFormat, setHttpsFormat] = useState<'pem' | 'pfx'>('pem');

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

  // Back sits first in the step's own actions row (design .form-actions); only BACK decides where it exists.
  const backButton = back && (
    <Button variant="default" data-testid="setup-back" leftSection={<Icon name="ArrowLeft" size={15} />} onClick={() => setStep(back)}>
      {t('setup.back')}
    </Button>
  );

  return (
    <SetupShell current={current}>
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
      {current === 'totp' && enrollment && (
        <div className={classes.embedded}>
          <TotpEnrollment enrollment={enrollment} onVerify={verifyAdmin} />
        </div>
      )}
      {current === 'codes' && (
        <div className={classes.embedded}>
          <RecoveryCodes codes={codes} onContinue={() => setStep('passphrase')} />
        </div>
      )}
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
      {current === 'https' && (
        <HttpsStep done={!!setupStatus?.https_chosen} format={httpsFormat} onFormat={setHttpsFormat} onDone={() => setStep('mail')} onGone={gone} back={backButton} />
      )}
      {current === 'mail' && <MailStep draft={mailDraft} onDraft={setMailDraft} onDone={() => setStep('license')} onGone={gone} back={backButton} />}
      {current === 'license' && <LicenseStep done={!!setupStatus?.license_chosen} onDone={() => setStep('platform')} onGone={gone} back={backButton} />}
      {current === 'platform' && <PlatformStep onDone={() => setStep('done')} back={backButton} />}
      {current === 'done' && <DoneStep onGone={gone} back={backButton} />}
    </SetupShell>
  );
}
