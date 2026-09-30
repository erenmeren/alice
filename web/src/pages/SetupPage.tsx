import { Container, Stack, Title } from '@mantine/core';
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
import { LanguageStep } from './setup/LanguageStep';
import { isGone } from './setup/gone';
import { PassphraseStep } from './setup/PassphraseStep';

export type WizardStep = 'code' | 'language' | 'admin' | 'totp' | 'codes' | 'passphrase' | 'done';

// startOf decides where the wizard begins. Before an administrator exists everybody
// starts with the setup code; afterwards only the signed-in administrator may finish
// the remaining steps (spec §18.5).
export function startOf(status: SetupStatus | null, session: SessionInfo | null): WizardStep | 'home' | 'login' {
  if (!status || !status.admin_exists) return 'code';
  if (!session) return 'login';
  if (session.user.role !== 'admin' || status.completed) return 'home';
  return status.recovery_passphrase_set ? 'done' : 'passphrase';
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
  const current: WizardStep = step ?? (start as WizardStep);

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
        {current === 'passphrase' && <PassphraseStep onDone={() => setStep('done')} onGone={gone} />}
        {current === 'done' && <DoneStep onGone={gone} />}
      </Stack>
    </Container>
  );
}
