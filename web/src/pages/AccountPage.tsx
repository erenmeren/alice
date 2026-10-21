import { Alert, Button, PasswordInput, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { changePassword, regenerateRecoveryCodes } from '../api/endpoints';
import { listPublicDirectories } from '../api/ldap';
import { PUBLIC_DIRECTORIES_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { useStepUp } from '../components/StepUpProvider';
import { AppearanceControl, FactList, PageHeader, Panel, StatusBadge } from '../components/ui';
import { Icon } from '../design/Icon';
import classes from './People.module.css';
import { initials } from '../initials';
import { roleLabel } from '../components/access/shared';

function ChangePassword() {
  const { t } = useTranslation();
  const { setSession } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    setDone(false);
    setMismatch(next !== repeat);
    if (next !== repeat) return;
    setBusy(true);
    try {
      setSession(await changePassword(current, next));
      setCurrent('');
      setNext('');
      setRepeat('');
      setDone(true);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={classes.section}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Title order={3} className={classes.sectionTitle}>
            {t('account.password.title')}
          </Title>
          {done && <Alert color="green">{t('account.password.changed')}</Alert>}
          {mismatch && (
            <Alert color="red" role="alert">
              {t('account.password.mismatch')}
            </Alert>
          )}
          <ErrorAlert error={error} />
          <PasswordInput
            label={t('account.password.current')}
            value={current}
            onChange={(e) => setCurrent(e.currentTarget.value)}
            autoComplete="current-password"
          />
          <PasswordInput
            label={t('account.password.new')}
            description={t('account.password.newHelp')}
            value={next}
            onChange={(e) => setNext(e.currentTarget.value)}
            autoComplete="new-password"
          />
          <PasswordInput
            label={t('account.password.repeat')}
            value={repeat}
            onChange={(e) => setRepeat(e.currentTarget.value)}
            autoComplete="new-password"
          />
          <Button type="submit" loading={busy} leftSection={<Icon name="LockKeyhole" size={15} />} w="fit-content">
            {t('account.password.submit')}
          </Button>
        </Stack>
      </form>
    </div>
  );
}

function NewRecoveryCodes() {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      setCodes((await run(() => regenerateRecoveryCodes())).recovery_codes);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={classes.section}>
      <Title order={3} className={classes.sectionTitle}>
        {t('account.recovery.title')}
      </Title>
      <p className={classes.help}>{t('account.recovery.help')}</p>
        <ErrorAlert error={error} />
        {saved && <Alert color="green">{t('account.recovery.active')}</Alert>}
        {codes ? (
          <RecoveryCodes
            codes={codes}
            onContinue={() => {
              setCodes(null);
              setSaved(true);
            }}
          />
        ) : (
          <Button variant="default" leftSection={<Icon name="KeyRound" size={15} />} onClick={() => void create()} loading={busy} w="fit-content">
            {t('account.recovery.create')}
          </Button>
        )}
    </div>
  );
}

export function AccountPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  // The directory's name comes from the public list of the sign-in page (switched-on directories only); without it the
  // fact says "Directory".
  const isDirectory = session?.user.auth_source === 'ldap';
  const directories = useQuery({ queryKey: PUBLIC_DIRECTORIES_KEY, queryFn: listPublicDirectories, enabled: isDirectory, retry: false });
  const directoryName = directories.data?.items.find((d) => d.id === session?.user.ldap_directory_id)?.name;
  if (!session) return null;
  const user = session.user;
  // A single sign-on account has no Alice password or authenticator: the server refuses both changes (ALC-USR-0003).
  const sso = user.auth_source === 'oidc';
  // A directory account has no Alice password (the directory owns it) but keeps Alice's authenticator and recovery codes.
  const directory = user.auth_source === 'ldap';
  const role = roleLabel(t, user.role);
  let mfa;
  if (sso) {
    mfa = (
      <StatusBadge tone="neutral" icon="Building2">
        {t('users.mfa.atProvider')}
      </StatusBadge>
    );
  } else if (user.mfa_enrolled) {
    mfa = (
      <StatusBadge tone="success" icon="ShieldCheck">
        {t('account.page.mfaOn')}
      </StatusBadge>
    );
  } else {
    mfa = (
      <StatusBadge tone="warning" icon="CircleAlert">
        {t('account.page.mfaOff')}
      </StatusBadge>
    );
  }
  let signInValue: string;
  if (sso) signInValue = t('account.page.sso');
  else if (directory) signInValue = directoryName ? t('account.page.directoryNamed', { name: directoryName }) : t('account.page.directory');
  else signInValue = user.mfa_enrolled ? t('account.page.local') : t('users.page.local');
  return (
    <Stack gap={0}>
      <PageHeader title={t('account.title')} description={t('account.page.description')} />
      <div className={classes.grid}>
        <Panel title={t('account.page.security')}>
          <div className={classes.profile}>
            <span className={`${classes.avatar} ${classes.avatarLarge}`} aria-hidden="true">
              {initials(user.display_name, i18n.language)}
            </span>
            <div>
              <p className={classes.profileName}>{user.display_name}</p>
              <p className={classes.profileMeta}>
                <span>{role}</span>
                {user.email && <span translate="no">{user.email}</span>}
              </p>
            </div>
          </div>
          <Text className={classes.summary} data-testid="account-summary">
            {t('account.summary', { username: user.username, role })}
          </Text>
          {/* The Sign-in fact names the authenticator app only when it is set up, as the MFA badge beside it says. */}
          <FactList
            facts={[
              { key: 'signIn', label: t('account.page.signIn'), value: signInValue },
              { key: 'mfa', label: t('account.page.mfa'), value: mfa },
            ]}
          />
          {sso && (
            <div className={classes.section}>
              <p className={classes.help}>{t('account.page.ssoNote')}</p>
            </div>
          )}
          {directory && (
            <>
              <div className={classes.section}>
                <p className={classes.help}>{t('account.page.directoryNote')}</p>
              </div>
              <NewRecoveryCodes />
            </>
          )}
          {!sso && !directory && (
            <>
              <NewRecoveryCodes />
              <ChangePassword />
            </>
          )}
        </Panel>
        <Panel title={t('appearance.title')} description={t('appearance.description')}>
          <AppearanceControl signedIn />
        </Panel>
      </div>
    </Stack>
  );
}
