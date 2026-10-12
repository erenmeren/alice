import { Button, Group, NativeSelect, NumberInput, PasswordInput, Stack, Text, TextInput, Textarea } from '@mantine/core';
import { useMutation } from '@tanstack/react-query';
import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { getSMTP, saveSMTP, sendTestMail, trustSMTPCertificate, untrustSMTPCertificate, type SMTPSettings, type TlsMode } from '../../api/settings';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { Icon } from '../../design/Icon';
import { LoadingIndicator } from '../LoadingIndicator';
import { useStepUp } from '../StepUpProvider';
import { SavedNote } from './SavedNote';
import classes from './settings.module.css';
import { TrustCertificateDialog } from './TrustCertificateDialog';
import { useChange, useSetting } from './useSetting';

// MailSettings is the SMTP server form with the test mail. The stored password never comes back from the server: the field
// stays empty and a password is sent only when one is typed.
// MailDraft is the non-secret part of the form (never the password). The wizard keeps it while the person goes Back.
export interface MailDraft {
  host: string;
  port: number | string;
  tlsMode: TlsMode;
  from: string;
  username: string;
  caPem: string;
}

// plainActions (the wizard) draws the save row without its rule: the wizard's own actions row has it.
export function MailSettings({ draft, onDraft, plainActions = false }: { draft?: MailDraft | null; onDraft?: (d: MailDraft) => void; plainActions?: boolean } = {}) {
  const q = useSetting('smtp', getSMTP);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <MailPanel settings={q.data} draft={draft ?? null} onDraft={onDraft} plainActions={plainActions} />;
}

function MailPanel({ settings, draft, onDraft, plainActions }: { settings: SMTPSettings; draft: MailDraft | null; onDraft?: (d: MailDraft) => void; plainActions: boolean }) {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const [to, setTo] = useState(session?.user.email ?? '');
  const [showUntrusted, setShowUntrusted] = useState(false);
  const { run } = useStepUp();
  const save = useChange('smtp', settings.version, saveSMTP);
  const trust = useChange('smtp', settings.version, trustSMTPCertificate);
  const untrust = useChange<SMTPSettings, void>('smtp', settings.version, (version) => untrustSMTPCertificate(version));
  const test = useMutation({
    mutationFn: () => run(() => sendTestMail(to.trim())),
    onError: (e) => setShowUntrusted(isApiError(e, 'notify.smtp_untrusted')),
  });
  const untrusted = showUntrusted && isApiError(test.error, 'notify.smtp_untrusted') ? test.error : null;
  const trusted = settings.trusted_certificate;

  return (
    <Stack gap="sm">
      {/* Keyed by the version: a saved or re-read setting draws the form again, which empties the password field. */}
      <MailForm key={settings.version} settings={settings} draft={draft} onDraft={onDraft} onSave={(body) => save.mutate(body)} plainActions={plainActions} busy={save.isPending} fieldErrors={fieldErrorsOf(save.error, t, i18n)} />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />

      {trusted && (
        <Stack gap="xs" className={classes.microCard}>
          {/* The fingerprint is hexadecimal data: it is never translated or case-changed. */}
          <Text size="sm" style={{ overflowWrap: 'anywhere' }}>
            {t('settings.mail.trusted', { fingerprint: trusted.fingerprint })}
          </Text>
          <Group>
            <Button variant="default" size="xs" loading={untrust.isPending} onClick={() => untrust.mutate()}>
              {t('settings.mail.untrust')}
            </Button>
          </Group>
          <ErrorAlert error={untrust.error} />
        </Stack>
      )}

      <Stack gap="xs" className={classes.subSection}>
        <Group align="flex-end" gap="sm">
          <TextInput style={{ flex: '1 1 240px' }} label={t('settings.mail.testTo')} type="email" value={to} onChange={(e) => setTo(e.currentTarget.value)} autoComplete="email" />
          <Button variant="default" leftSection={<Icon name="Mail" size={15} />} loading={test.isPending} onClick={() => test.mutate()}>
            {t('settings.mail.sendTest')}
          </Button>
        </Group>
        {test.isSuccess && (
          <Text role="status" size="sm" c="var(--alice-success)">
            {t('settings.mail.testSent', { to: to.trim() })}
          </Text>
        )}
        {!untrusted && <ErrorAlert error={test.error} />}
      </Stack>

      {untrusted && (
        <TrustCertificateDialog
          error={untrusted}
          busy={trust.isPending}
          trustError={trust.error}
          onTrust={(fingerprint) =>
            trust.mutate(fingerprint, {
              onSuccess: () => {
                setShowUntrusted(false);
                test.reset();
              },
            })
          }
          onClose={() => {
            setShowUntrusted(false);
            test.reset();
            trust.reset();
          }}
        />
      )}
    </Stack>
  );
}

function MailForm({ settings, draft, onDraft, onSave, plainActions, busy, fieldErrors }: { settings: SMTPSettings; draft: MailDraft | null; onDraft?: (d: MailDraft) => void; onSave: (b: Parameters<typeof saveSMTP>[1]) => void; plainActions: boolean; busy: boolean; fieldErrors: Record<string, string> }) {
  const { t } = useTranslation();
  const [host, setHost] = useState(draft?.host ?? settings.host);
  const [port, setPort] = useState<number | string>(draft?.port ?? (settings.port || 587));
  const [tlsMode, setTlsMode] = useState<TlsMode>(draft?.tlsMode ?? (settings.tls_mode || 'starttls'));
  const [from, setFrom] = useState(draft?.from ?? settings.from);
  const [username, setUsername] = useState(draft?.username ?? settings.username);
  const [password, setPassword] = useState('');
  const [caPem, setCaPem] = useState(draft?.caPem ?? settings.ca_pem);
  useEffect(() => {
    onDraft?.({ host, port, tlsMode, from, username, caPem });
  }, [onDraft, host, port, tlsMode, from, username, caPem]);

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const typed = password;
    setPassword(''); // the password is not kept in the page once it is sent
    onSave({ host: host.trim(), port: Number(port), tls_mode: tlsMode, from: from.trim(), username: username.trim(), ca_pem: caPem, ...(typed ? { password: typed } : {}) });
  };

  return (
    <form onSubmit={submit}>
      <Stack gap="sm">
        <div className={classes.grid2}>
          <TextInput label={t('settings.mail.host')} value={host} onChange={(e) => setHost(e.currentTarget.value)} error={fieldErrors.host} autoComplete="off" />
          <NumberInput label={t('settings.mail.port')} value={port} onChange={setPort} min={1} max={65535} allowDecimal={false} error={fieldErrors.port} />
        </div>
        <NativeSelect
          label={t('settings.mail.tlsMode')}
          value={tlsMode}
          onChange={(e) => setTlsMode(e.currentTarget.value as TlsMode)}
          data={[
            { value: 'starttls', label: t('settings.mail.tlsStarttls') },
            { value: 'tls', label: t('settings.mail.tlsImplicit') },
          ]}
        />
        <TextInput label={t('settings.mail.from')} type="email" value={from} onChange={(e) => setFrom(e.currentTarget.value)} error={fieldErrors.from} autoComplete="off" />
        <TextInput label={t('settings.mail.username')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} error={fieldErrors.username} autoComplete="off" />
        <PasswordInput
          label={t('settings.mail.password')}
          description={settings.has_password ? t('settings.mail.passwordKept') : undefined}
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          error={fieldErrors.password}
          autoComplete="new-password"
        />
        <Textarea label={t('settings.mail.caPem')} value={caPem} onChange={(e) => setCaPem(e.currentTarget.value)} error={fieldErrors.ca_pem} autosize minRows={3} maxRows={8} spellCheck={false} styles={{ input: { fontFamily: 'monospace' } }} />
      </Stack>
      <div className={plainActions ? `${classes.formActions} ${classes.formActionsPlain}` : classes.formActions}>
        <Button type="submit" loading={busy} leftSection={<Icon name="Check" size={15} />}>
          {t('settings.mail.save')}
        </Button>
      </div>
    </form>
  );
}
