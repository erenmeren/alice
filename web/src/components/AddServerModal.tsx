import { Alert, Button, Code, CopyButton, Group, Loader, NativeSelect, NumberInput, Stack, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { WEB_SERVER_TYPES, type WebServerType } from '../api/webServer';
import { softwareName } from './software';
import { confirmHostKey, createTarget, getPlatformKey, getWinRMSetup, listHostKeys, testTarget } from '../api/endpoints';
import { isAbort, JobTimeoutError, waitForJob } from '../api/jobs';
import { PLATFORM_KEY_KEY, TARGETS_KEY, targetKey } from '../api/queryKeys';
import { useAbort } from '../api/useAbort';
import type { HostKey, Job, JobError, Target, WindowsTransport } from '../api/types';
import { AppModal } from './AppModal';
import { CCSPasswordPanel } from './CCSPasswordPanel';
import { ErrorAlert } from './ErrorAlert';
import { fieldErrorsOf } from './fieldErrors';
import { HostKeyConfirm } from './HostKeyConfirm';
import { BlockedJobAlert, JobErrorAlert, StillWorkingAlert } from './JobErrorAlert';
import { DialogActions } from './ui';
import { WRAP } from './wrap';
import { Icon } from '../design/Icon';

// form: nothing exists yet. working: a request or a job is running. winrm: a WinRM server exists and waits for its
// setup script and password (R71 Ruling 22). confirm: waiting for the Administrator's comparison. failed: the server
// exists but the check did not succeed (the dialog can only be left, never resubmitted).
type Phase = 'form' | 'working' | 'winrm' | 'confirm' | 'failed';

type ServerType = 'linux' | WebServerType | 'windows';

// The account Alice signs in as: the Linux setup script creates alice-svc, the Windows one alice (or a domain account).
const LINUX_USER = 'alice-svc';
const WINDOWS_USER = 'alice';

// WINDOWS_USER_RE is the server's Windows account rule (R60 Ruling 1, internal/providers/windows/config.go): an
// optional NetBIOS domain of at most 15 characters and a backslash, then a SAM name of at most 20. It holds no quote,
// so the name can stand inside the script's single quotes.
const WINDOWS_USER_RE = /^([A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;

// WINRM_USER_RE is the same rule under WinRM, which also takes a local account written .\name (R71 Ruling 6).
const WINRM_USER_RE = /^(\.\\|[A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;

// The ports each transport of a Windows server listens on by default (R71 Ruling 2).
const PORTS: Record<WindowsTransport, number> = { ssh: 22, winrm: 5986 };

// withWindowsAccount sets the script's $AliceUser line to the account when the account passes the rule; otherwise
// the script keeps its default (the server refuses such a name when the form is sent).
function withWindowsAccount(script: string, account: string): string {
  if (!WINDOWS_USER_RE.test(account)) return script;
  return script.replace(/^\$AliceUser = '[^'\r\n]*'$/m, () => `$AliceUser = '${account}'`);
}

// AddServerModal creates a Linux or an Nginx server, waits for the first connection test and, when the server
// presented a fingerprint nobody confirmed yet, asks the Administrator to compare and confirm it.
// The server counts toward the license as soon as it is created (spec §7.3), so after the create
// call succeeds the form never comes back: problems end in the "failed" phase with a way to open
// the server. Closing the dialog stops the waiting and nothing navigates afterwards.
//
// A screen that cannot offer to open the server (the setup wizard) passes onFailedClose: the failed
// phase then has only Close, which reports the server through onFailedClose instead of onAdded, so
// that screen never shows the success of a check that did not succeed.
export function AddServerModal({
  onClose,
  onAdded,
  onFailedClose,
  initial,
}: {
  onClose: () => void;
  onAdded: (target: Target) => void;
  onFailedClose?: (target: Target) => void;
  // initial pre-fills the form (Network discovery's "Add as server": the address or host name found on the network).
  // The port stays the SSH port: the port a certificate was found on is not how Alice signs in to the server.
  initial?: { name?: string; host?: string };
}) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [type, setType] = useState<ServerType>('linux');
  const [name, setName] = useState(initial?.name ?? '');
  const [host, setHost] = useState(initial?.host ?? '');
  const [port, setPort] = useState<number | string>(22);
  const [username, setUsername] = useState(LINUX_USER);
  // userEdited: the person typed the account, so choosing another server type leaves it alone.
  const [userEdited, setUserEdited] = useState(false);
  const [transport, setTransport] = useState<WindowsTransport>('ssh');
  const [phase, setPhase] = useState<Phase>('form');
  const [error, setError] = useState<unknown>(null);
  const [jobError, setJobError] = useState<JobError | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [target, setTarget] = useState<Target | null>(null);
  const [candidate, setCandidate] = useState<HostKey | null>(null);
  // afterPassword: the connection test follows a saved WinRM password, so a failure gets the password hint (A9, R72).
  const [afterPassword, setAfterPassword] = useState(false);
  const abort = useAbort();

  // chooseType switches the server type; the account follows the type's default until the person edits it.
  const chooseType = (next: ServerType) => {
    setType(next);
    if (!userEdited) setUsername(next === 'windows' ? WINDOWS_USER : LINUX_USER);
    if (next !== 'windows' && transport === 'winrm') chooseTransport('ssh');
  };

  // chooseTransport switches a Windows server between OpenSSH and WinRM; the port follows the transport's default.
  const chooseTransport = (next: WindowsTransport) => {
    setTransport(next);
    setPort(PORTS[next]);
  };
  const winrm = type === 'windows' && transport === 'winrm';
  const userInvalid = winrm && username.trim() !== '' && !WINRM_USER_RE.test(username.trim());

  const refresh = () => void client.invalidateQueries({ queryKey: TARGETS_KEY });

  // close stops all waiting. A created server shows up in the list.
  const close = () => {
    abort.abort();
    if (target) refresh();
    if (target && (phase === 'failed' || phase === 'winrm') && onFailedClose) onFailedClose(target);
    else onClose();
  };
  const openServer = () => {
    abort.abort();
    if (target) {
      refresh();
      onAdded(target);
    }
  };

  // settle decides what a finished connection test means for the dialog.
  const settle = async (tgt: Target, job: Job, signal: AbortSignal) => {
    if (job.status === 'succeeded') {
      refresh();
      onAdded(tgt);
      return;
    }
    if (job.status === 'blocked_license') {
      setBlocked(true);
      setPhase('failed');
      return;
    }
    if (job.error?.reason === 'target.host_key_unconfirmed') {
      const keys = await listHostKeys(tgt.id);
      if (signal.aborted) return;
      const observed = keys.items.find((k) => k.status === 'observed') ?? null;
      if (observed) {
        setCandidate(observed);
        setPhase('confirm');
        return;
      }
    }
    setJobError(job.error);
    setPhase('failed');
  };

  // afterCreate runs the steps that follow a successful create call; any problem leaves the dialog
  // in the "failed" phase (or back at the confirmation), never at the form.
  const afterCreate = async (tgt: Target, step: (signal: AbortSignal) => Promise<Job>) => {
    const signal = abort.signal();
    setError(null);
    setJobError(null);
    setBlocked(false);
    setPhase('working');
    try {
      await settle(tgt, await step(signal), signal);
    } catch (e) {
      if (isAbort(e) || signal.aborted) return;
      setError(e);
      refresh();
      setPhase('failed');
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (userInvalid) return;
    const signal = abort.signal();
    setError(null);
    setPhase('working');
    let created;
    try {
      created = await createTarget({ name: name.trim(), type, host: host.trim(), port: Number(port), username: username.trim(), ...(winrm ? { transport } : {}) });
    } catch (err) {
      if (signal.aborted) return;
      setError(err);
      setPhase('form');
      return;
    }
    if (signal.aborted) {
      refresh();
      return;
    }
    setTarget(created.target);
    refresh();
    // A WinRM server cannot be reached before its password is set: its first test only says so, so the dialog shows
    // the setup script and the password, and tests the connection once the password is saved.
    if (winrm) {
      setPhase('winrm');
      return;
    }
    await afterCreate(created.target, (s) => waitForJob(created.job_id, { signal: s }));
  };

  // passwordSaved tests the connection of a WinRM server with the password just set; its listener's identity comes next.
  const passwordSaved = (saved: Target) => {
    setTarget(saved);
    setAfterPassword(true);
    void afterCreate(saved, async (s) => {
      const res = await testTarget(saved.id);
      return waitForJob(res.job_id, { signal: s });
    });
  };

  const confirm = () => {
    if (!target || !candidate) return;
    void afterCreate(target, async (s) => {
      const res = await confirmHostKey(target.id, candidate.id, candidate.fingerprint);
      return waitForJob(res.job_id, { signal: s });
    });
  };

  const problem = error instanceof JobTimeoutError ? <StillWorkingAlert /> : <ErrorAlert error={error} />;

  return (
    <AppModal opened onClose={close} title={phase === 'confirm' ? t('hostKeys.confirmTitle') : t('targets.add')} size="lg">
      {phase === 'working' && (
        <Group gap="sm" role="status" aria-live="polite">
          <Loader size="sm" aria-hidden />
          <Text size="sm">{t('targets.connecting')}</Text>
        </Group>
      )}
      {phase === 'form' && (
        <form onSubmit={(e) => void submit(e)}>
          <Stack gap="sm">
            <NativeSelect
              label={t('targets.form.type')}
              description={t('targets.form.typeHelp')}
              value={type}
              onChange={(e) => chooseType(e.currentTarget.value as ServerType)}
              data={[
                { value: 'linux', label: t('targets.form.typeLinux') },
                ...WEB_SERVER_TYPES.map((type) => ({ value: type, label: t('targets.form.typeWebServer', { software: softwareName(t, type) }) })),
                { value: 'windows', label: t('targets.form.typeWindows') },
              ]}
            />
            {type === 'windows' && (
              <NativeSelect
                label={t('targets.form.transport')}
                description={t('targets.form.transportHelp')}
                value={transport}
                onChange={(e) => chooseTransport(e.currentTarget.value as WindowsTransport)}
                data={[
                  { value: 'ssh', label: t('targets.form.transportSsh') },
                  { value: 'winrm', label: t('targets.form.transportWinrm') },
                ]}
              />
            )}
            {winrm ? (
              <>
                <Alert color="yellow" role="note" icon={<Icon name="ShieldAlert" size={16} />}>
                  {t('targets.form.winrmWarning')}
                </Alert>
                <Text size="sm">{t('targets.form.winrmScriptLater')}</Text>
              </>
            ) : (
              <ProfileScript type={type} account={username} />
            )}
            <TextInput label={t('targets.form.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={100} data-autofocus />
            <TextInput
              label={t('targets.form.host')}
              description={t('targets.form.hostHelp')}
              value={host}
              onChange={(e) => setHost(e.currentTarget.value)}
              required
              maxLength={253}
              autoComplete="off"
            />
            <NumberInput label={t(winrm ? 'targets.form.portWinrm' : 'targets.form.port')} value={port} onChange={setPort} min={1} max={65535} allowDecimal={false} required />
            <TextInput
              label={t(type === 'windows' ? 'targets.form.usernameWindows' : 'targets.form.username')}
              description={type === 'windows' ? t(winrm ? 'targets.form.usernameWinrmHelp' : 'targets.form.usernameWindowsHelp') : undefined}
              error={userInvalid ? t('targets.form.usernameWinrmInvalid') : undefined}
              value={username}
              onChange={(e) => {
                setUserEdited(true);
                setUsername(e.currentTarget.value);
              }}
              required
              maxLength={type === 'windows' ? 36 : 32}
              autoComplete="off"
            />
            {problem}
          </Stack>
          <DialogActions>
            <Button type="submit" rightSection={<Icon name="ArrowRight" size={15} />}>
              {t('targets.form.submit')}
            </Button>
          </DialogActions>
        </form>
      )}
      {phase === 'winrm' && target && (
        <Stack gap="sm">
          <WinRMSetupScript targetId={target.id} />
          <Text size="sm">{t('targets.winrm.passwordStep')}</Text>
          <CCSPasswordPanel kind="winrm" target={target} canSet onSaved={passwordSaved} />
          <Text size="sm">{t('targets.winrm.closeWithoutPassword')}</Text>
          <DialogActions>
            <Button variant="default" onClick={close}>
              {t('ui.close')}
            </Button>
          </DialogActions>
        </Stack>
      )}
      {phase === 'confirm' && target && candidate && (
        <Stack gap="sm">
          <HostKeyConfirm host={target.host} hostKey={candidate} onYes={confirm} onNo={close} />
          {problem}
        </Stack>
      )}
      {phase === 'failed' && (
        <Stack gap="sm">
          {blocked && <BlockedJobAlert />}
          {error !== null && problem}
          <JobErrorAlert error={jobError} />
          {!blocked && error === null && <Text size="sm">{t('targets.failedHelp')}</Text>}
          {afterPassword && <Text size="sm">{t('targets.winrm.failedAfterPassword')}</Text>}
          <DialogActions>
            <Button variant="default" onClick={close}>
              {t('ui.close')}
            </Button>
            {!onFailedClose && <Button onClick={openServer}>{t('targets.openServer')}</Button>}
          </DialogActions>
        </Stack>
      )}
    </AppModal>
  );
}

// WinRMSetupScript shows the script that prepares a Windows server for WinRM (GET /targets/{id}/winrm-setup, R71 Ruling
// 19). It holds no secret; a build that cannot verify the helper answers an empty script, which is not shown. Alice's
// address, when typed, is sent as ?from= (R72 Ruling 3).
export function WinRMSetupScript({ targetId }: { targetId: string }) {
  const { t } = useTranslation();
  const [from, field] = useAliceAddress();
  const setup = useQuery({ queryKey: [...targetKey(targetId), 'winrm-setup', from], queryFn: () => getWinRMSetup(targetId, from) });
  return (
    <Stack gap="xs">
      {field(setup.error)}
      {setup.data?.script ? (
        <ScriptBlock title={t('targets.winrm.setupTitle')} help={t('targets.winrm.setupHelp')} script={setup.data.script} testId="winrm-setup-script" />
      ) : (
        <AddressError error={setup.error} />
      )}
    </Stack>
  );
}

// useAliceAddress is the optional "Alice's address" field of a setup script (R72 Ruling 3): the debounced address to
// send as ?from= ('' for none) and the field, which shows the API's error on from (the API decides what is valid).
function useAliceAddress(): [string, (error: unknown) => ReactNode] {
  const { t, i18n } = useTranslation();
  const [value, setValue] = useState('');
  const [from] = useDebouncedValue(value.trim(), 400);
  const field = (error: unknown) => (
    <TextInput
      label={t('targets.form.aliceAddress')}
      description={t('targets.form.aliceAddressHelp')}
      value={value}
      onChange={(e) => setValue(e.currentTarget.value)}
      error={fieldErrorsOf(error, t, i18n).from}
      maxLength={64}
      autoComplete="off"
      spellCheck={false}
    />
  );
  return [from, field];
}

// AddressError is a script's load error, unless it is the address field's own (shown under the field).
function AddressError({ error }: { error: unknown }) {
  const { t, i18n } = useTranslation();
  return 'from' in fieldErrorsOf(error, t, i18n) ? null : <ErrorAlert error={error} />;
}

// ProfileScript shows the commands that prepare a server of the chosen type (the profile's setup
// script from Alice, the same text the Servers page shows). The script is not secret. The Windows script names the
// account typed in the form (final review I1).
function ProfileScript({ type, account }: { type: ServerType; account: string }) {
  const { t } = useTranslation();
  const [from, field] = useAliceAddress();
  const key = useQuery({ queryKey: from ? [...PLATFORM_KEY_KEY, from] : PLATFORM_KEY_KEY, queryFn: () => getPlatformKey(from) });
  const windows = type === 'windows';
  const shown = key.data?.profiles[type]?.script;
  const script = shown && windows ? withWindowsAccount(shown, account.trim()) : shown;
  const title = t(windows ? 'targets.form.scriptWindows' : 'targets.form.script');
  return (
    <Stack gap="xs">
      {field(key.error)}
      {script ? (
        <ScriptBlock title={title} help={windows ? t('targets.form.scriptWindowsHelp') : undefined} script={script} testId="add-server-script" />
      ) : (
        <AddressError error={key.error} />
      )}
    </Stack>
  );
}

// ScriptBlock is a setup script with its title, an optional help line and a copy button.
function ScriptBlock({ title, help, script, testId }: { title: string; help?: string; script: string; testId: string }) {
  const { t } = useTranslation();
  return (
    <Stack gap={4}>
      <Text size="sm" fw={600}>
        {title}
      </Text>
      {help && <Text size="xs">{help}</Text>}
      <Code block tabIndex={0} aria-label={title} data-testid={testId} style={{ ...WRAP, maxHeight: 160, overflow: 'auto' }} translate="no">
        {script}
      </Code>
      <CopyButton value={script}>
        {({ copied, copy }) => (
          <Button size="xs" variant="light" onClick={copy} w="fit-content" leftSection={<Icon name={copied ? 'Check' : 'Copy'} size={14} />}>
            {copied ? t('targets.prepare.copied') : t('targets.prepare.copy')}
          </Button>
        )}
      </CopyButton>
    </Stack>
  );
}
