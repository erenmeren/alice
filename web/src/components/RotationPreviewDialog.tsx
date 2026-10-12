import { Alert, Button, Code, Group, Loader, Stack, Table, Text } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { previewPolicy, runPolicy, type Policy, type Preview, type PreviewAction } from '../api/rotation';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { noteText, skipText } from './rotationText';
import { useStepUp } from './StepUpProvider';
import { DialogActions } from './ui';
import { WRAP } from './wrap';

function ChangeCell({ a }: { a: PreviewAction }) {
  const { t, i18n } = useTranslation();
  if (a.skip_reason !== '')
    return (
      <Stack gap={2}>
        <Text size="sm" fw={600}>
          {t('rotation.skipped')}
        </Text>
        <Text size="xs">{skipText(t, i18n, a.skip_reason)}</Text>
      </Stack>
    );
  return (
    <Stack gap={4}>
      <Text size="sm" fw={600}>
        {t('rotation.willChange')}
      </Text>
      {a.add_line && (
        <>
          <Text size="xs">{t('rotation.adds')}</Text>
          <Code translate="no" style={WRAP}>
            {a.add_line}
          </Code>
        </>
      )}
      {a.remove_line && (
        <>
          <Text size="xs">{t('rotation.removesAfter')}</Text>
          <Code translate="no" style={WRAP}>
            {a.remove_line}
          </Code>
        </>
      )}
    </Stack>
  );
}

function PreviewBody({ policy, onClose, onStarted }: { policy: Policy; onClose: () => void; onStarted: (rotationId: string) => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [confirming, setConfirming] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<unknown>(null);
  const [refreshed, setRefreshed] = useState(false);
  const alive = useRef(true);
  const asked = useRef(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const p = await previewPolicy(policy.id);
      if (alive.current) setPreview(p);
    } catch (e) {
      if (alive.current) setError(e);
    }
    if (alive.current) setLoading(false);
  };

  useEffect(() => {
    alive.current = true;
    // One request per opening, also under React StrictMode's second mount: a preview sends the administrators an email.
    if (!asked.current) {
      asked.current = true;
      void load();
    }
    return () => {
      alive.current = false;
    };
    // load reads the policy id only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    if (!preview) return;
    setStarting(true);
    setStartError(null);
    try {
      // The digest is this preview's own: the server starts a run only when the plan it builds now is the same.
      const started = await run(() => runPolicy(policy.id, preview.plan_digest));
      onStarted(started.rotation_id);
      return;
    } catch (e) {
      if (isApiError(e, 'rotation.plan_changed')) {
        // Never retried by itself: the person looks at the new plan first.
        setConfirming(false);
        setRefreshed(true);
        setPreview(null);
        void load();
      } else {
        setStartError(e);
      }
    }
    if (alive.current) setStarting(false);
  };

  return (
    <>
      <Stack gap="sm">
        {loading && (
          <Group gap="sm" role="status" aria-live="polite">
            <Loader size="sm" aria-hidden />
            <Text size="sm">{t('rotation.previewing')}</Text>
          </Group>
        )}
        {refreshed && !loading && (
          <Alert color="yellow" role="alert">
            {t('rotation.previewRefreshed')}
          </Alert>
        )}
        <ErrorAlert error={error} />
        {preview && (
          <>
            <Text size="sm">{t('rotation.previewIntro')}</Text>
            <Group gap="lg">
              <Text size="sm" fw={600}>
                {t('rotation.changes', { count: preview.change_count })}
              </Text>
              <Text size="sm" fw={600}>
                {t('rotation.skips', { count: preview.skip_count })}
              </Text>
            </Group>
            <Text size="sm">{t(preview.emailed ? 'rotation.previewEmailed' : 'rotation.previewNotEmailed')}</Text>
            {preview.change_count === 0 && (
              <Alert color="yellow" role="status">
                {t('rotation.nothingToChange')}
              </Alert>
            )}
            <Table.ScrollContainer minWidth={640}>
              <Table striped aria-label={t('rotation.previewTitle')}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('rotation.col.server')}</Table.Th>
                    <Table.Th>{t('rotation.col.user')}</Table.Th>
                    <Table.Th>{t('rotation.col.file')}</Table.Th>
                    <Table.Th>{t('rotation.col.change')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {preview.actions.map((a) => (
                    <Table.Tr key={a.n}>
                      <Table.Td style={WRAP} translate="no">
                        {a.target_name}
                      </Table.Td>
                      <Table.Td style={WRAP} translate="no">
                        {a.os_user}
                      </Table.Td>
                      <Table.Td>
                        <Code translate="no" style={WRAP}>
                          {a.file_path}
                        </Code>
                      </Table.Td>
                      <Table.Td>
                        <Stack gap={4}>
                          <ChangeCell a={a} />
                          {a.skip_reason === '' && !a.verify && <Text size="xs">{t('rotation.noLoginTest')}</Text>}
                          {a.skip_reason === '' && noteText(t, i18n, a.verify_note) !== '' && <Text size="xs">{noteText(t, i18n, a.verify_note)}</Text>}
                        </Stack>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </>
        )}
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('ui.close')}
        </Button>
        <Button onClick={() => setConfirming(true)} disabled={!preview || loading || preview.change_count === 0}>
          {t('rotation.runNow')}
        </Button>
      </DialogActions>
      {confirming && (
        <AppModal opened onClose={() => !starting && setConfirming(false)} title={t('rotation.runConfirmTitle')} centered zIndex={400}>
          <Stack gap="sm">
            <Text size="sm">{t('rotation.previewIntro')}</Text>
            <ErrorAlert error={startError} />
          </Stack>
          <DialogActions>
            <Button variant="default" onClick={() => setConfirming(false)} disabled={starting}>
              {t('ui.cancel')}
            </Button>
            <Button loading={starting} onClick={() => void start()}>
              {t('rotation.runConfirm')}
            </Button>
          </DialogActions>
        </AppModal>
      )}
    </>
  );
}

// RotationPreviewDialog asks the server to plan the policy's next run when it opens and shows the plan: where a new key is
// added, where it is skipped and why, and what is removed after the overlap. Run now starts the rotation with THIS plan's
// digest, with the Administrator's fresh code. When the plan changed in the meantime the server refuses (409); the dialog then
// shows the new plan and asks again; nothing starts by itself.
export function RotationPreviewDialog(props: { policy: Policy; onClose: () => void; onStarted: (rotationId: string) => void }) {
  const { t } = useTranslation();
  return (
    <AppModal opened onClose={props.onClose} title={t('rotation.previewTitle')} size="xl">
      <PreviewBody {...props} />
    </AppModal>
  );
}
