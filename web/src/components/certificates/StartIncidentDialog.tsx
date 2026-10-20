import { Button, Checkbox, List, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { startIncident } from '../../api/incidents';
import { CERTIFICATES_KEY, INCIDENTS_KEY } from '../../api/queryKeys';
import type { Certificate } from '../../api/types';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';

// StartIncidentDialog starts a key compromise incident ("this private key leaked"): it says, before anything happens,
// that every certificate with the key is marked compromised for good, where the replacement comes from, and when (and
// whether) Alice revokes the certificate. An Administrator with a fresh step-up; it cannot be undone.
export function StartIncidentDialog({ certificate, onClose }: { certificate: Pick<Certificate, 'id' | 'source'>; onClose: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const navigate = useNavigate();
  const client = useQueryClient();
  const acme = certificate.source === 'acme';
  const [now, setNow] = useState(false);
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      const i = await run(() => startIncident(certificate.id, now ? 'now' : 'after_verified'));
      void client.invalidateQueries({ queryKey: CERTIFICATES_KEY });
      void client.invalidateQueries({ queryKey: INCIDENTS_KEY });
      void navigate(`/incidents/${i.id}`);
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('incidents.start.title')} size="lg">
      <Stack gap="sm">
        <Text size="sm">{t('incidents.start.intro')}</Text>
        <List size="sm" spacing={4}>
          <List.Item>{t('incidents.start.stepMark')}</List.Item>
          <List.Item>{t(acme ? 'incidents.start.stepOrder' : 'incidents.start.stepChoose')}</List.Item>
          <List.Item>{t('incidents.start.stepDeploy')}</List.Item>
          <List.Item>{t(acme ? 'incidents.start.stepRevoke' : 'incidents.start.stepNoRevoke')}</List.Item>
        </List>
        {!acme && (
          <Notice tone="warning" title={t('incidents.start.notRevocableTitle')} testId="not-revocable">
            {t('incidents.start.notRevocableText')}
          </Notice>
        )}
        {acme && <Checkbox checked={now} onChange={(e) => setNow(e.currentTarget.checked)} label={t('incidents.start.revokeNow')} description={t('incidents.start.revokeNowHelp')} />}
        <Checkbox checked={understood} onChange={(e) => setUnderstood(e.currentTarget.checked)} label={t('incidents.start.understood')} />
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button color="red" loading={busy} disabled={!understood} onClick={() => void go()}>
            {t('incidents.start.confirm')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
