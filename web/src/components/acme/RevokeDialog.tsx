import { Button, Checkbox, NativeSelect, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { revokeACMECertificate, type ACMECertificate, type ACMEOrder } from '../../api/acme';
import { ACME_CERTIFICATES_KEY, acmeCertificateKey, acmeOrdersKey, CERTIFICATES_KEY } from '../../api/queryKeys';
import { REVOCATION_REASONS, type RevocationReason } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';

// revocableVersions are the issued certificates of the orders that are not revoked yet, newest first (the current
// certificate among them).
export function revocableVersions(orders: ACMEOrder[] | undefined): ACMEOrder[] {
  return (orders ?? []).filter((o) => o.kind === 'issue' && o.state === 'succeeded' && o.certificate_id !== null && o.revoked_at === null);
}

// RevokeDialog asks the certificate authority to revoke a version of the certificate (the current one by default) for a
// reason. It cannot be undone: the person ticks that they understand, and the server asks for a fresh step-up. A key that
// leaked is better handled by the incident (it replaces the certificate first); the dialog says so.
export function RevokeDialog({ c, orders, onClose }: { c: ACMECertificate; orders: ACMEOrder[] | undefined; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const versions = revocableVersions(orders);
  const current = c.current?.id ?? '';
  const [version, setVersion] = useState<string>(current || versions[0]?.certificate_id || '');
  const [reason, setReason] = useState<RevocationReason>('superseded');
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const options = versions.map((o) => ({
    value: o.certificate_id ?? '',
    label:
      o.certificate_id === current
        ? t('acme.issued.revoke.currentVersion', { time: formatDateTime(o.finished_at ?? o.started_at, i18n.language) })
        : t('acme.issued.revoke.olderVersion', { time: formatDateTime(o.finished_at ?? o.started_at, i18n.language) }),
  }));
  if (current && !options.some((o) => o.value === current)) options.unshift({ value: current, label: t('acme.issued.revoke.currentVersion', { time: '' }) });
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(() => revokeACMECertificate(c.id, reason, version === current ? undefined : version));
      setDone(true);
      void client.invalidateQueries({ queryKey: acmeCertificateKey(c.id) });
      void client.invalidateQueries({ queryKey: acmeOrdersKey(c.id) });
      void client.invalidateQueries({ queryKey: ACME_CERTIFICATES_KEY, predicate: (q) => q.queryKey[2] === 'list' });
      void client.invalidateQueries({ queryKey: CERTIFICATES_KEY });
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };
  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t('acme.issued.revoke.title')}>
      <Stack gap="sm">
        {done ? (
          <Notice tone="success" role="status" title={t('acme.issued.revoke.done')} testId="revoked">
            {t(c.auto_renew ? 'acme.issued.revoke.doneRenew' : 'acme.issued.revoke.doneNoRenew')}
          </Notice>
        ) : (
          <>
            <Text size="sm">{t('acme.issued.revoke.text')}</Text>
            <Notice tone="warning" title={t('acme.issued.revoke.leakedTitle')}>
              {t('acme.issued.revoke.leakedText')}
            </Notice>
            <NativeSelect label={t('acme.issued.revoke.version')} data={options} value={version} onChange={(e) => setVersion(e.currentTarget.value)} />
            <NativeSelect
              label={t('acme.issued.revoke.reason')}
              data={REVOCATION_REASONS.map((r) => ({ value: r, label: t(`acme.issued.revoke.reasons.${r}`) }))}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value as RevocationReason)}
            />
            <Checkbox checked={understood} onChange={(e) => setUnderstood(e.currentTarget.checked)} label={t('acme.issued.revoke.understood')} />
          </>
        )}
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t(done ? 'ui.close' : 'ui.cancel')}
          </Button>
          {!done && (
            <Button color="red" loading={busy} disabled={!understood || !version} onClick={() => void go()}>
              {t('acme.issued.revoke.confirm')}
            </Button>
          )}
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
