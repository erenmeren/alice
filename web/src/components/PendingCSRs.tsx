import { Alert, Button, Card, Code, Group, Stack, Table, Text, Textarea, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { keyAlgorithmKey } from '../api/enums';
import { cancelCSR, completeCSR, listCSRs } from '../api/endpoints';
import { CERTIFICATES_KEY, CSRS_KEY } from '../api/queryKeys';
import type { CSR, UploadResult } from '../api/types';
import { formatDateTime } from '../datetime';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { UploadWarnings } from './UploadWarnings';
import { WRAP } from './wrap';

const MAX_BYTES = 256 * 1024;

// namesOf is the request's names for display: the SANs (the common name first), else the common name.
const namesOf = (c: CSR) => (c.sans.length > 0 ? c.sans.join(', ') : c.common_name);

// CompleteDialog adds the certificate an authority issued for one pending request. The certificate
// is public data; the request's key stays in Alice and is never involved here.
function CompleteDialog({ csr, onClose, onCompleted }: { csr: CSR; onClose: () => void; onCompleted: (certificateId: string) => void }) {
  const { t } = useTranslation();
  const [pem, setPem] = useState('');
  const [problem, setProblem] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<UploadResult | null>(null);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (pem.trim() === '') return setProblem(t('certificates.csr.certificateRequired'));
    if (new Blob([pem]).size > MAX_BYTES) return setProblem(t('certificates.upload.textTooLarge'));
    setProblem('');
    setBusy(true);
    setError(null);
    try {
      const res = await completeCSR(csr.id, pem);
      setResult(res);
      onCompleted(res.certificate.id);
    } catch (e) {
      setError(e);
    }
    setBusy(false);
  };

  return (
    <AppModal opened onClose={onClose} title={t('certificates.csr.completeTitle')} size="lg">
      {result ? (
        <Stack gap="sm">
          <Alert color="green" role="status">
            {t('certificates.csr.completed')}
          </Alert>
          <UploadWarnings warnings={result.warnings} />
          <Group justify="flex-end">
            <Button onClick={onClose}>{t('certificates.upload.close')}</Button>
          </Group>
        </Stack>
      ) : (
        <form onSubmit={(ev) => void submit(ev)} noValidate>
          <Stack gap="sm">
            <Text size="sm">{t('certificates.csr.completeHelp', { name: csr.common_name })}</Text>
            <Textarea
              data-autofocus
              label={t('certificates.csr.certificatePem')}
              value={pem}
              onChange={(e) => setPem(e.currentTarget.value)}
              error={problem || undefined}
              autosize
              minRows={5}
              maxRows={12}
              spellCheck={false}
              autoComplete="off"
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            <ErrorAlert error={error} />
            <Group justify="flex-end">
              <Button variant="default" onClick={onClose}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" loading={busy}>
                {t('certificates.csr.completeSubmit')}
              </Button>
            </Group>
          </Stack>
        </form>
      )}
    </AppModal>
  );
}

// CancelDialog asks before a request is closed: no certificate can be added for it afterwards.
function CancelDialog({ csr, onClose, onCancelled }: { csr: CSR; onClose: () => void; onCancelled: () => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await cancelCSR(csr.id);
      onCancelled();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };

  return (
    <AppModal opened onClose={onClose} title={t('certificates.csr.cancelTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t('certificates.csr.cancelHelp')}</Text>
        <Code style={WRAP}>{namesOf(csr)}</Code>
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" data-autofocus onClick={onClose}>
            {t('certificates.csr.keep')}
          </Button>
          {/* red 9: white text 5.4:1 (WCAG AA). */}
          <Button color="red.9" loading={busy} onClick={() => void confirm()}>
            {t('certificates.csr.cancelRequest')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}

// PendingCSRs lists the signing requests that wait for a certificate (the API sends every pending
// one and some finished ones). It shows nothing when none is pending. Without canOperate the list
// has no actions.
export function PendingCSRs({ canOperate, onCompleted }: { canOperate: boolean; onCompleted: (certificateId: string) => void }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const list = useQuery({ queryKey: CSRS_KEY, queryFn: listCSRs });
  const [completing, setCompleting] = useState<CSR | null>(null);
  const [cancelling, setCancelling] = useState<CSR | null>(null);
  const pending = (list.data?.items ?? []).filter((c) => c.status === 'pending');

  const refresh = () => Promise.all([client.invalidateQueries({ queryKey: CSRS_KEY }), client.invalidateQueries({ queryKey: CERTIFICATES_KEY })]);

  return (
    <>
      <ErrorAlert error={list.error} />
      {pending.length > 0 && (
        <Card withBorder padding="md" data-testid="pending-csrs">
          <Stack gap="xs">
            <Title order={2} size="h3">
              {t('certificates.csr.pendingTitle')}
            </Title>
            <Table.ScrollContainer minWidth={560}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('certificates.csr.names')}</Table.Th>
                    <Table.Th>{t('certificates.detail.key')}</Table.Th>
                    <Table.Th>{t('certificates.csr.createdColumn')}</Table.Th>
                    {canOperate && <Table.Th>{t('sshKeys.actions')}</Table.Th>}
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {pending.map((c) => (
                    <Table.Tr key={c.id}>
                      <Table.Td>
                        <Code style={WRAP} id={`csr-names-${c.id}`}>
                          {namesOf(c)}
                        </Code>
                      </Table.Td>
                      <Table.Td>{t('certificates.detail.keyValue', { algorithm: t(keyAlgorithmKey(c.key_algorithm)), bits: c.key_bits })}</Table.Td>
                      <Table.Td>{formatDateTime(c.created_at, i18n.language)}</Table.Td>
                      {canOperate && (
                        <Table.Td>
                          <Group gap="xs" wrap="nowrap">
                            {/* The name of each button is its text plus the request's names (data, so not an aria-label text). */}
                            <Button size="xs" variant="light" onClick={() => setCompleting(c)} id={`csr-complete-${c.id}`} aria-labelledby={`csr-complete-${c.id} csr-names-${c.id}`}>
                              {t('certificates.csr.complete')}
                            </Button>
                            <Button size="xs" variant="subtle" color="red.9" onClick={() => setCancelling(c)} id={`csr-cancel-${c.id}`} aria-labelledby={`csr-cancel-${c.id} csr-names-${c.id}`}>
                              {t('certificates.csr.cancelRequest')}
                            </Button>
                          </Group>
                        </Table.Td>
                      )}
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Stack>
        </Card>
      )}
      {completing && (
        <CompleteDialog
          csr={completing}
          onClose={() => setCompleting(null)}
          onCompleted={(id) => {
            void refresh();
            onCompleted(id);
          }}
        />
      )}
      {cancelling && (
        <CancelDialog
          csr={cancelling}
          onClose={() => setCancelling(null)}
          onCancelled={() => {
            setCancelling(null);
            void refresh();
          }}
        />
      )}
    </>
  );
}
