import { Alert, Box, Button, Checkbox, Code, Stack, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useInfiniteQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { createBinding, listDeployableLocations, updateBindingLocations, type Binding, type DeployableLocation, type KVCertificateDetail } from '../api/keyvault';
import { BINDINGS_KEY, KV_CERTIFICATES_KEY } from '../api/queryKeys';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { LoadingIndicator } from './LoadingIndicator';
import { useStepUp } from './StepUpProvider';
import { DialogActions } from './ui';
import { keyTypeParam } from './vaultText';
import { WRAP } from './wrap';

const MAX_LOCATIONS = 200;

// ConnectWebsitesDialog connects 1 to 200 websites (on any server) to a vault certificate, or adds
// websites to an existing connection. The list is the websites that fit the certificate's key type
// and are not connected yet. All or nothing: a refusal names the first website that stops the request,
// which is highlighted. Adding to a connection that deploys automatically puts the new websites under
// automatic deployment; it needs an Administrator's fresh step-up (asked for when the server wants it).
export function ConnectWebsitesDialog({ certificate, binding, onClose, onDone }: { certificate: KVCertificateDetail; binding?: Binding; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const { run } = useStepUp();
  const [search, setSearch] = useState('');
  const [q] = useDebouncedValue(search.trim(), 250);
  const [picked, setPicked] = useState<Record<string, DeployableLocation>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [moved, setMoved] = useState(false);
  const keyType = keyTypeParam(certificate.key_type);

  const list = useInfiniteQuery({
    queryKey: ['locations', 'deployable', keyType, q],
    queryFn: ({ pageParam }) => listDeployableLocations({ key_type: keyType || undefined, unbound: true, q: q || undefined, cursor: pageParam, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const chosen = Object.values(picked);
  const existing = binding?.locations.map((l) => l.location_id) ?? [];
  const total = existing.length + chosen.length;
  const tooMany = total > MAX_LOCATIONS;

  const toggle = (l: DeployableLocation, on: boolean) =>
    setPicked((p) => {
      const next = { ...p };
      if (on) next[l.id] = l;
      else delete next[l.id];
      return next;
    });

  const submit = async () => {
    setBusy(true);
    setError(null);
    setRefused(null);
    setMoved(false);
    const ids = chosen.map((l) => l.id);
    try {
      if (binding) await run(() => updateBindingLocations(binding.id, binding.version, [...existing, ...ids]));
      else await createBinding(certificate.id, ids);
      void client.invalidateQueries({ queryKey: BINDINGS_KEY });
      void client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY });
      void client.invalidateQueries({ queryKey: ['locations'] });
      onDone();
      return;
    } catch (e) {
      setError(e);
      if (isApiError(e) && e.params.location_id) setRefused(e.params.location_id);
      if (isApiError(e) && e.status === 412) {
        setMoved(true);
        void client.invalidateQueries({ queryKey: BINDINGS_KEY });
      }
    }
    setBusy(false);
  };

  return (
    <AppModal opened onClose={() => !busy && onClose()} title={t(binding ? 'bindings.addTitle' : 'bindings.connect')} size="lg">
      <Stack gap="sm">
        <Text size="sm">{t('bindings.connectHelp')}</Text>
        {binding?.auto_deploy && (
          <Alert color="yellow" role="status">
            {t('bindings.addAutoWarning')}
          </Alert>
        )}
        <TextInput label={t('bindings.search')} value={search} onChange={(e) => setSearch(e.currentTarget.value)} maxLength={200} autoComplete="off" />
        {list.isPending && <LoadingIndicator />}
        <ErrorAlert error={list.error} />
        {list.isSuccess && items.length === 0 && <Text size="sm">{t('bindings.noLocations')}</Text>}
        <Stack gap="xs" role="group" aria-label={t('bindings.websites')}>
          {items.map((l) => {
            const bad = refused === l.id;
            return (
              <Box key={l.id} data-refused={bad ? 'true' : undefined} p="xs" style={bad ? { border: '2px solid var(--alice-danger)', borderRadius: 'var(--alice-radius-sm)' } : undefined}>
                <Checkbox
                  checked={l.id in picked}
                  onChange={(e) => toggle(l, e.currentTarget.checked)}
                  disabled={busy}
                  error={bad ? t('bindings.refused') : undefined}
                  label={
                    <span style={WRAP}>
                      <Text span translate="no" fw={600}>
                        {l.target_name}
                      </Text>{' '}
                      {l.server_names.map((n) => (
                        <Code key={n} translate="no" mr={4}>
                          {n}
                        </Code>
                      ))}
                      <Code translate="no">{l.cert_path}</Code>
                    </span>
                  }
                />
              </Box>
            );
          })}
        </Stack>
        {list.hasNextPage && (
          <Button variant="default" w="fit-content" loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {t('vaults.showMore')}
          </Button>
        )}
        <Text size="sm" role="status">
          {t('bindings.selectedCount', { count: chosen.length })}
        </Text>
        {tooMany && (
          <Alert color="red" role="alert">
            {t('bindings.limit', { max: MAX_LOCATIONS })}
          </Alert>
        )}
        {moved && (
          <Alert color="yellow" role="status">
            {t('bindings.moved')}
          </Alert>
        )}
        <ErrorAlert error={error} />
        <DialogActions>
          <Button variant="default" disabled={busy} onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button loading={busy} disabled={chosen.length === 0 || tooMany} onClick={() => void submit()}>
            {t(binding ? 'bindings.addWebsites' : 'bindings.connect')}
          </Button>
        </DialogActions>
      </Stack>
    </AppModal>
  );
}
