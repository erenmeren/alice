import { Button, NativeSelect, Stack, Text } from '@mantine/core';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { startDiscoveryScan, type DiscoveryScan, type DiscoveryScope } from '../../api/discovery';
import { DISCOVERY_SCANS_KEY, DISCOVERY_SCOPES_KEY } from '../../api/queryKeys';
import { Icon } from '../../design/Icon';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { DialogActions } from '../ui';
import classes from './discovery.module.css';
import { startBlock, type StartBlock } from './shared';

export interface StartContext {
  locked: boolean;
  scanningEnabled: boolean;
  activeCount: number;
}

// useStartScan starts a scan of one scope (an Operator or an Administrator; no step-up). Afterwards the scopes (their scan
// in flight) and the scans are read again, and the scopes' polling follows the new scan.
export function useStartScan(onStarted?: (scan: DiscoveryScan) => void) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (scopeId: string) => startDiscoveryScan(scopeId),
    onSuccess: (scan) => {
      void client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY });
      void client.invalidateQueries({ queryKey: DISCOVERY_SCANS_KEY });
      onStarted?.(scan);
    },
    // A refusal (already running, two scans, switched off, locked) may mean the lists are behind.
    onError: () => {
      void client.invalidateQueries({ queryKey: DISCOVERY_SCOPES_KEY });
    },
  });
}

export const blockKey = (b: StartBlock) => `discovery.block.${b}`;

// How long "The scan has started" stays.
export const STARTED_MESSAGE_MS = 6000;

// ScanNowButton starts a scan of one scope from its row. A scope that cannot be scanned now keeps a disabled button with
// the reason as visible text it is described by (a tooltip on a disabled button reaches nobody).
export function ScanNowButton({ scope, ctx }: { scope: DiscoveryScope; ctx: StartContext }) {
  const { t } = useTranslation();
  const start = useStartScan();
  const block = startBlock(scope, ctx);
  // "The scan has started" is news for a few seconds, and never once the scan is over.
  const { reset, isSuccess } = start;
  useEffect(() => {
    if (!isSuccess) return;
    const timer = window.setTimeout(reset, STARTED_MESSAGE_MS);
    return () => window.clearTimeout(timer);
  }, [isSuccess, reset]);
  const sawRunning = useRef(false);
  useEffect(() => {
    if (!isSuccess) {
      sawRunning.current = false;
      return;
    }
    if (scope.active_scan_id) sawRunning.current = true;
    else if (sawRunning.current) reset();
  }, [isSuccess, scope.active_scan_id, reset]);
  const reasonId = `scan-block-${scope.id}`;
  return (
    <div>
      <Button
        size="xs"
        variant="default"
        leftSection={<Icon name="CirclePlay" size={14} />}
        disabled={block !== ''}
        loading={start.isPending}
        aria-describedby={block ? reasonId : undefined}
        aria-label={t('discovery.scopes.scanLabel', { name: scope.name })}
        onClick={() => start.mutate(scope.id)}
      >
        {t('discovery.scopes.scanNow')}
      </Button>
      {block && (
        <p className={classes.reason} id={reasonId}>
          {t(blockKey(block))}
        </p>
      )}
      {start.isSuccess && (
        <Text size="xs" role="status">
          {t('discovery.scans.started', { name: scope.name })}
        </Text>
      )}
      <ErrorAlert error={start.error} />
    </div>
  );
}

// StartScanDialog chooses the scope to scan. A scope that cannot be scanned now is listed with its reason and cannot be
// chosen.
export function StartScanDialog({ scopes, ctx, onClose, onStarted }: { scopes: DiscoveryScope[]; ctx: StartContext; onClose: () => void; onStarted: (scan: DiscoveryScan) => void }) {
  const { t } = useTranslation();
  const firstFree = scopes.find((s) => startBlock(s, ctx) === '');
  const [scopeId, setScopeId] = useState(firstFree?.id ?? '');
  const start = useStartScan(onStarted);
  const chosen = scopes.find((s) => s.id === scopeId);
  const block = chosen ? startBlock(chosen, ctx) : '';
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!chosen || block || start.isPending) return;
    start.mutate(chosen.id);
  };
  return (
    <AppModal opened onClose={onClose} title={t('discovery.scans.startTitle')}>
      <form onSubmit={submit}>
        <Stack gap="sm">
          <Text size="sm">{t('discovery.scans.startHelp')}</Text>
          <NativeSelect
            label={t('discovery.scans.scope')}
            value={scopeId}
            onChange={(e) => setScopeId(e.currentTarget.value)}
            data={[
              ...(firstFree ? [] : [{ value: '', label: t('discovery.scans.noScopeReady'), disabled: true }]),
              ...scopes.map((s) => {
                const b = startBlock(s, ctx);
                return { value: s.id, label: b ? t('discovery.scans.optionBlocked', { name: s.name, reason: t(blockKey(b)) }) : s.name, disabled: b !== '' };
              }),
            ]}
            data-autofocus
          />
          {block && <Text size="sm">{t(blockKey(block))}</Text>}
          <ErrorAlert error={start.error} />
        </Stack>
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" leftSection={<Icon name="CirclePlay" size={15} />} disabled={!chosen || block !== ''} loading={start.isPending}>
            {t('discovery.scans.startConfirm')}
          </Button>
        </DialogActions>
      </form>
    </AppModal>
  );
}
