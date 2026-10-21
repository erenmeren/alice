import { Button, List, NativeSelect, Stack, Text } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listACMECertificates } from '../../api/acme';
import { listAllDiscoveryScopes } from '../../api/discovery';
import { listAllTargets, listCertificates, listSSHKeys } from '../../api/endpoints';
import { ACME_KEY, CERTIFICATES_KEY, DISCOVERY_KEY, SERVICE_LIST_KEY, SERVICES_KEY, SSH_KEYS_KEY, TARGETS_KEY } from '../../api/queryKeys';
import { assignToService, listServices, type AssignResource, type AssignResult, type AssignType } from '../../api/services';
import type { OwnerService, ServiceRef } from '../../api/types';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { useStepUp } from '../StepUpProvider';
import { DialogActions, Notice } from '../ui';

// The kinds a person picks in Move here (a signing request moves with Move to service on its own page only).
const PICKABLE: AssignType[] = ['target', 'certificate', 'acme_certificate', 'ssh_key', 'discovery_scope'];

interface Option {
  id: string;
  name: string;
  service?: OwnerService;
}

// optionsOf reads the resources of a kind a person may move (the first 200 of a paged list; the list page filters the rest).
async function optionsOf(kind: AssignType): Promise<Option[]> {
  switch (kind) {
    case 'target':
      return (await listAllTargets()).items.map((x) => ({ id: x.id, name: x.name, service: x.service }));
    case 'certificate':
      return (await listCertificates({ limit: 200 })).items.map((x) => ({ id: x.id, name: x.label || x.subject_cn || x.fingerprint.slice(0, 16), service: x.service }));
    case 'acme_certificate':
      return (await listACMECertificates({ limit: 200 })).items.map((x) => ({ id: x.id, name: x.names[0] ?? x.id, service: x.service }));
    case 'ssh_key':
      return (await listSSHKeys({ limit: 200 })).items.map((x) => ({ id: x.id, name: x.comment || x.fingerprint, service: x.service }));
    case 'discovery_scope':
      return (await listAllDiscoveryScopes()).items.map((x) => ({ id: x.id, name: x.name, service: x.service }));
    default:
      return [];
  }
}

export interface MoveDialogProps {
  // Move to service: the resource is fixed and the person picks the destination.
  resource?: AssignResource & { name: string; service?: OwnerService };
  // Move here: the destination is fixed and the person picks the resource.
  destination?: ServiceRef;
  onClose: () => void;
}

// MoveDialog moves one resource to another service (POST /services/{id}/actions/assign, services.assign: an
// Administrator with a fresh step-up). It always asks the server first what the move would do (the dry run): the
// bindings that would cross services without a trust stop deploying automatically, and the person sees them before
// confirming. Bindings stay in place.
export function MoveDialog({ resource, destination, onClose }: MoveDialogProps) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [kind, setKind] = useState<AssignType>(resource?.type ?? 'target');
  const [picked, setPicked] = useState(resource?.id ?? '');
  const [dest, setDest] = useState(destination?.id ?? '');
  const [preview, setPreview] = useState<AssignResult | null>(null);

  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal), enabled: !destination });
  const options = useQuery({ queryKey: ['services', 'move-options', kind], queryFn: () => optionsOf(kind), enabled: !resource });
  const choices = (options.data ?? []).filter((o) => o.service?.id !== destination?.id);
  const target: AssignResource | null = picked ? { type: kind, id: picked } : null;

  const check = useMutation({
    mutationFn: () => run(() => assignToService(dest, [target as AssignResource], true)),
    onSuccess: setPreview,
  });
  const move = useMutation({
    mutationFn: () => run(() => assignToService(dest, [target as AssignResource], false)),
    onSuccess: async () => {
      await Promise.all([SERVICES_KEY, TARGETS_KEY, CERTIFICATES_KEY, SSH_KEYS_KEY, ACME_KEY, DISCOVERY_KEY].map((k) => client.invalidateQueries({ queryKey: k })));
      onClose();
    },
  });
  const changed = preview?.moves.some((m) => m.changed) ?? false;

  return (
    <AppModal opened onClose={onClose} title={resource ? t('services.move.toTitle', { name: resource.name }) : t('services.move.hereTitle', { name: destination?.name ?? '' })} size="lg">
      <Stack gap="md">
        <Text size="sm">{t('services.move.intro')}</Text>
        {!resource && (
          <>
            <NativeSelect
              label={t('services.move.kind')}
              value={kind}
              onChange={(e) => {
                setKind(e.currentTarget.value as AssignType);
                setPicked('');
                setPreview(null);
              }}
              data={PICKABLE.map((k) => ({ value: k, label: t(`services.kinds.${k}`) }))}
            />
            <NativeSelect
              label={t('services.move.resource')}
              value={picked}
              onChange={(e) => {
                setPicked(e.currentTarget.value);
                setPreview(null);
              }}
              data={[{ value: '', label: t('services.move.pick') }, ...choices.map((o) => ({ value: o.id, label: o.service?.name ? `${o.name} (${o.service.name})` : o.name }))]}
            />
            <ErrorAlert error={options.error} />
          </>
        )}
        {!destination && (
          <NativeSelect
            label={t('services.move.destination')}
            value={dest}
            onChange={(e) => {
              setDest(e.currentTarget.value);
              setPreview(null);
            }}
            data={[
              { value: '', label: t('services.move.pickService') },
              ...(services.data?.items ?? []).filter((s) => s.id !== resource?.service?.id).map((s) => ({ value: s.id, label: s.name })),
            ]}
          />
        )}
        {preview && (
          <Stack gap="xs" data-testid="move-preview">
            {!changed && <Text size="sm">{t('services.move.nothing')}</Text>}
            {changed && (
              <List size="sm">
                {preview.moves.filter((m) => m.changed).map((m) => (
                  <List.Item key={m.id}>{t('services.move.line', { name: m.name, from: m.from.name, to: preview.destination.name })}</List.Item>
                ))}
              </List>
            )}
            {preview.untrusted.length > 0 && (
              <Notice tone="warning" title={t('services.move.untrustedTitle', { count: preview.untrusted.length })} testId="move-untrusted">
                <List size="sm">
                  {preview.untrusted.map((u) => (
                    <List.Item key={`${u.kind}-${u.location_id}`}>
                      {t('services.move.untrustedLine', { source: u.source_name, server: u.target_name, from: u.source_service.name, to: u.target_service.name })}
                    </List.Item>
                  ))}
                </List>
                <Text size="sm" mt="xs">
                  {t('services.move.untrustedHelp')}
                </Text>
              </Notice>
            )}
          </Stack>
        )}
        <ErrorAlert error={check.error ?? move.error} />
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {t('ui.cancel')}
        </Button>
        {preview && changed ? (
          <Button loading={move.isPending} onClick={() => move.mutate()}>
            {t('services.move.confirm')}
          </Button>
        ) : (
          <Button disabled={!target || !dest} loading={check.isPending} onClick={() => check.mutate()}>
            {t('services.move.check')}
          </Button>
        )}
      </DialogActions>
    </AppModal>
  );
}
