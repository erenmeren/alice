import { Button, NativeSelect, Stack, Textarea, TextInput } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { ENVIRONMENTS_KEY, SERVICES_KEY } from '../../api/queryKeys';
import { createService, listEnvironments, MAX_SERVICE_DESCRIPTION, MAX_SERVICE_NAME, updateService, type Service } from '../../api/services';
import { AppModal } from '../AppModal';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { useStepUp } from '../StepUpProvider';
import { DialogActions } from '../ui';
import { environmentLabel } from './shared';

// ServiceDialog adds a service or changes one's name, description and environment (services.manage: an Administrator with
// a fresh step-up). Changing the environment changes which environment role bindings reach the service.
export function ServiceDialog({ service, onClose, onSaved }: { service?: Service; onClose: () => void; onSaved?: (s: Service) => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const [name, setName] = useState(service?.name ?? '');
  const [description, setDescription] = useState(service?.description ?? '');
  const [environment, setEnvironment] = useState(service?.environment?.id ?? '');
  const environments = useQuery({ queryKey: ENVIRONMENTS_KEY, queryFn: ({ signal }) => listEnvironments(signal) });
  const save = useMutation({
    mutationFn: () =>
      run(() =>
        service
          ? updateService(service.id, service.version, { name, description, environment_id: environment || null })
          : createService({ name, description, environment_id: environment || null }),
      ),
    onSuccess: async (s) => {
      await client.invalidateQueries({ queryKey: SERVICES_KEY });
      onSaved?.(s);
      onClose();
    },
  });
  const fields = fieldErrorsOf(save.error, t, i18n);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };
  return (
    <AppModal opened onClose={onClose} title={service ? t('services.dialog.editTitle') : t('services.dialog.createTitle')}>
      <form onSubmit={submit}>
        <Stack gap="md">
          <TextInput label={t('services.fields.name')} value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={MAX_SERVICE_NAME} required error={fields.name} data-autofocus />
          <Textarea
            label={t('services.fields.description')}
            value={description}
            onChange={(e) => setDescription(e.currentTarget.value)}
            maxLength={MAX_SERVICE_DESCRIPTION}
            autosize
            minRows={2}
            error={fields.description}
          />
          <NativeSelect
            label={t('services.fields.environment')}
            description={service ? t('services.dialog.environmentHelp') : undefined}
            value={environment}
            onChange={(e) => setEnvironment(e.currentTarget.value)}
            error={fields.environment_id}
            data={[{ value: '', label: t('services.noEnvironment') }, ...(environments.data?.items ?? []).map((env) => ({ value: env.id, label: environmentLabel(t, env) }))]}
          />
          <ErrorAlert error={save.error} />
        </Stack>
        <DialogActions>
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="submit" loading={save.isPending}>
            {service ? t('services.dialog.save') : t('services.dialog.create')}
          </Button>
        </DialogActions>
      </form>
    </AppModal>
  );
}
