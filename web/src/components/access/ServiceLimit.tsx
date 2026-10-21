import { Checkbox, ScrollArea, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { SERVICE_LIST_KEY } from '../../api/queryKeys';
import { listServices } from '../../api/services';
import type { ApiToken, ServiceRef } from '../../api/types';
import { environmentLabel } from '../services/shared';

// ServiceLimitSelect is a token's "Limit to services" (R54, design §6.3): none chosen is no limit (the owner's whole
// reach); chosen services narrow the token to them, and a token so limited never opens a platform page. The services
// offered are those the caller sees (a person with roles on services sees theirs only); the server refuses a service the
// token's owner holds no role on.
export function ServiceLimitSelect({ value, onChange }: { value: string[]; onChange: (ids: string[]) => void }) {
  const { t } = useTranslation();
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal) });
  const items = services.data?.items ?? [];
  return (
    <Checkbox.Group label={t('tokens.fields.limit')} description={t('tokens.fields.limitHelp')} value={value} onChange={onChange}>
      <ScrollArea.Autosize mah={180} mt={6}>
        <Stack gap={6}>
          {items.map((s) => (
            <Checkbox key={s.id} value={s.id} label={s.environment ? `${s.name} (${environmentLabel(t, s.environment)})` : s.name} />
          ))}
          {services.isSuccess && items.length === 0 && <Text size="sm">{t('tokens.allMyServices')}</Text>}
        </Stack>
      </ScrollArea.Autosize>
    </Checkbox.Group>
  );
}

// tokenLimitText is a token's limit as text: the names of its services, or "All my services".
export function tokenLimitText(t: TFunction, token: Pick<ApiToken, 'service_ids'>, services: Pick<ServiceRef, 'id' | 'name'>[] | undefined): string {
  if (!token.service_ids || token.service_ids.length === 0) return t('tokens.allMyServices');
  return token.service_ids.map((id) => services?.find((s) => s.id === id)?.name ?? t('access.outside')).join(', ');
}

// TokenLimit shows a token's limit.
export function TokenLimit({ token }: { token: Pick<ApiToken, 'service_ids'> }) {
  const { t } = useTranslation();
  const limited = Boolean(token.service_ids?.length);
  const services = useQuery({ queryKey: SERVICE_LIST_KEY, queryFn: ({ signal }) => listServices(signal), enabled: limited });
  return (
    <Text size="sm" translate={limited ? 'no' : undefined} data-testid="token-limit">
      {tokenLimitText(t, token, services.data?.items)}
    </Text>
  );
}
