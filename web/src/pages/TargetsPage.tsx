import { Anchor, Button, Code, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllServers } from '../api/endpoints';
import { TARGETS_KEY } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { AddServerModal } from '../components/AddServerModal';
import { BlockedJobsPanel } from '../components/BlockedJobsPanel';
import { ErrorAlert } from '../components/ErrorAlert';
import { reasonTitle } from '../components/JobErrorAlert';
import { PlatformKeyPanel } from '../components/PlatformKeyPanel';
import { TargetStatusBadge } from '../components/TargetStatusBadge';
import { WRAP } from '../components/wrap';

// TargetsPage lists the managed servers for every role (metadata only, never credentials, R3).
// Administrators also get "Add server", the preparation commands and the paused changes.
export function TargetsPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  const admin = session?.user.role === 'admin';
  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllServers });
  const [adding, setAdding] = useState(false);

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('targets.title')}</Title>
        {admin && <Button onClick={() => setAdding(true)}>{t('targets.add')}</Button>}
      </Group>
      <ErrorAlert error={targets.error} />
      {targets.isSuccess && targets.data.items.length === 0 && <Text c="gray.7">{t('targets.empty')}</Text>}
      {targets.isSuccess && targets.data.items.length > 0 && (
        <Table.ScrollContainer minWidth={640}>
          <Table striped data-testid="targets-table">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('targets.columns.name')}</Table.Th>
                <Table.Th>{t('targets.columns.address')}</Table.Th>
                <Table.Th>{t('targets.columns.status')}</Table.Th>
                <Table.Th>{t('targets.columns.problem')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {targets.data.items.map((tg) => (
                <Table.Tr key={tg.id}>
                  <Table.Td>
                    <Anchor component={Link} to={`/servers/${tg.id}`}>
                      {tg.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Code style={WRAP}>{`${tg.host}:${tg.port}`}</Code>
                  </Table.Td>
                  <Table.Td>
                    <TargetStatusBadge status={tg.status} />
                  </Table.Td>
                  <Table.Td>{tg.last_error ? reasonTitle(t, i18n, tg.last_error.reason) : ''}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {admin && <BlockedJobsPanel />}
      {admin && <PlatformKeyPanel />}
      {adding && (
        <AddServerModal
          onClose={() => setAdding(false)}
          onAdded={(tg) => {
            setAdding(false);
            navigate(`/servers/${tg.id}`, { state: { added: true } });
          }}
        />
      )}
    </Stack>
  );
}
