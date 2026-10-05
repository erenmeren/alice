import { Box, Button, Code, CopyButton, Stack, Table, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import {
  CMD_CERTIFICATES_OFFICER,
  CMD_POLICY_OFFICER,
  CMD_POLICY_READER,
  CMD_POLICY_SECRETS,
  CMD_READER,
  CMD_SECRETS_USER,
  fillCommand,
  ROLE_CERTIFICATES_OFFICER,
  ROLE_READER,
  ROLE_SECRETS_USER,
  type CommandValues,
} from './roleCommands';
import { WRAP } from './wrap';

interface Row {
  id: 'monitor' | 'deploy' | 'import';
  role: string;
  plus: boolean;
  command: string;
  policy: string;
}

const ROWS: Row[] = [
  { id: 'monitor', role: ROLE_READER, plus: false, command: CMD_READER, policy: CMD_POLICY_READER },
  { id: 'deploy', role: ROLE_SECRETS_USER, plus: true, command: CMD_SECRETS_USER, policy: CMD_POLICY_SECRETS },
  { id: 'import', role: ROLE_CERTIFICATES_OFFICER, plus: true, command: CMD_CERTIFICATES_OFFICER, policy: CMD_POLICY_OFFICER },
];

function CommandCell({ command, label }: { command: string; label: string }) {
  const { t } = useTranslation();
  return (
    <Stack gap={4}>
      <Code block translate="no" tabIndex={0} aria-label={t('vaults.roles.commandLabel', { what: label })} style={WRAP}>
        {command}
      </Code>
      <CopyButton value={command}>
        {({ copied, copy }) => (
          <Button size="xs" variant="light" w="fit-content" onClick={copy} aria-label={t('vaults.roles.copyNamed', { what: label })}>
            {copied ? t('targets.prepare.copied') : t('vaults.roles.copy')}
          </Button>
        )}
      </CopyButton>
    </Stack>
  );
}

// RoleGuide lists the three roles Alice can use on a vault (monitor, deploy, import), each with the
// `az role assignment create` command that grants it, and the access-policy commands for a vault that
// does not use Azure roles. The client ID, the vault's name and the certificate's name fill the
// placeholders where known. Role names are never translated and always shown in <Code>. The
// commands are the text of roleCommands.ts, which the setup guide repeats.
export function RoleGuide({ clientId, vaultName, certificateName, openPolicies = false }: CommandValues & { openPolicies?: boolean }) {
  const { t } = useTranslation();
  const values = { clientId, vaultName, certificateName };
  return (
    <Stack gap="xs" data-testid="role-guide">
      <Title order={3} size="h4">
        {t('vaults.roles.title')}
      </Title>
      <Text size="sm">{t('vaults.roles.intro')}</Text>
      <Table.ScrollContainer minWidth={560}>
        <Table aria-label={t('vaults.roles.title')}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('vaults.access.what')}</Table.Th>
              <Table.Th>{t('vaults.roles.commandColumn')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {ROWS.map((r) => {
              const what = t(`vaults.roles.${r.id}`);
              return (
                <Table.Tr key={r.id} data-role-row={r.id}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="sm">{what}</Text>
                      <Text size="sm">
                        {r.plus && <span>+ </span>}
                        <Code translate="no">{r.role}</Code>
                      </Text>
                      {r.id === 'monitor' && (
                        <Text size="xs" c="gray.8">
                          {t('vaults.roles.readerUnconfirmed')}
                        </Text>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <CommandCell command={fillCommand(r.command, values)} label={what} />
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <Box component="details" open={openPolicies || undefined}>
        <Text component="summary" size="sm" fw={600} style={{ cursor: 'pointer' }}>
          {t('vaults.roles.policies')}
        </Text>
        <Stack gap="xs" mt="xs">
          <Text size="sm">{t('vaults.roles.policiesHelp')}</Text>
          {ROWS.map((r) => {
            const what = t(`vaults.roles.${r.id}`);
            return (
              <Stack key={r.id} gap={2}>
                <Text size="sm">{what}</Text>
                <CommandCell command={fillCommand(r.policy, values)} label={t('vaults.roles.policyNamed', { what })} />
              </Stack>
            );
          })}
        </Stack>
      </Box>
    </Stack>
  );
}
