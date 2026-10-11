import { Anchor, Badge, Group, List, Paper, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { ChecklistItem, ChecklistItemName } from '../../api/types';

// Where each item is finished. The recovery passphrase belongs to the wizard; the rest have their own pages.
const TARGETS: Record<ChecklistItemName, string> = {
  passphrase: '/setup',
  https: '/settings?tab=https',
  mail: '/settings?tab=mail',
  license: '/license',
  target: '/servers',
};

// SetupChecklist is "Finish setting up" (§18.5, R43 row 18): what the wizard skipped or left open, for Administrators.
// Required items are marked; finished ones stay listed as done. It is gone once everything is done.
export function SetupChecklist({ items }: { items: ChecklistItem[] }) {
  const { t } = useTranslation();
  const known = items.filter((i) => i.item in TARGETS);
  if (known.every((i) => i.done)) return null;
  return (
    <Paper withBorder p="md" data-testid="setup-checklist" component="section" aria-label={t('dashboard.checklist.title')}>
      <Title order={2} size="h4" mb="xs">
        {t('dashboard.checklist.title')}
      </Title>
      <Text size="sm" mb="sm">
        {t('dashboard.checklist.help')}
      </Text>
      <List spacing="xs">
        {known.map((i) => (
          <List.Item key={i.item}>
            <Group gap="xs" wrap="wrap">
              <Anchor component={Link} to={TARGETS[i.item]} size="sm">
                {t(`dashboard.checklist.${i.item}`)}
              </Anchor>
              {i.required && !i.done && (
                <Badge variant="light" color="red" tt="none">
                  {t('dashboard.checklist.required')}
                </Badge>
              )}
              {i.done && (
                <Badge variant="light" color="green" tt="none">
                  {t('dashboard.checklist.done')}
                </Badge>
              )}
            </Group>
          </List.Item>
        ))}
      </List>
    </Paper>
  );
}
