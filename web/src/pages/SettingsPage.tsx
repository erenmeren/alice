import { Stack, Tabs, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { AlertSettings } from '../components/settings/AlertSettings';
import { GeneralSettings } from '../components/settings/GeneralSettings';
import { MailSettings } from '../components/settings/MailSettings';
import { RecipientsSettings } from '../components/settings/RecipientsSettings';
import { SSOSettings } from '../components/sso/SSOSettings';
import { useUrlFilters } from '../hooks/useUrlFilters';

const TABS = ['mail', 'recipients', 'alerts', 'general', 'sso'] as const;
type Tab = (typeof TABS)[number];
const TAB_KEYS = ['tab'] as const;

// SettingsPage holds the Administrator's settings: mail, recipients, alert thresholds, general and single sign-on. The tab is
// in the address (?tab=), so a link opens it. Only the open tab is drawn, and each reads its own setting through step-up.
export function SettingsPage() {
  const { t } = useTranslation();
  const [filters, setFilters] = useUrlFilters(TAB_KEYS);
  const tab: Tab = (TABS as readonly string[]).includes(filters.tab) ? (filters.tab as Tab) : 'mail';
  return (
    <Stack gap="md">
      <Title order={1}>{t('settings.title')}</Title>
      <Tabs value={tab} onChange={(v) => v && setFilters({ tab: v })} keepMounted={false}>
        <Tabs.List aria-label={t('settings.tabsLabel')}>
          {TABS.map((x) => (
            <Tabs.Tab key={x} value={x}>
              {t(`settings.tabs.${x}`)}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="mail" pt="md">
          <MailSettings />
        </Tabs.Panel>
        <Tabs.Panel value="recipients" pt="md">
          <RecipientsSettings />
        </Tabs.Panel>
        <Tabs.Panel value="alerts" pt="md">
          <AlertSettings />
        </Tabs.Panel>
        <Tabs.Panel value="general" pt="md">
          <GeneralSettings />
        </Tabs.Panel>
        <Tabs.Panel value="sso" pt="md">
          <SSOSettings />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
