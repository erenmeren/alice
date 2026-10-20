import { Tabs, Title } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { AcmeSettings } from '../components/acme/AcmeSettings';
import { AlertSettings } from '../components/settings/AlertSettings';
import { BackupsTab } from '../components/settings/BackupsTab';
import { ForwardingTab } from '../components/settings/ForwardingTab';
import { HttpsTab } from '../components/settings/HttpsTab';
import { GeneralSettings } from '../components/settings/GeneralSettings';
import { MailSettings } from '../components/settings/MailSettings';
import { RecipientsSettings } from '../components/settings/RecipientsSettings';
import { SSOSettings } from '../components/sso/SSOSettings';
import { DirectoriesSettings } from '../components/directories/DirectoriesSettings';
import { EnvironmentsSettings } from '../components/settings/EnvironmentsSettings';
import { PageHeader, Panel } from '../components/ui';
import { Icon, type IconName } from '../design/Icon';
import { useUrlFilters } from '../hooks/useUrlFilters';
import classes from './SettingsPage.module.css';

const TABS = ['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'acme', 'forwarding', 'sso', 'directories', 'environments'] as const;
type Tab = (typeof TABS)[number];
const TAB_KEYS = ['tab'] as const;

const ICONS: Record<Tab, IconName> = {
  mail: 'Mail',
  recipients: 'Users',
  alerts: 'Bell',
  general: 'Settings2',
  backups: 'DatabaseBackup',
  https: 'LockKeyhole',
  acme: 'Globe',
  forwarding: 'Network',
  sso: 'ShieldCheck',
  directories: 'Server',
  environments: 'Layers',
};

const BODIES: Record<Tab, () => ReactNode> = {
  mail: () => <MailSettings />,
  recipients: () => <RecipientsSettings />,
  alerts: () => <AlertSettings />,
  general: () => <GeneralSettings />,
  backups: () => <BackupsTab />,
  https: () => <HttpsTab />,
  acme: () => <AcmeSettings />,
  forwarding: () => <ForwardingTab />,
  sso: () => <SSOSettings />,
  directories: () => <DirectoriesSettings />,
  environments: () => <EnvironmentsSettings />,
};

// SettingsPage holds the Administrator's settings: mail, recipients, alert thresholds, general, backups, the HTTPS
// certificate, the certificate authorities (ACME), audit forwarding, single sign-on and the directories (LDAP and Active Directory), in the design's settings layout
// (R16): the sections as a vertical tab list from 768 px (a scrolling row on a phone) and the open section in a panel
// with its heading and description.
// The tab is in the address (?tab=), so a link opens it. Only the open tab is drawn, and each reads its own setting
// through step-up.
export function SettingsPage() {
  const { t } = useTranslation();
  const [filters, setFilters] = useUrlFilters(TAB_KEYS);
  const wide = useMediaQuery('(min-width: 48em)', false, { getInitialValueInEffect: false });
  const tab: Tab = (TABS as readonly string[]).includes(filters.tab) ? (filters.tab as Tab) : 'mail';
  return (
    <>
      <PageHeader title={t('settings.title')} description={t('settings.page.description')} />
      <Tabs
        unstyled
        value={tab}
        onChange={(v) => v && setFilters({ tab: v })}
        keepMounted={false}
        orientation={wide ? 'vertical' : 'horizontal'}
        classNames={{ root: classes.layout, list: classes.navList, tab: classes.navTab, panel: classes.panel }}
      >
        <Tabs.List aria-label={t('settings.tabsLabel')}>
          {TABS.map((x) => (
            <Tabs.Tab key={x} value={x} leftSection={<Icon name={ICONS[x]} size={15} />}>
              {t(`settings.tabs.${x}`)}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        {TABS.map((x) => (
          <Tabs.Panel key={x} value={x}>
            <Panel>
              <div className={classes.formSection}>
                <Title order={2} className={classes.sectionTitle}>
                  {t(`settings.tabs.${x}`)}
                </Title>
                <p className={classes.sectionText}>{t(`settings.page.${x}`)}</p>
                {BODIES[x]()}
              </div>
            </Panel>
          </Tabs.Panel>
        ))}
      </Tabs>
    </>
  );
}
