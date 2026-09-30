import { Alert, Anchor, AppShell, Button, Group, NavLink, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link, Outlet, useLocation } from 'react-router';
import type { Role } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { LanguageSwitcher } from '../LanguageSwitcher';

interface NavItem {
  to: string;
  labelKey: string;
  roles: Role[];
}

const ALL: Role[] = ['admin', 'operator', 'auditor'];

// NAV_ITEMS lists the side navigation. Roles mirror the server permissions (docs/authz-matrix.md).
export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.home', roles: ALL },
  { to: '/users', labelKey: 'nav.users', roles: ['admin'] },
  { to: '/audit', labelKey: 'nav.audit', roles: ['admin', 'auditor'] },
  { to: '/tokens', labelKey: 'nav.tokens', roles: ALL },
  { to: '/account', labelKey: 'nav.account', roles: ALL },
];

function SetupBanner() {
  const { t } = useTranslation();
  const { session, setupStatus } = useAuth();
  if (session?.user.role !== 'admin' || !setupStatus || setupStatus.completed) return null;
  const text = setupStatus.recovery_passphrase_set ? t('nav.setupBannerFinish') : t('nav.setupBanner');
  return (
    <Alert color="red" mb="md" data-testid="setup-banner">
      <Anchor component={Link} to="/setup">
        {text}
      </Anchor>
    </Alert>
  );
}

export function AppLayout() {
  const { t } = useTranslation();
  const { session, signOut } = useAuth();
  const location = useLocation();
  if (!session) return null;
  const items = NAV_ITEMS.filter((i) => i.roles.includes(session.user.role));

  return (
    <AppShell header={{ height: 60 }} navbar={{ width: 220, breakpoint: 'sm' }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Text fw={700} size="xl">
            {t('app.name', { ns: 'common' })}
          </Text>
          <Group>
            <LanguageSwitcher signedIn />
            <Text size="sm" data-testid="current-user">
              {session.user.display_name}
            </Text>
            <Button variant="default" onClick={() => void signOut()}>
              {t('nav.signOut')}
            </Button>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs" aria-label={t('nav.label')}>
        {items.map((i) => (
          <NavLink
            key={i.to}
            component={Link}
            to={i.to}
            label={t(i.labelKey)}
            active={i.to === '/' ? location.pathname === '/' : location.pathname.startsWith(i.to)}
            // "filled": white on indigo 7 (5.0:1); the default "light" active style fails WCAG AA contrast.
            variant="filled"
          />
        ))}
      </AppShell.Navbar>
      <AppShell.Main>
        <SetupBanner />
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
