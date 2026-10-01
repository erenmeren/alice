import { useEffect } from 'react';
import { Alert, Anchor, AppShell, Burger, Button, Group, NavLink, Text } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useTranslation } from 'react-i18next';
import { Link, Outlet, useLocation } from 'react-router';
import type { Role } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { LicenseBanners } from '../components/LicenseBanners';
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
  { to: '/license', labelKey: 'nav.license', roles: ['admin', 'auditor'] },
  { to: '/tokens', labelKey: 'nav.tokens', roles: ALL },
  { to: '/account', labelKey: 'nav.account', roles: ALL },
];

function SetupBanner() {
  const { t } = useTranslation();
  const { session, setupStatus } = useAuth();
  if (session?.user.role !== 'admin' || !setupStatus || setupStatus.completed) return null;
  const text = !setupStatus.recovery_passphrase_set
    ? t('nav.setupBanner')
    : !setupStatus.license_chosen
      ? t('nav.setupBannerLicense')
      : t('nav.setupBannerFinish');
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
  const { session, signOut, signOutFailed } = useAuth();
  const location = useLocation();
  // Below the "sm" breakpoint the navigation covers the page, so it starts closed and the
  // menu button opens it; choosing a page closes it again.
  const [navOpened, nav] = useDisclosure(false);
  const closeNav = nav.close;
  // Every navigation closes the mobile menu, including redirects and buttons that navigate
  // (a menu link also closes it in its onClick, before the new page renders).
  useEffect(() => {
    closeNav();
  }, [location.pathname, closeNav]);
  if (!session) return null;
  const items = NAV_ITEMS.filter((i) => i.roles.includes(session.user.role));

  return (
    <AppShell header={{ height: 60 }} navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !navOpened } }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger
              opened={navOpened}
              onClick={nav.toggle}
              hiddenFrom="sm"
              size="sm"
              aria-label={navOpened ? t('nav.closeMenu') : t('nav.openMenu')}
              aria-expanded={navOpened}
              aria-controls="app-navbar"
            />
            <Text fw={700} size="xl">
              {t('app.name', { ns: 'common' })}
            </Text>
          </Group>
          <Group wrap="nowrap">
            <LanguageSwitcher signedIn />
            <Text size="sm" data-testid="current-user" visibleFrom="sm">
              {session.user.display_name}
            </Text>
            <Button variant="default" onClick={() => void signOut()}>
              {t('nav.signOut')}
            </Button>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar id="app-navbar" p="xs" aria-label={t('nav.label')}>
        {items.map((i) => (
          <NavLink
            key={i.to}
            component={Link}
            to={i.to}
            label={t(i.labelKey)}
            onClick={nav.close}
            active={i.to === '/' ? location.pathname === '/' : location.pathname.startsWith(i.to)}
            // "filled": white on indigo 7 (5.0:1); the default "light" active style fails WCAG AA contrast.
            variant="filled"
          />
        ))}
      </AppShell.Navbar>
      <AppShell.Main>
        {signOutFailed && (
          <Alert color="red" role="alert" mb="md" data-testid="signout-error">
            {t('nav.signOutFailed')}
          </Alert>
        )}
        <LicenseBanners />
        <SetupBanner />
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
