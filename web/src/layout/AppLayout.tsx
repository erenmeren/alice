import { useEffect } from 'react';
import { Alert, Anchor, AppShell, Burger, Button, Group, NavLink, Text } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useTranslation } from 'react-i18next';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';
import { ssoErrorReason } from '../api/sso';
import { SSOErrorAlert } from '../components/SSOErrorAlert';
import type { Role } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { BackupBanner } from '../components/BackupBanner';
import { LicenseBanners } from '../components/LicenseBanners';
import { NotificationsBanner } from '../components/NotificationsBanner';
import { LanguageSwitcher } from '../LanguageSwitcher';

interface NavItem {
  to: string;
  labelKey: string;
  roles: Role[];
}

const ALL: Role[] = ['admin', 'operator', 'auditor'];

// NAV_ITEMS lists the side navigation. Roles mirror the server permissions (docs/authz-matrix.md).
export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', roles: ALL },
  { to: '/servers', labelKey: 'nav.servers', roles: ALL },
  { to: '/key-vaults', labelKey: 'nav.keyVaults', roles: ALL },
  { to: '/certificates', labelKey: 'nav.certificates', roles: ALL },
  { to: '/deployments', labelKey: 'nav.deployments', roles: ALL },
  { to: '/ssh-keys', labelKey: 'nav.sshKeys', roles: ALL },
  { to: '/users', labelKey: 'nav.users', roles: ['admin'] },
  { to: '/settings', labelKey: 'nav.settings', roles: ['admin'] },
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
  const navigate = useNavigate();
  // The callback sends a refused step-up back to the page with ?sso_error=<reason>: the reason moves into the navigation state
  // (so a reload does not show it again) and the parameter leaves the address, the rest of it kept.
  const rawSsoError = new URLSearchParams(location.search).get('sso_error');
  const stateReason = ssoErrorReason((location.state as { ssoError?: string } | null)?.ssoError);
  useEffect(() => {
    if (rawSsoError === null) return;
    const p = new URLSearchParams(location.search);
    p.delete('sso_error');
    const qs = p.toString();
    const reason = ssoErrorReason(rawSsoError);
    navigate({ pathname: location.pathname, search: qs ? `?${qs}` : '', hash: location.hash }, { replace: true, state: reason ? { ssoError: reason } : location.state });
  }, [rawSsoError, location.pathname, location.search, location.hash, location.state, navigate]);
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
        <NotificationsBanner />
        <BackupBanner />
        <SetupBanner />
        {stateReason && (
          <div style={{ marginBottom: 'var(--mantine-spacing-md)' }}>
            <SSOErrorAlert reason={stateReason} onClose={() => navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true })} />
          </div>
        )}
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
