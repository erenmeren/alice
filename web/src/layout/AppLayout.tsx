import { useEffect, useRef } from 'react';
import { Alert, Anchor, AppShell, Burger, Button, NavLink } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';
import { getVersion } from '../api/endpoints';
import { ssoErrorReason } from '../api/sso';
import { SSOErrorAlert } from '../components/SSOErrorAlert';
import type { Role } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { BackupBanner } from '../components/BackupBanner';
import { LicenseBanners } from '../components/LicenseBanners';
import { NotificationsBanner } from '../components/NotificationsBanner';
import { AttentionBell } from '../components/shell/AttentionBell';
import { CommandPalette, anotherDialogOpen } from '../components/shell/CommandPalette';
import { LanguageToggle, ThemeToggle } from '../components/ui';
import { Icon, type IconName } from '../design/Icon';
import { initials } from '../initials';
import classes from './AppLayout.module.css';

export type NavGroup = 'none' | 'inventory' | 'operations' | 'administration';
export interface NavItem {
  to: string;
  labelKey: string;
  roles: Role[];
  icon: IconName;
  group: NavGroup;
  // match lists extra path prefixes that mark the item active (a page that lives under another address).
  match?: string[];
}

const ALL: Role[] = ['admin', 'operator', 'auditor'];

// NAV_ITEMS lists the side navigation in the design's groups. Roles mirror the server permissions (docs/authz-matrix.md);
// the UI is not an authorization boundary.
export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', roles: ALL, icon: 'LayoutDashboard', group: 'none' },
  { to: '/certificates', labelKey: 'nav.certificates', roles: ALL, icon: 'FileKey2', group: 'inventory' },
  { to: '/acme', labelKey: 'nav.acme', roles: ALL, icon: 'ShieldCheck', group: 'inventory' },
  { to: '/ssh-keys', labelKey: 'nav.sshKeys', roles: ALL, icon: 'KeyRound', group: 'inventory' },
  { to: '/servers', labelKey: 'nav.servers', roles: ALL, icon: 'Server', group: 'inventory' },
  { to: '/key-vaults', labelKey: 'nav.keyVaults', roles: ALL, icon: 'Cloud', group: 'inventory' },
  { to: '/deployments', labelKey: 'nav.deployments', roles: ALL, icon: 'Rocket', group: 'operations' },
  { to: '/rotations', labelKey: 'nav.rotations', roles: ALL, icon: 'RotateCw', group: 'operations', match: ['/rotation/'] },
  { to: '/audit', labelKey: 'nav.audit', roles: ['admin', 'auditor'], icon: 'ScrollText', group: 'operations' },
  { to: '/users', labelKey: 'nav.users', roles: ['admin'], icon: 'Users', group: 'administration' },
  { to: '/settings', labelKey: 'nav.settings', roles: ['admin'], icon: 'Settings2', group: 'administration' },
  { to: '/license', labelKey: 'nav.license', roles: ['admin', 'auditor'], icon: 'CreditCard', group: 'administration' },
];

// ACCOUNT_ITEMS are the person's own pages, shown as plain links above Sign out (R5).
export const ACCOUNT_ITEMS: NavItem[] = [
  { to: '/account', labelKey: 'nav.account', roles: ALL, icon: 'UserRound', group: 'none' },
  { to: '/tokens', labelKey: 'nav.tokens', roles: ALL, icon: 'KeySquare', group: 'none' },
];

const GROUPS: NavGroup[] = ['none', 'inventory', 'operations', 'administration'];

// isActive: the item's own address or a page under it ("/servers/abc" for "/servers"), or one of its match prefixes.
export function isActive(item: NavItem, pathname: string): boolean {
  if (item.to === '/') return pathname === '/';
  return pathname === item.to || pathname.startsWith(`${item.to}/`) || (item.match ?? []).some((m) => pathname.startsWith(m));
}

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
    <Alert color="red" data-testid="setup-banner" icon={<Icon name="ShieldAlert" />}>
      <Anchor component={Link} to="/setup" c="inherit" fw={600} underline="always">
        {text}
      </Anchor>
    </Alert>
  );
}

export function AppLayout() {
  const { t, i18n } = useTranslation();
  const { session, signOut, signOutFailed } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const version = useQuery({ queryKey: ['version'], queryFn: getVersion });
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
  // Escape closes the open phone menu (the design's app.js) and returns focus to the menu button, unless a dialog in
  // front of it takes the key.
  const burger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!navOpened) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || anotherDialogOpen()) return;
      closeNav();
      burger.current?.focus();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [navOpened, closeNav]);
  if (!session) return null;
  const items = NAV_ITEMS.filter((i) => i.roles.includes(session.user.role));
  const account = ACCOUNT_ITEMS.filter((i) => i.roles.includes(session.user.role));
  const current = [...items, ...account].find((i) => isActive(i, location.pathname));
  const deeper = current !== undefined && current.to !== '/' && location.pathname !== current.to;
  const navLink = (i: NavItem) => {
    const active = isActive(i, location.pathname);
    return (
      <NavLink
        key={i.to}
        component={Link}
        to={i.to}
        label={t(i.labelKey)}
        leftSection={<Icon name={i.icon} size={16} />}
        active={active}
        aria-current={active ? 'page' : undefined}
        onClick={nav.close}
        classNames={{ root: classes.link, label: classes.linkLabel }}
      />
    );
  };

  return (
    <AppShell
      layout="alt"
      header={{ height: 65 }}
      navbar={{ width: { sm: 202, lg: 222 }, breakpoint: 'sm', collapsed: { mobile: !navOpened } }}
      padding={0}
    >
      <a href="#main" className={classes.skipLink}>
        {t('shell.skip')}
      </a>
      {/* The sidebar is an aside (the design's markup); the one named navigation landmark holds only the links. */}
      <AppShell.Navbar component="aside" id="app-navbar" className={classes.navbar}>
        <Link to="/" className={classes.brand} onClick={nav.close}>
          <img src="/favicon.svg" alt="" className={classes.brandMark} />
          <span className={classes.brandName}>
            {t('app.name', { ns: 'common' })}
            <span className={classes.brandDot} aria-hidden="true">
              .
            </span>
          </span>
        </Link>
        <div className={classes.installation}>
          <span className={classes.installationSymbol} aria-hidden="true">
            <Icon name="Building2" size={16} />
          </span>
          <div className={classes.installationText}>
            <div className={classes.installationName}>{t('shell.installation')}</div>
            {version.data && <div className={classes.installationMeta}>{t('shell.versionLine', { version: version.data.version })}</div>}
          </div>
          <Icon name="LockKeyhole" size={14} className={classes.installationLock} />
        </div>
        <nav aria-label={t('nav.label')} className={classes.nav}>
          <div className={classes.navScroll}>
            {GROUPS.map((g) => {
              const inGroup = items.filter((i) => i.group === g);
              if (inGroup.length === 0) return null;
              return (
                <div key={g}>
                  {g !== 'none' && <div className={classes.group}>{t(`nav.groups.${g}`)}</div>}
                  {inGroup.map(navLink)}
                </div>
              );
            })}
          </div>
          <div className={classes.accountLinks}>{account.map(navLink)}</div>
        </nav>
        <div className={classes.bottom}>
          <div className={classes.account}>
            <span className={classes.avatar} aria-hidden="true">
              {initials(session.user.display_name, i18n.language)}
            </span>
            <div className={classes.accountText}>
              <div className={classes.accountName} data-testid="current-user">
                {session.user.display_name}
              </div>
              <div className={classes.accountRole}>{t(`enum.role.${session.user.role}`)}</div>
            </div>
          </div>
          <Button variant="default" size="xs" fullWidth leftSection={<Icon name="LogOut" size={15} />} onClick={() => void signOut()}>
            {t('nav.signOut')}
          </Button>
        </div>
      </AppShell.Navbar>
      <AppShell.Header className={classes.header}>
        <div className={classes.headerInner}>
          <div className={classes.headerStart}>
            <Burger
              ref={burger}
              className={classes.burger}
              opened={navOpened}
              onClick={nav.toggle}
              hiddenFrom="sm"
              size="sm"
              aria-label={navOpened ? t('nav.closeMenu') : t('nav.openMenu')}
              aria-expanded={navOpened}
              aria-controls="app-navbar"
            />
            {/* Plain text, never links or a landmark: page-wide link and navigation queries stay unique (R6). */}
            <div className={classes.breadcrumb} data-testid="breadcrumb">
              <span>{t('shell.workspace')}</span>
              <Icon name="ChevronRight" size={13} />
              <strong>{current ? t(current.labelKey) : t('app.name', { ns: 'common' })}</strong>
              {deeper && (
                <>
                  <Icon name="ChevronRight" size={13} />
                  <span>{t('shell.details')}</span>
                </>
              )}
            </div>
          </div>
          <div className={classes.topActions}>
            <CommandPalette items={[...items, ...account]} />
            <span className={classes.divider} aria-hidden="true" />
            <ThemeToggle />
            <LanguageToggle signedIn />
            <AttentionBell />
          </div>
        </div>
      </AppShell.Header>
      <AppShell.Main id="main" tabIndex={-1}>
        <div className={classes.content}>
          <div className={classes.banners}>
            {signOutFailed && (
              <Alert color="red" role="alert" data-testid="signout-error" icon={<Icon name="ShieldAlert" />}>
                {t('nav.signOutFailed')}
              </Alert>
            )}
            <LicenseBanners />
            <NotificationsBanner />
            <BackupBanner />
            <SetupBanner />
            {stateReason && (
              <SSOErrorAlert reason={stateReason} onClose={() => navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true })} />
            )}
          </div>
          <Outlet />
          <footer className={classes.footer}>
            <Icon name="LockKeyhole" size={14} />
            <span>{version.data ? t('shell.footer', { version: version.data.version }) : t('app.name', { ns: 'common' })}</span>
          </footer>
        </div>
      </AppShell.Main>
    </AppShell>
  );
}
