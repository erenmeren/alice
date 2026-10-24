import { useEffect, useRef } from 'react';
import { Alert, Anchor, AppShell, Burger, Button, NavLink } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';
import { getVersion } from '../api/endpoints';
import { ssoErrorReason } from '../api/sso';
import { SSOErrorAlert } from '../components/SSOErrorAlert';
import type { Permission, SessionInfo } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { can, canPlatform, hasNoAccess, sessionAccess } from '../auth/permissions';
import { NoAccessPage } from '../pages/NoAccessPage';
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
  // perm is the permission the page reads with (none: the person's own pages); platform: it needs a global grant.
  perm?: Permission;
  platform?: boolean;
  icon: IconName;
  group: NavGroup;
  // match lists extra path prefixes that mark the item active (a page that lives under another address).
  match?: string[];
}

// NAV_ITEMS lists the side navigation in the design's groups. The permissions mirror the server's (docs/authz-matrix.md):
// a resource page shows when the person reads something somewhere, a platform page only with a global grant. The UI is
// not an authorization boundary.
export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', perm: 'read', icon: 'LayoutDashboard', group: 'none' },
  { to: '/certificates', labelKey: 'nav.certificates', perm: 'read', icon: 'FileKey2', group: 'inventory' },
  { to: '/acme', labelKey: 'nav.acme', perm: 'acme.view', icon: 'ShieldCheck', group: 'inventory' },
  { to: '/discovery', labelKey: 'nav.discovery', perm: 'discovery.view', icon: 'Network', group: 'inventory' },
  { to: '/ssh-keys', labelKey: 'nav.sshKeys', perm: 'read', icon: 'KeyRound', group: 'inventory' },
  { to: '/servers', labelKey: 'nav.servers', perm: 'read', icon: 'Server', group: 'inventory' },
  { to: '/key-vaults', labelKey: 'nav.keyVaults', perm: 'read', icon: 'Cloud', group: 'inventory' },
  { to: '/deployments', labelKey: 'nav.deployments', perm: 'read', icon: 'Rocket', group: 'operations' },
  { to: '/incidents', labelKey: 'nav.incidents', perm: 'read', icon: 'ShieldAlert', group: 'operations' },
  { to: '/rotations', labelKey: 'nav.rotations', perm: 'read', icon: 'RotateCw', group: 'operations', match: ['/rotation/'] },
  { to: '/audit', labelKey: 'nav.audit', perm: 'audit.read', platform: true, icon: 'ScrollText', group: 'operations' },
  { to: '/users', labelKey: 'nav.users', perm: 'users.read', platform: true, icon: 'Users', group: 'administration' },
  { to: '/services', labelKey: 'nav.services', perm: 'read', icon: 'Layers', group: 'administration' },
  { to: '/settings', labelKey: 'nav.settings', perm: 'settings.manage', platform: true, icon: 'Settings2', group: 'administration' },
  { to: '/license', labelKey: 'nav.license', perm: 'license.read', platform: true, icon: 'CreditCard', group: 'administration' },
];

// ACCOUNT_ITEMS are the person's own pages, shown as plain links above Sign out (R5).
export const ACCOUNT_ITEMS: NavItem[] = [
  { to: '/account', labelKey: 'nav.account', icon: 'UserRound', group: 'none' },
  { to: '/tokens', labelKey: 'nav.tokens', icon: 'KeySquare', group: 'none' },
];

const GROUPS: NavGroup[] = ['none', 'inventory', 'operations', 'administration'];

// isActive: the item's own address or a page under it ("/servers/abc" for "/servers"), or one of its match prefixes.
export function isActive(item: NavItem, pathname: string): boolean {
  if (item.to === '/') return pathname === '/';
  return pathname === item.to || pathname.startsWith(`${item.to}/`) || (item.match ?? []).some((m) => pathname.startsWith(m));
}

// allowed: the navigation item is for this person.
export function allowed(session: SessionInfo, item: NavItem): boolean {
  if (!item.perm) return true;
  return item.platform ? canPlatform(session, item.perm) : can(session, item.perm);
}

// roleLine is the role under the person's name: the global role, or how many services they hold a role on.
function roleLine(t: TFunction, session: SessionInfo): string {
  const a = sessionAccess(session);
  if (a.global_role) return t(`enum.role.${a.global_role}`);
  if (a.services.length > 0) return t('access.shell.services', { count: a.services.length });
  return t('access.noGlobalRole');
}

function SetupBanner() {
  const { t } = useTranslation();
  const { session, setupStatus } = useAuth();
  // The setup wizard is the installation's: a global Administrator finishes it.
  if (!canPlatform(session, 'settings.manage') || !setupStatus || setupStatus.completed) return null;
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
  // A person with no role anywhere sees one page (design §9) and the account controls; nothing else is read for them.
  const nothing = hasNoAccess(session);
  const version = useQuery({ queryKey: ['version'], queryFn: getVersion, enabled: !nothing });
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
  const items = nothing ? [] : NAV_ITEMS.filter((i) => allowed(session, i));
  const account = nothing ? [] : ACCOUNT_ITEMS.filter((i) => allowed(session, i));
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
              <div className={classes.accountRole}>{roleLine(t, session)}</div>
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
            {!nothing && <CommandPalette items={[...items, ...account]} />}
            <span className={classes.divider} aria-hidden="true" />
            <ThemeToggle />
            <LanguageToggle signedIn />
            {!nothing && <AttentionBell />}
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
            {!nothing && (
              <>
                <LicenseBanners />
                <NotificationsBanner />
                <BackupBanner />
                <SetupBanner />
              </>
            )}
            {stateReason && (
              <SSOErrorAlert reason={stateReason} onClose={() => navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true })} />
            )}
          </div>
          {nothing ? <NoAccessPage /> : <Outlet />}
          <footer className={classes.footer}>
            <Icon name="LockKeyhole" size={14} />
            <span>{version.data ? t('shell.footer', { version: version.data.version }) : t('app.name', { ns: 'common' })}</span>
          </footer>
        </div>
      </AppShell.Main>
    </AppShell>
  );
}
