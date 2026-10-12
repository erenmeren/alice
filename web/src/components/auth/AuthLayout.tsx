import { Title } from '@mantine/core';
import type { ReactNode, Ref } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon, type IconName } from '../../design/Icon';
import { LanguageToggle, ThemeToggle } from '../ui';
import classes from './auth.module.css';

export interface AuthLayoutProps {
  children: ReactNode;
  // brand={false} leaves out the brand side (not-found and error pages show the form side alone).
  brand?: boolean;
  // wide gives the form side room for the authenticator enrollment and the recovery codes.
  wide?: boolean;
}

// AuthLayout is the design's sign-in layout (loginPage): a brand side with the product's promise and a form side.
// The brand side is decorative context (an aside, no heading): the form side carries the page's only <h1> and is the
// page's only <main>. The toggles sit top right; the language toggle never saves to an account (nobody is signed in).
export function AuthLayout({ children, brand = true, wide = false }: AuthLayoutProps) {
  const { t } = useTranslation();
  return (
    <div className={brand ? classes.layout : classes.single}>
      {brand && (
        <aside className={classes.brandSide} aria-label={t('app.name', { ns: 'common' })}>
          <div className={classes.brand}>
            <img src="/favicon.svg" alt="" className={classes.brandMark} />
            <span>
              {t('app.name', { ns: 'common' })}
              <span className={classes.brandDot} aria-hidden="true">
                .
              </span>
            </span>
          </div>
          <div className={classes.copy}>
            <p className={classes.eyebrow}>{t('login.brand.eyebrow')}</p>
            <p className={classes.tagline}>{t('login.brand.tagline')}</p>
            <p className={classes.text}>{t('login.brand.text')}</p>
          </div>
          <div className={classes.orbit} aria-hidden="true" />
          <ul className={classes.brandFooter}>
            <li>{t('login.brand.selfHosted')}</li>
            <li>{t('login.brand.offline')}</li>
            <li>{t('login.brand.control')}</li>
          </ul>
        </aside>
      )}
      <main className={classes.formSide}>
        <div className={classes.top}>
          <ThemeToggle />
          <LanguageToggle signedIn={false} />
        </div>
        <div className={classes.form} data-wide={wide || undefined}>
          {children}
        </div>
      </main>
    </div>
  );
}

export interface AuthMessageProps {
  icon: IconName;
  title: ReactNode;
  text?: ReactNode;
  // actions are the ways on (a link home, a reload button).
  actions?: ReactNode;
  headingRef?: Ref<HTMLHeadingElement>;
}

// AuthMessage is the design's empty-state block with the page's <h1> as its title: the not-found, error and no-access
// pages say what happened and offer the way on. (EmptyState's title is a paragraph, for empty tables inside a page.)
export function AuthMessage({ icon, title, text, actions, headingRef }: AuthMessageProps) {
  return (
    <div className={classes.message}>
      <span className={classes.iconTile}>
        <Icon name={icon} size={23} />
      </span>
      <Title order={1} size={29} className={classes.heading} ref={headingRef} tabIndex={headingRef ? -1 : undefined}>
        {title}
      </Title>
      {text && <p className={classes.messageText}>{text}</p>}
      {actions && <div className={classes.actions}>{actions}</div>}
    </div>
  );
}
