import { NativeSelect, Switch, useMantineColorScheme, type MantineColorScheme } from '@mantine/core';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { setMyLocale } from '../../api/endpoints';
import { Icon } from '../../design/Icon';
import { LANGUAGES, setLanguage, type Lang } from '../../i18n';
import { useDensity } from '../../preferences';
import classes from './ui.module.css';

const MODES: { value: MantineColorScheme; key: string }[] = [
  { value: 'light', key: 'appearance.light' },
  { value: 'dark', key: 'appearance.dark' },
  { value: 'auto', key: 'appearance.system' },
];

export interface AppearanceControlProps {
  signedIn: boolean;
}

// AppearanceControl is the design's appearance panel: color mode (per device), compact tables (per device) and the
// language (saved to the account when signed in, like the top bar's toggle).
export function AppearanceControl({ signedIn }: AppearanceControlProps) {
  const { t, i18n } = useTranslation();
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const [density, setDensity] = useDensity();
  const id = useId();
  const changeLanguage = async (code: Lang) => {
    try {
      await setLanguage(i18n, code);
    } catch {
      return; // the texts could not be loaded; the current language stays
    }
    if (signedIn) {
      try {
        await setMyLocale(code);
      } catch {
        // best effort, as in the top bar
      }
    }
  };
  return (
    <div>
      <fieldset className={classes.modeSet}>
        <legend className={classes.fieldLabel}>{t('appearance.colorMode')}</legend>
        <div className={classes.appearanceOptions}>
          {MODES.map((m) => {
            const active = colorScheme === m.value;
            return (
              <label key={m.value} className={classes.appearanceOption} data-active={active || undefined}>
                <input type="radio" name={`${id}-color-mode`} value={m.value} checked={active} onChange={() => setColorScheme(m.value)} className={classes.visuallyHidden} />
                <span className={classes.miniApp} data-mode={m.value} aria-hidden="true">
                  <i />
                  <span />
                </span>
                <span className={classes.themeChoice}>
                  {t(m.key)}
                  <Icon name={active ? 'CircleCheck' : 'Circle'} size={16} />
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>
      <div className={classes.switchRow}>
        <div>
          <div className={classes.rowTitle}>{t('appearance.compact')}</div>
          <p id={`${id}-compact-help`} className={classes.rowHelp}>{t('appearance.compactHelp')}</p>
        </div>
        <Switch checked={density === 'compact'} onChange={(e) => setDensity(e.currentTarget.checked ? 'compact' : 'comfortable')} aria-label={t('appearance.compact')} aria-describedby={`${id}-compact-help`} />
      </div>
      <div className={classes.switchRow}>
        <div>
          <div className={classes.rowTitle}>{t('language.label')}</div>
          {/* Mantine's input owns aria-describedby: the select carries the help as its (visually hidden) description and
              this visible copy is hidden from assistive technology, so it is read once. */}
          {signedIn && (
            <p className={classes.rowHelp} aria-hidden="true">
              {t('appearance.languageHelp')}
            </p>
          )}
        </div>
        <NativeSelect aria-label={t('language.label')} description={signedIn ? t('appearance.languageHelp') : undefined} classNames={{ description: classes.visuallyHidden }} value={i18n.language} onChange={(e) => void changeLanguage(e.currentTarget.value as Lang)} data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))} />
      </div>
    </div>
  );
}
