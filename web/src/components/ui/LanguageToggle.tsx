import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { setMyLocale } from '../../api/endpoints';
import { LANGUAGES, setLanguage } from '../../i18n';
import classes from './ui.module.css';

export interface LanguageToggleProps {
  signedIn: boolean;
}

// LanguageToggle is the design's TR/EN button (R9): it shows the other language's code and is named by that language's
// own name, so a person who reads only that language finds it. With two languages it toggles.
export function LanguageToggle({ signedIn }: LanguageToggleProps) {
  const { i18n } = useTranslation();
  const other = LANGUAGES.find((l) => l.code !== i18n.language) ?? LANGUAGES[0];
  const change = async () => {
    try {
      await setLanguage(i18n, other.code);
    } catch {
      return;
    }
    if (signedIn) {
      try {
        await setMyLocale(other.code);
      } catch {
        // best effort: the page is already translated
      }
    }
  };
  return (
    <Button variant="subtle" color="gray" size="xs" aria-label={other.name} lang={other.code} onClick={() => void change()}>
      <span className={classes.langCode} aria-hidden="true">
        {other.code}
      </span>
    </Button>
  );
}
