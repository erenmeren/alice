import { SegmentedControl } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { setMyLocale } from './api/endpoints';
import { LANGUAGES, setLanguage, type Lang } from './i18n';

// LanguageSwitcher changes the UI language. When signedIn is true the choice is also
// saved on the user's account so it follows them to other browsers.
export function LanguageSwitcher({ signedIn = false }: { signedIn?: boolean }) {
  const { t, i18n } = useTranslation();
  const change = async (value: string) => {
    try {
      await setLanguage(i18n, value as Lang);
    } catch {
      // The texts could not be loaded (a failed download): the current language stays, and the
      // switch shows it; choosing the language again retries.
      return;
    }
    if (signedIn) {
      try {
        await setMyLocale(value);
      } catch {
        // Saving the preference is best effort; the page is already translated.
      }
    }
  };
  return (
    <SegmentedControl
      aria-label={t('language.label')}
      value={i18n.language}
      onChange={(value) => void change(value)}
      data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))}
    />
  );
}
