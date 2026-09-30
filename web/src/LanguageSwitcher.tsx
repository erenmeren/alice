import { SegmentedControl } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { LANGUAGES, setLanguage, type Lang } from './i18n';

export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();
  return (
    <SegmentedControl
      aria-label={t('language.label')}
      value={i18n.language}
      onChange={(value) => void setLanguage(i18n, value as Lang)}
      data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))}
    />
  );
}
