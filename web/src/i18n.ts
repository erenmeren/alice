import i18next, { type i18n as I18n } from 'i18next';
import { initReactI18next } from 'react-i18next';
import commonEn from '@locales/common/en.json';
import commonTr from '@locales/common/tr.json';
import manifest from '@locales/manifest.json';
import webEn from './locales/en.json';
import webTr from './locales/tr.json';

export type Lang = 'en' | 'tr';
export const LANGUAGES: { code: Lang; name: string }[] = manifest.locales.map((l) => ({
  code: l.code as Lang,
  name: l.name,
}));

const STORAGE_KEY = 'alice.lang';

function isSupported(code: string): code is Lang {
  return LANGUAGES.some((l) => l.code === code);
}

// Language tags are ASCII protocol data, so invariant lowercasing is correct here.
function baseCode(tag: string): string {
  return tag.split('-')[0].toLocaleLowerCase('en-US');
}

export function pickLanguage(stored: string | null, browser: readonly string[]): Lang {
  if (stored && isSupported(stored)) return stored;
  for (const tag of browser) {
    const base = baseCode(tag);
    if (isSupported(base)) return base;
  }
  return 'en';
}

function readStored(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export async function createI18n(browserLanguages: readonly string[]): Promise<I18n> {
  const lng = pickLanguage(readStored(), browserLanguages);
  const instance = i18next.createInstance();
  await instance.use(initReactI18next).init({
    resources: {
      en: { web: webEn, common: commonEn },
      tr: { web: webTr, common: commonTr },
    },
    lng,
    fallbackLng: 'en',
    ns: ['web', 'common'],
    defaultNS: 'web',
    fallbackNS: 'common',
    interpolation: { escapeValue: false }, // React escapes output
  });
  document.documentElement.lang = lng;
  return instance;
}

export async function setLanguage(i18n: I18n, lang: Lang): Promise<void> {
  await i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Storage can be blocked (private mode); the choice then lasts for this page only.
  }
}
