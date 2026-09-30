import i18next, { type i18n as I18n } from 'i18next';
import { initReactI18next } from 'react-i18next';
import commonEn from '@locales/common/en.json';
import manifest from '@locales/manifest.json';
import webEn from './locales/en.json';

export type Lang = 'en' | 'tr';
export const LANGUAGES: { code: Lang; name: string }[] = manifest.locales.map((l) => ({
  code: l.code as Lang,
  name: l.name,
}));

const STORAGE_KEY = 'alice.lang';

interface Bundle {
  web: Record<string, unknown>;
  common: Record<string, unknown>;
}

// English is the source language and the fallback, so it is always bundled.
// Every other language is a separate chunk loaded on demand (spec §10.2).
const lazyBundles: Record<Exclude<Lang, 'en'>, () => Promise<Bundle>> = {
  tr: async () => ({
    web: (await import('./locales/tr.json')).default,
    common: (await import('@locales/common/tr.json')).default,
  }),
};

export function isSupported(code: string): code is Lang {
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

async function loadBundle(lang: Lang): Promise<Bundle> {
  if (lang === 'en') return { web: webEn, common: commonEn };
  return lazyBundles[lang]();
}

async function ensureLoaded(i18n: I18n, lang: Lang): Promise<void> {
  if (i18n.hasResourceBundle(lang, 'web')) return;
  const bundle = await loadBundle(lang);
  i18n.addResourceBundle(lang, 'web', bundle.web, true, true);
  i18n.addResourceBundle(lang, 'common', bundle.common, true, true);
}

export async function createI18n(browserLanguages: readonly string[]): Promise<I18n> {
  const lng = pickLanguage(readStored(), browserLanguages);
  const instance = i18next.createInstance();
  await instance.use(initReactI18next).init({
    resources: { en: { web: webEn, common: commonEn } },
    partialBundledLanguages: true,
    lng: 'en',
    fallbackLng: 'en',
    ns: ['web', 'common'],
    defaultNS: 'web',
    fallbackNS: 'common',
    interpolation: { escapeValue: false }, // React escapes output
  });
  if (lng !== 'en') {
    await ensureLoaded(instance, lng);
    await instance.changeLanguage(lng);
  }
  document.documentElement.lang = lng;
  return instance;
}

export async function setLanguage(i18n: I18n, lang: Lang): Promise<void> {
  await ensureLoaded(i18n, lang);
  await i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Storage can be blocked (private mode); the choice then lasts for this page only.
  }
}
