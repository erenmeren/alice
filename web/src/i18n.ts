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

export interface Bundle {
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

// LoadBundle reads the texts of one language (tests pass a failing one).
export type LoadBundle = (lang: Lang) => Promise<Bundle>;

export interface I18nOptions {
  load?: LoadBundle;
}

async function ensureLoaded(i18n: I18n, lang: Lang, load: LoadBundle = loadBundle): Promise<void> {
  if (i18n.hasResourceBundle(lang, 'web')) return;
  const bundle = await load(lang);
  i18n.addResourceBundle(lang, 'web', bundle.web, true, true);
  i18n.addResourceBundle(lang, 'common', bundle.common, true, true);
}

// createEnglishI18n makes an instance with the bundled English texts only; it loads nothing.
export async function createEnglishI18n(): Promise<I18n> {
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
  document.documentElement.lang = 'en';
  return instance;
}

// createI18n starts in the stored or the browser language. A language whose texts cannot be loaded
// (a failed chunk download) leaves the page in English, which is always bundled (AUD-25 d); a text
// missing in a language falls back to English.
export async function createI18n(browserLanguages: readonly string[], opts: I18nOptions = {}): Promise<I18n> {
  const lng = pickLanguage(readStored(), browserLanguages);
  const instance = await createEnglishI18n();
  if (lng !== 'en') {
    try {
      await ensureLoaded(instance, lng, opts.load);
      await instance.changeLanguage(lng);
      document.documentElement.lang = lng;
    } catch {
      // English stays in use; the language switcher can try again.
    }
  }
  return instance;
}

// setLanguage switches the language once its texts are loaded; when they cannot be loaded it
// rejects and the current language stays.
export async function setLanguage(i18n: I18n, lang: Lang, opts: Pick<I18nOptions, 'load'> = {}): Promise<void> {
  await ensureLoaded(i18n, lang, opts.load);
  await i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Storage can be blocked (private mode); the choice then lasts for this page only.
  }
}
