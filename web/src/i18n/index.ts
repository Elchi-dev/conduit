// Translations for the app. Strings are keyed by their English source, so a
// missing translation falls back to English. Add a language by adding a
// dictionary next to de.ts and listing it in `languages` and `dicts`.
// `pnpm test:i18n` checks that every t()/tn() string has a German entry.
import de from "./de";

export type Lang = "en" | "de";
export const languages: { id: Lang; label: string }[] = [
  { id: "en", label: "English" },
  { id: "de", label: "Deutsch" },
];
const dicts: Partial<Record<Lang, Record<string, string>>> = { de };
const storageKey = "conduit.lang";

function stored(): Lang | null {
  try {
    const v = localStorage.getItem(storageKey);
    return v === "en" || v === "de" ? v : null;
  } catch {
    return null;
  }
}

function detect(): Lang {
  const s = stored();
  if (s) return s;
  const nav = typeof navigator !== "undefined" ? navigator.language || "" : "";
  return nav.toLowerCase().startsWith("de") ? "de" : "en";
}

let lang: Lang = detect();
if (typeof document !== "undefined") document.documentElement.lang = lang;

/** The active language. */
export function currentLang(): Lang {
  return lang;
}

/** The locale for Intl formatting: undefined (the browser's) in English. */
export function locale(): string | undefined {
  return lang === "en" ? undefined : lang;
}

/**
 * Switch language. The choice is remembered on this device and the app
 * reloads, so every screen (and text computed at load time) re-renders.
 */
export function setLang(next: Lang) {
  try {
    localStorage.setItem(storageKey, next);
  } catch {
    /* private mode: only this page load */
  }
  if (next !== lang) {
    lang = next;
    if (typeof location !== "undefined") location.reload();
  }
}

function fill(s: string, vars?: Record<string, string | number | undefined | null>): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/** Translate an English UI string. `{name}` placeholders are filled from vars. */
export function t(source: string, vars?: Record<string, string | number | undefined | null>): string {
  const d = dicts[lang];
  return fill((d && d[source]) || source, vars);
}

/** Singular or plural by n; `{n}` is filled with n. */
export function tn(one: string, other: string, n: number, vars?: Record<string, string | number | undefined | null>): string {
  return t(n === 1 ? one : other, { n, ...vars });
}

/** Re-renders aren't needed: switching languages reloads the app. */
export function useLang(): [Lang, (l: Lang) => void] {
  return [lang, setLang];
}
