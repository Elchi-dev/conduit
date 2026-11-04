// Translations for the website's own pages. Strings are keyed by their
// English source, like the app's (web/src/i18n), so a missing translation
// falls back to English. English lives at /, German under /de/.
// The docs and the generated API reference stay English; German pages link
// to them. `pnpm test:i18n` checks that every t()/tn() string has a German
// entry in de.ts.
import de from "./de";
import deMarketplace from "./de-marketplace";

export type Lang = "en" | "de";
export const languages: { id: Lang; label: string; short: string }[] = [
  { id: "en", label: "English", short: "EN" },
  { id: "de", label: "Deutsch", short: "DE" },
];
// The marketplace pages keep their German apart (de-marketplace.ts); de.ts wins.
const dicts: Partial<Record<Lang, Record<string, string>>> = { de: { ...deMarketplace, ...de } };

type Vars = Record<string, string | number | undefined | null>;

function fill(s: string, vars?: Vars): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars && vars[k] != null ? String(vars[k]) : m));
}

/**
 * Pages that exist in both languages, as English paths. Everything else
 * (docs, the generated API reference) is English only.
 */
export const localizedPaths = [
  "/",
  "/download/",
  "/hub/",
  "/registry/",
  "/modules/",
  "/modules/package/",
  "/modules/publish/",
  "/changelog/",
  "/api/",
  "/account/",
  "/account/admin/",
  "/invite/",
  "/reset/",
  "/verify/",
];

function withSlash(p: string): string {
  p = p.replace(/index\.html$/, "");
  return p.endsWith("/") ? p : p + "/";
}

/** The language a path is in. */
export function langOf(pathname: string): Lang {
  return pathname === "/de" || pathname.startsWith("/de/") ? "de" : "en";
}

/** The English path for a path in any language. */
export function englishPath(pathname: string): string {
  return withSlash(langOf(pathname) === "de" ? pathname.slice(3) || "/" : pathname);
}

/** Whether a page (English path) has a German version. */
export function hasGerman(path: string): boolean {
  return localizedPaths.includes(withSlash(path));
}

/**
 * A link to an English path in the given language. Pages without a German
 * version (docs, API reference) keep their English path. Query and hash
 * are kept.
 */
export function localize(href: string, lang: Lang): string {
  if (lang === "en" || !href.startsWith("/")) return href;
  const m = href.match(/^([^?#]*)(.*)$/)!;
  const path = m[1] || "/";
  return hasGerman(path) ? "/de" + withSlash(path) + m[2] : href;
}

/** Translators for one language. */
export function translator(lang: Lang) {
  const d = dicts[lang];
  /** Translate an English string. `{name}` placeholders are filled from vars. */
  const t = (source: string, vars?: Vars): string => fill((d && d[source]) || source, vars);
  /** Singular or plural by n; `{n}` is filled with n. */
  const tn = (one: string, other: string, n: number, vars?: Vars): string => t(n === 1 ? one : other, { n, ...vars });
  return { t, tn };
}

/** Everything a page needs for its language, from Astro.currentLocale. */
export function i18n(locale: string | undefined) {
  const lang: Lang = locale === "de" ? "de" : "en";
  return {
    lang,
    ...translator(lang),
    /** Localize a site link. */
    l: (href: string) => localize(href, lang),
    /** BCP 47 tag for dates and numbers. */
    dateLocale: lang === "de" ? "de-DE" : "en-GB",
  };
}
