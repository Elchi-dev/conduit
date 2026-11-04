// The language of the page a browser script runs on, read from <html lang>.
import { localize, translator, type Lang } from ".";

export const lang: Lang = typeof document !== "undefined" && document.documentElement.lang === "de" ? "de" : "en";
export const { t, tn } = translator(lang);
/** Localize a site link. */
export const l = (href: string) => localize(href, lang);
/** BCP 47 tag for dates and numbers. */
export const dateLocale = lang === "de" ? "de-DE" : "en-GB";
