// The public marketplace browser (/modules/): reads a hub's registry from
// the browser. The site is static, so listings are always current without a
// rebuild. By default it talks to the hub that serves the site (same
// origin); build with PUBLIC_HUB_URL=https://hub.example to point a site
// hosted elsewhere at a hub (hubs answer the registry with CORS).
import { parseMarkdown, type Block, type Inline } from "../../../web/src/lib/markdown";
import { dateLocale, l, t, tn } from "../i18n/client";

export const HUB: string = ((import.meta.env.PUBLIC_HUB_URL as string | undefined) ?? "").replace(/\/+$/, "");

export type Pkg = {
  name: string;
  owner: string;
  description: string;
  homepage?: string;
  source?: string;
  license?: string;
  latest?: string;
  downloads: number;
  installs: number;
  rating: number;
  ratingCount: number;
  categories: string[];
  tags: string[];
  icon?: string;
  verified: boolean;
  createdAt: string;
  updatedAt: string;
  delisted?: boolean;
  delistReason?: string;
  delistNote?: string;
};
export type Version = { version: string; payload: string; yanked: boolean; yankedBy?: string; yankReason?: string; createdAt: string };
export type PkgDetail = {
  package: Pkg;
  authorKey: string;
  versions: Version[];
  readme: string;
  screenshots: { id: string; caption?: string }[];
  author: { handle: string; verified: boolean; banned: boolean; createdAt: string };
};
export type Category = { id: string; label: string; count: number };
export type Review = { id: string; author: string; rating: number; body: string; version?: string; updatedAt: string; reply?: string };
export type Reviews = { average: number; count: number; histogram: number[]; items: Review[] };

export async function hub<T>(path: string): Promise<{ data: T; total: number }> {
  let res: Response;
  try {
    res = await fetch(`${HUB}/v1${path}`);
  } catch {
    throw new Error(t("The hub didn't answer. Check your connection and try again."));
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as { error?: string }).error || res.statusText);
  return { data: data as T, total: Number(res.headers.get("X-Total-Count") ?? 0) };
}

/** The package page for a name, in the page's language. */
export const l10nPackage = (name: string) => `${l("/modules/package/")}?name=${encodeURIComponent(name)}`;

export const media = (id: string) => `${HUB}/v1/registry/media/${encodeURIComponent(id)}`;
export const pkgPath = (name: string) => `/registry/packages/${encodeURIComponent(name)}`;

/** Build an element; strings become text nodes, never HTML. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string | undefined> = {}, ...kids: (Node | string | null | undefined | false)[]) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined) e.setAttribute(k, v);
  for (const k of kids) if (k) e.append(k);
  return e;
}

/** Category names by id; the hub's labels are English. */
export function categoryLabel(id: string): string {
  const labels: Record<string, string> = {
    home: t("Home and IoT"),
    servers: t("Servers and infrastructure"),
    dev: t("Developer tools"),
    monitoring: t("Monitoring"),
    communication: t("Mail and chat"),
    media: t("Media"),
    games: t("Games"),
    productivity: t("Productivity"),
    finance: t("Finance"),
    security: t("Security"),
    ai: t("AI and agents"),
    data: t("Data and storage"),
    other: t("Other"),
  };
  return labels[id] ?? id;
}

export function reasonWord(r?: string): string {
  const words: Record<string, string> = {
    malware: t("malware"),
    broken: t("it doesn't work"),
    spam: t("spam"),
    impersonation: t("impersonation"),
    license: t("a license problem"),
    other: t("a policy problem"),
  };
  return (r && words[r]) || t("a policy problem");
}

export const num = (n: number) => n.toLocaleString(dateLocale);

/** "acme/weather" as a two-part name: the handle quiet, the module loud. */
export function nameEl(name: string, cls = "mk-name"): HTMLElement {
  const [owner, mod] = name.split("/");
  return h("span", { class: cls }, h("span", { class: "mk-owner" }, owner + "/"), h("span", { class: "mk-mod" }, mod ?? ""));
}

export function iconEl(p: { icon?: string; name: string }, size = 48): HTMLElement {
  const letter = (p.name.split("/")[1] ?? p.name).charAt(0).toUpperCase();
  const ph = h("span", { class: "mk-icon ph", "aria-hidden": "true", style: `--s:${size}px` }, letter);
  if (!p.icon) return ph;
  const img = h("img", { class: "mk-icon", src: media(p.icon), alt: "", width: String(size), height: String(size), loading: "lazy", style: `--s:${size}px` });
  img.addEventListener("error", () => img.replaceWith(ph));
  return img;
}

export function starsEl(value: number, count?: number): HTMLElement {
  const label = count ? t("Rated {rating} out of 5 by {count}", { rating: value.toFixed(1), count }) : t("Not rated yet");
  const fill = h("span", { class: "mk-stars-fill", style: `width:${(Math.max(0, Math.min(5, value)) / 5) * 100}%` }, "★★★★★");
  return h(
    "span",
    { class: "mk-stars", title: label },
    h("span", { class: "visually-hidden" }, label),
    h("span", { class: "mk-stars-track", "aria-hidden": "true" }, "★★★★★", fill),
    count !== undefined ? h("span", { "aria-hidden": "true" }, count ? value.toFixed(1) : "") : null,
  );
}

export function verifiedEl(): HTMLElement {
  const s = h("span", { class: "mk-verified", title: t("The hub's operators verified this author") });
  s.innerHTML = `<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M8 1.5 9.6 3l2.2-.2.5 2.1 1.9 1.1-.9 2 .9 2-1.9 1.1-.5 2.1-2.2-.2L8 14.5 6.4 13l-2.2.2-.5-2.1L1.8 10l.9-2-.9-2 1.9-1.1.5-2.1 2.2.2Z" fill="currentColor"/><path d="m5.4 8.2 1.8 1.7 3.5-3.6" stroke="var(--bg)" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  s.append(t("Verified"));
  return s;
}

/** Short relative date. */
export function ago(iso: string): string {
  const d = new Date(iso);
  if (isNaN(+d)) return "";
  const days = Math.floor((Date.now() - +d) / 86400000);
  if (days < 1) return t("today");
  if (days < 30) return tn("{n} day ago", "{n} days ago", days);
  return d.toLocaleDateString(dateLocale, { year: "numeric", month: "short", day: "numeric" });
}

/** The same short fingerprint the app shows before installing. */
export async function fingerprint(stdB64: string): Promise<string> {
  try {
    const raw = Uint8Array.from(atob(stdB64), (c) => c.charCodeAt(0));
    const sum = new Uint8Array(await crypto.subtle.digest("SHA-256", raw)).slice(0, 16);
    return btoa(String.fromCharCode(...sum)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  } catch {
    return "";
  }
}

// The signed version payload, read for display only (the app verifies it).
function payloadOf(v?: Version): { manifest?: { permissions?: { network?: unknown } }; artifacts?: { platform?: string }[] } | null {
  if (!v) return null;
  try {
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(v.payload), (c) => c.charCodeAt(0))));
  } catch {
    return null;
  }
}

/** Hosts a version may reach, from its signed manifest. */
export function networkOf(v?: Version): string[] | null {
  const p = payloadOf(v);
  if (!p) return null;
  const n = p.manifest?.permissions?.network;
  return Array.isArray(n) ? n.filter((x: unknown): x is string => typeof x === "string") : [];
}

/** Whether a version has a sandboxed (WebAssembly) build. */
export function hasWasm(v?: Version): boolean {
  return !!payloadOf(v)?.artifacts?.some((a) => a.platform === "wasm");
}

// --- readme ---------------------------------------------------------------------

function inline(x: Inline): Node {
  switch (x.t) {
    case "text":
      return document.createTextNode(x.v);
    case "code":
      return h("code", {}, x.v);
    case "strong":
      return h("strong", {}, ...x.c.map(inline));
    case "em":
      return h("em", {}, ...x.c.map(inline));
    case "link":
      return h("a", { href: x.href, target: "_blank", rel: "noopener noreferrer nofollow" }, ...x.c.map(inline));
  }
}

function block(b: Block): Node {
  switch (b.t) {
    case "h":
      return h(`h${Math.min(6, b.level + 1)}` as "h2", {}, ...b.c.map(inline));
    case "p":
      return h("p", {}, ...b.c.map(inline));
    case "code":
      return h("pre", {}, h("code", {}, b.v));
    case "ul":
      return h("ul", {}, ...b.items.map((it) => h("li", {}, ...it.map(inline))));
    case "ol":
      return h("ol", { start: String(b.start) }, ...b.items.map((it) => h("li", {}, ...it.map(inline))));
    case "quote":
      return h("blockquote", {}, ...b.c.map(block));
    case "hr":
      return h("hr");
  }
}

/** Render a readme as DOM nodes: tags in it stay text. */
export function readmeEl(src: string): HTMLElement {
  return h("div", { class: "prose mk-readme" }, ...parseMarkdown(src).map(block));
}
