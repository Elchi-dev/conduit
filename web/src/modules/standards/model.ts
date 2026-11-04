// Types and helpers for the Standards module page. render() mirrors Render in
// modules/standards/markdown.go, so the preview shows exactly what an AI gets.
import { api, ok, type Outcome } from "../../api/client";

export type Level = "must" | "should" | "may";
export type SectionKind = "principles" | "dodont" | "rules" | "examples" | "tokens" | "checklist" | "references" | "notes";
export type TokenKind = "color" | "type" | "spacing" | "radius" | "shadow" | "motion" | "other";

export interface Pair { do?: string; dont?: string }
export interface Rule { level: Level; text: string; why?: string }
export interface Example { title?: string; note?: string; lang?: string; good?: string; bad?: string }
export interface Token { key: string; value: string; note?: string }
export interface TokenGroup { name: string; kind: TokenKind; tokens: Token[] }
export interface Link { title: string; url: string; note?: string }
export interface Section {
  kind: SectionKind;
  title?: string;
  items?: string[];
  pairs?: Pair[];
  rules?: Rule[];
  examples?: Example[];
  groups?: TokenGroup[];
  links?: Link[];
  markdown?: string;
}
export interface Standard {
  id: string;
  title: string;
  icon?: string;
  category: string;
  summary?: string;
  tags?: string[];
  appliesTo?: string[];
  priority: number;
  enabled: boolean;
  sections: Section[];
  updated?: string;
}
export interface Row {
  id: string;
  title: string;
  icon?: string;
  category: string;
  summary?: string;
  tags: string[];
  appliesTo: string[];
  priority: number;
  enabled: boolean;
  updated?: string;
  counts: Record<string, number>;
}
export interface Toolkit { id: string; title: string; icon?: string; summary?: string; standards: string[]; updated?: string }

export const categories = ["frontend", "design", "writing", "code", "git", "review", "security", "product", "custom"] as const;
export const sectionKinds: SectionKind[] = ["principles", "dodont", "rules", "examples", "tokens", "checklist", "references", "notes"];
export const tokenKinds: TokenKind[] = ["color", "type", "spacing", "radius", "shadow", "motion", "other"];
export const levels: Level[] = ["must", "should", "may"];

/** Category hues, from the chart series tokens (amber stays reserved). */
export const categoryHue: Record<string, string> = {
  frontend: "var(--series-1)",
  design: "var(--series-5)",
  writing: "var(--series-7)",
  code: "var(--series-3)",
  git: "var(--series-2)",
  review: "var(--series-6)",
  security: "var(--series-8)",
  product: "var(--ink-2)",
  custom: "var(--off)",
};

export function blankSection(kind: SectionKind): Section {
  switch (kind) {
    case "principles":
    case "checklist":
      return { kind, items: [""] };
    case "dodont":
      return { kind, pairs: [{ do: "", dont: "" }] };
    case "rules":
      return { kind, rules: [{ level: "must", text: "" }] };
    case "examples":
      return { kind, examples: [{ title: "", lang: "", good: "", bad: "" }] };
    case "tokens":
      return { kind, groups: [{ name: "Colours", kind: "color", tokens: [{ key: "", value: "" }] }] };
    case "references":
      return { kind, links: [{ title: "", url: "" }] };
    case "notes":
      return { kind, markdown: "" };
  }
}

export function blankStandard(category = "custom"): Standard {
  return { id: "", title: "", icon: "ruler", category, summary: "", tags: [], appliesTo: [], priority: 50, enabled: true, sections: [blankSection("principles"), blankSection("rules")] };
}

// ---- rendering (mirror of markdown.go) ----

/** The section heading the module writes when a section has no title. */
export const defaultTitle: Record<SectionKind, string> = {
  principles: "Principles",
  dodont: "Do and don't",
  rules: "Rules",
  examples: "Examples",
  tokens: "Tokens",
  checklist: "Checklist",
  references: "References",
  notes: "Notes",
};

const line = (s?: string) => (s ?? "").split(/\s+/).filter(Boolean).join(" ");
const lines = (a?: string[]) => (a ?? []).map(line).filter(Boolean);

function fence(s: string) {
  let run = 0;
  let best = 0;
  for (const c of s) {
    if (c === "`") best = Math.max(best, ++run);
    else run = 0;
  }
  return "`".repeat(Math.max(3, best + 1));
}

const trimNl = (s?: string) => (s ?? "").replace(/^\n+|\n+$/g, "");

/** Cleans a standard the way the module's Normalize does (for the preview). */
export function clean(s: Standard): Standard {
  return {
    ...s,
    title: line(s.title),
    summary: line(s.summary),
    appliesTo: lines(s.appliesTo),
    tags: lines(s.tags),
    sections: s.sections.map((sec) => ({
      ...sec,
      title: line(sec.title) === defaultTitle[sec.kind] ? "" : line(sec.title),
      items: lines(sec.items),
      pairs: (sec.pairs ?? []).map((p) => ({ do: line(p.do), dont: line(p.dont) })).filter((p) => p.do || p.dont),
      rules: (sec.rules ?? []).map((r) => ({ level: r.level || "should", text: line(r.text), why: line(r.why) })).filter((r) => r.text),
      examples: (sec.examples ?? [])
        .map((e) => ({ title: line(e.title), note: line(e.note), lang: line(e.lang).toLowerCase() === "text" ? "" : line(e.lang).toLowerCase(), good: trimNl(e.good), bad: trimNl(e.bad) }))
        .filter((e) => e.good || e.bad),
      groups: (sec.groups ?? []).map((g) => ({
        ...g,
        name: line(g.name) || g.kind[0].toUpperCase() + g.kind.slice(1),
        tokens: g.tokens.map((t) => ({ key: line(t.key.replace(/`/g, "")), value: line(t.value.replace(/`/g, "'")), note: line(t.note) })).filter((t) => t.key),
      })),
      links: (sec.links ?? []).map((l) => ({ title: line(l.title) || line(l.url), url: line(l.url), note: line(l.note) })).filter((l) => l.url),
      markdown: trimNl((sec.markdown ?? "").replace(/\r\n/g, "\n")),
    })),
  };
}

function empty(sec: Section) {
  return !sec.items?.length && !sec.pairs?.length && !sec.rules?.length && !sec.examples?.length && !sec.groups?.length && !sec.links?.length && !sec.markdown?.trim();
}

const escLink = (s: string) => s.replace(/\\/g, "\\\\").replace(/\]/g, "\\]").replace(/\[/g, "\\[");
const linkURL = (u: string) => (/[ ()<>]/.test(u) ? `<${u.replace(/</g, "%3C").replace(/>/g, "%3E")}>` : u);

/** The compact Markdown the module's get action returns. */
export function render(raw: Standard): string {
  const s = clean(raw);
  const out: string[] = [];
  out.push(`# ${s.title}\n\n`);
  const meta = [`Category: ${s.category}`, `Priority: ${s.priority}`];
  if (s.appliesTo?.length) meta.push(`Applies to: ${s.appliesTo.join(", ")}`);
  if (!s.enabled) meta.push("Disabled");
  out.push(`_${meta.join(" · ")}_\n\n`);
  if (s.summary) out.push(s.summary + "\n\n");
  for (const sec of s.sections) {
    if (empty(sec)) continue;
    out.push(`## ${sec.title || defaultTitle[sec.kind]}\n\n`);
    switch (sec.kind) {
      case "principles":
        sec.items!.forEach((i) => out.push(`- ${i}\n`));
        break;
      case "checklist":
        sec.items!.forEach((i) => out.push(`- [ ] ${i}\n`));
        break;
      case "dodont":
        for (const p of sec.pairs!) {
          if (p.do && p.dont) out.push(`- Do: ${p.do}\n  Don't: ${p.dont}\n`);
          else if (p.do) out.push(`- Do: ${p.do}\n`);
          else out.push(`- Don't: ${p.dont}\n`);
        }
        break;
      case "rules":
        for (const r of sec.rules!) {
          out.push(`- **${r.level.toUpperCase()}** ${r.text}\n`);
          if (r.why) out.push(`  Why: ${r.why}\n`);
        }
        break;
      case "examples":
        sec.examples!.forEach((e, i) => {
          if (i > 0) out.push("\n");
          out.push(`### ${e.title || "Example"}\n\n`);
          if (e.note) out.push(e.note + "\n\n");
          const lang = e.lang || "text";
          for (const [label, body] of [["Good", e.good], ["Bad", e.bad]] as const) {
            if (!body) continue;
            const f = fence(body);
            out.push(`**${label}**\n\n${f}${lang}\n${body}\n${f}\n\n`);
          }
        });
        break;
      case "tokens":
        sec.groups!.forEach((g, i) => {
          if (i > 0) out.push("\n");
          out.push(`### ${g.name} (${g.kind})\n\n`);
          for (const t of g.tokens) out.push(`- \`${t.key}\`: \`${t.value}\`${t.note ? ` — ${t.note}` : ""}\n`);
        });
        break;
      case "references":
        for (const l of sec.links!) out.push(`- [${escLink(l.title)}](${linkURL(l.url)})${l.note ? ` — ${l.note}` : ""}\n`);
        break;
      case "notes":
        if (sec.markdown) out.push(sec.markdown + "\n");
        break;
    }
    out.push("\n");
  }
  return out.join("").replace(/\n+$/, "") + "\n";
}

// ---- line diff ----

export type DiffLine = { op: "same" | "add" | "del"; text: string };

/** A line diff (longest common subsequence); fine for documents this size. */
export function diffLines(a: string, b: string): DiffLine[] {
  const x = a.split("\n");
  const y = b.split("\n");
  const n = x.length;
  const m = y.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: "same", text: x[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ op: "del", text: x[i++] });
    else out.push({ op: "add", text: y[j++] });
  }
  while (i < n) out.push({ op: "del", text: x[i++] });
  while (j < m) out.push({ op: "add", text: y[j++] });
  return out;
}

// ---- calling the module ----

export async function run<T = unknown>(instance: string, action: string, input: unknown = {}, dryRun = false): Promise<{ out: T; outcome: Outcome }> {
  const outcome = await ok(
    api.POST("/instances/{id}/actions/{action}", { params: { path: { id: instance, action } }, body: { input: input as never, dryRun } }),
  );
  return { out: outcome.result.output as T, outcome };
}

/** Parses "32px / 1.15 / 650" into CSS for the type-scale preview. */
export function typeStyle(v: string): { fontSize?: string; lineHeight?: string; fontWeight?: number } {
  const parts = v.split("/").map((p) => p.trim());
  const size = parts[0]?.match(/^\d+(\.\d+)?(px|rem|em|pt)?$/) ? (/[a-z]/.test(parts[0]) ? parts[0] : parts[0] + "px") : undefined;
  const lh = parts[1] && /^\d+(\.\d+)?(px|rem|em|%)?$/.test(parts[1]) ? parts[1] : undefined;
  const w = parts[2] && /^\d{3}$/.test(parts[2]) ? Number(parts[2]) : undefined;
  return { fontSize: size, lineHeight: lh, fontWeight: w };
}

/** A CSS colour the browser understands, or undefined. */
export function cssColor(v: string): string | undefined {
  const s = v.trim();
  if (!s) return undefined;
  if (typeof CSS !== "undefined" && CSS.supports && CSS.supports("color", s)) return s;
  return undefined;
}

/** #rgb / #rrggbb as #rrggbb for <input type="color">. */
export function hex6(v: string): string | undefined {
  const m = v.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!m) return undefined;
  const h = m[1].length === 3 ? m[1].split("").map((c) => c + c).join("") : m[1];
  return "#" + h.toLowerCase();
}

/** Starts a download of text the module exported. */
export function download(filename: string, content: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
