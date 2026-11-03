// The API reference is rendered at build time from api/openapi/*.yaml, the
// same files the daemon and hub test their routes against.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

type Obj = Record<string, any>;

export type Prop = { name: string; type: string; required: boolean; description: string; depth: number };
export type Param = { name: string; in: string; type: string; required: boolean; description: string };
export type Body = { ref?: string; type: string; description: string; props: Prop[]; required: boolean };
export type Resp = { status: string; description: string; type: string };
export type Op = {
  id: string;
  method: string;
  path: string;
  summary: string;
  description: string;
  auth: boolean;
  params: Param[];
  body?: Body;
  responses: Resp[];
};
export type Group = { tag: string; ops: Op[] };
export type Schema = { name: string; description: string; type: string; props: Prop[] };
export type Api = {
  slug: string;
  title: string;
  version: string;
  description: string;
  base: string;
  server: string;
  groups: Group[];
  schemas: Schema[];
};

const METHODS = ["get", "post", "put", "patch", "delete"];

const tagTitles: Record<string, string> = {
  hub: "Hub",
  accounts: "Accounts",
  orgs: "Organisations",
  devices: "Devices",
  relay: "Relay",
  sync: "Sync",
  keys: "API keys",
  registry: "Module registry",
  updates: "Updates",
  remote: "Remote access",
  system: "System",
  auth: "Sign-in and sessions",
  modules: "Modules and actions",
  audit: "Audit log",
  approvals: "Approvals",
  policy: "Policy",
  panic: "Emergency stop",
  vault: "Vault",
  automations: "Automations",
  assistant: "Assistant and agents",
  events: "Events",
  webhooks: "Webhooks",
  other: "Other",
};
export const tagTitle = (t: string) => tagTitles[t] ?? t.charAt(0).toUpperCase() + t.slice(1);

const refName = (ref: string) => ref.split("/").pop()!;

function lookup(spec: Obj, ref: string): Obj {
  return ref
    .replace(/^#\//, "")
    .split("/")
    .reduce((o: Obj, k) => (o ? o[k] : undefined), spec) ?? {};
}

/** A short, readable type: "string", "array of Approval", "one of: a, b". */
export function typeOf(s: Obj | undefined): string {
  if (!s) return "";
  if (s.$ref) return refName(s.$ref);
  if (s.enum) return "one of: " + s.enum.map(String).join(", ");
  if (s.const !== undefined) return JSON.stringify(s.const);
  for (const k of ["oneOf", "anyOf"]) if (s[k]) return s[k].map(typeOf).join(" or ");
  if (s.allOf) return s.allOf.map(typeOf).join(" and ");
  const t = Array.isArray(s.type) ? s.type.join(" or ") : s.type;
  if (t === "array") return "array of " + (typeOf(s.items) || "anything");
  if (t === "object" || (!t && (s.properties || s.additionalProperties))) {
    if (!s.properties && s.additionalProperties && s.additionalProperties !== true) return "map of " + typeOf(s.additionalProperties);
    return "object";
  }
  let out = t ?? "any";
  if (s.format) out += ` (${s.format})`;
  return out;
}

function propsOf(spec: Obj, s: Obj | undefined, depth = 0, prefix = ""): Prop[] {
  if (!s) return [];
  if (s.$ref && depth === 0) s = lookup(spec, s.$ref);
  if (s.allOf) return s.allOf.flatMap((x: Obj) => propsOf(spec, x.$ref ? lookup(spec, x.$ref) : x, depth, prefix));
  if (!s.properties) return [];
  const req = new Set<string>(s.required ?? []);
  const out: Prop[] = [];
  for (const [name, p] of Object.entries<Obj>(s.properties)) {
    out.push({ name: prefix + name, type: typeOf(p), required: req.has(name), description: p.description ?? "", depth });
    // Inline objects (not $refs) are expanded one level, so a request body
    // reads in one table.
    const inner = p.type === "array" ? p.items : p;
    if (depth === 0 && inner && !inner.$ref && inner.properties) out.push(...propsOf(spec, inner, 1, prefix + name + (p.type === "array" ? "[]." : ".")));
  }
  return out;
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[{}]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function load(file: string, slug: string): Api {
  const spec: Obj = parse(readFileSync(fileURLToPath(new URL(`../../../api/openapi/${file}`, import.meta.url)), "utf8"));
  const server: string = spec.servers?.[0]?.url ?? "";
  let base = "";
  try {
    base = new URL(server).pathname.replace(/\/$/, "");
  } catch {}
  const globalAuth = (spec.security ?? []).length > 0;
  const order: string[] = (spec.tags ?? []).map((t: Obj) => t.name);
  const groups = new Map<string, Op[]>();
  for (const [path, item] of Object.entries<Obj>(spec.paths ?? {})) {
    const shared: Obj[] = item.parameters ?? [];
    for (const m of METHODS) {
      const op: Obj | undefined = item[m];
      if (!op) continue;
      const params: Param[] = [...shared, ...(op.parameters ?? [])].map((p) => {
        const q = p.$ref ? lookup(spec, p.$ref) : p;
        return { name: q.name, in: q.in, type: typeOf(q.schema), required: !!q.required, description: q.description ?? "" };
      });
      let body: Body | undefined;
      let rb: Obj | undefined = op.requestBody;
      if (rb?.$ref) rb = lookup(spec, rb.$ref);
      if (rb) {
        const [ct, media] = Object.entries<Obj>(rb.content ?? {})[0] ?? ["", {}];
        const sch: Obj | undefined = media?.schema;
        body = {
          ref: sch?.$ref ? refName(sch.$ref) : undefined,
          type: ct === "application/json" || !ct ? typeOf(sch) : `${ct}${sch ? ", " + typeOf(sch) : ""}`,
          description: rb.description ?? "",
          props: propsOf(spec, sch),
          required: !!rb.required,
        };
      }
      const responses: Resp[] = Object.entries<Obj>(op.responses ?? {}).map(([status, r]) => {
        const rr = r.$ref ? lookup(spec, r.$ref) : r;
        const sch = Object.values<Obj>(rr.content ?? {})[0]?.schema;
        return { status, description: rr.description ?? "", type: typeOf(sch) };
      });
      const tag = op.tags?.[0] ?? "other";
      const auth = op.security ? op.security.length > 0 : globalAuth;
      const o: Op = {
        id: op.operationId ?? slugify(`${m} ${path}`),
        method: m.toUpperCase(),
        path: base + path,
        summary: op.summary ?? "",
        description: op.description ?? "",
        auth,
        params,
        body,
        responses,
      };
      if (!groups.has(tag)) groups.set(tag, []);
      groups.get(tag)!.push(o);
    }
  }
  const tags = [...order.filter((t) => groups.has(t)), ...[...groups.keys()].filter((t) => !order.includes(t))];
  const schemas: Schema[] = Object.entries<Obj>(spec.components?.schemas ?? {})
    .map(([name, s]) => ({ name, description: s.description ?? "", type: typeOf(s), props: propsOf(spec, s) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    slug,
    title: spec.info?.title ?? slug,
    version: spec.info?.version ?? "",
    description: spec.info?.description ?? "",
    base,
    server,
    groups: tags.map((t) => ({ tag: t, ops: groups.get(t)! })),
    schemas,
  };
}

export const apis: Api[] = [load("daemon.yaml", "daemon"), load("hub.yaml", "hub")];

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Inline Markdown for spec descriptions: code, bold, links. */
function inline(s: string, schemaNames: Set<string>): string {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2">$1</a>')
    .replace(/\bdocs\/([a-z-]+(?:\/[a-z0-9-]+)*)(?:\.md)?\b/g, (m, p: string) => `<a href="/docs/${p.replace(/\/README$/, "")}/">${m}</a>`)
    .replace(/\b(api\/openapi\/[a-z]+\.yaml|internal\/[a-z/]+)\b/g, "<code>$1</code>")
    .replace(/#\/components\/schemas\/(\w+)/g, (_m, n: string) => (schemaNames.has(n) ? `<a href="#schema-${n}">${n}</a>` : n));
}

/** Block Markdown for spec descriptions: paragraphs and "-" lists. */
export function md(s: string, schemaNames: Set<string> = new Set()): string {
  if (!s) return "";
  const out: string[] = [];
  for (const block of s.trim().split(/\n\s*\n/)) {
    const lines = block.split("\n");
    if (lines.every((l) => /^\s*-\s/.test(l) || /^\s{2,}\S/.test(l))) {
      const items: string[] = [];
      for (const l of lines) {
        if (/^\s*-\s/.test(l)) items.push(l.replace(/^\s*-\s/, ""));
        else items[items.length - 1] += " " + l.trim();
      }
      out.push("<ul>" + items.map((i) => `<li>${inline(i, schemaNames)}</li>`).join("") + "</ul>");
    } else {
      const firstList = lines.findIndex((l) => /^\s*-\s/.test(l));
      if (firstList > 0) {
        out.push(`<p>${inline(lines.slice(0, firstList).join(" "), schemaNames)}</p>`);
        out.push(md(lines.slice(firstList).join("\n"), schemaNames));
      } else out.push(`<p>${inline(lines.join(" "), schemaNames)}</p>`);
    }
  }
  return out.join("");
}

/** A type string with schema names turned into links. */
export function typeHTML(t: string, schemaNames: Set<string>): string {
  return esc(t).replace(/\b[A-Z][A-Za-z0-9]+\b/g, (n) => (schemaNames.has(n) ? `<a href="#schema-${n}">${n}</a>` : n));
}
