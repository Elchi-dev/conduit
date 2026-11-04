#!/usr/bin/env node
// Checks the website's German: every string passed to t() or tn() in src/
// must have an entry in src/i18n/de.ts or src/i18n/de-marketplace.ts, with
// the same {placeholders} as the English. Exits 1 and lists what's wrong.
//
//   pnpm test:i18n
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const src = join(root, "src");
const dictFiles = ["src/i18n/de.ts", "src/i18n/de-marketplace.ts"];
const problems = [];

// ---- the German dictionaries ------------------------------------------------

const STRING = String.raw`"(?:[^"\\]|\\.)*"`;
const ENTRY = new RegExp(String.raw`^\s*(${STRING})\s*:\s*(${STRING}),?\s*$`);

/** Entries of a `const x: Record<string, string> = { ... };` file, line by line. */
function readDict(file) {
  const out = new Map();
  const lines = readFileSync(join(root, file), "utf8").split("\n");
  let inside = false;
  lines.forEach((line, i) => {
    if (!inside) {
      if (/Record<string,\s*string>\s*=\s*\{\s*$/.test(line)) inside = true;
      return;
    }
    if (/^\s*\};?\s*$/.test(line)) {
      inside = false;
      return;
    }
    if (/^\s*(\/\/.*)?$/.test(line)) return;
    const m = line.match(ENTRY);
    if (!m) {
      problems.push(`${file}:${i + 1}: can't read this line; write entries as "English": "Deutsch", one per line`);
      return;
    }
    const [en, de] = [JSON.parse(m[1]), JSON.parse(m[2])];
    if (out.has(en)) problems.push(`${file}:${i + 1}: "${en}" is listed twice`);
    if (!de.trim()) problems.push(`${file}:${i + 1}: "${en}" has an empty translation`);
    out.set(en, de);
  });
  if (!out.size) problems.push(`${file}: no entries found`);
  return out;
}

const dicts = dictFiles.map((f) => [f, readDict(f)]);
const german = new Map();
for (const [, d] of dicts.slice().reverse()) for (const [k, v] of d) german.set(k, v); // de.ts wins, as in index.ts

// ---- the strings the site uses ----------------------------------------------

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return walk(p);
    return /\.(astro|ts|tsx|mjs|js)$/.test(name) ? [p] : [];
  });
}

/** Read a JS string literal starting at s[i]; returns [value, end] or null. */
function literal(s, i) {
  const q = s[i];
  if (q !== '"' && q !== "'" && q !== "`") return null;
  let out = "";
  for (let j = i + 1; j < s.length; j++) {
    const c = s[j];
    if (c === "\\") {
      const n = s[++j];
      out += n === "n" ? "\n" : n === "t" ? "\t" : n;
      continue;
    }
    if (q === "`" && c === "$" && s[j + 1] === "{") return { dynamic: true, end: j };
    if (c === q) return { value: out, end: j + 1 };
    out += c;
  }
  return null;
}

const skipWs = (s, i) => {
  while (/\s/.test(s[i] ?? "")) i++;
  return i;
};

const used = new Map(); // key -> first place it's used
const CALL = /(?<![\w$])(tn?)\(/g;
for (const file of walk(src)) {
  const rel = relative(root, file);
  if (dictFiles.includes(rel) || rel.startsWith("src/i18n/")) continue;
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(CALL)) {
    const where = `${rel}:${text.slice(0, m.index).split("\n").length}`;
    let i = skipWs(text, m.index + m[0].length);
    const first = literal(text, i);
    if (!first) continue; // t(variable): a local helper or a pass-through, not a key
    if (first.dynamic) {
      problems.push(`${where}: ${m[1]}() needs a plain string; use {placeholders} instead of \${…}`);
      continue;
    }
    const keys = [first.value];
    if (m[1] === "tn") {
      i = skipWs(text, first.end);
      if (text[i] === ",") {
        const second = literal(text, skipWs(text, i + 1));
        if (second?.dynamic) problems.push(`${where}: tn() needs plain strings`);
        else if (second) keys.push(second.value);
      }
    }
    for (const k of keys) if (!used.has(k)) used.set(k, where);
  }
}

// ---- compare ----------------------------------------------------------------

const holes = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((x) => x[1]).sort().join(",");
let missing = 0;
for (const [en, where] of used) {
  const de = german.get(en);
  if (de === undefined) {
    missing++;
    problems.push(`${where}: no German for ${JSON.stringify(en)}`);
  } else if (holes(en) !== holes(de)) {
    problems.push(`${where}: placeholders differ: ${JSON.stringify(en)} has {${holes(en)}}, the German has {${holes(de)}}`);
  }
}
// Entries nobody uses are only reported, not fatal: a page may have moved.
const unused = [...german.keys()].filter((k) => !used.has(k));
// Placeholders in entries that are not used still have to match.
for (const [file, d] of dicts)
  for (const [en, de] of d) if (!used.has(en) && holes(en) !== holes(de)) problems.push(`${file}: placeholders differ for ${JSON.stringify(en)}`);

if (unused.length && process.argv.includes("--unused")) for (const k of unused) console.log(`unused: ${JSON.stringify(k)}`);
if (problems.length) {
  for (const p of problems) console.error(p);
  console.error(`\ni18n: ${problems.length} problem${problems.length === 1 ? "" : "s"} (${missing} missing), ${used.size} strings checked.`);
  process.exit(1);
}
console.log(`i18n: all ${used.size} strings have German (${german.size} entries, ${unused.length} unused; --unused lists them).`);
