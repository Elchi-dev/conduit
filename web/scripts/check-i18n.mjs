// Checks that every string passed to t() or tn() in src/ has a German entry
// in src/i18n/de.ts, and lists entries nothing uses any more.
// `node scripts/check-i18n.mjs --keys` prints the keys found in src/.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../src/", import.meta.url).pathname;
const str = String.raw`"(?:[^"\\\n]|\\.)*"`;
const callRe = new RegExp(String.raw`(?<![\w.])(t|tn)\(\s*(${str})(?:\s*,\s*(${str}))?`, "g");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== "i18n") walk(p, out);
    } else if (/\.tsx?$/.test(name) && !/\.(test|d)\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

const used = new Map(); // key -> first place it's used
for (const file of walk(root)) {
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(callRe)) {
    const keys = [JSON.parse(m[2])];
    if (m[1] === "tn" && m[3]) keys.push(JSON.parse(m[3]));
    const line = src.slice(0, m.index).split("\n").length;
    for (const k of keys) if (!used.has(k)) used.set(k, `${relative(root, file)}:${line}`);
  }
}

if (process.argv.includes("--keys")) {
  for (const [k, at] of used) console.log(JSON.stringify(k), "\t", at);
  process.exit(0);
}

const de = readFileSync(join(root, "i18n/de.ts"), "utf8");
const entryRe = new RegExp(String.raw`^\s*(${str})\s*:\s*(${str})\s*,?\s*$`, "gm");
const dict = new Map();
for (const m of de.matchAll(entryRe)) dict.set(JSON.parse(m[1]), JSON.parse(m[2]));

const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
let failed = false;
for (const [k, at] of used) {
  if (!dict.has(k)) {
    console.error(`missing German for ${JSON.stringify(k)} (${at})`);
    failed = true;
  } else if (placeholders(k) !== placeholders(dict.get(k))) {
    console.error(`placeholders differ for ${JSON.stringify(k)}: ${JSON.stringify(dict.get(k))}`);
    failed = true;
  }
}
const unused = [...dict.keys()].filter((k) => !used.has(k));
for (const k of unused) console.warn(`unused: ${JSON.stringify(k)}`);
console.log(`${used.size} strings, ${dict.size} German entries${unused.length ? `, ${unused.length} unused` : ""}`);
if (failed) process.exit(1);
