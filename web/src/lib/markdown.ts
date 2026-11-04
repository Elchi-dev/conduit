// A small Markdown parser for module readmes from a hub. It produces a tree,
// never HTML: renderers build elements from it (React in the app, DOM nodes
// on the website), so raw HTML in a readme shows as text and nothing in it
// can run. Links are kept only for http(s) and mailto; images are shown as
// links (loading them would tell any server who reads the readme).
// The website imports this file too (site/src/scripts/markdown.ts).

export type Inline =
  | { t: "text"; v: string }
  | { t: "code"; v: string }
  | { t: "strong"; c: Inline[] }
  | { t: "em"; c: Inline[] }
  | { t: "link"; href: string; c: Inline[] };

export type Block =
  | { t: "h"; level: 1 | 2 | 3 | 4 | 5 | 6; c: Inline[] }
  | { t: "p"; c: Inline[] }
  | { t: "code"; v: string; lang: string }
  | { t: "ul"; items: Inline[][] }
  | { t: "ol"; start: number; items: Inline[][] }
  | { t: "quote"; c: Block[] }
  | { t: "hr" };

const MAX_DEPTH = 4;

/** Only these link targets survive; anything else becomes plain text. */
export function safeHref(href: string): string | null {
  const h = href.trim();
  if (/^https?:\/\/[^\s"'<>]+$/i.test(h) || /^mailto:[^\s"'<>:]+@[^\s"'<>]+$/i.test(h)) return h;
  return null;
}

export function parseMarkdown(src: string, depth = 0): Block[] {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const out: Block[] = [];
  let i = 0;
  const isBlank = (l: string) => l.trim() === "";
  const listRe = /^\s{0,3}([-*+]|\d{1,9}[.)])\s+(.*)$/;
  const startsBlock = (l: string) =>
    /^\s{0,3}(#{1,6}\s|```|~~~|>)/.test(l) || listRe.test(l) || /^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(l);

  while (i < lines.length) {
    const line = lines[i];
    if (isBlank(line)) {
      i++;
      continue;
    }
    const fence = line.match(/^\s{0,3}(```|~~~)\s*([\w+-]*)/);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      out.push({ t: "code", v: body.join("\n"), lang: fence[2] || "" });
      continue;
    }
    const h = line.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (h) {
      out.push({ t: "h", level: h[1].length as 1, c: parseInline(h[2]) });
      i++;
      continue;
    }
    if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) {
      out.push({ t: "hr" });
      i++;
      continue;
    }
    if (/^\s{0,3}>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s{0,3}>/.test(lines[i])) body.push(lines[i++].replace(/^\s{0,3}>\s?/, ""));
      out.push(depth < MAX_DEPTH ? { t: "quote", c: parseMarkdown(body.join("\n"), depth + 1) } : { t: "p", c: parseInline(body.join(" ")) });
      continue;
    }
    const li = line.match(listRe);
    if (li) {
      const ordered = /\d/.test(li[1]);
      const items: Inline[][] = [];
      let cur: string[] = [];
      const start = ordered ? parseInt(li[1], 10) : 1;
      while (i < lines.length) {
        const m = lines[i].match(listRe);
        if (m && /\d/.test(m[1]) === ordered) {
          if (cur.length) items.push(parseInline(cur.join(" ")));
          cur = [m[2]];
          i++;
        } else if (!isBlank(lines[i]) && /^\s+/.test(lines[i]) && cur.length) {
          cur.push(lines[i++].trim());
        } else if (isBlank(lines[i]) && i + 1 < lines.length && lines[i + 1].match(listRe)) {
          i++;
        } else break;
      }
      if (cur.length) items.push(parseInline(cur.join(" ")));
      out.push(ordered ? { t: "ol", start, items } : { t: "ul", items });
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && !isBlank(lines[i]) && (para.length === 0 || !startsBlock(lines[i]))) para.push(lines[i++].trim());
    out.push({ t: "p", c: parseInline(para.join(" ")) });
  }
  return out;
}

export function parseInline(src: string, depth = 0): Inline[] {
  const out: Inline[] = [];
  let text = "";
  const flush = () => {
    if (text) out.push({ t: "text", v: text });
    text = "";
  };
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "\\" && i + 1 < src.length && /[\\`*_[\]()#+\-.!<>]/.test(src[i + 1])) {
      text += src[i + 1];
      i += 2;
      continue;
    }
    if (ch === "`") {
      const end = src.indexOf("`", i + 1);
      if (end > i) {
        flush();
        out.push({ t: "code", v: src.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }
    if (ch === "<") {
      const m = src.slice(i).match(/^<((?:https?:\/\/|mailto:)[^\s<>]+)>/i);
      if (m) {
        flush();
        const href = safeHref(m[1]);
        out.push(href ? { t: "link", href, c: [{ t: "text", v: m[1] }] } : { t: "text", v: m[0] });
        i += m[0].length;
        continue;
      }
    }
    // [text](url) and ![alt](url): images become links.
    if (ch === "[" || (ch === "!" && src[i + 1] === "[")) {
      const img = ch === "!";
      const open = img ? i + 1 : i;
      const close = matching(src, open, "[", "]");
      if (close > 0 && src[close + 1] === "(") {
        const end = matching(src, close + 1, "(", ")");
        if (end > 0) {
          const label = src.slice(open + 1, close);
          const target = src.slice(close + 2, end).trim().split(/\s+/)[0] ?? "";
          const href = safeHref(target.replace(/^<|>$/g, ""));
          flush();
          const kids: Inline[] = depth < MAX_DEPTH ? parseInline(label || target, depth + 1) : [{ t: "text", v: label }];
          if (href) out.push({ t: "link", href, c: img && !label ? [{ t: "text", v: href }] : kids });
          else out.push(...kids);
          i = end + 1;
          continue;
        }
      }
    }
    if (ch === "*" || ch === "_") {
      const dbl = src[i + 1] === ch;
      const mark = dbl ? ch + ch : ch;
      const end = src.indexOf(mark, i + mark.length);
      const inner = end > 0 ? src.slice(i + mark.length, end) : "";
      // _ only counts at word boundaries, so snake_case stays as it is.
      const boundary = ch === "*" || ((i === 0 || /\W/.test(src[i - 1])) && (end + mark.length >= src.length || /\W/.test(src[end + mark.length])));
      if (end > 0 && inner.trim() === inner && inner && boundary && depth < MAX_DEPTH) {
        flush();
        const c = parseInline(inner, depth + 1);
        out.push(dbl ? { t: "strong", c } : { t: "em", c });
        i = end + mark.length;
        continue;
      }
    }
    text += ch;
    i++;
  }
  flush();
  return out;
}

function matching(s: string, at: number, open: string, close: string): number {
  let n = 0;
  // Link labels and targets are short; a bounded scan keeps "[[[[…" linear.
  for (let j = at; j < s.length && j < at + 2000; j++) {
    if (s[j] === "\\") {
      j++;
      continue;
    }
    if (s[j] === open) n++;
    else if (s[j] === close && --n === 0) return j;
  }
  return -1;
}

/** Plain text of inlines (for alt text, titles, excerpts). */
export function inlineText(c: Inline[]): string {
  return c.map((x) => (x.t === "text" || x.t === "code" ? x.v : inlineText(x.c))).join("");
}
