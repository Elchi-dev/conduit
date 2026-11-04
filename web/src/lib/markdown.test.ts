// Checks the readme parser: structure, and that nothing unsafe survives.
// Run: node --experimental-strip-types src/lib/markdown.test.ts
import { parseInline, parseMarkdown, safeHref } from "./markdown.ts";

let failed = false;
function eq(name: string, got: unknown, want: unknown) {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error(`FAIL ${name}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
    failed = true;
  } else console.log(`ok   ${name}`);
}

eq("heading", parseMarkdown("## Hello *you*"), [{ t: "h", level: 2, c: [{ t: "text", v: "Hello " }, { t: "em", c: [{ t: "text", v: "you" }] }] }]);
eq("paragraph joins lines", parseMarkdown("one\ntwo\n\nthree"), [
  { t: "p", c: [{ t: "text", v: "one two" }] },
  { t: "p", c: [{ t: "text", v: "three" }] },
]);
eq("raw HTML is text", parseMarkdown("<script>alert(1)</script>"), [{ t: "p", c: [{ t: "text", v: "<script>alert(1)</script>" }] }]);
eq("javascript: links are dropped", parseInline("[click](javascript:alert(1))"), [{ t: "text", v: "click" }]);
eq("data: links are dropped", safeHref("data:text/html,<b>"), null);
eq("https links are kept", parseInline("[docs](https://example.com/a)"), [{ t: "link", href: "https://example.com/a", c: [{ t: "text", v: "docs" }] }]);
eq("images become links", parseInline("![logo](https://example.com/l.png)"), [{ t: "link", href: "https://example.com/l.png", c: [{ t: "text", v: "logo" }] }]);
eq("code is literal", parseInline("`<b>*x*</b>`"), [{ t: "code", v: "<b>*x*</b>" }]);
eq("snake_case stays", parseInline("a_b_c"), [{ t: "text", v: "a_b_c" }]);
eq("strong", parseInline("**bold**"), [{ t: "strong", c: [{ t: "text", v: "bold" }] }]);
eq("autolink", parseInline("<https://x.example>"), [{ t: "link", href: "https://x.example", c: [{ t: "text", v: "https://x.example" }] }]);
eq("lists", parseMarkdown("- a\n- b\n\n1. one\n2. two"), [
  { t: "ul", items: [[{ t: "text", v: "a" }], [{ t: "text", v: "b" }]] },
  { t: "ol", start: 1, items: [[{ t: "text", v: "one" }], [{ t: "text", v: "two" }]] },
]);
eq("fenced code", parseMarkdown("```sh\nrm -rf <x>\n```"), [{ t: "code", v: "rm -rf <x>", lang: "sh" }]);
eq("quote", parseMarkdown("> hi"), [{ t: "quote", c: [{ t: "p", c: [{ t: "text", v: "hi" }] }] }]);
eq("rule", parseMarkdown("---"), [{ t: "hr" }]);
// Deep nesting stops instead of recursing without end.
parseMarkdown(">".repeat(5000) + " x");
parseInline("*".repeat(5000));
const t0 = Date.now();
parseInline("[".repeat(65536));
parseInline("_a ".repeat(20000));
if (Date.now() - t0 > 2000) eq("pathological input is fast", Date.now() - t0, "< 2000 ms");
console.log("ok   deep nesting");
if (failed) process.exit(1);
