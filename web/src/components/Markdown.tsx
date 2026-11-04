import type { ReactNode } from "react";
import { parseMarkdown, type Block, type Inline } from "../lib/markdown";

/**
 * Renders untrusted Markdown (a module's readme from a hub) as React
 * elements only: no HTML strings, so tags in the text stay text. Headings
 * are shifted down so a readme can't outrank the page's own.
 */
export function Markdown({ source, className }: { source: string; className?: string }) {
  return <div className={className ?? "md"}>{parseMarkdown(source).map(block)}</div>;
}

function inline(x: Inline, i: number): ReactNode {
  switch (x.t) {
    case "text":
      return x.v;
    case "code":
      return <code key={i}>{x.v}</code>;
    case "strong":
      return <strong key={i}>{x.c.map(inline)}</strong>;
    case "em":
      return <em key={i}>{x.c.map(inline)}</em>;
    case "link":
      return (
        <a key={i} href={x.href} target="_blank" rel="noopener noreferrer nofollow">
          {x.c.map(inline)}
        </a>
      );
  }
}

function block(b: Block, i: number): ReactNode {
  switch (b.t) {
    case "h": {
      const level = Math.min(6, b.level + 2);
      const Tag = `h${level}` as "h3";
      return <Tag key={i}>{b.c.map(inline)}</Tag>;
    }
    case "p":
      return <p key={i}>{b.c.map(inline)}</p>;
    case "code":
      return (
        <pre key={i}>
          <code>{b.v}</code>
        </pre>
      );
    case "ul":
      return (
        <ul key={i}>
          {b.items.map((it, j) => (
            <li key={j}>{it.map(inline)}</li>
          ))}
        </ul>
      );
    case "ol":
      return (
        <ol key={i} start={b.start}>
          {b.items.map((it, j) => (
            <li key={j}>{it.map(inline)}</li>
          ))}
        </ol>
      );
    case "quote":
      return <blockquote key={i}>{b.c.map(block)}</blockquote>;
    case "hr":
      return <hr key={i} />;
  }
}
