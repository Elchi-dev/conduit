// The docs pages are the repository's docs/ folder, rendered as-is, so the
// website and the repo never disagree.
import path from "node:path";

type MdModule = { compiledContent: () => string | Promise<string>; rawContent: () => string };

const files = import.meta.glob<MdModule>("../../../docs/**/*.md", { eager: true });

export type Doc = { slug: string; file: string; title: string; section: string; html: () => Promise<string> };

const REPO = "https://github.com/Elchi-dev/conduit/blob/main/";

export const sections: [string, string][] = [
  ["architecture", "Architecture"],
  ["protocol", "Protocol"],
  ["api", "Developer API"],
  ["modules", "Modules"],
  ["self-hosting", "Self-hosting"],
];

function rel(key: string): string {
  // "../../../docs/api/keys.md" -> "api/keys.md"
  return key.slice(key.indexOf("/docs/") + "/docs/".length);
}

export function slugOf(file: string): string {
  const noExt = file.replace(/\.md$/, "");
  return noExt.endsWith("README") ? noExt.slice(0, -"README".length).replace(/\/$/, "") : noExt;
}

function titleOf(raw: string, file: string): string {
  const m = raw.match(/^#\s+(.+)$/m);
  return m ? m[1].trim() : path.basename(file, ".md");
}

/** Rewrite links between docs to site URLs, and repo files to GitHub. */
function rewrite(html: string, file: string): string {
  const dir = path.posix.dirname("docs/" + file);
  return html.replace(/href="([^"#:]+?)(#[^"]*)?"/g, (whole, target: string, hash = "") => {
    if (target.startsWith("/") || target.startsWith("http")) return whole;
    const abs = path.posix.normalize(path.posix.join(dir, target));
    if (abs.startsWith("docs/") && (abs.endsWith(".md") || !path.posix.extname(abs))) {
      const s = slugOf(abs.slice(5).replace(/\/$/, "") + (abs.endsWith(".md") ? "" : "/README.md"));
      return `href="/docs/${s ? s + "/" : ""}${hash}"`;
    }
    return `href="${REPO}${abs}${hash}"`;
  });
}

export const docs: Doc[] = Object.entries(files).map(([key, mod]) => {
  const file = rel(key);
  return {
    slug: slugOf(file),
    file,
    title: titleOf(mod.rawContent(), file),
    section: file.split("/")[0],
    html: async () => rewrite(await mod.compiledContent(), file),
  };
});

export function inSection(section: string): Doc[] {
  return docs
    .filter((d) => d.section === section)
    .sort((a, b) => (a.slug === section ? -1 : b.slug === section ? 1 : a.title.localeCompare(b.title)));
}
