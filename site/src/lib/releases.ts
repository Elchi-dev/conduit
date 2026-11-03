// The changelog is docs/releases/*.md, one file per version.
type MdModule = { compiledContent: () => string | Promise<string>; rawContent: () => string };

const files = import.meta.glob<MdModule>("../../../docs/releases/*.md", { eager: true });

export type Release = { version: string; date?: string; html: () => Promise<string> };

function parts(v: string): number[] {
  return v.replace(/^v/, "").split(/[.-]/).map((x) => Number.parseInt(x, 10) || 0);
}

function newer(a: string, b: string): number {
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (y[i] ?? 0) - (x[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export const releases: Release[] = Object.entries(files)
  .map(([key, mod]) => {
    const version = key.split("/").pop()!.replace(/\.md$/, "");
    const raw = mod.rawContent();
    const date = raw.match(/^Released (\d{4}-\d{2}-\d{2})\.?\s*$/m)?.[1];
    return {
      version,
      date,
      // The page shows its own heading and date, so drop the file's.
      html: async () =>
        (await mod.compiledContent())
          .replace(/<h1[^>]*>[\s\S]*?<\/h1>/, "")
          .replace(/<p>Released \d{4}-\d{2}-\d{2}\.?<\/p>/, "")
          // Each release is a section of the page: its headings move down one level.
          .replace(/<(\/?)h([2-5])/g, (_, slash: string, n: string) => `<${slash}h${Number(n) + 1}`),
    };
  })
  .sort((a, b) => newer(a.version, b.version));
