import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

// Automated accessibility checks (WCAG 2.1 A and AA rules that axe can
// test) on the main screens, in both color schemes. Serious and critical
// problems fail the run.
const pages = [
  ["Overview", "/"],
  ["Modules", "/modules"],
  ["This computer", "/i/system"],
  ["Approvals", "/approvals"],
  ["Timeline", "/timeline"],
  ["Settings", "/settings"],
  ["Standards", "/i/standards"],
  ["Networks", "/networks"],
  ["Marketplace", "/modules/registry"],
] as const;

for (const scheme of ["dark", "light"] as const) {
  test.describe(`${scheme} scheme`, () => {
    // Reduced motion: a scan mid-animation measures colors that are never at rest.
    test.use({ colorScheme: scheme, reducedMotion: "reduce" });
    test.beforeEach(async ({ page }) => signIn(page));
    for (const [name, path] of pages) {
      test(`${name} has no serious accessibility problems`, async ({ page }) => {
        await page.goto(path);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await page.waitForLoadState("networkidle");
        const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
        const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
        const report = bad
          .map((v) => {
            const nodes = v.nodes.slice(0, 6).map((n) => `${n.target.join(" ")}: ${(n.any[0]?.message ?? n.failureSummary ?? "").split("\n")[0]}`);
            return `${v.id} (${v.impact}, ${v.nodes.length} elements): ${v.help}\n    ${nodes.join("\n    ")}`;
          })
          .join("\n");
        expect(bad.length, `\n${report}\n`).toBe(0);
      });
    }
  });
}
