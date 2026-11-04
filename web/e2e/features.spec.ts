import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

test.beforeEach(async ({ page }) => signIn(page));

test("standards: the starter library is there and a standard opens", async ({ page }) => {
  await page.goto("/i/standards");
  await expect(page.getByRole("heading", { level: 1, name: "Standards" })).toBeVisible();
  await expect(page.getByText("Accessibility (WCAG 2.2 AA essentials)").first()).toBeVisible();
  await expect(page.getByText("Frontend design principles").first()).toBeVisible();
  await page.getByRole("button", { name: "New standard" }).click();
  await expect(page.getByRole("button", { name: "What the AI sees" }).or(page.getByLabel("What the AI sees")).first()).toBeVisible();
});

test("networks: the page offers to add a WireGuard network", async ({ page }) => {
  await page.goto("/networks");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: /add|paste/i }).first()).toBeVisible();
});

test("game library: a games instance shows the library page", async ({ page }) => {
  // Create it the way the app does, from the page (same-origin fetch).
  await page.goto("/");
  const id = await page.evaluate(async () => {
    const r = await fetch("/api/v1/instances", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ module: "games", name: "My games" }) });
    if (r.status !== 201) throw new Error(`${r.status} ${await r.text()}`);
    return (await r.json()).id as string;
  });
  await page.goto(`/i/${id}`);
  await expect(page.getByRole("heading", { level: 1, name: "My games" })).toBeVisible();
  // CI machines have no launchers: the library explains and offers to add a game.
  await expect(page.getByRole("heading", { level: 2, name: "No games found on this computer yet" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add a game" })).toBeVisible();
});
