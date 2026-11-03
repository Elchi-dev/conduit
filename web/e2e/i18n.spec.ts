import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

test.beforeEach(async ({ page }) => signIn(page));

test("switching to Deutsch translates the app, and back", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
  await page.getByRole("radiogroup", { name: "Language" }).getByRole("radio", { name: "Deutsch" }).click();

  // The app reloads in German.
  await expect(page.getByRole("heading", { level: 1, name: "Einstellungen" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await expect(page.getByRole("banner").getByRole("button", { name: "Notstopp" })).toBeVisible();
  await expect(page.getByRole("radiogroup", { name: "Sprache" }).getByRole("radio", { name: "Deutsch" })).toHaveAttribute("aria-checked", "true");

  await page.goto("/approvals");
  await expect(page.getByRole("heading", { level: 1, name: "Freigaben" })).toBeVisible();

  await page.goto("/settings");
  await page.getByRole("radiogroup", { name: "Sprache" }).getByRole("radio", { name: "English" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
});

test.describe("with a German browser", () => {
  test.use({ locale: "de-DE" });
  test("the app starts in German", async ({ page }) => {
    await page.goto("/timeline");
    await expect(page.getByRole("heading", { level: 1, name: "Verlauf" })).toBeVisible();
  });
});
