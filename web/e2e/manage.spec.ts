import { expect, test } from "@playwright/test";
import { ensureVault, signIn, suffix } from "./helpers";

test.beforeEach(async ({ page }) => signIn(page));

test("save a secret through the vault module", async ({ page }, info) => {
  await ensureVault(page);
  const name = `e2e/token-${suffix(info.project.name)}`;
  await page.goto("/i/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Vault" })).toBeVisible();
  await page.getByRole("navigation", { name: "Actions" }).getByRole("button", { name: "Save a secret" }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Save a secret" })).toBeVisible();
  await page.getByLabel(/^Name/).first().fill(name);
  await page.getByLabel(/^Value/).first().fill("s3cret-value-from-e2e");
  await page.getByRole("button", { name: "Save a secret", exact: true }).last().click();
  await expect(page.getByText(`secret://${name}`).first()).toBeVisible();
  // It's listed, and its value isn't shown.
  await page.getByRole("navigation", { name: "Actions" }).getByRole("button", { name: "Secrets" }).click();
  await expect(page.getByText(name).first()).toBeVisible();
  await expect(page.getByText("s3cret-value-from-e2e")).toHaveCount(0);
});

test("an API key's secret is shown once", async ({ page }, info) => {
  await page.goto("/keys");
  await page.getByRole("button", { name: "Create key" }).first().click();
  await page.getByRole("textbox", { name: "Name" }).fill(`e2e script ${suffix(info.project.name)}`);
  // The radios are drawn as cards; choose by clicking the card's text.
  await page.getByText("A program", { exact: true }).click();
  await expect(page.getByRole("radio", { name: /A program/ })).toBeChecked();
  await page.getByRole("button", { name: "Create key" }).last().click();
  const shown = page.getByRole("status").filter({ hasText: "Copy your new key now" });
  await expect(shown).toBeVisible();
  await expect(shown.getByText(/^cdt_live_/)).toBeVisible();
  await shown.getByRole("button", { name: "I've saved it" }).click();
  await expect(page.getByText(/^cdt_live_[A-Za-z0-9_]{20,}/)).toHaveCount(0);
  await expect(page.getByText(`e2e script ${suffix(info.project.name)}`)).toBeVisible();
});

test("agent rules: change the default autonomy", async ({ page }) => {
  await page.goto("/policy");
  const group = page.getByRole("radiogroup", { name: "Default autonomy" });
  await group.getByText("Ask before risky changes", { exact: true }).click();
  await expect(group.getByRole("radio", { name: /Ask before risky changes/ })).toBeChecked();
  await page.reload();
  const again = page.getByRole("radiogroup", { name: "Default autonomy" });
  await expect(again.getByRole("radio", { name: /Ask before risky changes/ })).toBeChecked();
  await again.getByText("Ask before changing", { exact: true }).click();
  await expect(again.getByRole("radio", { name: /Ask before changing/ })).toBeChecked();
});

test("people: add a member", async ({ page }, info) => {
  const email = `kim-${suffix(info.project.name)}@example.com`;
  await page.goto("/people");
  await page.getByRole("button", { name: "Add a person" }).click();
  await page.getByLabel("Name").fill("Kim");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("First password").fill("kim's long password");
  // The form's role, not the per-person "Role for …" selects.
  await page.getByRole("combobox", { name: /^Role(?! for)/ }).selectOption("member");
  await page.getByRole("button", { name: "Add person" }).click();
  await expect(page.getByText(email, { exact: false })).toBeVisible();
});
