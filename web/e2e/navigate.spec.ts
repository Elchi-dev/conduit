import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

test.beforeEach(async ({ page }) => signIn(page));

test("command bar opens and finds a page", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await page.keyboard.press("Control+k");
  const dialog = page.getByRole("dialog", { name: "Search and run" });
  await expect(dialog.getByRole("combobox", { name: "Search and run" })).toBeVisible();
  await dialog.getByRole("combobox").fill("agent rules");
  await dialog.getByRole("option", { name: "Agent rules" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Agent rules" })).toBeVisible();
});

test("modules are listed, and This computer shows its overview", async ({ page }) => {
  await page.goto("/modules");
  await expect(page.getByRole("heading", { level: 1, name: "Modules" })).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search modules" })).toBeVisible();
  await page.getByRole("searchbox", { name: "Search modules" }).fill("docker");
  await expect(page.getByText("Docker", { exact: true })).toBeVisible();

  await page.goto("/i/system");
  await expect(page.getByRole("heading", { level: 1, name: "This computer" })).toBeVisible();
  // The overview runs by itself: CPUs and hostname come from this machine.
  await expect(page.getByRole("term").filter({ hasText: "CPUs" })).toBeVisible();
  await expect(page.getByRole("term").filter({ hasText: "Hostname" })).toBeVisible();
});

test("a preset starts with a short list and shows the rest on request", async ({ page }) => {
  await page.goto("/modules?preset=developer");
  await expect(page.getByRole("heading", { level: 2, name: "Start here: Developer" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect GitHub" })).toBeVisible();
  await page.getByRole("button", { name: /^Show all \d+ for Developer$/ }).click();
  await expect(page.getByRole("heading", { level: 2, name: /^Development \d+$/ })).toBeVisible();
  // A category chip narrows the list; search finds by category too.
  await page.getByRole("button", { name: /^Monitoring \d+$/ }).click();
  await expect(page.getByRole("button", { name: "Connect GitHub" })).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Search modules" }).fill("zzzz");
  await expect(page.getByRole("heading", { level: 2, name: "No modules match" })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByRole("button", { name: "Connect GitHub" }).first()).toBeVisible();
});

test("settings show remote access, sync and webhooks", async ({ page }) => {
  await page.goto("/settings");
  for (const name of ["Remote access", "Sync", "Webhooks", "Appearance", "Password"]) {
    await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
  }
});

test("sign out, then sign back in", async ({ page }) => {
  await page.goto("/settings");
  await page.getByRole("button", { name: "Sign out", exact: true }).last().click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill("ada@example.com");
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText(/wrong|invalid|incorrect/i)).toBeVisible();
  await page.getByLabel("Password").fill("correct horse battery");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("banner").getByRole("button", { name: "Emergency stop" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in" })).toHaveCount(0);
});
