import { expect, test } from "@playwright/test";
import { owner } from "./helpers";

// The real first run: the setup code from the daemon's data folder, then
// the owner account, then the overview.
test("first run creates the owner and lands on the overview", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Create the owner account" })).toBeVisible();
  await page.getByLabel("Setup code").fill(process.env.CONDUIT_E2E_TOKEN!);
  await page.getByLabel("Your name").fill(owner.name);
  await page.getByLabel("Email").fill(owner.email);
  await page.getByLabel("Password").fill(owner.password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/^(Good|Working)/);
  await expect(page.getByRole("banner")).toBeVisible();
});
