import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

// Runs last in each project: the emergency stop ends every other session
// and locks the vault.
test("emergency stop on, then lifted by the person", async ({ page }) => {
  await signIn(page);
  await page.goto("/");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("banner").getByRole("button", { name: "Emergency stop" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Emergency stop is on" })).toBeVisible();
  await page.goto("/policy");
  await page.getByRole("button", { name: "Lift emergency stop" }).click();
  await expect(page.getByRole("heading", { name: "Emergency stop is on" })).toHaveCount(0);
  await expect(page.getByRole("banner").getByRole("button", { name: "Emergency stop" })).toBeVisible();
});
