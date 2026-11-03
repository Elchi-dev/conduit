import { expect, type Page } from "@playwright/test";

export const owner = { name: "Ada Owner", email: "ada@example.com", password: "correct horse battery" };
export const vaultPassphrase = "four random words here";

/** Sign in with a fresh session (cheap, keeps tests independent). */
export async function signIn(page: Page) {
  const r = await page.request.post("/api/v1/auth/login", { data: { email: owner.email, password: owner.password, device: "e2e" } });
  expect(r.ok(), await r.text()).toBeTruthy();
}

/** A per-project suffix, so the desktop and phone runs don't collide. */
export function suffix(project: string) {
  return project === "phone" ? "p" : "d";
}

/** The vault is unlocked (created on first use, unlocked after an emergency stop). */
export async function ensureVault(page: Page) {
  const st = await (await page.request.get("/api/v1/vault")).json();
  if (!st.setUp) {
    expect((await page.request.post("/api/v1/vault/setup", { data: { passphrase: vaultPassphrase } })).ok()).toBeTruthy();
  } else if (!st.unlocked) {
    expect((await page.request.post("/api/v1/vault/unlock", { data: { passphrase: vaultPassphrase } })).ok()).toBeTruthy();
  }
}
