import { expect, test } from "@playwright/test";
import { owner, suffix } from "./helpers";

// Passkeys with Chrome's virtual authenticator. WebAuthn refuses IP
// addresses, so this test opens the daemon at localhost (the daemon's host
// check allows it); at 127.0.0.1 passkeys aren't offered at all.
test("add a passkey in Settings and sign in with it at localhost", async ({ page }, info) => {
  const ip = process.env.CONDUIT_E2E_URL!;
  const local = ip.replace("127.0.0.1", "localhost");
  const name = `Virtual key ${suffix(info.project.name)}`;

  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  // At the IP address the sign-in page doesn't offer passkeys.
  await page.goto(ip + "/");
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toHaveCount(0);

  // Sign in with the password at localhost, then add a passkey.
  const r = await page.request.post(local + "/api/v1/auth/login", { data: { email: owner.email, password: owner.password, device: "e2e" } });
  expect(r.ok(), await r.text()).toBeTruthy();
  await page.goto(local + "/settings");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await page.getByLabel("Your password").fill(owner.password);
  await page.getByLabel("Passkey name").fill(name);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByText(name)).toBeVisible();
  await expect(page.getByText(/not used yet/).first()).toBeVisible();

  // Sign out, then back in with the passkey alone.
  await page.context().clearCookies();
  await page.goto(local + "/");
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/^(Good|Working)/);

  // Clean up: remove it again.
  const list = await (await page.request.get(local + "/api/v1/me/passkeys")).json();
  for (const k of list.filter((k: { name: string }) => k.name === name)) {
    expect((await page.request.delete(local + "/api/v1/me/passkeys/" + k.id)).status()).toBe(204);
  }
});
