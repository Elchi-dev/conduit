# Single sign-on

Let people sign in to a daemon with the account they already use at work:
Google Workspace, Microsoft Entra ID, Okta, Keycloak, Authentik, GitLab or
any OpenID Connect provider. How it works and its security rules:
[architecture/daemon.md](../architecture/daemon.md#single-sign-on).

## Before you start

1. Open Settings, Single sign-on, Set up, and copy the **redirect URI**. It is
   `https://<your daemon>/api/v1/auth/oidc/callback`, built from the address
   you're using right now. If people reach the daemon under another name
   (a reverse proxy, say), enter that address under "This daemon's address"
   and add the name to `CONDUIT_ALLOWED_HOSTS`.
2. Register an application with your provider (below), with that redirect
   URI and the scopes `openid email profile`.
3. Store the client secret in the vault (Vault module, Save a secret), for
   example as `sso/client-secret`, and enter `secret://sso/client-secret`.
4. Enter the issuer and client ID, a button label, and the email domains
   that may sign in (at least one is required). Turn on "Make an account…" if new colleagues should get
   an account (as members or viewers) the first time they sign in.
5. Tick "Show Sign in with…" and save. Sign out and try it.

## How accounts are matched

The provider's stable account id (the `sub` claim), not the email address,
decides which account signs in. The first time someone signs in, Conduit
links their identity to an account:

- **Members and viewers** with an address in an allowed domain are linked to
  the account with that address (or a new one, if making accounts is on).
- **Owners and admins** are never linked by email: they sign in with their
  password and choose **Link my account** under Settings, Single sign-on.
  This way nobody who can set an address at the provider (a provider admin,
  or a provider that lets people edit their own email) can sign in as an
  owner or admin.

Once linked, the identity keeps signing in to the same account even if its
email changes at the provider, and no other identity at the same provider
can sign in to that account. `email_verified` must be the JSON value `true`.
Single sign-on never makes owners or admins.

## Google Workspace

- Google Cloud console, APIs and services, Credentials, Create credentials,
  OAuth client ID, type **Web application**.
- Authorized redirect URIs: the redirect URI from step 1.
- On the OAuth consent screen choose **Internal** so only your Workspace can
  use it.
- Issuer: `https://accounts.google.com`.
- Allowed domains: your Workspace domain. Google puts the address in `email`
  with `email_verified`.

## Microsoft Entra ID

- Entra admin center, App registrations, New registration. Supported
  accounts: this organizational directory only.
- Redirect URI: platform **Web**, the redirect URI from step 1.
- Certificates and secrets: New client secret; store the **value** in the
  vault.
- API permissions: Microsoft Graph `openid`, `email`, `profile` (delegated).
- Issuer: `https://login.microsoftonline.com/<tenant id>/v2.0`.
- Entra only sends `email` when the user has one set, and doesn't always
  send `email_verified`; add the optional claim `email_verified` (Token
  configuration, Add optional claim, ID token) or sign-ins are refused as
  unverified.

## Okta

- Admin console, Applications, Create App Integration, **OIDC**, **Web
  Application**.
- Sign-in redirect URIs: the redirect URI from step 1. Grant type:
  Authorization Code.
- Assign the people or groups who may use it.
- Issuer: `https://<your org>.okta.com` (or your custom authorization
  server's issuer, such as `https://<your org>.okta.com/oauth2/default`).

## Keycloak

- Your realm, Clients, Create client, type **OpenID Connect**, Client
  authentication **on**, Standard flow **on**.
- Valid redirect URIs: the redirect URI from step 1.
- Credentials tab: the client secret.
- Issuer: `https://<keycloak>/realms/<realm>`.
- Make sure users' emails are marked verified (Users, Email verified).

## Authentik

- Applications, Providers, Create, **OAuth2/OpenID Provider**, client type
  Confidential.
- Redirect URIs: the redirect URI from step 1. Scopes: `openid`, `email`,
  `profile`.
- Create an Application that uses the provider.
- Issuer: `https://<authentik>/application/o/<application slug>/`.

## GitLab

- Admin area (or a group), Applications, New application, scopes `openid
  email profile`, confidential, redirect URI from step 1.
- Issuer: `https://gitlab.com` or your GitLab's address.

## When it doesn't work

The sign-in page shows a short reason; the daemon's log says more (search for
"single sign-on refused"). Common causes:

| Shown | Cause |
| --- | --- |
| Expired or started in another browser | Took longer than 10 minutes, or the browser blocked the sign-in cookie. Try again in one tab. |
| Email not confirmed | The provider didn't send `email_verified: true` (see Entra above). |
| Not in an accepted domain | Add the domain under Allowed email domains. |
| No account yet | Turn on making accounts, or add the person first. |
| Owners and admins sign in with their password first | Sign in with your password and choose Link my account in Settings. |
| Linked to a different identity | The account is linked to another identity at the provider; use that one, or have it unlinked. |
| Didn't work (other) | Wrong issuer, client ID or secret, the redirect URI isn't registered exactly, or the vault is locked. |
