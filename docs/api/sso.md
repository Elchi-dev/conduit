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
   that may sign in. Turn on "Make an account…" if new colleagues should get
   an account (as members or viewers) the first time they sign in.
5. Tick "Show Sign in with…" and save. Sign out and try it.

People who already have an account here are matched by email address. Give
them their roles (owner, admin) as usual; single sign-on never makes owners
or admins.

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
| Didn't work (other) | Wrong issuer, client ID or secret, the redirect URI isn't registered exactly, or the vault is locked. |
