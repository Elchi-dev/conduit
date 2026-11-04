# Conduit for teams

You'll add your colleagues with single sign-on, give them roles, set rules
for the agents everyone uses, run on-call from the same place, and keep a
tamper-evident record of who changed what.

## 1. People and sign-in

1. **People → Add a person** with a role: *admin* (everything except other
   admins), *member* (runs actions, decides approvals) or *viewer*.
2. Or connect your identity provider: **Settings → Single sign-on** with
   Google Workspace, Microsoft Entra, Okta, Keycloak or Authentik
   ([sso.md](../api/sso.md)). New colleagues from your domain get an account
   as members on first sign-in. Owners and admins link their account
   themselves.
3. Two-factor sign-in with an authenticator app, and passkeys, are under
   **Settings**. Passkeys need the daemon opened at a host name (such as
   `localhost` or your reverse proxy's name), not an IP address.

## 2. Rules for agents

**Agent rules** decide what each agent and API key may do: per module,
action and risk, with an expiry if you like ("full autonomy on staging for
an hour"). Approvals go to everyone who can decide them; the first decision
counts. Only people can approve, change rules or lift an emergency stop:
no key, however powerful, can.

## 3. On-call in one place

Connect **PagerDuty**, **Sentry**, **Slack** and **Jira** or **Linear**. An
automation can open a Jira issue and post to Slack when Sentry sees a new
error; an agent can draft the fix, and a person approves it.

## 4. The record

**Timeline** is the audit log: every action, by whom (person, agent, key or
automation), what changed and how to undo it, in a hash chain that shows
if anyone edited history. **What changed?** shows everything around a
moment, across all systems, which is where incident reviews start.

## 5. Your own hub

Run a hub for the team ([self-hosting](../self-hosting/README.md)):
organisations, devices, the encrypted relay for phones, a module registry
for your internal modules, and passkey sign-in.
