# Decisions

<p align="center"><img src="images/ori/thinking.svg" width="120" alt="Ori thinking"></p>

Newest first. Each one says what was decided and why, and what was given up.
The longer records are the ADRs in [architecture/adr](architecture/adr/README.md);
the day-by-day story is the [build log](BUILD_LOG.md).

## Raising risk inside version 1 (2026-11-04)

The final risk sweep read all 1,741 non-destructive actions and raised 27 in
11 modules to destructive because of what they do, not what they're called:
OBS going live, PagerDuty and Sentry silencing, AdGuard and Pi-hole
blocking, Tailscale access, Kubernetes scaling, GitHub access and
protection, S3 presigned links. The stability policy allows raising risk
within version 1, and the 1.1 notes list every change. No action was
renamed or removed. Given up: a few actions that ran without asking now
wait for approval.

## Some sends stay at write (2026-11-04)

The same sweep left sending mail and chat messages, and turning automations
back on (n8n, Node-RED), at write, and made InfluxDB `enable_task`
destructive. These were reviewed and kept as documented decisions; a rule
can still require approval for any of them. Given up: an approval on every
send by default.

## Mail servers never delete (2026-11-04)

Incus keeps `delete_snapshot` (snapshots only) as the undo of a new
snapshot, like Proxmox. Stalwart is supported from 0.16, through its JMAP
management API; the older REST API isn't. mailcow can flush its queue, which
only retries. Nothing on any mail server can be deleted through Conduit.
Given up: Stalwart before 0.16, and cleanup from Conduit.

## Money and send actions run what was approved (2026-11-04)

Destructive money and send actions take the values their preview showed
(the expected total, what was refunded, the status, a balance or a sha256 of
a newsletter) and refuse if the target changed. Applied to WooCommerce,
BigCommerce, Printful, Shopify, Stripe, Lemon Squeezy, Paddle, Invoice
Ninja, listmonk and the newsletters. It also stops a retried refund from
paying out twice. Given up: the inputs of these 1.0 actions changed. The
stability policy allows that for a security fix, and the 1.1 notes explain
it; agents pick the values up from the preview on their own.

## Spending by the hour is destructive (2026-11-04)

Starting a GPU rental is destructive, since it spends by the hour; starting
a cloud server stays write. rclone calls only a fixed list of rc methods and
never reads its config. Share links are named by a hash of their secret
part, so undo tokens never hold a link. Given up: one rule for every kind of
"start".

## A Discord bot, not a Discord account (2026-11-04)

The owner asked for a Discord user-account module. Discord's terms ban
automating a user account, and Discord bans accounts for it. The bot module
gained reading, replies, reactions, threads, pins and moderation instead.
When the owner pushed back, an opt-in account module was started and then
dropped: it would have had to impersonate Discord's own client. Given up:
acting as your own Discord account.

## Office sends and switches wait for approval (2026-11-04)

Emby is served by the Jellyfin module, so Bazarr took its place in the
batch. Starting a cloud server is write (like AWS and Hetzner); stop,
reboot and traffic changes are destructive. In the office and feature-flag
modules, sending mail, invitations, Teams posts, shared links and flag
toggles are destructive, since they reach people or change production at
once.

## Stopping alerts is destructive (2026-11-04)

NetBird `disable_peer` requires approval, since NetBird has no disable
call. Nginx Proxy Manager and Prometheus were already
covered (`npm`, `metrics`), so Gatus took Prometheus's place. Pausing
downloads, acknowledging Zabbix and Checkmk problems, silences and
downtimes are destructive, because they stop work or alerts.

## A risk check over every action (2026-11-04)

`internal/daemon/risk_lint_test.go` fails the build when an action named
like deploy, stop, restart, delete, revoke, refund, apply, merge, approve or
shutdown isn't destructive, with a short allow-list of documented
exceptions. It raised a dozen older actions. By the same rule, shipping
code, re-running pipelines, network access and filtering changes, and
running an automation are destructive. Given up: a little friction on
actions that are usually harmless.

## Daemon passkeys only under a host name (2026-11-04)

Passkeys on the daemon are usernameless and require user verification, so
they count as both factors. WebAuthn refuses IP addresses, so they work only
when the daemon is reached by a host name. Given up, for now: passkeys in
the desktop app, which talks to `127.0.0.1`, and through the relay.

## Work without asking (2026-11-04)

The owner, at 02:33: "work 100% on your own". Every choice during the build
is the most reasonable one, recorded in the build log, and stopped work is
restarted. Given up: asking the owner before a choice.

## MIT for everything (2026-11-04)

The owner's decision on 4 November: the whole repository is MIT, from
0.3.1 on.

## Signed releases, and an F-Droid step that may fail (2026-11-04)

From 0.3.1, checksums, desktop updates and the Android APK are signed with
the owner's keys. The F-Droid step needs a repository address ending in
`/repo`, which release downloads can't give, so it no longer fails a
release. Every release is tested by upgrading from every earlier one. Given
up: a release that is red when F-Droid publishing fails.

## Backups keep the two-factor and relay keys (2026-11-04)

A backup contains the two-factor and relay keys; the backup passphrase
protects them. This was documented rather than changed, so a restore brings
back a working daemon. Given up: backups that hold no keys at all.

## Single sign-on follows the provider's subject (2026-11-03)

Accounts follow the provider's stable `sub`, never the email alone. Owners
and admins are never linked by email; they link their identity themselves
while signed in. At least one allowed domain is required, and
`email_verified` must be the JSON value `true`. Sync tombstones are kept for
good, and the peer endpoint refuses documents sealed more than 15 minutes
ago. Given up: signing in existing owners by matching their address.

## The release workflow creates its tag (2026-11-03)

The build environment can't push tags, so the release workflow's manual
trigger creates the tag on the commit it runs on. Pushing a `v*` tag still
works too.

## The review comes first (2026-11-03)

The first security review found more than expected, so client SDK polish
was kept to the generated types; the external-module kits and API clients
are complete but minimal. Given up: richer SDKs in 0.1.

## Phone alerts without Firebase (2026-11-03)

Firebase push would tie every hub operator to a Google project. Background
alerts go through the notify module's ntfy channel, which has its own phone
app; the app notifies while open. Cleartext HTTP is allowed in the APK so
self-hosted hubs on a LAN work; relay content is end to end encrypted
regardless. The Android build targets arm64 and x86_64, which covers current
phones and keeps CI time sane. Given up: Google push, and 32-bit phones.

## Hub-free pairing and a real sandbox (2026-11-03)

Hub-free pairing and the WebAssembly sandbox were planned as scaffolds;
both were built in full. Pairing codes carry the daemon's address, so mDNS
discovery and peer-to-peer sync could wait for later releases.

## The daemon serves the desktop window (2026-11-03)

The desktop window loads the daemon's web app instead of a bundled copy;
the bundled page is a small splash. The app and the daemon can't drift
apart. The daemon retries its listen address for ten seconds, so a
restarted process can take over from the one it replaces.

## The pairing secret travels sealed (2026-11-03)

The pairing secret no longer travels in the plaintext hello: the client
seals it, with its device name, into a proof frame. A malicious hub can't
read the secret and enroll its own key, and the daemon admits a key only
after the client proves it holds it. Go and TypeScript share pinned test
vectors (`pkg/relay/testdata`), checked in CI, so the two can't drift.

## Grafana panels open in Grafana (2026-11-03)

Embedding panels needs server-side Grafana settings, so panels open in
Grafana instead. Given up: Grafana charts inside Conduit.

## App passwords for mail first (2026-11-03)

OAuth sign-in for Gmail and Outlook was left out of 0.1; app passwords
work, as planned. Google Calendar is read through its private ICS address.
OAuth arrived later with the Microsoft 365 and Google Workspace modules.

## No Docker SDK (2026-11-03)

The Docker module speaks the Engine API directly over the chosen transport
(local socket, Windows pipe, SSH tunnel or TCP). Given up: the official
client library.

## Leaked-key rotation starts small (2026-11-03)

Automatic rotation of leaked credentials stayed a documented scaffold in
0.1; `vault.rotate` later arrived with a Cloudflare token provider and a
provider interface.

## A small routing and styling layer (2026-11-03)

`wouter` and plain CSS files with design tokens as custom properties,
instead of TanStack Router and vanilla-extract. The app has about ten
routes and no nested data loading; tokens switch themes at runtime and are
shared with the website. TypeScript 7 lacks the compiler API the type
generator needs, so `pnpm gen:api` runs it with TypeScript 5. Given up:
typed routes and compile-checked class names.
[ADR 0004](architecture/adr/0004-frontend-libraries.md).

## Hand-written handlers and server-sent events (2026-11-03)

`api/openapi/*.yaml` stays the source of truth and the TypeScript client is
generated from it, but Go handlers are written by hand; `TestRoutesMatchOpenAPI`
fails if a served route is undocumented or a documented one isn't served.
Live events use server-sent events: no dependency, they work through proxies
and the relay, and browsers reconnect on their own. Given up: compile-time
checks of Go request shapes (API tests cover them) and a two-way socket.
[ADR 0003](architecture/adr/0003-api-contract-and-sse.md).

## The standard library router (2026-11-03)

Since Go 1.22, `net/http.ServeMux` matches methods and path parameters, so
it replaces chi with small middleware functions. One dependency fewer; chi
stays a drop-in if routing outgrows it.
[ADR 0002](architecture/adr/0002-stdlib-http-router.md).

## Go for the daemon, Tauri as a thin shell (2026-11-03)

The daemon, the hub and every API are Go; the desktop and Android apps are
Tauri 2 with no product logic in Rust; the UI is TypeScript and React,
served by the daemon. One language for all server logic, and static
binaries for every OS with `CGO_ENABLED=0`. Given up: any dependency that
isn't pure Go, and logic in the shell.
[ADR 0001](architecture/adr/0001-go-backend-tauri-shell.md).
