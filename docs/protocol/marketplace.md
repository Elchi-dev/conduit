# The module marketplace

Version 1. Every hub's [registry](hub.md#registry) is also a marketplace:
listings people can browse and search, install counts, ratings and reviews,
reports, and moderation by the hub's operators. This page is the
marketplace's policy and what each party can do. The HTTP surface is in
`api/openapi/hub.yaml` (tag `registry` and the `/admin/…` routes); the code
is `internal/hub/marketplace.go`, `internal/daemon/marketplace_api.go`, the
app's Modules → Add modules from your hub page, and the website's
`/modules/` pages.

## What's signed and what isn't

A version (name, version, permissions, builds and their SHA-256) is signed by
its author, checked by the hub on publish and again by every daemon before it
installs, and pinned to the author's key from the first install on. Nothing
in this page changes that.

The listing (description, readme, categories, tags, links, license, icon,
screenshots), counts, ratings and reviews are not signed. They describe a
package; they never decide what runs. Daemons show them and never trust them:
a hub that lies in a listing can mislead, but it can't change what installs.

## Listings

Authors edit a listing with `PUT /registry/packages/{name}/listing` (scope
`registry:publish`), at any time and without publishing a version.

| Field | Rules |
| --- | --- |
| `description` | Plain text, at most 300 characters. Also set from a version's signed description when that isn't empty. |
| `readme` | Markdown, at most 64 KiB. Rendered **without raw HTML**: tags show as text, links work only for `https:`, `http:` and `mailto:`, and images show as links (loading them would tell their server who reads the page). |
| `categories` | At most 3 from the fixed list (`GET /registry/categories`): home, servers, dev, monitoring, communication, media, games, productivity, finance, security, ai, data, other. |
| `tags` | At most 8, lowercase letters, digits and dashes, up to 24 characters each. |
| `homepage`, `source` | `https://` URLs. |
| `license` | An SPDX identifier or expression, like `MIT` or `Apache-2.0 OR MIT`. |
| icon | `PUT …/icon`: **PNG or WebP only**, at most 128 KiB. |
| screenshots | `POST …/screenshots`: PNG or WebP, at most 1 MiB each, at most 6, with an optional caption. |

SVG and every other image format are refused: SVG can carry scripts. The hub
sniffs the bytes (not the name or a declared type) on upload and again when
serving `GET /registry/media/{id}`, which answers with
`Content-Security-Policy: default-src 'none'; sandbox` and `nosniff`. Daemons
pass images to the app through their own `/api/v1/registry/media/{id}`, which
checks the type a third time, so the app never loads anything from a hub
directly. Images no longer on a listing are deleted.

## Search

`GET /registry/packages` searches listed packages (never delisted ones) by
name, tags and description, filters by `category`, and sorts by:

- `relevance` (default): an exact or module-name match, then a name match,
  then a tag match, then a description match; ties go to more installs;
- `installs`: daemons that have it now;
- `rating`: a weighted average, as if every package also had two 3-star
  ratings, so one 5-star rating doesn't beat fifty 4.8s;
- `newest` (first published) and `updated` (latest version).

`limit` and `offset` page through results; the total is in `X-Total-Count`.
Packages whose author an operator verified carry `verified: true`, shown as a
badge.

## Install counts

Daemons send an anonymous ping to `POST /registry/installs` when they install
or remove a package, and a heartbeat at most weekly while it stays
installed. The ping carries the package, the version, the event and an
opaque `daemon` id: an HMAC of the package name under a random secret the
daemon keeps, so the hub can count one daemon once without being able to tell
which packages one daemon has. The hub hashes it again before storing it.

- `downloads` counts installs, once per daemon per package per day.
- `installs` counts daemons that sent an install or heartbeat in the last 45
  days and no uninstall since.
- Pings are rate-limited per address. Turn them off on a daemon with the
  setting `registry.pings` = `off`.

## Ratings and reviews

Any account with a confirmed email address can rate a package from 1 to 5
stars, with an optional plain-text review of up to 2000 characters: one per
account per package, editable and withdrawable (`PUT` and `DELETE
/registry/packages/{name}/reviews/mine`). People rate from the app: a daemon
paired with an account rates for that account with its device token (scope
`registry:review`); hub API keys need that scope too. Authors can't rate
their own packages, and nobody can rate a delisted one.

Authors reply to a review with `POST …/reviews/{id}/reply`; an empty reply
removes it. Reviews show the reviewer's account name, never an email address.
Writes are limited to 30 per account per hour. Deleting an account deletes
its reviews and recounts the ratings.

## Reports

Anyone signed in with a confirmed email address can report a package, or one
of its versions, to the hub's operators (`POST …/reports`, from the app or the
API) for one of these reasons:

| Reason | Means |
| --- | --- |
| `malware` | It does something harmful: steals data, reaches hosts it shouldn't, sabotages. |
| `broken` | It doesn't work, or crashes. |
| `spam` | A misleading or keyword-stuffed listing, or a package with no real purpose. |
| `impersonation` | It pretends to be another author's or another product's module. |
| `license` | It breaks a license or someone's copyright. |
| `other` | Anything else; needs details. |

Each account can have one open report per package; reports are limited to
10 per account per hour. Malware reports email the hub's admins at once. The
author is never told who reported.

## Moderation

Operators (accounts with `is_admin`) work through the queue in the operator
console (`/account/admin/` on the hub's site, `GET /admin/reports`), malware
first. For each report they can:

| Action | Effect |
| --- | --- |
| **Dismiss** | Closes the report. Nothing else changes. |
| **Yank a version** | The version stops being offered and drops out of "latest". It keeps its reason (and an optional note), which daemons show. An operator's yank can be undone (`…/unyank`); an author's own can't. |
| **Delist the package** | It leaves search and can't be rated or installed; its page still answers, with the reason, so daemons can warn. Closes the package's other open reports. Reversible with `…/relist`. |
| **Ban the author** | Delists every package of the author, stops them publishing, rotating their key or editing listings, and takes away a verified badge. The handle and the key **stay as a tombstone**: nobody else can register the handle, and daemons that pinned the key keep refusing builds signed by anyone else. Lifting a ban lets them publish again; their packages stay delisted until an operator lists each again. |

Operators can also take these actions without a report (`/admin/registry/…`)
and give or take an author's **verified** badge, which says the operators
checked who the author is (a known project, a company, a person they know).
The author is emailed about every yank, delisting and ban, with the reason
and note; every action is written to the hub's log with the operator's
address.

Operators should yank or delist for malware at once and investigate after;
prefer yanking a version over delisting when only one version is bad; ban for
malware, impersonation or repeated spam. A note is shown to everyone who has
the module installed, so keep it short and factual.

## What daemons do

A daemon asks the hub about its installed modules a few minutes after start
and every six hours (`POST /registry/advisories`), and when someone opens the
installed list with a check.

- A **yanked** version (by an operator) or a **delisted** package is flagged
  on Modules → Add modules from your hub with the reason, for example
  "skyline/weather was removed from the marketplace: malware", the
  operator's note, and a button to remove it. For malware the warning is red
  and says to treat secrets given to the module as exposed. An update is
  offered when a newer good version exists, except for malware.
- Each newly flagged module raises a `registry.advisory` event, which the
  daemon forwards to phone notifications and the like (urgent for malware).
- A version the author withdrew shows a quieter notice.
- Nothing is removed automatically: the module keeps running, sandboxed as
  before, until a person removes it. Removing it deletes its connections and
  its files.
- Delisted packages can't be installed or updated from the hub.

## The website

The hub's site shows the marketplace at `/modules/` (search, categories,
sorting) and `/modules/package/?name=author/module` (readme, screenshots,
what it may reach, the author key's fingerprint, versions, ratings and
reviews), and explains publishing at `/modules/publish/`. It reads the hub's
registry from the browser, so it's always current; a site hosted apart from
a hub is pointed at one with `PUBLIC_HUB_URL` at build time.
