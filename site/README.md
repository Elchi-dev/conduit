# Website

The public Conduit website: landing page, downloads, hubs, the
documentation (rendered straight from `docs/`, so the site and the repo never
disagree) and the hub account pages (sign-in and sign-up, email verification,
password reset, invitations, pairing codes, devices, API keys and
organisations).

It's an Astro static site. A hub serves it with
`CONDUIT_HUB_SITE_DIR=site/dist` (the Docker image does this), and the
account pages call that hub's `/v1` API on the same origin, so every hub
gets its own site. No GitHub Pages.

```sh
pnpm install
pnpm dev      # http://localhost:4321 (account pages need a hub on the same origin)
pnpm build    # dist/
```

Pages:

| Path | What |
| --- | --- |
| `/` | Landing |
| `/download/` | Desktop, Android, daemon, hub |
| `/hub/` | What a hub can and can't do |
| `/docs/…` | Everything in `docs/`; links between docs are rewritten, links to other repo files go to GitHub |
| `/modules/` | The marketplace: modules published to this hub, a page per module, how to publish (`/registry/` redirects here) |
| `/api/` | API landing; `/api/daemon/` and `/api/hub/` are generated from the OpenAPI specs |
| `/changelog/` | Release notes from `docs/releases/` |
| `/account/` | Hub account |
| `/verify/`, `/reset/`, `/invite/` | Targets of the hub's emails (`?token=`) |

Languages: English at `/`, German under `/de/` (Astro i18n routing). Each
page is a view in `src/views/` with thin wrappers in `src/pages/` and
`src/pages/de/`; strings go through `t()` / `tn()` from `src/i18n`, keyed by
the English text, with German in `src/i18n/de.ts` (marketplace strings in
`de-marketplace.ts`). The docs and the generated API references stay
English. `pnpm test:i18n` fails if a string lacks German or its
placeholders differ.

Design follows the app: slate panels, warm ink, amber only for "needs you",
Schibsted Grotesk and IBM Plex Mono (data only). The hero's lamp row and
approval card are the one animated moment; it respects reduced motion.
