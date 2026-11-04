// The public website. Static output that any hub serves with
// CONDUIT_HUB_SITE_DIR=site/dist (account pages call the hub's /v1 API on the
// same origin).
//
// Languages: see src/i18n/index.ts.
import { defineConfig } from "astro/config";

export default defineConfig({
  output: "static",
  // Set CONDUIT_SITE_URL (e.g. https://conduit.example) to make the hreflang
  // alternates absolute; without it they are root-relative, so any hub works.
  site: process.env.CONDUIT_SITE_URL || undefined,
  build: { format: "directory" },
  trailingSlash: "ignore",
  // English at /, German under /de/. Pages exist in both languages as thin
  // wrappers around src/views/; the docs and API reference are English only.
  i18n: {
    locales: ["en", "de"],
    defaultLocale: "en",
    routing: { prefixDefaultLocale: false, redirectToDefaultLocale: false },
  },
  vite: { server: { fs: { allow: [".."] } } },
});
