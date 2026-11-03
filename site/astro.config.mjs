// The public website. Static output that any hub serves with
// CONDUIT_HUB_SITE_DIR=site/dist (account pages call the hub's /v1 API on the
// same origin).
import { defineConfig } from "astro/config";

export default defineConfig({
  output: "static",
  build: { format: "directory" },
  trailingSlash: "ignore",
  vite: { server: { fs: { allow: [".."] } } },
});
