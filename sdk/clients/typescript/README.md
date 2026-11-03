# TypeScript client

`@conduit/client`: typed clients for the daemon (`daemon()`) and hub
(`hub()`) APIs, generated from `api/openapi/daemon.yaml` and `hub.yaml` with
openapi-typescript and called through openapi-fetch. Regenerate with
`pnpm gen` after changing a spec. See `src/index.ts` for usage.
