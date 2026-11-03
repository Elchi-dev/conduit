#!/usr/bin/env -S node --experimental-strip-types --no-warnings
// Example: an HTTP check with an optional bearer token from the vault.
// Install: copy this file and conduit-module.ts into <data>/modules/,
// chmod +x example-uptime.ts, restart Conduit, add an "HTTP check" connection.
import { ActionError, serve } from "./conduit-module.ts";

const sites = new Map<string, { url: string; token?: string }>();
let host: import("./conduit-module.ts").Host;

serve({
  manifest: {
    id: "httpcheck",
    name: "HTTP check",
    version: "0.1.0",
    description: "Is a URL answering, and how fast.",
    category: "Example",
    configSchema: {
      type: "object",
      required: ["url"],
      properties: { url: { type: "string" }, token: { type: "string", "x-secret": true } },
    },
    actions: [{ name: "check", title: "Check now", risk: "read" }],
  },
  configure(h, instance, config) {
    if (typeof config.url !== "string" || !/^https?:\/\//.test(config.url)) throw new ActionError("set an http(s) URL");
    host = h;
    sites.set(instance, { url: config.url, token: config.token as string | undefined });
  },
  async invoke(instance, action) {
    const s = sites.get(instance);
    if (!s) throw new ActionError("this instance isn't set up");
    if (action !== "check") throw new ActionError(`unknown action ${action}`);
    const headers: Record<string, string> = {};
    if (s.token) headers.Authorization = `Bearer ${await host.secret(s.token)}`;
    const start = Date.now();
    const res = await fetch(s.url, { headers, signal: AbortSignal.timeout(15000) });
    return { output: { status: res.status, ok: res.ok, ms: Date.now() - start } };
  },
  health: (instance) => (sites.has(instance) ? { status: "ok" } : { status: "unconfigured" }),
});
