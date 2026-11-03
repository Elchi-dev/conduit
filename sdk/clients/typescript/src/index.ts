// Typed clients for Conduit. Types are generated from api/openapi/*.yaml
// (`pnpm gen`), so every path, parameter and response is checked.
//
//   import { daemon } from "@conduit/client";
//   const c = daemon({ baseUrl: "http://127.0.0.1:7600", apiKey: process.env.CONDUIT_API_KEY });
//   const { data } = await c.GET("/instances");
//   await c.POST("/instances/{id}/actions/{action}", { params: { path: { id: "web", action: "check_now" } }, body: {} });
import createClient from "openapi-fetch";
import type { paths as DaemonPaths, components as DaemonComponents } from "./daemon";
import type { paths as HubPaths, components as HubComponents } from "./hub";

export type DaemonSchemas = DaemonComponents["schemas"];
export type HubSchemas = HubComponents["schemas"];

type Opts = { baseUrl: string; apiKey?: string; fetch?: typeof fetch };

function headers(apiKey?: string): Record<string, string> {
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
}

/** A client for a daemon's API (`<daemon>/api/v1`). */
export function daemon({ baseUrl, apiKey, fetch: f }: Opts) {
  return createClient<DaemonPaths>({ baseUrl: baseUrl.replace(/\/$/, "") + "/api/v1", headers: headers(apiKey), fetch: f });
}

/** A client for a hub's API (`<hub>/v1`). */
export function hub({ baseUrl, apiKey, fetch: f }: Opts) {
  return createClient<HubPaths>({ baseUrl: baseUrl.replace(/\/$/, "") + "/v1", headers: headers(apiKey), fetch: f });
}
