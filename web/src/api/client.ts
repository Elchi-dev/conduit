import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

// Generated from api/openapi/daemon.yaml (`pnpm gen:api`).
export type S = components["schemas"];
export type Manifest = S["Manifest"];
export type ActionSpec = S["ActionSpec"];
export type Instance = S["Instance"];
export type AuditEntry = S["AuditEntry"];
export type Approval = S["Approval"];
export type Outcome = S["Outcome"];
export type Policy = S["Policy"];
export type Rule = S["Rule"];
export type ApiKey = S["ApiKey"];
export type User = S["User"];
export type Health = S["Health"];
export type Plan = S["Plan"];

export const api = createClient<paths>({ baseUrl: "/api/v1", credentials: "same-origin" });

/** ApiError carries the daemon's error message and HTTP status. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** Unwrap an openapi-fetch result, throwing ApiError on failure. */
export async function ok<T>(p: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok && response.status !== 202) {
    const msg =
      error && typeof error === "object" && "error" in error ? String((error as { error: string }).error) : response.statusText;
    throw new ApiError(msg || `Request failed (${response.status})`, response.status);
  }
  return data as T;
}
