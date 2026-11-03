// Conduit external module kit for TypeScript on Node 22+ (protocol v1).
// No dependencies: copy this file next to your module.
//
//   import { serve, ActionError, type Module } from "./conduit-module.ts";
//   serve({ manifest: {...}, async invoke(instance, action, input, dryRun) { ... } });
//
// Run with `node --experimental-strip-types mymodule.ts` (or compile to JS).
// See docs/protocol/external-modules.md.
import { createInterface } from "node:readline";

export const PROTOCOL = "1";

export type Risk = "read" | "write" | "destructive";
export type ActionSpec = {
  name: string;
  title?: string;
  description?: string;
  risk: Risk;
  input?: unknown;
  reversible?: boolean;
  dryRun?: boolean;
  sensitive?: boolean;
};
export type Manifest = {
  id: string;
  name: string;
  version: string;
  description?: string;
  category?: string;
  configSchema?: unknown;
  actions: ActionSpec[];
};
export type Result = {
  output?: unknown;
  plan?: { summary: string; changes: { target: string; op: string; before?: unknown; after?: unknown }[] };
  undo?: { action: string; input: unknown; description: string };
};
export type Health = { status: "ok" | "degraded" | "down" | "unconfigured"; message?: string };

/** Throw to fail an action with a message the person sees. */
export class ActionError extends Error {}

export interface Host {
  /** Resolve a "secret://name" reference from this instance's settings. */
  secret(ref: string): Promise<string>;
  publish(type: string, data?: unknown, instance?: string): void;
  log(msg: string, level?: "debug" | "info" | "warn" | "error", kv?: Record<string, unknown>): void;
}

export interface Module {
  manifest: Manifest;
  configure?(host: Host, instance: string, config: Record<string, unknown>): void | Promise<void>;
  invoke(instance: string, action: string, input: unknown, dryRun: boolean): Result | Promise<Result>;
  health?(instance: string): Health | Promise<Health>;
  close?(instance: string): void | Promise<void>;
}

type Msg = { jsonrpc: "2.0"; id?: number; method?: string; params?: any; result?: unknown; error?: { code: number; message: string } };

/** Serve a module over stdin/stdout until Conduit closes the stream. */
export function serve(m: Module, input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout) {
  let nextId = 1;
  const pending = new Map<number, (msg: Msg) => void>();
  const send = (msg: Msg) => output.write(JSON.stringify(msg) + "\n");
  const call = (method: string, params: unknown) =>
    new Promise<unknown>((resolve, reject) => {
      const id = nextId++;
      pending.set(id, (msg) => (msg.error ? reject(new ActionError(msg.error.message)) : resolve(msg.result)));
      send({ jsonrpc: "2.0", id, method, params });
    });
  const host: Host = {
    secret: (ref) => call("host.secret", { ref }) as Promise<string>,
    publish: (type, data, instance) => send({ jsonrpc: "2.0", method: "host.publish", params: { type, module: "", data, instance } }),
    log: (msg, level = "info", kv = {}) => send({ jsonrpc: "2.0", method: "host.log", params: { level, msg, kv: Object.entries(kv).flat() } }),
  };

  async function handle(msg: Msg) {
    const p = msg.params ?? {};
    try {
      let result: unknown;
      switch (msg.method) {
        case "initialize":
          result = { protocolVersion: PROTOCOL, manifest: m.manifest };
          break;
        case "configure":
          await m.configure?.(host, p.instance, p.config ?? {});
          result = {};
          break;
        case "invoke":
          result = (await m.invoke(p.instance, p.action, p.input, !!p.dryRun)) ?? {};
          break;
        case "health":
          result = (await m.health?.(p.instance)) ?? { status: "ok" };
          break;
        case "close":
          await m.close?.(p.instance);
          result = {};
          break;
        default:
          return send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } });
      }
      send({ jsonrpc: "2.0", id: msg.id, result });
    } catch (e) {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: e instanceof Error ? e.message : String(e) } });
    }
  }

  createInterface({ input }).on("line", (line) => {
    let msg: Msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (msg.method) void handle(msg);
    else if (msg.id !== undefined) {
      const done = pending.get(msg.id);
      pending.delete(msg.id);
      done?.(msg);
    }
  });
}
