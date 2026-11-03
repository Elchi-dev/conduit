// Where the app's API calls go.
//
// "direct": the page was served by the daemon (desktop, LAN, localhost); calls
// go to /api/v1 with the session cookie.
// "relay": the page runs elsewhere (the Android app, a hub's website) and was
// paired with a daemon by its QR code; calls go through the hub relay,
// end-to-end encrypted, with a bearer session token.
import { keyPairFrom, newKeyPair, parsePairing, RelayClient, type KeyPair } from "./relay";

export type RelayProfile = {
  mode: "relay";
  hub: string; // empty for LAN-only pairings
  lan?: string; // direct ws:// address on the local network
  daemon: string;
  key: string; // daemon public key, pinned at pairing
  name: string; // daemon name
  clientKey: string; // this device's private key (base64url)
  token?: string; // daemon session token
};

const STORAGE = "conduit.connection";

function load(): RelayProfile | null {
  try {
    const raw = localStorage.getItem(STORAGE);
    if (!raw) return null;
    const p = JSON.parse(raw) as RelayProfile;
    return p.mode === "relay" ? p : null;
  } catch {
    return null;
  }
}

function save(p: RelayProfile | null) {
  try {
    if (p) localStorage.setItem(STORAGE, JSON.stringify(p));
    else localStorage.removeItem(STORAGE);
  } catch {
    /* storage unavailable: the pairing lasts for this page only */
  }
}

let profile: RelayProfile | null = load();
let client: RelayClient | null = null;
let connecting: Promise<RelayClient> | null = null;

export function relayProfile(): RelayProfile | null {
  return profile;
}

export function isRelay(): boolean {
  return profile !== null;
}

function me(p: RelayProfile): KeyPair {
  const raw = atob(p.clientKey.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((p.clientKey.length + 3) % 4));
  return keyPairFrom(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
}

function connect(secret?: string): Promise<RelayClient> {
  if (client?.open) return Promise.resolve(client);
  if (connecting) return connecting;
  const p = profile;
  if (!p) return Promise.reject(new Error("Not paired with a daemon."));
  const name = deviceName();
  connecting = dialBest(p, { name, pairingSecret: secret })
    .then((c) => {
      client = c;
      c.onClose = () => {
        client = null;
      };
      return c;
    })
    .finally(() => {
      connecting = null;
    });
  return connecting;
}

/**
 * On the same network, go straight to the daemon (no hub); otherwise, or if
 * that fails, through the hub. Both are end-to-end encrypted to the pinned key.
 */
async function dialBest(p: RelayProfile, intro: { name: string; pairingSecret?: string }): Promise<RelayClient> {
  if (p.lan) {
    try {
      return await RelayClient.connect(p.lan, p.key, me(p), intro, p.hub ? 2500 : 15000);
    } catch (err) {
      if (!p.hub) throw err;
    }
  }
  return RelayClient.connect(RelayClient.hubURL(p.hub, p.daemon), p.key, me(p), intro);
}

function deviceName(): string {
  const ua = navigator.userAgent;
  if (/Android/i.test(ua)) return "Android";
  if (/iPhone|iPad/i.test(ua)) return "iPhone";
  return "Browser";
}

/** Pair with a daemon from the text of its QR code (conduit://pair?d=…). */
export async function pairFromCode(text: string): Promise<RelayProfile> {
  const info = parsePairing(text);
  const kp = newKeyPair();
  const b = String.fromCharCode(...kp.privateKey);
  const clientKey = btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const prev = profile;
  profile = { mode: "relay", hub: info.hub ?? "", lan: info.lan, daemon: info.daemon ?? "", key: info.key, name: info.name, clientKey };
  client?.close();
  client = null;
  try {
    await connect(info.secret);
  } catch (err) {
    profile = prev;
    throw err;
  }
  save(profile);
  return profile;
}

/** Forget the paired daemon and go back to talking to the serving daemon. */
export function forgetRelay() {
  client?.close();
  client = null;
  profile = null;
  save(null);
}

function setToken(token: string | undefined) {
  if (!profile) return;
  profile = { ...profile, token };
  save(profile);
}

/**
 * fetch for openapi-fetch and other API calls: direct mode passes through;
 * relay mode tunnels the request.
 */
export async function apiFetch(input: Request): Promise<Response> {
  if (!profile) return fetch(input);
  const url = new URL(input.url, location.href);
  const path = url.pathname + url.search;
  const headers: Record<string, string> = {};
  const ct = input.headers.get("Content-Type");
  if (ct) headers["Content-Type"] = ct;
  headers["Accept"] = input.headers.get("Accept") ?? "application/json";
  if (profile.token) headers["Authorization"] = `Bearer ${profile.token}`;
  const body = input.method === "GET" || input.method === "HEAD" ? undefined : new Uint8Array(await input.arrayBuffer());
  const c = await connect();
  const res = await c.request(input.method, path, headers, body);
  // Sessions are bearer tokens here: keep the one login hands out.
  if (res.ok && (path.endsWith("/auth/login") || path.endsWith("/setup"))) {
    try {
      const data = (await res.clone().json()) as { token?: string };
      if (data.token) setToken(data.token);
    } catch {
      /* not JSON */
    }
  }
  if (path.endsWith("/auth/logout")) setToken(undefined);
  return res;
}

/** Same as apiFetch, from fetch-style arguments. */
export function apiFetchUrl(url: string, init?: RequestInit): Promise<Response> {
  return apiFetch(new Request(new URL(url, location.href), init));
}

/** "through hub.example.com" or "on your network", for messages. */
export function routeLabel(p: RelayProfile): string {
  if (!p.hub) return "on your network";
  try {
    return `through ${new URL(p.hub).host}${p.lan ? " (or directly on your network)" : ""}`;
  } catch {
    return "through the hub";
  }
}

/**
 * The daemon's event stream through the relay: calls onEvent with each
 * parsed server-sent event. Reconnects after a drop. Returns a stop function.
 */
export function relayEvents(onEvent: (type: string, data: string) => void, onState: (live: boolean) => void): () => void {
  let stopped = false;
  let cancel: (() => void) | null = null;
  let retry: number | undefined;
  const open = async () => {
    if (stopped || !profile) return;
    try {
      const c = await connect();
      const headers: Record<string, string> = { Accept: "text/event-stream" };
      if (profile.token) headers.Authorization = `Bearer ${profile.token}`;
      let buf = "";
      onState(true);
      cancel = c.stream(
        "/api/v1/events",
        headers,
        (text) => {
          buf += text;
          let i: number;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let type = "message";
            const data: string[] = [];
            for (const line of block.split("\n")) {
              if (line.startsWith("event:")) type = line.slice(6).trim();
              else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
            }
            if (data.length) onEvent(type, data.join("\n"));
          }
        },
        () => {
          onState(false);
          if (!stopped) retry = window.setTimeout(open, 3000);
        },
      );
    } catch {
      onState(false);
      if (!stopped) retry = window.setTimeout(open, 5000);
    }
  };
  void open();
  return () => {
    stopped = true;
    clearTimeout(retry);
    cancel?.();
  };
}
