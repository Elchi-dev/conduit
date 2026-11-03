// Talks to the hub that serves this site (same origin, /v1). The session
// token lives in localStorage; it is a hub session, never a daemon one.

const KEY = "conduit.hub.session";

export function token(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null) {
  try {
    if (t) localStorage.setItem(KEY, t);
    else localStorage.removeItem(KEY);
  } catch {
    /* private mode: the session lasts for this page */
  }
}

export class HubError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new HubError("The hub didn't answer. Check your connection and try again.", 0);
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && t && path !== "/sessions") setToken(null);
    throw new HubError((data as { error?: string }).error || res.statusText, res.status);
  }
  return data as T;
}

/** Wire a form: collect named fields, run fn, show errors in [data-error]. */
export function form(el: HTMLFormElement, fn: (v: Record<string, string>) => Promise<void>) {
  const err = el.querySelector<HTMLElement>("[data-error]");
  const btn = el.querySelector<HTMLButtonElement>("button[type=submit], button:not([type])");
  el.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v: Record<string, string> = {};
    new FormData(el).forEach((val, k) => (v[k] = String(val)));
    if (err) err.hidden = true;
    if (btn) btn.disabled = true;
    try {
      await fn(v);
    } catch (x) {
      if (err) {
        err.textContent = x instanceof Error ? x.message : String(x);
        err.hidden = false;
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

export function param(name: string): string {
  return new URLSearchParams(location.search).get(name) ?? "";
}

export function ago(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {}, ...kids: (Node | string)[]) {
  const n = document.createElement(tag);
  const { class: cls, ...rest } = props;
  if (cls) n.className = cls;
  Object.assign(n, rest);
  n.append(...kids);
  return n;
}

// --- passkeys (WebAuthn) ---------------------------------------------------

/** Whether this browser can use passkeys here (needs a secure origin). */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials && window.isSecureContext;
}

function fromB64url(s: string): ArrayBuffer {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(b: ArrayBuffer | null | undefined): string | undefined {
  if (!b) return undefined;
  let s = "";
  for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type JSONOpts = Record<string, any>;
type PKC = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (o: JSONOpts) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (o: JSONOpts) => PublicKeyCredentialRequestOptions;
};

function creationOptions(o: JSONOpts): PublicKeyCredentialCreationOptions {
  const P = window.PublicKeyCredential as PKC;
  if (P.parseCreationOptionsFromJSON) return P.parseCreationOptionsFromJSON(o);
  return {
    ...o,
    challenge: fromB64url(o.challenge),
    user: { ...o.user, id: fromB64url(o.user.id) },
    excludeCredentials: (o.excludeCredentials ?? []).map((c: JSONOpts) => ({ ...c, id: fromB64url(c.id) })),
  } as PublicKeyCredentialCreationOptions;
}

function requestOptions(o: JSONOpts): PublicKeyCredentialRequestOptions {
  const P = window.PublicKeyCredential as PKC;
  if (P.parseRequestOptionsFromJSON) return P.parseRequestOptionsFromJSON(o);
  return {
    ...o,
    challenge: fromB64url(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map((c: JSONOpts) => ({ ...c, id: fromB64url(c.id) })),
  } as PublicKeyCredentialRequestOptions;
}

/** Serialise a credential the way the hub expects (base64url fields). */
function credentialJSON(c: PublicKeyCredential): JSONOpts {
  const withJSON = c as PublicKeyCredential & { toJSON?: () => JSONOpts };
  if (typeof withJSON.toJSON === "function") return withJSON.toJSON();
  const r = c.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: JSONOpts = { clientDataJSON: toB64url(r.clientDataJSON) };
  if ("attestationObject" in r && r.attestationObject) {
    response.attestationObject = toB64url(r.attestationObject);
    response.transports = r.getTransports?.() ?? [];
  } else {
    response.authenticatorData = toB64url(r.authenticatorData);
    response.signature = toB64url(r.signature);
    response.userHandle = toB64url(r.userHandle);
  }
  return { id: c.id, rawId: toB64url(c.rawId), type: c.type, response, clientExtensionResults: c.getClientExtensionResults?.() ?? {} };
}

type Ceremony = { ceremony: string; options: { publicKey: JSONOpts } };

/** Add a passkey to the signed-in account. */
export async function addPasskey(name: string): Promise<void> {
  const begin = await api<Ceremony>("POST", "/passkeys/register/begin");
  const cred = (await navigator.credentials.create({ publicKey: creationOptions(begin.options.publicKey) })) as PublicKeyCredential | null;
  if (!cred) throw new HubError("No passkey was created.", 0);
  await api("POST", "/passkeys/register/finish", { ceremony: begin.ceremony, name, response: credentialJSON(cred) });
}

/** Sign in with a passkey; returns the session token. */
export async function signInWithPasskey(device: string): Promise<string> {
  const begin = await api<Ceremony>("POST", "/sessions/passkey/begin");
  const cred = (await navigator.credentials.get({ publicKey: requestOptions(begin.options.publicKey) })) as PublicKeyCredential | null;
  if (!cred) throw new HubError("No passkey was chosen.", 0);
  const r = await api<{ token: string }>("POST", "/sessions/passkey/finish", { ceremony: begin.ceremony, device, response: credentialJSON(cred) });
  return r.token;
}

/** Turn a browser WebAuthn error into a sentence people can act on. */
export function passkeyError(x: unknown): string {
  if (x instanceof DOMException) {
    if (x.name === "NotAllowedError") return "The passkey request was cancelled or timed out.";
    if (x.name === "InvalidStateError") return "This device already has a passkey for your account.";
    if (x.name === "SecurityError") return "Passkeys only work when this hub is opened at its own https address.";
  }
  return x instanceof Error ? x.message : String(x);
}
