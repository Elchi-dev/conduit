// Browser side of passkeys (WebAuthn): turning the daemon's JSON options into
// what navigator.credentials wants, and the answer back into JSON.
import { t } from "../i18n";

/** Whether this browser can use passkeys on this page (needs a secure origin). */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials && window.isSecureContext;
}

function fromB64url(s: string): ArrayBuffer {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b + "===".slice((b.length + 3) % 4));
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

/** Serialise a credential the way the daemon expects (base64url fields). */
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

/** Ask the browser for a new passkey for these creation options. */
export async function createPasskey(publicKey: JSONOpts): Promise<JSONOpts> {
  const cred = (await navigator.credentials.create({ publicKey: creationOptions(publicKey) })) as PublicKeyCredential | null;
  if (!cred) throw new Error(t("No passkey was created."));
  return credentialJSON(cred);
}

/** Ask the browser to sign in with one of its passkeys for this site. */
export async function getPasskey(publicKey: JSONOpts): Promise<JSONOpts> {
  const cred = (await navigator.credentials.get({ publicKey: requestOptions(publicKey) })) as PublicKeyCredential | null;
  if (!cred) throw new Error(t("No passkey was chosen."));
  return credentialJSON(cred);
}

/** Turn a browser WebAuthn error into a sentence people can act on. */
export function passkeyError(x: unknown): string {
  if (x instanceof DOMException) {
    if (x.name === "NotAllowedError") return t("The passkey request was cancelled or timed out.");
    if (x.name === "InvalidStateError") return t("This device already has a passkey for your account.");
    if (x.name === "SecurityError") return t("Passkeys don't work at this address. Open Conduit at localhost or its host name.");
  }
  return x instanceof Error ? x.message : String(x);
}
