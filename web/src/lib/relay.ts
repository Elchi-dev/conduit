// End-to-end encrypted relay client: the TypeScript side of pkg/relay.
//
// The browser (or the Android app) reaches a daemon through a hub. The hub
// forwards frames and sees only ciphertext. The daemon's public key comes
// from its pairing QR code, never from the hub. pkg/relay/relay.go documents
// the construction; pkg/relay/testdata/vectors.json pins the wire format and
// relay.test.ts checks this file against it.
import { x25519 } from "@noble/curves/ed25519";

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s: string): Uint8Array {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Go marshals []byte as standard, padded base64.
function b64std(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
function unb64std(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const subtle = globalThis.crypto.subtle;

export type KeyPair = { privateKey: Uint8Array; publicKey: string };

export function newKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: b64url(x25519.getPublicKey(privateKey)) };
}

export function keyPairFrom(privateKey: Uint8Array): KeyPair {
  return { privateKey, publicKey: b64url(x25519.getPublicKey(privateKey)) };
}

/** The short fingerprint people compare between devices. */
export async function fingerprint(pub: string): Promise<string> {
  const h = new Uint8Array(await subtle.digest("SHA-256", unb64url(pub) as BufferSource));
  return b64url(h.slice(0, 16));
}

export type Hello = { v: number; static: string; ephemeral: string; salt: string; proof: string };
export type Intro = { name?: string; pairingSecret?: string };

function nonce(seq: number): Uint8Array {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(seq));
  return n;
}

async function derive(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const base = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: enc.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** One tunnel's keys and counters. Frames must be sealed and opened in order. */
export class Session {
  private sendSeq = 0;
  private recvSeq = 0;
  private send: CryptoKey;
  private recv: CryptoKey;
  constructor(send: CryptoKey, recv: CryptoKey) {
    this.send = send;
    this.recv = recv;
  }

  async seal(plain: Uint8Array): Promise<Uint8Array> {
    const iv = nonce(this.sendSeq++);
    return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, this.send, plain as BufferSource));
  }

  async open(frame: Uint8Array): Promise<Uint8Array> {
    const iv = nonce(this.recvSeq);
    let out: ArrayBuffer;
    try {
      out = await subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, this.recv, frame as BufferSource);
    } catch {
      throw new Error("relay frame failed to decrypt (tampered, replayed or out of order)");
    }
    this.recvSeq++;
    return new Uint8Array(out);
  }

  sealJSON(v: unknown) {
    return this.seal(enc.encode(JSON.stringify(v)));
  }
  async openJSON<T>(frame: Uint8Array): Promise<T> {
    return JSON.parse(dec.decode(await this.open(frame))) as T;
  }
}

/** Build the client hello for a daemon whose key was pinned at pairing. */
export async function clientHandshake(
  me: KeyPair,
  daemonPub: string,
  intro: Intro,
  fixed?: { ephemeral: Uint8Array; salt: Uint8Array },
): Promise<{ hello: Hello; session: Session }> {
  const dpub = unb64url(daemonPub);
  const eph = fixed?.ephemeral ?? x25519.utils.randomPrivateKey();
  const salt = fixed?.salt ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
  const dh1 = x25519.getSharedSecret(eph, dpub);
  const dh2 = x25519.getSharedSecret(me.privateKey, dpub);
  const ikm = new Uint8Array(64);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  const session = new Session(await derive(ikm, salt, "conduit-relay-v1 c2d"), await derive(ikm, salt, "conduit-relay-v1 d2c"));
  // Match Go's field order and omitempty so the proof is byte-identical.
  const body: Intro = {};
  if (intro.name) body.name = intro.name;
  if (intro.pairingSecret) body.pairingSecret = intro.pairingSecret;
  const proof = await session.sealJSON(body);
  return {
    hello: { v: 1, static: me.publicKey, ephemeral: b64url(x25519.getPublicKey(eph)), salt: b64url(salt), proof: b64url(proof) },
    session,
  };
}

/** The daemon's first frame on a stream. */
export type Welcome = { ok: boolean; error?: string; client?: string; daemon?: string };

type WireResponse = { id: number; status: number; headers?: Record<string, string>; body?: string };

/** What a pairing QR code carries (conduit://pair?d=…). */
export type PairingInfo = { v: number; hub: string; daemon: string; key: string; secret: string; name: string };

export function parsePairing(text: string): PairingInfo {
  const t = text.trim();
  const m = t.match(/[?&]d=([A-Za-z0-9_-]+)/);
  const raw = m ? dec.decode(unb64url(m[1])) : t;
  const p = JSON.parse(raw) as PairingInfo;
  if (p.v !== 1 || !p.hub || !p.daemon || !p.key) throw new Error("That isn't a Conduit pairing code.");
  return p;
}

/**
 * A connection to a daemon through a hub. Requests may overlap; responses
 * are matched by id.
 */
export class RelayClient {
  welcome!: Welcome;
  private ws!: WebSocket;
  private session!: Session;
  private nextId = 0;
  private pending = new Map<number, { resolve: (r: WireResponse) => void; reject: (e: Error) => void }>();
  private sendChain: Promise<void> = Promise.resolve();
  private recvChain: Promise<void> = Promise.resolve();
  onClose?: (reason: string) => void;

  static async connect(hub: string, daemon: string, daemonKey: string, me: KeyPair, intro: Intro): Promise<RelayClient> {
    const c = new RelayClient();
    const wsBase = hub.replace(/^http/, "ws").replace(/\/$/, "");
    const ws = new WebSocket(`${wsBase}/v1/relay/connect/${encodeURIComponent(daemon)}`);
    ws.binaryType = "arraybuffer";
    await new Promise<void>((res, rej) => {
      ws.onopen = () => res();
      ws.onerror = () => rej(new Error("Couldn't reach the daemon through the hub. Is it online?"));
    });
    const { hello, session } = await clientHandshake(me, daemonKey, intro);
    const first = new Promise<Uint8Array>((res, rej) => {
      ws.onmessage = (e) => res(new Uint8Array(e.data as ArrayBuffer));
      ws.onclose = (e) => rej(new Error(e.reason || "The hub closed the connection."));
    });
    ws.send(enc.encode(JSON.stringify(hello)));
    let welcome: Welcome;
    try {
      welcome = await session.openJSON<Welcome>(await first);
    } catch {
      ws.close();
      throw new Error("The daemon's answer didn't decrypt: its key doesn't match the one you paired with.");
    }
    if (!welcome.ok) {
      ws.close();
      throw new Error(welcome.error || "The daemon refused the connection.");
    }
    c.ws = ws;
    c.session = session;
    c.welcome = welcome;
    ws.onmessage = (e) => {
      const frame = new Uint8Array(e.data as ArrayBuffer);
      // Open strictly in arrival order: nonces count up.
      c.recvChain = c.recvChain.then(async () => {
        try {
          const r = await session.openJSON<WireResponse>(frame);
          const p = c.pending.get(r.id);
          c.pending.delete(r.id);
          p?.resolve(r);
        } catch (err) {
          c.fail(String(err));
        }
      });
    };
    ws.onclose = (e) => c.fail(e.reason || "connection closed");
    return c;
  }

  private fail(reason: string) {
    for (const p of this.pending.values()) p.reject(new Error(`Relay: ${reason}`));
    this.pending.clear();
    this.onClose?.(reason);
  }

  get open() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Send one HTTP request through the tunnel. */
  async request(method: string, path: string, headers: Record<string, string>, body?: Uint8Array): Promise<Response> {
    if (!this.open) throw new Error("Relay: not connected");
    const id = ++this.nextId;
    const wait = new Promise<WireResponse>((resolve, reject) => this.pending.set(id, { resolve, reject }));
    const req = { id, method, path, headers, body: body && body.length ? b64std(body) : undefined };
    // Seal and send in order.
    this.sendChain = this.sendChain.then(async () => {
      const frame = await this.session.sealJSON(req);
      this.ws.send(frame as Uint8Array<ArrayBuffer>);
    });
    await this.sendChain;
    const r = await wait;
    const bytes = r.body ? unb64std(r.body) : new Uint8Array();
    const nullBody = r.status === 204 || r.status === 304;
    return new Response(nullBody ? null : (bytes as BodyInit), { status: r.status, headers: r.headers });
  }

  close() {
    this.ws?.close();
  }
}
