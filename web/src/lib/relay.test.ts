// Checks relay.ts against the Go implementation's pinned vectors.
// Run: node --experimental-strip-types src/lib/relay.test.ts (pnpm test:relay)
import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { b64url, clientHandshake, fingerprint, keyPairFrom, unb64url } from "./relay.ts";

const v = JSON.parse(readFileSync(new URL("../../../pkg/relay/testdata/vectors.json", import.meta.url), "utf8"));

function eq(name: string, got: unknown, want: unknown) {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error(`FAIL ${name}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
    process.exit(1);
  }
  console.log(`ok   ${name}`);
}

const client = keyPairFrom(unb64url(v.clientPrivate));
const daemon = keyPairFrom(unb64url(v.daemonPrivate));
const { hello, session } = await clientHandshake(client, daemon.publicKey, v.intro, {
  ephemeral: unb64url(v.ephemeralPrivate),
  salt: unb64url(v.salt),
});
eq("hello", hello, v.hello);
eq("fingerprint", await fingerprint(daemon.publicKey), v.daemonFingerprint);
eq("welcome", await session.openWelcome(unb64url(v.welcomeFrame)), {
  ok: true,
  client: "c1",
  daemon: "Desk",
  ephemeral: b64url(x25519.getPublicKey(unb64url(v.daemonEphemeralPrivate))),
});
eq("client frame", b64url(await session.seal(new TextEncoder().encode("ping"))), v.clientFrame);
eq("daemon frame", await session.openJSON(unb64url(v.daemonFrame)), { ok: true });
let threw = false;
try {
  await session.open(unb64url(v.daemonFrame));
} catch {
  threw = true;
}
eq("replay rejected", threw, true);
