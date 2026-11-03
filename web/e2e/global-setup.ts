import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      s.close(() => (a && typeof a === "object" ? res(a.port) : rej(new Error("no port"))));
    });
  });
}

async function waitFor(url: string, ms: number) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`the daemon didn't start at ${url}`);
}

// Starts a fresh daemon (built with the UI) on a free port with a new data
// folder, and hands its address and setup code to the tests.
export default async function globalSetup() {
  const bin = resolve(process.env.CONDUIT_E2E_BIN ?? join(import.meta.dirname, "..", "..", "bin", "conduitd"));
  if (!existsSync(bin)) throw new Error(`no daemon at ${bin}; build it first with "make daemon" from the repository root`);
  const data = mkdtempSync(join(tmpdir(), "conduit-e2e-"));
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(bin, ["-data", data, "-listen", `127.0.0.1:${port}`], {
    stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env, CONDUIT_UPDATE_CHECK: "off" },
    detached: false,
  });
  child.stderr?.on("data", (b: Buffer) => {
    if (process.env.CONDUIT_E2E_LOG) process.stderr.write(b);
  });
  await waitFor(`${url}/healthz`, 15_000);
  process.env.CONDUIT_E2E_URL = url;
  process.env.CONDUIT_E2E_TOKEN = readFileSync(join(data, "setup-token"), "utf8").trim();
  writeFileSync(join(tmpdir(), "conduit-e2e.pid"), String(child.pid));
}
