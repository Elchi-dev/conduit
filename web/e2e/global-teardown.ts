import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export default async function globalTeardown() {
  const f = join(tmpdir(), "conduit-e2e.pid");
  try {
    process.kill(Number(readFileSync(f, "utf8")), "SIGTERM");
  } catch {
    /* already gone */
  }
  rmSync(f, { force: true });
}
