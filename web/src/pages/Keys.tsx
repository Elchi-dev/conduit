import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type ApiKey } from "../api/client";
import { ago, stamp } from "../lib/format";
import "./pages.css";

const scopeGroups: { label: string; scopes: { id: string; text: string }[] }[] = [
  {
    label: "Act",
    scopes: [
      { id: "actions:*:invoke", text: "Run actions on any module (rules still apply)" },
      { id: "audit:*:undo", text: "Undo actions" },
    ],
  },
  {
    label: "Read",
    scopes: [
      { id: "modules:*:read", text: "See modules, connections and health" },
      { id: "audit:*:read", text: "Read the timeline" },
      { id: "approvals:*:read", text: "See approvals and their status" },
      { id: "events:*:read", text: "Receive live events" },
      { id: "policy:*:read", text: "Read agent rules" },
    ],
  },
  {
    label: "Manage",
    scopes: [
      { id: "instances:*:manage", text: "Connect, change and disconnect systems" },
      { id: "keys:*:manage", text: "List and revoke keys" },
    ],
  },
];

const kindText = {
  agent: "For an AI agent. Its calls follow the agent rules, and emergency stop revokes it.",
  live: "For a script or integration you run for real.",
  test: "For development. Same powers, easy to spot and clean up.",
};

export function Keys() {
  const keys = useQuery({ queryKey: ["keys"], queryFn: () => ok(api.GET("/keys")) });
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const active = keys.data?.filter((k) => !k.revokedAt) ?? [];
  const revoked = keys.data?.filter((k) => k.revokedAt) ?? [];

  return (
    <div className="page">
      <div className="spread">
        <div className="page-head">
          <h1>API keys</h1>
          <p>Keys let programs and AI agents use Conduit without you signed in. Each key only gets the access you tick.</p>
        </div>
        {!creating && (
          <button className="btn primary" onClick={() => setCreating(true)}>
            Create key
          </button>
        )}
      </div>

      {secret && (
        <div className="panel runner secret-once" role="status">
          <h2>Copy your new key now</h2>
          <p className="small">This is the only time the full key for "{secret.name}" is shown. Store it somewhere safe.</p>
          <div className="inline">
            <code className="secret-value">{secret.value}</code>
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(secret.value)}>
              Copy
            </button>
          </div>
          <div>
            <button className="btn sm quiet" onClick={() => setSecret(null)}>
              I've saved it
            </button>
          </div>
        </div>
      )}

      {creating && <CreateKey onDone={(name, value) => { setCreating(false); if (value) setSecret({ name, value }); }} />}

      {keys.data?.length === 0 && !creating && (
        <div className="empty">
          <h2>No keys yet</h2>
          <p className="muted">Create an agent key to connect Claude Desktop or another MCP client, or a live key for your own scripts.</p>
        </div>
      )}

      {active.length > 0 && (
        <div className="panel rows">
          {active.map((k) => (
            <KeyRow key={k.id} k={k} onRotated={(v) => setSecret({ name: k.name, value: v })} />
          ))}
        </div>
      )}
      {revoked.length > 0 && (
        <details>
          <summary className="small muted">Revoked and expired ({revoked.length})</summary>
          <div className="panel rows" style={{ marginTop: 8 }}>
            {revoked.map((k) => (
              <div className="row key-row" key={k.id}>
                <strong>{k.name}</strong>
                <code className="xs muted">{k.prefix}</code>
                <span className="xs muted">
                  {k.revokeReason || "revoked"} {ago(k.revokedAt)}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

function KeyRow({ k, onRotated }: { k: ApiKey; onRotated: (secret: string) => void }) {
  const qc = useQueryClient();
  const [usage, setUsage] = useState(false);
  const revoke = useMutation({
    mutationFn: () => ok(api.DELETE("/keys/{id}", { params: { path: { id: k.id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });
  const rotate = useMutation({
    mutationFn: () => ok(api.POST("/keys/{id}/rotate", { params: { path: { id: k.id } }, body: { graceSeconds: 86400 } })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      onRotated(r.secret);
    },
  });
  const log = useQuery({
    queryKey: ["keys", k.id, "usage"],
    queryFn: () => ok(api.GET("/keys/{id}/usage", { params: { path: { id: k.id }, query: { limit: 20 } } })),
    enabled: usage,
  });
  return (
    <div className="row key-row">
      <div className="stack" style={{ gap: 2 }}>
        <strong>{k.name}</strong>
        <code className="xs muted">{k.prefix}</code>
      </div>
      <span className="tag">{k.kind}</span>
      <span className="xs muted">
        {k.lastUsedAt ? `used ${ago(k.lastUsedAt)}` : "never used"}
        {k.graceUntil ? `, retires ${ago(k.graceUntil)}` : ""}
        {k.expiresAt ? `, expires ${ago(k.expiresAt)}` : ""}
      </span>
      <div className="inline">
        <button className="btn sm quiet" onClick={() => setUsage(!usage)} aria-expanded={usage}>
          Usage
        </button>
        {!k.rotatedTo && (
          <button className="btn sm" onClick={() => rotate.mutate()} disabled={rotate.isPending} title="Issue a replacement; this key keeps working for 24 hours">
            Rotate
          </button>
        )}
        <button className="btn sm danger" onClick={() => confirm(`Revoke "${k.name}"? Anything using it stops working now.`) && revoke.mutate()}>
          Revoke
        </button>
      </div>
      {usage && (
        <div className="usage">
          <p className="xs muted">
            Scopes: <span className="data">{k.scopes.join(", ")}</span>
            {k.ipAllow.length > 0 && (
              <>
                {" "}
                Only from <span className="data">{k.ipAllow.join(", ")}</span>.
              </>
            )}{" "}
            Up to {k.ratePerMin} requests a minute.
          </p>
          {log.data?.length === 0 && <p className="xs muted">No requests in the last 30 days.</p>}
          {log.data && log.data.length > 0 && (
            <table className="table">
              <tbody>
                {log.data.map((u, i) => (
                  <tr key={i}>
                    <td className="xs">{stamp(u.at)}</td>
                    <td className="data xs">
                      {u.method} {u.path}
                    </td>
                    <td className="num xs">{u.status}</td>
                    <td className="data xs muted">{u.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function CreateKey({ onDone }: { onDone: (name: string, secret?: string) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"agent" | "live" | "test">("agent");
  const [scopes, setScopes] = useState<string[]>(["actions:*:invoke", "modules:*:read", "approvals:*:read"]);
  const [ips, setIps] = useState("");
  const [days, setDays] = useState("90");
  const create = useMutation({
    mutationFn: () =>
      ok(
        api.POST("/keys", {
          body: {
            name,
            kind,
            scopes,
            ipAllow: ips.split(/[\s,]+/).filter(Boolean),
            expiresAt: days ? new Date(Date.now() + Number(days) * 86400_000).toISOString() : undefined,
          },
        }),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      onDone(name, r.secret);
    },
  });
  const toggle = (id: string) => setScopes((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const agentBlocked = (id: string) => kind === "agent" && id === "keys:*:manage";

  return (
    <form
      className="panel runner"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <h2>New API key</h2>
      <label className="field">
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Assistant on my laptop" required />
      </label>
      <fieldset className="kinds">
        <legend className="small">Used by</legend>
        {(["agent", "live", "test"] as const).map((k) => (
          <label key={k} className={`kind ${kind === k ? "on" : ""}`}>
            <input type="radio" name="kind" checked={kind === k} onChange={() => setKind(k)} />
            <strong>{k === "agent" ? "An AI agent" : k === "live" ? "A program" : "Testing"}</strong>
            <span className="xs muted">{kindText[k]}</span>
          </label>
        ))}
      </fieldset>
      <div className="scope-groups">
        {scopeGroups.map((g) => (
          <fieldset key={g.label}>
            <legend className="small">{g.label}</legend>
            {g.scopes.map((s) => (
              <label key={s.id} className="check" title={s.id}>
                <input type="checkbox" checked={scopes.includes(s.id)} disabled={agentBlocked(s.id)} onChange={() => toggle(s.id)} />
                {s.text}
              </label>
            ))}
          </fieldset>
        ))}
      </div>
      <div className="rule-grid">
        <label className="field">
          <span>Only from these addresses (optional)</span>
          <input className="data" value={ips} onChange={(e) => setIps(e.target.value)} placeholder="192.168.1.0/24" />
        </label>
        <label className="field">
          <span>Expires</span>
          <select value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="30">in 30 days</option>
            <option value="90">in 90 days</option>
            <option value="365">in a year</option>
            <option value="">never</option>
          </select>
        </label>
      </div>
      {create.error && <div className="error">{create.error.message}</div>}
      <div className="inline" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn quiet" onClick={() => onDone("")}>
          Cancel
        </button>
        <button className="btn primary" disabled={create.isPending || scopes.length === 0}>
          Create key
        </button>
      </div>
    </form>
  );
}
