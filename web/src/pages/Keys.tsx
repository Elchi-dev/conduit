import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type ApiKey } from "../api/client";
import { ago, stamp } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";

const scopeGroups: { label: string; scopes: { id: string; text: string }[] }[] = [
  {
    label: t("Act"),
    scopes: [
      { id: "actions:*:invoke", text: t("Run actions on any module (rules still apply)") },
      { id: "audit:*:undo", text: t("Undo actions") },
    ],
  },
  {
    label: t("Read"),
    scopes: [
      { id: "modules:*:read", text: t("See modules, connections and health") },
      { id: "audit:*:read", text: t("Read the timeline") },
      { id: "approvals:*:read", text: t("See approvals and their status") },
      { id: "events:*:read", text: t("Receive live events") },
      { id: "policy:*:read", text: t("Read agent rules") },
    ],
  },
  {
    label: t("Manage"),
    scopes: [
      { id: "instances:*:manage", text: t("Connect, change and disconnect systems") },
      { id: "keys:*:manage", text: t("List and revoke keys") },
    ],
  },
];

const kindText = {
  agent: t("For an AI agent. Its calls follow the agent rules, and emergency stop revokes it."),
  live: t("For a script or integration you run for real."),
  test: t("For development. Same powers, easy to spot and clean up."),
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
          <h1>{t("API keys")}</h1>
          <p>{t("Keys let programs and AI agents use Conduit without you signed in. Each key only gets the access you tick.")}</p>
        </div>
        {!creating && (
          <button className="btn primary" onClick={() => setCreating(true)}>
            {t("Create key")}</button>
        )}
      </div>

      {secret && (
        <div className="panel runner secret-once" role="status">
          <h2>{t("Copy your new key now")}</h2>
          <p className="small">{t("This is the only time the full key for \"")}{secret.name}{t("\" is shown. Store it somewhere safe.")}</p>
          <div className="inline">
            <code className="secret-value">{secret.value}</code>
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(secret.value)}>
              {t("Copy")}</button>
          </div>
          <div>
            <button className="btn sm quiet" onClick={() => setSecret(null)}>
              {t("I've saved it")}</button>
          </div>
        </div>
      )}

      {creating && <CreateKey onDone={(name, value) => { setCreating(false); if (value) setSecret({ name, value }); }} />}

      {keys.data?.length === 0 && !creating && (
        <div className="empty">
          <h2>{t("No keys yet")}</h2>
          <p className="muted">{t("Create an agent key to connect Claude Desktop or another MCP client, or a live key for your own scripts.")}</p>
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
          <summary className="small muted">{t("Revoked and expired (")}{revoked.length})</summary>
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
        {k.lastUsedAt ? `used ${ago(k.lastUsedAt)}` : t("never used")}
        {k.graceUntil ? `, retires ${ago(k.graceUntil)}` : ""}
        {k.expiresAt ? `, expires ${ago(k.expiresAt)}` : ""}
      </span>
      <div className="inline">
        <button className="btn sm quiet" onClick={() => setUsage(!usage)} aria-expanded={usage}>
          {t("Usage")}</button>
        {!k.rotatedTo && (
          <button className="btn sm" onClick={() => rotate.mutate()} disabled={rotate.isPending} title={t("Issue a replacement; this key keeps working for 24 hours")}>
            {t("Rotate")}</button>
        )}
        <button className="btn sm danger" onClick={() => confirm(t("Revoke \"{name}\"? Anything using it stops working now.", { name: k.name })) && revoke.mutate()}>
          {t("Revoke")}</button>
      </div>
      {usage && (
        <div className="usage">
          <p className="xs muted">
            {t("Scopes:")}{" "}<span className="data">{k.scopes.join(", ")}</span>
            {k.ipAllow.length > 0 && (
              <>
                {" "}
                {t("Only from")}{" "}<span className="data">{k.ipAllow.join(", ")}</span>.
              </>
            )}{" "}
            {t("Up to")}{" "}{k.ratePerMin} {t("requests a minute.")}</p>
          {log.data?.length === 0 && <p className="xs muted">{t("No requests in the last 30 days.")}</p>}
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
      <h2>{t("New API key")}</h2>
      <label className="field">
        <span>{t("Name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("Assistant on my laptop")} required />
      </label>
      <fieldset className="kinds">
        <legend className="small">{t("Used by")}</legend>
        {(["agent", "live", "test"] as const).map((k) => (
          <label key={k} className={`kind ${kind === k ? "on" : ""}`}>
            <input type="radio" name="kind" checked={kind === k} onChange={() => setKind(k)} />
            <strong>{k === "agent" ? t("An AI agent") : k === "live" ? t("A program") : t("Testing")}</strong>
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
          <span>{t("Only from these addresses (optional)")}</span>
          <input className="data" value={ips} onChange={(e) => setIps(e.target.value)} placeholder="192.168.1.0/24" />
        </label>
        <label className="field">
          <span>{t("Expires")}</span>
          <select value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="30">{t("in 30 days")}</option>
            <option value="90">{t("in 90 days")}</option>
            <option value="365">{t("in a year")}</option>
            <option value="">{t("never")}</option>
          </select>
        </label>
      </div>
      {create.error && <div className="error">{create.error.message}</div>}
      <div className="inline" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn quiet" onClick={() => onDone("")}>
          {t("Cancel")}</button>
        <button className="btn primary" disabled={create.isPending || scopes.length === 0}>
          {t("Create key")}</button>
      </div>
    </form>
  );
}
