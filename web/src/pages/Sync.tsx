import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok } from "../api/client";
import { ago } from "../lib/format";
import "./pages.css";

type Coll = "vault" | "policy" | "automations";

/** Settings section: keep the vault, rules and automations the same on several daemons. */
export function SyncSection({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["sync"], queryFn: () => ok(api.GET("/sync")), enabled: admin, refetchInterval: 30_000 });
  const [mode, setMode] = useState<"idle" | "start" | "join">("idle");
  const [chosen, setChosen] = useState<Coll[]>(["vault", "policy"]);
  const [joinCode, setJoinCode] = useState("");
  const [peers, setPeers] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["sync"] });
  const peerList = () => peers.split(/[\s,]+/).filter(Boolean);

  const start = useMutation({
    mutationFn: () => ok(api.POST("/sync/group", { body: { collections: chosen, peers: peerList() } })),
    onSuccess: (r) => {
      setCode(r.code);
      setMode("idle");
      refresh();
    },
  });
  const join = useMutation({
    mutationFn: () => ok(api.POST("/sync/join", { body: { code: joinCode, collections: chosen, peers: peerList() } })),
    onSuccess: () => {
      setMode("idle");
      setJoinCode("");
      refresh();
    },
  });
  const run = useMutation({ mutationFn: () => ok(api.POST("/sync/run")), onSuccess: refresh });
  const showCode = useMutation({ mutationFn: () => ok(api.GET("/sync/code")), onSuccess: (r) => setCode(r.code) });
  const save = useMutation({
    mutationFn: (body: { collections?: Coll[]; peers?: string[] }) => ok(api.PUT("/sync/settings", { body })),
    onSuccess: refresh,
  });
  const leave = useMutation({ mutationFn: () => ok(api.DELETE("/sync/group")), onSuccess: refresh });
  if (!admin || !st.data) return null;
  const s = st.data;

  const picker = (current: Coll[], onChange: (v: Coll[]) => void) => (
    <div className="stack" style={{ gap: 6 }}>
      {s.available.map((c) => (
        <label className="check" key={c.name}>
          <input
            type="checkbox"
            checked={current.includes(c.name as Coll)}
            onChange={(e) => onChange(e.target.checked ? [...current, c.name as Coll] : current.filter((x) => x !== c.name))}
          />
          <span>
            <strong>{label(c.name)}</strong> <span className="muted small">{c.description}</span>
          </span>
        </label>
      ))}
    </div>
  );

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">Sync</h2>
      <p className="small muted">
        Keep secrets, agent rules and automations the same on your other computers running Conduit. Everything is encrypted
        with a key only your computers have, through your hub or directly on your network.
      </p>

      {code && (
        <div className="panel runner secret-once" role="status">
          <h2>Join code</h2>
          <p className="small">
            Enter this on your other computer under Settings, Sync. Anyone with it can read and change what you sync, so treat
            it like a password.
          </p>
          <div className="inline">
            <code className="secret-value">{code}</code>
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(code)}>
              Copy
            </button>
          </div>
          <div>
            <button className="btn sm quiet" onClick={() => setCode(null)}>
              Done
            </button>
          </div>
        </div>
      )}

      {!s.enabled && mode === "idle" && (
        <div className="inline">
          <button className="btn" onClick={() => setMode("start")}>
            Start syncing
          </button>
          <button className="btn quiet" onClick={() => setMode("join")}>
            Join with a code
          </button>
        </div>
      )}

      {!s.enabled && mode !== "idle" && (
        <form
          className="panel runner stack"
          onSubmit={(e) => {
            e.preventDefault();
            (mode === "start" ? start : join).mutate();
          }}
        >
          {mode === "join" && (
            <label className="field">
              <span>Join code from your other computer</span>
              <input className="data" value={joinCode} onChange={(e) => setJoinCode(e.target.value)} placeholder="conduit-sync-…" required autoComplete="off" />
            </label>
          )}
          <div className="field">
            <span>What to sync</span>
            {picker(chosen, setChosen)}
          </div>
          <label className="field">
            <span>Computers on your network (optional)</span>
            <input className="data" value={peers} onChange={(e) => setPeers(e.target.value)} placeholder="http://192.168.1.20:7600" />
            <small>To sync without a hub. The other computer has to listen on your network.</small>
          </label>
          {(start.error || join.error) && <div className="error">{(start.error || join.error)!.message}</div>}
          <div className="inline">
            <button type="button" className="btn quiet" onClick={() => setMode("idle")}>
              Cancel
            </button>
            <button className="btn primary" disabled={start.isPending || join.isPending}>
              {mode === "start" ? "Start syncing" : "Join"}
            </button>
          </div>
        </form>
      )}

      {s.enabled && (
        <div className="panel stack remote-panel">
          <div className="spread">
            <span className="small">
              Group <span className="data">{s.groupId}</span>,{" "}
              {s.viaHub ? "through your hub" : "not linked to a hub"}
              {s.peers.length > 0 && `, and directly with ${s.peers.length === 1 ? "1 computer" : `${s.peers.length} computers`}`}
            </span>
            <div className="inline">
              <button className="btn sm" onClick={() => run.mutate()} disabled={run.isPending}>
                Sync now
              </button>
              <button className="btn sm quiet" onClick={() => showCode.mutate()}>
                Add a computer
              </button>
            </div>
          </div>
          {picker(s.collections as Coll[], (v) => save.mutate({ collections: v }))}
          <label className="field">
            <span>Computers on your network</span>
            <input
              className="data"
              defaultValue={s.peers.join(" ")}
              onBlur={(e) => {
                const v = e.target.value.split(/[\s,]+/).filter(Boolean);
                if (v.join(" ") !== s.peers.join(" ")) save.mutate({ peers: v });
              }}
              placeholder="http://192.168.1.20:7600"
            />
          </label>
          {save.error && <div className="error">{save.error.message}</div>}
          {s.lastRun && (
            <div className="stack" style={{ gap: 4 }}>
              <span className="xs muted">Last synced {ago(s.lastRun)}</span>
              {s.results.map((r, i) => (
                <div className="inline xs" key={i}>
                  <span className={r.ok ? "state-ok" : r.skipped ? "muted" : "state-down"}>{r.ok ? "Synced" : r.skipped ? "Skipped" : "Failed"}</span>
                  <span>{label(r.collection)}</span>
                  {r.transport && <span className="muted data">{r.transport}</span>}
                  <span className="muted">
                    {r.ok ? `${r.sent} sent, ${r.received} received` : r.skipped || r.error}
                  </span>
                </div>
              ))}
            </div>
          )}
          <div>
            <button className="btn sm danger" onClick={() => leave.mutate()}>
              Stop syncing on this computer
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

function label(name: string) {
  return name === "vault" ? "Vault" : name === "policy" ? "Agent rules" : name === "automations" ? "Automations" : name;
}
