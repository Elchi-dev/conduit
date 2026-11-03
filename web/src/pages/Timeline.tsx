import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import { api, ok, type AuditEntry } from "../api/client";
import { actorLabel, ago, json, stamp } from "../lib/format";
import "./pages.css";

const statusText: Record<string, string> = {
  ok: "Done",
  error: "Failed",
  denied: "Blocked",
  planned: "Dry run",
};

export function Timeline() {
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const list = useInfiniteQuery({
    queryKey: ["audit", search],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      ok(api.GET("/audit", { params: { query: { q: search || undefined, before: pageParam || undefined, limit: 50 } } })),
    getNextPageParam: (last) => (last.length === 50 ? last[last.length - 1].seq : undefined),
  });
  const verify = useQuery({ queryKey: ["audit", "verify"], queryFn: () => ok(api.GET("/audit/verify")) });
  const entries = list.data?.pages.flat() ?? [];
  const [picked, setPicked] = useState<number[]>([]);
  const [, go] = useLocation();
  const qc = useQueryClient();
  const toggle = (seq: number) => setPicked((p) => (p.includes(seq) ? p.filter((x) => x !== seq) : [...p, seq]));
  const recordable = (e: AuditEntry) => e.status === "ok" && !e.dryRun && e.module !== "core" && !JSON.stringify(e.input ?? "").includes("[redacted]");
  const record = useMutation({
    mutationFn: () => {
      const steps = entries
        .filter((e) => picked.includes(e.seq))
        .sort((a, b) => a.seq - b.seq)
        .map((e) => ({ instance: e.instance, action: e.action, input: e.input ?? {} }));
      return ok(api.POST("/automations", { body: { name: `Recorded ${new Date().toLocaleDateString()}`, enabled: false, trigger: { kind: "manual" }, steps } }));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["automations"] });
      go("/automations");
    },
  });

  return (
    <div className="page">
      <div className="page-head">
        <h1>Timeline</h1>
        <p>Everything that happened, by anyone or anything, newest first. Reversible actions can be undone from here.</p>
      </div>
      <div className="spread">
        <form
          className="inline"
          onSubmit={(e) => {
            e.preventDefault();
            setSearch(q);
          }}
        >
          <input className="input" style={{ width: 280 }} placeholder="Search actions and data" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn">Search</button>
        </form>
        {verify.data &&
          (verify.data.ok ? (
            <span className="xs muted">Log intact: all {verify.data.entries} entries verified</span>
          ) : (
            <span className="xs" style={{ color: "var(--fault)" }}>
              Log tampered at entry {verify.data.brokenAt}: {verify.data.problem}
            </span>
          ))}
      </div>
      <WhatChanged />
      {picked.length > 0 && (
        <div className="panel runner record-bar" role="status">
          <span className="small">
            {picked.length} {picked.length === 1 ? "step" : "steps"} picked. Turn them into an automation you can run again or schedule.
          </span>
          <div className="inline">
            <button className="btn sm quiet" onClick={() => setPicked([])}>
              Clear
            </button>
            <button className="btn sm primary" onClick={() => record.mutate()} disabled={record.isPending}>
              Make an automation
            </button>
          </div>
          {record.error && <div className="error">{record.error.message}</div>}
        </div>
      )}
      {entries.length === 0 && !list.isPending && (
        <div className="empty">
          <h2>{search ? "No matches" : "Nothing has happened yet"}</h2>
          <p className="muted">Every action, approval and change appears here as it happens.</p>
        </div>
      )}
      <ol className="timeline">
        {entries.map((e) => (
          <TimelineRow key={e.seq} e={e} picked={picked.includes(e.seq)} onPick={recordable(e) ? () => toggle(e.seq) : undefined} />
        ))}
      </ol>
      {list.hasNextPage && (
        <button className="btn" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
          Load older
        </button>
      )}
    </div>
  );
}

function TimelineRow({ e, picked, onPick }: { e: AuditEntry; picked: boolean; onPick?: () => void }) {
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const undo = useMutation({
    mutationFn: () => ok(api.POST("/audit/{seq}/undo", { params: { path: { seq: e.seq } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["audit"] }),
  });
  const canUndo = e.undo && !e.undoneBy && e.status === "ok";
  return (
    <li className={`tl tl-${e.status}`}>
      <span className="tl-dot" aria-hidden="true" />
      <div className="tl-body">
        <div className="spread">
          <div className="inline" style={{ flexWrap: "nowrap" }}>
            {onPick && <input type="checkbox" checked={picked} onChange={onPick} aria-label="Pick this step for a new automation" title="Pick for a new automation" />}
          <button className="tl-title" onClick={() => setOpen(!open)} aria-expanded={open}>
            <strong>{actorLabel(e.actor)}</strong> <span className="muted">ran</span> <span className="data">{e.action}</span>{" "}
            <span className="muted">on {e.module}</span>
          </button>
          </div>
          <div className="inline">
            {e.undoneBy && <span className="tag">Undone</span>}
            {e.undoes && <span className="tag">Undo of #{e.undoes}</span>}
            <span className={`tag st-${e.status}`}>{statusText[e.status] ?? e.status}</span>
            {canUndo && (
              <button className="btn sm" onClick={() => undo.mutate()} disabled={undo.isPending} title={e.undo?.description}>
                Undo
              </button>
            )}
            <time className="xs muted" dateTime={e.at} title={stamp(e.at)}>
              {ago(e.at)}
            </time>
          </div>
        </div>
        {e.error && <p className="small" style={{ color: "var(--fault)" }}>{e.error}</p>}
        {undo.error && <div className="error">{undo.error.message}</div>}
        {open && (
          <div className="tl-detail">
            <dl className="kv xs">
              <dt>Entry</dt>
              <dd className="data">#{e.seq}</dd>
              <dt>Instance</dt>
              <dd className="data">{e.instance}</dd>
              <dt>Risk</dt>
              <dd>{e.risk}</dd>
              <dt>Policy</dt>
              <dd>{e.decision}</dd>
              <dt>Hash</dt>
              <dd className="data">{e.hash.slice(0, 16)}…</dd>
            </dl>
            {e.input != null && (
              <>
                <p className="xs muted">Input</p>
                <pre className="json">{json(e.input)}</pre>
              </>
            )}
            {e.output != null && (
              <>
                <p className="xs muted">Result</p>
                <pre className="json">{json(e.output)}</pre>
              </>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

function WhatChanged() {
  const [open, setOpen] = useState(false);
  const [minutes, setMinutes] = useState(60);
  const [at, setAt] = useState("");
  const q = useQuery({
    queryKey: ["audit", "changes", minutes, at],
    queryFn: () => ok(api.GET("/audit/changes", { params: { query: { minutes, at: at ? new Date(at).toISOString() : undefined } } })),
    enabled: open,
  });
  if (!open) {
    return (
      <div>
        <button className="btn" onClick={() => setOpen(true)}>
          What changed?
        </button>
      </div>
    );
  }
  const d = q.data;
  const section = (title: string, rows: NonNullable<typeof d>["changes"], tone?: string) =>
    rows.length > 0 && (
      <div className="stack" style={{ gap: 6 }}>
        <h3 className="section-title" style={tone ? { color: tone } : undefined}>
          {title}
        </h3>
        <div className="panel rows">
          {rows.map((r) => (
            <div className="row recent-row" key={r.entry}>
              <span className="small">
                <span className="data">{r.what}</span>
                {r.error && <span style={{ color: "var(--fault)" }}> {r.error}</span>}
              </span>
              <span className="xs muted">{r.who}</span>
              <span className="xs muted">#{r.entry}</span>
              <span className="xs muted">{ago(r.at)}</span>
            </div>
          ))}
        </div>
      </div>
    );
  return (
    <section className="panel runner">
      <div className="spread">
        <h2>What changed?</h2>
        <button className="btn sm quiet" onClick={() => setOpen(false)}>
          Close
        </button>
      </div>
      <div className="rule-grid">
        <label className="field">
          <span>Before</span>
          <input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} />
          <small>Leave empty for now.</small>
        </label>
        <label className="field">
          <span>Looking back</span>
          <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            <option value={15}>15 minutes</option>
            <option value={60}>1 hour</option>
            <option value={360}>6 hours</option>
            <option value={1440}>1 day</option>
            <option value={10080}>1 week</option>
          </select>
        </label>
      </div>
      {d && d.changes.length + d.failures.length + d.blocked.length === 0 && (
        <p className="small muted">Nothing changed in this window{d.readsOmitted ? `; there were ${d.readsOmitted} reads` : ""}.</p>
      )}
      {d && section("Failed", d.failures, "var(--fault)")}
      {d && section("Changed", d.changes)}
      {d && section("Blocked by your rules", d.blocked)}
      {d && d.readsOmitted > 0 && <p className="xs muted">{d.readsOmitted} reads in this window are left out because they change nothing.</p>}
    </section>
  );
}
