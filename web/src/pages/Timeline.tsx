import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
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
      {entries.length === 0 && !list.isPending && (
        <div className="empty">
          <h2>{search ? "No matches" : "Nothing has happened yet"}</h2>
          <p className="muted">Every action, approval and change appears here as it happens.</p>
        </div>
      )}
      <ol className="timeline">
        {entries.map((e) => (
          <TimelineRow key={e.seq} e={e} />
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

function TimelineRow({ e }: { e: AuditEntry }) {
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
          <button className="tl-title" onClick={() => setOpen(!open)} aria-expanded={open}>
            <strong>{actorLabel(e.actor)}</strong> <span className="muted">ran</span> <span className="data">{e.action}</span>{" "}
            <span className="muted">on {e.module}</span>
          </button>
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
