import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import { api, ok, type AuditEntry } from "../api/client";
import { actorLabel, ago, json, stamp } from "../lib/format";
import { locale, t, tn } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

const statusText: Record<string, string> = {
  ok: t("Done"),
  error: t("Failed"),
  denied: t("Blocked"),
  planned: t("Dry run"),
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
      return ok(api.POST("/automations", { body: { name: t("Recorded {date}", { date: new Date().toLocaleDateString(locale()) }), enabled: false, trigger: { kind: "manual" }, steps } }));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["automations"] });
      go("/automations");
    },
  });

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Timeline")}</h1>
        <p>{t("Everything that happened, by anyone or anything, newest first. Reversible actions can be undone from here.")}</p>
      </div>
      <div className="spread">
        <form
          className="inline"
          onSubmit={(e) => {
            e.preventDefault();
            setSearch(q);
          }}
        >
          <input className="input" style={{ width: 280, maxWidth: "100%" }} aria-label={t("Search actions and data")} placeholder={t("Search actions and data")} value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn">{t("Search")}</button>
        </form>
        {verify.data &&
          (verify.data.ok ? (
            <span className="xs muted">{t("Log intact: all")}{" "}{verify.data.entries} {t("entries verified")}</span>
          ) : (
            <span className="xs" style={{ color: "var(--fault)" }}>
              {t("Log tampered at entry")}{" "}{verify.data.brokenAt}: {verify.data.problem}
            </span>
          ))}
      </div>
      <WhatChanged />
      {picked.length > 0 && (
        <div className="panel runner record-bar" role="status">
          <span className="small">
            {tn("{n} step picked. Turn them into an automation you can run again or schedule.", "{n} steps picked. Turn them into an automation you can run again or schedule.", picked.length)}</span>
          <div className="inline">
            <button className="btn sm quiet" onClick={() => setPicked([])}>
              {t("Clear")}</button>
            <button className="btn sm primary" onClick={() => record.mutate()} disabled={record.isPending}>
              {t("Make an automation")}</button>
          </div>
          <ErrorNote error={record.error} />
        </div>
      )}
      {entries.length === 0 && !list.isPending && (
        <div className="empty">
          <h2>{search ? t("No matches") : t("Nothing has happened yet")}</h2>
          <p className="muted">
            {search
              ? t("Nothing in the timeline matches \"{q}\". Try a module name, a person, or an action like restart.", { q: search })
              : t("Every action, approval and change appears here as it happens.")}
          </p>
          {search && (
            <div className="inline">
              <button className="btn" onClick={() => { setSearch(""); setQ(""); }}>
                {t("Clear search")}
              </button>
            </div>
          )}
        </div>
      )}
      <ol className="timeline">
        {entries.map((e) => (
          <TimelineRow key={e.seq} e={e} picked={picked.includes(e.seq)} onPick={recordable(e) ? () => toggle(e.seq) : undefined} />
        ))}
      </ol>
      {list.hasNextPage && (
        <button className="btn" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
          {t("Load older")}</button>
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
            {onPick && <input type="checkbox" checked={picked} onChange={onPick} aria-label={t("Pick this step for a new automation")} title={t("Pick for a new automation")} />}
          <button className="tl-title" onClick={() => setOpen(!open)} aria-expanded={open}>
            <strong>{actorLabel(e.actor)}</strong> <span className="muted">{t("ran")}</span> <span className="data">{e.action}</span>{" "}
            <span className="muted">{t("on")}{" "}{e.module}</span>
          </button>
          </div>
          <div className="inline">
            {e.undoneBy && <span className="tag">{t("Undone")}</span>}
            {e.undoes && <span className="tag">{t("Undo of #")}{e.undoes}</span>}
            <span className={`tag st-${e.status}`}>{statusText[e.status] ?? e.status}</span>
            {canUndo && (
              <button className="btn sm" onClick={() => undo.mutate()} disabled={undo.isPending} title={e.undo?.description}>
                {t("Undo")}</button>
            )}
            <time className="xs muted" dateTime={e.at} title={stamp(e.at)}>
              {ago(e.at)}
            </time>
          </div>
        </div>
        {e.error && <p className="small" style={{ color: "var(--fault)" }}>{e.error}</p>}
        <ErrorNote error={undo.error} />
        {open && (
          <div className="tl-detail">
            <dl className="kv xs">
              <dt>{t("Entry")}</dt>
              <dd className="data">#{e.seq}</dd>
              <dt>{t("Instance")}</dt>
              <dd className="data">{e.instance}</dd>
              <dt>{t("Risk")}</dt>
              <dd>{e.risk}</dd>
              <dt>{t("Policy")}</dt>
              <dd>{e.decision}</dd>
              <dt>{t("Hash")}</dt>
              <dd className="data">{e.hash.slice(0, 16)}…</dd>
            </dl>
            {e.input != null && (
              <>
                <p className="xs muted">{t("Input")}</p>
                <pre className="json">{json(e.input)}</pre>
              </>
            )}
            {e.output != null && (
              <>
                <p className="xs muted">{t("Result")}</p>
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
          {t("What changed?")}</button>
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
        <h2>{t("What changed?")}</h2>
        <button className="btn sm quiet" onClick={() => setOpen(false)}>
          {t("Close")}</button>
      </div>
      <div className="rule-grid">
        <label className="field">
          <span>{t("Before")}</span>
          <input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} />
          <small>{t("Leave empty for now.")}</small>
        </label>
        <label className="field">
          <span>{t("Looking back")}</span>
          <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            <option value={15}>{t("15 minutes")}</option>
            <option value={60}>{t("1 hour")}</option>
            <option value={360}>{t("6 hours")}</option>
            <option value={1440}>{t("1 day")}</option>
            <option value={10080}>{t("1 week")}</option>
          </select>
        </label>
      </div>
      {d && d.changes.length + d.failures.length + d.blocked.length === 0 && (
        <p className="small muted">{t("Nothing changed in this window")}{d.readsOmitted ? tn("; there was {n} read", "; there were {n} reads", d.readsOmitted) : ""}.</p>
      )}
      {d && section(t("Failed"), d.failures, "var(--fault)")}
      {d && section(t("Changed"), d.changes)}
      {d && section(t("Blocked by your rules"), d.blocked)}
      {d && d.readsOmitted > 0 && <p className="xs muted">{tn("{n} read in this window is left out because it changes nothing.", "{n} reads in this window are left out because they change nothing.", d.readsOmitted)}</p>}
    </section>
  );
}
