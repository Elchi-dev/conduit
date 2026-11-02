import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { api, ok } from "../api/client";
import { actorLabel, ago } from "../lib/format";
import { ApprovalCard } from "./Approvals";
import "./pages.css";

function greeting() {
  const h = new Date().getHours();
  return h < 5 ? "Working late" : h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

export function Home() {
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => ok(api.GET("/instances")) });
  const pending = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => ok(api.GET("/approvals", { params: { query: { status: "pending" } } })),
  });
  const recent = useQuery({ queryKey: ["audit", "home"], queryFn: () => ok(api.GET("/audit", { params: { query: { limit: 12 } } })) });
  const list = instances.data ?? [];
  const health = useQueries({
    queries: list.map((i) => ({
      queryKey: ["instances", i.id, "health"],
      queryFn: () => ok(api.GET("/instances/{id}/health", { params: { path: { id: i.id } } })),
      enabled: i.enabled,
    })),
  });
  const down = list.filter((_, n) => health[n]?.data && health[n].data!.status !== "ok");
  const waiting = pending.data ?? [];

  const summary =
    list.length === 0
      ? "Nothing is connected yet."
      : down.length === 0
        ? `All ${list.length} connected ${list.length === 1 ? "system is" : "systems are"} working.`
        : `${down.length} of ${list.length} need attention.`;

  return (
    <div className="page">
      <div className="page-head">
        <h1>{greeting()}.</h1>
        <p>
          {summary}
          {waiting.length > 0 && ` ${waiting.length} ${waiting.length === 1 ? "request is" : "requests are"} waiting for your approval.`}
        </p>
      </div>

      {list.length === 0 && (
        <div className="empty start">
          <h2>Connect your first system</h2>
          <p className="muted">
            Start with whatever you check most: your mail, a server, your PC itself. Each one gets a lamp in the top row.
          </p>
          <Link href="/modules" className="btn primary" style={{ justifySelf: "start" }}>
            Browse modules
          </Link>
        </div>
      )}

      {down.length > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <h2 className="section-title">Needs attention</h2>
          <div className="panel rows">
            {down.map((i) => {
              const h = health[list.indexOf(i)].data!;
              return (
                <Link key={i.id} href={`/i/${i.id}`} className="row attention-row">
                  <span className={`lamp ${h.status}`} style={{ padding: 0 }}>
                    <span className="bulb" />
                  </span>
                  <strong>{i.name}</strong>
                  <span className="small muted">{h.message || h.status}</span>
                </Link>
              );
            })}
          </div>
        </section>
      )}

      {waiting.length > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <h2 className="section-title">Waiting for you</h2>
          {waiting.slice(0, 3).map((a) => (
            <ApprovalCard key={a.id} a={a} />
          ))}
          {waiting.length > 3 && (
            <Link href="/approvals" className="small">
              See all {waiting.length}
            </Link>
          )}
        </section>
      )}

      {(recent.data?.length ?? 0) > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <div className="spread">
            <h2 className="section-title">Latest activity</h2>
            <Link href="/timeline" className="small muted">
              Full timeline
            </Link>
          </div>
          <div className="panel rows">
            {recent.data!.map((e) => (
              <div className="row recent-row" key={e.seq}>
                <span className="small">
                  <span className="data">{e.action}</span> <span className="muted">on {e.module}</span>
                </span>
                <span className="xs muted">{actorLabel(e.actor)}</span>
                <span className={`tag st-${e.status}`}>{e.status}</span>
                <span className="xs muted">{ago(e.at)}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
