import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type Approval } from "../api/client";
import { PlanView } from "../components/PlanView";
import { actorLabel, ago, json } from "../lib/format";
import "./pages.css";

export function Approvals() {
  const [tab, setTab] = useState<"pending" | "">("pending");
  const q = useQuery({
    queryKey: ["approvals", tab],
    queryFn: () => ok(api.GET("/approvals", { params: { query: tab ? { status: tab } : {} } })),
  });
  return (
    <div className="page">
      <div className="page-head">
        <h1>Approvals</h1>
        <p>Agents and keys ask here before doing anything your rules don't allow outright. You see exactly what will change.</p>
      </div>
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "pending"} onClick={() => setTab("pending")}>
          Waiting
        </button>
        <button role="tab" aria-selected={tab === ""} onClick={() => setTab("")}>
          All
        </button>
      </div>
      {q.error && <div className="error">{q.error.message}</div>}
      {q.data?.length === 0 && (
        <div className="empty">
          <h2>{tab === "pending" ? "Nothing is waiting for you" : "No approvals yet"}</h2>
          <p className="muted">When an agent wants to change something, the request appears here and on your other devices.</p>
        </div>
      )}
      <div className="stack">
        {q.data?.map((a) => <ApprovalCard key={a.id} a={a} />)}
      </div>
    </div>
  );
}

export function ApprovalCard({ a }: { a: Approval }) {
  const qc = useQueryClient();
  const decide = useMutation({
    mutationFn: (approve: boolean) =>
      ok(
        approve
          ? api.POST("/approvals/{id}/approve", { params: { path: { id: a.id } } })
          : api.POST("/approvals/{id}/deny", { params: { path: { id: a.id } } }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });
  const pending = a.status === "pending";
  return (
    <article className={`panel approval ${pending ? "is-pending" : ""}`}>
      <header className="spread">
        <div className="stack" style={{ gap: 2 }}>
          <h2>
            {actorLabel(a.actor)} wants to run <span className="data">{a.action}</span>
          </h2>
          <p className="xs muted">
            on {a.module} (<span className="data">{a.instance}</span>), {ago(a.createdAt)}
          </p>
        </div>
        <span className={`tag ${a.risk}`}>{a.risk}</span>
      </header>
      {a.plan ? (
        <PlanView plan={a.plan} />
      ) : (
        a.input != null && <pre className="json">{json(a.input)}</pre>
      )}
      <footer className="spread">
        {pending ? (
          <>
            <span className="xs muted">Expires {ago(a.expiresAt)}</span>
            <div className="inline">
              <button className="btn" onClick={() => decide.mutate(false)} disabled={decide.isPending}>
                Deny
              </button>
              <button className="btn signal" onClick={() => decide.mutate(true)} disabled={decide.isPending}>
                Approve
              </button>
            </div>
          </>
        ) : (
          <span className="xs muted">
            {a.status === "approved" ? "Approved" : a.status === "denied" ? "Denied" : "Expired"}
            {a.decidedAt ? ` ${ago(a.decidedAt)}` : ""}
          </span>
        )}
      </footer>
      {decide.error && <div className="error">{decide.error.message}</div>}
    </article>
  );
}
