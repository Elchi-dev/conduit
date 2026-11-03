import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { confirmWithDevice } from "../lib/native";
import { api, ok, type Approval } from "../api/client";
import { PlanView } from "../components/PlanView";
import { actorLabel, ago, json } from "../lib/format";
import { t } from "../i18n";
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
        <h1>{t("Approvals")}</h1>
        <p>{t("Agents and keys ask here before doing anything your rules don't allow outright. You see exactly what will change.")}</p>
      </div>
      <div className="tabs" role="tablist">
        <button role="tab" aria-selected={tab === "pending"} onClick={() => setTab("pending")}>
          {t("Waiting")}</button>
        <button role="tab" aria-selected={tab === ""} onClick={() => setTab("")}>
          {t("All")}</button>
      </div>
      {q.error && <div className="error">{q.error.message}</div>}
      {q.data?.length === 0 && (
        <div className="empty">
          <h2>{tab === "pending" ? t("Nothing is waiting for you") : t("No approvals yet")}</h2>
          <p className="muted">{t("When an agent wants to change something, the request appears here and on your other devices.")}</p>
        </div>
      )}
      <div className="stack">
        {q.data?.map((a) => <ApprovalCard key={a.id} a={a} />)}
      </div>
    </div>
  );
}

export function ApprovalCard({ a, onDecided }: { a: Approval; onDecided?: (approved: boolean) => void }) {
  const qc = useQueryClient();
  const decide = useMutation({
    mutationFn: async (approve: boolean) => {
      // On the phone app, approving is confirmed with a fingerprint, face or
      // PIN: the phone acts as a hardware key for risky actions.
      if (approve && !(await confirmWithDevice(`Approve ${a.action} on ${a.instance}`))) {
        throw new Error(t("Not approved: the confirmation on this device was cancelled."));
      }
      return ok(
        approve
          ? api.POST("/approvals/{id}/approve", { params: { path: { id: a.id } } })
          : api.POST("/approvals/{id}/deny", { params: { path: { id: a.id } } }),
      );
    },
    onSuccess: (res, approve) => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      setDecided(res?.status ?? (approve ? "approved" : "denied"));
      onDecided?.(approve);
    },
  });
  const [decided, setDecided] = useState<string | null>(null);
  const status = decided ?? a.status;
  const pending = status === "pending";
  return (
    <article className={`panel approval ${pending ? "is-pending" : ""}`}>
      <header className="spread">
        <div className="stack" style={{ gap: 2 }}>
          <h2>
            {actorLabel(a.actor)} {t("wants to run")}{" "}<span className="data">{a.action}</span>
          </h2>
          <p className="xs muted">
            {t("on")}{" "}{a.module} (<span className="data">{a.instance}</span>), {ago(a.createdAt)}
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
            <span className="xs muted">{t("Expires")}{" "}{ago(a.expiresAt)}</span>
            <div className="inline">
              <button className="btn" onClick={() => decide.mutate(false)} disabled={decide.isPending}>
                {t("Deny")}</button>
              <button className="btn signal" onClick={() => decide.mutate(true)} disabled={decide.isPending}>
                {t("Approve")}</button>
            </div>
          </>
        ) : (
          <span className="xs muted">
            {status === "approved" ? t("Approved") : status === "denied" ? t("Denied") : t("Expired")}
            {a.decidedAt ? ` ${ago(a.decidedAt)}` : ""}
            {a.resultSeq != null && <>{t(", ran as timeline entry")}{" "}{a.resultSeq}</>}
          </span>
        )}
      </footer>
      {decide.error && <div className="error">{decide.error.message}</div>}
    </article>
  );
}
