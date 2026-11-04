import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type S } from "../api/client";
import { ago } from "../lib/format";
import { t, tn } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

type Webhook = S["Webhook"];

/** Settings section: outbound webhooks, signed with HMAC. */
export function Webhooks({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["webhooks"], queryFn: () => ok(api.GET("/webhooks")), enabled: admin });
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [secret, setSecret] = useState<{ name: string; value: string } | null>(null);
  const [f, setF] = useState({ name: "", url: "https://", events: "" });
  const create = useMutation({
    mutationFn: () =>
      ok(
        api.POST("/webhooks", {
          body: { name: f.name, url: f.url, events: f.events.split(/[\s,]+/).filter(Boolean) },
        }),
      ),
    onSuccess: (w) => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      setAdding(false);
      setF({ name: "", url: "https://", events: "" });
      if (w.secret) setSecret({ name: w.name, value: w.secret });
    },
  });
  const toggle = useMutation({
    mutationFn: (w: Webhook) => ok(api.PATCH("/webhooks/{id}", { params: { path: { id: w.id } }, body: { enabled: !w.enabled } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/webhooks/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });
  const rotate = useMutation({
    mutationFn: (w: Webhook) => ok(api.POST("/webhooks/{id}/rotate", { params: { path: { id: w.id } } })).then((r) => ({ name: w.name, value: r.secret })),
    onSuccess: (s) => setSecret(s),
  });
  if (!admin) return null;

  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <h2 className="section-title">{t("Webhooks")}</h2>
        {!adding && (
          <button className="btn sm" onClick={() => setAdding(true)}>
            {t("Add webhook")}</button>
        )}
      </div>
      <p className="small muted">
        {t("Send events to your own service as they happen, signed so it can tell they came from here. See the")}{" "}
        <a href="https://github.com/Elchi-dev/conduit/blob/main/docs/api/webhooks.md">{t("signature format")}</a>.
      </p>

      {secret && (
        <div className="panel runner secret-once" role="status">
          <h2>{t("Copy the signing secret now")}</h2>
          <p className="small">{t("This is the only time the secret for \"")}{secret.name}{t("\" is shown. Your receiver needs it to check signatures.")}</p>
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

      {adding && (
        <form
          className="panel runner stack"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <label className="field">
            <span>{t("Name")}</span>
            <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder={t("Deploy bot")} />
          </label>
          <label className="field">
            <span>{"URL"}</span>
            <input className="data" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} required />
          </label>
          <label className="field">
            <span>{t("Events")}</span>
            <input className="data" value={f.events} onChange={(e) => setF({ ...f, events: e.target.value })} placeholder={"action.error approval.requested"} />
            <small>{t("Event types or their beginnings, separated by spaces. Leave empty for everything.")}</small>
          </label>
          <ErrorNote error={create.error} />
          <div className="inline">
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>
              {t("Cancel")}</button>
            <button className="btn primary" disabled={create.isPending}>
              {t("Add webhook")}</button>
          </div>
        </form>
      )}

      {(list.data?.length ?? 0) > 0 && (
        <div className="panel rows">
          {list.data!.map((w) => (
            <div key={w.id}>
              <div className="row key-row">
                <div className="stack" style={{ gap: 2 }}>
                  <strong>{w.name}</strong>
                  <span className="xs muted data">{w.url}</span>
                </div>
                <span className="xs muted data">{w.events.length ? w.events.join(" ") : t("every event")}</span>
                {w.enabled ? (
                  w.failures > 0 ? <span className="tag warn">{w.failures} {t("failed")}</span> : <span className="tag">{t("On")}</span>
                ) : (
                  <span className="tag">{t("Off")}</span>
                )}
                <div className="inline">
                  <button className="btn sm quiet" onClick={() => setOpen(open === w.id ? null : w.id)} aria-expanded={open === w.id}>
                    {t("Deliveries")}</button>
                  <button className="btn sm quiet" onClick={() => toggle.mutate(w)}>
                    {w.enabled ? t("Switch off") : t("Switch on")}
                  </button>
                  <button className="btn sm quiet" onClick={() => rotate.mutate(w)}>
                    {t("New secret")}</button>
                  <button className="btn sm danger" onClick={() => remove.mutate(w.id)}>
                    {t("Remove")}</button>
                </div>
              </div>
              {open === w.id && <Deliveries id={w.id} />}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function Deliveries({ id }: { id: string }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["webhooks", id, "deliveries"], queryFn: () => ok(api.GET("/webhooks/{id}/deliveries", { params: { path: { id }, query: { limit: 20 } } })) });
  const test = useMutation({
    mutationFn: () => ok(api.POST("/webhooks/{id}/test", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks", id, "deliveries"] }),
  });
  return (
    <div className="stack" style={{ gap: 6, padding: "8px 12px 12px" }}>
      <div>
        <button className="btn sm" onClick={() => test.mutate()} disabled={test.isPending}>
          {t("Send a test event")}</button>
      </div>
      {list.data?.length === 0 && <p className="xs muted">{t("Nothing sent yet.")}</p>}
      {list.data?.map((d) => (
        <div className="inline xs" key={d.id}>
          <span className={d.ok ? "state-ok" : "state-down"}>{d.ok ? t("Delivered") : t("Failed")}</span>
          <span className="data">{d.event}</span>
          <span className="muted">
            {d.status ? `HTTP ${d.status}` : t("no answer")}, {tn("{n} try", "{n} tries", d.attempts)}, {t("{ms} ms,", { ms: d.durationMs })}{" "}{ago(d.at)}
          </span>
          {d.error && <span className="muted">{d.error}</span>}
        </div>
      ))}
    </div>
  );
}
