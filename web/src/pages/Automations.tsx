import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type S } from "../api/client";
import { SchemaForm, type JSONSchema } from "../components/SchemaForm";
import { ago, stamp } from "../lib/format";
import { t, tn } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

type Automation = S["Automation"];
type Step = S["Step"];
type Trigger = S["Trigger"];

const triggerText = (tr: Trigger) => {
  switch (tr.kind) {
    case "schedule":
      return tr.timezone ? t("On a schedule ({cron}, {zone})", { cron: tr.cron, zone: tr.timezone }) : t("On a schedule ({cron})", { cron: tr.cron });
    case "event":
      return t("When {event} happens", { event: tr.event });
    case "webhook":
      return t("When its webhook is called");
    default:
      return t("When you run it");
  }
};

const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

export function Automations() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["automations"], queryFn: () => ok(api.GET("/automations")) });
  const [editing, setEditing] = useState<Automation | "new" | null>(null);

  const quickBrief = useMutation({
    mutationFn: () =>
      ok(
        api.POST("/automations", {
          body: {
            name: t("Morning brief"),
            enabled: true,
            trigger: { kind: "schedule", cron: "30 7 * * 1-5", timezone: tz },
            steps: [{ instance: "brief", action: "send" }],
          },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["automations"] }),
  });

  if (editing) {
    return (
      <div className="page">
        <Editor initial={editing === "new" ? null : editing} onDone={() => setEditing(null)} />
      </div>
    );
  }

  const hasBrief = list.data?.some((a) => a.steps.some((s) => s.instance === "brief"));

  return (
    <div className="page">
      <div className="spread">
        <div className="page-head">
          <h1>{t("Automations")}</h1>
          <p>{t("Chains of actions that run on a schedule, when something happens, or when a webhook is called. Steps you save here run without asking; drafts from agents wait for you.")}</p>
        </div>
        <button className="btn primary" onClick={() => setEditing("new")}>
          {t("New automation")}</button>
      </div>

      {!hasBrief && (
        <div className="panel runner">
          <div className="spread">
            <div className="stack" style={{ gap: 4 }}>
              <h2>{t("Get a morning brief")}</h2>
              <p className="small muted">{t("Unread mail, today's events, anything down and approvals waiting, sent to your notification channels at 7:30 on weekdays.")}</p>
            </div>
            <button className="btn" onClick={() => quickBrief.mutate()} disabled={quickBrief.isPending}>
              {t("Turn on")}</button>
          </div>
          <ErrorNote error={quickBrief.error} />
        </div>
      )}

      {list.data?.length === 0 && (
        <div className="empty">
          <h2>{t("No automations yet")}</h2>
          <p className="muted">{t("For example: when a site goes down, restart its container and tell your phone.")}</p>
        </div>
      )}
      {(list.data?.length ?? 0) > 0 && (
        <div className="panel rows">
          {list.data!.map((a) => (
            <AutomationRow key={a.id} a={a} onEdit={() => setEditing(a)} />
          ))}
        </div>
      )}
    </div>
  );
}

function AutomationRow({ a, onEdit }: { a: Automation; onEdit: () => void }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const runs = useQuery({
    queryKey: ["automations", a.id, "runs"],
    queryFn: () => ok(api.GET("/automations/{id}/runs", { params: { path: { id: a.id }, query: { limit: 10 } } })),
    enabled: open,
  });
  const toggle = useMutation({
    mutationFn: () => ok(api.PUT("/automations/{id}", { params: { path: { id: a.id } }, body: { name: a.name, trigger: a.trigger, steps: a.steps, enabled: !a.enabled } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["automations"] }),
  });
  const run = useMutation({
    mutationFn: () => ok(api.POST("/automations/{id}/run", { params: { path: { id: a.id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["automations", a.id, "runs"] }),
  });
  const del = useMutation({
    mutationFn: () => ok(api.DELETE("/automations/{id}", { params: { path: { id: a.id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["automations"] }),
  });
  return (
    <div className="row auto-row">
      <button className="tl-title stack" style={{ gap: 2 }} onClick={() => setOpen(!open)} aria-expanded={open}>
        <strong>{a.name}</strong>
        <span className="xs muted">
          {triggerText(a.trigger)}, {tn("{n} step", "{n} steps", a.steps.length)}
        </span>
      </button>
      {!a.trusted && <span className="tag" title={t("Drafted by an agent or key. Review the steps, then turn it on.")}>{t("Needs review")}</span>}
      <label className="check xs">
        <input type="checkbox" checked={a.enabled} onChange={() => toggle.mutate()} />
        {a.enabled ? t("On") : t("Off")}
      </label>
      <div className="inline">
        <button className="btn sm" onClick={() => run.mutate()} disabled={!a.enabled || run.isPending}>
          {t("Run now")}</button>
        <button className="btn sm quiet" onClick={onEdit}>
          {t("Edit")}</button>
      </div>
      <ErrorNote error={toggle.error || run.error} style={{ gridColumn: "1 / -1" }} />
      {run.data && (
        <p className="xs" style={{ gridColumn: "1 / -1", color: run.data.status === "ok" ? "var(--ok)" : "var(--fault)" }}>
          {run.data.status === "ok" ? t("Finished.") : run.data.error}
        </p>
      )}
      {open && (
        <div className="usage">
          {a.hookPath && (
            <p className="xs">
              {t("Webhook address:")}{" "}<code className="data">{window.location.origin + a.hookPath}</code>{" "}
              <button className="btn sm quiet" onClick={() => navigator.clipboard?.writeText(window.location.origin + a.hookPath)}>
                {t("Copy")}</button>
            </p>
          )}
          <ol className="small steps-list">
            {a.steps.map((s, i) => (
              <li key={i}>
                <span className="data">{s.action}</span> <span className="muted">{t("on")}{" "}{s.instance}</span>
              </li>
            ))}
          </ol>
          <p className="xs muted">{t("Recent runs")}</p>
          {runs.data?.length === 0 && <p className="xs muted">{t("Hasn't run yet.")}</p>}
          {runs.data?.map((r) => (
            <p className="xs" key={r.id}>
              <span className={`tag st-${r.status === "ok" ? "ok" : "error"}`}>{r.status}</span> <span title={stamp(r.startedAt)}>{ago(r.startedAt)}</span>
              {r.error && <span className="muted"> {r.error}</span>}
            </p>
          ))}
          <div>
            <button className="btn sm danger" onClick={() => confirm(`Delete "${a.name}"?`) && del.mutate()}>
              {t("Delete")}</button>
          </div>
        </div>
      )}
    </div>
  );
}

function Editor({ initial, onDone }: { initial: Automation | null; onDone: () => void }) {
  const qc = useQueryClient();
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => ok(api.GET("/instances")) });
  const modules = useQuery({ queryKey: ["modules"], queryFn: () => ok(api.GET("/modules")) });
  const [name, setName] = useState(initial?.name ?? "");
  const [trigger, setTrigger] = useState<Trigger>(initial?.trigger ?? { kind: "schedule", cron: "0 8 * * *", timezone: tz });
  const [steps, setSteps] = useState<Step[]>(initial?.steps ?? []);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);

  const save = useMutation({
    mutationFn: () => {
      const body = { name, trigger, steps, enabled };
      return ok(initial ? api.PUT("/automations/{id}", { params: { path: { id: initial.id } }, body }) : api.POST("/automations", { body }));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["automations"] });
      onDone();
    },
  });

  const moduleOf = (instance: string) => {
    const inst = instances.data?.find((i) => i.id === instance);
    return modules.data?.find((m) => m.id === inst?.module);
  };
  const setStep = (i: number, s: Step) => setSteps(steps.map((x, j) => (j === i ? s : x)));

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <div className="page-head">
        <h1>{initial ? `Edit ${initial.name}` : t("New automation")}</h1>
      </div>
      <label className="field" style={{ maxWidth: 420 }}>
        <span>{t("Name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>

      <section className="panel runner">
        <h2>{t("When")}</h2>
        <div className="inline" role="radiogroup" aria-label={t("Trigger")}>
          {(["schedule", "event", "webhook", "manual"] as const).map((k) => (
            <button key={k} type="button" role="radio" aria-checked={trigger.kind === k} className={`btn sm ${trigger.kind === k ? "primary" : ""}`} onClick={() => setTrigger({ ...trigger, kind: k })}>
              {k === "schedule" ? t("On a schedule") : k === "event" ? t("When something happens") : k === "webhook" ? t("Webhook") : t("Only when I run it")}
            </button>
          ))}
        </div>
        {trigger.kind === "schedule" && (
          <div className="rule-grid">
            <label className="field">
              <span>{t("Schedule")}</span>
              <input className="data" value={trigger.cron ?? ""} onChange={(e) => setTrigger({ ...trigger, cron: e.target.value })} />
              <small>{t("Minute, hour, day, month, weekday. \"30 7 * * 1-5\" is 7:30 on weekdays.")}</small>
            </label>
            <label className="field">
              <span>{t("Time zone")}</span>
              <input value={trigger.timezone ?? ""} onChange={(e) => setTrigger({ ...trigger, timezone: e.target.value })} />
            </label>
          </div>
        )}
        {trigger.kind === "event" && (
          <div className="rule-grid">
            <label className="field">
              <span>{t("Event")}</span>
              <input className="data" list="event-types" value={trigger.event ?? ""} onChange={(e) => setTrigger({ ...trigger, event: e.target.value })} />
              <datalist id="event-types">
                {modules.data?.flatMap((m) => (m.events ?? []).map((ev) => <option key={ev.type} value={ev.type}>{ev.description}</option>))}
                <option value="approval.requested" />
                <option value="action.error" />
              </datalist>
              <small>{t("A type like web.down, or a prefix like mail.")}</small>
            </label>
            <label className="field">
              <span>{t("Only if (optional)")}</span>
              <input
                className="data"
                placeholder={"data.name=Shop"}
                value={Object.entries(trigger.match ?? {}).map(([k, v]) => `${k}=${v}`).join(", ")}
                onChange={(e) =>
                  setTrigger({
                    ...trigger,
                    match: Object.fromEntries(
                      e.target.value
                        .split(",")
                        .map((p) => p.trim().split("="))
                        .filter((p) => p.length === 2 && p[0])
                        .map(([k, v]) => [k.trim(), v.trim()]),
                    ),
                  })
                }
              />
            </label>
          </div>
        )}
        {trigger.kind === "webhook" && <p className="small muted">{t("After saving, the automation gets a secret address. Anything that can send an HTTP POST can start it.")}</p>}
      </section>

      <section className="panel runner">
        <h2>{t("Then")}</h2>
        <p className="small muted">
          {t("Steps run in order. Use")}{" "}<code>{"{{trigger.data.name}}"}</code> {t("for event data and")}{" "}<code>{"{{steps.0.output.field}}"}</code> {t("for an earlier step's result.")}</p>
        {steps.map((s, i) => {
          const m = moduleOf(s.instance);
          const act = m?.actions.find((a) => a.name === s.action);
          return (
            <div key={i} className="step-card">
              <div className="spread">
                <strong className="small">{t("Step")}{" "}{i + 1}</strong>
                <button type="button" className="btn sm quiet" onClick={() => setSteps(steps.filter((_, j) => j !== i))}>
                  {t("Remove")}</button>
              </div>
              <div className="rule-grid">
                <label className="field">
                  <span>{t("System")}</span>
                  <select value={s.instance} onChange={(e) => setStep(i, { instance: e.target.value, action: "", input: {} })}>
                    <option value="">{t("Choose…")}</option>
                    {instances.data?.map((inst) => (
                      <option key={inst.id} value={inst.id}>
                        {inst.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span>{t("Action")}</span>
                  <select value={s.action} onChange={(e) => setStep(i, { ...s, action: e.target.value, input: {} })} disabled={!m}>
                    <option value="">{t("Choose…")}</option>
                    {m?.actions.map((a) => (
                      <option key={a.name} value={a.name}>
                        {a.title || a.name}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              {act && (
                <SchemaForm
                  schema={act.input as JSONSchema}
                  value={(s.input as Record<string, unknown>) ?? {}}
                  onChange={(v) => setStep(i, { ...s, input: v })}
                  idPrefix={`step-${i}`}
                />
              )}
              <label className="check xs">
                <input type="checkbox" checked={!!s.continueOnError} onChange={(e) => setStep(i, { ...s, continueOnError: e.target.checked })} />
                {t("Keep going if this step fails")}</label>
            </div>
          );
        })}
        <div>
          <button type="button" className="btn" onClick={() => setSteps([...steps, { instance: "", action: "" }])}>
            {t("Add a step")}</button>
        </div>
      </section>

      <label className="check">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {t("Turn it on now")}</label>
      <ErrorNote error={save.error} />
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          {t("Cancel")}</button>
        <button className="btn primary" disabled={save.isPending}>
          {t("Save automation")}</button>
      </div>
    </form>
  );
}
