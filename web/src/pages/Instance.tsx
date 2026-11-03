import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useLocation, useSearch } from "wouter";
import { api, ok, type ActionSpec, type Outcome } from "../api/client";
import { PlanView } from "../components/PlanView";
import { defaults, SchemaForm, type JSONSchema } from "../components/SchemaForm";
import { ResultView } from "../components/ResultView";
import { PinButton } from "../components/Tiles";
import { VaultGate } from "../modules/vault/VaultGate";
import { ago } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";

export function InstancePage({ id }: { id: string }) {
  const search = useSearch();
  const qc = useQueryClient();
  const [, go] = useLocation();
  const inst = useQuery({
    queryKey: ["instances", id],
    queryFn: () => ok(api.GET("/instances/{id}", { params: { path: { id } } })),
  });
  const mod = useQuery({
    queryKey: ["modules", inst.data?.module],
    queryFn: () => ok(api.GET("/modules/{id}", { params: { path: { id: inst.data!.module } } })),
    enabled: !!inst.data,
  });
  const recent = useQuery({
    queryKey: ["audit", "instance", id],
    queryFn: () => ok(api.GET("/audit", { params: { query: { instance: id, limit: 8 } } })),
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    const a = new URLSearchParams(search).get("action");
    if (a) setSelected(a);
  }, [search]);

  // Open the first read action that needs no input, so the page shows data.
  useEffect(() => {
    if (selected || !mod.data) return;
    const first = mod.data.actions.find((a) => a.risk === "read" && !(a.input as JSONSchema | undefined)?.required?.length);
    if (first) setSelected(first.name);
  }, [mod.data, selected]);

  const del = useMutation({
    mutationFn: () => ok(api.DELETE("/instances/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["instances"] });
      go("/");
    },
  });

  if (inst.error) return <div className="page"><div className="error">{inst.error.message}</div></div>;
  if (!inst.data || !mod.data) return <div className="page" />;
  const i = inst.data;
  const m = mod.data;
  const action = m.actions.find((a) => a.name === selected);
  const h = i.health;

  return (
    <div className="page">
      <div className="spread">
        <div className="page-head">
          <div className="inline">
            <span className={`lamp ${h?.status ?? "pending"}`} style={{ padding: 0, height: "auto" }}>
              <span className="bulb" />
            </span>
            <h1>{i.name}</h1>
          </div>
          <p>
            {m.name !== i.name && `${m.name}. `}
            {h?.message || (h?.status === "ok" ? t("Working normally.") : "")}
          </p>
        </div>
        <div className="inline">
          <button className="btn" onClick={() => setEditing(!editing)}>
            {editing ? t("Close settings") : t("Settings")}
          </button>
        </div>
      </div>

      {editing && <InstanceSettings id={id} schema={m.configSchema as JSONSchema} initial={i.config as Record<string, unknown>} name={i.name} enabled={i.enabled} onDelete={() => confirm(t("Disconnect {name}? Its history stays in the timeline.", { name: i.name })) && del.mutate()} />}

      {m.id === "vault" && <VaultGate />}

      <div className="instance-grid">
        <nav className="actions panel" aria-label={t("Actions")}>
          {(["read", "write", "destructive"] as const).map((risk) => {
            const list = m.actions.filter((a) => a.risk === risk);
            if (!list.length) return null;
            return (
              <div key={risk}>
                <p className="actions-head">{risk === "read" ? t("Look") : risk === "write" ? t("Change") : t("Careful")}</p>
                {list.map((a) => (
                  <button key={a.name} className={selected === a.name ? "active" : undefined} onClick={() => setSelected(a.name)}>
                    {a.title || a.name}
                  </button>
                ))}
              </div>
            );
          })}
        </nav>
        <section className="stack">
          {action ? <ActionRunner key={action.name} instance={id} action={action} /> : <p className="muted">{t("Choose an action.")}</p>}
          {recent.data && recent.data.length > 0 && (
            <div className="stack" style={{ gap: 8 }}>
              <h2 className="section-title">{t("Recent on")}{" "}{i.name}</h2>
              <div className="panel rows">
                {recent.data.map((e) => (
                  <div className="row recent-row" key={e.seq}>
                    <span className="data small">{e.action}</span>
                    <span className="xs muted">{e.actor.name || e.actor.id}</span>
                    <span className={`tag st-${e.status}`}>{e.status}</span>
                    <span className="xs muted">{ago(e.at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function ActionRunner({ instance, action }: { instance: string; action: ActionSpec }) {
  const schema = action.input as JSONSchema | undefined;
  const [input, setInput] = useState<Record<string, unknown>>(defaults(schema));
  const [result, setResult] = useState<Outcome | null>(null);
  const autoRun = action.risk === "read" && !schema?.required?.length;

  const run = useMutation({
    mutationFn: (dryRun: boolean) =>
      ok(api.POST("/instances/{id}/actions/{action}", { params: { path: { id: instance, action: action.name } }, body: { input, dryRun } })),
    onSuccess: setResult,
  });

  useEffect(() => {
    if (autoRun) run.mutate(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="panel runner">
      <div className="spread">
        <div className="stack" style={{ gap: 2 }}>
          <h2>{action.title || action.name}</h2>
          {action.description && <p className="small muted">{action.description}</p>}
        </div>
        {action.risk !== "read" && <span className={`tag ${action.risk}`}>{action.risk}</span>}
      </div>
      {schema?.properties && Object.keys(schema.properties).length > 0 && (
        <SchemaForm schema={schema} value={input} onChange={setInput} idPrefix={`in-${action.name}`} />
      )}
      <div className="inline">
        <button className={`btn ${action.risk === "destructive" ? "danger" : "primary"}`} onClick={() => run.mutate(false)} disabled={run.isPending}>
          {action.risk === "read" ? (result ? t("Refresh") : t("Run")) : action.title || t("Run")}
        </button>
        {action.dryRun && (
          <button className="btn" onClick={() => run.mutate(true)} disabled={run.isPending}>
            {t("Preview changes")}</button>
        )}
        {run.isPending && <span className="xs muted">{t("Working…")}</span>}
      </div>
      {run.error && <div className="error">{run.error.message}</div>}
      {result?.result.plan && <PlanView plan={result.result.plan} />}
      {result && !result.result.plan && result.result.output !== undefined && <ResultView value={result.result.output} />}
      {result && action.risk === "read" && !action.sensitive && result.result.output !== undefined && (
        <PinButton instance={instance} action={action.name} title={action.title || action.name} input={input} output={result.result.output} />
      )}
      {result?.audit.undo && !result.result.plan && (
        <p className="xs muted">{t("Done. You can undo this from the timeline (")}{result.audit.undo.description}).</p>
      )}
    </div>
  );
}

function InstanceSettings({
  id,
  schema,
  initial,
  name: initialName,
  enabled,
  onDelete,
}: {
  id: string;
  schema?: JSONSchema;
  initial: Record<string, unknown>;
  name: string;
  enabled: boolean;
  onDelete: () => void;
}) {
  const qc = useQueryClient();
  const [config, setConfig] = useState(initial ?? {});
  const [name, setName] = useState(initialName);
  const save = useMutation({
    mutationFn: (en: boolean) => ok(api.PUT("/instances/{id}", { params: { path: { id } }, body: { name, config, enabled: en } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["instances"] }),
  });
  return (
    <form
      className="panel runner"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(enabled);
      }}
    >
      <h2>{t("Settings")}</h2>
      <label className="field">
        <span>{t("Name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <SchemaForm schema={schema} value={config} onChange={setConfig} idPrefix={`edit-${id}`} />
      {save.error && <div className="error">{save.error.message}</div>}
      <div className="spread">
        <button type="button" className="btn danger" onClick={onDelete}>
          {t("Disconnect")}</button>
        <div className="inline">
          <button type="button" className="btn" onClick={() => save.mutate(!enabled)}>
            {enabled ? t("Pause") : t("Resume")}
          </button>
          <button className="btn primary" disabled={save.isPending}>
            {t("Save")}</button>
        </div>
      </div>
      {save.isSuccess && <p className="xs muted">{t("Saved.")}</p>}
    </form>
  );
}
