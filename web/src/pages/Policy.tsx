import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type Rule } from "../api/client";
import { ago } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";

const presets: Record<string, { name: string; text: string }> = {
  "read-only": { name: t("Look only"), text: t("Agents can read anything and change nothing.") },
  "ask-writes": { name: t("Ask before changing"), text: t("Agents read freely and ask you before every change. Recommended.") },
  "ask-destructive": { name: t("Ask before risky changes"), text: t("Agents make ordinary changes and ask before deleting, restarting or revealing secrets.") },
  "full-autonomy": { name: t("Full autonomy"), text: t("Agents do whatever they're asked. Everything is still logged and can be stopped.") },
};

export function PolicyPage() {
  const qc = useQueryClient();
  const policy = useQuery({ queryKey: ["policy"], queryFn: () => ok(api.GET("/policy")) });
  const setPreset = useMutation({
    mutationFn: (preset: string) => ok(api.PUT("/policy/preset", { body: { preset: preset as never } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy"] }),
  });
  const lift = useMutation({
    mutationFn: () => ok(api.DELETE("/panic")),
    onSuccess: () => qc.invalidateQueries(),
  });
  const p = policy.data;

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Agent rules")}</h1>
        <p>
          {t("What AI agents, API keys and automations may do without asking. You, signed in, can always act directly. Rules are checked top to bottom before the default applies.")}</p>
      </div>

      {p?.frozen && (
        <div className="panel runner frozen-panel">
          <h2>{t("Emergency stop is on")}</h2>
          <p className="small">
            {t("Every agent, key and automation is frozen and agent keys were revoked. Lift it once you know what happened; check the timeline first. Revoked agent keys stay revoked; create new ones for agents you trust.")}</p>
          {lift.error && <div className="error">{lift.error.message}</div>}
          <div>
            <button className="btn" onClick={() => lift.mutate()} disabled={lift.isPending}>
              {t("Lift emergency stop")}</button>
          </div>
        </div>
      )}

      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">{t("Default for agents")}</h2>
        <div className="presets" role="radiogroup" aria-label={t("Default autonomy")}>
          {p?.presets.map((id) => (
            <button
              key={id}
              role="radio"
              aria-checked={p.preset === id}
              className={`preset ${p.preset === id ? "on" : ""}`}
              onClick={() => setPreset.mutate(id)}
            >
              <strong>{presets[id]?.name ?? id}</strong>
              <span className="small muted">{presets[id]?.text}</span>
            </button>
          ))}
        </div>
        {setPreset.error && <div className="error">{setPreset.error.message}</div>}
      </section>

      <Rules rules={p?.rules ?? []} />
    </div>
  );
}

const effectText = { allow: t("Allow"), ask: t("Ask me"), deny: t("Block") } as const;

function Rules({ rules }: { rules: Rule[] }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Rule>({ subject: "kind:agent", module: "*", action: "*", risk: "*", effect: "allow" });
  const [hours, setHours] = useState("");
  const save = useMutation({
    mutationFn: () =>
      ok(
        api.POST("/policy/rules", {
          body: {
            ...draft,
            position: rules.length,
            expiresAt: hours ? new Date(Date.now() + Number(hours) * 3600_000).toISOString() : undefined,
          },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
      setHours("");
    },
  });
  const del = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/policy/rules/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy"] }),
  });
  const set = (k: keyof Rule) => (e: { target: { value: string } }) => setDraft({ ...draft, [k]: e.target.value });

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">{t("Rules")}</h2>
      {rules.length > 0 && (
        <div className="panel rows">
          {rules.map((r) => (
            <div className="row rule-row" key={r.id}>
              <span className={`effect effect-${r.effect}`}>{effectText[r.effect]}</span>
              <span className="small">
                <span className="data">{r.subject}</span> <span className="muted">{t("running")}</span>{" "}
                <span className="data">{r.action === "*" ? t("any action") : r.action}</span> <span className="muted">{t("on")}</span>{" "}
                <span className="data">{r.module === "*" ? t("any module") : r.module}</span>
                {r.risk && r.risk !== "*" && <span className="muted"> {t("when")}{" "}{r.risk}</span>}
              </span>
              <span className="xs muted">{r.expiresAt ? `ends ${ago(r.expiresAt)}` : ""}</span>
              <button className="btn sm quiet" onClick={() => del.mutate(r.id!)} aria-label={t("Delete rule")}>
                {t("Delete")}</button>
            </div>
          ))}
        </div>
      )}
      <form
        className="panel runner rule-form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <h3>{t("Add a rule")}</h3>
        <div className="rule-grid">
          <label className="field">
            <span>{t("Who")}</span>
            <input className="data" value={draft.subject} onChange={set("subject")} />
            <small>{t("kind:agent, kind:key, agent:<key id> or *")}</small>
          </label>
          <label className="field">
            <span>{t("Module")}</span>
            <input className="data" value={draft.module} onChange={set("module")} />
          </label>
          <label className="field">
            <span>{t("Action")}</span>
            <input className="data" value={draft.action} onChange={set("action")} />
          </label>
          <label className="field">
            <span>{t("Risk")}</span>
            <select value={draft.risk} onChange={set("risk")}>
              <option value="*">{t("any")}</option>
              <option value="read">{t("read")}</option>
              <option value="write">{t("write")}</option>
              <option value="destructive">{t("destructive")}</option>
            </select>
          </label>
          <label className="field">
            <span>{t("Then")}</span>
            <select value={draft.effect} onChange={set("effect")}>
              <option value="allow">{t("Allow")}</option>
              <option value="ask">{t("Ask me")}</option>
              <option value="deny">{t("Block")}</option>
            </select>
          </label>
          <label className="field">
            <span>{t("For")}</span>
            <select value={hours} onChange={(e) => setHours(e.target.value)}>
              <option value="">{t("Until I remove it")}</option>
              <option value="1">{t("1 hour")}</option>
              <option value="8">{t("8 hours")}</option>
              <option value="24">{t("1 day")}</option>
            </select>
          </label>
        </div>
        {save.error && <div className="error">{save.error.message}</div>}
        <div>
          <button className="btn primary" disabled={save.isPending}>
            {t("Add rule")}</button>
        </div>
      </form>
    </section>
  );
}
