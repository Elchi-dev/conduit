import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useLocation, useSearch } from "wouter";
import { api, ok, type Manifest } from "../api/client";
import { defaults, SchemaForm, type JSONSchema } from "../components/SchemaForm";
import { t } from "../i18n";
import "./pages.css";

export const presetNames = [
  ["", t("Everything")],
  ["developer", t("Developer")],
  ["gamer", t("Gaming PC")],
  ["homelab", t("Homelab")],
  ["team", t("Team")],
] as const;

export function Modules() {
  const modules = useQuery({ queryKey: ["modules"], queryFn: () => ok(api.GET("/modules")) });
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => ok(api.GET("/instances")) });
  const [adding, setAdding] = useState<Manifest | null>(null);
  const [filter, setFilter] = useState("");
  const search = useSearch();
  const [preset, setPreset] = useState(() => new URLSearchParams(search).get("preset") ?? "");

  const count = (id: string) => instances.data?.filter((i) => i.module === id).length ?? 0;
  const list = (modules.data ?? []).filter(
    (m) =>
      (!filter || `${m.name} ${m.description} ${m.category ?? ""}`.toLowerCase().includes(filter.toLowerCase())) &&
      (!preset || m.presets?.includes(preset)),
  );
  const byCategory = new Map<string, Manifest[]>();
  for (const m of list) {
    const c = m.category || t("Other");
    byCategory.set(c, [...(byCategory.get(c) ?? []), m]);
  }

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Modules")}</h1>
        <p>
          {t("Each module connects one kind of thing — a mailbox, a server, a dashboard. Connect as many of each as you need, or")}{" "}
          <Link href="/modules/registry">{t("add modules from your hub")}</Link>.
        </p>
      </div>
      <div className="spread">
        <input className="input" style={{ maxWidth: 320 }} placeholder={t("Filter modules")} value={filter} onChange={(e) => setFilter(e.target.value)} />
        <div className="inline" role="radiogroup" aria-label={t("Show modules for")}>
          {presetNames.map(([id, label]) => (
            <button key={id} role="radio" aria-checked={preset === id} className={`btn sm ${preset === id ? "primary" : "quiet"}`} onClick={() => setPreset(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {modules.data?.length === 0 && (
        <div className="empty">
          <h2>{t("No modules installed")}</h2>
          <p className="muted">{t("Built-in modules ship with Conduit. External modules go in the daemon's modules folder.")}</p>
        </div>
      )}
      {[...byCategory.entries()].map(([cat, ms]) => (
        <section key={cat} className="stack" style={{ gap: 8 }}>
          <h2 className="section-title">{cat}</h2>
          <div className="panel rows">
            {ms.map((m) => (
              <div className="row module-row" key={m.id}>
                <div className="stack" style={{ gap: 2 }}>
                  <strong>{m.name}</strong>
                  <span className="small muted">{m.description}</span>
                </div>
                <span className="xs muted">
                  {count(m.id) > 0 ? `${count(m.id)} connected` : `${m.actions.length} actions`}
                </span>
                <button className="btn sm" onClick={() => setAdding(m)}>
                  {t("Connect")}</button>
              </div>
            ))}
          </div>
        </section>
      ))}
      {adding && <ConnectDialog m={adding} onClose={() => setAdding(null)} />}
    </div>
  );
}

function ConnectDialog({ m, onClose }: { m: Manifest; onClose: () => void }) {
  const qc = useQueryClient();
  const [, go] = useLocation();
  const schema = m.configSchema as JSONSchema | undefined;
  const [name, setName] = useState(m.name);
  const [config, setConfig] = useState<Record<string, unknown>>(defaults(schema));
  const save = useMutation({
    mutationFn: () => ok(api.POST("/instances", { body: { module: m.id, name, config } })),
    onSuccess: (inst) => {
      qc.invalidateQueries({ queryKey: ["instances"] });
      onClose();
      go(`/i/${inst.id}`);
    },
  });
  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div className="dialog panel" role="dialog" aria-modal="true" aria-labelledby="connect-title" onClick={(e) => e.stopPropagation()}>
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <h2 id="connect-title">{t("Connect")}{" "}{m.name}</h2>
          <label className="field">
            <span>{t("Name")}</span>
            <input value={name} onChange={(e) => setName(e.target.value)} required />
            <small>{t("Shown in the lamp row and the menu, e.g. \"Work mail\" or \"Home server\".")}</small>
          </label>
          <SchemaForm schema={schema} value={config} onChange={setConfig} idPrefix={`cfg-${m.id}`} />
          {save.error && <div className="error">{save.error.message}</div>}
          <div className="inline" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn quiet" onClick={onClose}>
              {t("Cancel")}</button>
            <button className="btn primary" disabled={save.isPending}>
              {t("Connect")}</button>
          </div>
        </form>
      </div>
    </div>
  );
}
