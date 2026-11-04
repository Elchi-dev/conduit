import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "wouter";
import { api, ok, type S } from "../api/client";
import { t } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

type Provider = S["Provider"];

export function AssistantSettings() {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["ai", "providers"], queryFn: () => ok(api.GET("/ai/providers")) });
  const presets = useQuery({ queryKey: ["ai", "presets"], queryFn: () => ok(api.GET("/ai/presets")) });
  const [draft, setDraft] = useState<Provider | null>(null);
  const detect = useMutation({ mutationFn: () => ok(api.GET("/ai/detect")) });
  const remove = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/ai/providers/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai"] }),
  });
  const makeDefault = useMutation({
    mutationFn: (p: Provider) => ok(api.PUT("/ai/providers/{id}", { params: { path: { id: p.id! } }, body: { ...p, default: true } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai"] }),
  });
  const origin = window.location.origin;

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Assistant and agents")}</h1>
        <p>{t("Choose the AI model the built-in assistant uses, and connect outside agents over MCP. Both follow your agent rules.")}</p>
      </div>

      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">{t("Models")}</h2>
        {(providers.data?.length ?? 0) > 0 && (
          <div className="panel rows">
            {providers.data!.map((p) => (
              <div className="row key-row" key={p.id}>
                <div className="stack" style={{ gap: 2 }}>
                  <strong>{p.name}</strong>
                  <span className="xs muted data">
                    {p.model} at {p.baseUrl}
                  </span>
                </div>
                {p.default ? <span className="tag">{t("Default")}</span> : <span />}
                <span />
                <div className="inline">
                  {!p.default && (
                    <button className="btn sm quiet" onClick={() => makeDefault.mutate(p)}>
                      {t("Make default")}</button>
                  )}
                  <button className="btn sm quiet" onClick={() => setDraft(p)}>
                    {t("Edit")}</button>
                  <button className="btn sm danger" onClick={() => remove.mutate(p.id!)}>
                    {t("Remove")}</button>
                </div>
              </div>
            ))}
          </div>
        )}
        {!draft && (
          <div className="panel runner">
            <h3>{t("Add a model")}</h3>
            <div className="inline">
              {presets.data?.map((p) => (
                <button key={p.name} className="btn sm" onClick={() => setDraft({ ...p, apiKey: "" })}>
                  {p.name}
                </button>
              ))}
              <button className="btn sm quiet" onClick={() => setDraft({ name: "", kind: "openai", baseUrl: "https://", model: "" })}>
                {t("Custom endpoint")}</button>
            </div>
            <div className="inline">
              <button className="btn sm" onClick={() => detect.mutate()} disabled={detect.isPending}>
                {t("Find models on this computer")}</button>
              {detect.data?.length === 0 && <span className="xs muted">{t("Nothing found. Start Ollama or LM Studio and try again.")}</span>}
              {detect.data?.map((p) => (
                <button key={p.baseUrl} className="btn sm primary" onClick={() => setDraft({ ...p, headers: {} })}>
                  {t("Use")}{" "}{p.name}
                  {p.model ? ` (${p.model})` : ""}
                </button>
              ))}
            </div>
          </div>
        )}
        {draft && <ProviderForm initial={draft} onDone={() => setDraft(null)} />}
      </section>

      <OutsideServers />

      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">{t("Connect an outside agent (MCP)")}</h2>
        <div className="panel runner">
          <p className="small">
            1. <Link href="/keys">{t("Create an API key")}</Link> {t("for \"An AI agent\". 2. Add Conduit to your agent's MCP settings:")}</p>
          <pre className="json">{`{
  "mcpServers": {
    "conduit": {
      "command": "conduitd",
      "args": ["mcp"],
      "env": {
        "CONDUIT_API_KEY": "cdt_agent_…",
        "CONDUIT_URL": "${origin}"
      }
    }
  }
}`}</pre>
          <p className="small muted">
            {t("Agents that connect over HTTP use")}{" "}<code className="data">{origin}/mcp</code> {t("with the key as a bearer token.")}</p>
        </div>
      </section>
    </div>
  );
}

function ProviderForm({ initial, onDone }: { initial: Provider; onDone: () => void }) {
  const qc = useQueryClient();
  const [p, setP] = useState<Provider>(initial);
  const models = initial.headers?.["x-detected-models"]?.split(",").filter(Boolean) ?? [];
  const save = useMutation({
    mutationFn: () => {
      const body = { ...p, headers: Object.fromEntries(Object.entries(p.headers ?? {}).filter(([k]) => !k.startsWith("x-detected"))) };
      return ok(p.id ? api.PUT("/ai/providers/{id}", { params: { path: { id: p.id } }, body }) : api.POST("/ai/providers", { body }));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai"] });
      onDone();
    },
  });
  const local = /^http:\/\/(127\.|localhost)/.test(p.baseUrl);
  return (
    <form
      className="panel runner"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <h3>{p.id ? `Edit ${p.name}` : p.name ? `Add ${p.name}` : t("Add a custom endpoint")}</h3>
      <div className="rule-grid">
        <label className="field">
          <span>{t("Name")}</span>
          <input value={p.name ?? ""} onChange={(e) => setP({ ...p, name: e.target.value })} />
        </label>
        <label className="field">
          <span>{t("API style")}</span>
          <select value={p.kind} onChange={(e) => setP({ ...p, kind: e.target.value as Provider["kind"] })}>
            <option value="openai">{t("OpenAI-compatible")}</option>
            <option value="anthropic">{"Anthropic"}</option>
          </select>
        </label>
        <label className="field">
          <span>{t("Base URL")}</span>
          <input className="data" value={p.baseUrl} onChange={(e) => setP({ ...p, baseUrl: e.target.value })} required />
        </label>
        <label className="field">
          <span>{t("Model")}</span>
          <input className="data" list="detected-models" value={p.model} onChange={(e) => setP({ ...p, model: e.target.value })} required />
          <datalist id="detected-models">
            {models.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </label>
        {!local && (
          <label className="field">
            <span>{t("API key")}</span>
            <input className="data" placeholder={"secret://ai/provider"} value={p.apiKey ?? ""} onChange={(e) => setP({ ...p, apiKey: e.target.value })} />
            <small>
              {t("Save the key in the")}{" "}<Link href="/i/vault">{t("vault")}</Link> {t("first and enter its reference here.")}</small>
          </label>
        )}
      </div>
      <ErrorNote error={save.error} />
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          {t("Cancel")}</button>
        <button className="btn primary" disabled={save.isPending}>
          {t("Save")}</button>
      </div>
    </form>
  );
}

function OutsideServers() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["mcp-servers"], queryFn: () => ok(api.GET("/mcp-servers")) });
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ name: "", transport: "stdio" as "stdio" | "http", command: "npx", args: "", url: "https://", envKey: "", envVal: "", trust: false });
  const save = useMutation({
    mutationFn: () =>
      ok(
        api.POST("/mcp-servers", {
          body: {
            name: f.name,
            transport: f.transport,
            command: f.transport === "stdio" ? f.command : undefined,
            args: f.transport === "stdio" ? f.args.split(" ").filter(Boolean) : undefined,
            url: f.transport === "http" ? f.url : undefined,
            env: f.transport === "stdio" && f.envKey ? { [f.envKey]: f.envVal } : undefined,
            headers: f.transport === "http" && f.envKey ? { [f.envKey]: f.envVal } : undefined,
            trustReadOnly: f.trust,
          },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mcp-servers"] });
      qc.invalidateQueries({ queryKey: ["instances"] });
      setAdding(false);
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/mcp-servers/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mcp-servers"] });
      qc.invalidateQueries({ queryKey: ["instances"] });
    },
  });
  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <h2 className="section-title">{t("Use tools from other MCP servers")}</h2>
        {!adding && (
          <button className="btn sm" onClick={() => setAdding(true)}>
            {t("Add a server")}</button>
        )}
      </div>
      <p className="small muted">{t("An MCP server added here becomes a module: its tools follow your agent rules and show up in the timeline.")}</p>
      {(list.data?.length ?? 0) > 0 && (
        <div className="panel rows">
          {list.data!.map((s) => (
            <div className="row session-row" key={s.id}>
              <span className="small">
                <strong>{s.name}</strong> <span className="muted data">{s.transport === "stdio" ? `${s.command} ${(s.args ?? []).join(" ")}` : s.url}</span>
              </span>
              <Link href={`/i/mcp-${s.id}`} className="btn sm quiet">
                {t("Open")}</Link>
              <button className="btn sm danger" onClick={() => remove.mutate(s.id!)}>
                {t("Remove")}</button>
            </div>
          ))}
        </div>
      )}
      {adding && (
        <form
          className="panel runner"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <div className="rule-grid">
            <label className="field">
              <span>{t("Name")}</span>
              <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required placeholder={"GitHub"} />
            </label>
            <label className="field">
              <span>{t("How it runs")}</span>
              <select value={f.transport} onChange={(e) => setF({ ...f, transport: e.target.value as "stdio" | "http" })}>
                <option value="stdio">{t("A command on this computer")}</option>
                <option value="http">{t("A remote server (HTTP)")}</option>
              </select>
            </label>
          </div>
          {f.transport === "stdio" ? (
            <div className="rule-grid">
              <label className="field">
                <span>{t("Command")}</span>
                <input className="data" value={f.command} onChange={(e) => setF({ ...f, command: e.target.value })} />
              </label>
              <label className="field">
                <span>{t("Arguments")}</span>
                <input className="data" value={f.args} onChange={(e) => setF({ ...f, args: e.target.value })} placeholder={"-y @modelcontextprotocol/server-github"} />
              </label>
            </div>
          ) : (
            <label className="field">
              <span>{"URL"}</span>
              <input className="data" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} />
            </label>
          )}
          <div className="rule-grid">
            <label className="field">
              <span>{f.transport === "stdio" ? t("Environment variable (optional)") : t("Header (optional)")}</span>
              <input className="data" value={f.envKey} onChange={(e) => setF({ ...f, envKey: e.target.value })} placeholder={f.transport === "stdio" ? "GITHUB_TOKEN" : "Authorization"} />
            </label>
            <label className="field">
              <span>{t("Value")}</span>
              <input className="data" value={f.envVal} onChange={(e) => setF({ ...f, envVal: e.target.value })} placeholder={"secret://github/token"} />
              <small>{t("Credentials must be vault references.")}</small>
            </label>
          </div>
          <label className="check">
            <input type="checkbox" checked={f.trust} onChange={(e) => setF({ ...f, trust: e.target.checked })} />
            <span>{t("Trust this server's read-only labels. Otherwise every tool counts as a change and follows your approval rules.")}</span>
          </label>
          <ErrorNote error={save.error} />
          <div className="inline">
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>
              {t("Cancel")}</button>
            <button className="btn primary" disabled={save.isPending}>
              {t("Add and connect")}</button>
          </div>
        </form>
      )}
    </section>
  );
}
