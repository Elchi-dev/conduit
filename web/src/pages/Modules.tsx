import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDeferredValue, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Link, useLocation, useSearch } from "wouter";
import { api, ok, type Manifest } from "../api/client";
import { ModuleIcon } from "../components/ModuleIcon";
import { defaults, SchemaForm, type JSONSchema } from "../components/SchemaForm";
import { t, tn } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

export const presetNames = [
  ["", t("Everything")],
  ["developer", t("Developer")],
  ["gamer", t("Gaming PC")],
  ["homelab", t("Homelab")],
  ["team", t("Team")],
] as const;

/**
 * What each preset suggests first, in order. A preset offers dozens of
 * modules; these are the ones most people in that situation connect first.
 * Built-in modules (the vault, this computer, notes) are already there, so
 * they aren't listed. Ids a daemon doesn't have are skipped.
 */
const featured: Record<string, string[]> = {
  developer: ["github", "docker", "servers", "web", "kubernetes", "cloudflare", "sentry", "database"],
  gamer: ["games", "discord", "spotify", "twitch", "obs", "gameservers", "plex", "homeassistant"],
  homelab: ["docker", "proxmox", "homeassistant", "pihole", "truenas", "jellyfin", "tailscale", "uptimekuma"],
  team: ["slack", "github", "jira", "linear", "mail", "calendar", "notion", "pagerduty"],
};

/** Categories in the order the page lists them; the daemon's names are English. */
const categoryOrder = [
  "Conduit",
  "Development",
  "Infrastructure",
  "Network",
  "Monitoring",
  "Security",
  "Storage",
  "Communication",
  "Productivity",
  "Media",
  "Gaming",
  "Smart home",
  "MCP servers",
];

function categoryLabel(c: string): string {
  const labels: Record<string, string> = {
    Conduit: t("Conduit"),
    Development: t("Development"),
    Infrastructure: t("Infrastructure"),
    Network: t("Network"),
    Monitoring: t("Monitoring"),
    Security: t("Security"),
    Storage: t("Storage"),
    Communication: t("Communication"),
    Productivity: t("Productivity"),
    Media: t("Media"),
    Gaming: t("Gaming"),
    "Smart home": t("Smart home"),
    "MCP servers": t("MCP servers"),
    "": t("Other"),
  };
  return labels[c] ?? c;
}

const rank = (c: string) => {
  const i = categoryOrder.indexOf(c);
  return i < 0 ? (c === "" ? 1000 : 500) : i;
};

type Show = "all" | "added" | "available";

/** Arrow keys move between the options of a radio group, like native radios. */
function arrowKeys(e: KeyboardEvent<HTMLElement>) {
  if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(e.key)) return;
  const opts = [...e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="radio"]')];
  const at = opts.indexOf(document.activeElement as HTMLButtonElement);
  if (at < 0) return;
  e.preventDefault();
  const next = e.key === "Home" ? 0 : e.key === "End" ? opts.length - 1 : (at + (e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 1) + opts.length) % opts.length;
  opts[next].focus();
  opts[next].click();
}

export function Modules() {
  const modules = useQuery({ queryKey: ["modules"], queryFn: () => ok(api.GET("/modules")) });
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => ok(api.GET("/instances")) });
  const [adding, setAdding] = useState<Manifest | null>(null);
  const search = useSearch();
  const [, go] = useLocation();
  const params = new URLSearchParams(search);
  const [query, setQuery] = useState("");
  const q = useDeferredValue(query.trim().toLowerCase());
  const [preset, setPresetState] = useState(() => params.get("preset") ?? "");
  const [category, setCategory] = useState(() => params.get("category") ?? "");
  const [show, setShow] = useState<Show>("all");
  const [expanded, setExpanded] = useState(false);
  const searchBox = useRef<HTMLInputElement>(null);

  const setPreset = (id: string) => {
    setPresetState(id);
    setExpanded(false);
    go(id ? `/modules?preset=${id}` : "/modules", { replace: true });
  };

  // "/" jumps to search from anywhere on the page, like most catalogs.
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey || el.closest("input, textarea, select, [contenteditable]")) return;
      e.preventDefault();
      searchBox.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const byModule = useMemo(() => {
    const m = new Map<string, { id: string; name: string }[]>();
    for (const i of instances.data ?? []) m.set(i.module, [...(m.get(i.module) ?? []), i]);
    return m;
  }, [instances.data]);
  const added = (id: string) => byModule.has(id);

  const all = useMemo(() => modules.data ?? [], [modules.data]);
  // Search matches the name, the description and the category (in English
  // and in the interface language), so "storage" and "Speicher" both work.
  const matches = useMemo(
    () =>
      all.filter(
        (m) =>
          (!preset || m.presets?.includes(preset)) &&
          (show === "all" || (show === "added") === byModule.has(m.id)) &&
          (!q || `${m.name} ${m.description} ${m.category ?? ""} ${categoryLabel(m.category ?? "")}`.toLowerCase().includes(q)),
      ),
    [all, preset, show, q, byModule],
  );
  const counts = useMemo(() => {
    const c = new Map<string, number>();
    for (const m of matches) c.set(m.category ?? "", (c.get(m.category ?? "") ?? 0) + 1);
    return [...c.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]));
  }, [matches]);
  const list = category ? matches.filter((m) => (m.category ?? "") === category) : matches;
  const groups = useMemo(() => {
    const g = new Map<string, Manifest[]>();
    for (const m of list) g.set(m.category ?? "", [...(g.get(m.category ?? "") ?? []), m]);
    for (const ms of g.values()) ms.sort((a, b) => Number(byModule.has(b.id)) - Number(byModule.has(a.id)) || a.name.localeCompare(b.name));
    return [...g.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]));
  }, [list, byModule]);

  const addedCount = all.filter((m) => added(m.id)).length;
  const presetLabel = presetNames.find(([id]) => id === preset)?.[1] ?? "";
  const picks = (featured[preset] ?? []).map((id) => all.find((m) => m.id === id)).filter((m): m is Manifest => !!m);
  const recommending = !!preset && !expanded && !q && !category && show === "all" && picks.length > 0;
  const clear = () => {
    setQuery("");
    setCategory("");
    setShow("all");
    searchBox.current?.focus();
  };

  const row = (m: Manifest) => <ModuleRow key={m.id} m={m} instances={byModule.get(m.id) ?? []} onConnect={() => setAdding(m)} />;

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Modules")}</h1>
        <p>
          {t("Each module connects one kind of thing, like a mailbox, a server or a media library. Connect as many of each as you need.")}{" "}
          <Link href="/modules/registry">{t("Find more on your hub")}</Link>
        </p>
      </div>

      <div className="mod-tools">
        <div className="mod-search">
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
            <path d="M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14ZM20 20l-4-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
          <input
            ref={searchBox}
            type="search"
            className="input"
            aria-label={t("Search modules")}
            placeholder={t("Search modules")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Escape" && query && (e.preventDefault(), setQuery(""))}
          />
          <kbd aria-hidden="true">/</kbd>
        </div>
        <div className="mod-seg" role="radiogroup" aria-label={t("Show modules for")} onKeyDown={arrowKeys}>
          {presetNames.map(([id, label]) => (
            <button key={id} type="button" role="radio" aria-checked={preset === id} tabIndex={preset === id ? 0 : -1} onClick={() => setPreset(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {modules.isError && (
        <ErrorNote error={modules.error} retry={() => modules.refetch()} />
      )}

      {modules.data?.length === 0 && (
        <div className="empty">
          <h2>{t("No modules installed")}</h2>
          <p className="muted">{t("Built-in modules ship with Conduit. Add more from your hub, or put external modules in the daemon's modules folder and restart it.")}</p>
          <div className="inline">
            <Link href="/modules/registry" className="btn">
              {t("Browse the hub")}
            </Link>
          </div>
        </div>
      )}

      {all.length > 0 && (
        <>
          <div className="mod-filters">
            <div className="mod-chips" role="group" aria-label={t("Categories")}>
              <button type="button" className="mod-chip" aria-pressed={category === ""} onClick={() => setCategory("")}>
                {t("All")} <span className="n">{matches.length}</span>
              </button>
              {counts.map(([c, n]) => (
                <button type="button" key={c} className="mod-chip" aria-pressed={category === c} onClick={() => setCategory(category === c ? "" : c)}>
                  {categoryLabel(c)} <span className="n">{n}</span>
                </button>
              ))}
              {category && !counts.some(([c]) => c === category) && (
                <button type="button" className="mod-chip" aria-pressed onClick={() => setCategory("")}>
                  {categoryLabel(category)} <span className="n">0</span>
                </button>
              )}
            </div>
            <div className="spread mod-status">
              <p className="small muted" aria-live="polite">
                {t("{added} added, {available} available", { added: addedCount, available: all.length - addedCount })}
              </p>
              <div className="mod-seg sm" role="radiogroup" aria-label={t("Show")} onKeyDown={arrowKeys}>
                {(
                  [
                    ["all", t("All")],
                    ["added", t("Added")],
                    ["available", t("Not added yet")],
                  ] as const
                ).map(([id, label]) => (
                  <button key={id} type="button" role="radio" aria-checked={show === id} tabIndex={show === id ? 0 : -1} onClick={() => setShow(id)}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {recommending ? (
            <section className="stack mod-picks" style={{ gap: 10 }} aria-labelledby="picks-title">
              <div className="stack" style={{ gap: 4 }}>
                <h2 id="picks-title">{t("Start here: {preset}", { preset: presetLabel })}</h2>
                <p className="small muted">{t("The ones most people pick first. Nothing is added until you connect it, and you can add the rest later.")}</p>
              </div>
              <div className="panel rows">{picks.map(row)}</div>
              <div>
                <button type="button" className="btn" onClick={() => setExpanded(true)}>
                  {t("Show all {n} for {preset}", { n: matches.length, preset: presetLabel })}
                </button>
              </div>
            </section>
          ) : list.length === 0 ? (
            <div className="empty">
              <h2>{show === "added" && !q && !category ? t("Nothing added here yet") : t("No modules match")}</h2>
              <p className="muted">
                {show === "added" && !q && !category
                  ? t("Connect a module and it shows up here.")
                  : q
                    ? t("Nothing matches \"{q}\". Try a product name like Plex, or a kind of thing like storage.", { q: query.trim() })
                    : t("Try another category, or show everything.")}
              </p>
              <div className="inline">
                <button type="button" className="btn" onClick={clear}>
                  {t("Clear filters")}
                </button>
                {preset && (
                  <button type="button" className="btn quiet" onClick={() => setPreset("")}>
                    {t("Show all modules")}
                  </button>
                )}
              </div>
            </div>
          ) : (
            groups.map(([cat, ms]) => (
              <section key={cat} className="stack" style={{ gap: 8 }} aria-labelledby={`cat-${cat || "other"}`}>
                <h2 className="section-title mod-cat" id={`cat-${cat || "other"}`}>
                  {categoryLabel(cat)} <span className="n">{ms.length}</span>
                </h2>
                <div className="panel rows">{ms.map(row)}</div>
              </section>
            ))
          )}
        </>
      )}
      {adding && <ConnectDialog m={adding} onClose={() => setAdding(null)} />}
    </div>
  );
}

function ModuleRow({ m, instances, onConnect }: { m: Manifest; instances: { id: string; name: string }[]; onConnect: () => void }) {
  // A built-in module has exactly one instance, with the module's own id.
  const builtin = instances.some((i) => i.id === m.id);
  const n = instances.length;
  return (
    <div className="row module-row" data-added={n > 0 || undefined}>
      <span className="mod-icon">
        <ModuleIcon icon={m.icon} category={m.category} />
      </span>
      <div className="stack mod-text" style={{ gap: 2 }}>
        <strong>{m.name}</strong>
        <span className="small muted">{m.description}</span>
      </div>
      <span className="mod-state xs">
        {builtin ? (
          <span className="mod-added">{t("Built in")}</span>
        ) : n > 0 ? (
          <span className="mod-added">{tn("Added", "{n} added", n)}</span>
        ) : null}
      </span>
      <span className="mod-act">
        {builtin || n === 1 ? (
          <Link href={`/i/${instances[0].id}`} className="btn sm" aria-label={t("Open {name}", { name: instances[0].name })}>
            {t("Open")}
          </Link>
        ) : null}
        {!builtin && (
          <button type="button" className={`btn sm ${n > 0 ? "quiet" : ""}`} onClick={onConnect} aria-label={n > 0 ? t("Add another {name}", { name: m.name }) : t("Connect {name}", { name: m.name })}>
            {n > 0 ? t("Add another") : t("Connect")}
          </button>
        )}
      </span>
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
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
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
          <div className="inline" style={{ gap: 10 }}>
            <span className="mod-icon">
              <ModuleIcon icon={m.icon} category={m.category} />
            </span>
            <h2 id="connect-title">{t("Connect {name}", { name: m.name })}</h2>
          </div>
          <label className="field">
            <span>{t("Name")}</span>
            <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
            <small>{t("Shown in the lamp row and the menu, e.g. \"Work mail\" or \"Home server\".")}</small>
          </label>
          <SchemaForm schema={schema} value={config} onChange={setConfig} idPrefix={`cfg-${m.id}`} />
          <ErrorNote error={save.error} />
          <div className="inline" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn quiet" onClick={onClose}>
              {t("Cancel")}
            </button>
            <button className="btn primary" disabled={save.isPending}>
              {save.isPending ? t("Connecting…") : t("Connect")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
