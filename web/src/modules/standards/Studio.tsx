import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import { useLocation, useSearch } from "wouter";
import type { Plan } from "../../api/client";
import { t, tn } from "../../i18n";
import { Editor, undoEntry } from "./Editor";
import { Icon, standardIcons } from "./icons";
import { categories, categoryHue, download, run, type Row, type Toolkit } from "./model";
import "./standards.css";
import { ErrorNote } from "../../components/ErrorNote";

export interface Library {
  standards: Row[];
  toolkits: Toolkit[];
}

/** Human names for categories and section kinds (the module sends ids). */
export function categoryName(c: string): string {
  switch (c) {
    case "frontend":
      return t("Frontend");
    case "design":
      return t("Design");
    case "writing":
      return t("Writing");
    case "code":
      return t("Code");
    case "git":
      return t("Git");
    case "review":
      return t("Review");
    case "security":
      return t("Security");
    case "product":
      return t("Product");
  }
  return t("Custom");
}

/** The Standards module's page: library, toolkits, editor. */
export function StandardsStudio({ instance }: { instance: string }) {
  const search = useSearch();
  const [loc, go] = useLocation();
  const open = new URLSearchParams(search).get("std");
  const lib = useQuery({
    queryKey: ["standards", instance, "list"],
    queryFn: async () => (await run<Library>(instance, "list")).out,
  });
  const setOpen = (id: string | null) => go(id ? `${loc}?std=${encodeURIComponent(id)}` : loc);
  const [toast, setToast] = useState<{ text: string; seq?: number; n: number } | null>(null);
  const notify = (text: string, seq?: number) => setToast({ text, seq, n: Date.now() });

  if (lib.error) return <ErrorNote error={lib.error} retry={() => lib.refetch()} />;
  if (!lib.data) return <p className="muted small">{t("Loading standards…")}</p>;
  return (
    <div className="std-root">
      {toast && <Toast key={toast.n} {...toast} instance={instance} onDone={() => setToast(null)} />}
      {open ? (
        <Editor key={open} instance={instance} id={open === "new" ? null : open} library={lib.data} onClose={() => setOpen(null)} onSaved={(id) => setOpen(id)} notify={notify} />
      ) : (
        <LibraryView instance={instance} lib={lib.data} onOpen={setOpen} />
      )}
    </div>
  );
}

function Toast({ text, seq, instance, onDone }: { text: string; seq?: number; instance: string; onDone: () => void }) {
  const qc = useQueryClient();
  const undo = useMutation({
    mutationFn: () => undoEntry(seq!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["standards", instance] });
      onDone();
    },
  });
  return (
    <div className="std-toast" role="status">
      <span className="small">{undo.error ? undo.error.message : text}</span>
      {seq !== undefined && !undo.isSuccess && (
        <button className="btn sm" onClick={() => undo.mutate()} disabled={undo.isPending}>
          {t("Undo")}</button>
      )}
      <button className="btn quiet sm" onClick={onDone} aria-label={t("Dismiss")}>
        <Icon name="x" size={13} />
      </button>
    </div>
  );
}

function LibraryView({ instance, lib, onOpen }: { instance: string; lib: Library; onOpen: (id: string) => void }) {
  const [cat, setCat] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [panel, setPanel] = useState<null | "import" | { kit: Toolkit | null }>(null);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of lib.standards) c[s.category] = (c[s.category] ?? 0) + 1;
    return c;
  }, [lib.standards]);
  const q = query.trim().toLowerCase();
  const shown = lib.standards.filter(
    (s) =>
      (cat === "all" || s.category === cat) &&
      (!q || [s.title, s.summary ?? "", ...s.tags, ...s.appliesTo].some((x) => x.toLowerCase().includes(q))),
  );
  const exportAll = useMutation({
    mutationFn: async (format: "markdown" | "json") => (await run<{ filename: string; content: string }>(instance, "export", { format })).out,
    onSuccess: (o) => download(o.filename, o.content, o.filename.endsWith(".json") ? "application/json" : "text/markdown"),
  });

  return (
    <div className="std">
      <div className="std-bar">
        <p className="std-lede">{t("Every connected AI reads these before it designs, writes or codes for you. The most important ones win when two disagree.")}</p>
        <div className="inline">
          <button className="btn" onClick={() => setPanel(panel === "import" ? null : "import")} aria-expanded={panel === "import"}>
            <Icon name="upload" size={15} />
            {t("Import")}
          </button>
          <button className="btn" onClick={() => exportAll.mutate("markdown")} disabled={exportAll.isPending}>
            <Icon name="downloadIcon" size={15} />
            {t("Export Markdown")}
          </button>
          <button className="btn" onClick={() => exportAll.mutate("json")} disabled={exportAll.isPending}>
            {t("Export JSON")}
          </button>
          <button className="btn primary" onClick={() => onOpen("new")}>
            <Icon name="plus" size={15} />
            {t("New standard")}
          </button>
        </div>
      </div>
      <ErrorNote error={exportAll.error} />
      {panel === "import" && <ImportPanel instance={instance} onClose={() => setPanel(null)} />}

      <section aria-labelledby="std-kits">
        <div className="spread">
          <h2 id="std-kits" className="section-title">{t("Toolkits")}</h2>
          <button className="btn quiet sm" onClick={() => setPanel({ kit: null })}>
            <Icon name="plus" size={14} />
            {t("New toolkit")}
          </button>
        </div>
        {panel && typeof panel === "object" && <ToolkitPanel instance={instance} kit={panel.kit} lib={lib} onClose={() => setPanel(null)} />}
        <div className="std-shelf">
          {lib.toolkits.length === 0 && <p className="muted small">{t("Bundle standards into a toolkit, like a frontend kit of design, accessibility and UI writing. Each toolkit becomes a prompt in every AI.")}</p>}
          {lib.toolkits.map((k) => (
            <ToolkitTile key={k.id} kit={k} lib={lib} onEdit={() => setPanel({ kit: k })} />
          ))}
        </div>
      </section>

      <div className="std-lib">
        <nav className="std-cats" aria-label={t("Categories")}>
          <button className={cat === "all" ? "active" : undefined} aria-pressed={cat === "all"} onClick={() => setCat("all")}>
            <span className="std-hue" style={{ background: "var(--ink-2)" }} />
            <span>{t("All standards")}</span>
            <span className="data std-count">{lib.standards.length}</span>
          </button>
          {categories.map((c) => (
            <button key={c} className={cat === c ? "active" : undefined} aria-pressed={cat === c} onClick={() => setCat(c)} data-empty={!counts[c] || undefined}>
              <span className="std-hue" style={{ background: categoryHue[c] }} />
              <span>{categoryName(c)}</span>
              <span className="data std-count">{counts[c] ?? 0}</span>
            </button>
          ))}
        </nav>
        <div className="stack" style={{ gap: 12, minWidth: 0 }}>
          <label className="std-search">
            <Icon name="search" size={16} />
            <span className="sr-only">{t("Filter standards")}</span>
            <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Filter by title, tag or file pattern")} />
          </label>
          {shown.length === 0 ? (
            <div className="std-empty">
              <p>{lib.standards.length === 0 ? t("No standards yet. Write your first one, or import a Markdown file you already keep.") : t("Nothing matches. Try another category or filter.")}</p>
              <button className="btn" onClick={() => onOpen("new")}>
                {t("New standard")}</button>
            </div>
          ) : (
            <ul className="std-grid">
              {shown.map((s) => (
                <li key={s.id}>
                  <StandardCard s={s} onOpen={() => onOpen(s.id)} />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function countLine(s: Row): string[] {
  const c = s.counts;
  const out: string[] = [];
  if (c.rules) out.push(tn("{n} rule", "{n} rules", c.rules));
  if (c.dodont) out.push(tn("{n} do / don't", "{n} do / don'ts", c.dodont));
  if (c.principles) out.push(tn("{n} principle", "{n} principles", c.principles));
  if (c.checklist) out.push(tn("{n} check", "{n} checks", c.checklist));
  if (c.examples) out.push(tn("{n} example", "{n} examples", c.examples));
  if (c.tokens) out.push(tn("{n} token", "{n} tokens", c.tokens));
  return out.slice(0, 3);
}

function StandardCard({ s, onOpen }: { s: Row; onOpen: () => void }) {
  return (
    <button className="std-card" onClick={onOpen} data-off={!s.enabled || undefined} style={{ ["--hue" as string]: categoryHue[s.category] ?? "var(--off)" }}>
      <span className="std-card-top">
        <span className="std-glyph">
          <Icon name={s.icon} size={20} />
        </span>
        <span className="std-prio" title={t("Priority")}>
          <span className="sr-only">{t("Priority")} </span>
          <span className="data">{s.priority}</span>
        </span>
      </span>
      <span className="std-card-title">{s.title}</span>
      {s.summary && <span className="std-card-sum">{s.summary}</span>}
      <span className="std-card-foot">
        <span className="std-cat">{categoryName(s.category)}</span>
        {!s.enabled && <span className="tag">{t("Off")}</span>}
        {countLine(s).map((l) => (
          <span key={l} className="xs muted">{l}</span>
        ))}
      </span>
      {s.appliesTo.length > 0 && (
        <span className="std-applies">
          {s.appliesTo.slice(0, 4).map((a) => (
            <code key={a}>{a}</code>
          ))}
          {s.appliesTo.length > 4 && <span className="xs muted">+{s.appliesTo.length - 4}</span>}
        </span>
      )}
    </button>
  );
}

/** A toolkit drawn as a shelf of spines: one per standard, coloured by
    category, taller for higher priority. */
function ToolkitTile({ kit, lib, onEdit }: { kit: Toolkit; lib: Library; onEdit: () => void }) {
  const members = kit.standards.map((id) => lib.standards.find((s) => s.id === id)).filter((s): s is Row => !!s);
  return (
    <button className="std-kit" onClick={onEdit} title={t("Edit toolkit {name}", { name: kit.title })}>
      <span className="std-spines" aria-hidden="true">
        {members.map((s) => (
          <span key={s.id} className="std-spine" data-off={!s.enabled || undefined} style={{ background: categoryHue[s.category], height: `${40 + s.priority * 0.4}%` }} title={s.title} />
        ))}
        {members.length === 0 && <span className="std-spine ghost" />}
      </span>
      <span className="std-kit-body">
        <span className="std-kit-title">
          <Icon name={kit.icon || "layers"} size={16} />
          {kit.title}
        </span>
        <span className="xs muted">{members.map((s) => s.title).join(", ") || t("No standards yet")}</span>
        <span className="xs std-kit-prompt">
          {t("Prompt")} <code>standards__{kit.id}</code>
        </span>
      </span>
    </button>
  );
}

function ToolkitPanel({ instance, kit, lib, onClose }: { instance: string; kit: Toolkit | null; lib: Library; onClose: () => void }) {
  const qc = useQueryClient();
  const [k, setK] = useState<Toolkit>(kit ?? { id: "", title: "", icon: "layers", summary: "", standards: [] });
  const done = () => {
    qc.invalidateQueries({ queryKey: ["standards", instance] });
    onClose();
  };
  const save = useMutation({ mutationFn: () => run(instance, "save_toolkit", k), onSuccess: done });
  const del = useMutation({ mutationFn: () => run(instance, "delete_toolkit", { id: k.id }), onSuccess: done });
  const toggle = (id: string) => setK({ ...k, standards: k.standards.includes(id) ? k.standards.filter((x) => x !== id) : [...k.standards, id] });
  return (
    <form
      className="panel std-panel"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <h3>{kit ? t("Edit toolkit") : t("New toolkit")}</h3>
      <div className="std-meta-grid">
        <label className="field">
          <span>{t("Title")}</span>
          <input value={k.title} onChange={(e) => setK({ ...k, title: e.target.value })} required autoFocus placeholder={t("My frontend kit")} />
        </label>
        <label className="field">
          <span>{t("Icon")}</span>
          <select value={k.icon} onChange={(e) => setK({ ...k, icon: e.target.value })}>
            {standardIcons.map((i) => (
              <option key={i} value={i}>{i}</option>
            ))}
          </select>
        </label>
      </div>
      <label className="field">
        <span>{t("Summary")}</span>
        <input value={k.summary ?? ""} onChange={(e) => setK({ ...k, summary: e.target.value })} />
      </label>
      <fieldset className="std-pick">
        <legend className="small">{t("Standards in this toolkit")}</legend>
        {lib.standards.map((s) => (
          <label key={s.id} className="check">
            <input type="checkbox" checked={k.standards.includes(s.id)} onChange={() => toggle(s.id)} />
            <span className="std-hue" style={{ background: categoryHue[s.category] }} />
            {s.title}
          </label>
        ))}
      </fieldset>
      <ErrorNote error={save.error || del.error} />
      <div className="spread">
        {kit ? (
          <button type="button" className="btn danger" onClick={() => confirm(t("Delete the toolkit {name}? Its standards stay.", { name: kit.title })) && del.mutate()}>
            {t("Delete toolkit")}</button>
        ) : (
          <span />
        )}
        <div className="inline">
          <button type="button" className="btn quiet" onClick={onClose}>
            {t("Cancel")}</button>
          <button className="btn primary" disabled={save.isPending}>
            {t("Save toolkit")}</button>
        </div>
      </div>
    </form>
  );
}

function ImportPanel({ instance, onClose }: { instance: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [content, setContent] = useState("");
  const [plan, setPlan] = useState<Plan | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const preview = useMutation({
    mutationFn: async () => (await run(instance, "import", { content }, true)).outcome.result.plan ?? null,
    onSuccess: setPlan,
  });
  const go = useMutation({
    mutationFn: () => run(instance, "import", { content }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["standards", instance] });
      onClose();
    },
  });
  return (
    <div className="panel std-panel">
      <div className="spread">
        <h3>{t("Import standards")}</h3>
        <button className="btn quiet sm" onClick={onClose} aria-label={t("Close")}>
          <Icon name="x" size={14} />
        </button>
      </div>
      <p className="small muted">{t("Markdown with front matter (one or many standards), JSON from an export, or any Markdown guide: headings like Rules, Principles or Checklist become sections. Standards with the same id are replaced; you can undo it.")}</p>
      <div className="inline">
        <button className="btn sm" onClick={() => file.current?.click()}>
          {t("Choose a file")}</button>
        <input
          ref={file}
          type="file"
          accept=".md,.markdown,.json,.txt,text/markdown,application/json"
          hidden
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f) {
              setContent(await f.text());
              setPlan(null);
            }
          }}
        />
      </div>
      <label className="field">
        <span>{t("Or paste it here")}</span>
        <textarea
          value={content}
          onChange={(e) => {
            setContent(e.target.value);
            setPlan(null);
          }}
          rows={8}
        />
      </label>
      <ErrorNote error={preview.error || go.error} />
      {plan && (
        <ul className="std-plan">
          <li className="small">{plan.summary}</li>
          {plan.changes.map((c) => (
            <li key={c.target} className="xs">
              <span className={`std-op ${c.op}`}>{c.op === "create" ? t("new") : t("replaces")}</span> <code>{c.target}</code>
            </li>
          ))}
        </ul>
      )}
      <div className="inline">
        <button className="btn" disabled={!content.trim() || preview.isPending} onClick={() => preview.mutate()}>
          {t("Preview")}</button>
        <button className="btn primary" disabled={!plan || go.isPending} onClick={() => go.mutate()}>
          {t("Import")}</button>
      </div>
    </div>
  );
}
