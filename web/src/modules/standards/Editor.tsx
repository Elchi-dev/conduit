import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { api, ok } from "../../api/client";
import { t, tn } from "../../i18n";
import { ago } from "../../lib/format";
import { Icon, standardIcons } from "./icons";
import {
  blankSection,
  blankStandard,
  categories,
  categoryHue,
  cssColor,
  diffLines,
  download,
  hex6,
  levels,
  render,
  run,
  sectionKinds,
  tokenKinds,
  typeStyle,
  type Example,
  type Level,
  type Link,
  type Pair,
  type Rule,
  type Section,
  type SectionKind,
  type Standard,
  type TokenGroup,
  type TokenKind,
} from "./model";
import { categoryName, type Library } from "./Studio";

export function kindName(k: SectionKind): string {
  switch (k) {
    case "principles":
      return t("Principles");
    case "dodont":
      return t("Do and don't");
    case "rules":
      return t("Rules");
    case "examples":
      return t("Examples");
    case "tokens":
      return t("Tokens");
    case "checklist":
      return t("Checklist");
    case "references":
      return t("References");
    case "notes":
      return t("Notes");
  }
}

const kindIcon: Record<SectionKind, string> = {
  principles: "compass",
  dodont: "flag",
  rules: "ruler",
  examples: "code",
  tokens: "palette",
  checklist: "check",
  references: "book",
  notes: "pen",
};

function levelName(l: Level) {
  return l === "must" ? t("Must") : l === "should" ? t("Should") : t("May");
}

function tokenKindName(k: TokenKind) {
  switch (k) {
    case "color":
      return t("Colours");
    case "type":
      return t("Type scale");
    case "spacing":
      return t("Spacing");
    case "radius":
      return t("Radii");
    case "shadow":
      return t("Shadows");
    case "motion":
      return t("Motion");
  }
  return t("Other");
}

export type Notify = (text: string, undoSeq?: number) => void;

export function Editor({ instance, id, library, onClose, onSaved, notify }: { instance: string; id: string | null; library: Library; onClose: () => void; onSaved: (id: string) => void; notify: Notify }) {
  const qc = useQueryClient();
  const loaded = useQuery({
    queryKey: ["standards", instance, "get", id],
    queryFn: async () => (await run<{ standard: Standard }>(instance, "get", { id, format: "full" })).out.standard,
    enabled: !!id,
  });
  const [draft, setDraft] = useState<Standard | null>(id ? null : blankStandard());
  const base = id ? loaded.data : undefined;
  useEffect(() => {
    if (loaded.data && !draft) setDraft(withDefaults(loaded.data));
  }, [loaded.data, draft]);
  const [review, setReview] = useState<{ before?: string; after: string; op: string } | null>(null);
  const [side, setSide] = useState<"preview" | "history">("preview");

  const dirty = useMemo(() => !!draft && (!base || JSON.stringify(stripMeta(withDefaults(base))) !== JSON.stringify(stripMeta(draft))), [draft, base]);
  useEffect(() => {
    if (!dirty) return;
    const h = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty]);

  const refresh = () => qc.invalidateQueries({ queryKey: ["standards", instance] });
  const preview = useMutation({
    mutationFn: async () => {
      const { outcome } = await run(instance, "save", draft, true);
      const c = outcome.result.plan?.changes?.[0];
      return { before: typeof c?.before === "string" ? c.before : undefined, after: typeof c?.after === "string" ? c.after : render(draft!), op: c?.op ?? "create" };
    },
    onSuccess: setReview,
  });
  const save = useMutation({
    mutationFn: async () => (await run<{ id: string }>(instance, "save", draft)).outcome,
    onSuccess: (o) => {
      setReview(null);
      refresh();
      if (o.approval?.status === "pending") {
        notify(t("Waiting for approval before it's saved."));
        return;
      }
      const sid = (o.result.output as { id: string }).id;
      notify(t("Saved {name}.", { name: draft!.title }), o.audit.undo ? o.audit.seq : undefined);
      setDraft(null);
      onSaved(sid);
    },
  });
  const del = useMutation({
    mutationFn: async () => (await run(instance, "delete", { id })).outcome,
    onSuccess: (o) => {
      refresh();
      notify(t("Deleted {name}.", { name: draft!.title }), o.audit.undo ? o.audit.seq : undefined);
      onClose();
    },
  });
  const exp = useMutation({
    mutationFn: async (format: "markdown" | "json") => (await run<{ filename: string; content: string }>(instance, "export", { id, format })).out,
    onSuccess: (o) => download(o.filename, o.content, o.filename.endsWith(".json") ? "application/json" : "text/markdown"),
  });

  if (loaded.error) return <div className="error">{loaded.error.message}</div>;
  if (!draft) return <p className="muted small">{t("Loading standards…")}</p>;
  const set = (p: Partial<Standard>) => setDraft({ ...draft, ...p });
  const close = () => (!dirty || confirm(t("Leave without saving your changes?"))) && onClose();
  const md = render(draft);
  const hue = categoryHue[draft.category] ?? "var(--off)";

  return (
    <div className="std std-editor" style={{ ["--hue" as string]: hue }}>
      <div className="std-ed-bar">
        <button className="btn quiet" onClick={close}>
          <Icon name="back" size={16} />
          {t("All standards")}
        </button>
        <div className="inline">
          {dirty && <span className="xs muted" role="status">{t("Unsaved changes")}</span>}
          {id && (
            <>
              <button className="btn sm" onClick={() => exp.mutate("markdown")}>
                {t("Export Markdown")}</button>
              <button className="btn sm" onClick={() => exp.mutate("json")}>
                {t("Export JSON")}</button>
              <button className="btn sm danger" onClick={() => confirm(t("Delete {name}? You can undo it from the timeline.", { name: draft.title })) && del.mutate()}>
                {t("Delete")}</button>
            </>
          )}
          <button className="btn primary" disabled={!draft.title.trim() || preview.isPending || (!!id && !dirty)} onClick={() => preview.mutate()}>
            {t("Review and save")}</button>
        </div>
      </div>
      {(preview.error || save.error || del.error || exp.error) && <div className="error">{(preview.error || save.error || del.error || exp.error)!.message}</div>}

      {review && (
        <section className="panel std-review" aria-labelledby="std-review-h">
          <div className="spread">
            <h2 id="std-review-h">{review.op === "create" ? t("This is what every AI will get") : t("What changes for every AI")}</h2>
            <div className="inline">
              <button className="btn quiet" onClick={() => setReview(null)}>
                {t("Keep editing")}</button>
              <button className="btn primary" onClick={() => save.mutate()} disabled={save.isPending} autoFocus>
                {review.op === "create" ? t("Create standard") : t("Save changes")}
              </button>
            </div>
          </div>
          <Diff before={review.before ?? ""} after={review.after} />
        </section>
      )}

      <div className="std-ed-grid">
        <div className="stack std-ed-main">
          <MetaForm s={draft} set={set} library={library} isNew={!id} />
          <Sections sections={draft.sections} onChange={(sections) => set({ sections })} />
        </div>
        <aside className="std-aside" aria-label={t("Preview and history")}>
          <div className="std-tabs" role="tablist" aria-label={t("Preview and history")}>
            <button role="tab" aria-selected={side === "preview"} onClick={() => setSide("preview")}>
              {t("What the AI sees")}</button>
            {id && (
              <button role="tab" aria-selected={side === "history"} onClick={() => setSide("history")}>
                <Icon name="history" size={14} />
                {t("History")}
              </button>
            )}
          </div>
          {side === "preview" || !id ? (
            <AIPreview md={md} id={draft.id || ""} enabled={draft.enabled} />
          ) : (
            <History
              instance={instance}
              id={id}
              current={base ? render(base) : md}
              onRestored={(o) => {
                refresh();
                setDraft(null);
                notify(t("Restored an earlier version."), o);
              }}
              dirty={dirty}
            />
          )}
        </aside>
      </div>
    </div>
  );
}

function withDefaults(s: Standard): Standard {
  return { ...s, tags: s.tags ?? [], appliesTo: s.appliesTo ?? [], sections: s.sections ?? [] };
}

function stripMeta(s: Standard) {
  const { updated: _u, ...rest } = s;
  void _u;
  return rest;
}

// ---- meta ----

function MetaForm({ s, set, library, isNew }: { s: Standard; set: (p: Partial<Standard>) => void; library: Library; isNew: boolean }) {
  const uid = useId();
  const [iconOpen, setIconOpen] = useState(false);
  const kits = library.toolkits.filter((k) => s.id && k.standards.includes(s.id));
  return (
    <section className="std-meta" aria-label={t("About this standard")}>
      <div className="std-title-row">
        <div className="std-icon-pick">
          <button className="std-glyph big" onClick={() => setIconOpen(!iconOpen)} aria-expanded={iconOpen} aria-label={t("Choose an icon")}>
            <Icon name={s.icon} size={26} />
          </button>
          {iconOpen && (
            <div className="std-icons" role="radiogroup" aria-label={t("Icon")}>
              {standardIcons.map((i) => (
                <label key={i} title={i}>
                  <input
                    type="radio"
                    name={`${uid}-icon`}
                    checked={s.icon === i}
                    onChange={() => {
                      set({ icon: i });
                      setIconOpen(false);
                    }}
                    onKeyDown={(e) => e.key === "Escape" && setIconOpen(false)}
                  />
                  <Icon name={i} size={20} />
                  <span className="sr-only">{i}</span>
                </label>
              ))}
            </div>
          )}
        </div>
        <label className="std-title-field">
          <span className="sr-only">{t("Title")}</span>
          <textarea
            rows={1}
            className="std-grow"
            value={s.title}
            onChange={(e) => set({ title: e.target.value.replace(/\n/g, " ") })}
            onKeyDown={(e) => e.key === "Enter" && e.preventDefault()}
            placeholder={t("Name this standard")}
            autoFocus={isNew}
          />
        </label>
        <label className="std-switch">
          <input type="checkbox" role="switch" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
          <span>{s.enabled ? t("On for every AI") : t("Off")}</span>
        </label>
      </div>
      <label className="field">
        <span className="sr-only">{t("Summary")}</span>
        <input className="std-summary" value={s.summary ?? ""} onChange={(e) => set({ summary: e.target.value })} placeholder={t("One sentence on what this standard is for")} />
      </label>
      <div className="std-meta-grid">
        <label className="field">
          <span>{t("Category")}</span>
          <select value={s.category} onChange={(e) => set({ category: e.target.value })}>
            {categories.map((c) => (
              <option key={c} value={c}>{categoryName(c)}</option>
            ))}
          </select>
        </label>
        <div className="field">
          <label htmlFor={`${uid}-prio`}>
            <span>{t("Priority")}</span>
          </label>
          <div className="std-prio-row">
            <input id={`${uid}-prio`} type="range" min={0} max={100} step={5} value={s.priority} onChange={(e) => set({ priority: Number(e.target.value) })} aria-describedby={`${uid}-prio-h`} />
            <output className="data" htmlFor={`${uid}-prio`}>{s.priority}</output>
          </div>
          <small id={`${uid}-prio-h`}>{t("Higher wins when two standards disagree.")}</small>
        </div>
        {isNew && (
          <label className="field">
            <span>{t("ID")}</span>
            <input className="data" value={s.id} onChange={(e) => set({ id: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-") })} placeholder={t("made from the title")} />
          </label>
        )}
      </div>
      <Chips label={t("Applies to")} value={s.appliesTo ?? []} onChange={(appliesTo) => set({ appliesTo })} mono placeholder={t("*.tsx, project:shop, frontend, email …")}
        hint={t("File patterns, project:<name>, or kinds of task (frontend, writing, email, code, git, review). Empty: whenever the task is about its category.")} />
      <Chips label={t("Tags")} value={s.tags ?? []} onChange={(tags) => set({ tags })} placeholder={t("Add a tag")} />
      {kits.length > 0 && (
        <p className="xs muted">
          {t("In toolkits:")} {kits.map((k) => k.title).join(", ")}
        </p>
      )}
    </section>
  );
}

function Chips({ label, value, onChange, placeholder, hint, mono }: { label: string; value: string[]; onChange: (v: string[]) => void; placeholder?: string; hint?: string; mono?: boolean }) {
  const uid = useId();
  const [text, setText] = useState("");
  const add = (raw: string) => {
    const parts = raw.split(",").map((p) => p.trim()).filter((p) => p && !value.includes(p));
    if (parts.length) onChange([...value, ...parts]);
    setText("");
  };
  return (
    <div className="field">
      <label htmlFor={uid}>
        <span>{label}</span>
      </label>
      <div className="std-chips">
        {value.map((v) => (
          <span key={v} className={`std-chip${mono ? " data" : ""}`}>
            {v}
            <button type="button" onClick={() => onChange(value.filter((x) => x !== v))} aria-label={t("Remove {name}", { name: v })}>
              <Icon name="x" size={12} />
            </button>
          </span>
        ))}
        <input
          id={uid}
          value={text}
          className={mono ? "data" : undefined}
          placeholder={value.length ? "" : placeholder}
          aria-describedby={hint ? `${uid}-h` : undefined}
          onChange={(e) => (e.target.value.includes(",") ? add(e.target.value) : setText(e.target.value))}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add(text);
            } else if (e.key === "Backspace" && !text && value.length) onChange(value.slice(0, -1));
          }}
          onBlur={() => text && add(text)}
        />
      </div>
      {hint && <small id={`${uid}-h`}>{hint}</small>}
    </div>
  );
}

// ---- sections ----

function move<T>(a: T[], from: number, to: number): T[] {
  if (to < 0 || to >= a.length || from === to) return a;
  const c = a.slice();
  const [x] = c.splice(from, 1);
  c.splice(to, 0, x);
  return c;
}

function Sections({ sections, onChange }: { sections: Section[]; onChange: (s: Section[]) => void }) {
  const [announce, setAnnounce] = useState("");
  const [drag, setDrag] = useState<number | null>(null);
  const [over, setOver] = useState<number | null>(null);
  const [focusHandle, setFocusHandle] = useState<number | null>(null);
  const root = useRef<HTMLDivElement>(null);
  // Stable keys so React keeps each block's state while they move.
  const keys = useRef<number[]>([]);
  const next = useRef(0);
  while (keys.current.length < sections.length) keys.current.push(next.current++);
  if (keys.current.length > sections.length) keys.current.length = sections.length;

  useEffect(() => {
    if (focusHandle === null) return;
    root.current?.querySelectorAll<HTMLButtonElement>("[data-handle]")[focusHandle]?.focus();
    setFocusHandle(null);
  }, [focusHandle]);

  const moveTo = (from: number, to: number) => {
    if (to < 0 || to >= sections.length || from === to) return;
    keys.current = move(keys.current, from, to);
    onChange(move(sections, from, to));
    setAnnounce(t("Moved to position {n} of {total}.", { n: to + 1, total: sections.length }));
    setFocusHandle(to);
  };
  const update = (i: number, s: Section) => onChange(sections.map((x, j) => (j === i ? s : x)));
  const remove = (i: number) => {
    keys.current.splice(i, 1);
    onChange(sections.filter((_, j) => j !== i));
  };
  const add = (k: SectionKind) => {
    onChange([...sections, blankSection(k)]);
    setTimeout(() => {
      const blocks = root.current?.querySelectorAll<HTMLElement>(".std-block");
      blocks?.[blocks.length - 1]?.querySelector<HTMLElement>(".std-block-body input, .std-block-body textarea")?.focus();
    });
  };

  return (
    <div className="stack" style={{ gap: 12 }} ref={root}>
      <p className="sr-only" role="status" aria-live="polite">{announce}</p>
      {sections.length === 0 && <p className="std-empty small">{t("No sections yet. Add principles, rules or a checklist below.")}</p>}
      {sections.map((sec, i) => (
        <article
          key={keys.current[i]}
          className="std-block"
          data-kind={sec.kind}
          data-drag={drag === i || undefined}
          data-over={over === i && drag !== null && drag !== i ? (drag > i ? "before" : "after") : undefined}
          draggable={drag === i}
          onDragStart={(e) => {
            e.dataTransfer.effectAllowed = "move";
            e.dataTransfer.setData("text/plain", String(i));
          }}
          onDragOver={(e) => {
            if (drag === null) return;
            e.preventDefault();
            setOver(i);
          }}
          onDrop={(e) => {
            e.preventDefault();
            if (drag !== null) moveTo(drag, i);
            setDrag(null);
            setOver(null);
          }}
          onDragEnd={() => {
            setDrag(null);
            setOver(null);
          }}
          onKeyDown={(e: KeyboardEvent) => {
            if (e.altKey && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
              e.preventDefault();
              moveTo(i, i + (e.key === "ArrowUp" ? -1 : 1));
            }
          }}
          aria-label={sec.title || kindName(sec.kind)}
        >
          <header className="std-block-head">
            <button
              type="button"
              className="std-handle"
              data-handle
              aria-label={t("Move {name}. Use the arrow keys.", { name: sec.title || kindName(sec.kind) })}
              aria-roledescription={t("drag handle")}
              onPointerDown={() => setDrag(i)}
              onPointerUp={() => drag === i && over === null && setDrag(null)}
              onKeyDown={(e) => {
                if (e.key === "ArrowUp" || e.key === "ArrowDown") {
                  e.preventDefault();
                  e.stopPropagation();
                  moveTo(i, i + (e.key === "ArrowUp" ? -1 : 1));
                }
              }}
            >
              <Icon name="grip" size={18} strokeWidth={2.8} />
            </button>
            <span className="std-kind">
              <Icon name={kindIcon[sec.kind]} size={15} />
              <span className="sr-only">{kindName(sec.kind)}</span>
            </span>
            <input className="std-block-title" value={sec.title ?? ""} placeholder={kindName(sec.kind)} onChange={(e) => update(i, { ...sec, title: e.target.value })} aria-label={t("Section title")} />
            <span className="std-block-tools">
              <button type="button" className="btn quiet sm" onClick={() => moveTo(i, i - 1)} disabled={i === 0} aria-label={t("Move up")}>
                <Icon name="up" size={14} />
              </button>
              <button type="button" className="btn quiet sm" onClick={() => moveTo(i, i + 1)} disabled={i === sections.length - 1} aria-label={t("Move down")}>
                <Icon name="down" size={14} />
              </button>
              <button type="button" className="btn quiet sm" onClick={() => confirm(t("Remove this section?")) && remove(i)} aria-label={t("Remove section")}>
                <Icon name="x" size={14} />
              </button>
            </span>
          </header>
          <div className="std-block-body">
            <SectionBody sec={sec} onChange={(s) => update(i, s)} />
          </div>
        </article>
      ))}
      <div className="std-add" role="group" aria-label={t("Add a section")}>
        <span className="small muted">{t("Add")}</span>
        {sectionKinds.map((k) => (
          <button key={k} type="button" className="btn sm" onClick={() => add(k)}>
            <Icon name={kindIcon[k]} size={14} />
            {kindName(k)}
          </button>
        ))}
      </div>
      <p className="xs muted">{t("Tip: Alt+↑ and Alt+↓ move the section you're in.")}</p>
    </div>
  );
}

function SectionBody({ sec, onChange }: { sec: Section; onChange: (s: Section) => void }) {
  switch (sec.kind) {
    case "principles":
      return <Items items={sec.items ?? []} onChange={(items) => onChange({ ...sec, items })} placeholder={t("A belief that guides the work")} />;
    case "checklist":
      return <Items items={sec.items ?? []} onChange={(items) => onChange({ ...sec, items })} placeholder={t("Something to check before calling it done")} checkbox />;
    case "dodont":
      return <Pairs pairs={sec.pairs ?? []} onChange={(pairs) => onChange({ ...sec, pairs })} />;
    case "rules":
      return <Rules rules={sec.rules ?? []} onChange={(rules) => onChange({ ...sec, rules })} />;
    case "examples":
      return <Examples examples={sec.examples ?? []} onChange={(examples) => onChange({ ...sec, examples })} />;
    case "tokens":
      return <Tokens groups={sec.groups ?? []} onChange={(groups) => onChange({ ...sec, groups })} />;
    case "references":
      return <Links links={sec.links ?? []} onChange={(links) => onChange({ ...sec, links })} />;
    case "notes":
      return (
        <label className="field">
          <span className="sr-only">{t("Notes")}</span>
          <textarea className="std-notes" value={sec.markdown ?? ""} onChange={(e) => onChange({ ...sec, markdown: e.target.value })} rows={6} placeholder={t("Anything else, in Markdown: preferred stacks, background, links to decide by.")} />
        </label>
      );
  }
}

/** A list where Enter adds a row below and Backspace in an empty row removes it. */
function useRowFocus() {
  const ref = useRef<HTMLDivElement>(null);
  const [focus, setFocus] = useState<number | null>(null);
  useEffect(() => {
    if (focus === null) return;
    ref.current?.querySelectorAll<HTMLElement>("[data-row]")[focus]?.querySelector<HTMLElement>("input, textarea")?.focus();
    setFocus(null);
  }, [focus]);
  return { ref, setFocus };
}

function RemoveRow({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button type="button" className="btn quiet sm std-x" onClick={onClick} aria-label={label}>
      <Icon name="x" size={13} />
    </button>
  );
}

function AddRow({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" className="btn quiet sm std-addrow" onClick={onClick}>
      <Icon name="plus" size={13} />
      {children}
    </button>
  );
}

function Items({ items, onChange, placeholder, checkbox }: { items: string[]; onChange: (v: string[]) => void; placeholder: string; checkbox?: boolean }) {
  const { ref, setFocus } = useRowFocus();
  return (
    <div className="std-rows" ref={ref}>
      {items.map((it, i) => (
        <div key={i} className="std-item" data-row>
          <span className={checkbox ? "std-box" : "std-bullet"} aria-hidden="true" />
          <textarea
            rows={1}
            className="std-grow"
            value={it}
            placeholder={placeholder}
            aria-label={checkbox ? t("Check {n}", { n: i + 1 }) : t("Item {n}", { n: i + 1 })}
            onChange={(e) => onChange(items.map((x, j) => (j === i ? e.target.value : x)))}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                onChange([...items.slice(0, i + 1), "", ...items.slice(i + 1)]);
                setFocus(i + 1);
              } else if (e.key === "Backspace" && !it && items.length > 1) {
                e.preventDefault();
                onChange(items.filter((_, j) => j !== i));
                setFocus(Math.max(0, i - 1));
              }
            }}
          />
          <RemoveRow onClick={() => onChange(items.filter((_, j) => j !== i))} label={t("Remove item {n}", { n: i + 1 })} />
        </div>
      ))}
      <AddRow
        onClick={() => {
          onChange([...items, ""]);
          setFocus(items.length);
        }}
      >
        {checkbox ? t("Add a check") : t("Add an item")}
      </AddRow>
    </div>
  );
}

function Pairs({ pairs, onChange }: { pairs: Pair[]; onChange: (v: Pair[]) => void }) {
  const { ref, setFocus } = useRowFocus();
  const set = (i: number, p: Pair) => onChange(pairs.map((x, j) => (j === i ? p : x)));
  return (
    <div className="std-rows" ref={ref}>
      <div className="std-pair std-pair-head" aria-hidden="true">
        <span className="std-do-h">
          <Icon name="check" size={14} /> {t("Do")}
        </span>
        <span className="std-dont-h">
          <Icon name="x" size={14} /> {t("Don't")}
        </span>
        <span />
      </div>
      {pairs.map((p, i) => (
        <div key={i} className="std-pair" data-row>
          <textarea rows={1} className="std-do std-grow" value={p.do ?? ""} onChange={(e) => set(i, { ...p, do: e.target.value })} aria-label={t("Do, row {n}", { n: i + 1 })} placeholder={t("Do this")} />
          <textarea
            rows={1}
            className="std-dont std-grow"
            value={p.dont ?? ""}
            onChange={(e) => set(i, { ...p, dont: e.target.value })}
            aria-label={t("Don't, row {n}", { n: i + 1 })}
            placeholder={t("instead of this")}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                onChange([...pairs.slice(0, i + 1), { do: "", dont: "" }, ...pairs.slice(i + 1)]);
                setFocus(i + 1);
              }
            }}
          />
          <RemoveRow onClick={() => onChange(pairs.filter((_, j) => j !== i))} label={t("Remove row {n}", { n: i + 1 })} />
        </div>
      ))}
      <AddRow
        onClick={() => {
          onChange([...pairs, { do: "", dont: "" }]);
          setFocus(pairs.length);
        }}
      >
        {t("Add a pair")}
      </AddRow>
    </div>
  );
}

function Rules({ rules, onChange }: { rules: Rule[]; onChange: (v: Rule[]) => void }) {
  const uid = useId();
  const { ref, setFocus } = useRowFocus();
  const set = (i: number, r: Rule) => onChange(rules.map((x, j) => (j === i ? r : x)));
  return (
    <div className="std-rows" ref={ref}>
      {rules.map((r, i) => (
        <div key={i} className="std-rule" data-row data-level={r.level}>
          <div className="std-rule-main">
            <textarea
              rows={1}
              className="std-grow"
              value={r.text}
              onChange={(e) => set(i, { ...r, text: e.target.value })}
              aria-label={t("Rule {n}", { n: i + 1 })}
              placeholder={t("The rule, as an instruction")}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  onChange([...rules.slice(0, i + 1), { level: r.level, text: "" }, ...rules.slice(i + 1)]);
                  setFocus(i + 1);
                }
              }}
            />
            <input className="std-why" value={r.why ?? ""} onChange={(e) => set(i, { ...r, why: e.target.value })} aria-label={t("Why, rule {n}", { n: i + 1 })} placeholder={t("Why (optional)")} />
          </div>
          <div className="std-levels" role="radiogroup" aria-label={t("Strength of rule {n}", { n: i + 1 })}>
            {levels.map((l) => (
              <label key={l} className="std-level" data-l={l}>
                <input type="radio" name={`${uid}-${i}`} checked={r.level === l} onChange={() => set(i, { ...r, level: l })} />
                <span>{levelName(l)}</span>
              </label>
            ))}
          </div>
          <RemoveRow onClick={() => onChange(rules.filter((_, j) => j !== i))} label={t("Remove rule {n}", { n: i + 1 })} />
        </div>
      ))}
      <AddRow
        onClick={() => {
          onChange([...rules, { level: "should", text: "" }]);
          setFocus(rules.length);
        }}
      >
        {t("Add a rule")}
      </AddRow>
    </div>
  );
}

function Examples({ examples, onChange }: { examples: Example[]; onChange: (v: Example[]) => void }) {
  const set = (i: number, e: Example) => onChange(examples.map((x, j) => (j === i ? e : x)));
  return (
    <div className="std-rows">
      {examples.map((e, i) => (
        <div key={i} className="std-example" data-row>
          <div className="std-ex-meta">
            <input value={e.title ?? ""} onChange={(ev) => set(i, { ...e, title: ev.target.value })} aria-label={t("Example title")} placeholder={t("What this example shows")} />
            <input className="data std-lang" value={e.lang ?? ""} onChange={(ev) => set(i, { ...e, lang: ev.target.value })} aria-label={t("Language")} placeholder={t("tsx, css … or empty for text")} />
            <RemoveRow onClick={() => onChange(examples.filter((_, j) => j !== i))} label={t("Remove example")} />
          </div>
          <input className="std-ex-note" value={e.note ?? ""} onChange={(ev) => set(i, { ...e, note: ev.target.value })} aria-label={t("Note")} placeholder={t("A note on the example (optional)")} />
          <div className="std-ex-sides">
            <label className="std-side good">
              <span>
                <Icon name="check" size={14} /> {t("Good")}
              </span>
              <textarea value={e.good ?? ""} onChange={(ev) => set(i, { ...e, good: ev.target.value })} rows={6} spellCheck={!e.lang} />
            </label>
            <label className="std-side bad">
              <span>
                <Icon name="x" size={14} /> {t("Bad")}
              </span>
              <textarea value={e.bad ?? ""} onChange={(ev) => set(i, { ...e, bad: ev.target.value })} rows={6} spellCheck={!e.lang} />
            </label>
          </div>
        </div>
      ))}
      <AddRow onClick={() => onChange([...examples, { title: "", lang: examples[examples.length - 1]?.lang ?? "", good: "", bad: "" }])}>{t("Add an example")}</AddRow>
    </div>
  );
}

function Tokens({ groups, onChange }: { groups: TokenGroup[]; onChange: (v: TokenGroup[]) => void }) {
  const set = (i: number, g: TokenGroup) => onChange(groups.map((x, j) => (j === i ? g : x)));
  return (
    <div className="std-rows">
      {groups.map((g, gi) => (
        <div key={gi} className="std-tgroup" data-row>
          <div className="std-tg-head">
            <input value={g.name} onChange={(e) => set(gi, { ...g, name: e.target.value })} aria-label={t("Group name")} />
            <select value={g.kind} onChange={(e) => set(gi, { ...g, kind: e.target.value as TokenKind })} aria-label={t("Kind of tokens")}>
              {tokenKinds.map((k) => (
                <option key={k} value={k}>{tokenKindName(k)}</option>
              ))}
            </select>
            <RemoveRow onClick={() => onChange(groups.filter((_, j) => j !== gi))} label={t("Remove group {name}", { name: g.name })} />
          </div>
          <TokenPreview g={g} />
          <div className="std-tokens">
            {g.tokens.map((tk, ti) => {
              const setTk = (p: Partial<typeof tk>) => set(gi, { ...g, tokens: g.tokens.map((x, j) => (j === ti ? { ...x, ...p } : x)) });
              const h = g.kind === "color" ? hex6(tk.value) : undefined;
              return (
                <div key={ti} className="std-token">
                  {g.kind === "color" && (
                    <label className="std-swatch" style={{ background: cssColor(tk.value) ?? "transparent" }} data-none={!cssColor(tk.value) || undefined}>
                      <span className="sr-only">{t("Pick a colour for {name}", { name: tk.key || t("token {n}", { n: ti + 1 }) })}</span>
                      <input type="color" value={h ?? "#000000"} onChange={(e) => setTk({ value: e.target.value })} />
                    </label>
                  )}
                  <input className="data" value={tk.key} onChange={(e) => setTk({ key: e.target.value })} aria-label={t("Token name")} placeholder={t("name")} />
                  <input className="data" value={tk.value} onChange={(e) => setTk({ value: e.target.value })} aria-label={t("Value")} placeholder={g.kind === "color" ? "#3d6bd8" : g.kind === "type" ? "16px / 1.5 / 400" : t("value")} />
                  <input value={tk.note ?? ""} onChange={(e) => setTk({ note: e.target.value })} aria-label={t("Note")} placeholder={t("use (optional)")} />
                  <RemoveRow onClick={() => set(gi, { ...g, tokens: g.tokens.filter((_, j) => j !== ti) })} label={t("Remove token {name}", { name: tk.key })} />
                </div>
              );
            })}
            <AddRow onClick={() => set(gi, { ...g, tokens: [...g.tokens, { key: "", value: "" }] })}>{t("Add a token")}</AddRow>
          </div>
        </div>
      ))}
      <AddRow onClick={() => onChange([...groups, { name: "", kind: "other", tokens: [{ key: "", value: "" }] }])}>{t("Add a token group")}</AddRow>
    </div>
  );
}

function TokenPreview({ g }: { g: TokenGroup }) {
  const toks = g.tokens.filter((x) => x.key && x.value);
  if (!toks.length) return null;
  switch (g.kind) {
    case "color":
      return (
        <div className="std-tp-colors" aria-hidden="true">
          {toks.map((x, i) => (
            <span key={i} style={{ background: cssColor(x.value) ?? "transparent" }} title={`${x.key} ${x.value}`} />
          ))}
        </div>
      );
    case "type":
      return (
        <div className="std-tp-type" aria-hidden="true">
          {toks.map((x, i) => (
            <div key={i}>
              <span className="data xs muted">{x.key}</span>
              <span style={typeStyle(x.value)}>{t("Clear words, kindly set")}</span>
            </div>
          ))}
        </div>
      );
    case "spacing":
      return (
        <div className="std-tp-space" aria-hidden="true">
          {toks.map((x, i) => (
            <span key={i} style={{ width: /^\d+(\.\d+)?(px|rem|em)?$/.test(x.value.trim()) ? (/[a-z]$/.test(x.value.trim()) ? x.value.trim() : x.value.trim() + "px") : 0 }} title={`${x.key} ${x.value}`} />
          ))}
        </div>
      );
    case "radius":
      return (
        <div className="std-tp-radius" aria-hidden="true">
          {toks.map((x, i) => (
            <span key={i} style={{ borderRadius: x.value }} title={x.key} />
          ))}
        </div>
      );
  }
  return null;
}

function Links({ links, onChange }: { links: Link[]; onChange: (v: Link[]) => void }) {
  const set = (i: number, l: Link) => onChange(links.map((x, j) => (j === i ? l : x)));
  return (
    <div className="std-rows">
      {links.map((l, i) => (
        <div key={i} className="std-link" data-row>
          <input value={l.title} onChange={(e) => set(i, { ...l, title: e.target.value })} aria-label={t("Link title")} placeholder={t("Title")} />
          <input className="data" type="url" value={l.url} onChange={(e) => set(i, { ...l, url: e.target.value })} aria-label={t("Address")} placeholder="https://" />
          <input value={l.note ?? ""} onChange={(e) => set(i, { ...l, note: e.target.value })} aria-label={t("Note")} placeholder={t("why it matters (optional)")} />
          <RemoveRow onClick={() => onChange(links.filter((_, j) => j !== i))} label={t("Remove link")} />
        </div>
      ))}
      <AddRow onClick={() => onChange([...links, { title: "", url: "" }])}>{t("Add a link")}</AddRow>
    </div>
  );
}

// ---- preview, diff, history ----

function mdLineClass(l: string, inCode: boolean): string {
  if (inCode) return "c";
  if (/^#{1,6} /.test(l)) return "h" + Math.min(3, l.match(/^#+/)![0].length);
  if (/^_.*_$/.test(l)) return "m";
  if (/^\s*Why: /.test(l)) return "w";
  return "";
}

function Highlighted({ md }: { md: string }) {
  let inCode = "";
  return (
    <>
      {md.split("\n").map((l, i) => {
        const f = l.match(/^(`{3,})/);
        let cls: string;
        if (f && !inCode) {
          inCode = f[1];
          cls = "f";
        } else if (f && l.trim() === inCode) {
          inCode = "";
          cls = "f";
        } else cls = mdLineClass(l, !!inCode);
        const m = !inCode && cls !== "f" ? l.match(/^(- )\*\*(MUST|SHOULD|MAY)\*\*( .*)$/) : null;
        return (
          <span key={i} className={cls ? `l-${cls}` : undefined}>
            {m ? (
              <>
                {m[1]}
                <b className={`lv lv-${m[2].toLowerCase()}`}>**{m[2]}**</b>
                {m[3]}
              </>
            ) : (
              l
            )}
            {"\n"}
          </span>
        );
      })}
    </>
  );
}

function AIPreview({ md, id, enabled }: { md: string; id: string; enabled: boolean }) {
  const [copied, setCopied] = useState(false);
  const approxTokens = Math.ceil(md.length / 4);
  return (
    <div className="std-preview">
      <div className="spread std-preview-head">
        <p className="xs muted">
          {enabled ? t("Served as") : t("Off: no AI gets this.")} {enabled && <code>conduit://standards/{id || "…"}</code>}
        </p>
        <div className="inline">
          <span className="xs muted">{tn("about {n} token", "about {n} tokens", approxTokens)}</span>
          <button
            className="btn quiet sm"
            onClick={() =>
              navigator.clipboard?.writeText(md).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              })
            }
          >
            {copied ? t("Copied") : t("Copy")}
          </button>
        </div>
      </div>
      <pre className="std-md" tabIndex={0} aria-label={t("What the AI sees")}>
        <Highlighted md={md} />
      </pre>
    </div>
  );
}

export function Diff({ before, after }: { before: string; after: string }) {
  const d = useMemo(() => diffLines(before, after), [before, after]);
  const adds = d.filter((x) => x.op === "add").length;
  const dels = d.filter((x) => x.op === "del").length;
  return (
    <div className="std-diff-wrap">
      <p className="xs muted">
        {before ? t("{add} lines added, {del} removed", { add: adds, del: dels }) : t("A new standard")}
      </p>
      <pre className="std-md std-diff" tabIndex={0}>
        {d.map((x, i) => (
          <span key={i} className={`d-${x.op}`}>
            <span className="d-mark" aria-hidden="true">{x.op === "add" ? "+" : x.op === "del" ? "−" : " "}</span>
            {x.op !== "same" && <span className="sr-only">{x.op === "add" ? t("added:") : t("removed:")} </span>}
            {x.text}
            {"\n"}
          </span>
        ))}
      </pre>
    </div>
  );
}

interface Version { version: string; replacedAt: string; updated?: string; title: string; sections: number; enabled: boolean }

function History({ instance, id, current, onRestored, dirty }: { instance: string; id: string; current: string; onRestored: (seq?: number) => void; dirty: boolean }) {
  const list = useQuery({
    queryKey: ["standards", instance, "history", id],
    queryFn: async () => (await run<{ versions: Version[] }>(instance, "history", { id })).out.versions,
  });
  const [sel, setSel] = useState<string | null>(null);
  const ver = useQuery({
    queryKey: ["standards", instance, "history", id, sel],
    queryFn: async () => (await run<{ markdown: string }>(instance, "history", { id, version: sel })).out.markdown,
    enabled: !!sel,
  });
  const restore = useMutation({
    mutationFn: async () => (await run(instance, "restore", { id, kind: "standard", version: sel })).outcome,
    onSuccess: (o) => {
      setSel(null);
      onRestored(o.audit.undo ? o.audit.seq : undefined);
    },
  });
  if (list.error) return <div className="error">{list.error.message}</div>;
  if (!list.data) return null;
  if (!list.data.length) return <p className="small muted std-pad">{t("No earlier versions yet. Each save keeps the one before it; the last 20 are kept.")}</p>;
  return (
    <div className="std-history">
      <ol className="std-versions">
        {list.data.map((v) => (
          <li key={v.version}>
            <button aria-pressed={sel === v.version} onClick={() => setSel(sel === v.version ? null : v.version)}>
              <span className="small">{v.updated ? ago(v.updated) : ago(v.replacedAt)}</span>
              <span className="xs muted">
                {v.title} {!v.enabled && `(${t("Off")})`}
              </span>
              <span className="xs muted">{tn("{n} section", "{n} sections", v.sections)}</span>
            </button>
          </li>
        ))}
      </ol>
      {sel && ver.data !== undefined && (
        <div className="stack" style={{ gap: 8 }}>
          <div className="spread">
            <p className="xs muted">{t("From that version to the saved one")}</p>
            <button className="btn sm" disabled={restore.isPending} onClick={() => (!dirty || confirm(t("Restoring discards your unsaved changes. Go ahead?"))) && restore.mutate()}>
              {t("Restore this version")}</button>
          </div>
          {restore.error && <div className="error">{restore.error.message}</div>}
          <Diff before={ver.data} after={current} />
        </div>
      )}
    </div>
  );
}

/** Undo a timeline entry (the toast's Undo button). */
export function undoEntry(seq: number) {
  return ok(api.POST("/audit/{seq}/undo", { params: { path: { seq } } }));
}
