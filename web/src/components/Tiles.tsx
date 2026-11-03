import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "wouter";
import { api, ok } from "../api/client";
import { locale, t, tn } from "../i18n";
import "./tiles.css";

export type Tile = { id: string; instance: string; action: string; input?: unknown; label: string; field?: string; refresh: number };

export function useTiles() {
  const qc = useQueryClient();
  const tiles = useQuery({ queryKey: ["tiles"], queryFn: () => ok(api.GET("/me/tiles")) as Promise<Tile[]> });
  const save = useMutation({
    mutationFn: (next: Tile[]) => ok(api.PUT("/me/tiles", { body: next as never })) as Promise<Tile[]>,
    onSuccess: (next) => qc.setQueryData(["tiles"], next),
  });
  return { tiles: tiles.data ?? [], save };
}

/** Follow a dot path ("cpu.percent", "items.0.name") into a value. */
export function pick(v: unknown, path?: string): unknown {
  if (!path) return v;
  let cur: unknown = v;
  for (const part of path.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** Paths to scalar values in a result, for choosing what a tile shows. */
export function scalarPaths(v: unknown, prefix = "", depth = 0): string[] {
  if (v == null || typeof v !== "object" || depth > 2) return [];
  if (Array.isArray(v)) return prefix ? [] : [];
  const out: string[] = [];
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (x == null || typeof x !== "object") out.push(p);
    else out.push(...scalarPaths(x, p, depth + 1));
  }
  return out.slice(0, 40);
}

function format(v: unknown): { big: string; small?: string } {
  if (v === undefined || v === null) return { big: "–" };
  if (typeof v === "number") return { big: Number.isInteger(v) ? v.toLocaleString(locale()) : v.toLocaleString(locale(), { maximumFractionDigits: 1 }) };
  if (typeof v === "boolean") return { big: v ? t("Yes") : t("No") };
  if (typeof v === "string") return v.length > 24 ? { big: v.slice(0, 22) + "…", small: v } : { big: v };
  if (Array.isArray(v)) return { big: v.length.toLocaleString(locale()), small: tn("item", "items", v.length) };
  const entries = Object.entries(v as Record<string, unknown>).filter(([, x]) => x === null || typeof x !== "object");
  if (entries.length === 0) return { big: "…" };
  const [k, x] = entries[0];
  const rest = entries
    .slice(1, 3)
    .map(([a, b]) => `${a} ${String(b)}`)
    .join(", ");
  return { big: format(x).big, small: rest ? `${k}; ${rest}` : k };
}

function TileView({ tile, editing, onRemove, onMove }: { tile: Tile; editing: boolean; onRemove: () => void; onMove: (d: -1 | 1) => void }) {
  const q = useQuery({
    queryKey: ["tile", tile.id],
    queryFn: () =>
      ok(api.POST("/instances/{id}/actions/{action}", { params: { path: { id: tile.instance, action: tile.action } }, body: { input: (tile.input ?? {}) as never } })),
    refetchInterval: Math.max(15, tile.refresh || 60) * 1000,
    retry: false,
  });
  const v = format(pick(q.data?.result.output, tile.field));
  return (
    <div className={`tile ${q.error ? "tile-error" : ""}`}>
      <Link href={`/i/${tile.instance}`} className="tile-label">
        {tile.label}
      </Link>
      {q.error ? (
        <span className="tile-small">{(q.error as Error).message}</span>
      ) : (
        <>
          <span className="tile-value data" title={v.small}>
            {q.isPending ? "…" : v.big}
          </span>
          {v.small && <span className="tile-small">{v.small}</span>}
        </>
      )}
      {editing && (
        <div className="tile-edit">
          <button className="btn sm quiet" onClick={() => onMove(-1)} aria-label={`Move ${tile.label} earlier`}>
            {t("Earlier")}</button>
          <button className="btn sm quiet" onClick={() => onMove(1)} aria-label={`Move ${tile.label} later`}>
            {t("Later")}</button>
          <button className="btn sm danger" onClick={onRemove}>
            {t("Remove")}</button>
        </div>
      )}
    </div>
  );
}

/** The home board: pinned read actions, refreshing on their own. */
export function TileBoard() {
  const { tiles, save } = useTiles();
  const [editing, setEditing] = useState(false);
  if (tiles.length === 0) return null;
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= tiles.length) return;
    const next = [...tiles];
    [next[i], next[j]] = [next[j], next[i]];
    save.mutate(next);
  };
  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <h2 className="section-title">{t("Your board")}</h2>
        <button className="btn sm quiet" onClick={() => setEditing(!editing)} aria-pressed={editing}>
          {editing ? t("Done") : t("Arrange")}
        </button>
      </div>
      <div className="tiles">
        {tiles.map((x, i) => (
          <TileView key={x.id} tile={x} editing={editing} onMove={(d) => move(i, d)} onRemove={() => save.mutate(tiles.filter((y) => y.id !== x.id))} />
        ))}
      </div>
      {save.error && <div className="error">{save.error.message}</div>}
    </section>
  );
}

/** "Pin to home" for a read action's result. */
export function PinButton({ instance, action, title, input, output }: { instance: string; action: string; title: string; input: unknown; output: unknown }) {
  const { tiles, save } = useTiles();
  const [open, setOpen] = useState(false);
  const paths = scalarPaths(output);
  const [label, setLabel] = useState(title);
  const [field, setField] = useState(paths[0] ?? "");
  const [refresh, setRefresh] = useState(60);
  if (save.isSuccess && !open) return <span className="xs muted">{t("Pinned to your home board.")}</span>;
  if (!open)
    return (
      <button className="btn sm quiet" onClick={() => setOpen(true)}>
        {t("Pin to home")}</button>
    );
  return (
    <form
      className="inline pin-form"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate([...tiles, { id: "", instance, action, input, label, field, refresh }], { onSuccess: () => setOpen(false) });
      }}
    >
      <label className="field">
        <span>{t("Label")}</span>
        <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={60} />
      </label>
      {paths.length > 0 && (
        <label className="field">
          <span>{t("Show")}</span>
          <select className="input" value={field} onChange={(e) => setField(e.target.value)}>
            <option value="">{t("A summary")}</option>
            {paths.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
      )}
      <label className="field">
        <span>{t("Update every")}</span>
        <select className="input" value={refresh} onChange={(e) => setRefresh(Number(e.target.value))}>
          <option value={15}>{t("15 seconds")}</option>
          <option value={60}>{t("minute")}</option>
          <option value={300}>{t("5 minutes")}</option>
          <option value={3600}>{t("hour")}</option>
        </select>
      </label>
      <button className="btn sm primary" disabled={save.isPending}>
        {t("Pin")}</button>
      <button type="button" className="btn sm quiet" onClick={() => setOpen(false)}>
        {t("Cancel")}</button>
      {save.error && <div className="error">{save.error.message}</div>}
    </form>
  );
}
