import { useMemo } from "react";
import { t } from "../i18n";

/** The subset of JSON Schema modules use to describe inputs and settings. */
export type JSONSchema = {
  type?: string | string[];
  title?: string;
  description?: string;
  properties?: Record<string, JSONSchema>;
  required?: string[];
  enum?: unknown[];
  default?: unknown;
  format?: string;
  items?: JSONSchema;
  minimum?: number;
  maximum?: number;
  /** Conduit extension: the value is a vault reference (secret://name). */
  "x-secret"?: boolean;
  /** Conduit extension: render a multi-line text box. */
  "x-multiline"?: boolean;
};

type Props = {
  schema?: JSONSchema | null;
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
  idPrefix: string;
};

function label(key: string, s: JSONSchema) {
  if (s.title) return s.title;
  const words = key.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Initial values from schema defaults. */
export function defaults(schema?: JSONSchema | null): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, s] of Object.entries(schema?.properties ?? {})) {
    if (s.default !== undefined) out[k] = s.default;
  }
  return out;
}

/** Renders a form for an object schema. Unknown shapes fall back to JSON. */
export function SchemaForm({ schema, value, onChange, idPrefix }: Props) {
  const props = useMemo(() => Object.entries(schema?.properties ?? {}), [schema]);
  if (!schema || props.length === 0) return null;
  const required = new Set(schema.required ?? []);
  const set = (k: string, v: unknown) => {
    const next = { ...value };
    if (v === "" || v === undefined) delete next[k];
    else next[k] = v;
    onChange(next);
  };

  return (
    <div className="stack">
      {props.map(([key, s]) => {
        const id = `${idPrefix}-${key}`;
        const ty = Array.isArray(s.type) ? s.type[0] : s.type;
        const v = value[key];
        const head = (
          <span>
            {label(key, s)}
            {required.has(key) ? "" : <span className="muted"> {t("(optional)")}</span>}
          </span>
        );
        const help = s.description ? <small>{s.description}</small> : null;

        if (s.enum) {
          return (
            <label className="field" key={key} htmlFor={id}>
              {head}
              <select id={id} value={v === undefined ? "" : String(v)} onChange={(e) => set(key, e.target.value)}>
                {!required.has(key) && <option value="">—</option>}
                {s.enum.map((o) => (
                  <option key={String(o)} value={String(o)}>
                    {String(o)}
                  </option>
                ))}
              </select>
              {help}
            </label>
          );
        }
        if (ty === "boolean") {
          return (
            <div key={key} className="stack" style={{ gap: 4 }}>
              <label className="check" htmlFor={id}>
                <input id={id} type="checkbox" checked={Boolean(v)} onChange={(e) => set(key, e.target.checked)} />
                {label(key, s)}
              </label>
              {help}
            </div>
          );
        }
        if (ty === "integer" || ty === "number") {
          return (
            <label className="field" key={key} htmlFor={id}>
              {head}
              <input
                id={id}
                type="number"
                min={s.minimum}
                max={s.maximum}
                step={ty === "integer" ? 1 : "any"}
                value={v === undefined ? "" : String(v)}
                onChange={(e) => set(key, e.target.value === "" ? undefined : Number(e.target.value))}
              />
              {help}
            </label>
          );
        }
        if (ty === "array" && (s.items?.type === "string" || !s.items)) {
          const text = Array.isArray(v) ? (v as string[]).join("\n") : "";
          return (
            <label className="field" key={key} htmlFor={id}>
              {head}
              <textarea
                id={id}
                value={text}
                placeholder={t("One per line")}
                onChange={(e) =>
                  set(
                    key,
                    e.target.value
                      .split("\n")
                      .map((x) => x.trim())
                      .filter(Boolean),
                  )
                }
              />
              {help}
            </label>
          );
        }
        if (ty === "object" || ty === "array") {
          return (
            <label className="field" key={key} htmlFor={id}>
              {head}
              <textarea
                id={id}
                defaultValue={v === undefined ? "" : JSON.stringify(v, null, 2)}
                placeholder={"JSON"}
                onBlur={(e) => {
                  try {
                    set(key, e.target.value.trim() ? JSON.parse(e.target.value) : undefined);
                  } catch {
                    /* keep last valid value */
                  }
                }}
              />
              {help}
            </label>
          );
        }
        const secret = s["x-secret"] || s.format === "password";
        return (
          <label className="field" key={key} htmlFor={id}>
            {head}
            {s["x-multiline"] ? (
              <textarea id={id} value={(v as string) ?? ""} onChange={(e) => set(key, e.target.value)} />
            ) : (
              <input
                id={id}
                type={s.format === "password" ? "password" : "text"}
                className={secret ? "data" : undefined}
                placeholder={s["x-secret"] ? "secret://name" : undefined}
                value={(v as string) ?? ""}
                onChange={(e) => set(key, e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            )}
            {s["x-secret"] ? <small>{t("Stored in the vault. Enter a reference like secret://mail-password.")}</small> : help}
          </label>
        );
      })}
    </div>
  );
}
