import { json } from "../lib/format";
import { isSeriesOutput, LineChart } from "./LineChart";
import { t } from "../i18n";

type Row = Record<string, unknown>;

function isRows(v: unknown): v is Row[] {
  return Array.isArray(v) && v.length > 0 && v.every((r) => r && typeof r === "object" && !Array.isArray(r));
}

function isScalarList(v: unknown): v is (string | number | boolean)[] {
  return Array.isArray(v) && v.length <= 12 && v.every((x) => x === null || typeof x !== "object");
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (isScalarList(v)) return v.join(", ");
  if (typeof v === "boolean") return v ? t("Yes") : t("No");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

const acronyms: Record<string, string> = { cpu: "CPU", cpus: "CPUs", os: "OS", gb: "GB", mb: "MB", id: "ID", ip: "IP", url: "URL", pid: "PID", tcp: "TCP" };

export function label(k: string) {
  const words = k
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .split(" ")
    .map((w) => acronyms[w.toLowerCase()] ?? w.toLowerCase());
  const s = words.join(" ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function isPlainObject(v: unknown): v is Row {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function Meter({ value, name }: { value: number; name: string }) {
  const pct = Math.max(0, Math.min(100, value));
  const tone = pct >= 90 ? "fault" : pct >= 75 ? "signal" : "ok";
  return (
    <span className="meter" role="meter" aria-label={name} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
      <span className={`meter-fill ${tone}`} style={{ width: `${pct}%` }} />
      <span className="meter-label">{pct}%</span>
    </span>
  );
}

/** An object's scalar fields as readouts; nested values as their own sections. */
function ObjectView({ value, depth }: { value: Row; depth: number }) {
  const entries = Object.entries(value);
  const scalars = entries.filter(([, v]) => !isPlainObject(v) && (!Array.isArray(v) || isScalarList(v)));
  const nested = entries.filter(([, v]) => isPlainObject(v) || (Array.isArray(v) && !isScalarList(v)));
  return (
    <div className="objview">
      {scalars.length > 0 && (
        <dl className="readouts">
          {scalars.map(([k, v]) => (
            <div key={k} className="readout">
              <dt>{label(k)}</dt>
              <dd className={typeof v === "number" ? "num" : undefined}>
                {k.toLowerCase().includes("percent") && typeof v === "number" ? <Meter value={v} name={label(k)} /> : cell(v)}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {nested.map(([k, v]) => (
        <section key={k} className="objview-section">
          <h3 className="section-title">{label(k)}</h3>
          {depth < 2 ? <ResultView value={v} depth={depth + 1} /> : <pre className="json">{json(v)}</pre>}
        </section>
      ))}
    </div>
  );
}

/**
 * Shows an action's output the way a person reads it: a list of objects as a
 * table, an object as readouts, a long string as a log, anything else as JSON.
 */
export function ResultView({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (isSeriesOutput(value)) return <LineChart series={value.series} />;
  if (isRows(value)) {
    const cols = Array.from(new Set(value.flatMap((r) => Object.keys(r)))).slice(0, 8);
    return (
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c}>{label(c)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {value.slice(0, 500).map((r, i) => (
              <tr key={i}>
                {cols.map((c) => (
                  <td key={c} className={typeof r[c] === "number" ? "num" : undefined}>
                    {c.toLowerCase().includes("percent") && typeof r[c] === "number" ? (
                      <Meter value={r[c] as number} name={label(c)} />
                    ) : typeof r[c] === "string" && /^https?:\/\//.test(r[c] as string) ? (
                      <a href={r[c] as string} target="_blank" rel="noreferrer noopener">
                        {t("Open")}</a>
                    ) : (
                      cell(r[c])
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {value.length > 500 && <p className="xs muted">{t("Showing 500 of {n}.", { n: value.length })}</p>}
      </div>
    );
  }
  if (typeof value === "string" && value.includes("\n")) {
    return <pre className="json log">{value}</pre>;
  }
  if (Array.isArray(value) && value.length === 0) return <p className="small muted">{t("Nothing to show.")}</p>;
  if (isPlainObject(value) && Object.keys(value).length > 0) return <ObjectView value={value} depth={depth} />;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return <p className="small">{String(value)}</p>;
  }
  return <pre className="json">{json(value)}</pre>;
}
