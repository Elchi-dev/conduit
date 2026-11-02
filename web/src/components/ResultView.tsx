import { json } from "../lib/format";

type Row = Record<string, unknown>;

function isRows(v: unknown): v is Row[] {
  return Array.isArray(v) && v.length > 0 && v.every((r) => r && typeof r === "object" && !Array.isArray(r));
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/**
 * Shows an action's output the way a person reads it: a list of objects as a
 * table, a long string as a log, anything else as formatted JSON.
 */
export function ResultView({ value }: { value: unknown }) {
  if (isRows(value)) {
    const cols = Array.from(new Set(value.flatMap((r) => Object.keys(r)))).slice(0, 8);
    return (
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {value.slice(0, 500).map((r, i) => (
              <tr key={i}>
                {cols.map((c) => (
                  <td key={c} className={typeof r[c] === "number" ? "num" : undefined}>
                    {cell(r[c])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {value.length > 500 && <p className="xs muted">Showing 500 of {value.length}.</p>}
      </div>
    );
  }
  if (typeof value === "string" && value.includes("\n")) {
    return <pre className="json log">{value}</pre>;
  }
  if (Array.isArray(value) && value.length === 0) return <p className="small muted">Nothing to show.</p>;
  return <pre className="json">{json(value)}</pre>;
}
