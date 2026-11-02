import { useMemo, useRef, useState } from "react";

export type Series = { name: string; points: [number, number][] };

/** True when an output has the {series: [...]} shape modules use for charts. */
export function isSeriesOutput(v: unknown): v is { series: Series[] } {
  if (!v || typeof v !== "object" || !("series" in v)) return false;
  const s = (v as { series: unknown }).series;
  return Array.isArray(s) && s.every((x) => x && typeof x === "object" && "points" in x && Array.isArray((x as Series).points));
}

const W = 760;
const H = 260;
const PAD = { l: 52, r: 16, t: 12, b: 28 };

function niceTicks(min: number, max: number, count = 4) {
  if (min === max) {
    const d = Math.abs(min) || 1;
    min -= d;
    max += d;
  }
  const raw = (max - min) / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const lo = Math.floor(min / step) * step;
  const hi = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = lo; v <= hi + step / 2; v += step) ticks.push(Number(v.toPrecision(12)));
  return { lo, hi, ticks };
}

function fmtNum(v: number) {
  const a = Math.abs(v);
  if (a >= 1e9) return (v / 1e9).toFixed(1) + "G";
  if (a >= 1e6) return (v / 1e6).toFixed(1) + "M";
  if (a >= 1e3) return (v / 1e3).toFixed(1) + "k";
  if (a >= 100) return v.toFixed(0);
  return String(Number(v.toFixed(a >= 10 ? 1 : 3)));
}

function fmtTime(t: number, span: number) {
  const d = new Date(t * 1000);
  return span > 2 * 86400
    ? d.toLocaleDateString(undefined, { weekday: "short", hour: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/**
 * A time-series line chart: one y-axis, 2px lines, recessive grid, a legend
 * for two or more series (direct end labels for up to four), a crosshair
 * tooltip, and a table view. Colors come from --series-N tokens, assigned in
 * fixed order and capped at eight.
 */
export function LineChart({ series }: { series: Series[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const shown = series.slice(0, 8).filter((s) => s.points.length > 0);

  const geo = useMemo(() => {
    const xs = shown.flatMap((s) => s.points.map((p) => p[0]));
    const ys = shown.flatMap((s) => s.points.map((p) => p[1]));
    if (xs.length === 0) return null;
    const x0 = Math.min(...xs);
    const x1 = Math.max(...xs);
    const { lo, hi, ticks } = niceTicks(Math.min(0, ...ys), Math.max(...ys));
    const sx = (t: number) => PAD.l + ((t - x0) / (x1 - x0 || 1)) * (W - PAD.l - PAD.r);
    const sy = (v: number) => H - PAD.b - ((v - lo) / (hi - lo || 1)) * (H - PAD.t - PAD.b);
    const times = Array.from(new Set(xs)).sort((a, b) => a - b);
    return { x0, x1, sx, sy, ticks, times };
  }, [shown]);

  if (!geo) return <p className="small muted">No data in this range.</p>;
  const { x0, x1, sx, sy, ticks, times } = geo;
  const span = x1 - x0;
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => x0 + f * span);

  const onMove = (e: React.PointerEvent) => {
    const r = svgRef.current?.getBoundingClientRect();
    if (!r) return;
    const t = x0 + (((e.clientX - r.left) / r.width) * W - PAD.l) / ((W - PAD.l - PAD.r) / (span || 1));
    let best = 0;
    for (let i = 1; i < times.length; i++) if (Math.abs(times[i] - t) < Math.abs(times[best] - t)) best = i;
    setHover(best);
  };
  const ht = hover != null ? times[hover] : null;
  const valueAt = (s: Series, t: number) => s.points.find((p) => p[0] === t)?.[1];

  return (
    <div className="chart">
      <div className="spread">
        {shown.length >= 2 ? (
          <ul className="legend">
            {shown.map((s, i) => (
              <li key={s.name}>
                <span className="swatch" style={{ background: `var(--series-${i + 1})` }} />
                <span className="data xs">{s.name}</span>
              </li>
            ))}
          </ul>
        ) : (
          <span className="data xs muted">{shown[0].name}</span>
        )}
        <button className="btn sm quiet" onClick={() => setAsTable(!asTable)}>
          {asTable ? "Show chart" : "Show as table"}
        </button>
      </div>
      {series.length > 8 && <p className="xs muted">Showing the first 8 of {series.length} series. Narrow the query to see the rest.</p>}
      {asTable ? (
        <div className="table-wrap" style={{ maxHeight: 320, overflow: "auto" }}>
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                {shown.map((s) => (
                  <th key={s.name}>{s.name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {times.map((t) => (
                <tr key={t}>
                  <td className="xs">{new Date(t * 1000).toLocaleString()}</td>
                  {shown.map((s) => (
                    <td key={s.name} className="num">
                      {valueAt(s, t) ?? ""}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart-plot">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label={`Line chart of ${shown.map((s) => s.name).join(", ")}`}
            onPointerMove={onMove}
            onPointerLeave={() => setHover(null)}
          >
            {ticks.map((v) => (
              <g key={v}>
                <line x1={PAD.l} x2={W - PAD.r} y1={sy(v)} y2={sy(v)} className="grid" />
                <text x={PAD.l - 8} y={sy(v) + 4} textAnchor="end" className="tick">
                  {fmtNum(v)}
                </text>
              </g>
            ))}
            {xTicks.map((t, i) => (
              <text key={i} x={sx(t)} y={H - 8} textAnchor={i === 0 ? "start" : i === 4 ? "end" : "middle"} className="tick">
                {fmtTime(t, span)}
              </text>
            ))}
            {shown.map((s, i) => (
              <polyline
                key={s.name}
                points={s.points.map((p) => `${sx(p[0])},${sy(p[1])}`).join(" ")}
                fill="none"
                stroke={`var(--series-${i + 1})`}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
            ))}
            {ht != null && (
              <g>
                <line x1={sx(ht)} x2={sx(ht)} y1={PAD.t} y2={H - PAD.b} className="crosshair" />
                {shown.map((s, i) => {
                  const v = valueAt(s, ht);
                  return v == null ? null : (
                    <circle key={s.name} cx={sx(ht)} cy={sy(v)} r={4.5} fill={`var(--series-${i + 1})`} className="dot" />
                  );
                })}
              </g>
            )}
          </svg>
          {ht != null && (
            <div className="chart-tip" style={{ left: `${(sx(ht) / W) * 100}%` }} role="status">
              <p className="xs muted">{new Date(ht * 1000).toLocaleString()}</p>
              {shown.map((s, i) => {
                const v = valueAt(s, ht);
                return v == null ? null : (
                  <p key={s.name} className="xs tip-row">
                    <span className="swatch" style={{ background: `var(--series-${i + 1})` }} />
                    <span className="tip-name">{s.name}</span>
                    <strong className="data">{fmtNum(v)}</strong>
                  </p>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
