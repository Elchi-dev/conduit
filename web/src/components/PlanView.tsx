import type { Plan } from "../api/client";
import { json } from "../lib/format";

/** Renders a dry-run plan as a list of concrete changes with before/after. */
export function PlanView({ plan }: { plan: Plan }) {
  return (
    <div className="plan">
      <p className="small">{plan.summary}</p>
      {plan.changes.length > 0 && (
        <ul className="plan-list">
          {plan.changes.map((c, i) => (
            <li key={i}>
              <div className="inline small">
                <span className={`op op-${c.op}`}>{c.op}</span>
                <span className="data">{c.target}</span>
              </div>
              {(c.before !== undefined || c.after !== undefined) && (
                <div className="diff">
                  {c.before !== undefined && <pre className="json before">{json(c.before)}</pre>}
                  {c.after !== undefined && <pre className="json after">{json(c.after)}</pre>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
