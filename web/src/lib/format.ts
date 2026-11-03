const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** "3 min ago", "in 2 h", or a date for anything older than a week. */
export function ago(iso?: string | null): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  const diff = (t - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 7 * 86400) return rtf.format(Math.round(diff / 86400), "day");
  return new Date(iso).toLocaleDateString();
}

export function stamp(iso?: string | null): string {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function json(v: unknown): string {
  if (v === undefined || v === null) return "";
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function actorLabel(a?: { kind: string; name?: string; id: string }): string {
  if (!a) return "";
  const who = a.name || a.id;
  switch (a.kind) {
    case "user":
      return who;
    case "agent":
      return a.name ? who : `Agent ${who}`;
    case "key":
      return a.name ? who : `Key ${who}`;
    case "automation":
      return a.name ? `Automation "${who}"` : `Automation ${who}`;
    default:
      return "Conduit";
  }
}

/** Built-in features that have an instance but aren't "connected systems". */
export const featureInstances = new Set(["automations", "brief", "status"]);
