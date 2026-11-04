import { api, ok, type Plan } from "../../api/client";
import { apiFetchUrl } from "../../lib/connection";
import { locale, t } from "../../i18n";

export type Game = {
  id: string;
  title: string;
  launcher: string;
  nativeId: string;
  appId?: number;
  installed: boolean;
  installPath?: string;
  sizeBytes?: number;
  size?: string;
  executables?: string[];
  processNames?: string[];
  hasCover: boolean;
  lastPlayed?: string;
  playSeconds: number;
  launcherPlaySeconds?: number;
  totalPlaySeconds: number;
  running: boolean;
  custom?: boolean;
};

export type Proc = { pid: number; name: string; exe?: string };
export type Running = { id: string; title: string; launcher: string; pid: number; processes: Proc[]; since: string; seconds: number };
export type Session = { gameId: string; title: string; launcher: string; start: string; end: string; seconds: number };
export type Stats = {
  days: number;
  totalSeconds: number;
  sessions: number;
  daysPlayed: number;
  averageSessionSeconds: number;
  streak: { current: number; longest: number };
  top: { id: string; title: string; seconds: number }[];
  series: { name: string; points: [number, number][] }[];
};
export type Detail = { game: Game; stats: Stats; sessions: Session[]; launch: string; running?: Running };

export type Acted<T> = { output?: T; plan?: Plan; pending: boolean };

/** Runs one of the games module's actions through the permission engine. */
export async function act<T>(instance: string, action: string, input: Record<string, unknown> = {}, dryRun = false): Promise<Acted<T>> {
  const o = await ok(api.POST("/instances/{id}/actions/{action}", { params: { path: { id: instance, action } }, body: { input, dryRun } }));
  const pending = o.decision?.effect === "ask" && !o.result?.output && !o.result?.plan;
  return { output: o.result?.output as T | undefined, plan: o.result?.plan, pending };
}

// Covers come through the daemon (the page loads nothing from other sites),
// as blobs so they work through the relay too. One request per game per
// page load.
const covers = new Map<string, Promise<string | null>>();
export function coverURL(id: string): Promise<string | null> {
  let p = covers.get(id);
  if (!p) {
    p = apiFetchUrl(`/api/v1/games/covers/${encodeURIComponent(id)}`, { headers: { Accept: "image/*" } })
      .then(async (r) => (r.ok ? URL.createObjectURL(await r.blob()) : null))
      .catch(() => null);
    covers.set(id, p);
  }
  return p;
}

export const launcherNames: Record<string, string> = {
  steam: "Steam",
  epic: "Epic Games",
  gog: "GOG",
  riot: "Riot Games",
  battlenet: "Battle.net",
  ea: "EA app",
  ubisoft: "Ubisoft Connect",
  xbox: "Xbox",
  itch: "itch.io",
  lutris: "Lutris",
};

export function launcherLabel(id: string): string {
  if (id === "custom") return t("Added by you");
  if (id === "windows") return t("Other installed");
  return launcherNames[id] ?? id;
}

/** "45 min", "3 h 20 min", "120 h". */
export function duration(secs: number): string {
  if (secs < 60) return t("under a minute");
  const m = Math.round(secs / 60);
  if (m < 60) return t("{n} min", { n: m });
  const h = Math.floor(m / 60);
  const rest = m % 60;
  if (h >= 10 || rest === 0) return t("{h} h", { h: h.toLocaleString(locale()) });
  return t("{h} h {m} min", { h, m: rest });
}

/** A ticking clock for a running game: 1:04:09. */
export function clock(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s % 60)}` : `${m}:${pad(s % 60)}`;
}

/** A stable hue for a title, for posters without cover art. */
export function hue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 360;
}
