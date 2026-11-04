// The hub operator console (/account/admin/): talks to /v1/admin, which
// answers only signed-in hub admins.
import { api } from "./hub";
import { dateLocale } from "../i18n/client";

export type AdminStats = {
  accounts: number;
  verified: number;
  admins: number;
  disabled: number;
  devices: number;
  daemons: number;
  daemonsOnline: number;
  orgs: number;
  syncBlobs: number;
  syncBytes: number;
  packages: number;
  releases: number;
  openReports?: number;
  delisted?: number;
};

export type AdminAccount = {
  id: string;
  email: string;
  name: string;
  verified: boolean;
  admin: boolean;
  disabled?: boolean;
  createdAt: string;
  devices: number;
  lastSignInAt?: string;
};

export const stats = () => api<AdminStats>("GET", "/admin/stats");

export function accounts(q: string, offset = 0, limit = 50) {
  const p = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (q) p.set("q", q);
  return api<{ total: number; items: AdminAccount[] }>("GET", `/admin/accounts?${p}`);
}

export const disable = (id: string) => api<AdminAccount>("POST", `/admin/accounts/${encodeURIComponent(id)}/disable`);
export const enable = (id: string) => api<AdminAccount>("POST", `/admin/accounts/${encodeURIComponent(id)}/enable`);
export const remove = (id: string) => api<void>("DELETE", `/admin/accounts/${encodeURIComponent(id)}`);

/** 1536 → "1.5 KB". */
export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${(v < 10 ? Math.round(v * 10) / 10 : Math.round(v)).toLocaleString(dateLocale)} ${units[i]}`;
}
