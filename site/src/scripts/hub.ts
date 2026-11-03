// Talks to the hub that serves this site (same origin, /v1). The session
// token lives in localStorage; it is a hub session, never a daemon one.

const KEY = "conduit.hub.session";

export function token(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null) {
  try {
    if (t) localStorage.setItem(KEY, t);
    else localStorage.removeItem(KEY);
  } catch {
    /* private mode: the session lasts for this page */
  }
}

export class HubError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new HubError("The hub didn't answer. Check your connection and try again.", 0);
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && t && path !== "/sessions") setToken(null);
    throw new HubError((data as { error?: string }).error || res.statusText, res.status);
  }
  return data as T;
}

/** Wire a form: collect named fields, run fn, show errors in [data-error]. */
export function form(el: HTMLFormElement, fn: (v: Record<string, string>) => Promise<void>) {
  const err = el.querySelector<HTMLElement>("[data-error]");
  const btn = el.querySelector<HTMLButtonElement>("button[type=submit], button:not([type])");
  el.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v: Record<string, string> = {};
    new FormData(el).forEach((val, k) => (v[k] = String(val)));
    if (err) err.hidden = true;
    if (btn) btn.disabled = true;
    try {
      await fn(v);
    } catch (x) {
      if (err) {
        err.textContent = x instanceof Error ? x.message : String(x);
        err.hidden = false;
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

export function param(name: string): string {
  return new URLSearchParams(location.search).get(name) ?? "";
}

export function ago(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {}, ...kids: (Node | string)[]) {
  const n = document.createElement(tag);
  const { class: cls, ...rest } = props;
  if (cls) n.className = cls;
  Object.assign(n, rest);
  n.append(...kids);
  return n;
}
