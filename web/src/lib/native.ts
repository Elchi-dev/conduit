// Bridge to the native shell (apps/desktop) when the web app runs inside it.
// In a plain browser every function here is a harmless no-op, so the app
// never depends on the shell.
//
// The shell exposes window.__TAURI__ (withGlobalTauri). The daemon's page is
// a remote origin to Tauri, so it only gets what capabilities/daemon.json
// grants: these commands, events and notifications.

type Tauri = {
  core: { invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T> };
  event: { listen: <T>(event: string, cb: (e: { payload: T }) => void) => Promise<() => void> };
  notification?: {
    isPermissionGranted: () => Promise<boolean>;
    requestPermission: () => Promise<string>;
    sendNotification: (o: { title: string; body?: string }) => void;
  };
};

function tauri(): Tauri | null {
  return (globalThis as { __TAURI__?: Tauri }).__TAURI__ ?? null;
}

export function isNative(): boolean {
  return tauri() !== null;
}

export type ShellInfo = { version: string; platform: string; managedDaemon: boolean; updates: boolean; autostart: boolean; tray: boolean };
export type UpdateInfo = { version: string; current: string; notes?: string; date?: string };

export async function shellInfo(): Promise<ShellInfo | null> {
  const t = tauri();
  return t ? t.core.invoke<ShellInfo>("shell_info") : null;
}

let lastAttention = "";
/** Light the tray icon when approvals wait or the emergency stop is on. */
export function setAttention(waiting: number, frozen: boolean) {
  const t = tauri();
  const key = `${waiting}/${frozen}`;
  if (!t || key === lastAttention) return;
  lastAttention = key;
  t.core.invoke("set_attention", { waiting, frozen }).catch(() => {});
}

export async function checkUpdate(): Promise<UpdateInfo | null> {
  const t = tauri();
  if (!t) return null;
  return t.core.invoke<UpdateInfo | null>("check_update");
}

export async function installUpdate(): Promise<void> {
  const t = tauri();
  if (!t) return;
  await t.core.invoke("install_update");
}

export async function setAutostart(enabled: boolean): Promise<boolean> {
  const t = tauri();
  if (!t) return false;
  return t.core.invoke<boolean>("set_autostart", { enabled });
}

let permission: Promise<boolean> | null = null;
/**
 * Show a native notification when the window isn't in front. In a browser
 * this falls back to the Notification API if the person allowed it.
 */
export async function notify(title: string, body?: string) {
  if (typeof document !== "undefined" && document.visibilityState === "visible" && document.hasFocus()) return;
  const n = tauri()?.notification;
  if (n) {
    permission ??= n.isPermissionGranted().then(async (ok) => ok || (await n.requestPermission()) === "granted");
    if (await permission) n.sendNotification({ title, body });
    return;
  }
  if ("Notification" in globalThis && Notification.permission === "granted") {
    new Notification(title, { body });
  }
}

/** Listen to a shell event (tray menu actions). Returns an unsubscribe. */
export function onShell<T>(event: "conduit://navigate" | "conduit://panic", cb: (payload: T) => void): () => void {
  const t = tauri();
  if (!t) return () => {};
  let off: (() => void) | null = null;
  let cancelled = false;
  t.event
    .listen<T>(event, (e) => cb(e.payload))
    .then((u) => {
      if (cancelled) u();
      else off = u;
    })
    .catch(() => {});
  return () => {
    cancelled = true;
    off?.();
  };
}
