import { t } from "../i18n";
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
  const tw = tauri();
  return tw ? tw.core.invoke<ShellInfo>("shell_info") : null;
}

let lastAttention = "";
/** Light the tray icon when approvals wait or the emergency stop is on. */
export function setAttention(waiting: number, frozen: boolean) {
  const tw = tauri();
  const key = `${waiting}/${frozen}`;
  if (!tw || key === lastAttention) return;
  lastAttention = key;
  tw.core.invoke("set_attention", { waiting, frozen }).catch(() => {});
}

export async function checkUpdate(): Promise<UpdateInfo | null> {
  const tw = tauri();
  if (!tw) return null;
  return tw.core.invoke<UpdateInfo | null>("check_update");
}

export async function installUpdate(): Promise<void> {
  const tw = tauri();
  if (!tw) return;
  await tw.core.invoke("install_update");
}

export async function setAutostart(enabled: boolean): Promise<boolean> {
  const tw = tauri();
  if (!tw) return false;
  return tw.core.invoke<boolean>("set_autostart", { enabled });
}

let permission: Promise<boolean> | null = null;
/**
 * Show a native notification when the window isn't in front. In a browser
 * this falls back to the Notification API if the person allowed it.
 */
export async function notify(title: string, body?: string) {
  if (typeof document !== "undefined" && document.visibilityState === "visible" && document.hasFocus()) return;
  const n = tauri()?.notification;
  if (!n && isNative()) {
    tauri()!.core.invoke("plugin:notification|notify", { options: { title, body } }).catch(() => {});
    return;
  }
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
  const tw = tauri();
  if (!tw) return () => {};
  let off: (() => void) | null = null;
  let cancelled = false;
  tw.event
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

// --- phone ---------------------------------------------------------------------

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const tw = tauri();
  if (!tw) return Promise.reject(new Error(t("not in the Conduit app")));
  return tw.core.invoke<T>(cmd, args);
}

/** The Conduit app on a phone (not the desktop shell, not a browser). */
export function isMobileApp(): boolean {
  return isNative() && /Android|iPhone|iPad/i.test(navigator.userAgent);
}

/** Scan a QR code with the camera; resolves to its text. */
export async function scanQR(): Promise<string> {
  try {
    await invoke("plugin:barcode-scanner|request_permissions");
  } catch {
    /* older plugin builds ask on scan */
  }
  const r = await invoke<{ content: string }>("plugin:barcode-scanner|scan", { windowed: false, formats: ["QR_CODE"] });
  return r.content;
}

/**
 * Ask for a fingerprint, face or the device PIN before a sensitive step.
 * Resolves true when confirmed, or when this device can't do biometrics (so
 * phones without a sensor still work); false when the person cancels.
 */
export async function confirmWithDevice(reason: string): Promise<boolean> {
  if (!isMobileApp()) return true;
  try {
    const s = await invoke<{ isAvailable: boolean }>("plugin:biometric|status");
    if (!s.isAvailable) return true;
  } catch {
    return true;
  }
  try {
    await invoke("plugin:biometric|authenticate", { reason, allowDeviceCredential: true, title: t("Confirm in Conduit") });
    return true;
  } catch {
    return false;
  }
}

/** Open a link in the system browser (or the APK installer). */
export async function openExternal(url: string) {
  if (!isNative()) {
    window.open(url, "_blank", "noopener");
    return;
  }
  await invoke("plugin:opener|open_url", { url });
}

/** conduit:// links the app was opened with, now and later. */
export function onDeepLink(cb: (url: string) => void): () => void {
  if (!isMobileApp()) return () => {};
  invoke<string[] | null>("plugin:deep-link|get_current")
    .then((urls) => urls?.forEach(cb))
    .catch(() => {});
  return onShellRaw<string[]>("deep-link://new-url", (urls) => urls.forEach(cb));
}

function onShellRaw<T>(event: string, cb: (payload: T) => void): () => void {
  const tw = tauri();
  if (!tw) return () => {};
  let off: (() => void) | null = null;
  let cancelled = false;
  tw.event
    .listen<T>(event, (e) => cb(e.payload))
    .then((u) => (cancelled ? u() : (off = u)))
    .catch(() => {});
  return () => {
    cancelled = true;
    off?.();
  };
}

export type ApkRelease = { version: string; url: string; notes: string };

/**
 * Newest Android release on GitHub, if newer than this app. The APK isn't in
 * a store; Android's installer refuses an update signed with another key.
 */
export async function checkApkUpdate(current: string): Promise<ApkRelease | null> {
  const res = await fetch("https://api.github.com/repos/Elchi-dev/conduit/releases/latest", { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) return null;
  const r = (await res.json()) as { tag_name: string; body?: string; assets: { name: string; browser_download_url: string }[] };
  const version = r.tag_name.replace(/^v/, "");
  const apk = r.assets.find((a) => a.name.endsWith(".apk"));
  if (!apk || !newer(version, current)) return null;
  return { version, url: apk.browser_download_url, notes: r.body ?? "" };
}

function newer(a: string, b: string): boolean {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10));
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10));
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return false;
}
