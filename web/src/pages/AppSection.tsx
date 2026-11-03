import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ok } from "../api/client";
import { ago } from "../lib/format";
import { checkApkUpdate, checkUpdate, installUpdate, isMobileApp, isNative, openExternal, setAutostart, shellInfo } from "../lib/native";

/** Settings section for the desktop app: updates and start at login. */
export function AppSection() {
  const info = useQuery({ queryKey: ["shell-info"], queryFn: shellInfo, enabled: isNative() });
  const check = useMutation({ mutationFn: checkUpdate });
  const install = useMutation({ mutationFn: installUpdate });
  const autostart = useMutation({ mutationFn: setAutostart, onSuccess: () => info.refetch() });
  const apk = useMutation({ mutationFn: () => checkApkUpdate(info.data?.version ?? "0.0.0") });
  if (!isNative() || !info.data) return null;
  const i = info.data;

  if (isMobileApp()) {
    return (
      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">App</h2>
        <div className="panel stack app-panel">
          <div className="spread">
            <strong className="small">
              Conduit for Android <span className="data">{i.version}</span>
            </strong>
            <button className="btn" onClick={() => apk.mutate()} disabled={apk.isPending}>
              {apk.isPending ? "Checking…" : "Check for updates"}
            </button>
          </div>
          {apk.error && <div className="error">{updateError(apk.error)}</div>}
          {apk.isSuccess && !apk.data && <p className="small muted">You have the latest version.</p>}
          {apk.data && (
            <div className="update-offer stack" style={{ gap: 8 }}>
              <strong className="small">
                Version <span className="data">{apk.data.version}</span> is ready
              </strong>
              <p className="xs muted">
                The download opens Android's installer, which only accepts it if it's signed with the same key as this app.
              </p>
              <div>
                <button className="btn primary" onClick={() => openExternal(apk.data!.url)}>
                  Download and install
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">App</h2>
      <div className="panel stack app-panel">
        <div className="spread">
          <div className="stack" style={{ gap: 2 }}>
            <strong className="small">
              Conduit for {i.platform === "macos" ? "Mac" : i.platform === "windows" ? "Windows" : i.platform === "linux" ? "Linux" : i.platform}{" "}
              <span className="data">{i.version}</span>
            </strong>
            <span className="xs muted">
              {i.managedDaemon
                ? "The app runs Conduit and updates it with itself."
                : "Attached to a Conduit already running on this computer; update that one separately."}
            </span>
          </div>
          {i.updates && (
            <button className="btn" onClick={() => check.mutate()} disabled={check.isPending || install.isPending}>
              {check.isPending ? "Checking…" : "Check for updates"}
            </button>
          )}
        </div>
        {check.error && <div className="error">{updateError(check.error)}</div>}
        {check.isSuccess && !check.data && <p className="small muted">You have the latest version.</p>}
        {check.data && (
          <div className="update-offer stack" style={{ gap: 8 }}>
            <strong className="small">
              Version <span className="data">{check.data.version}</span> is ready
            </strong>
            {check.data.notes && <p className="small muted update-notes">{check.data.notes}</p>}
            <p className="xs muted">The download is checked against Conduit's signing key before it installs. Conduit restarts afterwards.</p>
            <div>
              <button className="btn primary" onClick={() => install.mutate()} disabled={install.isPending}>
                {install.isPending ? "Installing…" : "Install and restart"}
              </button>
            </div>
            {install.error && <div className="error">{String(install.error)}</div>}
          </div>
        )}
        <label className="check">
          <input type="checkbox" checked={i.autostart} onChange={(e) => autostart.mutate(e.target.checked)} disabled={autostart.isPending} />
          <span className="small">Start Conduit when you sign in to this computer{i.tray ? ", in the tray" : ""}</span>
        </label>
        <p className="xs muted">
          {i.tray
            ? "Closing the window keeps Conduit running in the tray. Quit it from the tray menu."
            : "This desktop has no system tray, so closing the window quits Conduit."}
        </p>
      </div>
    </section>
  );
}

function updateError(e: unknown): string {
  const m = String(e);
  if (/release JSON|404|Not Found/i.test(m)) return "No update is published yet, or the update server couldn't be reached. Try again later.";
  if (/network|dns|connect|timed out/i.test(m)) return "Couldn't reach the update server. Check your connection and try again.";
  return m;
}

/** Settings section for a daemon that updates itself (servers, headless). */
export function DaemonUpdates({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["update"], queryFn: () => ok(api.GET("/system/update")), enabled: admin });
  const check = useMutation({
    mutationFn: () => ok(api.POST("/system/update/check")),
    onSuccess: (d) => qc.setQueryData(["update"], d),
  });
  const apply = useMutation({ mutationFn: () => ok(api.POST("/system/update/apply")) });
  const s = status.data;
  if (!admin || !s || s.managed) return null;
  const dev = !/^v?\d+\.\d+\.\d+/.test(s.current);

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">Updates</h2>
      <div className="panel stack app-panel">
        <div className="spread">
          <div className="stack" style={{ gap: 2 }}>
            <strong className="small">
              Conduit <span className="data">{s.current}</span> for <span className="data">{s.platform}</span>
            </strong>
            <span className="xs muted">
              {dev
                ? "A development build. It doesn't update itself."
                : s.checkedAt
                  ? `Checked ${ago(s.checkedAt)}.`
                  : "Checks for new releases every six hours. Installing is always your choice."}
            </span>
          </div>
          {!dev && (
            <button className="btn" onClick={() => check.mutate()} disabled={check.isPending}>
              {check.isPending ? "Checking…" : "Check now"}
            </button>
          )}
        </div>
        {(check.error || s.lastError) && <div className="error">{check.error?.message ?? s.lastError}</div>}
        {s.last && (
          <p className="xs muted">
            {s.last.result === "rolled_back"
              ? `Version ${s.last.to} kept failing to start, so Conduit went back to ${s.last.from} ${ago(s.last.at)}.`
              : s.last.result === "confirmed"
                ? `Updated from ${s.last.from} to ${s.last.to} ${ago(s.last.at)}.`
                : `Installing ${s.last.to}…`}
          </p>
        )}
        {s.available && (
          <div className="update-offer stack" style={{ gap: 8 }}>
            <strong className="small">
              Version <span className="data">{s.available.version}</span> is available
            </strong>
            {s.available.notes && <p className="small muted update-notes">{s.available.notes}</p>}
            <p className="xs muted">
              Signed by Conduit's release key and checked before installing. Conduit restarts; if the new version fails to start
              three times, it goes back to this one by itself.
            </p>
            <div>
              <button className="btn primary" onClick={() => apply.mutate()} disabled={apply.isPending || apply.isSuccess}>
                {apply.isSuccess ? "Restarting…" : apply.isPending ? "Installing…" : "Install and restart"}
              </button>
            </div>
            {apply.error && <div className="error">{apply.error.message}</div>}
          </div>
        )}
      </div>
    </section>
  );
}
