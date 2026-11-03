import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ok } from "../api/client";
import { ago } from "../lib/format";
import "./pages.css";

type Schedule = { enabled: boolean; folder: string; passphrase: string; keep: number; hour: number; lastRun?: string; lastFile?: string; lastError?: string };

/** Settings section: download a backup, or have one written every day. */
export function BackupSection({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const sched = useQuery({ queryKey: ["backup", "schedule"], queryFn: () => ok(api.GET("/backup/schedule")) as Promise<Schedule>, enabled: admin });
  const [pass, setPass] = useState("");
  const [f, setF] = useState<Schedule | null>(null);
  useEffect(() => {
    if (sched.data && !f) setF(sched.data);
  }, [sched.data, f]);

  const download = useMutation({
    mutationFn: async () => {
      const r = await api.POST("/backup", { body: { passphrase: pass }, parseAs: "blob" });
      if (!r.response.ok) {
        const e = r.error as { error?: string } | undefined;
        throw new Error(e?.error || "The backup failed.");
      }
      const name = /filename="([^"]+)"/.exec(r.response.headers.get("Content-Disposition") ?? "")?.[1] ?? "conduit-backup.cdb";
      const url = URL.createObjectURL(r.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setPass("");
    },
  });
  const save = useMutation({
    mutationFn: (c: Schedule) => ok(api.PUT("/backup/schedule", { body: c })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["backup"] }),
  });
  const run = useMutation({
    mutationFn: () => ok(api.POST("/backup/run")),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["backup"] }),
  });
  if (!admin) return null;

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">Backups</h2>
      <p className="small muted">
        One encrypted file with everything: settings, modules, agent rules, the audit log and the vault (which stays locked with
        its own passphrase). Restore with <span className="data">conduitd restore -in &lt;file&gt;</span>.
      </p>
      <form
        className="inline"
        onSubmit={(e) => {
          e.preventDefault();
          download.mutate();
        }}
      >
        <label className="field" style={{ minWidth: 260 }}>
          <span>Backup passphrase</span>
          <input type="password" minLength={12} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" required />
        </label>
        <button className="btn" disabled={download.isPending} style={{ alignSelf: "end" }}>
          {download.isPending ? "Preparing…" : "Download a backup"}
        </button>
      </form>
      <p className="xs muted">Without this passphrase the backup can't be opened, by anyone. Keep it somewhere other than this computer.</p>
      {download.error && <div className="error">{download.error.message}</div>}

      {f && (
        <div className="panel stack remote-panel">
          <label className="check">
            <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
            <span>Write a backup every day</span>
          </label>
          {f.enabled && (
            <div className="grid-2">
              <label className="field">
                <span>Folder</span>
                <input className="data" value={f.folder} onChange={(e) => setF({ ...f, folder: e.target.value })} />
                <small>Another disk, a NAS or a synced folder is best.</small>
              </label>
              <label className="field">
                <span>Passphrase in the vault</span>
                <input className="data" value={f.passphrase} onChange={(e) => setF({ ...f, passphrase: e.target.value })} placeholder="secret://backup/passphrase" />
                <small>Save it with the Vault module first. The vault must be unlocked for scheduled backups.</small>
              </label>
              <label className="field">
                <span>Keep the newest</span>
                <input type="number" min={1} max={365} value={f.keep} onChange={(e) => setF({ ...f, keep: Number(e.target.value) })} />
              </label>
              <label className="field">
                <span>At (hour of the day)</span>
                <input type="number" min={0} max={23} value={f.hour} onChange={(e) => setF({ ...f, hour: Number(e.target.value) })} />
              </label>
            </div>
          )}
          {(save.error || run.error) && <div className="error">{(save.error || run.error)!.message}</div>}
          <div className="spread">
            <span className="xs muted">
              {sched.data?.lastRun
                ? sched.data.lastError
                  ? `Last backup failed ${ago(sched.data.lastRun)}: ${sched.data.lastError}`
                  : `Last backup ${ago(sched.data.lastRun)}`
                : "No scheduled backup yet."}
            </span>
            <div className="inline">
              {sched.data?.enabled && (
                <button className="btn sm quiet" onClick={() => run.mutate()} disabled={run.isPending}>
                  Back up now
                </button>
              )}
              <button className="btn sm primary" onClick={() => save.mutate(f)} disabled={save.isPending}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
