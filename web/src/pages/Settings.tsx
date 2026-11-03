import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ok } from "../api/client";
import { ago } from "../lib/format";
import { AppSection, DaemonUpdates } from "./AppSection";
import { RemoteAccess } from "./RemoteAccess";
import { SsoSection } from "./Sso";
import { SyncSection } from "./Sync";
import { Webhooks } from "./Webhooks";
import "./pages.css";

function useTheme() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("conduit.theme") ?? "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("conduit.theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  return [theme, setTheme] as const;
}

export function Settings() {
  const qc = useQueryClient();
  const [theme, setTheme] = useTheme();
  const me = useQuery({ queryKey: ["me"], queryFn: () => ok(api.GET("/me")) });
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => ok(api.GET("/me/sessions")) });
  const version = useQuery({ queryKey: ["version"], queryFn: () => ok(api.GET("/version")) });
  const [pw, setPw] = useState({ current: "", new: "" });
  const [allSessions, setAllSessions] = useState(false);
  const changePw = useMutation({
    mutationFn: () => ok(api.POST("/me/password", { body: pw })),
    onSuccess: () => {
      setPw({ current: "", new: "" });
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
  const endSession = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/me/sessions/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });
  const logout = useMutation({
    mutationFn: () => ok(api.POST("/auth/logout")),
    onSuccess: () => qc.invalidateQueries(),
  });

  return (
    <div className="page">
      <div className="page-head">
        <h1>Settings</h1>
        <p>
          Signed in as {me.data?.user.name} ({me.data?.user.email}), {me.data?.user.role}.
        </p>
      </div>

      <AppSection />
      <DaemonUpdates admin={me.data?.user.role === "owner" || me.data?.user.role === "admin"} />

      <RemoteAccess admin={me.data?.user.role === "owner" || me.data?.user.role === "admin"} />

      <SyncSection admin={me.data?.user.role === "owner" || me.data?.user.role === "admin"} />

      <SsoSection admin={me.data?.user.role === "owner" || me.data?.user.role === "admin"} />

      <Webhooks admin={me.data?.user.role === "owner" || me.data?.user.role === "admin"} />

      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">Appearance</h2>
        <div className="inline" role="radiogroup" aria-label="Theme">
          {["system", "dark", "light"].map((t) => (
            <button key={t} role="radio" aria-checked={theme === t} className={`btn ${theme === t ? "primary" : ""}`} onClick={() => setTheme(t)}>
              {t === "system" ? "Match system" : t === "dark" ? "Dark" : "Light"}
            </button>
          ))}
        </div>
      </section>

      <section className="stack" style={{ gap: 8 }}>
        <h2 className="section-title">Signed-in devices</h2>
        <div className="panel rows">
          {(allSessions ? sessions.data : sessions.data?.slice(0, 5))?.map((s) => (
            <div className="row session-row" key={s.id}>
              <span className="small">{s.device || "Unknown device"}</span>
              <span className="xs muted">active {ago(s.lastSeenAt)}</span>
              <button className="btn sm quiet" onClick={() => endSession.mutate(s.id)}>
                Sign out
              </button>
            </div>
          ))}
        </div>
        {!allSessions && (sessions.data?.length ?? 0) > 5 && (
          <div>
            <button className="btn sm quiet" onClick={() => setAllSessions(true)}>
              Show all {sessions.data?.length}
            </button>
          </div>
        )}
      </section>


      <section className="stack" style={{ gap: 8, maxWidth: 420 }}>
        <h2 className="section-title">Password</h2>
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            changePw.mutate();
          }}
        >
          <label className="field">
            <span>Current password</span>
            <input type="password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} autoComplete="current-password" required />
          </label>
          <label className="field">
            <span>New password</span>
            <input type="password" minLength={10} value={pw.new} onChange={(e) => setPw({ ...pw, new: e.target.value })} autoComplete="new-password" required />
            <small>Changing it signs out every other device.</small>
          </label>
          {changePw.error && <div className="error">{changePw.error.message}</div>}
          {changePw.isSuccess && <p className="small muted">Password changed.</p>}
          <div>
            <button className="btn">Change password</button>
          </div>
        </form>
      </section>

      <section className="spread">
        <span className="xs muted">
          Conduit <span className="data">{version.data?.version}</span> ({version.data?.os}/{version.data?.arch})
        </span>
        <button className="btn" onClick={() => logout.mutate()}>
          Sign out
        </button>
      </section>
    </div>
  );
}
