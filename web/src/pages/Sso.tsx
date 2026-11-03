import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ok, type S } from "../api/client";
import "./pages.css";

type Settings = S["OIDCSettings"];

/** Settings section: sign in with an OpenID Connect provider. */
export function SsoSection({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const cur = useQuery({ queryKey: ["auth", "oidc", "settings"], queryFn: () => ok(api.GET("/auth/oidc/settings")), enabled: admin });
  const [f, setF] = useState<Settings | null>(null);
  const [domains, setDomains] = useState("");
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (cur.data && !f) {
      setF(cur.data);
      setDomains((cur.data.allowedDomains ?? []).join(" "));
    }
  }, [cur.data, f]);
  const save = useMutation({
    mutationFn: (s: Settings) => {
      const { redirectUri: _ignored, ...body } = s;
      return ok(api.PUT("/auth/oidc", { body: { ...body, allowedDomains: domains.split(/[\s,]+/).filter(Boolean) } }));
    },
    onSuccess: (s) => {
      setF(s);
      qc.invalidateQueries({ queryKey: ["auth", "oidc"] });
    },
  });
  if (!admin || !cur.data || !f) return null;
  const set = (patch: Partial<Settings>) => setF({ ...f, ...patch });

  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <h2 className="section-title">Single sign-on</h2>
        {!open && (
          <button className="btn sm" onClick={() => setOpen(true)}>
            {cur.data.enabled ? "Change" : "Set up"}
          </button>
        )}
      </div>
      <p className="small muted">
        {cur.data.enabled
          ? `On: people can sign in with ${cur.data.label} (${cur.data.issuer}).`
          : "Let your team sign in with Google Workspace, Microsoft Entra ID, Okta, Keycloak, Authentik or any OpenID Connect provider."}
      </p>
      {open && (
        <form
          className="panel runner stack remote-panel"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate(f);
          }}
        >
          <div className="field">
            <span>Redirect URI to register with your provider</span>
            <div className="inline">
              <code className="secret-value">{cur.data.redirectUri}</code>
              <button type="button" className="btn sm" onClick={() => navigator.clipboard?.writeText(cur.data!.redirectUri ?? "")}>
                Copy
              </button>
            </div>
          </div>
          <label className="field">
            <span>Issuer</span>
            <input className="data" value={f.issuer ?? ""} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://accounts.google.com" />
          </label>
          <label className="field">
            <span>Client ID</span>
            <input className="data" value={f.clientId ?? ""} onChange={(e) => set({ clientId: e.target.value })} />
          </label>
          <label className="field">
            <span>Client secret</span>
            <input className="data" value={f.clientSecret ?? ""} onChange={(e) => set({ clientSecret: e.target.value })} placeholder="secret://sso/client-secret" />
            <small>Save the secret in the vault first and enter its reference here.</small>
          </label>
          <label className="field">
            <span>Button label</span>
            <input value={f.label ?? ""} onChange={(e) => set({ label: e.target.value })} placeholder="Google" />
          </label>
          <label className="field">
            <span>Allowed email domains</span>
            <input className="data" value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com" />
            <small>Leave empty to let only people who already have an account here sign in.</small>
          </label>
          <label className="check">
            <input type="checkbox" checked={!!f.autoCreate} onChange={(e) => set({ autoCreate: e.target.checked })} />
            <span>Make an account the first time someone from an allowed domain signs in</span>
          </label>
          {f.autoCreate && (
            <label className="field">
              <span>New accounts are</span>
              <select value={f.newUserRole ?? "member"} onChange={(e) => set({ newUserRole: e.target.value as "member" | "viewer" })}>
                <option value="member">Members: can act, undo and decide approvals</option>
                <option value="viewer">Viewers: can only look</option>
              </select>
            </label>
          )}
          <label className="field">
            <span>This daemon's address (optional)</span>
            <input className="data" value={f.redirectBase ?? ""} onChange={(e) => set({ redirectBase: e.target.value })} placeholder="https://conduit.example.com" />
            <small>When people reach it under another name than this page, such as through a reverse proxy.</small>
          </label>
          <label className="check">
            <input type="checkbox" checked={!!f.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
            <span>Show "Sign in with {f.label || "single sign-on"}" on the sign-in page</span>
          </label>
          {save.error && <div className="error">{save.error.message}</div>}
          {save.isSuccess && <p className="small muted">Saved.</p>}
          <div className="inline">
            <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
              Close
            </button>
            <button className="btn primary" disabled={save.isPending}>
              Save
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
