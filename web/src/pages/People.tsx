import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type S } from "../api/client";
import { ago } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";

type User = S["User"];
type Role = "admin" | "member" | "viewer";

const roleHelp: Record<string, string> = {
  owner: t("Everything, and the only one who manages admins."),
  admin: t("Everything except managing other admins."),
  member: t("Runs actions, decides approvals, undoes changes."),
  viewer: t("Sees everything, changes nothing."),
};

/** Accounts on this daemon: add people, change roles, switch accounts off. */
export function People() {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: () => ok(api.GET("/me")) });
  const list = useQuery({ queryKey: ["users"], queryFn: () => ok(api.GET("/users")) });
  const [adding, setAdding] = useState(false);
  const [resetFor, setResetFor] = useState<User | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const update = useMutation({
    mutationFn: (v: { id: string; role?: Role; disabled?: boolean }) =>
      ok(api.PATCH("/users/{id}", { params: { path: { id: v.id } }, body: { role: v.role, disabled: v.disabled } })),
    onSuccess: refresh,
  });
  const myRole = me.data?.user.role;
  const canManage = (u: User) => u.id !== me.data?.user.id && u.role !== "owner" && (myRole === "owner" || u.role !== "admin");

  return (
    <div className="page">
      <div className="page-head spread">
        <div>
          <h1>{t("People")}</h1>
          <p>{t("Everyone who can sign in to this Conduit. Agents and programs use API keys instead.")}</p>
        </div>
        {!adding && (
          <button className="btn primary" onClick={() => setAdding(true)}>
            {t("Add a person")}</button>
        )}
      </div>

      {adding && <AddPerson owner={myRole === "owner"} onDone={() => { setAdding(false); refresh(); }} />}
      {resetFor && <ResetPassword user={resetFor} onDone={() => setResetFor(null)} />}
      {update.error && <div className="error">{update.error.message}</div>}

      <div className="panel rows">
        {list.data?.map((u) => (
          <div className="row people-row" key={u.id}>
            <div className="stack" style={{ gap: 2 }}>
              <strong className={u.disabled ? "muted" : ""}>
                {u.name}
                {u.id === me.data?.user.id && <span className="muted"> {t("(you)")}</span>}
              </strong>
              <span className="xs muted">
                {u.email}{t(", added")}{" "}{ago(u.createdAt)}
                {u.disabled && t(", switched off")}
              </span>
            </div>
            {canManage(u) ? (
              <select
                className="input role-select"
                aria-label={t("Role for {name}", { name: u.name })}
                value={u.role}
                onChange={(e) => update.mutate({ id: u.id, role: e.target.value as Role })}
                title={roleHelp[u.role]}
              >
                {myRole === "owner" && <option value="admin">{t("Admin")}</option>}
                <option value="member">{t("Member")}</option>
                <option value="viewer">{t("Viewer")}</option>
              </select>
            ) : (
              <span className="tag" title={roleHelp[u.role]}>
                {u.role[0].toUpperCase() + u.role.slice(1)}
              </span>
            )}
            <div className="inline">
              {canManage(u) && (
                <>
                  <button className="btn sm quiet" onClick={() => setResetFor(u)}>
                    {t("Set password")}</button>
                  <button className={`btn sm ${u.disabled ? "" : "danger"}`} onClick={() => update.mutate({ id: u.id, disabled: !u.disabled })}>
                    {u.disabled ? t("Switch on") : t("Switch off")}
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {myRole === "owner" && <VaultFolders people={list.data ?? []} />}

      <section className="stack" style={{ gap: 6 }}>
        <h2 className="section-title">{t("Roles")}</h2>
        {Object.entries(roleHelp).map(([r, d]) => (
          <p className="small" key={r}>
            <strong>{r[0].toUpperCase() + r.slice(1)}</strong> <span className="muted">{d}</span>
          </p>
        ))}
        <p className="small muted">
          {t("A person's API keys can never do more than their role allows. Teams can also sign in with their company account: see Settings, Single sign-on.")}</p>
      </section>
    </div>
  );
}

function AddPerson({ owner, onDone }: { owner: boolean; onDone: () => void }) {
  const [f, setF] = useState({ name: "", email: "", password: "", role: "member" as Role });
  const create = useMutation({
    mutationFn: () => ok(api.POST("/users", { body: f })),
    onSuccess: onDone,
  });
  return (
    <form
      className="panel runner stack"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <div className="grid-2">
        <label className="field">
          <span>{t("Name")}</span>
          <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoComplete="off" />
        </label>
        <label className="field">
          <span>{t("Email")}</span>
          <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required autoComplete="off" />
        </label>
        <label className="field">
          <span>{t("First password")}</span>
          <input type="password" minLength={10} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required autoComplete="new-password" />
          <small>{t("Give it to them in person; they can change it in Settings.")}</small>
        </label>
        <label className="field">
          <span>{t("Role")}</span>
          <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as Role })}>
            {owner && <option value="admin">{t("Admin")}</option>}
            <option value="member">{t("Member")}</option>
            <option value="viewer">{t("Viewer")}</option>
          </select>
          <small>{roleHelp[f.role]}</small>
        </label>
      </div>
      {create.error && <div className="error">{create.error.message}</div>}
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          {t("Cancel")}</button>
        <button className="btn primary" disabled={create.isPending}>
          {t("Add person")}</button>
      </div>
    </form>
  );
}

function ResetPassword({ user, onDone }: { user: User; onDone: () => void }) {
  const [pw, setPw] = useState("");
  const reset = useMutation({
    mutationFn: () => ok(api.POST("/users/{id}/password", { params: { path: { id: user.id } }, body: { password: pw } })),
    onSuccess: onDone,
  });
  return (
    <form
      className="panel runner stack"
      onSubmit={(e) => {
        e.preventDefault();
        reset.mutate();
      }}
    >
      <label className="field">
        <span>{t("New password for")}{" "}{user.name}</span>
        <input type="password" minLength={10} value={pw} onChange={(e) => setPw(e.target.value)} required autoComplete="new-password" />
        <small>{t("This signs them out everywhere.")}</small>
      </label>
      {reset.error && <div className="error">{reset.error.message}</div>}
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          {t("Cancel")}</button>
        <button className="btn primary" disabled={reset.isPending}>
          {t("Set password")}</button>
      </div>
    </form>
  );
}

type Folder = S["VaultFolder"];

/** The owner restricts vault folders to roles and people. */
function VaultFolders({ people }: { people: User[] }) {
  const qc = useQueryClient();
  const cur = useQuery({ queryKey: ["vault", "folders"], queryFn: () => ok(api.GET("/vault/folders")) });
  const [draft, setDraft] = useState<Folder[] | null>(null);
  const folders = draft ?? cur.data ?? [];
  const save = useMutation({
    mutationFn: (fs: Folder[]) => ok(api.PUT("/vault/folders", { body: fs })),
    onSuccess: (fs) => {
      qc.setQueryData(["vault", "folders"], fs);
      setDraft(null);
    },
  });
  const edit = (i: number, f: Partial<Folder>) => setDraft(folders.map((x, j) => (j === i ? { ...x, ...f } : x)));
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="spread">
        <h2 className="section-title">{t("Restricted vault folders")}</h2>
        <button className="btn sm" onClick={() => setDraft([...folders, { prefix: "", roles: ["owner"], users: [], automations: false }])}>
          {t("Restrict a folder")}</button>
      </div>
      <p className="small muted">
        {t("Secrets in a restricted folder, such as")}{" "}<span className="data">finance/</span>{t(", can only be revealed, changed or used in settings by the roles and people you pick, and by agents and keys acting for them. Everyone still sees that they exist.")}</p>
      {folders.map((f, i) => (
        <div className="panel stack remote-panel" key={i}>
          <div className="spread">
            <label className="field" style={{ maxWidth: 260 }}>
              <span>{t("Folder")}</span>
              <input className="data" value={f.prefix} onChange={(e) => edit(i, { prefix: e.target.value })} placeholder={"finance/"} />
            </label>
            <button className="btn sm quiet" onClick={() => setDraft(folders.filter((_, j) => j !== i))}>
              {t("Remove restriction")}</button>
          </div>
          <fieldset className="inline" style={{ border: 0, padding: 0, flexWrap: "wrap" }}>
            <legend className="small">{t("Roles")}</legend>
            {["owner", "admin", "member", "viewer"].map((r) => (
              <label className="check" key={r}>
                <input type="checkbox" checked={f.roles.includes(r as Folder["roles"][number]) || r === "owner"} disabled={r === "owner"}
                  onChange={() => edit(i, { roles: toggle(f.roles, r) as Folder["roles"] })} />
                <span>{r[0].toUpperCase() + r.slice(1)}</span>
              </label>
            ))}
          </fieldset>
          <fieldset className="inline" style={{ border: 0, padding: 0, flexWrap: "wrap" }}>
            <legend className="small">{t("And these people")}</legend>
            {people.filter((u) => u.role !== "owner").map((u) => (
              <label className="check" key={u.id}>
                <input type="checkbox" checked={f.users.includes(u.id)} onChange={() => edit(i, { users: toggle(f.users, u.id) })} />
                <span>{u.name}</span>
              </label>
            ))}
          </fieldset>
          <label className="check">
            <input type="checkbox" checked={f.automations} onChange={(e) => edit(i, { automations: e.target.checked })} />
            <span>{t("Automations may use these secrets")}</span>
          </label>
        </div>
      ))}
      {save.error && <div className="error">{save.error.message}</div>}
      {draft && (
        <div className="inline">
          <button className="btn quiet" onClick={() => setDraft(null)}>
            {t("Cancel")}</button>
          <button className="btn primary" onClick={() => save.mutate(draft)} disabled={save.isPending}>
            {t("Save restrictions")}</button>
        </div>
      )}
    </section>
  );
}
