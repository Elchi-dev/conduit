import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok, type S } from "../api/client";
import { ago } from "../lib/format";
import "./pages.css";

type User = S["User"];
type Role = "admin" | "member" | "viewer";

const roleHelp: Record<string, string> = {
  owner: "Everything, and the only one who manages admins.",
  admin: "Everything except managing other admins.",
  member: "Runs actions, decides approvals, undoes changes.",
  viewer: "Sees everything, changes nothing.",
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
          <h1>People</h1>
          <p>Everyone who can sign in to this Conduit. Agents and programs use API keys instead.</p>
        </div>
        {!adding && (
          <button className="btn primary" onClick={() => setAdding(true)}>
            Add a person
          </button>
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
                {u.id === me.data?.user.id && <span className="muted"> (you)</span>}
              </strong>
              <span className="xs muted">
                {u.email}, added {ago(u.createdAt)}
                {u.disabled && ", switched off"}
              </span>
            </div>
            {canManage(u) ? (
              <select
                className="input role-select"
                aria-label={`Role for ${u.name}`}
                value={u.role}
                onChange={(e) => update.mutate({ id: u.id, role: e.target.value as Role })}
                title={roleHelp[u.role]}
              >
                {myRole === "owner" && <option value="admin">Admin</option>}
                <option value="member">Member</option>
                <option value="viewer">Viewer</option>
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
                    Set password
                  </button>
                  <button className={`btn sm ${u.disabled ? "" : "danger"}`} onClick={() => update.mutate({ id: u.id, disabled: !u.disabled })}>
                    {u.disabled ? "Switch on" : "Switch off"}
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      <section className="stack" style={{ gap: 6 }}>
        <h2 className="section-title">Roles</h2>
        {Object.entries(roleHelp).map(([r, d]) => (
          <p className="small" key={r}>
            <strong>{r[0].toUpperCase() + r.slice(1)}</strong> <span className="muted">{d}</span>
          </p>
        ))}
        <p className="small muted">
          A person's API keys can never do more than their role allows. Teams can also sign in with their company account: see
          Settings, Single sign-on.
        </p>
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
          <span>Name</span>
          <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoComplete="off" />
        </label>
        <label className="field">
          <span>Email</span>
          <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required autoComplete="off" />
        </label>
        <label className="field">
          <span>First password</span>
          <input type="password" minLength={10} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required autoComplete="new-password" />
          <small>Give it to them in person; they can change it in Settings.</small>
        </label>
        <label className="field">
          <span>Role</span>
          <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as Role })}>
            {owner && <option value="admin">Admin</option>}
            <option value="member">Member</option>
            <option value="viewer">Viewer</option>
          </select>
          <small>{roleHelp[f.role]}</small>
        </label>
      </div>
      {create.error && <div className="error">{create.error.message}</div>}
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          Cancel
        </button>
        <button className="btn primary" disabled={create.isPending}>
          Add person
        </button>
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
        <span>New password for {user.name}</span>
        <input type="password" minLength={10} value={pw} onChange={(e) => setPw(e.target.value)} required autoComplete="new-password" />
        <small>This signs them out everywhere.</small>
      </label>
      {reset.error && <div className="error">{reset.error.message}</div>}
      <div className="inline">
        <button type="button" className="btn quiet" onClick={onDone}>
          Cancel
        </button>
        <button className="btn primary" disabled={reset.isPending}>
          Set password
        </button>
      </div>
    </form>
  );
}
