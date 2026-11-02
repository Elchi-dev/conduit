import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, ok } from "../api/client";
import "../components/shell.css";

function Brand() {
  return (
    <div className="inline" style={{ gap: 10 }}>
      <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true" style={{ color: "var(--signal)" }}>
        <path d="M6 10h20M6 16h13M6 22h20" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      <strong style={{ fontSize: "var(--t-xl)", letterSpacing: "-0.02em" }}>Conduit</strong>
    </div>
  );
}

export function Setup() {
  const qc = useQueryClient();
  const [f, setF] = useState({ token: "", name: "", email: "", password: "" });
  const m = useMutation({
    mutationFn: () => ok(api.POST("/setup", { body: { ...f, device: "Browser" } })),
    onSuccess: () => qc.invalidateQueries(),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    m.mutate();
  };
  return (
    <div className="gate">
      <div className="gate-box stack" style={{ gap: 24 }}>
        <Brand />
        <div className="stack" style={{ gap: 8 }}>
          <h1>Create the owner account</h1>
          <p className="muted">
            This account controls everything Conduit manages on this machine. The setup code is in the daemon's log and
            in the file <code>setup-token</code> in its data folder.
          </p>
        </div>
        <form onSubmit={submit}>
          <label className="field">
            <span>Setup code</span>
            <input
              className="data"
              value={f.token}
              onChange={(e) => setF({ ...f, token: e.target.value.trim() })}
              required
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>Your name</span>
            <input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoComplete="name" />
          </label>
          <label className="field">
            <span>Email</span>
            <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required autoComplete="email" />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              minLength={10}
              value={f.password}
              onChange={(e) => setF({ ...f, password: e.target.value })}
              required
              autoComplete="new-password"
            />
            <small>At least 10 characters.</small>
          </label>
          {m.error && <div className="error">{m.error.message}</div>}
          <button className="btn primary" disabled={m.isPending}>
            Create account
          </button>
        </form>
      </div>
    </div>
  );
}

export function Login() {
  const qc = useQueryClient();
  const [f, setF] = useState({ email: "", password: "" });
  const m = useMutation({
    mutationFn: () => ok(api.POST("/auth/login", { body: { ...f, device: "Browser" } })),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <div className="gate">
      <div className="gate-box stack" style={{ gap: 24 }}>
        <Brand />
        <h1>Sign in</h1>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <label className="field">
            <span>Email</span>
            <input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required autoComplete="email" />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              value={f.password}
              onChange={(e) => setF({ ...f, password: e.target.value })}
              required
              autoComplete="current-password"
            />
          </label>
          {m.error && <div className="error">{m.error.message}</div>}
          <button className="btn primary" disabled={m.isPending}>
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}
