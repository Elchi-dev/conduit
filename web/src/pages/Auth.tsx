import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { api, ok } from "../api/client";
import { forgetRelay, pairFromCode, relayProfile, routeLabel } from "../lib/connection";
import { fingerprint } from "../lib/relay";
import { isMobileApp, scanQR } from "../lib/native";
import "../components/shell.css";

export function Brand() {
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
  const [elsewhere, setElsewhere] = useState(false);
  const relay = relayProfile();
  const [fp, setFp] = useState("");
  useEffect(() => {
    if (relay) fingerprint(relay.key).then(setFp);
  }, [relay]);
  // Single sign-on is a browser redirect, so it works only on the daemon's own address.
  const sso = useQuery({ queryKey: ["auth", "oidc"], queryFn: () => ok(api.GET("/auth/oidc")), enabled: !relay, retry: false });
  const ssoError = new URLSearchParams(window.location.search).get("signin_error");
  if (elsewhere) return <Connect onBack={() => setElsewhere(false)} />;
  const m = useMutation({
    mutationFn: () => ok(api.POST("/auth/login", { body: { ...f, device: "Browser" } })),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <div className="gate">
      <div className="gate-box stack" style={{ gap: 24 }}>
        <Brand />
        <div className="stack" style={{ gap: 8 }}>
          <h1>Sign in</h1>
          {relay && (
            <p className="muted">
              To {relay.name}, {routeLabel(relay)}. The connection is end-to-end encrypted to the key{" "}
              <span className="data">{fp}</span>, which should match the fingerprint shown on that computer.
            </p>
          )}
        </div>
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
        {!relay && sso.data?.enabled && (
          <a className="btn" href="/api/v1/auth/oidc/start">
            Sign in with {sso.data.label}
          </a>
        )}
        {!relay && ssoError && <div className="error">{ssoMessage(ssoError)}</div>}
        {relay ? (
          <button
            className="btn quiet"
            onClick={() => {
              forgetRelay();
              qc.invalidateQueries();
            }}
          >
            Forget {relay.name} and disconnect
          </button>
        ) : (
          <button className="btn quiet" onClick={() => setElsewhere(true)}>
            Connect to a Conduit on another computer
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * Pair this device with a daemon elsewhere by the code it shows under
 * Settings, Remote access. Used when the page isn't served by a daemon
 * (the Android app, a hub's website) or to reach another one.
 */
export function Connect({ onBack, reason }: { onBack?: () => void; reason?: string }) {
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const m = useMutation({
    mutationFn: (text?: string) => pairFromCode(text ?? code),
    onSuccess: () => qc.invalidateQueries(),
  });
  const scan = useMutation({
    mutationFn: scanQR,
    onSuccess: (text) => {
      setCode(text);
      m.mutate(text);
    },
  });
  return (
    <div className="gate">
      <div className="gate-box stack" style={{ gap: 24 }}>
        <Brand />
        <div className="stack" style={{ gap: 8 }}>
          <h1>Connect to your Conduit</h1>
          {reason && <p className="muted">{reason}</p>}
          <p className="muted">
            On the computer running Conduit, open Settings, then Remote access, and choose Pair a device. Scan the code
            with your phone's camera, or copy the pairing link and paste it here.
          </p>
        </div>
        {isMobileApp() && (
          <div className="stack" style={{ gap: 8 }}>
            <button className="btn primary scan-btn" onClick={() => scan.mutate()} disabled={scan.isPending || m.isPending}>
              {scan.isPending ? "Opening the camera…" : "Scan the pairing code"}
            </button>
            {scan.error && <div className="error">{String(scan.error)}</div>}
          </div>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate(undefined);
          }}
        >
          <label className="field">
            <span>Pairing link</span>
            <textarea
              className="data"
              rows={3}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="conduit://pair?d=…"
              required
              autoComplete="off"
              spellCheck={false}
            />
            <small>Single use, valid for 10 minutes.</small>
          </label>
          {m.error && <div className="error">{m.error.message}</div>}
          <button className={`btn ${isMobileApp() ? "" : "primary"}`} disabled={m.isPending}>
            {m.isPending ? "Connecting…" : "Connect"}
          </button>
        </form>
        {onBack && (
          <button className="btn quiet" onClick={onBack}>
            Back to sign in
          </button>
        )}
      </div>
    </div>
  );
}

/** Plain-language text for a single sign-on failure code. */
function ssoMessage(code: string): string {
  switch (code) {
    case "unverified":
      return "Your provider didn't confirm your email address, so single sign-on can't use it.";
    case "domain":
      return "Your email address isn't in a domain this Conduit accepts. Ask its owner to add it.";
    case "link_required":
      return "Owners and admins sign in with their password first, then link single sign-on in Settings.";
    case "linked_elsewhere":
      return "This account is linked to a different identity at your provider. Sign in with that one, or with your password.";
    case "no_account":
      return "There's no account here for your email address yet. Ask the owner to add you.";
    case "disabled":
      return "Your account here is switched off. Ask the owner.";
    case "state":
    case "expired":
      return "That sign-in expired or was started in another browser. Try again.";
    case "provider_refused":
      return "The sign-in was cancelled at your provider.";
    case "busy":
      return "Too many sign-in attempts. Wait a minute and try again.";
    default:
      return "Single sign-on didn't work. Try again, or sign in with your password; the owner can see the reason in the daemon's log.";
  }
}
