import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { api, ok, type S } from "../api/client";
import { isRelay } from "../lib/connection";
import { ago } from "../lib/format";

/**
 * Settings section: link this daemon to a hub, then pair phones and other
 * browsers by QR code. Shown only to admins on the daemon's own page.
 */
export function RemoteAccess({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["remote"],
    queryFn: () => ok(api.GET("/remote")),
    enabled: admin,
    refetchInterval: 5_000,
  });
  const [form, setForm] = useState({ hub: "", code: "" });
  const [pairing, setPairing] = useState<S["RemotePairing"] | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["remote"] });
  const link = useMutation({ mutationFn: () => ok(api.POST("/remote/link", { body: form })), onSuccess: refresh });
  const unlink = useMutation({
    mutationFn: () => ok(api.DELETE("/remote/link")),
    onSuccess: () => {
      setPairing(null);
      refresh();
    },
  });
  const pair = useMutation({ mutationFn: () => ok(api.POST("/remote/pairings")), onSuccess: setPairing });
  const revoke = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/remote/clients/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });

  // When a phone pairs, its entry appears; close the code.
  const clientCount = status.data?.clients.length ?? 0;
  const [seen, setSeen] = useState(clientCount);
  useEffect(() => {
    if (clientCount > seen && pairing) setPairing(null);
    setSeen(clientCount);
  }, [clientCount, seen, pairing]);

  if (!admin) return null;
  const st = status.data;

  return (
    <section className="stack" style={{ gap: 8 }}>
      <h2 className="section-title">Remote access</h2>
      {!st ? null : !st.linked ? (
        <div className="panel stack remote-panel">
          <p className="small">
            Reach this Conduit from your phone or another computer without opening a port. Link it to a hub account, then pair
            devices by QR code. Everything between your devices and this computer is end-to-end encrypted; the hub only
            forwards ciphertext.
          </p>
          <p className="xs muted">
            Use any hub: the default one, a hub your organisation runs, or your own (see the self-hosting guide). On the hub,
            sign in and create a pairing code under Devices.
          </p>
          <form
            className="remote-link-form"
            onSubmit={(e) => {
              e.preventDefault();
              link.mutate();
            }}
          >
            <label className="field">
              <span>Hub address</span>
              <input
                type="url"
                className="data"
                placeholder="https://hub.example.com"
                value={form.hub}
                onChange={(e) => setForm({ ...form, hub: e.target.value })}
                required
              />
            </label>
            <label className="field">
              <span>Pairing code</span>
              <input
                className="data"
                value={form.code}
                onChange={(e) => setForm({ ...form, code: e.target.value.toUpperCase() })}
                required
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <div className="field">
              <span aria-hidden="true">&nbsp;</span>
              <button className="btn primary" disabled={link.isPending}>
                {link.isPending ? "Linking…" : "Link to hub"}
              </button>
            </div>
          </form>
          {link.error && <div className="error">{link.error.message}</div>}
          {st.lan.length > 0 ? (
            <div className="stack lan-pair" style={{ gap: 8 }}>
              <div className="spread">
                <span className="small">
                  Or pair a phone on this network without any hub. It connects straight to{" "}
                  <span className="data">{st.lan[0].replace(/^ws:\/\//, "").replace(/\/relay$/, "")}</span>.
                </span>
                {!isRelay() && (
                  <button className="btn" onClick={() => pair.mutate()} disabled={pair.isPending}>
                    Pair on this network
                  </button>
                )}
              </div>
              {pair.error && <div className="error">{pair.error.message}</div>}
              {pairing && <PairingCode pairing={pairing} fingerprint={st.fingerprint} onClose={() => setPairing(null)} />}
            </div>
          ) : (
            <p className="xs muted">
              To pair phones on your network without a hub, start Conduit with <span className="data">-listen 0.0.0.0:7600</span>.
            </p>
          )}
        </div>
      ) : (
        <div className="panel stack remote-panel">
          <div className="spread">
            <div className="inline" style={{ gap: 10 }}>
              <span className={`bulb ${st.connected ? "on" : "warn"}`} aria-hidden="true" />
              <div className="stack" style={{ gap: 2 }}>
                <strong className="small">
                  {st.connected ? "Reachable through" : "Not connected to"} {hostOf(st.link?.hub)}
                </strong>
                <span className="xs muted">
                  {st.lan.length > 0 && "Phones on this network connect directly. "}
                  Linked to {st.link?.account} {st.link?.linkedAt ? ago(st.link.linkedAt) : ""}
                  {st.streams > 0 && `, ${st.streams === 1 ? "1 device" : `${st.streams} devices`} connected now`}
                </span>
                {!st.connected && st.lastError && <span className="xs muted">{st.lastError}</span>}
              </div>
            </div>
            <div className="inline">
              {!isRelay() && (
                <button className="btn primary" onClick={() => pair.mutate()} disabled={pair.isPending}>
                  Pair a device
                </button>
              )}
              <button className="btn quiet" onClick={() => unlink.mutate()} disabled={unlink.isPending}>
                Unlink
              </button>
            </div>
          </div>
          {pair.error && <div className="error">{pair.error.message}</div>}
          {pairing && <PairingCode pairing={pairing} fingerprint={st.fingerprint} onClose={() => setPairing(null)} />}
          <div className="stack" style={{ gap: 4 }}>
            <span className="xs muted">
              This computer's key fingerprint <span className="data">{st.fingerprint}</span>
            </span>
          </div>
          {st.clients.length > 0 && (
            <div className="rows">
              {st.clients.map((c) => (
                <div className="row session-row" key={c.id}>
                  <span className="small">{c.name}</span>
                  <span className="xs muted">
                    paired {ago(c.createdAt)}, last used {ago(c.lastSeenAt)}
                  </span>
                  <button className="btn sm quiet" onClick={() => revoke.mutate(c.id)}>
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function PairingCode({ pairing, fingerprint, onClose }: { pairing: S["RemotePairing"]; fingerprint: string; onClose: () => void }) {
  const [svg, setSvg] = useState("");
  const [left, setLeft] = useState(() => Math.max(0, new Date(pairing.expiresAt).getTime() - Date.now()));
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    QRCode.toString(pairing.uri, { type: "svg", margin: 1, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } }).then(
      setSvg,
    );
  }, [pairing.uri]);
  useEffect(() => {
    const t = setInterval(() => setLeft(Math.max(0, new Date(pairing.expiresAt).getTime() - Date.now())), 1000);
    return () => clearInterval(t);
  }, [pairing.expiresAt]);
  const mins = Math.floor(left / 60000);
  const secs = Math.floor((left % 60000) / 1000);
  const expired = left === 0;

  return (
    <div className="pairing">
      <div className={`pairing-qr ${expired ? "expired" : ""}`} dangerouslySetInnerHTML={{ __html: svg }} aria-label="Pairing QR code" role="img" />
      <div className="stack" style={{ gap: 8 }}>
        <strong className="small">Scan with the Conduit app, or open the link on the other device</strong>
        <p className="xs muted">
          The code works once. After pairing, check that the other device shows the fingerprint{" "}
          <span className="data">{fingerprint}</span>.
        </p>
        <span className="xs">
          {expired ? "Expired. Make a new one." : `Valid for ${mins}:${String(secs).padStart(2, "0")}`}
        </span>
        <div className="inline">
          <button
            className="btn sm"
            disabled={expired}
            onClick={() => {
              navigator.clipboard?.writeText(pairing.uri).then(() => setCopied(true));
            }}
          >
            {copied ? "Copied" : "Copy pairing link"}
          </button>
          <button className="btn sm quiet" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

function hostOf(u?: string) {
  try {
    return u ? new URL(u).host : "the hub";
  } catch {
    return u ?? "the hub";
  }
}
