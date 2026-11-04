import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../api/client";
import { apiFetchUrl } from "../lib/connection";
import { ago } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

// Networks: userspace WireGuard tunnels that connections can be attached to
// (docs/architecture/networks.md). These endpoints are newer than the
// generated client, so they're called directly.

export type NetworkPeer = {
  name?: string;
  publicKey: string;
  presharedKey?: string;
  endpoint?: string;
  allowedIPs: string[];
  persistentKeepalive?: number;
};
export type Network = {
  id: string;
  name: string;
  privateKey: string;
  publicKey?: string;
  addresses: string[];
  dns?: string[];
  mtu?: number;
  listenPort?: number;
  peers: NetworkPeer[];
  instances: string[];
  updatedAt: string;
};
type PeerStatus = { publicKey: string; name?: string; endpoint?: string; lastHandshake?: string; handshakeAgeSeconds: number; rxBytes: number; txBytes: number };
type NetworkStatus = { id: string; running: boolean; error?: string; since?: string; peers: PeerStatus[] };

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await apiFetchUrl("/api/v1" + path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error || msg;
    } catch {
      /* not JSON */
    }
    throw new ApiError(msg || t("Request failed ({status})", { status: res.status }), res.status);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export function useNetworks(enabled = true) {
  return useQuery({ queryKey: ["networks"], queryFn: () => call<Network[]>("GET", "/networks"), enabled, retry: false });
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

const lines = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

export function Networks() {
  const list = useNetworks();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <div className="page stack">
      <div className="spread">
        <div className="page-head">
          <h1>{t("Networks")}</h1>
          <p>
            {t("Reach servers inside a WireGuard network. Conduit runs the tunnel itself, without root and without changing this computer's network settings; only connections you attach to a network use it.")}
          </p>
        </div>
        {!adding && (
          <button className="btn primary" onClick={() => setAdding(true)}>
            {t("Add network")}</button>
        )}
      </div>

      {adding && <NetworkForm onDone={() => setAdding(false)} />}
      <ErrorNote error={list.error} />

      {list.data?.length === 0 && !adding && (
        <div className="empty">
          <h2>{t("No networks yet")}</h2>
          <p className="muted">{t("Paste the WireGuard file your VPN server gave you (wg-quick format). The private key goes into the vault.")}</p>
        </div>
      )}

      {list.data?.map((n) =>
        editing === n.id ? (
          <NetworkForm key={n.id} existing={n} onDone={() => setEditing(null)} />
        ) : (
          <NetworkCard key={n.id} n={n} onEdit={() => setEditing(n.id)} />
        ),
      )}
    </div>
  );
}

function NetworkCard({ n, onEdit }: { n: Network; onEdit: () => void }) {
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["networks", n.id, "status"],
    queryFn: () => call<NetworkStatus>("GET", `/networks/${encodeURIComponent(n.id)}/status`),
    refetchInterval: 10_000,
  });
  const restart = useMutation({
    mutationFn: () => call<NetworkStatus>("POST", `/networks/${encodeURIComponent(n.id)}/restart`),
    onSuccess: (s) => qc.setQueryData(["networks", n.id, "status"], s),
  });
  const del = useMutation({
    mutationFn: () => call<void>("DELETE", `/networks/${encodeURIComponent(n.id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["networks"] }),
  });
  const st = status.data;
  const lamp = st?.error ? "down" : st?.running ? "ok" : "pending";
  return (
    <section className="panel stack" style={{ gap: 10, padding: 14 }} aria-label={n.name}>
      <div className="spread">
        <div className="inline">
          <span className={`lamp ${lamp}`} style={{ padding: 0, height: "auto" }}>
            <span className="bulb" />
          </span>
          <h2 className="section-title" style={{ margin: 0 }}>{n.name}</h2>
          <span className="xs muted">
            {st?.error ? st.error : st?.running ? t("Up since {when}", { when: ago(st.since) }) : t("Starts when a connection uses it")}
          </span>
        </div>
        <div className="inline">
          <button className="btn sm" onClick={() => restart.mutate()} disabled={restart.isPending}>
            {st?.running ? t("Restart") : t("Connect now")}</button>
          <button className="btn sm" onClick={onEdit}>
            {t("Edit")}</button>
          <button
            className="btn sm danger"
            onClick={() => confirm(t("Remove the network {name}? Its keys are deleted from the vault.", { name: n.name })) && del.mutate()}
          >
            {t("Remove")}</button>
        </div>
      </div>
      <ErrorNote error={del.error || restart.error} />
      <dl className="kv small">
        <dt>{t("Addresses")}</dt>
        <dd className="data">{n.addresses.join(", ")}</dd>
        {n.dns && n.dns.length > 0 && (
          <>
            <dt>{t("DNS")}</dt>
            <dd className="data">{n.dns.join(", ")}</dd>
          </>
        )}
        <dt>{t("Public key")}</dt>
        <dd className="inline">
          <code className="xs">{n.publicKey || "–"}</code>
          {n.publicKey && (
            <button className="btn sm quiet" onClick={() => navigator.clipboard?.writeText(n.publicKey ?? "")}>
              {t("Copy")}</button>
          )}
        </dd>
        <dt>{t("Used by")}</dt>
        <dd>{n.instances.length ? n.instances.join(", ") : <span className="muted">{t("No connections yet")}</span>}</dd>
      </dl>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>{t("Peer")}</th>
              <th>{t("Endpoint")}</th>
              <th>{t("Allowed IPs")}</th>
              <th>{t("Last handshake")}</th>
              <th className="num">{t("Received")}</th>
              <th className="num">{t("Sent")}</th>
            </tr>
          </thead>
          <tbody>
            {n.peers.map((p) => {
              const ps = st?.peers.find((x) => x.publicKey === p.publicKey);
              return (
                <tr key={p.publicKey}>
                  <td>
                    {p.name && <strong>{p.name} </strong>}
                    <code className="xs muted">{p.publicKey.slice(0, 10)}…</code>
                  </td>
                  <td className="data xs">{ps?.endpoint || p.endpoint || "–"}</td>
                  <td className="data xs">{p.allowedIPs.join(", ")}</td>
                  <td className="xs">
                    {!ps || ps.handshakeAgeSeconds < 0
                      ? t("never")
                      : ps.handshakeAgeSeconds > 180
                        ? <span className="st-error">{ago(ps.lastHandshake)}</span>
                        : ago(ps.lastHandshake)}
                  </td>
                  <td className="num xs">{ps ? bytes(ps.rxBytes) : "–"}</td>
                  <td className="num xs">{ps ? bytes(ps.txBytes) : "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

type PeerDraft = { name: string; publicKey: string; presharedKey: string; endpoint: string; allowedIPs: string; persistentKeepalive: string };
const emptyPeer: PeerDraft = { name: "", publicKey: "", presharedKey: "", endpoint: "", allowedIPs: "", persistentKeepalive: "25" };

function NetworkForm({ existing, onDone }: { existing?: Network; onDone: () => void }) {
  const qc = useQueryClient();
  const [mode, setMode] = useState<"file" | "fields">(existing ? "fields" : "file");
  const [name, setName] = useState(existing?.name ?? "");
  const [conf, setConf] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [generate, setGenerate] = useState(false);
  const [addresses, setAddresses] = useState(existing?.addresses.join(", ") ?? "");
  const [dns, setDns] = useState(existing?.dns?.join(", ") ?? "");
  const [mtu, setMtu] = useState(existing?.mtu ? String(existing.mtu) : "");
  const [peers, setPeers] = useState<PeerDraft[]>(
    existing?.peers.map((p) => ({
      name: p.name ?? "",
      publicKey: p.publicKey,
      presharedKey: p.presharedKey ?? "",
      endpoint: p.endpoint ?? "",
      allowedIPs: p.allowedIPs.join(", "),
      persistentKeepalive: p.persistentKeepalive ? String(p.persistentKeepalive) : "",
    })) ?? [{ ...emptyPeer }],
  );
  const save = useMutation({
    mutationFn: () => {
      const body =
        mode === "file"
          ? { name, conf }
          : {
              name,
              privateKey: generate ? "" : privateKey,
              generateKey: generate,
              addresses: lines(addresses),
              dns: lines(dns),
              mtu: mtu ? Number(mtu) : 0,
              peers: peers.map((p) => ({
                name: p.name,
                publicKey: p.publicKey.trim(),
                presharedKey: p.presharedKey.trim(),
                endpoint: p.endpoint.trim(),
                allowedIPs: lines(p.allowedIPs),
                persistentKeepalive: p.persistentKeepalive ? Number(p.persistentKeepalive) : 0,
              })),
            };
      return existing
        ? call<Network>("PUT", `/networks/${encodeURIComponent(existing.id)}`, body)
        : call<Network>("POST", "/networks", body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["networks"] });
      onDone();
    },
  });
  const setPeer = (i: number, patch: Partial<PeerDraft>) => setPeers(peers.map((p, j) => (j === i ? { ...p, ...patch } : p)));

  return (
    <form
      className="panel runner stack"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <h2>{existing ? t("Edit {name}", { name: existing.name }) : t("Add a network")}</h2>
      <label className="field">
        <span>{t("Name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. Office or Forgejo box")} required={!existing} />
      </label>
      <div className="inline" role="radiogroup" aria-label={t("How to set it up")}>
        <button type="button" className={`btn sm ${mode === "file" ? "primary" : ""}`} aria-pressed={mode === "file"} onClick={() => setMode("file")}>
          {t("Paste a WireGuard file")}</button>
        <button type="button" className={`btn sm ${mode === "fields" ? "primary" : ""}`} aria-pressed={mode === "fields"} onClick={() => setMode("fields")}>
          {t("Enter by hand")}</button>
      </div>

      {mode === "file" ? (
        <label className="field">
          <span>{t("WireGuard file (.conf)")}</span>
          <textarea
            value={conf}
            onChange={(e) => setConf(e.target.value)}
            rows={10}
            spellCheck={false}
            className="data"
            placeholder={"[Interface]\nPrivateKey = …\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24"}
            required
          />
          <small>{t("Keys in the file are moved into the vault. PostUp, Table and similar wg-quick settings aren't needed and are ignored.")}</small>
        </label>
      ) : (
        <>
          <label className="field">
            <span>{t("Private key")}</span>
            <input
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              disabled={generate}
              type="password"
              autoComplete="off"
              placeholder={existing ? t("Leave empty to keep the current key") : t("Base64 key or a secret:// reference")}
            />
          </label>
          <label className="inline small">
            <input type="checkbox" checked={generate} onChange={(e) => setGenerate(e.target.checked)} />
            {t("Make a new key (then add the public key on the server)")}
          </label>
          <label className="field">
            <span>{t("Addresses")}</span>
            <input value={addresses} onChange={(e) => setAddresses(e.target.value)} placeholder="10.8.0.2/32" className="data" />
          </label>
          <div className="inline" style={{ alignItems: "flex-start" }}>
            <label className="field" style={{ flex: 2 }}>
              <span>{t("DNS servers (optional)")}</span>
              <input value={dns} onChange={(e) => setDns(e.target.value)} placeholder="10.8.0.1" className="data" />
            </label>
            <label className="field" style={{ flex: 1 }}>
              <span>{t("MTU")}</span>
              <input value={mtu} onChange={(e) => setMtu(e.target.value)} inputMode="numeric" placeholder="1420" />
            </label>
          </div>
          {peers.map((p, i) => (
            <fieldset key={i} className="panel stack" style={{ gap: 8, padding: 12 }}>
              <legend className="small">{t("Peer {n}", { n: i + 1 })}</legend>
              <div className="inline" style={{ alignItems: "flex-start" }}>
                <label className="field" style={{ flex: 1 }}>
                  <span>{t("Name (optional)")}</span>
                  <input value={p.name} onChange={(e) => setPeer(i, { name: e.target.value })} />
                </label>
                <label className="field" style={{ flex: 2 }}>
                  <span>{t("Public key")}</span>
                  <input value={p.publicKey} onChange={(e) => setPeer(i, { publicKey: e.target.value })} className="data" required />
                </label>
              </div>
              <div className="inline" style={{ alignItems: "flex-start" }}>
                <label className="field" style={{ flex: 2 }}>
                  <span>{t("Endpoint")}</span>
                  <input value={p.endpoint} onChange={(e) => setPeer(i, { endpoint: e.target.value })} placeholder="vpn.example.com:51820" className="data" />
                </label>
                <label className="field" style={{ flex: 1 }}>
                  <span>{t("Keepalive (seconds)")}</span>
                  <input value={p.persistentKeepalive} onChange={(e) => setPeer(i, { persistentKeepalive: e.target.value })} inputMode="numeric" />
                </label>
              </div>
              <label className="field">
                <span>{t("Allowed IPs")}</span>
                <input value={p.allowedIPs} onChange={(e) => setPeer(i, { allowedIPs: e.target.value })} placeholder="10.8.0.0/24" className="data" required />
                <small>{t("Only these addresses go through the tunnel; everything else is reached directly.")}</small>
              </label>
              <label className="field">
                <span>{t("Preshared key (optional)")}</span>
                <input
                  value={p.presharedKey}
                  onChange={(e) => setPeer(i, { presharedKey: e.target.value })}
                  type={p.presharedKey.startsWith("secret://") ? "text" : "password"}
                  autoComplete="off"
                  className="data"
                />
              </label>
              {peers.length > 1 && (
                <div>
                  <button type="button" className="btn sm quiet" onClick={() => setPeers(peers.filter((_, j) => j !== i))}>
                    {t("Remove peer")}</button>
                </div>
              )}
            </fieldset>
          ))}
          <div>
            <button type="button" className="btn sm" onClick={() => setPeers([...peers, { ...emptyPeer }])}>
              {t("Add peer")}</button>
          </div>
        </>
      )}

      <ErrorNote error={save.error} />
      <div className="inline">
        <button className="btn primary" disabled={save.isPending}>
          {existing ? t("Save") : t("Add network")}</button>
        <button type="button" className="btn quiet" onClick={onDone}>
          {t("Cancel")}</button>
      </div>
    </form>
  );
}

/**
 * The network picker in a connection's settings. It saves on change, apart
 * from the rest of the settings form.
 */
export function NetworkPicker({ instance, current }: { instance: string; current?: string }) {
  const qc = useQueryClient();
  const list = useNetworks();
  const [value, setValue] = useState(current ?? "");
  const save = useMutation({
    mutationFn: (network: string) => call<unknown>("PUT", `/instances/${encodeURIComponent(instance)}`, { network }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["instances"] });
      qc.invalidateQueries({ queryKey: ["networks"] });
    },
  });
  // Networks are for admins; others don't see the picker.
  if (list.error || !list.data) return null;
  return (
    <label className="field">
      <span>{t("Network")}</span>
      <select
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          save.mutate(e.target.value);
        }}
        disabled={save.isPending}
      >
        <option value="">{t("Direct (no network)")}</option>
        {list.data.map((n) => (
          <option key={n.id} value={n.id}>
            {n.name}
          </option>
        ))}
      </select>
      <small>
        {list.data.length === 0
          ? t("Add a WireGuard network under Networks to reach servers inside it.")
          : save.isSuccess
            ? t("Saved.")
            : t("Connections to the network's addresses go through its WireGuard tunnel.")}
      </small>
      <ErrorNote error={save.error} />
    </label>
  );
}
