import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok } from "../api/client";
import { relayProfile } from "../lib/connection";
import { ago } from "../lib/format";
import { createPasskey, passkeyError, passkeysSupported } from "../lib/passkeys";
import { t } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

/** Settings section: passkeys for signing in to this account. */
export function PasskeysSection() {
  const qc = useQueryClient();
  const relay = relayProfile();
  const avail = useQuery({ queryKey: ["passkeys", "available"], queryFn: () => ok(api.GET("/auth/passkeys/available")), enabled: !relay, retry: false });
  const usable = !relay && !!avail.data?.available && passkeysSupported();
  const list = useQuery({ queryKey: ["passkeys"], queryFn: () => ok(api.GET("/me/passkeys")) });
  const [adding, setAdding] = useState(false);
  const [pw, setPw] = useState("");
  const [name, setName] = useState("");
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["passkeys"] });

  const add = useMutation({
    mutationFn: async () => {
      const begin = await ok(api.POST("/me/passkeys/register/begin", { body: { password: pw } }));
      let response;
      try {
        response = await createPasskey(begin.options.publicKey);
      } catch (e) {
        throw new Error(passkeyError(e));
      }
      return ok(api.POST("/me/passkeys/register/finish", { body: { ceremony: begin.ceremony, name: name.trim(), response } }));
    },
    onSuccess: () => {
      setAdding(false);
      setPw("");
      setName("");
      refresh();
    },
  });
  const rename = useMutation({
    mutationFn: (r: { id: string; name: string }) => ok(api.PATCH("/me/passkeys/{id}", { params: { path: { id: r.id } }, body: { name: r.name } })),
    onSuccess: () => {
      setRenaming(null);
      refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => ok(api.DELETE("/me/passkeys/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });

  const keys = list.data ?? [];
  if (!list.data) return null;
  // Nothing to show or do: no passkeys, and none can be added here.
  if (!usable && keys.length === 0 && !avail.isLoading) {
    return (
      <section className="stack" style={{ gap: 8, maxWidth: 560 }}>
        <h2 className="section-title">{t("Passkeys")}</h2>
        <p className="small muted">
          {t("Passkeys need Conduit opened at a host name such as localhost, not an IP address like 127.0.0.1. Open it in a browser at http://localhost and its port to add one.")}
        </p>
      </section>
    );
  }

  return (
    <section className="stack" style={{ gap: 8, maxWidth: 560 }}>
      <h2 className="section-title">{t("Passkeys")}</h2>
      <p className="small muted">
        {t("Sign in with your fingerprint, face or device PIN instead of your password. A passkey counts as both factors, so it skips the code from your authenticator app. Changing your password removes all your passkeys.")}
      </p>

      {keys.length > 0 && (
        <div className="panel rows">
          {keys.map((k) => (
            <div className="row session-row" key={k.id}>
              {renaming?.id === k.id ? (
                <form
                  className="inline"
                  style={{ flex: 1 }}
                  onSubmit={(e) => {
                    e.preventDefault();
                    rename.mutate(renaming);
                  }}
                >
                  <input
                    aria-label={t("Passkey name")}
                    value={renaming.name}
                    maxLength={60}
                    onChange={(e) => setRenaming({ id: k.id, name: e.target.value })}
                    autoFocus
                    required
                  />
                  <button className="btn sm primary" disabled={rename.isPending}>
                    {t("Save")}</button>
                  <button type="button" className="btn sm quiet" onClick={() => setRenaming(null)}>
                    {t("Cancel")}</button>
                </form>
              ) : (
                <>
                  <span className="small">
                    {k.name} <span className="xs muted data">{k.rpId}</span>
                  </span>
                  <span className="xs muted">
                    {k.lastUsedAt ? t("Last used {when}", { when: ago(k.lastUsedAt) }) : t("Added {when}, not used yet", { when: ago(k.createdAt) })}
                  </span>
                  <span className="inline">
                    <button className="btn sm quiet" onClick={() => setRenaming({ id: k.id, name: k.name })}>
                      {t("Rename")}</button>
                    <button
                      className="btn sm danger"
                      disabled={remove.isPending}
                      onClick={() => {
                        if (confirm(t("Remove the passkey {name}? It stops working for signing in.", { name: k.name }))) remove.mutate(k.id);
                      }}
                    >
                      {t("Remove")}</button>
                  </span>
                </>
              )}
            </div>
          ))}
        </div>
      )}
      <ErrorNote error={rename.error} />
      <ErrorNote error={remove.error} />

      {usable && !adding && (
        <div>
          <button className="btn" onClick={() => setAdding(true)}>
            {t("Add a passkey")}</button>
        </div>
      )}
      {!usable && keys.length > 0 && (
        <p className="xs muted">{t("New passkeys can only be added when Conduit is opened at a host name such as localhost.")}</p>
      )}

      {adding && (
        <form
          className="panel runner stack"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <label className="field">
            <span>{t("Your password")}</span>
            <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} required autoFocus autoComplete="current-password" />
          </label>
          <label className="field">
            <span>{t("Passkey name")}</span>
            <input value={name} maxLength={60} onChange={(e) => setName(e.target.value)} placeholder={t("For example: Laptop")} />
          </label>
          <ErrorNote error={add.error} />
          <div className="inline">
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setAdding(false);
                setPw("");
              }}
            >
              {t("Cancel")}</button>
            <button className="btn primary" disabled={add.isPending}>
              {t("Continue")}</button>
          </div>
        </form>
      )}
    </section>
  );
}
