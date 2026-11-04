import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ok } from "../../api/client";
import { t, tn } from "../../i18n";
import { ErrorNote } from "../../components/ErrorNote";

/** Set up, unlock or lock the vault. Shown above the vault's actions. */
export function VaultGate() {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["vault"], queryFn: () => ok(api.GET("/vault")) });
  const [pass, setPass] = useState("");
  const [confirmPass, setConfirm] = useState("");
  const [remember, setRemember] = useState(true);
  const done = () => {
    setPass("");
    setConfirm("");
    qc.invalidateQueries({ queryKey: ["vault"] });
    qc.invalidateQueries({ queryKey: ["instances"] });
  };
  const setup = useMutation({ mutationFn: () => ok(api.POST("/vault/setup", { body: { passphrase: pass } })), onSuccess: done });
  const unlock = useMutation({ mutationFn: () => ok(api.POST("/vault/unlock", { body: { passphrase: pass, remember } })), onSuccess: done });
  const lock = useMutation({ mutationFn: (forget: boolean) => ok(api.POST("/vault/lock", { body: { forget } })), onSuccess: done });

  if (!st.data) return null;
  const s = st.data;

  if (!s.setUp) {
    return (
      <form
        className="panel runner"
        onSubmit={(e) => {
          e.preventDefault();
          if (pass === confirmPass) setup.mutate();
        }}
      >
        <h2>{t("Choose a vault passphrase")}</h2>
        <p className="small muted">
          {t("Secrets are encrypted with a key that only this passphrase can open. Conduit can't recover it for you, so write it down somewhere safe.")}</p>
        <div className="rule-grid">
          <label className="field">
            <span>{t("Passphrase")}</span>
            <input type="password" minLength={12} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" required />
            <small>{t("At least 12 characters. A few random words work well.")}</small>
          </label>
          <label className="field">
            <span>{t("Type it again")}</span>
            <input type="password" value={confirmPass} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
            {confirmPass && pass !== confirmPass && <small style={{ color: "var(--fault)" }}>{t("Doesn't match yet.")}</small>}
          </label>
        </div>
        <ErrorNote error={setup.error} />
        <div>
          <button className="btn primary" disabled={setup.isPending || pass !== confirmPass}>
            {t("Create vault")}</button>
        </div>
      </form>
    );
  }

  if (!s.unlocked) {
    return (
      <form
        className="panel runner secret-once"
        onSubmit={(e) => {
          e.preventDefault();
          unlock.mutate();
        }}
      >
        <h2>{t("The vault is locked")}</h2>
        <p className="small muted">{t("Modules can't use their passwords and tokens until you unlock it.")}</p>
        <label className="field" style={{ maxWidth: 380 }}>
          <span>{t("Passphrase")}</span>
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="current-password" required />
        </label>
        <label className="check">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          {t("Unlock automatically on this computer (uses the system keychain)")}</label>
        <ErrorNote error={unlock.error} />
        <div>
          <button className="btn signal" disabled={unlock.isPending}>
            {t("Unlock")}</button>
        </div>
      </form>
    );
  }

  return (
    <div className="spread panel runner" style={{ padding: "12px 16px" }}>
      <span className="small">
        {s.remembered
          ? tn("Unlocked, {n} secret. Unlocks automatically on this computer.", "Unlocked, {n} secrets. Unlocks automatically on this computer.", s.secrets)
          : tn("Unlocked, {n} secret.", "Unlocked, {n} secrets.", s.secrets)}
      </span>
      <div className="inline">
        {s.remembered && (
          <button className="btn sm quiet" onClick={() => lock.mutate(true)}>
            {t("Forget on this computer")}</button>
        )}
        <button className="btn sm" onClick={() => lock.mutate(false)}>
          {t("Lock now")}</button>
      </div>
    </div>
  );
}
