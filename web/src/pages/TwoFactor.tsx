import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { api, ok } from "../api/client";
import { t, tn } from "../i18n";
import "./pages.css";
import { ErrorNote } from "../components/ErrorNote";

/** Settings section: two-factor sign-in with an authenticator app. */
export function TwoFactorSection() {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["2fa"], queryFn: () => ok(api.GET("/me/2fa")) });
  const [step, setStep] = useState<"idle" | "password" | "scan" | "off" | "codes">("idle");
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [svg, setSvg] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["2fa"] });
  const reset = () => {
    setStep("idle");
    setPw("");
    setCode("");
  };

  const begin = useMutation({
    mutationFn: () => ok(api.POST("/me/2fa/setup", { body: { password: pw } })),
    onSuccess: (r) => {
      setSetup(r);
      setStep("scan");
      setPw("");
    },
  });
  const enable = useMutation({
    mutationFn: () => ok(api.POST("/me/2fa/enable", { body: { code } })),
    onSuccess: (r) => {
      setCodes(r.recoveryCodes);
      setSetup(null);
      reset();
      refresh();
    },
  });
  const disable = useMutation({
    mutationFn: () => ok(api.POST("/me/2fa/disable", { body: { password: pw, code } })),
    onSuccess: () => {
      reset();
      refresh();
    },
  });
  const regenerate = useMutation({
    mutationFn: () => ok(api.POST("/me/2fa/recovery-codes", { body: { password: pw, code } })),
    onSuccess: (r) => {
      setCodes(r.recoveryCodes);
      reset();
      refresh();
    },
  });
  useEffect(() => {
    if (!setup) return;
    QRCode.toString(setup.uri, { type: "svg", margin: 1, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } }).then(setSvg);
  }, [setup]);
  if (!st.data) return null;

  const confirmForm = (label: string, m: { mutate: () => void; error: Error | null; isPending: boolean }, danger: boolean) => (
    <form
      className="panel runner stack"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate();
      }}
    >
      <label className="field">
        <span>{t("Password")}</span>
        <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} required autoComplete="current-password" />
      </label>
      <label className="field">
        <span>{t("Code from your app, or a recovery code")}</span>
        <input className="data" value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="one-time-code" />
      </label>
      <ErrorNote error={m.error} />
      <div className="inline">
        <button type="button" className="btn quiet" onClick={reset}>
          {t("Cancel")}</button>
        <button className={`btn ${danger ? "danger" : "primary"}`} disabled={m.isPending}>
          {label}
        </button>
      </div>
    </form>
  );

  return (
    <section className="stack" style={{ gap: 8, maxWidth: 560 }}>
      <h2 className="section-title">{t("Two-factor sign-in")}</h2>
      <p className="small muted">
        {st.data.enabled
          ? tn("On. Signing in asks for a code from your authenticator app after your password. {n} recovery code left.", "On. Signing in asks for a code from your authenticator app after your password. {n} recovery codes left.", st.data.recoveryCodesLeft)
          : t("Ask for a code from an authenticator app (such as Aegis, 2FAS, Google Authenticator or your password manager) after your password, so a stolen password isn't enough.")}
      </p>

      {codes && (
        <div className="panel runner secret-once" role="status">
          <h2>{t("Save your recovery codes")}</h2>
          <p className="small">
            {t("Each works once, instead of a code from your app, if you lose your phone. This is the only time they're shown.")}</p>
          <pre className="data recovery-codes">{codes.join("\n")}</pre>
          <div className="inline">
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(codes.join("\n"))}>
              {t("Copy")}</button>
            <button className="btn sm quiet" onClick={() => setCodes(null)}>
              {t("I've saved them")}</button>
          </div>
        </div>
      )}

      {!st.data.enabled && step === "idle" && (
        <div>
          <button className="btn" onClick={() => setStep("password")}>
            {t("Set up two-factor sign-in")}</button>
        </div>
      )}

      {step === "password" && (
        <form
          className="panel runner stack"
          onSubmit={(e) => {
            e.preventDefault();
            begin.mutate();
          }}
        >
          <label className="field">
            <span>{t("Your password")}</span>
            <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} required autoFocus autoComplete="current-password" />
          </label>
          <ErrorNote error={begin.error} />
          <div className="inline">
            <button type="button" className="btn quiet" onClick={reset}>
              {t("Cancel")}</button>
            <button className="btn primary" disabled={begin.isPending}>
              {t("Continue")}</button>
          </div>
        </form>
      )}

      {step === "scan" && setup && (
        <form
          className="panel runner stack"
          onSubmit={(e) => {
            e.preventDefault();
            enable.mutate();
          }}
        >
          <div className="pairing">
            <div className="pairing-qr" dangerouslySetInnerHTML={{ __html: svg }} aria-label={t("QR code for your authenticator app")} role="img" />
            <div className="stack" style={{ gap: 8 }}>
              <strong className="small">{t("Scan this with your authenticator app")}</strong>
              <p className="xs muted">{t("Or type this key into it:")}</p>
              <code className="secret-value">{setup.secret}</code>
            </div>
          </div>
          <label className="field">
            <span>{t("Code the app shows now")}</span>
            <input className="data" value={code} onChange={(e) => setCode(e.target.value)} required inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
          </label>
          <ErrorNote error={enable.error} />
          <div className="inline">
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setSetup(null);
                reset();
              }}
            >
              {t("Cancel")}</button>
            <button className="btn primary" disabled={enable.isPending}>
              {t("Turn on")}</button>
          </div>
        </form>
      )}

      {st.data.enabled && step === "idle" && (
        <div className="inline">
          <button className="btn sm quiet" onClick={() => setStep("codes")}>
            {t("New recovery codes")}</button>
          <button className="btn sm danger" onClick={() => setStep("off")}>
            {t("Turn off")}</button>
        </div>
      )}
      {step === "off" && confirmForm(t("Turn off"), disable, true)}
      {step === "codes" && confirmForm(t("Make new codes"), regenerate, false)}
    </section>
  );
}
