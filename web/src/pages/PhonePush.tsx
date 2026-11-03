import { useMutation } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { api, ok } from "../api/client";
import { isMobileApp, openExternal } from "../lib/native";

/**
 * Notifications on the phone when Conduit isn't open, through the ntfy app
 * (no Google services needed). Part of the Remote access section.
 */
export function PhonePush() {
  const [open, setOpen] = useState(false);
  const [server, setServer] = useState("https://ntfy.sh");
  const [details, setDetails] = useState(false);
  const [svg, setSvg] = useState("");
  const setup = useMutation({
    mutationFn: () => ok(api.POST("/notify/phone", { body: { server, private: !details } })),
  });
  useEffect(() => {
    if (!setup.data) return;
    QRCode.toString(setup.data.subscribe, { type: "svg", margin: 1, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } }).then(setSvg);
  }, [setup.data]);

  if (!open) {
    return (
      <div className="spread">
        <span className="xs muted">Get approvals and alerts on your phone even when Conduit is closed.</span>
        <button className="btn sm" onClick={() => setOpen(true)}>
          Phone notifications
        </button>
      </div>
    );
  }
  if (setup.data) {
    const d = setup.data;
    return (
      <div className="pairing">
        <div className="pairing-qr" dangerouslySetInnerHTML={{ __html: svg }} aria-label="Subscription QR code" role="img" />
        <div className="stack" style={{ gap: 8 }}>
          <strong className="small">Subscribe in the ntfy app</strong>
          <p className="xs muted">
            Install ntfy from F-Droid or Google Play, then scan this code or open the link on your phone. A test message is already
            waiting there. The topic name is the only thing that protects it, so don't share it.
          </p>
          <div className="inline">
            {isMobileApp() ? (
              <button className="btn sm primary" onClick={() => openExternal(d.subscribe)}>
                Open in ntfy
              </button>
            ) : (
              <a className="btn sm" href={d.web} target="_blank" rel="noreferrer">
                Open in a browser
              </a>
            )}
            <button className="btn sm quiet" onClick={() => setOpen(false)}>
              Done
            </button>
          </div>
          <span className="xs muted data">{d.web}</span>
        </div>
      </div>
    );
  }
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        setup.mutate();
      }}
    >
      <label className="field">
        <span>ntfy server</span>
        <input className="data" value={server} onChange={(e) => setServer(e.target.value)} required />
        <small>The public ntfy.sh works; your own server keeps everything in your hands.</small>
      </label>
      <label className="check">
        <input type="checkbox" checked={details} onChange={(e) => setDetails(e.target.checked)} />
        <span>Include what needs approval in the notification. Leave off for servers you don't run: they see every message.</span>
      </label>
      {setup.error && <div className="error">{setup.error.message}</div>}
      <div className="inline">
        <button type="button" className="btn quiet" onClick={() => setOpen(false)}>
          Cancel
        </button>
        <button className="btn primary" disabled={setup.isPending}>
          Set up
        </button>
      </div>
    </form>
  );
}
