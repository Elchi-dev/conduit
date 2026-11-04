// One way to show a failure: what went wrong (the daemon's message, as it
// sent it) and what to do next, chosen by the kind of failure.
import type { CSSProperties } from "react";
import { ApiError } from "../api/client";
import { t } from "../i18n";

/** The next step for a failure, or "" when the message already is one. */
export function nextStep(e: unknown): string {
  if (e instanceof ApiError) {
    const s = e.status;
    if (s === 400 || s === 422) return t("Check what you entered, then try again.");
    if (s === 401) return t("Your session ended. Sign in again to continue.");
    if (s === 403) return t("Your account isn't allowed to do this. Ask the owner or an admin.");
    if (s === 404) return t("It may have been removed. Reload the page to see what's there now.");
    if (s === 409) return t("Something changed in the meantime. Reload the page, then try again.");
    if (s === 429) return t("Wait a minute, then try again.");
    if (s === 502 || s === 503 || s === 504) return t("The service on the other end didn't answer properly. Check that it's running, then try again.");
    if (s >= 500) return t("Try again. If it keeps happening, check the daemon's log.");
    return "";
  }
  if (e instanceof TypeError) return t("Conduit didn't answer. Check that the daemon is running and this device is online, then try again.");
  return t("Try again. If it keeps happening, reload the page.");
}

/** "couldn't reach the hub" reads as "Couldn't reach the hub." */
export function sentence(s: string): string {
  const v = s.trim();
  if (!v) return v;
  const c = v.charAt(0).toUpperCase() + v.slice(1);
  return /[.!?:)]$/.test(c) ? c : c + ".";
}

function message(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  return String(e ?? "");
}

export function ErrorNote({ error, retry, style }: { error: unknown; retry?: () => void; style?: CSSProperties }) {
  if (!error) return null;
  const msg = sentence(message(error)) || t("Something went wrong.");
  const step = nextStep(error);
  // A message that already ends with advice doesn't need a second one.
  const advised = /try again|sign in|reload|check |ask /i.test(msg);
  return (
    <div className="error" role="alert" style={style}>
      <span>
        {msg}
        {step && !advised && <> {step}</>}
      </span>
      {retry && (
        <>
          {" "}
          <button type="button" className="btn sm" onClick={retry} style={{ marginLeft: 6 }}>
            {t("Try again")}
          </button>
        </>
      )}
    </div>
  );
}
