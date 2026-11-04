// The marketplace reports queue in the operator console (/account/admin/):
// what people reported, and the four answers: dismiss, yank the version,
// delist the package, ban the author. See docs/protocol/marketplace.md.
import { api, ago, el } from "./hub";
import { l, t, tn } from "../i18n/client";
import "../styles/admin-reports.css";

export type AdminReport = {
  id: string;
  name: string;
  version?: string;
  reason: string;
  details: string;
  status: "open" | "dismissed" | "actioned";
  action?: string;
  note?: string;
  reporter: string;
  resolvedBy?: string;
  createdAt: string;
  resolvedAt?: string;
  owner: string;
  delisted: boolean;
  authorState: "ok" | "verified" | "banned";
  openReports: number;
};

function reasonLabel(r: string): string {
  const labels: Record<string, string> = {
    malware: t("Malware"),
    broken: t("Broken"),
    spam: t("Spam"),
    impersonation: t("Impersonation"),
    license: t("License"),
    other: t("Other"),
  };
  return labels[r] ?? r;
}

function actionLabel(a?: string): string {
  const labels: Record<string, string> = {
    dismiss: t("Dismissed"),
    yank: t("Version yanked"),
    delist: t("Package delisted"),
    ban: t("Author banned"),
  };
  return (a && labels[a]) || "";
}

/** Fill a container with the queue; onChange runs after every decision. */
export function reportsQueue(box: HTMLElement, onChange: () => void) {
  let status: "open" | "resolved" = "open";
  const list = el("div", { class: "rq-list" });
  const err = el("div", { class: "error" });
  err.hidden = true;
  const tabs = el("div", { class: "rq-tabs" });
  tabs.setAttribute("role", "group");
  tabs.setAttribute("aria-label", t("Show"));
  const tab = (id: "open" | "resolved", label: string) => {
    const b = el("button", { class: "btn sm", type: "button" }, label);
    b.setAttribute("aria-pressed", String(status === id));
    b.onclick = () => {
      status = id;
      for (const x of tabs.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      load();
    };
    return b;
  };
  tabs.append(tab("open", t("Open")), tab("resolved", t("Resolved")));
  box.replaceChildren(tabs, err, list);

  const fail = (e: unknown) => {
    err.textContent = e instanceof Error ? e.message : String(e);
    err.hidden = false;
  };

  async function load() {
    err.hidden = true;
    try {
      const page = await api<{ total: number; items: AdminReport[] }>("GET", `/admin/reports?status=${status}&limit=100`);
      if (!page.items.length) {
        list.replaceChildren(el("p", { class: "muted" }, status === "open" ? t("No open reports. The marketplace is quiet.") : t("Nothing resolved yet.")));
        return;
      }
      list.replaceChildren(...page.items.map(card));
    } catch (e) {
      fail(e);
    }
  }

  function card(r: AdminReport): HTMLElement {
    const href = `${l("/modules/package/")}?name=${encodeURIComponent(r.name)}`;
    const title = el(
      "p",
      { class: "rq-title" },
      el("span", { class: `rq-reason${r.reason === "malware" ? " bad" : ""}` }, reasonLabel(r.reason)),
      " ",
      el("a", { href, class: "data" }, r.name),
      r.version ? el("span", { class: "data muted" }, ` ${r.version}`) : "",
    );
    const facts: string[] = [t("by {who}", { who: r.reporter || t("a deleted account") }), ago(r.createdAt)];
    if (r.openReports > 1 && r.status === "open") facts.push(tn("{n} open report on this package", "{n} open reports on this package", r.openReports));
    if (r.delisted) facts.push(t("already delisted"));
    if (r.authorState === "banned") facts.push(t("author banned"));
    if (r.authorState === "verified") facts.push(t("verified author"));
    const c = el("div", { class: "rq-card" }, title, el("p", { class: "muted small" }, facts.join(", ")));
    if (r.details) c.append(el("p", { class: "rq-details" }, r.details));
    if (r.status !== "open") {
      c.append(el("p", { class: "small" }, `${actionLabel(r.action)}${r.resolvedBy ? ` (${r.resolvedBy}${r.resolvedAt ? `, ${ago(r.resolvedAt)}` : ""})` : ""}${r.note ? `: ${r.note}` : ""}`));
      return c;
    }
    const note = el("input", { type: "text", maxLength: 500, placeholder: t("Note for the author and for daemons (optional)") }) as HTMLInputElement;
    note.setAttribute("aria-label", t("Note"));
    const acts = el("div", { class: "rq-acts" });
    const act = (action: string, label: string, danger: boolean, confirmText?: string) => {
      const b = el("button", { class: `btn sm${danger ? " danger" : ""}`, type: "button" }, label);
      b.onclick = async () => {
        if (confirmText && !window.confirm(confirmText)) return;
        for (const x of acts.querySelectorAll("button")) (x as HTMLButtonElement).disabled = true;
        try {
          await api("POST", `/admin/reports/${encodeURIComponent(r.id)}/resolve`, { action, note: note.value.trim() });
          await load();
          onChange();
        } catch (e) {
          fail(e);
          for (const x of acts.querySelectorAll("button")) (x as HTMLButtonElement).disabled = false;
        }
      };
      return b;
    };
    acts.append(act("dismiss", t("Dismiss"), false));
    if (r.version) acts.append(act("yank", t("Yank {version}", { version: r.version }), true));
    if (!r.delisted) acts.append(act("delist", t("Delist the package"), true));
    if (r.authorState !== "banned")
      acts.append(act("ban", t("Ban {author}", { author: r.owner }), true, t("Ban {author}? All their packages leave the marketplace and they can't publish again. Their handle and key stay reserved.", { author: r.owner })));
    c.append(el("label", { class: "field rq-note" }, note), acts);
    return c;
  }

  load();
}
