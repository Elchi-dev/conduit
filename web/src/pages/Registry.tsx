import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { Link } from "wouter";
import { api, ok, type S } from "../api/client";
import { Markdown } from "../components/Markdown";
import { ago } from "../lib/format";
import { t, tn } from "../i18n";
import "./pages.css";
import "./registry.css";

type Advisory = S["RegistryAdvisory"];
type Installed = S["InstalledModule"];
type Review = S["RegistryReview"];
type Reason = "malware" | "broken" | "spam" | "impersonation" | "license" | "other";
type Sort = "relevance" | "installs" | "rating" | "newest" | "updated";

/** Category names by id; the hub's labels are English. */
function categoryLabel(id: string): string {
  const labels: Record<string, string> = {
    home: t("Home and IoT"),
    servers: t("Servers and infrastructure"),
    dev: t("Developer tools"),
    monitoring: t("Monitoring"),
    communication: t("Mail and chat"),
    media: t("Media"),
    games: t("Games"),
    productivity: t("Productivity"),
    finance: t("Finance"),
    security: t("Security"),
    ai: t("AI and agents"),
    data: t("Data and storage"),
    other: t("Other"),
  };
  return labels[id] ?? id;
}

/** What a report is about, as the person picks it. */
function reasonLabel(r: string): string {
  const labels: Record<string, string> = {
    malware: t("Malware: it does something harmful"),
    broken: t("Broken: it doesn't work"),
    spam: t("Spam or a misleading listing"),
    impersonation: t("Impersonation: it pretends to be someone else's"),
    license: t("A license or copyright problem"),
    other: t("Something else"),
  };
  return labels[r] ?? r;
}

/** The short reason in a warning: "removed from the marketplace: malware". */
function reasonWord(r?: string): string {
  const words: Record<string, string> = {
    malware: t("malware"),
    broken: t("broken"),
    spam: t("spam"),
    impersonation: t("impersonation"),
    license: t("license problem"),
    other: t("other"),
  };
  return (r && words[r]) || t("no reason given");
}

const reasons: Reason[] = ["malware", "broken", "spam", "impersonation", "license", "other"];

/** Modules from the linked hub's marketplace: browse, check, install, rate. */
export function RegistryPage() {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [category, setCategory] = useState("");
  const [sort, setSort] = useState<Sort>("relevance");
  const [open, setOpen] = useState<string | null>(null);
  const search = useQuery({
    queryKey: ["registry", "search", term, category, sort],
    queryFn: () => ok(api.GET("/registry", { params: { query: { q: term || undefined, category: category || undefined, sort } } })),
    retry: false,
  });
  const cats = useQuery({ queryKey: ["registry", "categories"], queryFn: () => ok(api.GET("/registry/categories")), retry: false });
  const installed = useQuery({ queryKey: ["registry", "installed"], queryFn: () => ok(api.GET("/registry/installed", { params: { query: { check: "1" } } })) });
  const remove = useMutation({
    mutationFn: (name: string) => ok(api.DELETE("/registry/installed", { params: { query: { name } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["registry"] }),
  });
  const flagged = installed.data?.filter((m) => m.advisory) ?? [];

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Modules from your hub")}</h1>
        <p>
          {t("Modules other people published, signed by their authors. They run sandboxed: no access to this computer, and only the internet addresses they list.")}{" "}<Link href="/modules">{t("Back to modules")}</Link>
        </p>
      </div>

      {flagged.length > 0 && (
        <div className="stack" style={{ gap: 8 }} role="alert">
          {flagged.map((m) => (
            <AdvisoryNotice key={m.name} m={m} onRemove={() => remove.mutate(m.name)} onUpdate={() => setOpen(m.name)} removing={remove.isPending} />
          ))}
        </div>
      )}

      {(installed.data?.length ?? 0) > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <h2 className="section-title">{t("Installed")}</h2>
          <div className="panel rows">
            {installed.data!.map((m) => (
              <div className="row key-row" key={m.name}>
                <div className="stack" style={{ gap: 2 }}>
                  <strong className="data">
                    {m.name}
                    {m.advisory && <span className={`tag ${m.advisory.reason === "malware" ? "destructive" : "warn"} reg-flag`}>{t("Flagged")}</span>}
                  </strong>
                  <span className="xs muted">
                    {m.version}{t(", installed")}{" "}{ago(m.installedAt)}{t(", author key")}{" "}<span className="data">{m.fingerprint}</span>
                  </span>
                </div>
                <span className="xs muted">{m.network.length ? t("Reaches {hosts}", { hosts: m.network.join(", ") }) : t("No network")}</span>
                {m.latest && m.latest !== m.version ? (
                  <button className="btn sm" onClick={() => setOpen(m.name)}>
                    {t("Update to")}{" "}{m.latest}
                  </button>
                ) : (
                  <span />
                )}
                <button className="btn sm danger" onClick={() => remove.mutate(m.name)}>
                  {t("Remove")}</button>
              </div>
            ))}
          </div>
          {remove.error && <div className="error">{remove.error.message}</div>}
        </section>
      )}

      <section className="stack" style={{ gap: 12 }}>
        <h2 className="section-title">{t("Browse")}</h2>
        <form
          className="reg-controls"
          role="search"
          onSubmit={(e) => {
            e.preventDefault();
            setTerm(q.trim());
          }}
        >
          <label className="field reg-search">
            <span>{t("Search")}</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("weather, router, backup…")} />
          </label>
          <button className="btn">{t("Search")}</button>
          <label className="field">
            <span>{t("Sort by")}</span>
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="relevance">{t("Best match")}</option>
              <option value="installs">{t("Most installed")}</option>
              <option value="rating">{t("Highest rated")}</option>
              <option value="newest">{t("Newest")}</option>
              <option value="updated">{t("Recently updated")}</option>
            </select>
          </label>
        </form>
        {cats.data && (
          <div className="reg-cats" role="group" aria-label={t("Categories")}>
            <button type="button" className="reg-cat" aria-pressed={category === ""} onClick={() => setCategory("")}>
              {t("All")}
            </button>
            {cats.data
              .filter((c) => (c.count ?? 0) > 0 || c.id === category)
              .map((c) => (
                <button type="button" key={c.id} className="reg-cat" aria-pressed={category === c.id} onClick={() => setCategory(category === c.id ? "" : c.id!)}>
                  {categoryLabel(c.id!)} <span className="muted">{c.count}</span>
                </button>
              ))}
          </div>
        )}
        {search.error && <div className="error">{(search.error as Error).message}</div>}
        {search.data?.length === 0 && <p className="muted">{term || category ? t("Nothing matches.") : t("Nothing is published on this hub yet.")}</p>}
        <div className="panel rows">
          {search.data?.map((p) => (
            <div key={p.name}>
              <div className="row reg-row">
                <Icon id={p.icon} name={p.name} />
                <div className="stack" style={{ gap: 2, minWidth: 0 }}>
                  <span className="inline" style={{ gap: 6 }}>
                    <strong className="data">{p.name}</strong>
                    {p.verified && <Verified />}
                  </span>
                  <span className="small muted">{p.description}</span>
                </div>
                <div className="reg-meta xs muted">
                  <Stars value={p.rating ?? 0} count={p.ratingCount ?? 0} />
                  <span>{tn("{n} install", "{n} installs", p.installs ?? 0)}</span>
                  <span>{p.latest ?? t("pre-release")}</span>
                </div>
                <button className="btn sm" onClick={() => setOpen(open === p.name ? null : p.name)} aria-expanded={open === p.name}>
                  {t("Details")}</button>
              </div>
              {open === p.name && <Details name={p.name} installedVersion={installed.data?.find((m) => m.name === p.name)?.version} />}
            </div>
          ))}
        </div>
        {open && !search.data?.some((p) => p.name === open) && (
          <div className="panel">
            <Details name={open} installedVersion={installed.data?.find((m) => m.name === open)?.version} />
          </div>
        )}
      </section>
    </div>
  );
}

function AdvisoryNotice({ m, onRemove, onUpdate, removing }: { m: Installed; onRemove: () => void; onUpdate: () => void; removing: boolean }) {
  const a = m.advisory as Advisory;
  const malware = a.reason === "malware";
  let what: string;
  if (a.status === "delisted") what = t("{name} was removed from the marketplace: {reason}.", { name: m.name, reason: reasonWord(a.reason) });
  else if (a.status === "yanked" && a.by === "operator") what = t("{name} {version} was withdrawn by the hub's operators: {reason}.", { name: m.name, version: m.version, reason: reasonWord(a.reason) });
  else if (a.status === "yanked") what = t("The author of {name} withdrew version {version}.", { name: m.name, version: m.version });
  else what = t("{name} is no longer on this hub.", { name: m.name });
  return (
    <div className={`panel reg-advisory${malware ? " danger" : ""}`}>
      <div className="stack" style={{ gap: 4 }}>
        <strong>{what}</strong>
        {a.note && <span className="small">“{a.note}”</span>}
        <span className="small muted">
          {malware
            ? t("Remove it now. It ran sandboxed, so it could only reach the addresses it listed, but treat any secrets you gave it as exposed and change them.")
            : t("It keeps running until you remove it. Removing it also deletes its connections.")}
        </span>
      </div>
      <div className="inline">
        {a.status === "yanked" && a.latest && a.latest !== m.version && !malware && (
          <button className="btn sm" onClick={onUpdate}>
            {t("Update to")}{" "}{a.latest}
          </button>
        )}
        <button className={`btn sm ${malware ? "danger" : ""}`} onClick={onRemove} disabled={removing}>
          {t("Remove {name}", { name: m.name })}
        </button>
      </div>
    </div>
  );
}

function Icon({ id, name }: { id?: string; name: string }) {
  const [failed, setFailed] = useState(false);
  const letter = (name.split("/")[1] ?? name).charAt(0).toUpperCase();
  if (!id || failed) {
    return (
      <span className="reg-icon placeholder" aria-hidden="true">
        {letter}
      </span>
    );
  }
  return <img className="reg-icon" src={`/api/v1/registry/media/${id}`} alt="" width={40} height={40} onError={() => setFailed(true)} />;
}

function Verified() {
  return (
    <span className="reg-verified" title={t("The hub's operators verified this author")}>
      <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
        <path d="M8 1.5 9.6 3l2.2-.2.5 2.1 1.9 1.1-.9 2 .9 2-1.9 1.1-.5 2.1-2.2-.2L8 14.5 6.4 13l-2.2.2-.5-2.1L1.8 10l.9-2-.9-2 1.9-1.1.5-2.1 2.2.2Z" fill="currentColor" />
        <path d="m5.4 8.2 1.8 1.7 3.5-3.6" stroke="var(--panel)" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {t("Verified")}
    </span>
  );
}

/** Five stars, filled to the average. */
function Stars({ value, count }: { value: number; count?: number }) {
  const label = count ? t("Rated {rating} out of 5 by {count}", { rating: value.toFixed(1), count }) : t("Not rated yet");
  return (
    <span className="reg-stars" title={label}>
      <span className="visually-hidden">{label}</span>
      <span aria-hidden="true" className="reg-stars-track">
        ★★★★★
        <span className="reg-stars-fill" style={{ width: `${(Math.max(0, Math.min(5, value)) / 5) * 100}%` }}>
          ★★★★★
        </span>
      </span>
      {count !== undefined && <span aria-hidden="true">{count ? value.toFixed(1) : "–"}</span>}
    </span>
  );
}

function Details({ name, installedVersion }: { name: string; installedVersion?: string }) {
  const qc = useQueryClient();
  const [reporting, setReporting] = useState(false);
  const info = useQuery({ queryKey: ["registry", "package", name], queryFn: () => ok(api.GET("/registry/package", { params: { query: { name } } })), retry: false });
  const install = useMutation({
    mutationFn: () => ok(api.POST("/registry/install", { body: { name, fingerprint: info.data!.fingerprint } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["registry"] }),
  });
  if (info.error) return <div className="error reg-detail">{(info.error as Error).message}</div>;
  if (!info.data) return <p className="xs muted" style={{ padding: 12 }}>{t("Checking the signature…")}</p>;
  const d = info.data;
  const l = d.listing;
  return (
    <div className="reg-detail stack">
      <div className="reg-facts">
        <p className="small">
          {t("Version")}{" "}<span className="data">{d.version}</span>{t(", signed by the author's key")}{" "}<span className="data">{d.fingerprint}</span>.
        </p>
        <p className="small">{d.network.length ? <>{t("It may reach:")}{" "}<span className="data">{d.network.join(", ")}</span>.</> : t("It can't reach the network.")}</p>
        <div className="inline small">
          {l?.license && <span className="tag">{l.license}</span>}
          {l?.categories?.map((c) => (
            <span className="tag" key={c}>
              {categoryLabel(c)}
            </span>
          ))}
          {l?.tags?.map((tag) => (
            <span className="tag read" key={tag}>
              #{tag}
            </span>
          ))}
          {d.homepage?.startsWith("https://") && (
            <a href={d.homepage} target="_blank" rel="noopener noreferrer">
              {t("Homepage")}</a>
          )}
          {l?.source && (
            <a href={l.source} target="_blank" rel="noopener noreferrer">
              {t("Source code")}</a>
          )}
        </div>
      </div>
      <div className="inline">
        {!d.installable ? (
          <p className="small muted">{t("This module has no sandboxed build, so it can't be installed from here.")}</p>
        ) : install.isSuccess ? (
          <p className="small">
            {t("Installed. Set it up from")}{" "}<Link href="/modules">{t("Modules")}</Link>.
          </p>
        ) : installedVersion === d.version ? (
          <p className="small muted">{t("This version is installed.")}</p>
        ) : (
          <button className="btn primary" onClick={() => install.mutate()} disabled={install.isPending}>
            {installedVersion ? t("Update to {version}", { version: d.version }) : t("Install")}
          </button>
        )}
        <button className="btn sm quiet" onClick={() => setReporting(true)}>
          {t("Report")}</button>
      </div>
      {install.error && <div className="error">{install.error.message}</div>}

      {l?.screenshots && l.screenshots.length > 0 && (
        <div className="reg-shots">
          {l.screenshots.map((s) => (
            <figure key={s.id}>
              <img src={`/api/v1/registry/media/${s.id}`} alt={s.caption || t("Screenshot")} loading="lazy" />
              {s.caption && <figcaption className="xs muted">{s.caption}</figcaption>}
            </figure>
          ))}
        </div>
      )}
      {l?.readme ? <Markdown source={l.readme} className="md reg-readme" /> : <p className="small muted">{d.description}</p>}
      <Reviews name={name} version={installedVersion} />
      {reporting && <ReportDialog name={name} version={d.version} onClose={() => setReporting(false)} />}
    </div>
  );
}

function Reviews({ name, version }: { name: string; version?: string }) {
  const r = useQuery({ queryKey: ["registry", "reviews", name], queryFn: () => ok(api.GET("/registry/reviews", { params: { query: { name } } })), retry: false });
  if (r.error) return <div className="error">{(r.error as Error).message}</div>;
  if (!r.data) return null;
  const d = r.data;
  const max = Math.max(1, ...d.histogram);
  return (
    <section className="reg-reviews stack" aria-label={t("Ratings and reviews")}>
      <h3 className="section-title">{t("Ratings and reviews")}</h3>
      <div className="reg-summary">
        <div className="reg-average">
          <span className="reg-average-num">{d.count ? d.average.toFixed(1) : "–"}</span>
          <Stars value={d.average} />
          <span className="xs muted">{tn("{n} rating", "{n} ratings", d.count)}</span>
        </div>
        <div className="reg-hist" aria-hidden="true">
          {[5, 4, 3, 2, 1].map((s) => (
            <div key={s} className="reg-hist-row">
              <span className="xs muted">{s}</span>
              <span className="reg-hist-bar">
                <span style={{ width: `${(d.histogram[s - 1] / max) * 100}%` }} />
              </span>
            </div>
          ))}
        </div>
      </div>
      {d.canReview ? (
        <MyReview name={name} version={version} mine={(d.mine as Review | null) ?? null} />
      ) : (
        <p className="small muted">{t("Pair this daemon with an account on its hub to rate and review modules.")}</p>
      )}
      {d.items.length > 0 && (
        <ul className="reg-review-list">
          {d.items
            .filter((x) => x.body)
            .map((x) => (
              <li key={x.id}>
                <div className="inline" style={{ gap: 8 }}>
                  <Stars value={x.rating} />
                  <strong className="small">{x.author || t("Someone")}</strong>
                  <span className="xs muted">
                    {ago(x.updatedAt)}
                    {x.version ? `, ${x.version}` : ""}
                  </span>
                </div>
                <p className="small reg-review-body">{x.body}</p>
                {x.reply && (
                  <div className="reg-reply small">
                    <span className="xs muted">{t("The author replied")}</span>
                    <p className="reg-review-body">{x.reply}</p>
                  </div>
                )}
              </li>
            ))}
        </ul>
      )}
    </section>
  );
}

function MyReview({ name, version, mine }: { name: string; version?: string; mine: Review | null }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(!mine);
  const [rating, setRating] = useState(mine?.rating ?? 0);
  const [body, setBody] = useState(mine?.body ?? "");
  const groupId = useId();
  useEffect(() => {
    setRating(mine?.rating ?? 0);
    setBody(mine?.body ?? "");
  }, [mine?.rating, mine?.body]);
  const save = useMutation({
    mutationFn: () => ok(api.PUT("/registry/reviews", { body: { name, rating, body, version } })),
    onSuccess: () => {
      setEditing(false);
      qc.invalidateQueries({ queryKey: ["registry", "reviews", name] });
    },
  });
  const withdraw = useMutation({
    mutationFn: () => ok(api.DELETE("/registry/reviews", { params: { query: { name } } })),
    onSuccess: () => {
      setRating(0);
      setBody("");
      setEditing(true);
      qc.invalidateQueries({ queryKey: ["registry", "reviews", name] });
    },
  });
  if (mine && !editing) {
    return (
      <div className="reg-mine inline">
        <span className="small">{t("Your rating")}</span>
        <Stars value={mine.rating} />
        <button className="btn sm quiet" onClick={() => setEditing(true)}>
          {t("Edit")}</button>
        <button className="btn sm quiet" onClick={() => withdraw.mutate()} disabled={withdraw.isPending}>
          {t("Withdraw")}</button>
        {withdraw.error && <div className="error">{withdraw.error.message}</div>}
      </div>
    );
  }
  return (
    <form
      className="reg-mine stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (rating) save.mutate();
      }}
    >
      <fieldset className="reg-rate">
        <legend className="small" id={groupId}>
          {mine ? t("Change your rating") : t("Rate this module")}
        </legend>
        {[1, 2, 3, 4, 5].map((n) => (
          <label key={n} className={n <= rating ? "on" : ""}>
            <input type="radio" name={groupId} value={n} checked={rating === n} onChange={() => setRating(n)} />
            <span aria-hidden="true">★</span>
            <span className="visually-hidden">{tn("{n} star", "{n} stars", n)}</span>
          </label>
        ))}
      </fieldset>
      <label className="field">
        <span>{t("Review (optional)")}</span>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} maxLength={2000} rows={3} placeholder={t("What worked, what didn't, what you use it for")} />
        <small>{t("Shown with your account's name on this hub.")}</small>
      </label>
      {save.error && <div className="error">{save.error.message}</div>}
      <div className="inline">
        <button className="btn primary sm" disabled={!rating || save.isPending}>
          {mine ? t("Save rating") : t("Post rating")}
        </button>
        {mine && (
          <button type="button" className="btn sm quiet" onClick={() => setEditing(false)}>
            {t("Cancel")}</button>
        )}
      </div>
    </form>
  );
}

function ReportDialog({ name, version, onClose }: { name: string; version: string; onClose: () => void }) {
  const [reason, setReason] = useState<Reason | "">("");
  const [details, setDetails] = useState("");
  const [whole, setWhole] = useState(false);
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => {
    first.current?.focus();
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose]);
  const send = useMutation({
    mutationFn: () => ok(api.POST("/registry/reports", { body: { name, version: whole ? undefined : version, reason: reason as Reason, details } })),
  });
  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div className="dialog panel" role="dialog" aria-modal="true" aria-labelledby="report-title" onClick={(e) => e.stopPropagation()}>
        {send.isSuccess ? (
          <div className="stack">
            <h2 id="report-title">{t("Thanks, it's reported")}</h2>
            <p className="small">{t("The hub's operators look at every report. If they remove the module, every daemon that has it is told, this one included.")}</p>
            <div className="inline" style={{ justifyContent: "flex-end" }}>
              <button className="btn primary" onClick={onClose}>
                {t("Done")}</button>
            </div>
          </div>
        ) : (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              if (reason) send.mutate();
            }}
          >
            <h2 id="report-title">{t("Report {name}", { name })}</h2>
            <p className="small muted">{t("Your report goes to the people who run this hub, with your account's email address. The author doesn't see who reported.")}</p>
            <fieldset className="reg-reasons">
              <legend className="small">{t("What's wrong?")}</legend>
              {reasons.map((r, i) => (
                <label key={r} className="check">
                  <input ref={i === 0 ? first : undefined} type="radio" name="reason" value={r} checked={reason === r} onChange={() => setReason(r)} />
                  {reasonLabel(r)}
                </label>
              ))}
            </fieldset>
            <label className="check">
              <input type="checkbox" checked={whole} onChange={(e) => setWhole(e.target.checked)} />
              {t("It's about every version, not just {version}", { version })}
            </label>
            <label className="field">
              <span>{reason === "other" ? t("Details") : t("Details (optional)")}</span>
              <textarea value={details} onChange={(e) => setDetails(e.target.value)} maxLength={2000} rows={4} required={reason === "other"} placeholder={t("What did you see? Links and steps help.")} />
            </label>
            {send.error && <div className="error">{send.error.message}</div>}
            <div className="inline" style={{ justifyContent: "flex-end" }}>
              <button type="button" className="btn quiet" onClick={onClose}>
                {t("Cancel")}</button>
              <button className="btn danger" disabled={!reason || send.isPending}>
                {t("Send report")}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
