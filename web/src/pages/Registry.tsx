import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "wouter";
import { api, ok } from "../api/client";
import { ago } from "../lib/format";
import { t } from "../i18n";
import "./pages.css";

type Pkg = { name: string; owner: string; description: string; latest?: string; downloads: number };

/** Modules from the linked hub's registry: browse, check, install. */
export function RegistryPage() {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const search = useQuery({ queryKey: ["registry", term], queryFn: () => ok(api.GET("/registry", { params: { query: { q: term } } })) as Promise<Pkg[]>, retry: false });
  const installed = useQuery({ queryKey: ["registry", "installed"], queryFn: () => ok(api.GET("/registry/installed", { params: { query: { check: "1" } } })) });
  const remove = useMutation({
    mutationFn: (name: string) => ok(api.DELETE("/registry/installed", { params: { query: { name } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["registry"] }),
  });

  return (
    <div className="page">
      <div className="page-head">
        <h1>{t("Modules from your hub")}</h1>
        <p>
          {t("Modules other people published, signed by their authors. They run sandboxed: no access to this computer, and only the internet addresses they list.")}{" "}<Link href="/modules">{t("Back to modules")}</Link>
        </p>
      </div>

      {(installed.data?.length ?? 0) > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <h2 className="section-title">{t("Installed")}</h2>
          <div className="panel rows">
            {installed.data!.map((m) => (
              <div className="row key-row" key={m.name}>
                <div className="stack" style={{ gap: 2 }}>
                  <strong className="data">{m.name}</strong>
                  <span className="xs muted">
                    {m.version}{t(", installed")}{" "}{ago(m.installedAt)}{t(", author key")}{" "}<span className="data">{m.fingerprint}</span>
                  </span>
                </div>
                <span className="xs muted">{m.network.length ? `Reaches ${m.network.join(", ")}` : t("No network")}</span>
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

      <form
        className="inline"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          setTerm(q);
        }}
      >
        <label className="field" style={{ minWidth: 280 }}>
          <span>{t("Search")}</span>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("weather, router, backup…")} />
        </label>
        <button className="btn" style={{ alignSelf: "end" }}>
          {t("Search")}</button>
      </form>
      {search.error && <div className="error">{(search.error as Error).message}</div>}
      {search.data?.length === 0 && <p className="muted">{term ? t("Nothing matches.") : t("Nothing is published on this hub yet.")}</p>}
      <div className="panel rows">
        {search.data?.map((p) => (
          <div key={p.name}>
            <div className="row key-row">
              <div className="stack" style={{ gap: 2 }}>
                <strong className="data">{p.name}</strong>
                <span className="small muted">{p.description}</span>
              </div>
              <span className="xs muted">{p.latest ?? "pre-release"}, {p.downloads} {t("installs")}</span>
              <span />
              <button className="btn sm" onClick={() => setOpen(open === p.name ? null : p.name)} aria-expanded={open === p.name}>
                {t("Details")}</button>
            </div>
            {open === p.name && <Install name={p.name} />}
          </div>
        ))}
      </div>
      {open && !search.data?.some((p) => p.name === open) && <Install name={open} />}
    </div>
  );
}

function Install({ name }: { name: string }) {
  const qc = useQueryClient();
  const info = useQuery({ queryKey: ["registry", "package", name], queryFn: () => ok(api.GET("/registry/package", { params: { query: { name } } })), retry: false });
  const install = useMutation({
    mutationFn: () => ok(api.POST("/registry/install", { body: { name, fingerprint: info.data!.fingerprint } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["registry"] }),
  });
  if (info.error) return <div className="error">{(info.error as Error).message}</div>;
  if (!info.data) return <p className="xs muted" style={{ padding: 12 }}>{t("Checking the signature…")}</p>;
  const d = info.data;
  return (
    <div className="stack" style={{ gap: 8, padding: "8px 12px 14px" }}>
      <p className="small">
        {t("Version")}{" "}<span className="data">{d.version}</span>{t(", signed by the author's key")}{" "}<span className="data">{d.fingerprint}</span>.
        {d.homepage && (
          <>
            {" "}
            <a href={d.homepage} target="_blank" rel="noreferrer">
              {t("Homepage")}</a>
          </>
        )}
      </p>
      <p className="small">{d.network.length ? <>{t("It may reach:")}{" "}<span className="data">{d.network.join(", ")}</span>.</> : t("It can't reach the network.")}</p>
      {!d.installable ? (
        <p className="small muted">{t("This module has no sandboxed build, so it can't be installed from here.")}</p>
      ) : install.isSuccess ? (
        <p className="small">
          {t("Installed. Set it up from")}{" "}<Link href="/modules">{t("Modules")}</Link>.
        </p>
      ) : (
        <div>
          <button className="btn primary" onClick={() => install.mutate()} disabled={install.isPending}>
            {t("Install")}</button>
        </div>
      )}
      {install.error && <div className="error">{install.error.message}</div>}
    </div>
  );
}
