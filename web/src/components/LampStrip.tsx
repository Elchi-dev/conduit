import { useQueries } from "@tanstack/react-query";
import { Link } from "wouter";
import { api, ok, type Instance } from "../api/client";
import { t } from "../i18n";

/**
 * One indicator lamp per connected instance, lit by its live health. This is
 * the signature element of the interface: the whole system at a glance.
 */
export function LampStrip({ instances }: { instances: Instance[] }) {
  const health = useQueries({
    queries: instances.map((i) => ({
      queryKey: ["instances", i.id, "health"],
      queryFn: () => ok(api.GET("/instances/{id}/health", { params: { path: { id: i.id } } })),
      refetchInterval: 30_000,
      enabled: i.enabled,
    })),
  });

  if (instances.length === 0) {
    return (
      <div className="lamps lamps-empty">
        <Link href="/modules" className="xs muted">
          {t("Nothing connected yet. Add a module to light the panel.")}</Link>
      </div>
    );
  }

  return (
    <ul className="lamps" aria-label={t("Connected systems")}>
      {instances.map((i, n) => {
        const h = health[n]?.data;
        const state = !i.enabled ? "off" : (h?.status ?? "pending");
        const label = `${i.name}: ${!i.enabled ? "disabled" : (h?.status ?? "checking")}${h?.message ? ` — ${h.message}` : ""}`;
        return (
          <li key={i.id}>
            <Link href={`/i/${i.id}`} className={`lamp ${state}`} aria-label={label} title={label}>
              <span className="bulb" />
              <span className="lamp-name">{i.name}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
