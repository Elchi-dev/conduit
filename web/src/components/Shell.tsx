import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation } from "wouter";
import { api, ok, type S } from "../api/client";
import { useLiveEvents } from "../lib/events";
import { featureInstances } from "../lib/format";
import { onShell, setAttention } from "../lib/native";
import { Assistant } from "./Assistant";
import { CommandBar } from "./CommandBar";
import { LampStrip } from "./LampStrip";
import "./shell.css";

type Me = { user: S["User"]; actor: S["Actor"]; scopes: string[] };

const nav = [
  { href: "/", label: "Overview" },
  { href: "/approvals", label: "Approvals" },
  { href: "/timeline", label: "Timeline" },
  { href: "/automations", label: "Automations" },
  { href: "/i/brief", label: "Daily brief" },
  { href: "/modules", label: "Modules" },
];
const navAdmin = [
  { href: "/policy", label: "Agent rules" },
  { href: "/assistant", label: "Assistant and agents" },
  { href: "/keys", label: "API keys" },
  { href: "/settings", label: "Settings" },
];

export function Shell({ me, children }: { me: Me; children: ReactNode }) {
  const [loc, setLocation] = useLocation();
  const [cmdOpen, setCmdOpen] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [seed, setSeed] = useState<string | undefined>();
  const { connected } = useLiveEvents(true);
  const qc = useQueryClient();

  const pending = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => ok(api.GET("/approvals", { params: { query: { status: "pending" } } })),
    refetchInterval: 30_000,
  });
  const policy = useQuery({ queryKey: ["policy"], queryFn: () => ok(api.GET("/policy")) });
  const all = useQuery({ queryKey: ["instances"], queryFn: () => ok(api.GET("/instances")) });
  const instances = { data: all.data?.filter((i) => !featureInstances.has(i.id)) };

  const stop = useMutation({
    mutationFn: () => ok(api.POST("/panic")),
    onSuccess: () => qc.invalidateQueries(),
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const frozen = policy.data?.frozen;
  const waiting = pending.data?.length ?? 0;

  // Native shell: light the tray, and follow its menu.
  useEffect(() => setAttention(waiting, !!frozen), [waiting, frozen]);
  const panic = stop.mutate;
  useEffect(() => {
    const offNav = onShell<string>("conduit://navigate", (path) => setLocation(path));
    const offPanic = onShell("conduit://panic", () => panic());
    return () => {
      offNav();
      offPanic();
    };
  }, [setLocation, panic]);

  return (
    <div className={`shell ${assistantOpen ? "with-assistant" : ""}`}>
      <header className="bar">
        <Link href="/" className="brand" aria-label="Conduit overview">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M6 10h20M6 16h13M6 22h20" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
          </svg>
          <span>Conduit</span>
        </Link>
        <LampStrip instances={instances.data ?? []} />
        <div className="bar-end">
          <button className={`btn quiet assistant-toggle ${assistantOpen ? "on" : ""}`} onClick={() => setAssistantOpen(!assistantOpen)} aria-expanded={assistantOpen}>
            Assistant
          </button>
          <button className="btn quiet cmd-trigger" onClick={() => setCmdOpen(true)}>
            Search and run
            <kbd>{navigator.platform.includes("Mac") ? "⌘K" : "Ctrl K"}</kbd>
          </button>
          {frozen ? (
            <Link href="/policy" className="btn danger">
              Emergency stop is on
            </Link>
          ) : (
            <button
              className="btn danger"
              onClick={() => {
                if (confirm("Emergency stop freezes every agent, key and automation, denies all pending approvals and revokes agent keys. Continue?"))
                  stop.mutate();
              }}
              disabled={stop.isPending}
            >
              Emergency stop
            </button>
          )}
        </div>
      </header>

      <nav className="rail" aria-label="Main">
        <ul>
          {nav.map((n) => (
            <li key={n.href}>
              <Link href={n.href} className={loc === n.href ? "active" : undefined}>
                {n.label}
                {n.href === "/approvals" && waiting > 0 && <span className="count">{waiting}</span>}
              </Link>
            </li>
          ))}
        </ul>
        {(instances.data?.length ?? 0) > 0 && (
          <>
            <p className="rail-head">Connected</p>
            <ul>
              {instances.data!.map((i) => (
                <li key={i.id}>
                  <Link href={`/i/${i.id}`} className={loc === `/i/${i.id}` ? "active" : undefined}>
                    {i.name}
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
        <ul className="rail-foot">
          {navAdmin.map((n) => (
            <li key={n.href}>
              <Link href={n.href} className={loc === n.href ? "active" : undefined}>
                {n.label}
              </Link>
            </li>
          ))}
        </ul>
        <p className="rail-who xs muted">
          {me.user.name}
          <span className={connected ? "live on" : "live"} title={connected ? "Live updates connected" : "Reconnecting"} />
        </p>
      </nav>

      <main className="main">
        {frozen && (
          <div className="frozen-banner" role="status">
            Emergency stop is on. Agents, API keys and automations are frozen; you can still act yourself.{" "}
            <Link href="/policy">Review and lift it</Link>
          </div>
        )}
        {stop.error && <div className="error">{String(stop.error.message)}</div>}
        {children}
      </main>

      <CommandBar
        open={cmdOpen}
        onOpenChange={setCmdOpen}
        instances={instances.data ?? []}
        onAsk={(q) => {
          setSeed(q);
          setAssistantOpen(true);
        }}
      />
      <Assistant open={assistantOpen} onClose={() => setAssistantOpen(false)} seed={seed} onSeedUsed={() => setSeed(undefined)} />
    </div>
  );
}
