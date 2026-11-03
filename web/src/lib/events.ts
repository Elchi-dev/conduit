import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { isRelay } from "./connection";
import { notify } from "./native";

export type LiveEvent = { type: string; module: string; instance?: string; data?: unknown; at: string };

/**
 * Subscribes to the daemon's event stream and refreshes the affected queries,
 * so every view is live without polling. Returns the latest few events.
 */
export function useLiveEvents(enabled: boolean) {
  const qc = useQueryClient();
  const [recent, setRecent] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled || !isRelay()) return;
    // The relay doesn't carry the event stream yet: refresh the live views
    // on a timer instead.
    setConnected(true);
    const t = setInterval(() => {
      for (const k of ["audit", "approvals", "instances", "policy"]) qc.invalidateQueries({ queryKey: [k] });
    }, 10_000);
    return () => clearInterval(t);
  }, [enabled, qc]);

  useEffect(() => {
    if (!enabled || isRelay()) return;
    const es = new EventSource("/api/v1/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    const onAny = (e: MessageEvent) => {
      let ev: LiveEvent;
      try {
        ev = JSON.parse(e.data);
      } catch {
        return;
      }
      setRecent((r) => [ev, ...r].slice(0, 20));
      if (ev.type.startsWith("action.")) {
        qc.invalidateQueries({ queryKey: ["audit"] });
      }
      if (ev.type.startsWith("approval.")) qc.invalidateQueries({ queryKey: ["approvals"] });
      if (ev.type === "approval.requested") {
        const a = ev.data as { action?: string; instance?: string; plan?: { summary?: string } } | undefined;
        notify("Conduit needs your approval", a?.plan?.summary || (a?.action ? `${a.action} on ${a.instance}` : undefined));
      }
      if (ev.type === "update.available") {
        qc.invalidateQueries({ queryKey: ["update"] });
        const u = ev.data as { version?: string } | undefined;
        notify("A Conduit update is available", u?.version ? `Version ${u.version} is ready to install in Settings.` : undefined);
      }
      if (ev.type === "notify.desktop") {
        const n = ev.data as { title?: string; message?: string } | undefined;
        notify(n?.title || "Conduit", n?.message);
      }
      if (ev.type.startsWith("instance.")) qc.invalidateQueries({ queryKey: ["instances"] });
      if (ev.type.startsWith("panic.")) qc.invalidateQueries({ queryKey: ["policy"] });
    };
    // Named events: register the families the UI cares about plus a catch-all.
    for (const t of [
      "action.ok",
      "action.error",
      "action.denied",
      "action.planned",
      "approval.requested",
      "approval.decided",
      "instance.saved",
      "instance.deleted",
      "panic.on",
      "panic.off",
      "notify.desktop",
      "update.available",
    ]) {
      es.addEventListener(t, onAny as EventListener);
    }
    es.onmessage = onAny;
    return () => es.close();
  }, [enabled, qc]);

  return { recent, connected };
}
