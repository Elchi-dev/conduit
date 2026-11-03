import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { useState } from "react";
import { useLocation } from "wouter";
import { api, ok, type Instance } from "../api/client";

const pages = [
  ["Overview", "/"],
  ["Approvals", "/approvals"],
  ["Timeline", "/timeline"],
  ["Automations", "/automations"],
  ["Modules", "/modules"],
  ["Agent rules", "/policy"],
  ["Assistant and agents", "/assistant"],
  ["API keys", "/keys"],
  ["Settings", "/settings"],
] as const;

/** Ctrl/⌘+K: jump anywhere, or open any action on any connected system. */
export function CommandBar({
  open,
  onOpenChange,
  instances,
  onAsk,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  instances: Instance[];
  onAsk: (question: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [, go] = useLocation();
  const modules = useQuery({ queryKey: ["modules"], queryFn: () => ok(api.GET("/modules")), enabled: open });
  const byId = new Map((modules.data ?? []).map((m) => [m.id, m]));

  const run = (href: string) => {
    onOpenChange(false);
    go(href);
  };

  return (
    <Command.Dialog open={open} onOpenChange={onOpenChange} label="Search and run" className="cmdk">
      <Command.Input placeholder="Go to a page, run an action, or ask the assistant…" value={search} onValueChange={setSearch} />
      <Command.List>
        <Command.Empty>No match. Press Enter on "Ask the assistant" below, or try a module name.</Command.Empty>
        {search.trim().length > 3 && (
          <Command.Group heading="Assistant">
            <Command.Item
              value={`ask ${search}`}
              forceMount
              onSelect={() => {
                onOpenChange(false);
                onAsk(search.trim());
                setSearch("");
              }}
            >
              Ask the assistant: <span className="muted">{search.trim()}</span>
            </Command.Item>
          </Command.Group>
        )}
        <Command.Group heading="Go to">
          {pages.map(([name, href]) => (
            <Command.Item key={href} value={`go ${name}`} onSelect={() => run(href)}>
              {name}
            </Command.Item>
          ))}
        </Command.Group>
        {instances.length > 0 && (
          <Command.Group heading="Actions">
            {instances.flatMap((i) =>
              (byId.get(i.module)?.actions ?? []).map((a) => (
                <Command.Item
                  key={`${i.id}/${a.name}`}
                  value={`${i.name} ${a.title || a.name} ${a.name}`}
                  onSelect={() => run(`/i/${i.id}?action=${encodeURIComponent(a.name)}`)}
                >
                  <span>{a.title || a.name}</span>
                  <span className="muted"> on {i.name}</span>
                  {a.risk !== "read" && <span className={`tag ${a.risk}`}>{a.risk}</span>}
                </Command.Item>
              )),
            )}
          </Command.Group>
        )}
      </Command.List>
    </Command.Dialog>
  );
}
