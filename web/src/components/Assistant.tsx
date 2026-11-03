import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link } from "wouter";
import { api, ok, type S } from "../api/client";
import { apiFetchUrl } from "../lib/connection";
import { useDictation, voiceSupported } from "../lib/voice";
import { ApprovalCard } from "../pages/Approvals";
import "./assistant.css";

type Step = S["AssistantStep"];
type Item =
  | { kind: "user"; text: string }
  | { kind: "text"; text: string }
  | { kind: "tool"; title: string; tool: string; result?: string; isError?: boolean; approval?: S["Approval"] }
  | { kind: "error"; text: string };

/** Turns stored messages back into display items. */
function fromMessages(msgs: S["AssistantMessage"][]): Item[] {
  const items: Item[] = [];
  const byCall = new Map<string, Item & { kind: "tool" }>();
  for (const m of msgs) {
    if (m.role === "user") items.push({ kind: "user", text: m.text ?? "" });
    if (m.role === "assistant") {
      if (m.text) items.push({ kind: "text", text: m.text });
      for (const c of m.toolCalls ?? []) {
        const it: Item & { kind: "tool" } = { kind: "tool", title: c.name, tool: c.name };
        byCall.set(c.id, it);
        items.push(it);
      }
    }
    if (m.role === "tool" && m.toolCallId) {
      const it = byCall.get(m.toolCallId);
      if (it) {
        it.result = m.text;
        it.isError = m.isError;
      }
    }
  }
  return items;
}

/** Minimal formatting: paragraphs, line breaks, `code` and **bold**. */
function Prose({ text }: { text: string }) {
  return (
    <div className="prose">
      {text.split(/\n{2,}/).map((para, i) => (
        <p key={i}>
          {para.split("\n").map((line, j) => (
            <span key={j}>
              {j > 0 && <br />}
              {line.split(/(`[^`]+`|\*\*[^*]+\*\*)/).map((part, k) =>
                part.startsWith("`") && part.endsWith("`") ? (
                  <code key={k}>{part.slice(1, -1)}</code>
                ) : part.startsWith("**") && part.endsWith("**") ? (
                  <strong key={k}>{part.slice(2, -2)}</strong>
                ) : (
                  part
                ),
              )}
            </span>
          ))}
        </p>
      ))}
    </div>
  );
}

export function Assistant({ open, onClose, seed, onSeedUsed }: { open: boolean; onClose: () => void; seed?: string; onSeedUsed?: () => void }) {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["ai", "providers"], queryFn: () => ok(api.GET("/ai/providers")), enabled: open });
  const convs = useQuery({ queryKey: ["ai", "conversations"], queryFn: () => ok(api.GET("/assistant/conversations")), enabled: open });
  const [conv, setConv] = useState<string>("");
  const [items, setItems] = useState<Item[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [showList, setShowList] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const voice = useDictation(setInput);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [items]);
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  const send = async (text: string) => {
    if (!text.trim() || busy) return;
    setBusy(true);
    setInput("");
    setItems((it) => [...it, { kind: "user", text }]);
    try {
      const res = await apiFetchUrl("/api/v1/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ conversation: conv || undefined, message: text }),
      });
      if (!res.ok || !res.body) {
        const e = await res.json().catch(() => ({ error: res.statusText }));
        setItems((it) => [...it, { kind: "error", text: e.error }]);
        return;
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          const st: Step = JSON.parse(line);
          setItems((it) => apply(it, st));
          if (st.type === "done" && st.conversation) {
            setConv(st.conversation);
            qc.invalidateQueries({ queryKey: ["ai", "conversations"] });
          }
        }
      }
    } catch (e) {
      setItems((it) => [...it, { kind: "error", text: String(e) }]);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (open && seed) {
      onSeedUsed?.();
      void send(seed);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, seed]);

  const loadConv = async (id: string) => {
    const c = await ok(api.GET("/assistant/conversations/{id}", { params: { path: { id } } }));
    setConv(id);
    setItems(fromMessages(c.messages ?? []));
    setShowList(false);
  };

  if (!open) return null;
  const none = providers.data && providers.data.length === 0;

  return (
    <aside className="assistant" aria-label="Assistant">
      <header className="assistant-head">
        <strong>Assistant</strong>
        <div className="inline">
          <button className="btn sm quiet" onClick={() => setShowList(!showList)} aria-expanded={showList}>
            History
          </button>
          <button
            className="btn sm quiet"
            onClick={() => {
              setConv("");
              setItems([]);
              setShowList(false);
            }}
          >
            New
          </button>
          <button className="btn sm quiet" onClick={onClose} aria-label="Close assistant">
            Close
          </button>
        </div>
      </header>

      {showList && (
        <div className="assistant-list">
          {convs.data?.length === 0 && <p className="xs muted">No conversations yet.</p>}
          {convs.data?.map((c) => (
            <button key={c.id} className={c.id === conv ? "active" : undefined} onClick={() => loadConv(c.id)}>
              {c.title}
            </button>
          ))}
        </div>
      )}

      <div className="assistant-body" ref={scroller}>
        {none && (
          <div className="stack small" style={{ gap: 8 }}>
            <p>The assistant needs an AI model to talk to: a cloud provider with an API key, or one running on this computer.</p>
            <Link href="/assistant" className="btn" onClick={onClose}>
              Set up a model
            </Link>
          </div>
        )}
        {!none && items.length === 0 && (
          <div className="assistant-empty">
            <p className="small muted">Ask about anything connected, or tell it what to do. Changes wait for your approval.</p>
            {["What needs my attention?", "Why is my server slow?", "What changed in the last hour?"].map((q) => (
              <button key={q} className="btn sm" onClick={() => send(q)}>
                {q}
              </button>
            ))}
          </div>
        )}
        {items.map((it, i) => {
          switch (it.kind) {
            case "user":
              return (
                <div key={i} className="msg msg-user">
                  {it.text}
                </div>
              );
            case "text":
              return (
                <div key={i} className="msg msg-assistant">
                  <Prose text={it.text} />
                </div>
              );
            case "error":
              return (
                <div key={i} className="error">
                  {it.text}
                </div>
              );
            case "tool":
              return (
                <div key={i} className="msg-tool">
                  <details>
                    <summary className={`xs ${it.isError ? "tool-error" : "muted"}`}>
                      {it.result === undefined ? "Working: " : it.isError ? "Failed: " : it.approval ? "Asked you: " : "Checked: "}
                      {it.title}
                    </summary>
                    {it.result && <pre className="json">{it.result}</pre>}
                  </details>
                  {it.approval && (
                    <ApprovalCard
                      a={it.approval}
                      onDecided={(approved) => {
                        if (approved) void send("Approved. Go ahead.");
                      }}
                    />
                  )}
                </div>
              );
          }
        })}
        {busy && <p className="xs muted working">Working…</p>}
      </div>

      <form
        className="assistant-input"
        onSubmit={(e) => {
          e.preventDefault();
          void send(input);
        }}
      >
        <textarea
          ref={inputRef}
          rows={2}
          value={input}
          placeholder={none ? "Set up a model first" : "Ask or tell it what to do"}
          disabled={none}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void send(input);
            }
          }}
        />
        <div className="assistant-buttons">
          {voiceSupported() && !none && (
            <button
              type="button"
              className={`btn ${voice.listening ? "signal" : ""}`}
              onClick={() => (voice.listening ? voice.stop() : voice.start())}
              aria-pressed={voice.listening}
              title="Speak instead of typing; check the text, then send"
            >
              {voice.listening ? "Listening…" : "Speak"}
            </button>
          )}
          <button className="btn primary" disabled={busy || none || !input.trim()}>
            Send
          </button>
        </div>
      </form>
      {voice.error && <p className="xs muted voice-error">{voice.error}</p>}
    </aside>
  );
}

function apply(items: Item[], st: Step): Item[] {
  switch (st.type) {
    case "text":
      return [...items, { kind: "text", text: st.text ?? "" }];
    case "tool":
      return [...items, { kind: "tool", title: st.title || st.tool || "", tool: st.tool ?? "" }];
    case "result": {
      const out = [...items];
      for (let i = out.length - 1; i >= 0; i--) {
        const it = out[i];
        if (it.kind === "tool" && it.tool === st.tool && it.result === undefined) {
          out[i] = { ...it, result: st.text, isError: st.isError, approval: st.approval };
          break;
        }
      }
      return out;
    }
    case "error":
      return [...items, { kind: "error", text: st.text ?? "Something went wrong" }];
  }
  return items;
}
