// Voice input for the assistant, a first cut: dictation through the
// browser's speech recognition where it exists (Chrome, Edge, Safari). The
// recognised text lands in the input for the person to check and send;
// nothing is sent by voice alone.
import { useCallback, useEffect, useRef, useState } from "react";

type Recognition = {
  lang: string;
  interimResults: boolean;
  continuous: boolean;
  start(): void;
  stop(): void;
  onresult: ((e: { results: ArrayLike<ArrayLike<{ transcript: string }> & { isFinal: boolean }> }) => void) | null;
  onend: (() => void) | null;
  onerror: ((e: { error: string }) => void) | null;
};

function ctor(): (new () => Recognition) | null {
  const g = globalThis as unknown as { SpeechRecognition?: new () => Recognition; webkitSpeechRecognition?: new () => Recognition };
  return g.SpeechRecognition ?? g.webkitSpeechRecognition ?? null;
}

export function voiceSupported(): boolean {
  return ctor() !== null;
}

/** Dictation: start() streams words into onText until stop() or silence. */
export function useDictation(onText: (text: string) => void) {
  const [listening, setListening] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rec = useRef<Recognition | null>(null);
  const cb = useRef(onText);
  useEffect(() => {
    cb.current = onText;
  }, [onText]);

  const stop = useCallback(() => rec.current?.stop(), []);
  const start = useCallback(() => {
    const C = ctor();
    if (!C) return;
    const r = new C();
    r.lang = navigator.language || "en-US";
    r.interimResults = true;
    r.continuous = false;
    r.onresult = (e) => {
      let text = "";
      for (let i = 0; i < e.results.length; i++) text += e.results[i][0].transcript;
      cb.current(text);
    };
    r.onerror = (e) => setError(e.error === "not-allowed" ? "Microphone access was blocked." : `Voice input stopped (${e.error}).`);
    r.onend = () => setListening(false);
    rec.current = r;
    setError(null);
    setListening(true);
    r.start();
  }, []);
  useEffect(() => () => rec.current?.stop(), []);
  return { listening, error, start, stop };
}
