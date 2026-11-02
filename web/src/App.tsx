import { useEffect, useState } from "react";

type Version = { version: string; commit: string };

export default function App() {
  const [v, setV] = useState<Version | null>(null);
  useEffect(() => {
    fetch("/api/v1/version")
      .then((r) => (r.ok ? r.json() : null))
      .then(setV)
      .catch(() => setV(null));
  }, []);
  return (
    <main className="boot">
      <h1>Conduit</h1>
      <p>{v ? `daemon ${v.version} (${v.commit})` : "daemon not reachable"}</p>
    </main>
  );
}
