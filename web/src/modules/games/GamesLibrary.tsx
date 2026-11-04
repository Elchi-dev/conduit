import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { LineChart } from "../../components/LineChart";
import { ago } from "../../lib/format";
import { locale, t, tn } from "../../i18n";
import { act, clock, coverURL, duration, hue, launcherLabel, type Detail, type Game, type Stats } from "./api";
import "./games.css";

type Sort = "recent" | "played" | "title";
const sortKey = "conduit.games.sort";

function storedSort(): Sort {
  try {
    const v = localStorage.getItem(sortKey);
    return v === "played" || v === "title" ? v : "recent";
  } catch {
    return "recent";
  }
}

/** The game library: every game on this computer, ready to play. */
export function GamesLibrary({ instance }: { instance: string }) {
  const qc = useQueryClient();
  const [launcher, setLauncher] = useState<string>("");
  const [query, setQuery] = useState("");
  const [sort, setSortState] = useState<Sort>(storedSort);
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const opener = useRef<HTMLElement | null>(null);

  const setSort = (s: Sort) => {
    setSortState(s);
    try {
      localStorage.setItem(sortKey, s);
    } catch {
      /* private mode */
    }
  };

  const lib = useQuery({
    queryKey: ["games", instance, "library"],
    queryFn: async () => (await act<Game[]>(instance, "library")).output ?? [],
  });
  const week = useQuery({
    queryKey: ["games", instance, "stats", 7],
    queryFn: async () => (await act<Stats>(instance, "stats", { days: 7 })).output,
  });
  const refresh = useMutation({
    mutationFn: () => act(instance, "refresh"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["games", instance] }),
  });
  const play = useMutation({
    mutationFn: (g: Game) => act(instance, "play", { id: g.id }),
    onSuccess: (r, g) => {
      setNotice(r.pending ? t("Waiting for approval to start {title}. You'll find it under Approvals.", { title: g.title }) : t("Starting {title}…", { title: g.title }));
      setTimeout(() => qc.invalidateQueries({ queryKey: ["games", instance] }), 12000);
    },
    onError: (e) => setNotice(e.message),
  });

  const games = useMemo(() => lib.data ?? [], [lib.data]);
  const counts = useMemo(() => {
    const c = new Map<string, number>();
    for (const g of games) c.set(g.launcher, (c.get(g.launcher) ?? 0) + 1);
    return [...c.entries()].sort((a, b) => b[1] - a[1]);
  }, [games]);
  const shown = useMemo(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    const list = games.filter((g) => (!launcher || g.launcher === launcher) && words.every((w) => g.title.toLowerCase().includes(w)));
    const byTitle = (a: Game, b: Game) => a.title.localeCompare(b.title, locale(), { sensitivity: "base" });
    list.sort((a, b) => {
      if (sort === "played") return b.totalPlaySeconds - a.totalPlaySeconds || byTitle(a, b);
      if (sort === "recent") {
        if (a.running !== b.running) return a.running ? -1 : 1;
        return (b.lastPlayed ?? "").localeCompare(a.lastPlayed ?? "") || byTitle(a, b);
      }
      return byTitle(a, b);
    });
    return list;
  }, [games, launcher, query, sort]);
  const running = games.filter((g) => g.running);
  const totalSecs = games.reduce((s, g) => s + g.totalPlaySeconds, 0);

  const openGame = (id: string) => {
    opener.current = document.activeElement as HTMLElement | null;
    setOpen(id);
  };
  const closeGame = () => {
    setOpen(null);
    opener.current?.focus();
  };

  useEffect(() => {
    if (!notice) return;
    const h = setTimeout(() => setNotice(null), 8000);
    return () => clearTimeout(h);
  }, [notice]);

  return (
    <div className="glib">
      {running.map((g) => (
        <NowPlaying key={g.id} instance={instance} game={g} onOpen={() => openGame(g.id)} />
      ))}

      {games.length > 0 && (
        <div className="glib-head">
          <div className="glib-summary">
            <p>
              <strong>{tn("{n} game", "{n} games", games.length)}</strong>
              {totalSecs > 0 && <span className="muted">{" "}{t("{time} played in all", { time: duration(totalSecs) })}</span>}
            </p>
            {week.data && week.data.totalSeconds > 0 && (
              <p className="small muted">
                {t("This week: {time}", { time: duration(week.data.totalSeconds) })}
                {week.data.streak.current > 1 && <>{" "}{tn("({n} day streak)", "({n} days in a row)", week.data.streak.current)}</>}
              </p>
            )}
          </div>
          <div className="inline">
            <button className="btn" onClick={() => setAdding(!adding)} aria-expanded={adding}>
              {adding ? t("Close") : t("Add a game")}
            </button>
            <button className="btn quiet" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
              {refresh.isPending ? t("Looking…") : t("Look for games again")}
            </button>
          </div>
        </div>
      )}

      {adding && <AddGame instance={instance} onDone={() => setAdding(false)} />}
      {notice && (
        <p className="glib-notice small" role="status">
          {notice}
        </p>
      )}
      {lib.error && <div className="error">{lib.error.message}</div>}

      {games.length > 0 && (
        <div className="glib-tools">
          <div className="glib-chips" role="group" aria-label={t("Launcher")}>
            <button className="glib-chip" aria-pressed={launcher === ""} onClick={() => setLauncher("")}>
              {t("All")} <span className="glib-count">{games.length}</span>
            </button>
            {counts.map(([id, n]) => (
              <button key={id} className="glib-chip" aria-pressed={launcher === id} onClick={() => setLauncher(launcher === id ? "" : id)}>
                {launcherLabel(id)} <span className="glib-count">{n}</span>
              </button>
            ))}
          </div>
          <div className="glib-find">
            <input
              className="input"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("Search games")}
              aria-label={t("Search games")}
            />
            <label className="glib-sort">
              <span className="small muted">{t("Sort")}</span>
              <select className="input" value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
                <option value="recent">{t("Recently played")}</option>
                <option value="played">{t("Most played")}</option>
                <option value="title">{t("A–Z")}</option>
              </select>
            </label>
          </div>
        </div>
      )}

      {lib.isPending ? (
        <ul className="glib-grid" aria-busy="true" aria-label={t("Loading games")}>
          {Array.from({ length: 12 }, (_, i) => (
            <li key={i} className="gtile">
              <div className="gtile-art gtile-ghost" />
            </li>
          ))}
        </ul>
      ) : games.length === 0 ? (
        <div className="empty start">
          <h2>{t("No games found on this computer yet")}</h2>
          <p className="muted">
            {t("Conduit looks in Steam, Epic Games, GOG, Riot, Battle.net, EA, Ubisoft, Xbox, itch.io, Heroic and Lutris. Install one, or add a game by hand.")}</p>
          <div className="inline">
            <button className="btn primary" onClick={() => setAdding(true)}>
              {t("Add a game")}</button>
            <button className="btn" onClick={() => refresh.mutate()}>
              {t("Look for games again")}</button>
          </div>
        </div>
      ) : shown.length === 0 ? (
        <p className="muted">{t("No games match. Try another word or launcher.")}</p>
      ) : (
        <ul className="glib-grid" aria-label={t("Games")}>
          {shown.map((g) => (
            <Tile key={g.id} game={g} onOpen={() => openGame(g.id)} onPlay={() => play.mutate(g)} busy={play.isPending && play.variables?.id === g.id} />
          ))}
        </ul>
      )}

      {open && <GameDrawer instance={instance} id={open} fallback={games.find((g) => g.id === open)} onClose={closeGame} />}
    </div>
  );
}

/** Loads a cover when it scrolls into view. */
function useCover(game: Game, ref: React.RefObject<HTMLElement | null>, eager = false) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    if (!game.hasCover) return;
    let live = true;
    const load = () => coverURL(game.id).then((u) => live && setSrc(u));
    const el = ref.current;
    if (eager || !el || typeof IntersectionObserver === "undefined") {
      load();
      return () => {
        live = false;
      };
    }
    const io = new IntersectionObserver(
      (es) => {
        if (es.some((e) => e.isIntersecting)) {
          io.disconnect();
          load();
        }
      },
      { rootMargin: "300px" },
    );
    io.observe(el);
    return () => {
      live = false;
      io.disconnect();
    };
  }, [game.id, game.hasCover, ref, eager]);
  return src;
}

/** A 2:3 poster: the cover, or the title set as type when there's none. */
function Poster({ game, eager }: { game: Game; eager?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const src = useCover(game, ref, eager);
  const [failed, setFailed] = useState(false);
  const art = src && !failed;
  return (
    <div ref={ref} className={`poster${art ? " has-art" : ""}`} style={{ "--hue": hue(game.title) } as CSSProperties}>
      {art ? (
        <img src={src} alt="" loading="lazy" decoding="async" onError={() => setFailed(true)} />
      ) : (
        <span className="poster-type" aria-hidden="true">
          {game.title}
        </span>
      )}
    </div>
  );
}

function Tile({ game, onOpen, onPlay, busy }: { game: Game; onOpen: () => void; onPlay: () => void; busy: boolean }) {
  const meta = game.totalPlaySeconds > 0 ? duration(game.totalPlaySeconds) : game.lastPlayed ? ago(game.lastPlayed) : t("Not played yet");
  return (
    <li className={`gtile${game.running ? " is-running" : ""}`}>
      <div className="gtile-art">
        <button className="gtile-open" onClick={onOpen} aria-label={t("{title}, details", { title: game.title })}>
          <Poster game={game} />
        </button>
        {game.running ? (
          <span className="gtile-live">
            <span className="bulb" aria-hidden="true" />
            {t("Playing")}
          </span>
        ) : (
          game.installed && (
            <button className="gtile-play" onClick={onPlay} disabled={busy} aria-label={t("Play {title}", { title: game.title })}>
              <PlayIcon />
              <span>{busy ? t("Starting…") : t("Play")}</span>
            </button>
          )
        )}
      </div>
      <p className="gtile-title" title={game.title}>
        {game.title}
      </p>
      <p className="gtile-meta xs muted">
        {launcherLabel(game.launcher)}
        <span aria-hidden="true">, </span>
        {meta}
      </p>
    </li>
  );
}

function PlayIcon() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
      <path d="M4 2.5v11l9.5-5.5z" fill="currentColor" />
    </svg>
  );
}

/** Seconds since an ISO time, ticking once a second. */
function useElapsed(since?: string) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!since) return;
    const h = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(h);
  }, [since]);
  return since ? (now - new Date(since).getTime()) / 1000 : 0;
}

function NowPlaying({ instance, game, onOpen }: { instance: string; game: Game; onOpen: () => void }) {
  const ref = useRef<HTMLElement>(null);
  const src = useCover(game, ref, true);
  // The library knows a game is running; the running action says since when.
  const run = useQuery({
    queryKey: ["games", instance, "running"],
    queryFn: async () => (await act<{ id: string; since: string }[]>(instance, "running")).output ?? [],
    staleTime: 60_000,
  });
  const since = run.data?.find((r) => r.id === game.id)?.since;
  const secs = useElapsed(since);
  return (
    <section ref={ref} className="nowplaying" aria-label={t("Now playing")} style={src ? ({ "--art": `url("${src}")` } as CSSProperties) : undefined}>
      <div className="nowplaying-poster">
        <Poster game={game} eager />
      </div>
      <div className="nowplaying-body">
        <p className="nowplaying-label small">
          <span className="bulb" aria-hidden="true" />
          {t("Now playing")}
        </p>
        <h2 className="nowplaying-title">{game.title}</h2>
        <p className="small muted">
          {launcherLabel(game.launcher)}
          {since && (
            <>
              <span aria-hidden="true">, </span>
              {t("running for")} <span className="data nowplaying-clock">{clock(secs)}</span>
            </>
          )}
        </p>
      </div>
      <div className="nowplaying-actions">
        <button className="btn" onClick={onOpen}>
          {t("Details")}</button>
      </div>
    </section>
  );
}

function GameDrawer({ instance, id, fallback, onClose }: { instance: string; id: string; fallback?: Game; onClose: () => void }) {
  const qc = useQueryClient();
  const closeRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  const [confirmStop, setConfirmStop] = useState<string | null>(null);
  const [allSessions, setAllSessions] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const d = useQuery({
    queryKey: ["games", instance, "game", id],
    queryFn: async () => (await act<Detail>(instance, "game", { id })).output,
  });
  const g = d.data?.game ?? fallback;
  const done = () => qc.invalidateQueries({ queryKey: ["games", instance] });
  const play = useMutation({
    mutationFn: () => act(instance, "play", { id }),
    onSuccess: (r) => {
      setMsg(r.pending ? t("Waiting for approval. You'll find it under Approvals.") : t("Starting {title}…", { title: g?.title ?? "" }));
      setTimeout(done, 12000);
    },
  });
  const preview = useMutation({
    mutationFn: () => act(instance, "stop", { id }, true),
    onSuccess: (r) => setConfirmStop(r.plan?.summary ?? ""),
  });
  const stop = useMutation({
    mutationFn: () => act<{ closedGracefully: boolean }>(instance, "stop", { id }),
    onSuccess: (r) => {
      setConfirmStop(null);
      setMsg(r.pending ? t("Waiting for approval. You'll find it under Approvals.") : r.output?.closedGracefully === false ? t("It didn't close in time, so it was ended.") : t("Closed."));
      done();
    },
  });
  const remove = useMutation({
    mutationFn: () => act(instance, "remove_custom", { id }),
    onSuccess: () => {
      done();
      onClose();
    },
  });

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && panelRef.current) {
        // Keep focus inside the drawer.
        const f = panelRef.current.querySelectorAll<HTMLElement>("button:not([disabled]), a[href], input, select, [tabindex]:not([tabindex='-1'])");
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const sessions = d.data?.sessions ?? [];
  const stats = d.data?.stats;
  const series = stats?.series?.[0];
  const anyPlay = !!series?.points.some((p) => p[1] > 0);
  const err = d.error || play.error || preview.error || stop.error || remove.error;

  return (
    <div className="gdrawer-backdrop" onClick={onClose}>
      <aside ref={panelRef} className="gdrawer" role="dialog" aria-modal="true" aria-labelledby="gdrawer-title" onClick={(e) => e.stopPropagation()}>
        <div className="gdrawer-top">
          <button ref={closeRef} className="btn quiet sm" onClick={onClose}>
            {t("Close")}</button>
        </div>
        {g && (
          <>
            <header className="gdrawer-head">
              <div className="gdrawer-poster">
                <Poster game={g} eager />
              </div>
              <div className="stack" style={{ gap: 6 }}>
                <h2 id="gdrawer-title" className="gdrawer-title">
                  {g.title}
                </h2>
                <p className="small muted">{launcherLabel(g.launcher)}</p>
                {g.running && (
                  <p className="gdrawer-live small">
                    <span className="bulb" aria-hidden="true" />
                    {d.data?.running ? t("Playing for {time}", { time: duration(d.data.running.seconds) }) : t("Playing")}
                  </p>
                )}
                <div className="inline gdrawer-actions">
                  {g.running ? (
                    <button className="btn danger" onClick={() => preview.mutate()} disabled={preview.isPending || stop.isPending}>
                      {t("Stop game")}</button>
                  ) : (
                    g.installed && (
                      <button className="btn primary gdrawer-play" onClick={() => play.mutate()} disabled={play.isPending}>
                        <PlayIcon />
                        {play.isPending ? t("Starting…") : t("Play")}
                      </button>
                    )
                  )}
                </div>
              </div>
            </header>

            {confirmStop !== null && (
              <div className="gdrawer-confirm" role="alertdialog" aria-labelledby="gstop-title" aria-describedby="gstop-desc">
                <p id="gstop-title" className="strong">
                  {t("Stop {title}?", { title: g.title })}
                </p>
                <p id="gstop-desc" className="small muted">
                  {confirmStop || t("Unsaved progress can be lost.")}
                </p>
                {d.data?.running && (
                  <ul className="gdrawer-procs">
                    {d.data.running.processes.map((p) => (
                      <li key={p.pid} className="data xs">
                        {p.name} ({p.pid})
                      </li>
                    ))}
                  </ul>
                )}
                <div className="inline">
                  <button className="btn danger" onClick={() => stop.mutate()} disabled={stop.isPending}>
                    {stop.isPending ? t("Stopping…") : t("Stop game")}
                  </button>
                  <button className="btn" onClick={() => setConfirmStop(null)}>
                    {t("Keep playing")}</button>
                </div>
              </div>
            )}
            {msg && (
              <p className="small" role="status">
                {msg}
              </p>
            )}
            {err && <div className="error">{err.message}</div>}

            <dl className="gdrawer-stats">
              <div>
                <dt>{t("Played")}</dt>
                <dd>{g.totalPlaySeconds > 0 ? duration(g.totalPlaySeconds) : t("Not yet")}</dd>
              </div>
              <div>
                <dt>{t("Last 30 days")}</dt>
                <dd>{stats ? duration(stats.totalSeconds) : "…"}</dd>
              </div>
              <div>
                <dt>{t("Sessions")}</dt>
                <dd>{stats ? stats.sessions : "…"}</dd>
              </div>
              <div>
                <dt>{t("Last played")}</dt>
                <dd>{g.lastPlayed ? ago(g.lastPlayed) : t("Never")}</dd>
              </div>
            </dl>
            {g.launcherPlaySeconds && g.launcherPlaySeconds > g.playSeconds ? (
              <p className="xs muted">
                {t("Includes play time {launcher} recorded before Conduit.", { launcher: launcherLabel(g.launcher) })}</p>
            ) : null}

            <section className="stack" style={{ gap: 8 }}>
              <h3 className="section-title">{t("Play time, last 30 days")}</h3>
              {anyPlay && series ? (
                <LineChart series={[{ name: t("Hours played"), points: series.points }]} />
              ) : (
                <p className="small muted">{t("Nothing recorded in the last 30 days. Conduit records sessions while it runs on this computer.")}</p>
              )}
            </section>

            {sessions.length > 0 && (
              <section className="stack" style={{ gap: 8 }}>
                <h3 className="section-title">{t("Sessions")}</h3>
                <ol className="gsessions">
                  {(allSessions ? sessions : sessions.slice(0, 8)).map((s) => (
                    <li key={s.start}>
                      <span>{new Date(s.start).toLocaleDateString(locale(), { weekday: "short", day: "numeric", month: "short" })}</span>
                      <span className="data xs muted">
                        {new Date(s.start).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })}–
                        {new Date(s.end).toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })}
                      </span>
                      <span className="gsessions-len">{duration(s.seconds)}</span>
                    </li>
                  ))}
                </ol>
                {sessions.length > 8 && (
                  <button className="btn quiet sm" onClick={() => setAllSessions(!allSessions)}>
                    {allSessions ? t("Show fewer") : tn("Show all {n} session", "Show all {n} sessions", sessions.length)}
                  </button>
                )}
              </section>
            )}

            <section className="stack" style={{ gap: 8 }}>
              <h3 className="section-title">{t("On this computer")}</h3>
              <dl className="gdrawer-facts small">
                {g.installPath && (
                  <>
                    <dt>{t("Folder")}</dt>
                    <dd className="data">{g.installPath}</dd>
                  </>
                )}
                {g.size && (g.sizeBytes ?? 0) > 0 && (
                  <>
                    <dt>{t("Size")}</dt>
                    <dd>{g.size}</dd>
                  </>
                )}
                {d.data?.launch && (
                  <>
                    <dt>{t("Starts with")}</dt>
                    <dd className="data">{d.data.launch}</dd>
                  </>
                )}
                <dt>{t("Id")}</dt>
                <dd className="data">{g.id}</dd>
              </dl>
              {g.custom && (
                <div>
                  <button className="btn danger sm" onClick={() => confirm(t("Remove {title} from the library? Its play history stays.", { title: g.title })) && remove.mutate()}>
                    {t("Remove from library")}</button>
                </div>
              )}
            </section>
          </>
        )}
      </aside>
    </div>
  );
}

function AddGame({ instance, onDone }: { instance: string; onDone: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ title: "", executable: "", args: "", workingDir: "", uri: "", coverUrl: "" });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const add = useMutation({
    mutationFn: () => {
      const input: Record<string, unknown> = { title: f.title.trim() };
      if (f.executable.trim()) input.executable = f.executable.trim();
      if (f.args.trim()) input.args = f.args.trim().split(/\s+/);
      if (f.workingDir.trim()) input.workingDir = f.workingDir.trim();
      if (f.uri.trim()) input.uri = f.uri.trim();
      if (f.coverUrl.trim()) input.coverUrl = f.coverUrl.trim();
      return act(instance, "add_custom", input);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["games", instance] });
      onDone();
    },
  });
  return (
    <form
      className="panel runner glib-add"
      onSubmit={(e) => {
        e.preventDefault();
        add.mutate();
      }}
    >
      <h2>{t("Add a game")}</h2>
      <p className="small muted">{t("For games no launcher knows: a program to run, or a launch link.")}</p>
      <div className="glib-add-grid">
        <label className="field">
          <span>{t("Title")}</span>
          <input value={f.title} onChange={set("title")} required />
        </label>
        <label className="field">
          <span>{t("Program")}</span>
          <input value={f.executable} onChange={set("executable")} placeholder="/opt/game/run.sh" className="data" />
        </label>
        <label className="field">
          <span>{t("Arguments")}</span>
          <input value={f.args} onChange={set("args")} placeholder="--fullscreen" className="data" />
          <small>{t("Separated by spaces.")}</small>
        </label>
        <label className="field">
          <span>{t("Working folder")}</span>
          <input value={f.workingDir} onChange={set("workingDir")} className="data" />
        </label>
        <label className="field">
          <span>{t("Or a launch link")}</span>
          <input value={f.uri} onChange={set("uri")} placeholder="heroic://launch?appName=…" className="data" />
        </label>
        <label className="field">
          <span>{t("Cover image link")}</span>
          <input value={f.coverUrl} onChange={set("coverUrl")} placeholder="https://…" type="url" className="data" />
          <small>{t("A portrait image, 2:3.")}</small>
        </label>
      </div>
      {add.error && <div className="error">{add.error.message}</div>}
      <div className="inline">
        <button className="btn primary" disabled={add.isPending || !f.title.trim() || (!f.executable.trim() && !f.uri.trim())}>
          {t("Add to library")}</button>
        <button type="button" className="btn" onClick={onDone}>
          {t("Cancel")}</button>
      </div>
    </form>
  );
}
