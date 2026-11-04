// Module glyphs: the `icon` names module manifests use, drawn on a 24 px grid
// with a 1.6 px stroke to match the standards icons. A name this set doesn't
// know falls back to its category's glyph, then to a plain box, so a module
// from a hub or an MCP server never renders blank.
import type { SVGProps } from "react";

const paths: Record<string, string> = {
  shield: "M12 3 4.5 6v5.5c0 4.5 3.2 8.2 7.5 9.5 4.3-1.3 7.5-5 7.5-9.5V6L12 3Z",
  server: "M4 4.5h16v6H4zM4 13.5h16v6H4zM7.5 7.5h.01M7.5 16.5h.01M11 7.5h5M11 16.5h5",
  pipeline: "M6 8.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM18 20.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM8.5 6H14a3 3 0 0 1 3 3v6.5M6 8.5V15a3 3 0 0 0 3 3h6.5",
  network: "M12 9a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM5 20a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM19 20a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM11 8.8 6.3 15.3M13 8.8l4.7 6.5M7.5 17.5h9",
  git: "M6 3v12M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM18 9a9 9 0 0 1-9 9",
  cloud: "M7 18.5a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 18 9.6a4.5 4.5 0 0 1-.5 8.9H7Z",
  chat: "M4 5.5h16v10H10l-4.5 3.5v-3.5H4z",
  chart: "M4 4v16h16M8 15l3.5-4 3 2.5L19 8",
  video: "M3.5 6.5h12v11h-12zM15.5 10.5l5-3v9l-5-3",
  rocket: "M14 4c3-1 6-1 6-1s0 3-1 6l-6 6-5-5 6-6ZM9 11l-4 1-2 3 4 1M13 15l-1 4-3 2-1-4M15 9h.01",
  list: "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM3 12h18M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3Z",
  film: "M4 4h16v16H4zM8 4v16M16 4v16M4 8h4M4 12h4M4 16h4M16 8h4M16 12h4M16 16h4",
  disk: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM12 12h.01",
  database: "M4.5 6c0-1.7 3.4-3 7.5-3s7.5 1.3 7.5 3-3.4 3-7.5 3-7.5-1.3-7.5-3ZM4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3",
  workflow: "M3.5 4h6v6h-6zM14.5 14h6v6h-6zM6.5 10v4.5a2.5 2.5 0 0 0 2.5 2.5h5.5M17.5 14V9.5A2.5 2.5 0 0 0 15 7H9.5",
  play: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM10 8.5v7l6-3.5-6-3.5Z",
  music: "M9 18V5.5l11-2V16M9 18a3 3 0 1 1-6 0 3 3 0 0 1 6 0ZM20 16a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z",
  layout: "M4 4h16v16H4zM4 9h16M9 9v11",
  key: "M8 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM12 11h8.5M17.5 11v3M20.5 11v2",
  folder: "M3.5 6.5a1 1 0 0 1 1-1H10l2 2h7.5a1 1 0 0 1 1 1V18a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z",
  document: "M6 3h8l4 4v14H6zM14 3v4h4M9 12h6M9 16h6",
  container: "M3.5 7.5 12 3.5l8.5 4v9l-8.5 4-8.5-4zM8 9.5v7M12 11v8M16 9.5v7M3.5 7.5 12 11.5l8.5-4",
  check: "M9 11.5 11.5 14 16 9M4 5a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z",
  box: "M12 3 4 7v10l8 4 8-4V7l-8-4ZM4 7l8 4 8-4M12 11v10",
  bell: "M6 16.5V11a6 6 0 1 1 12 0v5.5l1.5 1.5h-15L6 16.5ZM10 20.5a2 2 0 0 0 4 0",
  wifi: "M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01",
  train: "M6 4h12v11a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2zM6 10h12M9 14h.01M15 14h.01M8.5 17 6.5 20.5M15.5 17l2 3.5",
  sun: "M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4",
  send: "M20.5 3.5 10 14M20.5 3.5 14 20.5l-4-6.5-6.5-4z",
  ruler: "M3.5 15.5 15.5 3.5l5 5-12 12-5-5ZM7 12l2 2M10 9l1.5 1.5M13 6l2 2",
  pulse: "M3 12h4l2.5-6 4 12 2.5-6H21",
  photo: "M4 5h16v14H4zM4 16l4.5-4.5 3.5 3.5 2.5-2.5L20 17M15.5 9.5h.01",
  package: "M12 3 4 7v10l8 4 8-4V7l-8-4ZM4 7l8 4 8-4M12 11v10M8 5l8 4",
  note: "M5 4h14v11l-5 5H5zM14 20v-5h5M8.5 9h7M8.5 12.5h4",
  mail: "M3.5 6h17v12h-17zM3.5 6.5 12 13l8.5-6.5",
  layers: "M12 3.5 3 8l9 4.5L21 8l-9-4.5ZM3 12.5l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5",
  lamp: "M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2V16h5v-.1c0-.8.4-1.5 1-2A6 6 0 0 0 12 3Z",
  home: "M3.5 11 12 4l8.5 7M6 9v11h12V9M10 20v-5h4v5",
  gauge: "M4 17a8 8 0 1 1 16 0M12 17l3.5-5M12 17h.01",
  gamepad: "M7 8h10a4 4 0 0 1 4 4v1.5a3.5 3.5 0 0 1-6.3 2.1L14 14.5h-4l-.7 1.1A3.5 3.5 0 0 1 3 13.5V12a4 4 0 0 1 4-4ZM7.5 10.5v3M6 12h3M15.5 11.5h.01M17.5 13h.01",
  game: "M3.5 6h3v13h-3zM8.5 6h3v13h-3zM14 6.8l2.9-.8 3.6 12.5-2.9.8z",
  download: "M12 4v11M7 10.5l5 5 5-5M4 19.5h16",
  "credit-card": "M3 6h18v12H3zM3 10h18M6.5 14.5h4",
  cpu: "M7 7h10v10H7zM10 10h4v4h-4zM10 3.5V7M14 3.5V7M10 17v3.5M14 17v3.5M3.5 10H7M3.5 14H7M17 10h3.5M17 14h3.5",
  chip: "M7 7h10v10H7zM9.5 14.5l1.2-5h.6l1.2 5M9.9 13h2.2M14.5 9.5v5M10 3.5V7M14 3.5V7M10 17v3.5M14 17v3.5M3.5 10H7M3.5 14H7M17 10h3.5M17 14h3.5",
  calendar: "M4 5.5h16V20H4zM4 10h16M8 3.5v4M16 3.5v4",
  bug: "M8 9.5a4 4 0 0 1 8 0V15a4 4 0 0 1-8 0zM12 11v8M8 12H4M20 12h-4M8 16.5l-3 2M16 16.5l3 2M8.5 8 6 5.5M15.5 8 18 5.5",
  book: "M4 5.5A1.5 1.5 0 0 1 5.5 4H11v16H5.5A1.5 1.5 0 0 1 4 18.5zM20 5.5A1.5 1.5 0 0 0 18.5 4H13v16h5.5a1.5 1.5 0 0 0 1.5-1.5z",
  battery: "M3 8h15v8H3zM18 10.5h2.5v3H18M6 10.5v3M9 10.5v3",
  plug: "M9 3.5V8M15 3.5V8M6.5 8h11v3a5.5 5.5 0 0 1-11 0zM12 16.5v4",
  bookmark: "M6.5 3.5h11v17L12 16l-5.5 4.5z",
  headset: "M4.5 14v-2a7.5 7.5 0 0 1 15 0v2M4.5 14h3v5h-2a1 1 0 0 1-1-1zM19.5 14h-3v5h2a1 1 0 0 0 1-1zM18.5 19c0 1.2-2 2-5 2",
};

/** Synonyms a module author might reasonably use for a glyph above. */
const aliases: Record<string, string> = {
  gamepad2: "gamepad",
  controller: "gamepad",
  games: "game",
  message: "chat",
  messages: "chat",
  terminal: "server",
  ssh: "server",
  hdd: "disk",
  drive: "disk",
  storage: "disk",
  image: "photo",
  images: "photo",
  camera: "video",
  file: "document",
  files: "folder",
  docs: "document",
  lock: "key",
  vault: "key",
  heartbeat: "pulse",
  activity: "pulse",
  monitor: "chart",
  graph: "chart",
  money: "credit-card",
  payment: "credit-card",
  ai: "chip",
  brain: "chip",
  router: "wifi",
  dns: "globe",
  web: "globe",
  ci: "pipeline",
  deploy: "rocket",
  docker: "container",
  calendar2: "calendar",
  notification: "bell",
  alert: "bell",
  task: "check",
  tasks: "list",
  power: "battery",
  ups: "battery",
  speed: "gauge",
  movie: "film",
  tv: "video",
  audio: "music",
  sound: "music",
  support: "headset",
  helpdesk: "headset",
};

/** The glyph for each category, for icon names the set doesn't know. */
const byCategory: Record<string, string> = {
  Conduit: "lamp",
  Development: "git",
  Infrastructure: "server",
  Network: "network",
  Storage: "disk",
  Security: "shield",
  Monitoring: "chart",
  Communication: "chat",
  Productivity: "check",
  Media: "play",
  Gaming: "gamepad",
  "Smart home": "home",
  "MCP servers": "plug",
};

/** The glyph name a module renders with: its own, an alias, its category's, or a box. */
function moduleIconName(icon?: string, category?: string): string {
  const n = (icon ?? "").trim().toLowerCase();
  if (paths[n]) return n;
  if (aliases[n]) return aliases[n];
  return byCategory[category ?? ""] ?? "box";
}

export function ModuleIcon({ icon, category, size = 20, ...rest }: { icon?: string; category?: string; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" {...rest}>
      <path d={paths[moduleIconName(icon, category)]} />
    </svg>
  );
}
