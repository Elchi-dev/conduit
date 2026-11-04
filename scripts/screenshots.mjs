#!/usr/bin/env node
// Screenshots of the real app for the README (docs/images/*.webp).
//
// It starts a fresh daemon (bin/conduitd, built with the UI) on a free port
// with a throwaway data folder and HOME, starts small fake servers on
// 127.0.0.1 that answer like Docker, Proxmox VE, Home Assistant, Pi-hole,
// Jellyfin, Uptime Kuma and an OpenAI-compatible model server, connects
// instances to them, seeds agent activity, approvals, rules, people and
// vault entries through the daemon's HTTP API, and then drives the web app
// with Playwright. Every name, address and secret in it is made up; nothing
// leaves this computer.
//
// Rerun from the repository root:
//
//   CI=true make daemon            # builds the web app and bin/conduitd
//   node scripts/screenshots.mjs   # writes docs/images/*.webp
//
// Needs Node 20+, Playwright with Chromium (require("playwright") or
// @playwright/test from web/node_modules), openssl, and one WebP encoder:
// cwebp, sharp (web/node_modules) or Python with Pillow. Set KEEP=1 to keep
// the PNG captures and the data folder (printed at the end) for inspection,
// ONLY=home,policy to capture a subset.

import { execFileSync, spawn } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { createServer as netServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "docs", "images");
const bin = process.env.CONDUIT_BIN ?? join(root, "bin", "conduitd");
const only = process.env.ONLY ? new Set(process.env.ONLY.split(",")) : null;
const keep = !!process.env.KEEP;

const require = createRequire(import.meta.url);
function loadPlaywright() {
  for (const p of ["playwright", join(root, "web", "node_modules", "playwright"), join(root, "web", "node_modules", "@playwright", "test")]) {
    try {
      return require(p);
    } catch {
      /* next */
    }
  }
  throw new Error("Playwright isn't installed (npm i -g playwright, or pnpm install in web/)");
}
const { chromium } = loadPlaywright();

const tmp = mkdtempSync(join(tmpdir(), "conduit-shots-"));
const data = join(tmp, "data");
const home = join(tmp, "home");
const raw = join(tmp, "raw");
for (const d of [data, home, raw, outDir]) mkdirSync(d, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function freePort() {
  return new Promise((res, rej) => {
    const s = netServer();
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      s.close(() => (a && typeof a === "object" ? res(a.port) : rej(new Error("no port"))));
    });
  });
}

// ---------------------------------------------------------------- fakes

const servers = [];
function json(res, code, body) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((r) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => r(b));
  });
}
async function serve(handler, { tls, socket } = {}) {
  const wrap = async (req, res) => {
    try {
      const u = new URL(req.url, "http://x");
      const body = await readBody(req);
      const out = await handler(req.method, u.pathname, u.searchParams, body, req);
      if (out === undefined) return json(res, 404, { message: `no route ${req.method} ${u.pathname}` });
      if (typeof out === "object" && out && out.__status) return json(res, out.__status, out.body ?? {});
      if (typeof out === "object" && out && "__text" in out) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end(out.__text);
      }
      json(res, 200, out);
    } catch (e) {
      json(res, 500, { message: String(e) });
    }
  };
  const s = tls ? https.createServer(tls, wrap) : http.createServer(wrap);
  servers.push(s);
  if (socket) {
    await new Promise((r) => s.listen(socket, r));
    return socket;
  }
  const port = await freePort();
  await new Promise((r) => s.listen(port, "127.0.0.1", r));
  return port;
}

const base32 = (n) => [...randomBytes(n)].map((b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[b % 32]).join("");
const hex = (seed) => createHash("sha256").update(seed).digest("hex");

// Docker Engine API (the parts the module reads), one per host.
function dockerFake(version, list) {
  const containers = list.map(([name, image, project, state, status, ports, cpu, memMB]) => ({
    Id: hex(name + version),
    Names: ["/" + name],
    Image: image,
    State: state,
    Status: status,
    Labels: project ? { "com.docker.compose.project": project } : {},
    Ports: (ports ?? []).map(([pub, priv]) => ({ PublicPort: pub, PrivatePort: priv, Type: "tcp" })),
    Created: Math.floor((now - 9 * DAY) / 1000),
    cpu,
    memMB,
  }));
  const find = (id) => containers.find((c) => c.Id === id || c.Id.startsWith(id) || c.Names[0] === "/" + id);
  return (method, path, q) => {
    path = path.replace(/^\/v1\.\d+/, "");
    if (path === "/_ping") return "OK";
    if (path === "/info")
      return { ServerVersion: version, Containers: containers.length, ContainersRunning: containers.filter((c) => c.State === "running").length };
    if (path === "/version") return { Version: version, ApiVersion: "1.43" };
    if (path === "/containers/json") return containers.filter((c) => q.get("all") || c.State === "running").map(({ cpu, memMB, ...c }) => c);
    if (path === "/images/json")
      return [...new Set(containers.map((c) => c.Image))].map((t, i) => ({ Id: "sha256:" + hex(t), RepoTags: [t], Size: (80 + i * 37) * 2 ** 20, Created: Math.floor((now - (3 + i) * DAY) / 1000) }));
    let m = path.match(/^\/containers\/([^/]+)\/logs$/);
    if (m) {
      const t = (s) => new Date(now - s * 1000).toISOString();
      return { __text: [
        `${t(62)} level=info msg="GET /v1/orders 200" duration=18ms`,
        `${t(41)} level=info msg="POST /v1/checkout 201" duration=142ms`,
        `${t(33)} level=warn msg="slow query" table=orders duration=1.9s`,
        `${t(20)} level=info msg="GET /v1/orders 200" duration=21ms`,
        `${t(4)} level=info msg="GET /healthz 200" duration=1ms`,
      ].join("\n") + "\n" };
    }
    m = path.match(/^\/containers\/([^/]+)\/(json|stats|start|stop|restart|pause|unpause)$/);
    if (m) {
      const c = find(decodeURIComponent(m[1]));
      if (!c) return { __status: 404, body: { message: `No such container: ${m[1]}` } };
      if (m[2] === "json") return { Id: c.Id, Name: c.Names[0], State: { Status: c.State, Running: c.State === "running" } };
      if (m[2] === "stats") {
        const sys = 4_000_000_000;
        return {
          cpu_stats: { cpu_usage: { total_usage: 1e9 + Math.round((c.cpu / 100) * (sys / 8)) }, system_cpu_usage: 2 * sys, online_cpus: 8 },
          precpu_stats: { cpu_usage: { total_usage: 1e9 }, system_cpu_usage: sys },
          memory_stats: { usage: c.memMB * 2 ** 20, limit: 32 * 2 ** 30 },
        };
      }
      if (method === "POST") {
        if (m[2] === "stop") c.State = "exited";
        if (m[2] === "start" || m[2] === "restart") (c.State = "running"), (c.Status = "Up 2 seconds");
        return { __status: 204 };
      }
    }
    return undefined;
  };
}

const homelabDocker = dockerFake("27.3.1", [
  ["caddy", "caddy:2.8", "edge", "running", "Up 9 days", [[443, 443], [80, 80]], 0.4, 38],
  ["authelia", "authelia/authelia:4.38", "edge", "running", "Up 9 days", [], 0.2, 61],
  ["jellyfin", "jellyfin/jellyfin:10.10.3", "media", "running", "Up 3 days", [[8096, 8096]], 14.8, 1840],
  ["audiobookshelf", "advplyr/audiobookshelf:2.17", "media", "running", "Up 3 days", [[13378, 80]], 0.6, 212],
  ["immich-server", "ghcr.io/immich-app/immich-server:v1.120", "photos", "running", "Up 5 days", [[2283, 2283]], 6.1, 1290],
  ["immich-ml", "ghcr.io/immich-app/immich-machine-learning:v1.120", "photos", "running", "Up 5 days", [], 22.3, 2410],
  ["postgres", "postgres:16-alpine", "photos", "running", "Up 5 days", [], 1.9, 480],
  ["paperless", "ghcr.io/paperless-ngx/paperless-ngx:2.13", "docs", "running", "Up 2 days (unhealthy)", [[8000, 8000]], 3.4, 702],
  ["redis", "redis:7-alpine", "docs", "running", "Up 2 days", [], 0.3, 24],
  ["homeassistant", "ghcr.io/home-assistant/home-assistant:2026.10", "home", "running", "Up 11 days", [[8123, 8123]], 2.2, 540],
  ["mosquitto", "eclipse-mosquitto:2", "home", "running", "Up 11 days", [[1883, 1883]], 0.1, 9],
  ["zigbee2mqtt", "koenkk/zigbee2mqtt:1.41", "home", "running", "Up 11 days", [[8080, 8080]], 0.7, 118],
  ["uptime-kuma", "louislam/uptime-kuma:1.23", "monitoring", "running", "Up 9 days", [[3001, 3001]], 0.9, 96],
  ["grafana", "grafana/grafana:11.3", "monitoring", "running", "Up 9 days", [[3000, 3000]], 0.5, 142],
  ["restic-backup", "restic/restic:0.17", "", "exited", "Exited (0) 6 hours ago", [], 0, 0],
]);
const prodDocker = dockerFake("27.2.0", [
  ["api", "registry.example.com/shop/api:2.14.1", "shop", "running", "Up 4 days", [[8080, 8080]], 31.5, 920],
  ["worker", "registry.example.com/shop/worker:2.14.1", "shop", "running", "Up 4 days", [], 12.2, 610],
  ["web", "registry.example.com/shop/web:2.14.1", "shop", "running", "Up 4 days", [[3000, 3000]], 4.8, 330],
  ["traefik", "traefik:v3.2", "edge", "running", "Up 21 days", [[443, 443]], 0.8, 74],
  ["postgres", "postgres:16", "shop", "running", "Up 21 days", [], 9.6, 2100],
  ["valkey", "valkey/valkey:8", "shop", "running", "Up 21 days", [], 0.9, 180],
]);

// Proxmox VE, over https with a self-signed certificate pinned by fingerprint.
function makeCert() {
  const key = join(tmp, "pve.key");
  const crt = join(tmp, "pve.crt");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=pve-01.lan"], { stdio: "ignore" });
  const der = execFileSync("openssl", ["x509", "-in", crt, "-outform", "der"]);
  return { key: readFileSync(key), cert: readFileSync(crt), fingerprint: createHash("sha256").update(der).digest("hex") };
}
const pveGuests = [
  [100, "truenas", "pve-01", "qemu", "running", 0.06, 4, 16, 14.2, 19 * DAY, "storage"],
  [101, "docker-host", "pve-01", "qemu", "running", 0.21, 8, 32, 21.7, 9 * DAY, "apps"],
  [102, "home-assistant", "pve-02", "qemu", "running", 0.03, 2, 4, 2.6, 11 * DAY, "home"],
  [103, "pihole", "pve-02", "lxc", "running", 0.01, 1, 1, 0.2, 30 * DAY, "dns"],
  [104, "win11-gaming", "pve-01", "qemu", "stopped", 0, 12, 24, 0, 0, "desktop"],
  [105, "k3s-lab", "pve-02", "qemu", "running", 0.12, 4, 8, 5.9, 2 * DAY, "lab"],
  [106, "wireguard", "pve-02", "lxc", "running", 0.0, 1, 0.5, 0.06, 30 * DAY, "net"],
];
const proxmoxFake = (method, path) => {
  path = path.replace(/^\/api2\/json/, "");
  const G = 2 ** 30;
  if (path === "/version") return { data: { version: "8.2.7", release: "8.2" } };
  if (path === "/cluster/resources")
    return { data: pveGuests.map(([vmid, name, node, type, status, cpu, maxcpu, maxmem, mem, uptime, tags]) => ({ vmid, name, node, type, status, cpu, maxcpu, maxmem: maxmem * G, mem: Math.round(mem * G), uptime: Math.round(uptime / 1000), tags, id: `${type}/${vmid}` })) };
  if (path === "/nodes")
    return { data: [
      { node: "pve-01", status: "online", cpu: 0.18, maxcpu: 16, mem: 41 * G, maxmem: 64 * G, uptime: 19 * 86400 },
      { node: "pve-02", status: "online", cpu: 0.07, maxcpu: 8, mem: 12 * G, maxmem: 32 * G, uptime: 30 * 86400 },
    ] };
  let m = path.match(/^\/nodes\/([^/]+)\/storage$/);
  if (m) return { data: [{ storage: "local-zfs", type: "zfspool", total: 1800 * G, used: 912 * G, avail: 888 * G, active: 1, enabled: 1 }, { storage: "backup-nfs", type: "nfs", total: 8000 * G, used: 5120 * G, avail: 2880 * G, active: 1, enabled: 1 }] };
  m = path.match(/^\/nodes\/([^/]+)\/(qemu|lxc)\/(\d+)\/status\/(current|\w+)$/);
  if (m) {
    const g = pveGuests.find((x) => x[0] === Number(m[3]));
    if (m[4] === "current") return { data: { status: g?.[4] ?? "unknown", name: g?.[1] } };
    if (method === "POST") return { data: `UPID:${m[1]}:000A1B2C:0F1E2D3C:672A1B00:qm${m[4]}:${m[3]}:conduit@pve!conduit:` };
  }
  m = path.match(/^\/nodes\/([^/]+)\/(qemu|lxc)\/(\d+)\/snapshot$/);
  if (m) return { data: [{ name: "before-upgrade", description: "Before 8.2 upgrade", snaptime: Math.floor((now - 6 * DAY) / 1000) }, { name: "current", description: "You are here!" }] };
  return undefined;
};

// Home Assistant REST API.
const haStates = [
  ["sensor.living_room_temperature", "21.4", { friendly_name: "Living room temperature", unit_of_measurement: "°C", device_class: "temperature" }],
  ["sensor.office_co2", "612", { friendly_name: "Office CO2", unit_of_measurement: "ppm" }],
  ["sensor.solar_power", "2.84", { friendly_name: "Solar power", unit_of_measurement: "kW" }],
  ["sensor.grid_import_today", "3.1", { friendly_name: "Grid import today", unit_of_measurement: "kWh" }],
  ["light.desk", "on", { friendly_name: "Desk lamp", brightness: 180, rgb_color: [255, 200, 140] }],
  ["light.kitchen", "off", { friendly_name: "Kitchen lights" }],
  ["light.hallway", "on", { friendly_name: "Hallway", brightness: 90 }],
  ["switch.server_rack_fan", "on", { friendly_name: "Server rack fan" }],
  ["switch.coffee_machine", "off", { friendly_name: "Coffee machine" }],
  ["cover.garage_door", "closed", { friendly_name: "Garage door", device_class: "garage" }],
  ["lock.front_door", "locked", { friendly_name: "Front door" }],
  ["climate.living_room", "heat", { friendly_name: "Living room heating", temperature: 21 }],
  ["binary_sensor.washing_machine", "off", { friendly_name: "Washing machine running" }],
  ["sensor.ups_battery", "100", { friendly_name: "UPS battery", unit_of_measurement: "%" }],
].map(([entity_id, state, attributes], i) => ({ entity_id, state, attributes, last_changed: iso((i + 1) * 37 * MIN) }));
const haFake = (method, path) => {
  if (path === "/api/config") return { location_name: "Home", version: "2026.10.3", time_zone: "Europe/Berlin" };
  if (path === "/api/" || path === "/api") return { message: "API running." };
  if (path === "/api/states") return haStates;
  let m = path.match(/^\/api\/states\/(.+)$/);
  if (m) return haStates.find((s) => s.entity_id === m[1]) ?? { __status: 404, body: { message: "Entity not found." } };
  if (path.startsWith("/api/services/") && method === "POST") return [];
  return undefined;
};

// Pi-hole v6 API.
const piholeFake = (method, path, q) => {
  if (path === "/api/auth") return { session: { valid: true, sid: "fake-sid-" + hex("pi").slice(0, 12), validity: 1800 } };
  if (path === "/api/dns/blocking") return { blocking: "enabled", timer: null };
  if (path === "/api/stats/summary")
    return { queries: { total: 48213, blocked: 9187, percent_blocked: 19.05 }, clients: { active: 23 }, gravity: { domains_being_blocked: 412883 } };
  if (path === "/api/stats/top_domains")
    return { domains: [["telemetry.tv-vendor.example", 1840], ["ads.tracker.example", 1122], ["metrics.phone-oem.example", 804], ["beacon.analytics.example", 611], ["pixel.adnet.example", 402]].slice(0, Number(q.get("count") || 10)).map(([domain, count]) => ({ domain, count })) };
  return undefined;
};

// Jellyfin.
const jellyfinFake = (method, path) => {
  if (path === "/System/Info") return { ServerName: "media", Version: "10.10.3", OperatingSystem: "Linux" };
  if (path === "/Library/VirtualFolders")
    return [
      { Name: "Movies", CollectionType: "movies", Locations: ["/media/movies"] },
      { Name: "Shows", CollectionType: "tvshows", Locations: ["/media/shows"] },
      { Name: "Music", CollectionType: "music", Locations: ["/media/music"] },
      { Name: "Home videos", CollectionType: "homevideos", Locations: ["/media/home"] },
    ];
  if (path === "/Items") return { Items: [] };
  if (path === "/Sessions") return [];
  return undefined;
};

// Uptime Kuma, through a public status page. One monitor is down, so the
// overview has something that needs attention.
const kumaMonitors = [
  [1, "Website", "http", 1, 142, 1],
  [2, "Shop API", "http", 1, 88, 0.9998],
  [3, "Nextcloud", "http", 1, 210, 0.9991],
  [4, "Mail (SMTP)", "port", 1, 31, 1],
  [5, "Paperless", "http", 0, 0, 0.962],
  [6, "VPN endpoint", "ping", 1, 18, 1],
  [7, "DNS (pi.hole)", "dns", 1, 4, 1],
  [8, "Backups (push)", "push", 1, 0, 1],
];
const kumaFake = (method, path) => {
  if (path === "/api/status-page/homelab")
    return { config: { slug: "homelab", title: "Homelab" }, publicGroupList: [{ name: "Services", monitorList: kumaMonitors.map(([id, name, type]) => ({ id, name, type })) }] };
  if (path === "/api/status-page/heartbeat/homelab") {
    const heartbeatList = {};
    const uptimeList = {};
    for (const [id, , , status, ping, up] of kumaMonitors) {
      heartbeatList[id] = [{ status, msg: status ? "200 - OK" : "connect ECONNREFUSED 10.0.20.14:8000", ping, time: iso(MIN) }];
      uptimeList[`${id}_24`] = up;
    }
    return { heartbeatList, uptimeList };
  }
  return undefined;
};

// An OpenAI-compatible model server that plays one short, scripted turn:
// look at Docker usage, then answer; asked to restart, call restart (which
// waits for approval) and say so.
const llm = { docker: "" };
const llmFake = (method, path, q, body) => {
  if (path === "/v1/models") return { data: [{ id: "qwen3:14b" }] };
  if (path !== "/v1/chat/completions") return undefined;
  const req = JSON.parse(body || "{}");
  const msgs = req.messages ?? [];
  const lastUser = [...msgs].reverse().find((m) => m.role === "user")?.content ?? "";
  const last = msgs[msgs.length - 1];
  const tools = (req.tools ?? []).map((t) => t.function.name);
  const tool = (action) => tools.find((n) => n === `${llm.docker}__${action}`) ?? tools.find((n) => n.endsWith(`__${action}`));
  const reply = (message) => ({ id: "chatcmpl-1", object: "chat.completion", model: req.model, choices: [{ index: 0, finish_reason: message.tool_calls ? "tool_calls" : "stop", message: { role: "assistant", ...message } }] });
  const call = (name, args) => reply({ content: null, tool_calls: [{ id: "call_" + randomBytes(4).toString("hex"), type: "function", function: { name, arguments: JSON.stringify(args) } }] });
  if (/restart/i.test(lastUser)) {
    if (last.role !== "tool") return call(tool("restart"), { container: "paperless" });
    return reply({ content: "I asked to restart **paperless** on homelab. It's a destructive action, so it's waiting for your approval; it runs as soon as you approve it." });
  }
  if (last.role !== "tool") return call(tool("stats"), {});
  return reply({
    content:
      "14 of 15 containers on **homelab** are running; `restic-backup` is the nightly job and exited cleanly.\n\n" +
      "Busiest right now: **immich-ml** (22.3% CPU, 2.4 GB), **jellyfin** (14.8%, 1.8 GB) and **immich-server** (6.1%, 1.3 GB).\n\n" +
      "One problem: **paperless** reports unhealthy, and Uptime Kuma has had it down since this morning. A restart usually clears it. Want me to restart it?",
  });
};

// Fictional Steam library: manifests, play time and locally cached covers.
const games = [
  [2105430, "Lanternfall", 38.2, 2 * DAY, ["#0f2a3d", "#f2a93b"], "mountain"],
  [2081190, "Tidewright", 112.5, 5 * HOUR, ["#06343a", "#5fd3c6"], "waves"],
  [1990270, "Hollow Orbit", 64.0, 3 * DAY, ["#120d26", "#b48cff"], "planet"],
  [2244310, "Copperline Express", 21.7, 9 * DAY, ["#3a1d0c", "#ff8a3d"], "rails"],
  [1876500, "Mossbound", 87.3, 26 * HOUR, ["#11291a", "#9fdc7c"], "forest"],
  [2310880, "Northwind Kitchen", 9.4, 14 * DAY, ["#3b0f1d", "#ffd27a"], "sun"],
  [2156020, "Pixel Garrison", 143.9, 6 * DAY, ["#1b1f3a", "#ff5d73"], "grid"],
  [2290410, "Glasshouse", 4.2, 30 * DAY, ["#0e2f2a", "#e9f7ef"], "panes"],
];
function coverHTML(title, [bg, fg], motif) {
  const shapes = {
    mountain: `<polygon points="0,900 220,470 360,640 470,520 600,900" fill="${fg}" opacity=".85"/><polygon points="0,900 140,640 300,900" fill="${bg}" opacity=".7"/><circle cx="420" cy="260" r="70" fill="${fg}" opacity=".9"/>`,
    waves: [0, 1, 2, 3, 4].map((i) => `<path d="M0 ${560 + i * 70} q75 -40 150 0 t150 0 t150 0 t150 0 V900 H0Z" fill="${fg}" opacity="${0.18 + i * 0.16}"/>`).join(""),
    planet: `<circle cx="300" cy="420" r="170" fill="${fg}" opacity=".9"/><ellipse cx="300" cy="420" rx="290" ry="60" fill="none" stroke="${fg}" stroke-width="14" opacity=".6"/>` + [...Array(40)].map((_, i) => `<circle cx="${(i * 137) % 600}" cy="${(i * 211) % 900}" r="${1 + (i % 3)}" fill="#fff" opacity=".7"/>`).join(""),
    rails: `<polygon points="250,360 350,360 600,900 0,900" fill="${fg}" opacity=".25"/>` + [...Array(9)].map((_, i) => `<rect x="${260 - i * 30}" y="${380 + i * 60}" width="${80 + i * 60}" height="${8 + i * 2}" fill="${fg}" opacity=".8"/>`).join("") + `<circle cx="300" cy="250" r="90" fill="${fg}"/>`,
    forest: [...Array(9)].map((_, i) => `<polygon points="${i * 75 - 40},900 ${i * 75 + 30},${430 + (i % 3) * 70} ${i * 75 + 100},900" fill="${fg}" opacity="${0.35 + (i % 4) * 0.15}"/>`).join(""),
    sun: `<circle cx="300" cy="520" r="200" fill="${fg}"/>` + [...Array(6)].map((_, i) => `<rect x="0" y="${560 + i * 40}" width="600" height="${6 + i * 3}" fill="${bg}"/>`).join(""),
    grid: [...Array(7)].flatMap((_, x) => [...Array(7)].map((_, y) => ((x * 3 + y * 5) % 4 === 0 ? `<rect x="${60 + x * 70}" y="${330 + y * 70}" width="56" height="56" fill="${fg}" opacity="${0.4 + ((x + y) % 3) * 0.25}"/>` : ""))).join(""),
    panes: [...Array(4)].flatMap((_, x) => [...Array(5)].map((_, y) => `<rect x="${70 + x * 118}" y="${300 + y * 105}" width="104" height="92" fill="${fg}" opacity="${0.08 + ((x * 2 + y) % 5) * 0.08}" stroke="${fg}" stroke-opacity=".5"/>`)).join(""),
  };
  return `<!doctype html><html><body style="margin:0"><div style="width:600px;height:900px;position:relative;overflow:hidden;background:linear-gradient(170deg,${bg},#000 140%);font-family:Georgia,serif">
<svg width="600" height="900" style="position:absolute;inset:0">${shapes[motif]}</svg>
<div style="position:absolute;left:40px;right:40px;top:70px;color:${fg};font-size:${title.length > 14 ? 54 : 68}px;line-height:1.02;font-weight:700;letter-spacing:.5px;text-shadow:0 2px 18px rgba(0,0,0,.45)">${title}</div></div></body></html>`;
}
async function makeSteam(browser) {
  const steam = join(home, ".steam", "steam");
  const apps = join(steam, "steamapps");
  const cache = join(steam, "appcache", "librarycache");
  const cfg = join(steam, "userdata", "40417", "config");
  for (const d of [apps, cache, cfg]) mkdirSync(d, { recursive: true });
  writeFileSync(join(apps, "libraryfolders.vdf"), `"libraryfolders"\n{\n\t"0"\n\t{\n\t\t"path"\t\t"${steam}"\n\t}\n}\n`);
  const page = await browser.newPage({ viewport: { width: 600, height: 900 } });
  let local = "";
  for (const [id, title, hours, last, colors, motif] of games) {
    const dir = title.toLowerCase().replace(/[^a-z0-9]+/g, "");
    writeFileSync(join(apps, `appmanifest_${id}.acf`), `"AppState"\n{\n\t"appid"\t\t"${id}"\n\t"name"\t\t"${title}"\n\t"installdir"\t\t"${dir}"\n\t"SizeOnDisk"\t\t"${(3 + (id % 37)) * 1_073_741_824}"\n\t"LastUpdated"\t\t"${Math.floor((now - 4 * DAY) / 1000)}"\n\t"StateFlags"\t\t"4"\n}\n`);
    mkdirSync(join(apps, "common", dir), { recursive: true });
    await page.setContent(coverHTML(title, colors, motif));
    await page.screenshot({ path: join(cache, `${id}_library_600x900.jpg`), type: "jpeg", quality: 88 });
    local += `\t\t\t\t\t"${id}"\n\t\t\t\t\t{\n\t\t\t\t\t\t"LastPlayed"\t\t"${Math.floor((now - last) / 1000)}"\n\t\t\t\t\t\t"Playtime"\t\t"${Math.round(hours * 60)}"\n\t\t\t\t\t}\n`;
  }
  await page.close();
  writeFileSync(join(cfg, "localconfig.vdf"), `"UserLocalConfigStore"\n{\n\t"Software"\n\t{\n\t\t"Valve"\n\t\t{\n\t\t\t"Steam"\n\t\t\t{\n\t\t\t\t"apps"\n\t\t\t\t{\n${local}\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n`);
}

// ---------------------------------------------------------------- daemon

let daemon;
async function startDaemon() {
  if (!existsSync(bin)) throw new Error(`no daemon at ${bin}; build it with "CI=true make daemon"`);
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  daemon = spawn(bin, ["-data", data, "-listen", `127.0.0.1:${port}`], {
    stdio: ["ignore", "ignore", process.env.CONDUIT_LOG ? "inherit" : "ignore"],
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_DATA_HOME: join(home, ".local", "share"), CONDUIT_UPDATE_CHECK: "off" },
  });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${url}/healthz`)).ok) return url;
    } catch {
      /* not up yet */
    }
    await sleep(150);
  }
  throw new Error("the daemon didn't start");
}

let base;
async function call(token, method, path, body) {
  const r = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  let out;
  try {
    out = text ? JSON.parse(text) : null;
  } catch {
    out = text;
  }
  return { status: r.status, body: out };
}
async function must(token, method, path, body, ok = [200, 201, 202, 204]) {
  const r = await call(token, method, path, body);
  if (!ok.includes(r.status)) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body;
}

// Seconds between the phases of seeded activity, so times read "3 minutes ago".
const gap = Number(process.env.GAP ?? 61) * 1000;
const owner = { name: "Maya", email: "maya@homelab.example", password: "lantern-harbor-orbit-42" };

async function seed() {
  const token = readFileSync(join(data, "setup-token"), "utf8").trim();
  const s = await must(null, "POST", "/setup", { token, name: owner.name, email: owner.email, password: owner.password, device: "Laptop" });
  const me = s.token;

  // The vault and the secrets the connections use. Values are random and
  // never shown; only the names appear in screenshots.
  await must(me, "POST", "/vault/setup", { passphrase: "quiet copper lantern meadow" });
  const secrets = [
    ["homelab/pihole-app-password", "password", "Pi-hole app password"],
    ["homelab/home-assistant-token", "token", "Long-lived token"],
    ["homelab/jellyfin-api-key", "token", "Media server key"],
    ["homelab/proxmox-token", "token", "conduit@pve API token"],
    ["homelab/restic-repo-password", "password", "Offsite backups"],
    ["prod-eu/docker-tls-key", "ssh-key", "Docker API client key"],
    ["prod-eu/postgres-admin", "password", "Primary database"],
    ["prod-eu/stripe-restricted-key", "token", "Refunds, read-only"],
    ["team/github-deploy-token", "token", "Deploys only"],
    ["personal/router-admin", "password", "Router admin"],
    ["personal/github-2fa", "totp", "Two-factor codes"],
  ];
  for (const [name, kind, description] of secrets) {
    await must(me, "POST", "/instances/vault/actions/set", { input: { name, kind, description, value: kind === "totp" ? base32(20) : randomBytes(18).toString("base64url") } });
  }

  // Connections, each to a fake server on this computer.
  const sock = join(tmp, "docker.sock");
  await serve(homelabDocker, { socket: sock });
  const prodPort = await serve(prodDocker);
  const cert = makeCert();
  const pvePort = await serve(proxmoxFake, { tls: { key: cert.key, cert: cert.cert } });
  const haPort = await serve(haFake);
  const piPort = await serve(piholeFake);
  const jfPort = await serve(jellyfinFake);
  const kumaPort = await serve(kumaFake);
  const llmPort = await serve(llmFake);

  const mk = async (module, name, config) => (await must(me, "POST", "/instances", { module, name, config })).id;
  const ids = {};
  ids.homelab = await mk("docker", "homelab", { mode: "local", socket: sock });
  ids.prod = await mk("docker", "prod-eu", { mode: "tcp", address: `127.0.0.1:${prodPort}` });
  ids.pve = await mk("proxmox", "pve cluster", { url: `https://127.0.0.1:${pvePort}`, tokenId: "conduit@pve!conduit", tokenSecret: "secret://homelab/proxmox-token", fingerprint: cert.fingerprint });
  ids.ha = await mk("homeassistant", "Home", { url: `http://127.0.0.1:${haPort}`, token: "secret://homelab/home-assistant-token" });
  ids.pihole = await mk("pihole", "pi.hole", { url: `http://127.0.0.1:${piPort}`, password: "secret://homelab/pihole-app-password" });
  ids.jellyfin = await mk("jellyfin", "Media", { url: `http://127.0.0.1:${jfPort}`, apiKey: "secret://homelab/jellyfin-api-key" });
  ids.kuma = await mk("uptimekuma", "Status page", { url: `http://127.0.0.1:${kumaPort}`, statusPages: ["homelab"] });
  ids.games = await mk("games", "Gaming PC", {});
  llm.docker = ids.homelab.replace(/[^A-Za-z0-9_]/g, "_");
  for (const [k, id] of Object.entries(ids)) {
    const h = await must(me, "GET", `/instances/${id}/health`);
    console.log(`  ${k.padEnd(9)} ${h.status} ${h.message ?? ""}`);
  }

  // The model the built-in assistant uses: a "local" server.
  await must(me, "POST", "/ai/providers", { name: "Ollama on this computer", kind: "openai", baseUrl: `http://127.0.0.1:${llmPort}/v1`, model: "qwen3:14b", default: true });

  // People.
  await must(me, "POST", "/users", { name: "Jonas", email: "jonas@homelab.example", password: "jonas-long-first-password", role: "admin" }, [200, 201]);
  await must(me, "POST", "/users", { name: "Lea", email: "lea@homelab.example", password: "lea-long-first-password", role: "member" }, [200, 201]);

  // Agents and a program, each with its own key.
  const key = async (name, kind, scopes) => (await must(me, "POST", "/keys", { name, kind, scopes })).secret;
  const agentScopes = ["actions:*:invoke", "modules:*:read", "approvals:*:read", "audit:*:read"];
  const claude = await key("Claude Code (laptop)", "agent", agentScopes);
  const ops = await key("ops-bot", "agent", agentScopes);
  const digest = await key("Morning digest", "agent", ["actions:*:invoke", "modules:*:read"]);
  const ci = await key("deploy pipeline", "live", ["actions:docker:invoke", "modules:*:read"]);

  // Agent rules: ask before any change, plus a few exceptions.
  await must(me, "PUT", "/policy/preset", { preset: "ask-writes" });
  const policy = await must(me, "GET", "/keys?all=1");
  const keyId = (name) => policy.find((k) => k.name === name)?.id;
  const rules = [
    { subject: "kind:agent", module: "vault", action: "reveal", effect: "deny", note: "Agents never see secret values" },
    { subject: "kind:agent", module: "homeassistant", action: "call_service", effect: "deny", note: "No locks or alarms from agents" },
    { subject: `agent:${keyId("ops-bot")}`, module: "docker", instance: ids.homelab, action: "restart", effect: "allow", expiresAt: new Date(now + 6 * DAY).toISOString(), note: "While the photo stack is being tuned" },
    { subject: `agent:${keyId("Morning digest")}`, risk: "read", effect: "allow", note: "Reads for the 7:00 digest" },
    { subject: "kind:agent", module: "proxmox", risk: "destructive", effect: "ask", note: "Always ask before touching a VM" },
  ];
  for (const r of rules) await must(me, "POST", "/policy/rules", r);

  // Activity, a little at a time, from agents, a program and people.
  const act = (tok, inst, action, input = {}, extra = {}) => call(tok, "POST", `/instances/${inst}/actions/${action}`, { input, ...extra });
  await act(digest, ids.pihole, "summary");
  await act(digest, ids.ha, "entities", { domain: "sensor" });
  await act(digest, ids.kuma, "monitors");
  await act(digest, ids.pve, "guests");
  await sleep(gap);
  await act(me, "notes", "write", { name: "homelab/runbook", content: "# Runbook\n\n- Photos: immich on homelab, backups nightly at 02:00\n- DNS: pi.hole, fallback 9.9.9.9\n- Restarting paperless clears the stuck consumer\n" });
  await act(ci, ids.prod, "containers");
  await act(claude, ids.prod, "stats");
  await act(claude, ids.prod, "logs", { container: "api", lines: 50 });
  await act(claude, "vault", "reveal", { name: "prod-eu/postgres-admin" });
  await act(ops, ids.homelab, "restart", { container: "immich-ml" });
  await act(me, ids.ha, "turn_off", { entity: "light.kitchen" });
  await sleep(gap);
  // One approval decided already, so the inbox has history.
  const first = await act(ops, ids.pihole, "disable", { seconds: 300 });
  if (first.body?.approval?.id) await must(me, "POST", `/approvals/${first.body.approval.id}/deny`);
  await act(ops, ids.homelab, "stats");
  await act(claude, ids.prod, "images");
  await sleep(gap);
  // Waiting for a person now (newest first in the inbox): a coffee, a VM
  // stop and a restart in production.
  await act(claude, ids.ha, "turn_on", { entity: "switch.coffee_machine" });
  await act(ops, ids.pve, "stop", { vmid: 105 });
  await act(claude, ids.prod, "restart", { container: "api" });

  // The home board.
  await must(me, "PUT", "/me/tiles", [
    { id: "", instance: ids.pihole, action: "summary", label: "DNS blocked today", field: "percentBlocked", refresh: 300 },
    { id: "", instance: ids.ha, action: "state", input: { entity: "sensor.living_room_temperature" }, label: "Living room °C", field: "state", refresh: 300 },
    { id: "", instance: ids.ha, action: "state", input: { entity: "sensor.solar_power" }, label: "Solar now (kW)", field: "state", refresh: 300 },
    { id: "", instance: ids.homelab, action: "containers", input: { running: true }, label: "Containers running", refresh: 300 },
    { id: "", instance: ids.pve, action: "guests", label: "Proxmox guests", refresh: 600 },
  ]);
  return { me, ids };
}

// ---------------------------------------------------------------- capture

function encoder() {
  try {
    execFileSync("cwebp", ["-version"], { stdio: "ignore" });
    return (src, dst, width) => execFileSync("cwebp", ["-quiet", "-q", "85", "-m", "6", "-resize", String(width), "0", src, "-o", dst]);
  } catch {
    /* next */
  }
  for (const p of [join(root, "web", "node_modules", "sharp"), "sharp"]) {
    try {
      require.resolve(p);
      const sharpPath = p;
      return (src, dst, width) => execFileSync(process.execPath, ["-e", `require(${JSON.stringify(sharpPath)})(${JSON.stringify(src)}).resize(${width}).webp({quality:85}).toFile(${JSON.stringify(dst)})`]);
    } catch {
      /* next */
    }
  }
  return (src, dst, width) =>
    execFileSync("python3", ["-I", "-c", "import sys\nfrom PIL import Image\nim=Image.open(sys.argv[1]).convert('RGB')\nw=int(sys.argv[3])\nim=im.resize((w, round(im.height*w/im.width)), Image.LANCZOS)\nim.save(sys.argv[2],'WEBP',quality=85,method=6)", src, dst, String(width)]);
}
const toWebp = encoder();

async function shoot(page, name, width = 1600, opts = {}) {
  if (only && !only.has(name)) return;
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.evaluate(() => document.fonts.ready);
  await sleep(opts.settle ?? 600);
  const png = join(raw, `${name}.png`);
  await page.screenshot({ path: png, fullPage: false, animations: "disabled", caret: "hide" });
  toWebp(png, join(outDir, `${name}.webp`), width);
  console.log(`  docs/images/${name}.webp`);
}

async function signedIn(browser, scheme, viewport, scale) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: scale, colorScheme: scheme, baseURL: base, locale: "en-US", timezoneId: "Europe/Berlin", reducedMotion: "reduce" });
  await ctx.addInitScript(() => {
    try {
      localStorage.setItem("conduit.lang", "en");
    } catch {
      /* fine */
    }
  });
  const r = await ctx.request.post("/api/v1/auth/login", { data: { email: owner.email, password: owner.password, device: "Laptop" } });
  if (!r.ok()) throw new Error("sign-in failed: " + (await r.text()));
  return ctx;
}

async function main() {
  base = await startDaemon();
  console.log(`daemon at ${base}`);
  const browser = await chromium.launch();
  await makeSteam(browser);
  const { me, ids } = await seed();

  const desk = { width: 1440, height: 900 };
  // Light first. The home board's tiles run read actions as Maya each time
  // the overview opens, so the overview comes after the timeline.
  const ctx = await signedIn(browser, "light", desk, 2);
  const page = await ctx.newPage();
  const open = async (path, name) => {
    await page.goto(path);
    await (name ? page.getByRole("heading", { level: 1, name }) : page.getByRole("heading", { level: 1 })).waitFor();
  };

  await open("/approvals");
  await shoot(page, "approval");

  await open(`/i/${ids.homelab}`);
  if (!only || only.has("agent")) {
    await page.getByRole("button", { name: "Assistant", exact: true }).click();
    const box = page.getByPlaceholder("Ask or tell it what to do");
    await box.fill("Which containers on homelab use the most, and is anything unhealthy?");
    await box.press("Enter");
    await page.getByText("Want me to restart it?").waitFor({ timeout: 30_000 });
    await box.fill("Yes, restart paperless");
    await box.press("Enter");
    await page.getByText("waiting for your approval").last().waitFor({ timeout: 30_000 });
    await shoot(page, "agent", 1600, { settle: 1200 });
    await page.getByRole("button", { name: "Close assistant" }).click().catch(() => {});
  }

  await open("/timeline");
  await shoot(page, "audit");

  await open("/policy");
  await shoot(page, "policy");

  await open("/i/vault", "Vault");
  await shoot(page, "vault");

  await open("/modules");
  await shoot(page, "modules");

  await open("/i/standards", "Standards");
  await shoot(page, "standards");

  await open(`/i/${ids.games}`);
  await page.locator("img").first().waitFor().catch(() => {});
  await shoot(page, "games", 1600, { settle: 1500 });

  const overview = async (pg, name, width) => {
    await pg.goto("/");
    await pg.getByRole("heading", { level: 1 }).waitFor();
    await pg.locator(".tile-value").first().waitFor();
    await sleep(2500); // tiles and lamps settle
    await shoot(pg, name, width, { settle: 800 });
  };
  await overview(page, "home", 1600);
  await ctx.close();

  const dark = await signedIn(browser, "dark", desk, 2);
  await overview(await dark.newPage(), "home-dark", 1600);
  await dark.close();

  const phone = await signedIn(browser, "light", { width: 390, height: 844 }, 3);
  await overview(await phone.newPage(), "phone", 780);
  await phone.close();
  await browser.close();
}

let failed = false;
try {
  await main();
} catch (e) {
  failed = true;
  console.error(e);
} finally {
  daemon?.kill("SIGTERM");
  for (const s of servers) s.close();
  await sleep(300);
  if (keep) console.log(`kept ${tmp}`);
  else rmSync(tmp, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
