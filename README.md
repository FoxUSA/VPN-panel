<div align="center">

# 🛡️ VPN-panel

**Manage your VPN server from a single screen**

AmneziaWG&nbsp;·&nbsp;XRay (VLESS — TLS / Reality)&nbsp;·&nbsp;mtg (MTProto)&nbsp;·&nbsp;Hysteria 2&nbsp;·&nbsp;Mihomo cascade

[![Platform](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Backend](https://img.shields.io/badge/backend-Flask-000000?logo=flask&logoColor=white)](https://byfox.dev/awg-panel/)
[![Database](https://img.shields.io/badge/database-none%20·%20JSON-6c6c6c)](https://byfox.dev/awg-panel/)
[![i18n](https://img.shields.io/badge/i18n-EN%20%2F%20RU-1f6feb)](https://byfox.dev/awg-panel/)
[![AmneziaWG](https://img.shields.io/badge/AmneziaWG-WireGuard-88171a)](https://byfox.dev/awg-panel/)
[![XRay](https://img.shields.io/badge/XRay-VLESS%20·%20Reality-f40612)](https://byfox.dev/awg-panel/)
[![MTProto](https://img.shields.io/badge/Telegram-MTProto%20·%20mtg-26a5e4?logo=telegram&logoColor=white)](https://byfox.dev/awg-panel/)
[![Hysteria2](https://img.shields.io/badge/Hysteria-2-ff6b35)](https://byfox.dev/awg-panel/)
[![Mihomo](https://img.shields.io/badge/Mihomo-Clash.Meta%20cascade-2ea043)](https://byfox.dev/awg-panel/)

### [🌐 Website](https://byfox.dev/awg-panel/) · [⬇️ Download](https://byfox.dev/data/awg-panel/awg-panel.zip) · [🇷🇺 Русский](README.ru.md)

<img src="https://byfox.dev/awg-panel/img/awg-panel-overview-en.png" alt="VPN-panel overview" width="860">

</div>

---

**VPN-panel** is a lightweight web panel that brings management of four VPN/proxy protocols into a single interface: **AmneziaWG**, **XRay (VLESS over TLS or Reality)**, **mtg (MTProto proxy for Telegram)** and **Hysteria 2**. Built on Flask and vanilla JavaScript, with **no database** — all state lives in plain JSON files next to the app.

One screen for everything: clients, links and QR codes, traffic limits and schedules, connection logs, updates and backups. The server can also be cascaded through a second VPN, routing its clients by clash rules.

> 📥 **Files are not hosted in this repo.** Grab the ready-made archive directly — [byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip) — or visit the project site: [byfox.dev/awg-panel](https://byfox.dev/awg-panel/).

## ✨ Features

- **AWG / XRay / mtg / Hysteria 2 clients** — create, delete, share links and QR codes, traffic limits and schedule, online status.
- **Protocol installation from the panel** — XRay, mtg and Hysteria 2 are installed with a button: the panel drops the binary, generates the config, picks a free port and opens it in the firewall (AmneziaWG is manual — it's a kernel module).
- **XRay in TLS and Reality modes** — ready-made configs for **Shadowrocket / Loon / Clash** with routing rule sets (built-in blackmatrix7 lists + your own).
- **Connection logs** — IP, geo, domains, traffic stats, deduplication and grouping by organization.
- **Global routing rules** — server-side routing for all VLESS, list / via / direct modes, applied with one button.
- **Cascade through a second VPN** — a built-in **Mihomo (Clash.Meta)** engine makes the server a client of another VPN: listed traffic goes out through it, everything else leaves directly.
- **Per-client DNS** — encrypted DNS (DoH / DoH3 / DoQ) written straight into the Shadowrocket / Loon / Clash profile: ready-made templates or your own resolver, applied to one client or to all at once. The server's own resolver is set separately.
- **IP filtering** — per-client allow and block lists of addresses and subnets; the rule lives in the server routing, nothing is written into the client config.
- **External monitoring** — a companion utility on another server watches this one from the outside: XRay/MTProto ports, speed, uptime history and a public status page.
- **Login masking** — the panel hides behind an ordinary decoy website (fake landing).
- **Backups & automatic dependency check** — a checklist of server settings with auto-fixes.
- **In-UI updates** — XRay, mtg and the panel itself update via manifest; protocol versions are tracked.
- **Admin audit log** — logins, settings and client changes.
- **Bilingual UI (EN / RU)** — language auto-detected on login, 🌐 toggle, live translation with no reload.

## 🔌 Supported protocols

| Protocol | Modes | Clients |
|---|---|---|
| **AmneziaWG** | obfuscated WireGuard | official AmneziaWG apps |
| **XRay / VLESS** | TLS, Reality | Shadowrocket, Loon, Clash |
| **mtg / MTProto** | Telegram proxy | Telegram (any client) |
| **Hysteria 2** | QUIC-based, obfuscated | Shadowrocket, Clash/Mihomo (Loon via a manual profile line) |
| **Mihomo (Clash.Meta)** | cascade — the server as a client of a second VPN | upstream: VLESS, VMess, Trojan, SS, Hysteria2, Hysteria, TUIC, AnyTLS |

## 🔗 Cascade through a second VPN

The panel can install and manage a **Mihomo (Clash.Meta)** engine, turning the server itself into a client of *another* VPN. Traffic from your XRay and MTProto clients is then routed by clash rules coming from that second server: whatever the rules list goes out through the second VPN, everything else leaves directly from this server's own IP.

- **No iptables, no TUN.** Traffic reaches the engine only because XRay and mtg point at its local SOCKS port — the server's own traffic never touches it, so panel and SSH access cannot be lost by switching the cascade on.
- **Profiles** — a whole clash config, a subscription link, or plain node links: `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `hysteria`, `tuic`, `anytls` (a base64 subscription blob works too). Everything pasted is parsed and shown before it is saved. Several profiles can be stored, one is active.
- **Safe mode** — a dead-man's switch rather than a lock: you start the engine, get a five-minute window to check that everything still works, and if the server gets blocked or contact is lost, the panel detaches the cascade, stops the engine and disables autostart on its own.
- **Watchdog** — if the engine goes silent, the cascade is removed from the configs automatically instead of leaving clients pointed at a dead socket.
- A dedicated **Mihomo** tab shows the link to the second VPN with latency and cumulative traffic, the rules received from it, node switching and per-service cascade switches.

## 🩺 External monitoring

A separate lightweight utility is installed on **another** server — ideally in the country your users connect from — and watches this one from the outside. Download: **[byfox.dev/data/awg-panel/monitoring.zip](https://byfox.dev/data/awg-panel/monitoring.zip)**

- **Ports** — TCP checks of XRay and MTProto with retries and a debounce, so a single lost SYN never raises a false alarm. The ports are pulled from the panel itself over a token-protected probe API, so they can't go stale after a change on the server.
- **Speed** — down and up measurement against the panel, with presets that trade traffic for resolution: from *availability only* (zero traffic) to a dense debug mode. Every measurement's cost is shown before you save.
- **History** — per-server uptime bars, an outage log with durations, all in SQLite next to the utility.
- **Two faces** — a public status page for your users and a password-protected admin area for you. Nothing you type lives in the code: password, servers and settings sit in `data/` and survive updates, which the utility applies to itself from the same CDN.

## 📸 Screenshots

| Overview | Routing templates |
|---|---|
| [![Overview](https://byfox.dev/awg-panel/img/awg-panel-overview.png)](https://byfox.dev/awg-panel/img/awg-panel-overview.png) | [![Templates](https://byfox.dev/awg-panel/img/awg-panel-templates.png)](https://byfox.dev/awg-panel/img/awg-panel-templates.png) |
| **Connection logs** | **MTProto** |
| [![Logs](https://byfox.dev/awg-panel/img/awg-panel-logs.png)](https://byfox.dev/awg-panel/img/awg-panel-logs.png) | [![MTProto](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png)](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png) |
| **Settings** | **Traffic schedule** |
| [![Settings](https://byfox.dev/awg-panel/img/awg-panel-settings.png)](https://byfox.dev/awg-panel/img/awg-panel-settings.png) | [![Schedule](https://byfox.dev/awg-panel/img/awg-panel-schedule.png)](https://byfox.dev/awg-panel/img/awg-panel-schedule.png) |
| **External monitoring** | **Client config** |
| [![Monitoring](https://byfox.dev/awg-panel/img/awg-panel-monitoring.png)](https://byfox.dev/awg-panel/img/awg-panel-monitoring.png) | [![Config](https://byfox.dev/awg-panel/img/awg-panel-config.png)](https://byfox.dev/awg-panel/img/awg-panel-config.png) |
| **Client card** | |
| [![Client card](https://byfox.dev/awg-panel/img/awg-panel-client-card.png)](https://byfox.dev/awg-panel/img/awg-panel-client-card.png) | |

## 🚀 Installation

A step-by-step interactive guide — open **`install_interactive.html`** from the archive in a browser: TLS and Reality modes, with every command generated for your own data (bilingual).

Full package archive: **[byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip)**

## 🔄 Updates

The panel checks its own version and updates its code via `manifest.json` (button in the footer). Per-server data — `server.json`, `admin.json`, clients and the `data/` folder — is **left untouched** by updates.

## 🌍 Geo & logs

**MaxMind GeoLite2** databases (City/ASN) are downloaded automatically and version-checked roughly every 180 days. Connection logs show IP, country/city and domains with deduplication.

## 🌐 Languages (i18n)

Translation runs on the client: Russian is the source, the engine translates the visible text into EN on the fly. Language is auto-detected on login, with a 🌐 toggle and no page reload.

## 📦 Package layout

- `app.py` — backend (Flask)
- `static/` — UI (`index.html` + `app.js`), localization engine and log pages
- `install_interactive.html` — interactive install guide (bilingual)
- `manifest.json` — panel version + geo database version
- `data/` — geo databases and logs; created by the panel on the server

---

<div align="center">

**Download:** [byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip) &nbsp;·&nbsp; **Website:** [byfox.dev/awg-panel](https://byfox.dev/awg-panel/)

<sub>Keywords: VPN panel, AmneziaWG, WireGuard, XRay, VLESS, Reality, MTProto, mtg, Mihomo, Clash.Meta, Hysteria2, TUIC, VPN cascade, Shadowrocket, Clash, Loon, DNS-over-HTTPS, DoH, DoH3, DoQ, IP allowlist, uptime monitoring, status page, VPN server, anti-censorship, censorship circumvention, proxy, self-hosted, Flask.</sub>

</div>
