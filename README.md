<div align="center">

# 🛡️ VPN-panel

**Manage your VPN server from a single screen**

AmneziaWG&nbsp;·&nbsp;XRay (VLESS — TLS / Reality)&nbsp;·&nbsp;mtg (MTProto)

[![Platform](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Backend](https://img.shields.io/badge/backend-Flask-000000?logo=flask&logoColor=white)](https://byfox.dev/awg-panel/)
[![Database](https://img.shields.io/badge/database-none%20·%20JSON-6c6c6c)](https://byfox.dev/awg-panel/)
[![i18n](https://img.shields.io/badge/i18n-EN%20%2F%20RU-1f6feb)](https://byfox.dev/awg-panel/)
[![AmneziaWG](https://img.shields.io/badge/AmneziaWG-WireGuard-88171a)](https://byfox.dev/awg-panel/)
[![XRay](https://img.shields.io/badge/XRay-VLESS%20·%20Reality-f40612)](https://byfox.dev/awg-panel/)
[![MTProto](https://img.shields.io/badge/Telegram-MTProto%20·%20mtg-26a5e4?logo=telegram&logoColor=white)](https://byfox.dev/awg-panel/)

### [🌐 Website](https://byfox.dev/awg-panel/) · [⬇️ Download](https://byfox.dev/data/awg-panel/awg-panel.zip) · [🇷🇺 Русский](README.ru.md)

<img src="https://byfox.dev/awg-panel/img/awg-panel-overview-en.png" alt="VPN-panel overview" width="860">

</div>

---

**VPN-panel** is a lightweight web panel that brings management of three VPN/proxy protocols into a single interface: **AmneziaWG**, **XRay (VLESS over TLS or Reality)** and **mtg (MTProto proxy for Telegram)**. Built on Flask and vanilla JavaScript, with **no database** — all state lives in plain JSON files next to the app.

One screen for everything: clients, links and QR codes, traffic limits and schedules, connection logs, updates and backups.

> 📥 **Files are not hosted in this repo.** Grab the ready-made archive directly — [byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip) — or visit the project site: [byfox.dev/awg-panel](https://byfox.dev/awg-panel/).

## ✨ Features

- **AWG / XRay / mtg clients** — create, delete, share links and QR codes, traffic limits and schedule, online status.
- **XRay in TLS and Reality modes** — ready-made configs for **Shadowrocket / Loon / Clash** with routing rule sets (built-in blackmatrix7 lists + your own).
- **Connection logs** — IP, geo, domains, traffic stats, deduplication and grouping by organization.
- **Global routing rules** — server-side routing for all VLESS, list / via / direct modes, applied with one button.
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

## 📸 Screenshots

| Overview | Routing templates |
|---|---|
| [![Overview](https://byfox.dev/awg-panel/img/awg-panel-overview.png)](https://byfox.dev/awg-panel/img/awg-panel-overview.png) | [![Templates](https://byfox.dev/awg-panel/img/awg-panel-templates.png)](https://byfox.dev/awg-panel/img/awg-panel-templates.png) |
| **Connection logs** | **MTProto** |
| [![Logs](https://byfox.dev/awg-panel/img/awg-panel-logs.png)](https://byfox.dev/awg-panel/img/awg-panel-logs.png) | [![MTProto](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png)](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png) |
| **Settings** | **Traffic schedule** |
| [![Settings](https://byfox.dev/awg-panel/img/awg-panel-settings.png)](https://byfox.dev/awg-panel/img/awg-panel-settings.png) | [![Schedule](https://byfox.dev/awg-panel/img/awg-panel-schedule.png)](https://byfox.dev/awg-panel/img/awg-panel-schedule.png) |

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

<sub>Keywords: VPN panel, AmneziaWG, WireGuard, XRay, VLESS, Reality, MTProto, mtg, Shadowrocket, Clash, Loon, VPN server, anti-censorship, censorship circumvention, proxy, self-hosted, Flask.</sub>

</div>
