<div align="center">

# 🛡️ VPN-panel

**A web panel to administer your own VPN server.**

Users, access rules, ready-made rule templates, logs and stats — in one browser window.

[![Platform](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Self-hosted](https://img.shields.io/badge/self--hosted-free-2ea043)](https://byfox.dev/awg-panel/)
[![i18n](https://img.shields.io/badge/UI-EN%20%2F%20RU-1f6feb)](https://byfox.dev/awg-panel/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

### [⬇️ Download](https://byfox.dev/data/awg-panel/awg-panel.zip) · [▶️ Live demo](https://byfox.dev/awg-panel/demo/?lang=en) · [🌐 Website](https://byfox.dev/awg-panel/) · [🇷🇺 Русский](README.ru.md)

</div>

Installs on your VPS and replaces hand-editing configs over SSH. You add users, decide who may do what, and see where they go. The user gets a QR code or a link — and it just works.

- **VPN users** — add, disable, delete, set a traffic limit or an expiry date, hand out the config by QR.
- **Flexible permissions** — every user has their own rules: what goes through the VPN, what goes direct, what is blocked.
- **Ready-made rule templates** — hundreds of services and countries, picked by search, updated automatically.
- **Logs & stats** — traffic, online status, where the user goes — with geo for every IP.
- **Cascade through a second VPN** — the server itself can reach the internet through another VPN, for the services you choose.
- **Protocols with one click** — AmneziaWG, XRay, Hysteria 2 and MTProto are installed and updated from the panel. Hysteria 2 also runs inside XRay, and with core 26.9.30 — XDNS: VLESS over a DNS tunnel for networks where only DNS gets through. Telegram WEB proxy — Telegram over ordinary HTTPS on your domain.

## Install

1. Unpack the [archive](https://byfox.dev/data/awg-panel/awg-panel.zip) to `/opt/awg-panel/`
2. Start the service
3. Open the panel — it creates the password itself

Debian/Ubuntu. Step-by-step guide inside the archive: `install_interactive.html`.

## Source code & license

The [archive](https://byfox.dev/data/awg-panel/awg-panel.zip) **is the source code** — Python (Flask) and vanilla JavaScript, no build or compilation step. Unpack it and read everything the panel runs.

Licensed under the [GNU AGPL-3.0](LICENSE) (or any later version): use, study and modify freely; if you distribute a modified panel or let others use it over a network, publish your changes under the same terms.

---

<div align="center">
<sub>VPN panel · AmneziaWG · WireGuard · XRay · VLESS · Reality · Hysteria2 · XDNS · MTProto · Telegram WEB proxy · Shadowrocket · Loon · Clash · self-hosted</sub>
</div>
