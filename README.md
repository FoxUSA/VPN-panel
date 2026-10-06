<div align="center">

# 🛡️ VPN-panel

**A web panel to administer your own VPN server.**

Users, access rules, ready-made rule templates, logs and stats — in one browser window.

[![Platform](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Self-hosted](https://img.shields.io/badge/self--hosted-free-2ea043)](https://byfox.dev/awg-panel/)
[![i18n](https://img.shields.io/badge/UI-EN%20%2F%20RU-1f6feb)](https://byfox.dev/awg-panel/)

### [⬇️ Download](https://byfox.dev/data/awg-panel/awg-panel.zip) · [🌐 Website](https://byfox.dev/awg-panel/) · [🇷🇺 Русский](README.ru.md)

</div>

<p align="center">
<a href="https://byfox.dev/awg-panel/img/awg-panel-overview.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-overview.png" height="140" alt="overview"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-client-card.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-client-card.png" height="140" alt="client-card"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-config.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-config.png" height="140" alt="config"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-settings.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-settings.png" height="140" alt="settings"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-logs.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-logs.png" height="140" alt="logs"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-templates.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-templates.png" height="140" alt="templates"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-schedule.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-schedule.png" height="140" alt="schedule"></a>
<a href="https://byfox.dev/awg-panel/img/awg-panel-monitoring.png"><img src="https://byfox.dev/awg-panel/img/awg-panel-monitoring.png" height="140" alt="monitoring"></a>
</p>

Installs on your VPS and replaces hand-editing configs over SSH. You add users, decide who may do what, and see where they go. The user gets a QR code or a link — and it just works.

- **VPN users** — add, disable, delete, set a traffic limit or an expiry date, hand out the config by QR.
- **Flexible permissions** — every user has their own rules: what goes through the VPN, what goes direct, what is blocked.
- **Ready-made rule templates** — hundreds of services and countries, picked by search, updated automatically.
- **Logs & stats** — traffic, online status, where the user goes — with geo for every IP.
- **Cascade through a second VPN** — the server itself can reach the internet through another VPN, for the services you choose.
- **Protocols with one click** — AmneziaWG, XRay, Hysteria 2 and MTProto are installed and updated from the panel. Hysteria 2 also runs inside XRay, and with core 26.9.30 — XDNS: VLESS over a DNS tunnel for networks where only DNS gets through.

## Install

1. Unpack the [archive](https://byfox.dev/data/awg-panel/awg-panel.zip) to `/opt/awg-panel/`
2. Start the service
3. Open the panel — it creates the password itself

Debian/Ubuntu. Step-by-step guide inside the archive: `install_interactive.html`.

---

<div align="center">
<sub>VPN panel · AmneziaWG · WireGuard · XRay · VLESS · Reality · Hysteria2 · XDNS · MTProto · Shadowrocket · Loon · Clash · self-hosted</sub>
</div>
