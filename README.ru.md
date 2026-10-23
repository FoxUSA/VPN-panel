<div align="center">

# 🛡️ VPN-panel

**Веб-панель для администрирования своего VPN-сервера.**

Пользователи, права доступа, готовые шаблоны правил, логи и статистика — в одном окне браузера.

[![Platform](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Self-hosted](https://img.shields.io/badge/self--hosted-free-2ea043)](https://byfox.dev/awg-panel/)
[![i18n](https://img.shields.io/badge/UI-RU%20%2F%20EN-1f6feb)](https://byfox.dev/awg-panel/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

### [⬇️ Скачать](https://byfox.dev/data/awg-panel/awg-panel.zip) · [▶️ Демо](https://byfox.dev/awg-panel/demo/?lang=ru) · [🌐 Сайт](https://byfox.dev/awg-panel/) · [🇬🇧 English](README.md)

</div>

Ставится на ваш VPS и заменяет ручную правку конфигов по SSH. Вы заводите пользователей, решаете, кому что можно, и видите, кто куда ходит. Пользователь получает QR-код или ссылку — и всё работает.

- **Пользователи VPN** — добавить, отключить, удалить, поставить лимит трафика или срок, выдать конфиг по QR.
- **Гибкие разрешения** — у каждого пользователя свои правила: что идёт через VPN, что напрямую, что заблокировано.
- **Готовые шаблоны правил** — сотни сервисов и страны, выбираются поиском, обновляются сами.
- **Логи и статистика** — трафик, онлайн, куда ходит пользователь — с гео по каждому IP.
- **Каскад через второй VPN** — сам сервер может выходить в интернет через другой VPN — для нужных сервисов.
- **Протоколы кнопкой** — AmneziaWG, XRay, Hysteria 2 и MTProto ставятся и обновляются из панели. Hysteria 2 работает и внутри XRay, а с ядром 26.9.30 — XDNS: VLESS через DNS-туннель, когда открыт только DNS. Telegram WEB-прокси — Telegram через обычный HTTPS на вашем домене.

## Установка

1. Распаковать [архив](https://byfox.dev/data/awg-panel/awg-panel.zip) в `/opt/awg-panel/`
2. Запустить сервис
3. Открыть панель — пароль она создаст сама

Debian/Ubuntu. Пошаговая инструкция — в архиве: `install_interactive.html`.

## Исходный код и лицензия

[Архив](https://byfox.dev/data/awg-panel/awg-panel.zip) — **это и есть исходный код**: Python (Flask) и чистый JavaScript, без сборки и компиляции. Распакуйте и читайте всё, что выполняет панель.

Лицензия — [GNU AGPL-3.0](LICENSE) (или любая более поздняя версия): пользоваться, изучать и менять можно свободно; кто распространяет изменённую панель или даёт другим пользоваться ею по сети, обязан открыть свои изменения на тех же условиях.

---

<div align="center">
<sub>VPN-панель · AmneziaWG · WireGuard · XRay · VLESS · Reality · Hysteria2 · XDNS · MTProto · Telegram WEB-прокси · Shadowrocket · Loon · Clash · self-hosted</sub>
</div>
