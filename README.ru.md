<div align="center">

# 🛡️ VPN-panel

**Веб-панель управления VPN-сервером на одном экране**

AmneziaWG&nbsp;·&nbsp;XRay (VLESS — TLS / Reality)&nbsp;·&nbsp;mtg (MTProto)

[![Платформа](https://img.shields.io/badge/platform-Linux-2b2b2b)](https://byfox.dev/awg-panel/)
[![Бэкенд](https://img.shields.io/badge/backend-Flask-000000?logo=flask&logoColor=white)](https://byfox.dev/awg-panel/)
[![База данных](https://img.shields.io/badge/database-none%20·%20JSON-6c6c6c)](https://byfox.dev/awg-panel/)
[![Языки](https://img.shields.io/badge/i18n-RU%20%2F%20EN-1f6feb)](https://byfox.dev/awg-panel/)
[![AmneziaWG](https://img.shields.io/badge/AmneziaWG-WireGuard-88171a)](https://byfox.dev/awg-panel/)
[![XRay](https://img.shields.io/badge/XRay-VLESS%20·%20Reality-f40612)](https://byfox.dev/awg-panel/)
[![MTProto](https://img.shields.io/badge/Telegram-MTProto%20·%20mtg-26a5e4?logo=telegram&logoColor=white)](https://byfox.dev/awg-panel/)

### [🌐 Сайт проекта](https://byfox.dev/awg-panel/) · [⬇️ Скачать архив](https://byfox.dev/data/awg-panel/awg-panel.zip) · [🇬🇧 English](README.md)

<img src="https://byfox.dev/awg-panel/img/awg-panel-overview.png" alt="Обзор VPN-panel" width="860">

</div>

---

**VPN-panel** — это лёгкая веб-панель, которая собирает управление сразу тремя VPN/прокси-протоколами в одном интерфейсе: **AmneziaWG**, **XRay (VLESS на TLS или Reality)** и **mtg (MTProto-прокси для Telegram)**. Написана на Flask и ванильном JavaScript, **без базы данных** — всё состояние хранится в обычных JSON-файлах рядом с приложением.

Один экран — клиенты, ссылки и QR-коды, лимиты и расписание трафика, логи подключений, обновления и бэкапы.

> 📥 **Файлы здесь не выкладываются.** Скачивайте готовый архив напрямую — [byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip) — или заходите на сайт проекта: [byfox.dev/awg-panel](https://byfox.dev/awg-panel/).

## ✨ Возможности

- **Клиенты AWG / XRay / mtg** — добавление, удаление, ссылки и QR-коды, лимиты и расписание трафика, онлайн-статус.
- **XRay в режимах TLS и Reality** — готовые конфиги для **Shadowrocket / Loon / Clash** с наборами правил маршрутизации (готовые списки blackmatrix7 + свои).
- **Логи подключений** — IP, гео, домены, статистика трафика, дедупликация и группировка по организациям.
- **Глобальные правила маршрутизации** — серверный роутинг для всех VLESS, режимы списков/via/direct, применение по кнопке.
- **Маскировка входа** — панель прячется за обычным сайтом-витриной (fake landing).
- **Бэкапы и авто-проверка зависимостей** — чек-лист настроек сервера с автофиксами.
- **Обновления из интерфейса** — XRay, mtg и сама панель обновляются по манифесту; отслеживание версий протоколов.
- **Журнал действий администратора** — входы, изменения настроек и клиентов.
- **Двуязычный интерфейс RU / EN** — авто-определение языка при входе, переключатель 🌐, перевод на лету без перезагрузки.

## 🔌 Поддерживаемые протоколы

| Протокол | Режимы | Клиенты |
|---|---|---|
| **AmneziaWG** | обфусцированный WireGuard | официальные клиенты AmneziaWG |
| **XRay / VLESS** | TLS, Reality | Shadowrocket, Loon, Clash |
| **mtg / MTProto** | Telegram-прокси | Telegram (любой клиент) |

## 📸 Скриншоты

| Обзор | Шаблоны правил |
|---|---|
| [![Обзор](https://byfox.dev/awg-panel/img/awg-panel-overview.png)](https://byfox.dev/awg-panel/img/awg-panel-overview.png) | [![Шаблоны](https://byfox.dev/awg-panel/img/awg-panel-templates.png)](https://byfox.dev/awg-panel/img/awg-panel-templates.png) |
| **Логи подключений** | **MTProto** |
| [![Логи](https://byfox.dev/awg-panel/img/awg-panel-logs.png)](https://byfox.dev/awg-panel/img/awg-panel-logs.png) | [![MTProto](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png)](https://byfox.dev/awg-panel/img/awg-panel-mtproto.png) |
| **Настройки** | **Расписание трафика** |
| [![Настройки](https://byfox.dev/awg-panel/img/awg-panel-settings.png)](https://byfox.dev/awg-panel/img/awg-panel-settings.png) | [![Расписание](https://byfox.dev/awg-panel/img/awg-panel-schedule.png)](https://byfox.dev/awg-panel/img/awg-panel-schedule.png) |

## 🚀 Установка

Пошаговый интерактивный гайд — открой **`install_interactive.html`** из архива в браузере: режимы TLS и Reality, все команды генерируются под твои данные (двуязычный).

Готовый архив всего пакета: **[byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip)**

## 🔄 Обновления

Панель сама проверяет версию и обновляет код по `manifest.json` (кнопка в подвале). Данные конкретного сервера — `server.json`, `admin.json`, клиенты и папка `data/` — обновление **не трогает**.

## 🌍 Гео и логи

Базы **MaxMind GeoLite2** (City/ASN) панель качает автоматически и сверяет версию раз в ~180 дней. Логи подключений показывают IP, страну/город и домены с дедупликацией.

## 🌐 Языки (i18n)

Перевод выполняется на клиенте: русский — источник, движок переводит видимый текст в EN на лету. Авто-определение языка при входе и переключатель 🌐 без перезагрузки страницы.

## 📦 Состав пакета

- `app.py` — бэкенд (Flask)
- `static/` — интерфейс (`index.html` + `app.js`), движок локализации и страницы логов
- `install_interactive.html` — интерактивная инструкция установки (двуязычная)
- `manifest.json` — версия панели + версия гео-баз
- `data/` — гео-базы и логи; создаётся панелью на сервере

---

<div align="center">

**Скачать:** [byfox.dev/data/awg-panel/awg-panel.zip](https://byfox.dev/data/awg-panel/awg-panel.zip) &nbsp;·&nbsp; **Сайт:** [byfox.dev/awg-panel](https://byfox.dev/awg-panel/)

<sub>Ключевые слова: VPN-панель, AmneziaWG, WireGuard, XRay, VLESS, Reality, MTProto, mtg, Shadowrocket, Clash, Loon, VPN-сервер, обход блокировок, анти-цензура, прокси, self-hosted, Flask.</sub>

</div>
