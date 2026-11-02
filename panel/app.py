#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 byFox (https://byfox.dev). Full text: LICENSE.
# Additional term under AGPL section 7(b): keep the author attribution, see NOTICE.
import os
import subprocess
import json
import hashlib
import hmac
import secrets
import time
import re
import base64
import gzip
import glob
import shutil
import urllib.request
import uuid as uuid_lib
import threading
import datetime
import io
import ipaddress
import socket
import zipfile
from collections import deque
from urllib.parse import quote, unquote, urlsplit, parse_qs
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session, Response, redirect
# Чистые хелперы ссылок и yaml — вынесены в proxy_links.py. Импортируем именами,
# чтобы все вызовы в коде ниже остались нетронутыми.
from modules.proxy_links import (
    _yaml_top_sections, _yaml_scalar, _yaml_lines, _yaml_proxy,
    _b64text, _uhost, _uport, _q, _truthy, _alpn_list, _mihomo_transport,
    _link_vless, _link_vmess, _link_trojan, _link_ss,
    _link_hy2, _link_hy1, _link_tuic, _link_anytls,
)

app = Flask(__name__, static_folder='static')

# === Panel version & update source ===
# Версия панели больше НЕ хардкодится в коде — она живёт в manifest.json
# (поле version) и читается из локального манифеста ниже (после MANIFEST_FILE).
# Обновление: качаем весь awg-panel.zip (внутри — копия манифеста), а сам
# manifest.json остаётся доступен и отдельным файлом на CDN для дешёвой проверки.
UPDATE_BASE_URL = 'https://byfox.dev/data/awg-panel/'
UPDATE_ZIP_URL = UPDATE_BASE_URL.rstrip('/') + '/awg-panel.zip'
GEO_BASE_URL = 'https://byfox.dev/data/maxmind/'
GEO_FILES = {
    # local-filename: remote-filename — keep local names as panel was built around them
    'GeoLite2-City.mmdb': 'GeoLite2-City.mmdb',
    'GeoLite2-ASN.mmdb':  'GeoLite2-ASN.mmdb',
}

# === Config files ===
AWG_CONFIG = '/etc/amnezia/amneziawg/awg0.conf'
AWG_BIN = '/usr/bin/awg'
AWG_QUICK_BIN = '/usr/bin/awg-quick'
# Пути пользовательских данных (CLIENTS_DB, SERVER_CONFIG_FILE, ADMIN_FILE,
# SECRET_KEY_FILE, AUDIT_LOG_FILE) — ниже, в блоке раскладки: они считаются от
# DATA_*_DIR, а те определены после PANEL_ROOT.
# manifest.json — только версия панели и дата релиза. Поле files больше не нужно:
# апдейтер накатывает весь архив (см. _do_panel_update). Даты/периоды/свитчи гео и
# blackmatrix7 живут в server.json, чтобы обновление кода (manifest приходит из zip) их не затирало.
MANIFEST_FILE = '/opt/awg-panel/manifest.json'

def _local_manifest():
    """Локальный manifest.json как dict (пусто при отсутствии/битом)."""
    try:
        with open(MANIFEST_FILE, 'r') as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}

# Версия и дата релиза панели — из локального манифеста, не из константы.
PANEL_VERSION = str(_local_manifest().get('version') or '0.0.0')
PANEL_RELEASED = str(_local_manifest().get('released') or '')

# === Auto-detected paths (work regardless of where panel is installed) ===
PANEL_ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(PANEL_ROOT, 'static')
PUBLIC_DIR = os.path.join(PANEL_ROOT, 'public')

# === Раскладка хранилища ===
# Правило: в корне панели живёт только код (ровно то, что приезжает в awg-panel.zip),
# всё пользовательское — под data/. Апдейтер заменяет папки из архива целиком, но
# data/ пропускает (_UPDATE_SKIP_TOP), поэтому данные там переживают любое обновление.
# Переезд идёт фазами: каждая фаза добавляет пары в MIGRATION_MAP и переключает
# соответствующие константы на новые пути.
DATA_DIR = os.path.join(PANEL_ROOT, 'data')
DATA_AWG_DIR = os.path.join(DATA_DIR, 'awg')
DATA_XRAY_DIR = os.path.join(DATA_DIR, 'xray')
DATA_MTPROTO_DIR = os.path.join(DATA_DIR, 'mtproto')
DATA_MIHOMO_DIR = os.path.join(DATA_DIR, 'mihomo')
DATA_GEO_DIR = os.path.join(DATA_DIR, 'geo_rules')
DATA_LOGS_DIR = os.path.join(DATA_DIR, 'logs')

# (старый путь → новый путь). Пополняется по фазам переезда.
MIGRATION_MAP = [
    # Фаза 1 — XRay. Префикс xray_ в именах не нужен: его несёт папка.
    (os.path.join(PANEL_ROOT, 'xray_clients.json'),       os.path.join(DATA_XRAY_DIR, 'clients.json')),
    (os.path.join(PANEL_ROOT, 'xray_rule_lists.json'),    os.path.join(DATA_XRAY_DIR, 'rule_lists.json')),
    (os.path.join(PANEL_ROOT, 'xray_global.json'),        os.path.join(DATA_XRAY_DIR, 'global.json')),
    (os.path.join(PANEL_ROOT, 'xray_global_cache.json'),  os.path.join(DATA_XRAY_DIR, 'global_cache.json')),
    (os.path.join(PANEL_ROOT, 'xray_global_totals.json'), os.path.join(DATA_XRAY_DIR, 'global_totals.json')),
    (os.path.join(PANEL_ROOT, 'xray_last_ips.json'),      os.path.join(DATA_XRAY_DIR, 'last_ips.json')),
    # Фаза 2 — AmneziaWG
    (os.path.join(PANEL_ROOT, 'clients.json'),            os.path.join(DATA_AWG_DIR, 'clients.json')),
    (os.path.join(PANEL_ROOT, 'awg_totals.json'),         os.path.join(DATA_AWG_DIR, 'totals.json')),
    # Фаза 3 — ядро панели
    (os.path.join(PANEL_ROOT, 'server.json'),             os.path.join(DATA_DIR, 'server.json')),
    (os.path.join(PANEL_ROOT, 'admin.json'),              os.path.join(DATA_DIR, 'admin.json')),
    (os.path.join(PANEL_ROOT, 'secret.key'),              os.path.join(DATA_DIR, 'secret.key')),
    # Фаза 4 — журнал действий (вместе с собственными ротациями .1….5)
    (os.path.join(PANEL_ROOT, 'audit.log'),               os.path.join(DATA_LOGS_DIR, 'audit.log')),
    # Фаза 5 — гео-базы и источники правил. os.replace умеет переносить и папки,
    # если целевой ещё нет; когда она есть — пара пропускается, как и для файлов.
    (os.path.join(DATA_DIR, 'GeoLite2-City.mmdb'),        os.path.join(DATA_GEO_DIR, 'GeoLite2-City.mmdb')),
    (os.path.join(DATA_DIR, 'GeoLite2-ASN.mmdb'),         os.path.join(DATA_GEO_DIR, 'GeoLite2-ASN.mmdb')),
    (os.path.join(DATA_DIR, 'GeoLite2-Country.mmdb'),     os.path.join(DATA_GEO_DIR, 'GeoLite2-Country.mmdb')),
    (os.path.join(DATA_DIR, 'countries_src'),             os.path.join(DATA_GEO_DIR, 'countries_src')),
    (os.path.join(DATA_DIR, 'countries'),                 os.path.join(DATA_GEO_DIR, 'countries')),
    (os.path.join(PANEL_ROOT, 'blackmatrix7_templates.json'), os.path.join(DATA_GEO_DIR, 'blackmatrix7_templates.json')),
    (os.path.join(PANEL_ROOT, 'byfox_rules.json'),        os.path.join(DATA_GEO_DIR, 'byfox_rules.json')),
    # Фаза 6 — каскад (mihomo). Оба файла раньше вычислялись от dirname(CLIENTS_DB)
    # и от корня панели: после переезда клиентской базы в data/awg/ профили
    # каскада остались бы лежать в корне, а панель искала бы их в data/awg/ —
    # то есть настроенный каскад молча превращался бы в пустой список.
    (os.path.join(PANEL_ROOT, 'mihomo_profiles.json'),    os.path.join(DATA_MIHOMO_DIR, 'profiles.json')),
    (os.path.join(DATA_DIR, 'mihomo_safe_deadline'),      os.path.join(DATA_MIHOMO_DIR, 'safe_deadline')),
] + [
    (os.path.join(PANEL_ROOT, f'audit.log.{i}'), os.path.join(DATA_LOGS_DIR, f'audit.log.{i}'))
    for i in range(1, 6)
]

def _migrate_data_layout():
    """Переносит пользовательские файлы из корня панели в data/**.

    Идемпотентна: файл переносится, только если существует по старому пути и
    отсутствует по новому — повторные запуски ничего не делают. os.replace в
    пределах одной ФС атомарен, так что оборванный старт не оставит полуфайла.
    Ошибка на одном файле не мешает остальным и не роняет панель: хуже потери
    одного файла только паника на старте, когда не поднимается вообще ничего.
    """
    moved = []
    for old, new in MIGRATION_MAP:
        try:
            # Папку создаём всегда, даже когда переносить нечего: на свежей установке
            # файлов ещё нет, а первая же запись должна лечь в готовый каталог.
            os.makedirs(os.path.dirname(new), exist_ok=True)
            if not os.path.exists(old) or os.path.exists(new):
                continue
            os.replace(old, new)
            moved.append(os.path.relpath(new, PANEL_ROOT))
        except Exception as e:
            print(f'[layout] не удалось перенести {old} → {new}: {e}', flush=True)
    if moved:
        print(f'[layout] перенесено в data/: {", ".join(moved)}', flush=True)
    return moved

# Вызов ДО первого чтения любого из этих файлов (SERVER_CFG грузится ниже).
LAYOUT_MIGRATED = _migrate_data_layout()

# === Пути пользовательских данных ===
# Живут под data/, потому что обязаны пережить обновление панели.
CLIENTS_DB = os.path.join(DATA_AWG_DIR, 'clients.json')   # клиенты AmneziaWG
SERVER_CONFIG_FILE = os.path.join(DATA_DIR, 'server.json')  # настройки сервера
ADMIN_FILE = os.path.join(DATA_DIR, 'admin.json')           # хеш пароля админа
SECRET_KEY_FILE = os.path.join(DATA_DIR, 'secret.key')      # ключ подписи сессий
# Журнал действий лежит вместе с остальными логами. У него своя ротация 1 МБ × 5
# (см. audit()), поэтому общий logrotate на 100 МБ до него практически не доходит.
AUDIT_LOG_FILE = os.path.join(DATA_LOGS_DIR, 'audit.log')
# Получатели MTProto: перечень выданных прокси — данные протокола, а не настройки
# сервера, поэтому лежат отдельно от server.json (перенос см. в _mtg_recipients).
MTG_RECIPIENTS_DB = os.path.join(DATA_MTPROTO_DIR, 'recipients.json')

# === server.json — per-server settings, NOT touched by updater ===
DEFAULT_SERVER_CONFIG = {
    'server_name': '',
    'server_ip': '',
    'sni': '',
    'mtg_fake_host': '',
    'mtg_port': 8443,
    # По умолчанию показываем ВСЕ протоколы: панель ставит их сама (кнопкой на
    # вкладке или починкой в «Зависимостях»), а лишние пользователь скрывает.
    'enabled_protocols': ['awg', 'xray', 'mtg', 'hysteria', 'tgweb'],
    'enabled_platforms': ['shadowrocket', 'loon', 'clash'],
    'profile_naming': 'friendly',  # 'friendly' = <server>-<client>, 'token' = just <token>
    'fake_enabled': False,
    # Глобальное логирование destination AWG-клиентов через conntrack.
    # Off по умолчанию. Включается из UI; зависимости (conntrack, dnsmasq) проверяются только если on.
    'awg_dest_log_enabled': False,
    'login_path': '/login.html',
    # Режим «только по ключу» (для Reality): корень '/' и всё кроме login_path → 404.
    # Фейк-сайт не отдаётся (его роль играет сам Reality, уводя на dest-сайт).
    'login_block_root': False,
    # Отдельный порт для доступа к панели (для Reality, когда 443 занят VPN).
    # 0 = не опубликована (только через 443-fallback при TLS или SSH-туннель).
    # Панель сама поднимает свой nginx-блок на этом порту, конфиг XRay не трогает.
    'panel_port': 0,
    # Пустая строка = автоопределение через `ip route get 1.1.1.1`.
    # Непустая = явный выбор юзера в модалке «Источники правды», переопределяет live.
    'server_ip_override': '',
    # Токен внешнего мониторинга (probe-API). Генерится сам при первом старте,
    # виден в «Здоровье сервера → Мониторинг». Пустой = probe-API выключено.
    'probe_token': '',
    # Which settings items appear directly in the gear dropdown (favorites).
    # Everything else is reachable via gear → Настройки → modal list.
    'settings_favorites': ['backup_quick'],
    # Порядок вкладок, перетаскиваемых мышью: {'main': [id вкладок], 'tg': ['mtg', 'web']}.
    # Пустой = порядок из разметки.
    'tab_order': {},
    # === Обновления (раньше жили в manifest.json — переехали сюда, чтобы
    # обновление кода их не затирало). Свитчи авто-обновления по умолчанию ВКЛ:
    # применяется без запроса, пишется в журнал. last_check — epoch-секунды
    # последней проверки (0 = ещё не проверяли). interval — период в днях.
    'panel_check_interval_days': 1,
    'panel_auto_update': True,
    'panel_last_check': 0,
    'geo_version': '',                 # дата YYYYMMDD установленных geo-баз
    'geo_check_interval_days': 180,
    'geo_auto_update': True,
    'geo_last_check': 0,
    'bm7_version': '',                 # дата DD.MM.YYYY установленных шаблонов blackmatrix7
    'bm7_check_interval_days': 7,
    'bm7_auto_update': True,
    'bm7_last_check': 0,
    # DNS по умолчанию для НОВЫХ XRay-клиентов (и «дефолт» в модалке Global).
    # mode='off' → панель не пишет DNS в конфиги (клиент рулит сам, ничего не затираем).
    'dns_default': {'mode': 'off', 'template': '', 'plain': [], 'doh': ''},
    # Каскад через второй VPN (движок mihomo). Подробности — в секции Mihomo ниже.
    'mihomo': {
        'check_interval_days': 7,
        'auto_update': True,
        'last_check': 0,
        'autostart': False,      # systemctl enable — поднимать движок при перезагрузке
        'safe_mode': False,      # предохранитель: пробный запуск с автооткатом через 5 мин
        'safe_deadline': 0,      # epoch, когда окно пробного запуска истекает (0 = окна нет)
        'cascade_xray': False,   # XRay-клиенты ходят в мир через движок
        'cascade_mtg': False,    # mtg ходит в Telegram через движок
        'cascade_hysteria': False,  # клиенты Hysteria ходят в мир через движок
        'cascade_tgweb': False,     # telemt (Telegram WEB) ходит к DC Telegram через движок
        'active_profile': '',    # id профиля из mihomo_profiles.json
        'secret': '',            # ключ к external-controller (генерится при установке)
    },
}

# Known settings-modal item IDs (used to validate settings_favorites).
# 'password' переехал внутрь карточки «Сервер и обновления» — в списке хаба его
# больше нет, но id остаётся валидным ради старых favorites (мигрируются ниже).
SETTINGS_ITEM_IDS = {
    'server_name', 'profile_naming', 'protocols', 'password',
    'audit', 'backup_settings', 'backup_quick', 'system_paths',
    'truths', 'dependencies', 'fake_landing', 'health', 'mihomo',
}

# Routes that must NEVER be shadowed by the fake-landing catch-all.
# Flask matches specific routes first, but we also filter inside catch-all defensively.
_RESERVED_FAKE_PREFIXES = ('api/', 'static/', 'sub/', 'conf/', 'clash/', 'loon/', 'country/', 'hy/')

def _validate_login_path(s):
    """login_path: '/' + любые [A-Za-z0-9._-], минимум 1 символ. Без ведущего '/' добавим сами."""
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    if not s.startswith('/'):
        s = '/' + s
    if re.match(r'^/[A-Za-z0-9._-]+$', s):
        return s
    return None

def _normalize_client_name(s):
    """Имя клиента храним в нижнем регистре — как его ни введи.

    Имя уходит в имя файла профиля и в публичный URL подписки, а те lowercase
    (_safe_filename). Если хранить как напечатали, карточка показывала бы «Fox»,
    а ссылка вела на /clash/fox — и «Fox» с «fox» выглядели бы как два клиента,
    хотя резолвятся в одного."""
    return (s or '').strip().lower()

def _client_name_taken(clients, name, skip_uuid=''):
    """Занято ли имя другим клиентом. Имя — не просто ярлык.

    От него зависят имя файла профиля, публичный URL подписки и email в статистике
    (`имя-uuid8`). Два клиента с одинаковым именем дают две неотличимые строки в
    карточках, логах и трафике: понять, кому из них выдана ссылка, нельзя.
    Сравниваем по нормализованному имени — оно уже lowercase.
    """
    want = _normalize_client_name(name)
    for uid, c in (clients or {}).items():
        if skip_uuid and (uid == skip_uuid or (c.get('uuid') or '') == skip_uuid):
            continue
        if _normalize_client_name(c.get('name')) == want:
            return True
    return False


def _validate_safe_name(s):
    """Allow only [A-Za-z0-9_-], spaces become underscores, max 32 chars."""
    if not s:
        return ''
    s = str(s).strip().replace(' ', '_')
    s = re.sub(r'[^A-Za-z0-9_-]', '', s)
    return s[:32]
def _load_server_config():
    if os.path.exists(SERVER_CONFIG_FILE):
        try:
            with open(SERVER_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            # Backfill missing keys from defaults
            for k, v in DEFAULT_SERVER_CONFIG.items():
                cfg.setdefault(k, v)
            # Разовая миграция: geo_version и blackmatrix7_version раньше лежали
            # в manifest.json. Если в server.json их ещё нет — перенести оттуда,
            # чтобы не потерять дату и не перекачивать базы заново.
            mani = _local_manifest()
            migrated = False
            if not cfg.get('geo_version') and mani.get('geo_version'):
                cfg['geo_version'] = str(mani.get('geo_version')); migrated = True
            if not cfg.get('bm7_version') and mani.get('blackmatrix7_version'):
                cfg['bm7_version'] = str(mani.get('blackmatrix7_version')); migrated = True
            # Вложенные словари setdefault не добирает — дописываем новые ключи внутрь.
            for k, v in DEFAULT_SERVER_CONFIG.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    for sk, sv in v.items():
                        if sk not in cfg[k]:
                            cfg[k][sk] = sv; migrated = True
            # «Сменить пароль» больше не отдельный пункт хаба — он внутри карточки
            # «Сервер и обновления». Если он был в избранном, ссылка стала бы битой.
            favs = cfg.get('settings_favorites')
            if isinstance(favs, list) and 'password' in favs:
                cfg['settings_favorites'] = [
                    ('server_name' if f == 'password' else f) for f in favs
                ]
                seen = set()
                cfg['settings_favorites'] = [
                    f for f in cfg['settings_favorites']
                    if not (f in seen or seen.add(f))
                ]
                migrated = True
            if migrated:
                try:
                    _save_server_config(cfg)
                except Exception:
                    pass
            return cfg
        except Exception:
            pass
    cfg = dict(DEFAULT_SERVER_CONFIG)
    try:
        os.makedirs(os.path.dirname(SERVER_CONFIG_FILE), exist_ok=True)
        with open(SERVER_CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass
    return cfg

def _save_server_config(cfg):
    with open(SERVER_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

SERVER_CFG = _load_server_config()


# Протоколы, снятые с вооружения. Их мало вычеркнуть из кода: server.json на
# уже работающем сервере продолжает их перечислять, а модалка «Протоколы»
# намеренно рисует чекбокс для каждого незнакомого id из enabled_protocols —
# чтобы не потерять протокол, который просто не загрузился. Тогда остался бы
# чекбокс без названия и без всего, чем он управлял.
#
# Hysteria отсюда убрана: протокол вернулся самостоятельным (modules/hysteria/),
# со своим сервисом, вкладкой и данными. Оставь её здесь — и панель на каждом
# старте вычёркивала бы её из enabled_protocols, то есть прятала бы вкладку
# сразу после того, как пользователь её включил.
RETIRED_PROTOCOLS = []


def _protocols_seen_upgrade():
    """Разово досыпает новые протоколы в enabled_protocols существующих серверов
    и вычищает снятые с вооружения.

    Без этого панель, обновлённая с версии без нового протокола, не показала бы вкладку:
    в server.json лежит старый список, а отсутствие протокола в нём неотличимо
    от «пользователь его скрыл». Флаг protocols_seen фиксирует, что протокол уже
    предлагался — если после этого его скрыть, он больше не вернётся.
    """
    seen = SERVER_CFG.get('protocols_seen')
    if not isinstance(seen, list):
        seen = []
    known = ['awg', 'xray', 'mtg', 'hysteria', 'tgweb']
    enabled = SERVER_CFG.get('enabled_protocols')
    if not isinstance(enabled, list):
        enabled = list(known)
    changed = False
    # Сначала уборка: снятый протокол выкидываем из обоих списков. Из seen —
    # чтобы запись не тянулась годами; вернуться ему всё равно неоткуда.
    for p in RETIRED_PROTOCOLS:
        if p in enabled:
            enabled = [x for x in enabled if x != p]
            changed = True
        if p in seen:
            seen = [x for x in seen if x != p]
            changed = True
    fresh = [p for p in known if p not in seen]
    for p in fresh:
        if p not in enabled:
            enabled.append(p)
        changed = True
    if not changed:
        return
    SERVER_CFG['enabled_protocols'] = enabled
    SERVER_CFG['protocols_seen'] = known
    _save_server_config(SERVER_CFG)


_protocols_seen_upgrade()

# Токен внешнего мониторинга: генерится один раз при первом старте. Показывается
# в «Здоровье сервера → Мониторинг», оттуда переносится в утилиту мониторинга.
if not SERVER_CFG.get('probe_token'):
    SERVER_CFG['probe_token'] = secrets.token_hex(16)
    _save_server_config(SERVER_CFG)

# === DNS для клиентских конфигов (XRay: Loon/Clash/Shadowrocket) ============
# Каталог готовых резолверов, который показывает модалка настройки DNS.
# ТОЛЬКО зашифрованный DoH — plain намеренно пустой: обычный UDP :53 в РФ виден
# провайдеру/ТСПУ и легко подменяется (основной механизм блокировок), DoH — нет.
# Где сертификат провайдера покрывает сам IP — DoH задан в IP-форме
# (https://<ip>/dns-query): резолвить хост не нужно → нет даже bootstrap-запроса
# открытым текстом. У кого IP в сертификате нет — хост-форма (разовый bootstrap
# имени резолвера неизбежен, это мелочь). NextDNS — свой профиль, ID в URL.
# Билдер каждого клиента переводит doh в свой синтаксис (см. _render_dns_*).
# boot — plain-IP ТОГО ЖЕ резолвера (:53 того же провайдера). Нужен только там, где
# DoH задан именем: чем-то надо резолвить сам хост. Чужие 1.1.1.1/8.8.8.8 сюда
# подставлять нельзя — клиент должен ходить только к выбранному резолверу.
# Внимание: A-запись DoH-хоста для этого НЕ годится (у NextDNS это edge-нода без
# :53, у OpenDNS — 146.112.41.2 вместо 208.67.222.222), поэтому список ручной.
DNS_TEMPLATES = [
    {'id': 'cloudflare',          'name': 'Cloudflare',         'plain': [], 'doh': 'https://1.1.1.1/dns-query',
     'boot': ['1.1.1.1', '1.0.0.1']},
    {'id': 'google',              'name': 'Google',             'plain': [], 'doh': 'https://8.8.8.8/dns-query',
     'boot': ['8.8.8.8', '8.8.4.4']},
    {'id': 'quad9',               'name': 'Quad9',              'plain': [], 'doh': 'https://9.9.9.9/dns-query',
     'boot': ['9.9.9.9', '149.112.112.112']},
    {'id': 'adguard',             'name': 'AdGuard',            'plain': [], 'doh': 'https://dns.adguard-dns.com/dns-query',
     'boot': ['94.140.14.14', '94.140.15.15']},
    {'id': 'nextdns',             'name': 'NextDNS',            'plain': [], 'doh': 'h3://dns.nextdns.io/',
     'boot': ['45.90.28.0', '45.90.30.0']},
]

def _norm_dns(d):
    """Валидирует объект DNS-настройки → {mode, template, plain, doh}.
    mode='off' → в конфиг клиента не пишем никаких DNS-строк (ничего не затираем).
    mode='set' → пишем plain-резолверы и/или DoH-URL."""
    if not isinstance(d, dict):
        d = {}
    mode = d.get('mode')
    if mode not in ('off', 'set'):
        mode = 'off'
    template = d.get('template')
    template = str(template)[:40] if isinstance(template, str) else ''
    plain = []
    for x in (d.get('plain') or []):
        if isinstance(x, str):
            s = x.strip()
            if s and len(s) <= 128 and re.match(r'^[A-Za-z0-9.:_\-\[\]]+$', s):
                plain.append(s)
    plain = list(dict.fromkeys(plain))[:6]
    doh = d.get('doh')
    doh = doh.strip() if isinstance(doh, str) else ''
    if doh and not re.match(r'^(https|h3|quic)://', doh):
        doh = ''
    doh = doh[:200]
    # fallback: при h3:// (DoH3) дополнительно отдать https://-форму того же
    # резолвера, чтобы при блокировке QUIC клиент откатился на HTTP/2 (тот же TLS,
    # та же приватность). Осмысленно только для h3://.
    fallback = bool(d.get('fallback'))
    return {'mode': mode, 'template': template, 'plain': plain, 'doh': doh, 'fallback': fallback}

def _dns_h2_form(doh):
    """https://-форма h3://-URL (тот же хост/путь) для фолбэка. Иначе None."""
    if isinstance(doh, str) and doh.startswith('h3://'):
        return 'https://' + doh[len('h3://'):]
    return None


def _dns_is_ip(s):
    """IP-литерал (v4 или v6, в скобках или без)? Только такие годятся в bootstrap."""
    s = (s or '').strip().strip('[]')
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):
        return True
    return ':' in s and bool(re.match(r'^[0-9A-Fa-f:]+$', s))

def _dns_entry_host(s):
    """Хост записи резолвера: 'https://dns.x/y#h3=true' → 'dns.x', '1.1.1.1' → '1.1.1.1'."""
    s = re.sub(r'^[A-Za-z0-9]+://', '', (s or '').strip()).split('/')[0].split('#')[0]
    if s.startswith('['):
        return s.split(']')[0].lstrip('[')
    return s.split(':')[0] if s.count(':') == 1 else s

def _dns_needs_bootstrap(entries):
    """Есть ли среди резолверов заданный ИМЕНЕМ — тогда клиенту нужен bootstrap."""
    return any(not _dns_is_ip(_dns_entry_host(x)) for x in entries)

def _dns_bootstrap_for(d):
    """Plain-IP, которые клиент вправе спрашивать по UDP: ТОЛЬКО выбранный резолвер.
    Приоритет: свои резолверы юзера → IP-форма самого DoH → boot нашего шаблона.
    Ничего не нашли (кастомный хост без plain) → пусто: чужой резолвер не подставляем."""
    boot = [x for x in d['plain'] if _dns_is_ip(x)]
    if boot:
        return boot
    if not d['doh']:
        return []
    host = _dns_entry_host(d['doh'])
    for tpl in DNS_TEMPLATES:               # матч по хосту: ID/схема в URL не важны
        if _dns_entry_host(tpl['doh']).lower() == host.lower():
            return list(tpl.get('boot') or [])
    if _dns_is_ip(host):
        return [host]                       # свой DoH по IP — он же и plain-адрес
    return []

def _global_dns_default():
    """DNS-дефолт для новых юзеров (из server.json, правится модалкой Global)."""
    return _norm_dns(SERVER_CFG.get('dns_default'))


def _xray_dns_section(d):
    """Секция `dns` для xray.json из DNS-настройки Global. None → секции быть не должно.

    Зачем: домен, уходящий в VPN, клиент отдаёт серверу ИМЕНЕМ — резолвит его xray,
    а не устройство. Значит серверу нужен тот же резолвер, что прописан клиентам,
    иначе фильтрация/статистика провайдера DNS перестаёт видеть проксируемый трафик
    (ровно это и вылезло с «Режим исключений: VPN»).

    Ограничение xray: секция dns глобальная, выбрать резолвер под конкретного юзера
    нельзя — поэтому источник один, Global.
    """
    if not isinstance(d, dict) or d.get('mode') != 'set':
        return None
    servers = []
    doh = (d.get('doh') or '').strip()
    if doh:
        # h3:// xray не понимает — берём https-форму того же URL (тот же хост/путь).
        # +local: запрос к резолверу идёт напрямую, мимо routing — иначе он попадёт
        # под Global-правила/каскад и может зациклиться.
        u = _dns_h2_form(doh) or doh
        if u.startswith('https://'):
            u = 'https+local://' + u[len('https://'):]
        elif u.startswith('quic://'):
            u = 'quic+local://' + u[len('quic://'):]
        servers.append(u)
    # Plain-IP того же провайдера — резерв. У xray серверы опрашиваются ПО ПОРЯДКУ
    # (в отличие от клиентов, где параллельный опрос похоронил бы DoH), так что
    # открытым текстом спросим только если DoH не ответил.
    servers += [ip for ip in (d.get('plain') or []) if _dns_is_ip(ip)]
    if not servers:
        return None
    # Последний рубеж: системный резолвер. Без него недоступность DoH = отвал DNS
    # у всех клиентов сразу.
    servers.append('localhost')
    out = {'servers': servers, 'queryStrategy': 'UseIPv4'}
    host = _dns_entry_host(doh) if doh else ''
    if host and not _dns_is_ip(host):
        # Чем резолвить имя самого резолвера (аналог bootstrap в клиентских конфигах).
        boot = _dns_bootstrap_for(d)
        if boot:
            out['hosts'] = {host: boot}
    return out


def _is_valid_ipv4(s):
    """Строгая проверка IPv4 (regex вида \\d{1,3} пропускал 999.999.999.999)."""
    import ipaddress
    try:
        ipaddress.IPv4Address((s or '').strip())
        return True
    except Exception:
        return False

def _is_private_ipv4(s):
    """Серый адрес (RFC1918 / CGNAT 100.64 / link-local / loopback / 0.0.0.0) —
    такой IP в клиентской ссылке снаружи недоступен. Через is_global, а не
    is_private: в py3.13 100.64/10 выкинули из is_private, is_global стабилен."""
    import ipaddress
    try:
        return not ipaddress.IPv4Address((s or '').strip()).is_global
    except Exception:
        return False

def _detect_server_ip():
    """Determine the server's outbound IPv4 via the default route."""
    try:
        out = subprocess.run(
            ['ip', 'route', 'get', '1.1.1.1'],
            capture_output=True, text=True, timeout=2
        )
        m = re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)', out.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ''

def _list_server_ipv4s():
    """Все IPv4-адреса всех интерфейсов кроме loopback/link-local.
    Возвращает [{'ip','iface','is_outbound'}, ...]"""
    addrs = []
    try:
        out = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show'],
            capture_output=True, text=True, timeout=2
        )
        outbound = _detect_server_ip()
        # Формат строки: "2: eth0    inet 1.2.3.4/24 brd ..."
        for line in out.stdout.splitlines():
            m = re.search(r'^\s*\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if not m:
                continue
            iface = m.group(1)
            ip = m.group(2)
            if iface == 'lo' or ip.startswith('127.') or ip.startswith('169.254.'):
                continue
            addrs.append({'ip': ip, 'iface': iface, 'is_outbound': ip == outbound})
    except Exception:
        pass
    return addrs

def get_server_ip():
    """Источник правды для IP сервера, попадающего в клиентские конфиги/ссылки.
    Приоритет: явный override из server.json → live-detect → legacy server_ip
    из server.json → '0.0.0.0' (последний бастион)."""
    override = (SERVER_CFG.get('server_ip_override') or '').strip()
    if override:
        return override
    live = _detect_server_ip()
    if live:
        return live
    legacy = (SERVER_CFG.get('server_ip') or '').strip()
    if legacy:
        return legacy
    return '0.0.0.0'

# Legacy глобал — оставлен только для обратной совместимости со старыми вызовами,
# но НИГДЕ в кодогенерации клиентских конфигов больше не используется (см. get_server_ip()).
SERVER_IP = get_server_ip()

# === admin.json — password hash ===
def _admin_valid(data):
    """Годен только словарь с непустым password_hash.

    Битый или чужого формата файл (раньше инструкция предлагала писать admin.json
    руками, и ключ называли 'password') роняли панель на импорте по KeyError —
    сервис не поднимался вообще. Теперь такой файл считаем отсутствующим."""
    return isinstance(data, dict) and isinstance(data.get('password_hash'), str) and data['password_hash']

def _load_admin():
    if os.path.exists(ADMIN_FILE):
        try:
            with open(ADMIN_FILE, 'r') as f:
                data = json.load(f)
            if _admin_valid(data):
                return data
            print(f'[admin] {ADMIN_FILE} без password_hash — создаю новый пароль', flush=True)
        except Exception:
            pass
    # Страховка на случай неудавшегося переезда в data/: файл мог остаться в корне.
    # Без неё панель засеяла бы дефолтный пароль — то есть открылась бы всем.
    legacy = os.path.join(PANEL_ROOT, 'admin.json')
    if os.path.exists(legacy):
        try:
            with open(legacy, 'r') as f:
                data = json.load(f)
            if not _admin_valid(data):
                raise ValueError('no password_hash')
            print(f'[layout] admin.json прочитан из старого пути {legacy} — переезд не состоялся', flush=True)
            return data
        except Exception:
            pass
    # Первый запуск: пароль генерируем случайно и показываем владельцу сервера.
    # Раньше здесь стояло зашитое в код значение — одно и то же у всех, кто
    # развернул панель из архива, то есть панель открывалась любому, кто читал
    # исходники. Единственное место, где новый пароль виден, — журнал сервиса и
    # файл рядом с данными: наружу он не уходит.
    first_pass = secrets.token_urlsafe(12)
    seed = {
        'password_hash': hashlib.sha256(first_pass.encode()).hexdigest(),
        'must_change': True,
    }
    try:
        os.makedirs(os.path.dirname(ADMIN_FILE), exist_ok=True)
        with open(ADMIN_FILE, 'w') as f:
            json.dump(seed, f)
        os.chmod(ADMIN_FILE, 0o600)
    except Exception:
        pass
    # Дублируем в файл: журнал systemd ротируется, и пароль может пропасть раньше,
    # чем владелец до него доберётся.
    try:
        hint = os.path.join(os.path.dirname(ADMIN_FILE), 'first_login.txt')
        with open(hint, 'w', encoding='utf-8') as f:
            f.write(f'Пароль первого входа в панель: {first_pass}\n'
                    'Смените его в панели — после смены этот файл можно удалить.\n')
        os.chmod(hint, 0o600)
    except Exception:
        hint = '(не удалось записать файл)'
    print('=' * 62, flush=True)
    print(f'  Пароль первого входа в панель: {first_pass}', flush=True)
    print(f'  Он записан в {hint}', flush=True)
    print('  Смените его после первого входа.', flush=True)
    print('=' * 62, flush=True)
    return seed

ADMIN = _load_admin()
PANEL_PASSWORD_HASH = ADMIN['password_hash']

# === Audit log — ring buffer + file (rotation 1MB × 5) ===
AUDIT_RING = deque(maxlen=400)
AUDIT_LOCK = threading.Lock()

def audit(level, msg):
    """Log admin/system events. level: info | warn | error | progress.
    Возвращает id записи (uuid-short) — можно использовать для последующего
    обновления текста (audit_update_msg)."""
    rec_id = uuid_lib.uuid4().hex[:12]
    rec = {'id': rec_id, 'ts': int(time.time()), 'level': level, 'msg': str(msg)[:500]}
    with AUDIT_LOCK:
        AUDIT_RING.append(rec)
        try:
            # Rotate if > 1MB
            if os.path.exists(AUDIT_LOG_FILE) and os.path.getsize(AUDIT_LOG_FILE) > 1024 * 1024:
                for i in range(4, 0, -1):
                    src = f'{AUDIT_LOG_FILE}.{i}'
                    dst = f'{AUDIT_LOG_FILE}.{i+1}'
                    if os.path.exists(src):
                        os.replace(src, dst)
                if os.path.exists(AUDIT_LOG_FILE):
                    os.replace(AUDIT_LOG_FILE, f'{AUDIT_LOG_FILE}.1')
            with open(AUDIT_LOG_FILE, 'a') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        except Exception:
            pass
    return rec_id

def audit_update_msg(rec_id, new_msg):
    """Обновляет текст ранее записанной audit-записи по id (в ring + в файле).
    Используется, чтобы после Login OK дописать в запись реальный IP+geo,
    которые подгружает фронт через api.ru.dog/v1/me."""
    if not rec_id:
        return False
    new_msg = str(new_msg)[:500]
    with AUDIT_LOCK:
        updated = False
        for r in AUDIT_RING:
            if r.get('id') == rec_id:
                r['msg'] = new_msg
                updated = True
                break
        if not updated:
            return False
        try:
            if os.path.exists(AUDIT_LOG_FILE):
                with open(AUDIT_LOG_FILE, 'r') as f:
                    lines = f.readlines()
                out = []
                for line in lines:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        out.append(line)
                        continue
                    if obj.get('id') == rec_id:
                        obj['msg'] = new_msg
                        out.append(json.dumps(obj, ensure_ascii=False) + '\n')
                    else:
                        out.append(line)
                with open(AUDIT_LOG_FILE, 'w') as f:
                    f.writelines(out)
        except Exception:
            pass
        return True

def _xray_recent_real_ip(within_sec=5):
    """Newest src IP из XRay access.log с dst=127.0.0.1 (фоллбек XRay→nginx),
    за последние N секунд. Используется чтобы восстановить реальный IP клиента,
    когда remote_addr=127.0.0.1 (запрос пришёл через XRay→nginx→Flask).
    Зависит от XRay access-log (включается через patch_xray_for_access_log)."""
    try:
        if not os.path.exists(XRAY_ACCESS_LOG):
            return ''
        text = _tail_bytes(XRAY_ACCESS_LOG, 256 * 1024)
        if not text:
            return ''
        cutoff = time.time() - within_sec
        for r in _xray_parse_access_lines(text):
            if r.get('host') != '127.0.0.1':
                continue
            try:
                t = time.mktime(time.strptime(r['ts'], '%Y/%m/%d %H:%M:%S'))
            except Exception:
                continue
            if t < cutoff:
                break  # дальше только старее — newest-first
            ip = r.get('ip') or ''
            if ip and not ip.startswith('127.'):
                return ip
    except Exception:
        pass
    return ''

def _is_private_ip(ip):
    """loopback / RFC1918 / link-local / IPv6 loopback — не настоящий клиентский."""
    if not ip:
        return True
    if ip in ('::1', '0.0.0.0') or ip.startswith('127.') or ip.startswith('10.') \
       or ip.startswith('192.168.') or ip.startswith('169.254.') or ip.startswith('fe80:'):
        return True
    return bool(re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip))

def _client_ip():
    try:
        # Порядок: X-Real-IP (nginx) → первый ПУБЛИЧНЫЙ из X-Forwarded-For → remote_addr.
        candidates = []
        xri = (request.headers.get('X-Real-IP') or '').strip()
        if xri:
            candidates.append(xri)
        xff = request.headers.get('X-Forwarded-For', '')
        candidates += [p.strip() for p in xff.split(',') if p.strip()]
        if request.remote_addr:
            candidates.append(request.remote_addr)
        for ip in candidates:
            if not _is_private_ip(ip):
                return ip
        # Всё приватное/loopback (запрос через XRay→nginx fallback, remote_addr=127.0.0.1):
        # пробуем восстановить реальный IP из XRay access.log по времени.
        real = _xray_recent_real_ip()
        if real:
            return real
        return candidates[0] if candidates else '?'
    except Exception:
        return '?'

def _load_audit_tail(n=200):
    """Load tail entries from file on startup so the ring survives restarts."""
    try:
        if not os.path.exists(AUDIT_LOG_FILE):
            return
        with open(AUDIT_LOG_FILE, 'r') as f:
            lines = f.readlines()[-n:]
        for line in lines:
            try:
                AUDIT_RING.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass

_load_audit_tail()

# GeoIP (MaxMind GeoLite2-City + GeoLite2-ASN)
GEO_DB = os.path.join(DATA_GEO_DIR, 'GeoLite2-City.mmdb')
ASN_DB = os.path.join(DATA_GEO_DIR, 'GeoLite2-ASN.mmdb')
_geo_reader = None
_asn_reader = None
_maxminddb_loaded = False
_geo_init_error = None
try:
    import maxminddb
    _maxminddb_loaded = True
    if os.path.exists(GEO_DB):
        try:
            _geo_reader = maxminddb.open_database(GEO_DB)
        except Exception as e:
            _geo_init_error = f'GeoLite2-City открыть не удалось: {e}'
    else:
        _geo_init_error = f'GeoLite2-City.mmdb не найден: {GEO_DB}'
    if os.path.exists(ASN_DB):
        try:
            _asn_reader = maxminddb.open_database(ASN_DB)
        except Exception as e:
            _geo_init_error = (_geo_init_error or '') + f' | ASN открыть не удалось: {e}'
    else:
        _geo_init_error = (_geo_init_error or '') + f' | ASN.mmdb не найден: {ASN_DB}'
except Exception as e:
    _geo_init_error = f'maxminddb модуль не установлен в venv: {e}. Установи: /opt/awg-panel/venv/bin/pip install maxminddb && systemctl restart awg-panel'
if _geo_init_error:
    try:
        audit('error', f'Geo init: {_geo_init_error}')
    except Exception:
        pass

def _geo_locale():
    """Язык гео-имён (страна/город) — по cookie `lang`, которую панель ставит из
    выбранного в UI языка. Дефолт 'ru'. Вне request-контекста — тоже 'ru'."""
    try:
        from flask import has_request_context
        if has_request_context():
            l = request.cookies.get('lang')
            if l in ('ru', 'en'):
                return l
    except Exception:
        pass
    return 'ru'

def _geo_name(names, loc):
    return names.get(loc) or names.get('en') or names.get('ru')

def geoip_lookup(ip):
    if not ip or _geo_reader is None:
        return None
    try:
        rec = _geo_reader.get(ip)
        if not rec:
            return None
        loc = _geo_locale()
        country = rec.get('country') or {}
        city = rec.get('city') or {}
        names_c = country.get('names') or {}
        names_ci = city.get('names') or {}
        return {
            'cc': country.get('iso_code'),
            'country': _geo_name(names_c, loc),
            'city': _geo_name(names_ci, loc)
        }
    except Exception:
        return None

def asn_lookup(ip):
    if not ip or _asn_reader is None:
        return None
    try:
        rec = _asn_reader.get(ip)
        if not rec:
            return None
        return {
            'asn': rec.get('autonomous_system_number'),
            'org': rec.get('autonomous_system_organization'),
        }
    except Exception:
        return None

def geo_asn_full(ip):
    """Combined lookup → {cc, country, city, asn, org} (or None)."""
    g = geoip_lookup(ip) or {}
    a = asn_lookup(ip) or {}
    if not g and not a:
        return None
    out = dict(g)
    out.update(a)
    return out

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# === Country IP-range rule-sets (для клиентских правил Loon/Clash/Shadowrocket) ===
# Источник — готовый byfox.dev/data/maxmind/countries.zip (формат строк start-end,
# по файлу на страну). Качаем по тому же 180-дневному циклу, что и геобазы, кладём
# в справочник по ISO-коду, а при отдаче конвертим start-end → CIDR (с диск-кешем).
# На сервер (XRay) это НЕ идёт — там whitelist/blacklist по geoip:cc в глобал-руле.
COUNTRIES_ZIP_URL = GEO_BASE_URL.rstrip('/') + '/countries.zip'
COUNTRIES_SRC_DIR = os.path.join(DATA_GEO_DIR, 'countries_src')   # сырые start-end по ISO
COUNTRIES_CACHE_DIR = os.path.join(DATA_GEO_DIR, 'countries')     # сконвертированный CIDR-кеш


def _geo_bootstrap_if_missing():
    """Разовый бутстрап geo-баз: если mmdb-файлов нет в data/ (новый сервер или их
    удалили), качаем сразу в фоне, не дожидаясь периодического гео-цикла. Проверяем
    именно НАЛИЧИЕ ФАЙЛОВ, а не маркер версии (он мог остаться при удалённых базах).
    После загрузки — рестарт: geo-читалки открываются один раз на старте."""
    time.sleep(8)
    try:
        if os.path.exists(GEO_DB) and os.path.exists(ASN_DB):
            return
        remote_v = _fetch_remote_geo_version()
        if not remote_v:
            audit('warn', 'geo bootstrap: не удалось получить версию гео с CDN')
            return
        audit('info', 'geo bootstrap: mmdb отсутствуют — первичная загрузка')
        ok, err = _do_geo_update(remote_v)
        if ok:
            SERVER_CFG['geo_last_check'] = int(time.time()); _save_server_config(SERVER_CFG)
            audit('info', f'geo bootstrap: базы загружены (v{remote_v}), перезапуск')
            _restart_panel_soon()
        else:
            audit('warn', f'geo bootstrap failed: {err}')
    except Exception as e:
        try: audit('warn', f'geo bootstrap failed: {e}')
        except Exception: pass

threading.Thread(target=_geo_bootstrap_if_missing, daemon=True).start()

def _dest_org_for_host(host, cache):
    """Если host — IP, вернёт {asn, org} из MaxMind, иначе {}. Кеш — per-request."""
    if not host or not _IPV4_RE.match(host):
        return {}
    if host not in cache:
        info = asn_lookup(host) or {}
        cache[host] = {'asn': info.get('asn'), 'org': info.get('org')} if info else {}
    return cache[host]

# XRay (VLESS + TLS, Let's Encrypt cert with Nginx fallback)
XRAY_CONFIG = '/usr/local/etc/xray/config.json'
XRAY_CLIENTS_DB = os.path.join(DATA_XRAY_DIR, 'clients.json')
XRAY_RULE_LISTS_DB = os.path.join(DATA_XRAY_DIR, 'rule_lists.json')
XRAY_GLOBAL_DB = os.path.join(DATA_XRAY_DIR, 'global.json')
XRAY_GLOBAL_CACHE_DB = os.path.join(DATA_XRAY_DIR, 'global_cache.json')
XRAY_GLOBAL_TOTALS_DB = os.path.join(DATA_XRAY_DIR, 'global_totals.json')
XRAY_PARAMS = {
    'port': 443,  # fallback only — реальный порт читается из config.json (get_xray_port)
    'sni': SERVER_CFG['sni'],
    'fingerprint': 'chrome',
    'flow': 'xtls-rprx-vision',
    'inbound_tag': 'vless-tls'
}
XRAY_BIN = '/usr/local/bin/xray'

def get_xray_sni():
    """Какой SNI должен прописываться клиенту:
    - в TLS-режиме это server.json['sni'] (значение, под которое выпущен сертификат);
    - в Reality — первый serverName из realitySettings.
    Fallback — SERVER_CFG['sni']."""
    try:
        with open(XRAY_CONFIG, 'r') as f:
            cfg = json.load(f)
        for inb in cfg.get('inbounds', []):
            if inb.get('protocol') != 'vless':
                continue
            ss = inb.get('streamSettings') or {}
            sec = ss.get('security') or 'tls'
            if sec == 'reality':
                rs = ss.get('realitySettings') or {}
                names = rs.get('serverNames') or []
                if names:
                    return names[0]
            break
    except Exception:
        pass
    return SERVER_CFG.get('sni', '')

def get_xray_port():
    """Реальный порт XRay из /usr/local/etc/xray/config.json по tag='vless-tls'.
    Fallback на XRAY_PARAMS['port'] (443), если файл/тег отсутствует."""
    try:
        with open(XRAY_CONFIG, 'r') as f:
            cfg = json.load(f)
        target = XRAY_PARAMS.get('inbound_tag') or 'vless-tls'
        for inb in cfg.get('inbounds', []):
            if inb.get('tag') == target:
                p = inb.get('port')
                if isinstance(p, int) and p > 0:
                    return p
                try:
                    return int(p)
                except (TypeError, ValueError):
                    break
    except Exception:
        pass
    return XRAY_PARAMS['port']

_xray_pubkey_cache = {}  # privateKey -> publicKey (деривация дорогая, кешируем в RAM)

def _parse_x25519(blob):
    """(privateKey, publicKey) из вывода `xray x25519`. Разные версии xray:
    'Private key: / Public key:', 'PrivateKey: / Password:' и новый
    'PrivateKey: / Password (PublicKey):' — регистр и вставка до ':' любые."""
    blob = blob or ''
    m_priv = re.search(r'Private\s*key[^:\n]*:\s*(\S+)', blob, re.I)
    m_pub = re.search(r'(?:Public\s*key|Password)[^:\n]*:\s*(\S+)', blob, re.I)
    return (m_priv.group(1) if m_priv else ''), (m_pub.group(1) if m_pub else '')

def _derive_reality_pubkey(private_key):
    """Публичный x25519-ключ из приватного через `xray x25519 -i`. В конфиге reality
    хранится только privateKey, клиенту нужен publicKey. Кешируется по privateKey."""
    private_key = (private_key or '').strip()
    if not private_key:
        return ''
    if private_key in _xray_pubkey_cache:
        return _xray_pubkey_cache[private_key]
    out, err, rc = run_cmd(f'{XRAY_BIN} x25519 -i {private_key}')
    pub = _parse_x25519((out or '') + '\n' + (err or ''))[1]
    _xray_pubkey_cache[private_key] = pub
    return pub

def get_xray_inbound_params():
    """Единый live-источник параметров активного vless-инбаунда для генерации
    клиентских конфигов. Никакого хардкода: security/sni/flow/fingerprint и, для
    reality, public_key/short_id/spider_x/dest читаются из config.json.
    XRAY_PARAMS/server.json — только фолбэк, когда инбаунд не найден."""
    params = {
        'security': 'tls',
        'port': get_xray_port(),
        'sni': SERVER_CFG.get('sni', ''),
        'flow': XRAY_PARAMS['flow'],
        'fingerprint': XRAY_PARAMS['fingerprint'],
        'public_key': '',
        'short_id': '',
        'spider_x': '/',
        'dest': '',
    }
    try:
        with open(XRAY_CONFIG, 'r') as f:
            cfg = json.load(f)
    except Exception:
        return params
    target = XRAY_PARAMS.get('inbound_tag') or 'vless-tls'
    inb = next((ib for ib in cfg.get('inbounds', [])
                if ib.get('tag') == target and ib.get('protocol') == 'vless'), None)
    if inb is None:
        inb = next((ib for ib in cfg.get('inbounds', [])
                    if ib.get('protocol') == 'vless'
                    and (ib.get('streamSettings') or {}).get('security') in ('tls', 'reality')), None)
    if inb is None:
        return params
    ss = inb.get('streamSettings') or {}
    sec = ss.get('security') or 'tls'
    params['security'] = sec
    # flow — из первого клиента инбаунда (а не из хардкода)
    clients = (inb.get('settings') or {}).get('clients') or []
    if clients and ('flow' in clients[0]):
        params['flow'] = clients[0].get('flow') or ''
    if sec == 'reality':
        rs = ss.get('realitySettings') or {}
        names = rs.get('serverNames') or []
        params['sni'] = names[0] if names else ''
        params['dest'] = rs.get('dest', '') or (names[0] if names else '')
        sids = rs.get('shortIds') or []
        params['short_id'] = next((s for s in sids if s), (sids[0] if sids else ''))
        params['public_key'] = _derive_reality_pubkey(rs.get('privateKey') or '')
    else:
        ts = ss.get('tlsSettings') or {}
        params['sni'] = ts.get('serverName') or SERVER_CFG.get('sni', '')
    return params
XRAY_API_ADDR = '127.0.0.1:10085'
XRAY_API_PORT = 10085
PANEL_LOGS_DIR = DATA_LOGS_DIR   # единый источник правды с блоком раскладки
# Персистентные тоталы трафика AWG per-pubkey: awg show transfer обнуляется
# при рестарте сервиса, поэтому панель сама копит накопительные суммы
# (как XRay делает в XRAY_GLOBAL_TOTALS_DB).
AWG_TOTALS_DB = os.path.join(DATA_AWG_DIR, 'totals.json')
XRAY_ACCESS_LOG = f'{PANEL_LOGS_DIR}/xray_access.log'
MTG_ACCESS_LOG = f'{PANEL_LOGS_DIR}/mtg_access.log'
# Пути и интервал сбора destinations живут в awg_dest_log.py — фича владеет ими целиком.
AWG_ACCESS_LOG = f'{PANEL_LOGS_DIR}/awg_access.log'
# Tail at most this many bytes from the end on every status refresh.
# 1MB ≈ 5000 connection lines — enough to find recent IP for any active client.
XRAY_LOG_TAIL_BYTES = 1024 * 1024
# Maximum bytes to scan when reading per-client full logs.
XRAY_LOG_FULL_BYTES = 50 * 1024 * 1024  # 50 MB (covers half a 100 MB file)
# Persistent cache of last IP per email — survives log rotation and tail eviction.
XRAY_LAST_IPS_FILE = os.path.join(DATA_XRAY_DIR, 'last_ips.json')

# Shadowrocket / Surge rule lists
XRAY_GEOIP_MMDB_URL = 'https://byfox.dev/data/maxmind/GeoLite2-Country.mmdb'
XRAY_GEOIP_ASN_MMDB_URL = 'https://byfox.dev/data/maxmind/GeoLite2-ASN.mmdb'
XRAY_RULE_UPDATE_INTERVAL = 86400  # 24h, applied to RULE-SET and config update-interval

# Режим исключений («что делать с трафиком вне списков») в geo_mode='lists'.
# Один кортеж на валидацию во всех точках входа — см. _lists_final_policy().
LISTS_DEFAULT_MODES = ('direct', 'vpn', 'block')


# MTProto Proxy (mtg). Источник правды для порта/маски — сам /etc/mtg/config.toml
# (bind-to и hex-хвост секрета). server.json держит только last-known значения для
# случаев, когда mtg ещё не сконфигурирован.
MTG_BIN = '/usr/local/bin/mtg'
MTG_CONFIG = '/etc/mtg/config.toml'
MTG_PORT = SERVER_CFG['mtg_port']           # fallback, реальное — get_mtg_port()
MTG_FAKE_HOST = SERVER_CFG['mtg_fake_host'] # fallback, реальное — get_mtg_fake_host()


def load_or_create_secret_key():
    # Persist secret_key so multiple gunicorn workers share it and sessions
    # survive process restarts. Without this each worker has its own key
    # and clients get 401 on the next request after login.
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    os.chmod(SECRET_KEY_FILE, 0o600)
    return key

app.secret_key = load_or_create_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = 7 * 24 * 3600

# AWG obfuscation params — MUST match the server's awg0.conf [Interface] section,
# иначе handshake у клиента не пройдёт. На новом сервере amnezia-install генерирует
# свежие H1-H4/Jc/Jmin/Jmax/S1/S2, поэтому читаем их прямо из awg0.conf.
# Значения ниже используются только как fallback, если файл недоступен или ключ
# отсутствует в [Interface].
_AWG_PARAMS_FALLBACK = {
    'Jc': '5', 'Jmin': '50', 'Jmax': '1000',
    'S1': '67', 'S2': '68',
    'H1': '1691596450', 'H2': '847085121',
    'H3': '740697121', 'H4': '1182320545',
}
_AWG_PARAM_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4')
_AWG_PORT_FALLBACK = 443

def get_awg_port():
    """Реальный UDP-порт AmneziaWG: [Interface] ListenPort = N в awg0.conf.
    Fallback на 443, если файл/ключ недоступен."""
    try:
        with open(AWG_CONFIG, 'r') as f:
            in_interface = False
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    in_interface = line.lower() == '[interface]'
                    continue
                if not in_interface or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                if k.strip() == 'ListenPort':
                    try:
                        return int(v.strip())
                    except (TypeError, ValueError):
                        break
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return _AWG_PORT_FALLBACK


def get_mtg_listen_port():
    """Порт, который MTProto действительно держит за собой, или 0. Без
    конфига mtg не установлен — запасной 8443 из get_mtg_port() в проверках
    занятости давал бы ложный конфликт."""
    if not os.path.isfile(MTG_CONFIG):
        return 0
    try:
        return int(get_mtg_port() or 0)
    except Exception:
        return 0


def get_awg_listen_port():
    """Порт, который AWG действительно держит за собой, или 0.

    В отличие от get_awg_port() без запасного 443: тот нужен при сборке
    клиентских конфигов, а в проверках «кто занимает порт» выдуманное число
    давало ложный конфликт — на сервере без awg0.conf AWG «держал» 443/udp и
    спорил за него с Hysteria."""
    if not os.path.isfile(AWG_CONFIG):
        return 0
    port = get_awg_port()
    try:
        with open(AWG_CONFIG, 'r') as f:
            has_key = any(l.strip().startswith('ListenPort') for l in f)
    except Exception:
        has_key = False
    return int(port or 0) if has_key else 0

def get_awg_params():
    """Парсит [Interface]-секцию awg0.conf и возвращает obf-параметры.
    Любая отсутствующая или нечисловая запись подменяется fallback-значением."""
    params = dict(_AWG_PARAMS_FALLBACK)
    try:
        with open(AWG_CONFIG, 'r') as f:
            in_interface = False
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    in_interface = line.lower() == '[interface]'
                    continue
                if not in_interface or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                k = k.strip()
                if k in _AWG_PARAM_KEYS:
                    val = v.strip()
                    if val:
                        params[k] = val
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return params

def load_clients():
    if not os.path.exists(CLIENTS_DB):
        return {}
    with open(CLIENTS_DB, 'r') as f:
        clients = json.load(f)
    changed = False
    for c in clients.values():
        if 'disabled' not in c:
            c['disabled'] = False
            changed = True
        if 'scheduled_action' not in c:
            c['scheduled_action'] = None
            changed = True
        if 'scheduled_at' not in c:
            c['scheduled_at'] = None
            changed = True
        if 'traffic_limit_gb' not in c:
            c['traffic_limit_gb'] = None
            changed = True
        if 'traffic_reset_day' not in c:
            c['traffic_reset_day'] = None
            changed = True
        if 'traffic_last_reset' not in c:
            c['traffic_last_reset'] = None
            changed = True
        if 'disabled_by_limit' not in c:
            c['disabled_by_limit'] = False
            changed = True
    if changed:
        with open(CLIENTS_DB, 'w') as f:
            json.dump(clients, f, indent=2)
    return clients

def save_clients(clients):
    with open(CLIENTS_DB, 'w') as f:
        json.dump(clients, f, indent=2)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', 1

def get_awg_status():
    stdout, _, rc = run_cmd(f'{AWG_BIN} show awg0')
    if rc != 0:
        return None
    return stdout

# === AWG access-log collector ===
# WireGuard/AWG не пишет per-connection лог. Панель сама собирает снапшоты
# `awg show awg0` и пишет их JSON-line в /opt/awg-panel/data/logs/awg_access.log.
# Каждая запись = peer на момент тика.
AWG_COLLECT_INTERVAL_SEC = 30

_TRANSFER_UNITS = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}

def _parse_awg_transfer(s):
    """'2.97 MiB received, 83.26 MiB sent' → (received_bytes, sent_bytes). На ошибке (0,0)."""
    if not s:
        return (0, 0)
    rec = 0
    sent = 0
    m_rec = re.search(r'([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\s+received', s)
    m_sent = re.search(r'([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\s+sent', s)
    try:
        if m_rec:
            rec = int(float(m_rec.group(1)) * _TRANSFER_UNITS.get(m_rec.group(2), 1))
        if m_sent:
            sent = int(float(m_sent.group(1)) * _TRANSFER_UNITS.get(m_sent.group(2), 1))
    except (ValueError, TypeError):
        pass
    return (rec, sent)

def _load_awg_totals():
    """{pubkey: {up_seen, down_seen, up_total, down_total}}.
    up = received from peer (peer upload), down = sent to peer (peer download)."""
    try:
        with open(AWG_TOTALS_DB, 'r') as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get('per_pubkey'), dict):
            return d['per_pubkey']
    except (OSError, ValueError):
        pass
    return {}

def _save_awg_totals(per_pubkey):
    try:
        tmp = AWG_TOTALS_DB + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'ts': time.strftime('%Y-%m-%d %H:%M'), 'per_pubkey': per_pubkey}, f)
        os.replace(tmp, AWG_TOTALS_DB)
    except OSError:
        pass

def _awg_collect_once():
    output = get_awg_status()
    if not output:
        return
    peers = parse_awg_show(output)
    if not peers:
        return
    # Накопительные суммы трафика. Если awg рестартнулся, счётчики peer сброшены
    # → берём текущее значение как дельту (как XRay делает с persisted vs live).
    try:
        per_pubkey = _load_awg_totals()
        for p in peers:
            pk = p.get('public_key') or ''
            if not pk:
                continue
            cur_up, cur_down = _parse_awg_transfer(p.get('transfer') or '')
            row = per_pubkey.get(pk) or {'up_seen': 0, 'down_seen': 0, 'up_total': 0, 'down_total': 0}
            d_up = cur_up - row.get('up_seen', 0)
            if d_up < 0:
                d_up = cur_up  # счётчик ресетнулся (awg restart)
            d_down = cur_down - row.get('down_seen', 0)
            if d_down < 0:
                d_down = cur_down
            row['up_total'] = int(row.get('up_total', 0)) + max(0, d_up)
            row['down_total'] = int(row.get('down_total', 0)) + max(0, d_down)
            row['up_seen'] = cur_up
            row['down_seen'] = cur_down
            per_pubkey[pk] = row
        _save_awg_totals(per_pubkey)
    except Exception:
        pass
    try:
        os.makedirs(PANEL_LOGS_DIR, exist_ok=True)
    except Exception:
        return
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(AWG_ACCESS_LOG, 'a') as f:
            for p in peers:
                ep = p.get('endpoint') or ''
                hs = p.get('latest_handshake') or ''
                tr = p.get('transfer') or ''
                # Записываем только peer-ов с реально активным endpoint (есть кто и где).
                if not ep or ep == '(none)':
                    continue
                ip = ep.rsplit(':', 1)[0] if ':' in ep else ep
                rec = {
                    'ts': ts,
                    'pubkey': p.get('public_key', ''),
                    'endpoint': ep,
                    'ip': ip,
                    'latest_handshake': hs,
                    'transfer': tr,
                }
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass

def _awg_collector_loop():
    # Sleep сначала, чтобы дождаться полной загрузки модуля
    # (parse_awg_show определена ниже по файлу).
    while True:
        try:
            time.sleep(AWG_COLLECT_INTERVAL_SEC)
            _awg_collect_once()
        except Exception:
            pass

threading.Thread(target=_awg_collector_loop, daemon=True).start()

# Сбор destinations (conntrack + домены из dnsmasq) вынесен в awg_dest_log.py:
# коллектор, пункт зависимостей и роуты свитча. Подключение — в конце файла.

def parse_awg_show(output):
    if not output:
        return []
    peers = []
    current_peer = None
    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('peer:'):
            if current_peer:
                peers.append(current_peer)
            current_peer = {'public_key': line.split('peer:')[1].strip()}
        elif current_peer:
            if line.startswith('endpoint:'):
                current_peer['endpoint'] = line.split('endpoint:')[1].strip()
            elif line.startswith('allowed ips:'):
                current_peer['allowed_ips'] = line.split('allowed ips:')[1].strip()
            elif line.startswith('latest handshake:'):
                current_peer['latest_handshake'] = line.split('latest handshake:')[1].strip()
            elif line.startswith('transfer:'):
                current_peer['transfer'] = line.split('transfer:')[1].strip()
    if current_peer:
        peers.append(current_peer)
    return peers

_AWG_NETWORK_FALLBACK = '10.20.0.1/24'

def get_awg_interface_address():
    """[Interface] Address из awg0.conf — реальный CIDR серверного интерфейса.
    Возвращает строку 'X.X.X.X/NN' или fallback, если файл/ключ недоступен."""
    try:
        with open(AWG_CONFIG, 'r') as f:
            in_interface = False
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    in_interface = line.lower() == '[interface]'
                    continue
                if not in_interface or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                if k.strip() == 'Address':
                    val = v.strip().split(',')[0].strip()
                    if '/' in val:
                        return val
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return _AWG_NETWORK_FALLBACK

def get_awg_iface_ip():
    """IP-часть [Interface] Address (без префикса). На этом IP будет слушать локальный DNS
    для логирования доменов клиентов AWG. Fallback — '10.20.0.1'."""
    import ipaddress
    addr = get_awg_interface_address()
    try:
        return str(ipaddress.ip_interface(addr).ip)
    except ValueError:
        return '10.20.0.1'

def get_awg_network_str():
    """CIDR серверной сети AWG ('10.9.9.0/24'). Используется для фильтра conntrack."""
    import ipaddress
    addr = get_awg_interface_address()
    try:
        return str(ipaddress.ip_interface(addr).network)
    except ValueError:
        return '10.20.0.0/24'

def get_next_ip(clients):
    import ipaddress
    iface_addr = get_awg_interface_address()
    try:
        net = ipaddress.ip_interface(iface_addr).network
        server_ip = str(ipaddress.ip_interface(iface_addr).ip)
    except ValueError:
        net = ipaddress.ip_network(_AWG_NETWORK_FALLBACK, strict=False)
        server_ip = '10.20.0.1'
    used_ips = {server_ip}
    for c in clients.values():
        used_ips.add(c.get('address', '').replace('/32', ''))
    for host in net.hosts():
        ip = str(host)
        if ip == server_ip:
            continue
        if ip not in used_ips:
            return ip
    return None

def generate_keys():
    priv_out, _, _ = run_cmd(f'{AWG_BIN} genkey')
    pub_out, _, _ = run_cmd(f'echo "{priv_out}" | {AWG_BIN} pubkey')
    return priv_out, pub_out

def add_peer_to_config(public_key, allowed_ip):
    with open(AWG_CONFIG, 'a') as f:
        f.write(f'\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {allowed_ip}/32\n')
    run_cmd(f'{AWG_BIN} set awg0 peer {public_key} allowed-ips {allowed_ip}/32')

def remove_peer_from_config(public_key):
    run_cmd(f'{AWG_BIN} set awg0 peer {public_key} remove')
    with open(AWG_CONFIG, 'r') as f:
        content = f.read()
    # Remove peer block
    pattern = rf'\n\[Peer\]\nPublicKey\s*=\s*{re.escape(public_key)}\nAllowedIPs\s*=\s*[^\n]+\n?'
    content = re.sub(pattern, '\n', content)
    with open(AWG_CONFIG, 'w') as f:
        f.write(content.strip() + '\n')

def generate_client_config(private_key, address, dns_local=False):
    """dns_local=True → DNS клиента = IP внутри туннеля (наш локальный dnsmasq), для логирования
    доменов. False → стандарт 1.1.1.1, домены НЕ логируются (только destination IP через conntrack)."""
    server_pub = ''
    with open(AWG_CONFIG, 'r') as f:
        for line in f:
            if line.strip().startswith('PrivateKey'):
                server_priv = line.split('=', 1)[1].strip()
                pub_out, _, _ = run_cmd(f'echo "{server_priv}" | {AWG_BIN} pubkey')
                server_pub = pub_out
                break

    awg_p = get_awg_params()
    obf_lines = []
    for key in _AWG_PARAM_KEYS:
        if key in awg_p:
            obf_lines.append(f'{key} = {awg_p[key]}')
    obf_block = '\n'.join(obf_lines)
    dns_ip = get_awg_iface_ip() if dns_local else '1.1.1.1'
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {address}/32
DNS = {dns_ip}
{obf_block}

[Peer]
PublicKey = {server_pub}
Endpoint = {get_server_ip()}:{get_awg_port()}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
    return config

# Routes
@app.route('/')
def index():
    # Режим «только по ключу» (Reality): корень закрыт, панель только на login_path.
    if SERVER_CFG.get('login_block_root'):
        return ('Not Found', 404)
    if SERVER_CFG.get('fake_enabled'):
        idx = os.path.join(PUBLIC_DIR, 'index.html')
        if os.path.isfile(idx):
            return send_from_directory(PUBLIC_DIR, 'index.html')
        return ('Not Found', 404)
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/favicon.ico')
def favicon():
    # key-only: корень закрыт — не палим иконку панели.
    if SERVER_CFG.get('login_block_root'):
        return ('Not Found', 404)
    if SERVER_CFG.get('fake_enabled'):
        fav = os.path.join(PUBLIC_DIR, 'favicon.ico')
        if os.path.isfile(fav):
            return send_from_directory(PUBLIC_DIR, 'favicon.ico')
    return send_from_directory(PANEL_ROOT, 'fox.ico', mimetype='image/x-icon')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    pwd = data.get('password', '')
    ip = _client_ip()
    if hashlib.sha256(pwd.encode()).hexdigest() == PANEL_PASSWORD_HASH:
        session.permanent = True
        session['authenticated'] = True
        rec_id = audit('info', f'Login OK from {ip}')
        return jsonify({'ok': True, 'audit_id': rec_id})
    audit('warn', f'Login FAIL from {ip}')
    return jsonify({'error': 'Wrong password'}), 403

@app.route('/api/audit/client-ip', methods=['POST'])
@login_required
def audit_client_ip():
    """Дописывает в запись Login OK реальный IP+geo, полученные фронтом
    через api.ru.dog/v1/me (см. app.js). Принимает {audit_id, ip, country, city}."""
    data = request.json or {}
    rec_id = data.get('audit_id') or ''
    ip = (data.get('ip') or '').strip()
    country = (data.get('country') or '').strip()
    city = (data.get('city') or '').strip()
    if not rec_id or not ip or not re.match(r'^[0-9a-fA-F\.:]{3,45}$', ip):
        return jsonify({'error': 'bad'}), 400
    geo_parts = [p for p in (country, city) if p]
    geo = f' ({", ".join(geo_parts)})' if geo_parts else ''
    audit_update_msg(rec_id, f'Login OK from {ip}{geo}')
    return jsonify({'ok': True})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    audit('info', f'Logout from {_client_ip()}')
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/restart', methods=['POST'])
@login_required
def restart_panel():
    audit('info', 'Restart requested by admin')
    subprocess.Popen([
        'systemd-run', '--no-block', '--collect',
        '/bin/bash', '-c',
        'sleep 1 && systemctl restart awg-panel'
    ])
    return jsonify({'ok': True})

# === Update mechanism ===
def _http_get_text(url, timeout=8):
    req = urllib.request.Request(url, headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', errors='replace')

def _http_get_bytes(url, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def _read_local_geo_version():
    """Локальная версия гео = поле geo_version в server.json (дата YYYYMMDD).
    Живёт в server.json, а не в manifest.json: обновление кода затирает манифест."""
    v = str(SERVER_CFG.get('geo_version') or '').strip()
    return v if re.match(r'^\d{8}$', v) else ''

def _write_local_geo_version(v):
    """Пишет дату гео в server.json."""
    try:
        SERVER_CFG['geo_version'] = v
        _save_server_config(SERVER_CFG)
        return True
    except Exception:
        return False

def _fetch_remote_geo_version():
    """Тянет одной строкой содержимое GEO_BASE_URL/geolite2_data.txt — это дата YYYYMMDD."""
    try:
        v = _http_get_text(GEO_BASE_URL.rstrip('/') + '/geolite2_data.txt').strip()
        if re.match(r'^\d{8}$', v):
            return v
    except Exception as e:
        audit('warn', f'Geo version fetch failed: {e}')
    return ''

def _vtuple(v):
    """'1.2.3' → (1,2,3); junk → (0,)"""
    try:
        return tuple(int(x) for x in str(v).split('.'))
    except Exception:
        return (0,)


def _zip_member_bytes(zf, names, rel):
    """Достать файл rel из zip с учётом возможной верхней папки (напр. 'awg-panel/').
    Возвращает bytes; KeyError, если не найден."""
    rel = rel.lstrip('/')
    if rel in names:
        return zf.read(rel)
    cands = [n for n in names if n.endswith('/' + rel)]
    if cands:
        return zf.read(min(cands, key=len))
    raise KeyError(rel)

def _restart_panel_soon():
    """Отложенный перезапуск панели (чтобы успеть отдать HTTP-ответ)."""
    subprocess.Popen([
        'systemd-run', '--no-block', '--collect',
        '/bin/bash', '-c',
        'sleep 2 && systemctl restart awg-panel'
    ])

def _do_geo_update(remote_v):
    """Ядро гео-обновления: качает mmdb + countries.zip, пишет geo_version в server.json.
    Возвращает (ok, err). Перезапуск (чтобы перечитать БД) делает вызывающий."""
    data_dir = DATA_GEO_DIR
    os.makedirs(data_dir, exist_ok=True)
    try:
        for local_name, remote_name in GEO_FILES.items():
            url = GEO_BASE_URL.rstrip('/') + '/' + remote_name
            audit('progress', f'Скачиваю {remote_name}')
            data = _http_get_bytes(url, timeout=120)
            target = os.path.join(data_dir, local_name)
            tmp = target + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(data)
            os.replace(tmp, target)
            audit('info', f'Обновлён {local_name} ({len(data) // 1024} КБ)')
        # Country IP-ranges (для клиентских правил по странам) — тот же цикл, что и геобазы.
        try:
            audit('progress', 'Скачиваю countries.zip')
            n_countries = _countries_download_and_store()
            audit('info', f'Диапазоны стран обновлены: {n_countries} стран')
        except Exception as ce:
            audit('warn', f'countries.zip не обновлён: {ce}')
        if not _write_local_geo_version(remote_v):
            audit('warn', 'Не удалось записать geo_version в server.json')
        return True, ''
    except Exception as e:
        audit('error', f'Geo update failed: {e}')
        return False, str(e)

def _do_geo_update_response():
    remote_v = _fetch_remote_geo_version()
    if not remote_v:
        return jsonify({'ok': False, 'error': 'Не удалось получить версию гео с CDN'}), 400
    audit('info', f'Geo update: starting (target {remote_v})')
    SERVER_CFG['geo_last_check'] = int(time.time()); _save_server_config(SERVER_CFG)
    ok, err = _do_geo_update(remote_v)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 500
    audit('info', f'Geo update: done (v{remote_v}). Перезапуск для перечитки БД.')
    # geo readers загружаются один раз на старте — нужен рестарт, чтобы подхватить.
    _restart_panel_soon()
    return jsonify({'ok': True, 'new_version': remote_v})

# === Авто-обновление (единый фоновый воркер для панели / гео / blackmatrix7) ===
# Свитчи *_auto_update в server.json (дефолт ВКЛ). Для каждого: если свитч включён и
# с прошлой проверки прошло >= интервала — проверяем и при наличии свежего применяем
# БЕЗ запроса, пишем в журнал. last_check ставим при КАЖДОЙ проверке (это «дата
# последней проверки обновления»), а не только при успешном апдейте.
def _geo_newer(remote, local):
    try:
        if not remote: return False
        if not local:  return True
        return int(remote) > int(local)
    except Exception:
        return bool(remote) and remote != local

# === Audit endpoint ===
@app.route('/api/audit')
@login_required
def audit_recent():
    n = int(request.args.get('n', 100))
    n = max(1, min(n, 400))
    with AUDIT_LOCK:
        items = list(AUDIT_RING)[-n:]
    return jsonify({'items': items})

# === Admin password change ===
@app.route('/api/admin/password-state')
@login_required
def admin_password_state():
    """Временный ли сейчас пароль: панель просит сменить сгенерированный при установке."""
    return jsonify({'must_change': bool(ADMIN.get('must_change'))})


@app.route('/api/admin/change-password', methods=['POST'])
@login_required
def admin_change_password():
    body = request.get_json(force=True) or {}
    old = (body.get('old') or '').strip()
    new = (body.get('new') or '').strip()
    global PANEL_PASSWORD_HASH, ADMIN
    if hashlib.sha256(old.encode()).hexdigest() != PANEL_PASSWORD_HASH:
        return jsonify({'ok': False, 'error': 'Старый пароль неверен'}), 403
    if len(new) < 6:
        return jsonify({'ok': False, 'error': 'Новый пароль слишком короткий (мин 6)'}), 400
    new_hash = hashlib.sha256(new.encode()).hexdigest()
    ADMIN['password_hash'] = new_hash
    ADMIN.pop('must_change', None)
    PANEL_PASSWORD_HASH = new_hash
    with open(ADMIN_FILE, 'w') as f:
        json.dump(ADMIN, f)
    # Пароль первого входа больше не актуален — файл с ним не должен лежать на диске.
    try:
        os.remove(os.path.join(os.path.dirname(ADMIN_FILE), 'first_login.txt'))
    except Exception:
        pass
    audit('info', 'Admin password changed')
    return jsonify({'ok': True})

SERVICE_UNITS = {
    'awg':  ['awg-quick@awg0'],
    'xray': ['xray'],
    'mtg':  ['mtg'],
    # Telegram WEB-прокси (modules/tgweb/): установка, конфиг и удаление — в
    # пакете, а состояние юнита и пункты «остановлен / автозапуск» — общие.
    'tgweb': ['telemt'],
}

# Per-protocol bin paths used to detect "не установлен" (бинаря нет → ставить нечего)
PROTO_BINS = {
    'awg':  AWG_BIN,
    'xray': XRAY_BIN,
    'mtg':  MTG_BIN,
    'tgweb': '/usr/local/bin/telemt',
}

def _proto_state(proto):
    """Returns one of: 'not_installed' | 'stopped' | 'active'.

    Installed = бинарь существует ИЛИ (для AWG) уже поднят интерфейс.
    Active   = systemd-юнит active ИЛИ (для AWG) интерфейс up.
    """
    bin_path = PROTO_BINS.get(proto)
    iface_up = (proto == 'awg' and _awg_iface_exists())
    installed = (bin_path and os.path.exists(bin_path)) or iface_up
    if not installed:
        return 'not_installed'
    if proto == 'awg':
        return 'active' if _awg_real_running() else 'stopped'
    units = SERVICE_UNITS.get(proto) or []
    if not units:
        return 'stopped'
    _, _, rc = run_cmd(f'systemctl is-active --quiet {units[0]}')
    return 'active' if rc == 0 else 'stopped'

def _awg_iface_exists():
    _, _, rc = run_cmd('ip link show awg0')
    return rc == 0

def _awg_real_running():
    """AWG is 'running' if either the systemd unit is active OR the interface
    is up. Treat both signals as truth — interface presence is what users feel."""
    _, _, rc_unit = run_cmd('systemctl is-active --quiet awg-quick@awg0')
    return rc_unit == 0 or _awg_iface_exists()

def _awg_force_down():
    """Bring AWG down whatever the state — handle the failed-unit-but-iface-up case."""
    subprocess.run(['systemctl', 'stop', 'awg-quick@awg0'], check=False, capture_output=True, timeout=15)
    if _awg_iface_exists():
        # Interface lingered (unit failed mid-stop or external bring-up). Force delete.
        run_cmd('ip link delete awg0')
        audit('warn', 'AWG: интерфейс остался после systemctl stop, удалён через ip link delete')

def _awg_force_up():
    """Start AWG, recovering from 'already exists' if the previous shutdown left iface."""
    if _awg_iface_exists():
        # Stale interface from a broken state — clean before starting.
        run_cmd('ip link delete awg0')
        audit('warn', 'AWG: найден stale-интерфейс, удалён перед стартом')
    out, err, rc = run_cmd('systemctl start awg-quick@awg0')
    if rc != 0 and 'already exists' in (err + out).lower():
        run_cmd('ip link delete awg0')
        out, err, rc = run_cmd('systemctl start awg-quick@awg0')
    return rc

@app.route('/api/service/toggle', methods=['POST'])
@login_required
def service_toggle():
    body = request.get_json(force=True) or {}
    proto = body.get('proto') or ''
    units = SERVICE_UNITS.get(proto)
    if not units:
        return jsonify({'ok': False, 'error': 'Unknown protocol'}), 400

    if proto == 'awg':
        # Use real running detection (unit OR interface) so UI and toggle agree.
        running = _awg_real_running()
        action = 'stop' if running else 'start'
        audit('info', f'Service awg → {action} (real_running={running})')
        if action == 'stop':
            _awg_force_down()
        else:
            _awg_force_up()
        new_running = _awg_real_running()
        return jsonify({'ok': True, 'proto': proto, 'running': new_running, 'action': action})

    # Generic path for xray / mtg
    _, _, rc = run_cmd(f'systemctl is-active --quiet {units[0]}')
    running = (rc == 0)
    action = 'stop' if running else 'start'
    if proto == 'xray':
        if action == 'start':
            ok, msg = _tgweb_before_xray()
            if not ok:
                return jsonify({'ok': False, 'error': msg, 'proto': proto, 'running': False}), 409
        _tgweb_reconcile_later()
    audit('info', f'Service {proto} → {action} (units: {",".join(units)})')
    for u in units:
        subprocess.run(['systemctl', action, u], check=False)
    _, _, rc2 = run_cmd(f'systemctl is-active --quiet {units[0]}')
    return jsonify({'ok': True, 'proto': proto, 'running': rc2 == 0, 'action': action})


# === Единое управление сервисами протоколов ==================================
#
# Кнопки «Перезапустить / Остановить / Запустить / Удалить» одинаковы у всех
# протоколов и живут в одной модалке «Настройки протокола». Раньше каждый
# протокол делал это по-своему (mtg — ⏻ на плитке, XRay — никак), поэтому
# набор действий сведён сюда.

# 'hysteria' есть в заголовках, но не в PROTO_BINS/SERVICE_UNITS: её сервисом
# управляет свой пакет (/api/hysteria/*), а не общие роуты протоколов.
PROTO_TITLES = {'awg': 'AmneziaWG', 'xray': 'XRay', 'mtg': 'MTProto',
                'hysteria': 'Hysteria 2', 'tgweb': 'Telegram WEB'}


def _service_state_blob(proto):
    """Состояние протокола одним словарём — им питается модалка настроек."""
    state = _proto_state(proto)
    units = SERVICE_UNITS.get(proto) or []
    enabled = False
    if units:
        out, _, _ = run_cmd(f'systemctl is-enabled {units[0]}')
        enabled = out.strip() in ('enabled', 'enabled-runtime')
    return {
        'proto': proto,
        'title': PROTO_TITLES.get(proto, proto),
        'installed': state != 'not_installed',
        'active': state == 'active',
        'autostart': enabled,
        'unit': units[0] if units else '',
        'bin': PROTO_BINS.get(proto, ''),
    }


@app.route('/api/service/state')
@login_required
def service_state():
    proto = (request.args.get('proto') or '').strip()
    if proto not in SERVICE_UNITS:
        return jsonify({'ok': False, 'error': 'Unknown protocol'}), 400
    return jsonify({'ok': True, **_service_state_blob(proto)})


@app.route('/api/service/action', methods=['POST'])
@login_required
def service_action():
    """start / stop / restart / autostart для awg, xray, mtg.

    Исход проверяется реально (is-active после действия), а не по коду возврата
    systemctl: у awg-quick юнит может отчитаться об успехе, оставив интерфейс.
    """
    body = request.get_json(force=True) or {}
    proto = (body.get('proto') or '').strip()
    action = (body.get('action') or '').strip()
    units = SERVICE_UNITS.get(proto)
    if not units:
        return jsonify({'ok': False, 'error': 'Unknown protocol'}), 400
    if action not in ('start', 'stop', 'restart', 'autostart_on', 'autostart_off'):
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    if proto == 'xray' and action in ('start', 'restart', 'autostart_on'):
        ok, msg = _tgweb_before_xray()
        if not ok:
            return jsonify({'ok': False, 'error': msg, **_service_state_blob(proto)}), 409

    audit('info', f'Сервис {PROTO_TITLES.get(proto, proto)} → {action}')
    if proto == 'xray':
        # Кто держит 443 для Telegram WEB, решается по состоянию XRay: встал в
        # TLS — WEB за его фоллбек; выключен с автозапуском — WEB берёт 443 сам.
        _tgweb_reconcile_later()

    if action in ('autostart_on', 'autostart_off'):
        verb = 'enable' if action == 'autostart_on' else 'disable'
        for u in units:
            subprocess.run(['systemctl', verb, u], check=False, capture_output=True, timeout=20)
        return jsonify({'ok': True, **_service_state_blob(proto)})

    if proto == 'awg':
        # У AWG «перезапуск» — это down+up с принудительной чисткой интерфейса:
        # systemctl restart на подвисшем awg-quick оставляет awg0 живым.
        if action in ('stop', 'restart'):
            _awg_force_down()
        if action in ('start', 'restart'):
            _awg_force_up()
        st = _service_state_blob('awg')
        want_active = action in ('start', 'restart')
        return jsonify({'ok': st['active'] == want_active, **st})

    for u in units:
        subprocess.run(['systemctl', action, u], check=False, capture_output=True, timeout=60)
    if action in ('start', 'restart'):
        time.sleep(1.5)
    st = _service_state_blob(proto)
    want_active = action in ('start', 'restart')
    if st['active'] != want_active:
        out, _, _ = run_cmd(f'journalctl -u {units[0]} -n 20 --no-pager')
        return jsonify({'ok': False, 'error': (out or 'сервис не в ожидаемом состоянии')[-1500:], **st})
    return jsonify({'ok': True, **st})


# Что именно панель сносит при удалении протокола. AWG в списке нет намеренно:
# он ставится модулем ядра (DKMS), и снос из панели легко оставляет сервер без
# сети — там только инструкция.
PROTO_UNINSTALL = {
    'xray': {
        'units': ['xray'],
        'paths': ['/usr/local/bin/xray', '/usr/local/etc/xray',
                  '/etc/systemd/system/xray.service',
                  '/etc/systemd/system/xray@.service',
                  '/etc/systemd/system/xray.service.d'],
        'data': [],          # заполняется в рантайме: DATA_XRAY_DIR
    },
    'mtg': {
        'units': ['mtg'],
        'paths': ['/usr/local/bin/mtg', '/etc/mtg',
                  '/etc/systemd/system/mtg.service',
                  '/etc/systemd/system/mtg.service.d'],
        'data': [],
    },
}


@app.route('/api/service/uninstall', methods=['POST'])
@login_required
def service_uninstall():
    """Снос протокола с сервера. purge_data=true — вместе с клиентами панели.

    Клиенты по умолчанию остаются: снести протокол ради переустановки и потерять
    при этом весь список выданных конфигов — не то, чего ждёшь от кнопки.
    """
    body = request.get_json(force=True) or {}
    proto = (body.get('proto') or '').strip()
    purge = bool(body.get('purge_data'))
    spec = PROTO_UNINSTALL.get(proto)
    if not spec:
        return jsonify({'ok': False, 'error': 'Этот протокол из панели не удаляется'}), 400

    for u in spec['units']:
        subprocess.run(['systemctl', 'disable', '--now', u], check=False, capture_output=True, timeout=30)
    for p in spec['paths']:
        try:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.exists(p):
                os.remove(p)
        except Exception as e:
            audit('warn', f'{proto}: не удалось удалить {p}: {e}')
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=20)

    if purge:
        data_dir = {'xray': DATA_XRAY_DIR, 'mtg': DATA_MTPROTO_DIR}.get(proto)
        if data_dir:
            shutil.rmtree(data_dir, ignore_errors=True)

    # Протокол больше не установлен — прячем его вкладку, иначе панель сама себе
    # нарисует предупреждение «включён, но не установлен».
    enabled = SERVER_CFG.get('enabled_protocols')
    if isinstance(enabled, list) and proto in enabled:
        SERVER_CFG['enabled_protocols'] = [p for p in enabled if p != proto]
        _save_server_config(SERVER_CFG)

    _VERSION_CACHE.clear()
    audit('warn', f'{PROTO_TITLES.get(proto, proto)} удалён с сервера'
                  f'{" вместе с данными панели" if purge else ""}')
    if proto == 'xray':
        # 443 освободился — Telegram WEB (если стоит) займёт его сам.
        _tgweb_reconcile_later()
    return jsonify({'ok': True})

# === Server config (toggles, mtg port, etc.) ===
@app.route('/api/server/config', methods=['GET'])
@login_required
def server_config_get():
    cfg = dict(SERVER_CFG)
    # Шапка панели отображает фактический IP, который пойдёт в клиентские конфиги.
    cfg['server_ip'] = get_server_ip()
    # База адреса входа (scheme+host) для превью URL: домен+https если есть серт, иначе IP+http.
    cfg['panel_access'] = _panel_access_info()
    # Публичный адрес для клиентских ссылок и сайта-маскировки — без порта админки.
    cfg['public_access'] = _public_access_info()
    # Системная таймзона сервера — чтобы фронт показывал ВСЕ epoch-метки
    # (журнал, проверки) в системном времени сервера, а не в зоне браузера.
    lt = time.localtime()
    resp = jsonify({
        'config': cfg,
        'panel_version': PANEL_VERSION,
        'server_tz': {
            'offset_sec': lt.tm_gmtoff if lt.tm_gmtoff is not None else 0,
            'name': time.strftime('%Z') or 'UTC',
        },
        'paths': {
            'panel_root': PANEL_ROOT,
            'public_dir': PUBLIC_DIR,
            'public_exists': os.path.isdir(PUBLIC_DIR),
            'public_index_exists': os.path.isfile(os.path.join(PUBLIC_DIR, 'index.html')),
        },
    })
    resp.headers['Cache-Control'] = 'no-store'
    return resp

@app.route('/api/server/config', methods=['POST'])
@login_required
def server_config_set():
    body = request.get_json(force=True) or {}
    allowed_keys = {'enabled_protocols', 'enabled_platforms', 'mtg_fake_host', 'sni', 'server_name', 'profile_naming', 'fake_enabled', 'login_path', 'login_block_root', 'settings_favorites', 'server_ip_override', 'tab_order',
                    'panel_check_interval_days', 'panel_auto_update',
                    'geo_check_interval_days', 'geo_auto_update',
                    'bm7_check_interval_days', 'bm7_auto_update'}
    # Свитчи авто-обновления (bool) и периоды проверки (int дней, >=1).
    _bool_keys = {'panel_auto_update', 'geo_auto_update', 'bm7_auto_update'}
    _interval_keys = {'panel_check_interval_days', 'geo_check_interval_days', 'bm7_check_interval_days'}
    changes = {}
    for k, v in body.items():
        if k not in allowed_keys:
            continue
        if k in _bool_keys:
            v = bool(v)
        if k in _interval_keys:
            try:
                v = max(1, int(v))
            except Exception:
                return jsonify({'ok': False, 'error': f'{k}: ожидается целое число дней (>=1)'}), 400
        if k == 'server_name':
            v = _validate_safe_name(v)
            if not v:
                return jsonify({'ok': False, 'error': 'server_name пустое или содержит только запрещённые символы'}), 400
        if k == 'login_path':
            checked = _validate_login_path(v)
            if checked is None:
                return jsonify({'ok': False, 'error': 'login_path: разрешены символы A-Z a-z 0-9 . _ -, минимум 1 символ'}), 400
            v = checked
        if k == 'fake_enabled':
            v = bool(v)
        if k == 'login_block_root':
            v = bool(v)
        if k == 'settings_favorites':
            if not isinstance(v, list):
                return jsonify({'ok': False, 'error': 'settings_favorites must be a list'}), 400
            v = [x for x in v if isinstance(x, str) and x in SETTINGS_ITEM_IDS]
        if k == 'tab_order':
            # Только порядок: группа → список коротких id. Что за id — решает
            # фронт (незнакомые просто встают в конец), здесь лишь форма.
            if not isinstance(v, dict):
                return jsonify({'ok': False, 'error': 'tab_order must be an object'}), 400
            v = {
                g: [x for x in ids if isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,40}', x)][:30]
                for g, ids in v.items()
                if isinstance(g, str) and re.fullmatch(r'[a-z0-9_]{1,20}', g) and isinstance(ids, list)
            }
        if k == 'server_ip_override':
            v = (v or '').strip()
            # IP может не совпадать ни с одним локальным интерфейсом: в облаках с NAT
            # (Yandex Cloud, GCP, AWS) белый адрес висит на NAT провайдера, внутри ВМ
            # виден только серый. Поэтому проверяем только валидность IPv4.
            if v and not _is_valid_ipv4(v):
                return jsonify({'ok': False, 'error': 'server_ip_override должен быть IPv4 или пустой строкой'}), 400
        SERVER_CFG[k] = v
        changes[k] = v
    _save_server_config(SERVER_CFG)
    ip = _client_ip()
    sensitive = {'fake_enabled', 'login_block_root', 'login_path', 'server_ip_override'}
    for k in sensitive:
        if k in changes:
            audit('warn', f'Server config [{k}] → {changes[k]!r} (from {ip})')
    rest = {k: v for k, v in changes.items() if k not in sensitive}
    if rest:
        summary = ', '.join(f'{k}={v}' for k, v in rest.items())
        audit('info', f'Server config: {summary}')
    return jsonify({'ok': True, 'config': SERVER_CFG})

# === Доступ к панели по отдельному порту (для Reality, когда 443 занят VPN) ===
# Панель публикует себя своим nginx-блоком в выделенном файле. Конфиги XRay/чужие
# сайты НЕ трогаются — только собственный файл awg-panel-access.
# Адрес без https:// на TLS-порту: вместо голого «400 The plain HTTP request was sent
# to HTTPS port» nginx переводит на https (497 — его внутренний код для этого случая).
PANEL_HTTP_REDIRECT = '    error_page 497 =301 https://$host:$server_port$request_uri;\n'
PANEL_NGINX_SITE = '/etc/nginx/sites-available/awg-panel-access'
PANEL_NGINX_LINK = '/etc/nginx/sites-enabled/awg-panel-access'

def _find_le_cert():
    """(fullchain, privkey, domain) первого Let's Encrypt-серта или None."""
    base = '/etc/letsencrypt/live'
    try:
        for d in sorted(os.listdir(base)):
            full = os.path.join(base, d, 'fullchain.pem')
            key = os.path.join(base, d, 'privkey.pem')
            if os.path.isfile(full) and os.path.isfile(key):
                return (full, key, d)
    except Exception:
        pass
    return None

def _panel_access_info():
    """scheme/host/base для адреса входа в панель. Домен+https если есть LE-серт,
    иначе IP+http. base включает порт, если он задан.

    Без своего порта панели вход идёт через 443, а там TLS терминирует XRay —
    значит и хост обязан совпадать с ЕГО serverName, иначе клиент получает серт
    на чужое имя. _find_le_cert() отдаёт первый каталог в /etc/letsencrypt/live,
    и когда сертов несколько (домен сайта + домен XRay), он запросто оказывается
    не тем: так «Адрес панели» в мониторинге разъехался с карточкой маскировки.
    С panel_port TLS поднимает nginx с тем самым первым сертом — там оставляем
    его; при Reality serverName чужой (маскировка), туда лезть нельзя."""
    cert = _find_le_cert()
    if cert:
        scheme, host = 'https', cert[2]
    else:
        scheme, host = 'http', get_server_ip()
    port = int(SERVER_CFG.get('panel_port') or 0)
    if not port:
        try:
            xp = get_xray_inbound_params()
            if xp.get('security') == 'tls' and xp.get('sni'):
                scheme, host = 'https', xp['sni']
        except Exception:
            pass
    base = f'{scheme}://{host}' + (f':{port}' if port else '')
    return {'port': port, 'scheme': scheme, 'host': host, 'base': base}

def _public_access_info():
    """База для ссылок, которые открывает КЛИЕНТ: профили Shadowrocket/Loon/Clash,
    подписки, rule-set'ы стран и адрес сайта-маскировки.

    Это сознательно НЕ адрес панели. Панель может сидеть на своём порту
    (panel_port) или быть открыта через SSH-туннель на localhost — админский
    порт в клиентской ссылке не нужен: он выдаёт наружу существование админки,
    а при смене порта все выданные ссылки разом перестают открываться.

    Считает не эта функция, а profile_public_base() — единственный источник
    правды по публичному адресу, общий с update-url внутри самих
    профилей. Здесь только раскладываем результат для фронта: via_panel_port
    говорит UI, что 443 недоступен (Reality) и адрес взят с порта панели.
    """
    base, why = profile_public_base()
    port = int(SERVER_CFG.get('panel_port') or 0)
    try:
        security = get_xray_inbound_params().get('security') or ''
    except Exception:
        security = ''
    return {
        'base': base,
        'reason': why,
        'security': security,
        'via_panel_port': bool(base and port and base.endswith(f':{port}')),
    }

def _panel_port_reserved():
    """Порты, которые нельзя занимать под панель (заняты сервисами)."""
    res = {22, 80, 443, 5000, 8444}
    try: res.add(get_xray_port())
    except Exception: pass
    try: res.add(get_mtg_listen_port())
    except Exception: pass
    # Внутренние порты Telegram WEB: панель слушает 0.0.0.0 и заняла бы их.
    for _it in _tgweb_port_items():
        res.add(_it['port'])
    res.discard(0)
    return res

def _apply_panel_access_port(port):
    """Публикует/снимает доступ к панели на отдельном порту. TLS если есть LE-серт
    (тогда вход по домену с валидным сертом), иначе plain HTTP по IP."""
    prev = int(SERVER_CFG.get('panel_port') or 0)
    port = int(port or 0)
    if port:
        if port < 1 or port > 65535:
            raise ValueError('Порт должен быть 1–65535')
        if port in _panel_port_reserved():
            raise ValueError(f'Порт {port} занят сервисом — выбери другой')
    # снять публикацию
    if not port:
        for p in (PANEL_NGINX_LINK, PANEL_NGINX_SITE):
            try: os.remove(p)
            except FileNotFoundError: pass
        run_cmd('systemctl reload nginx')
        if prev: run_cmd(f'ufw delete allow {prev}/tcp')
        return {'published': False, 'url': ''}
    cert = _find_le_cert()
    if cert:
        full, key, domain = cert
        listen_line = f'listen {port} ssl;'
        tls_lines = (f'    ssl_certificate {full};\n'
                     f'    ssl_certificate_key {key};\n'
                     f'    ssl_protocols TLSv1.2 TLSv1.3;\n'
                     f'{PANEL_HTTP_REDIRECT}')
        scheme, host = 'https', domain
    else:
        listen_line = f'listen {port};'
        tls_lines = ''
        scheme, host = 'http', get_server_ip()
    conf = (f'server {{\n'
            f'    {listen_line}\n'
            f'    server_name _;\n'
            f'{tls_lines}'
            f'    location / {{\n'
            f'        proxy_pass http://127.0.0.1:5000;\n'
            f'        proxy_set_header Host $host;\n'
            f'        proxy_set_header X-Real-IP $remote_addr;\n'
            f'        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            f'        proxy_set_header X-Forwarded-Proto {scheme};\n'
            f'    }}\n'
            f'}}\n')
    prev_content = None
    if os.path.exists(PANEL_NGINX_SITE):
        try:
            with open(PANEL_NGINX_SITE) as f: prev_content = f.read()
        except Exception: prev_content = None
    with open(PANEL_NGINX_SITE, 'w') as f:
        f.write(conf)
    if not os.path.exists(PANEL_NGINX_LINK):
        try: os.symlink(PANEL_NGINX_SITE, PANEL_NGINX_LINK)
        except FileExistsError: pass
    out, err, rc = run_cmd('nginx -t')
    if rc != 0:
        # откат
        if prev_content is not None:
            with open(PANEL_NGINX_SITE, 'w') as f: f.write(prev_content)
        else:
            for p in (PANEL_NGINX_LINK, PANEL_NGINX_SITE):
                try: os.remove(p)
                except FileNotFoundError: pass
        raise RuntimeError(f'nginx -t не прошёл: {err or out}')
    run_cmd('systemctl reload nginx')
    run_cmd(f'ufw allow {port}/tcp')
    if prev and prev != port:
        run_cmd(f'ufw delete allow {prev}/tcp')
    login_path = SERVER_CFG.get('login_path', '/login.html')
    return {'published': True, 'tls': bool(cert), 'host': host,
            'url': f'{scheme}://{host}:{port}{login_path}'}

@app.route('/api/panel/access-port', methods=['POST'])
@login_required
def panel_access_port_set():
    data = request.get_json(force=True) or {}
    try:
        port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'порт должен быть числом'}), 400
    try:
        result = _apply_panel_access_port(port)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    SERVER_CFG['panel_port'] = port
    SERVER_CFG.pop('panel_port_auto', None)  # порт выбрал человек — дальше его не трогаем
    _save_server_config(SERVER_CFG)
    audit('warn', f'Доступ к панели: порт → {port or "снят"} (from {_client_ip()})')
    return jsonify({'ok': True, **result})

# === Ссылки на профили: откуда берётся база и почему её может не быть ========
# Профиль клиента отдаётся по URL, и этот URL обязан вести на панель СНАРУЖИ.
# Куда именно — зависит от того, что стоит на 443:
#   * TLS      — панель работает фоллбеком за XRay, ссылка идёт на его serverName;
#   * Reality  — фоллбек до панели не доходит в принципе, и снаружи её видно
#                только на отдельном порту (panel_port).
# Раньше базу считал каждый протокол сам и умел только первый случай, а UI при
# этом советовал включить порт — совет не срабатывал, ссылка всё равно не
# появлялась. Теперь база одна на всех, и рядом лежит разбор, чего не хватает.


def _awg_offline_peer(pk, info, totals):
    """Строка клиента, которого нет в живом `awg show`: сохранённые данные + накопленный трафик."""
    row = totals.get(pk) or {}
    up_t = int(row.get('up_total') or 0)
    down_t = int(row.get('down_total') or 0)
    return {
        'public_key': pk,
        'name': info.get('name', 'Unnamed'),
        'address': info.get('address', ''),
        'created': info.get('created', ''),
        'endpoint': '-',
        'latest_handshake': '-',
        'transfer': '-',
        'disabled': bool(info.get('disabled')),
        'scheduled_action': info.get('scheduled_action'),
        'scheduled_at': info.get('scheduled_at'),
        'dns_local': bool(info.get('dns_local')),
        'traffic_limit_gb': info.get('traffic_limit_gb'),
        'traffic_reset_day': info.get('traffic_reset_day'),
        'disabled_by_limit': bool(info.get('disabled_by_limit')),
        'up': up_t,
        'down': down_t,
        'total': up_t + down_t,
    }


@app.route('/api/status')
@login_required
def status():
    try:
        _run_awg_scheduler()
    except Exception as _e:
        audit('warn', f'AWG scheduler error: {_e}')
    output = get_awg_status()
    if output is None:
        # Интерфейс не поднят: сервис остановлен, awg-quick упал, бинаря нет.
        # Клиенты от этого никуда не делись — показываем их offline. Иначе панель
        # выглядит как «клиентов нет», а создание клиента с тем же именем упирается
        # в проверку дубликата по clients.json, необъяснимую с точки зрения глаза.
        try:
            _saved = load_clients()
            _totals = _load_awg_totals()
            _peers = [_awg_offline_peer(pk, info, _totals) for pk, info in _saved.items()]
        except Exception as _e:
            audit('warn', f'AWG status: не удалось прочитать сохранённых клиентов: {_e}')
            _peers = []
        return jsonify({
            'running': False,
            'state': _proto_state('awg'),
            'peers': _peers,
            # Без awg0.conf порта нет — плитка покажет «—», а не выдуманный 443.
            'server': {'port': get_awg_listen_port() or ''},
        })

    live_peers = parse_awg_show(output)
    clients = load_clients()
    # Накопительные тоталы трафика (обновляются фоновым _awg_collect_once).
    totals = _load_awg_totals()
    clients_changed = False

    # Merge live data with saved names + GeoIP + totals + лимит
    for peer in live_peers:
        pk = peer['public_key']
        if pk in clients:
            c = clients[pk]
            peer['name'] = c.get('name', 'Unnamed')
            peer['address'] = c.get('address', '')
            peer['created'] = c.get('created', '')
            peer['disabled'] = bool(c.get('disabled'))
            peer['scheduled_action'] = c.get('scheduled_action')
            peer['scheduled_at'] = c.get('scheduled_at')
            peer['dns_local'] = bool(c.get('dns_local'))
            peer['traffic_limit_gb'] = c.get('traffic_limit_gb')
            peer['traffic_reset_day'] = c.get('traffic_reset_day')
            peer['disabled_by_limit'] = bool(c.get('disabled_by_limit'))
        else:
            peer['name'] = 'Unknown'
            peer['address'] = peer.get('allowed_ips', '')
            peer['disabled'] = False
            peer['scheduled_action'] = None
            peer['scheduled_at'] = None
            peer['dns_local'] = False
            peer['traffic_limit_gb'] = None
            peer['traffic_reset_day'] = None
            peer['disabled_by_limit'] = False
        # Тоталы (up = received from peer, down = sent to peer — терминология XRay).
        row = totals.get(pk) or {}
        peer['up'] = int(row.get('up_total') or 0)
        peer['down'] = int(row.get('down_total') or 0)
        peer['total'] = peer['up'] + peer['down']
        # Авто-отключение по лимиту трафика (per-client) — зеркало XRay.
        if pk in clients:
            c = clients[pk]
            limit_gb = c.get('traffic_limit_gb')
            if limit_gb and not c.get('disabled') and peer['total'] >= int(limit_gb) * (1024 ** 3):
                remove_peer_from_config(pk)
                c['disabled'] = True
                c['disabled_by_limit'] = True
                peer['disabled'] = True
                peer['disabled_by_limit'] = True
                clients_changed = True
                audit('info', f'Авто-отключение AWG по лимиту {limit_gb} GB: {c.get("name")}')
        ep = peer.get('endpoint', '')
        if ep and ep != '-':
            ip = ep.rsplit(':', 1)[0]
            peer['geo'] = geoip_lookup(ip)
    if clients_changed:
        save_clients(clients)

    # Add offline clients
    live_keys = {p['public_key'] for p in live_peers}
    for pk, info in clients.items():
        if pk not in live_keys:
            live_peers.append(_awg_offline_peer(pk, info, totals))

    # Server info
    server_info = {}
    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('listening port:'):
            server_info['port'] = line.split(':')[1].strip()
        elif line.startswith('public key:'):
            server_info['public_key'] = line.split('public key:')[1].strip()
    # Если live-порт не нашли в awg show — подменим конфиговым (источник правды для клиентов).
    if not server_info.get('port'):
        server_info['port'] = get_awg_port()

    return jsonify({
        'running': True,
        'state': _proto_state('awg'),
        'server': server_info,
        'peers': live_peers
    })

@app.route('/api/clients', methods=['POST'])
@login_required
def create_client():
    data = request.json
    name = _normalize_client_name(data.get('name'))
    if not name:
        return jsonify({'error': 'Name required'}), 400

    clients = load_clients()
    # Check duplicate name
    for c in clients.values():
        if c.get('name') == name:
            return jsonify({'error': 'Name already exists'}), 400

    private_key, public_key = generate_keys()
    next_ip = get_next_ip(clients)
    if not next_ip:
        return jsonify({'error': 'No free IPs'}), 400

    add_peer_to_config(public_key, next_ip)

    client_config = generate_client_config(private_key, next_ip)

    clients[public_key] = {
        'name': name,
        'address': next_ip,
        'created': time.strftime('%Y-%m-%d %H:%M'),
        'config': client_config
    }
    save_clients(clients)
    audit('info', f'AWG peer создан: {name} ({next_ip})')

    return jsonify({
        'ok': True,
        'public_key': public_key,
        'name': name,
        'address': next_ip,
        'config': client_config
    })

@app.route('/api/clients/<path:public_key>', methods=['DELETE'])
@login_required
def delete_client(public_key):
    clients = load_clients()
    name = (clients.get(public_key) or {}).get('name') or public_key[:12] + '…'
    remove_peer_from_config(public_key)
    if public_key in clients:
        del clients[public_key]
        save_clients(clients)
    audit('info', f'AWG peer удалён: {name}')
    return jsonify({'ok': True})

def _awg_client_config_live(c):
    """Конфиг клиента с Endpoint по текущему адресу и порту сервера.

    Конфиг хранится текстом, собранным при создании клиента, и Endpoint в нём
    застывал: после смены порта AWG (или IP сервера) окно «Конфиг», QR и
    скачанный .conf продолжали отдавать старый порт — клиент не подключался.
    Строку Endpoint пересобираем при каждой выдаче тем же выражением, что и
    шаблон создания; остальной текст (ключи, обфускация, DNS) не трогаем."""
    cfg = c.get('config', '') or ''
    if not cfg:
        return cfg
    try:
        endpoint = f'{get_server_ip()}:{get_awg_listen_port() or get_awg_port()}'
    except Exception:
        return cfg
    return re.sub(r'^(\s*Endpoint\s*=\s*).*$', lambda m: m.group(1) + endpoint,
                  cfg, count=1, flags=re.M)


@app.route('/api/clients/<path:public_key>/config')
@login_required
def get_client_config(public_key):
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Client not found'}), 404
    return jsonify({'config': _awg_client_config_live(clients[public_key])})

@app.route('/api/clients/<path:public_key>/config-file')
@login_required
def get_client_config_file(public_key):
    """Return AWG client config as downloadable .conf with proper MIME type so
    Safari/Chrome don't save it as .txt. WireGuard / AmneziaWG iOS apps register
    application/x-wireguard-profile and similar."""
    clients = load_clients()
    if public_key not in clients:
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    c = clients[public_key]
    cfg = _awg_client_config_live(c)
    fname = _profile_filename(c.get('name', 'awg')) + '.conf'
    return (cfg, 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename={fname}',
        'Cache-Control': 'no-store',
    })

@app.route('/api/clients/<path:public_key>/disable', methods=['POST'])
@login_required
def awg_set_disabled(public_key):
    data = request.json or {}
    disabled = bool(data.get('disabled'))
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Not found'}), 404
    c = clients[public_key]
    was = bool(c.get('disabled'))
    c['disabled'] = disabled
    save_clients(clients)
    if disabled and not was:
        remove_peer_from_config(public_key)
        audit('info', f'AWG peer отключён: {c.get("name")}')
    elif not disabled and was:
        ip = (c.get('address') or '').split('/')[0]
        if ip:
            run_cmd(f'{AWG_BIN} set awg0 peer {public_key} allowed-ips {ip}/32')
        audit('info', f'AWG peer включён: {c.get("name")}')
    return jsonify({'ok': True, 'disabled': disabled})

@app.route('/api/clients/<path:public_key>/traffic/reset', methods=['POST'])
@login_required
def awg_reset_traffic_now(public_key):
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Not found'}), 404
    c = clients[public_key]
    _awg_reset_traffic_for_pubkey(public_key)
    today = time.strftime('%Y-%m-%d')
    c['traffic_last_reset'] = today
    _awg_reenable_if_disabled_by_limit(public_key, c)
    save_clients(clients)
    audit('info', f'Сброс трафика AWG (вручную): {c.get("name")}')
    return jsonify({'ok': True, 'reset_at': today})

@app.route('/api/clients/<path:public_key>/traffic/limit', methods=['POST'])
@login_required
def awg_set_traffic_limit(public_key):
    data = request.json or {}
    raw = data.get('gb', None)
    if raw in (None, '', 0, '0'):
        gb = None
    else:
        try:
            gb = int(raw)
            if gb < 1:
                return jsonify({'error': 'gb must be >= 1'}), 400
        except Exception:
            return jsonify({'error': 'gb must be integer'}), 400
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[public_key]['traffic_limit_gb'] = gb
    save_clients(clients)
    name = clients[public_key].get('name')
    audit('info', f'Лимит трафика AWG {name}: {gb} GB' if gb else f'Лимит трафика AWG снят: {name}')
    return jsonify({'ok': True, 'traffic_limit_gb': gb})

@app.route('/api/clients/<path:public_key>/traffic/reset-day', methods=['POST'])
@login_required
def awg_set_reset_day(public_key):
    data = request.json or {}
    raw = data.get('day', None)
    if raw in (None, '', 0, '0'):
        day = None
    else:
        try:
            day = int(raw)
            if day < 1 or day > 31:
                return jsonify({'error': 'day must be 1..31'}), 400
        except Exception:
            return jsonify({'error': 'day must be integer'}), 400
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[public_key]['traffic_reset_day'] = day
    save_clients(clients)
    audit('info', f'Установлен день сброса трафика AWG {clients[public_key].get("name")}: {day}')
    return jsonify({'ok': True, 'traffic_reset_day': day})

@app.route('/api/clients/<path:public_key>/schedule', methods=['POST'])
@login_required
def awg_set_schedule(public_key):
    data = request.json or {}
    raw_action = data.get('action')
    raw_date = data.get('date')
    if raw_action in (None, '', 'none'):
        action, date = None, None
    elif raw_action in ('delete', 'disable'):
        date = _validate_schedule_date(raw_date)
        if not date:
            return jsonify({'error': 'date must be future YYYY-MM-DD'}), 400
        action = raw_action
    else:
        return jsonify({'error': 'action must be delete|disable|none'}), 400
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[public_key]['scheduled_action'] = action
    clients[public_key]['scheduled_at'] = date
    save_clients(clients)
    audit('info', f'AWG schedule {clients[public_key].get("name")}: {action or "сброшено"} {date or ""}')
    return jsonify({'ok': True, 'scheduled_action': action, 'scheduled_at': date})

def _awg_reenable_if_disabled_by_limit(pk, c):
    """Если клиент был выключен авто-лимитом — включаем (трафик уже сброшен)."""
    if c.get('disabled') and c.get('disabled_by_limit'):
        c['disabled'] = False
        c['disabled_by_limit'] = False
        ip = (c.get('address') or '').split('/')[0]
        if ip:
            try:
                run_cmd(f'{AWG_BIN} set awg0 peer {pk} allowed-ips {ip}/32')
            except Exception:
                pass
        audit('info', f'Авто-включение AWG после сброса трафика: {c.get("name")}')
        return True
    return False

def _awg_reset_traffic_for_pubkey(pk):
    """Сброс накопительных тоталов AWG для пира — обнуляет up_total/down_total,
    но НЕ трогает up_seen/down_seen (чтобы не словить дельту от старого awg show)."""
    per = _load_awg_totals()
    row = per.get(pk) or {}
    # Запоминаем текущий live-снимок как "точку отсчёта новой эпохи".
    row['up_total'] = 0
    row['down_total'] = 0
    per[pk] = row
    _save_awg_totals(per)

def _run_awg_scheduler():
    today = time.strftime('%Y-%m-%d')
    clients = load_clients()
    changed = False
    to_delete = []
    for pk, c in list(clients.items()):
        # Ежемесячный сброс трафика per-client.
        rd = c.get('traffic_reset_day')
        if rd and _is_traffic_reset_due(rd, today) and c.get('traffic_last_reset') != today:
            _awg_reset_traffic_for_pubkey(pk)
            c['traffic_last_reset'] = today
            _awg_reenable_if_disabled_by_limit(pk, c)
            changed = True
            audit('info', f'Авто-сброс трафика AWG (день {rd}): {c.get("name")}')
        sa = c.get('scheduled_action')
        sd = c.get('scheduled_at')
        if not sa or not sd or sd > today:
            continue
        if sa == 'delete':
            to_delete.append(pk)
            audit('info', f'Auto-delete (по расписанию) AWG: {c.get("name")}')
        elif sa == 'disable':
            if not c.get('disabled'):
                c['disabled'] = True
                remove_peer_from_config(pk)
                audit('info', f'Auto-disable (по расписанию) AWG: {c.get("name")}')
            c['scheduled_action'] = None
            c['scheduled_at'] = None
            changed = True
    for pk in to_delete:
        remove_peer_from_config(pk)
        clients.pop(pk, None)
        changed = True
    if changed:
        save_clients(clients)

@app.route('/api/clients/<path:public_key>/rename', methods=['POST'])
@login_required
def rename_client(public_key):
    data = request.json
    name = _normalize_client_name(data.get('name'))
    if not name:
        return jsonify({'error': 'Name required'}), 400

    clients = load_clients()
    old_name = (clients.get(public_key) or {}).get('name')
    if public_key in clients:
        clients[public_key]['name'] = name
    else:
        # Peer exists in awg0.conf but not in clients.json (legacy/manual entry).
        # Create a stub so it can be managed from the panel.
        allowed_ip = ''
        live = parse_awg_show(get_awg_status() or '')
        for p in live:
            if p['public_key'] == public_key:
                allowed_ip = (p.get('allowed_ips', '') or '').split('/')[0]
                break
        clients[public_key] = {
            'name': name,
            'address': allowed_ip,
            'created': '',
            'config': ''
        }
    save_clients(clients)
    if old_name and old_name != name:
        audit('info', f'AWG peer переименован: {old_name} → {name}')
    elif not old_name:
        audit('info', f'AWG peer переименован: → {name}')
    return jsonify({'ok': True})

# ============================================================
# XRay (VLESS + Reality) management
# ============================================================

def load_xray_clients():
    if not os.path.exists(XRAY_CLIENTS_DB):
        return {}
    with open(XRAY_CLIENTS_DB, 'r') as f:
        clients = json.load(f)
    # Lazy migration: ensure every client has a subscription token + rule_lists.
    # rule_lists — единый набор: {lists: [ids]} (как geo_countries). Старые схемы
    # (плоский список / {shadowrocket,loon,clash[,surge]}) сливаем в один 'lists'.
    changed = False
    for c in clients.values():
        if not c.get('token'):
            c['token'] = secrets.token_hex(16)
            changed = True
        rl = c.get('rule_lists')
        if rl is None or not isinstance(rl, (list, dict)):
            c['rule_lists'] = {'lists': []}
            changed = True
        elif isinstance(rl, list):
            c['rule_lists'] = {'lists': list(rl)}
            changed = True
        elif 'lists' not in rl:
            # Объединяем старые per-platform наборы по id (порядок: sr, loon, clash, surge).
            union = list(dict.fromkeys(
                (rl.get('shadowrocket') or []) + (rl.get('loon') or [])
                + (rl.get('clash') or []) + (rl.get('surge') or [])))
            c['rule_lists'] = {'lists': union}
            changed = True
        elif not isinstance(rl.get('lists'), list):
            rl['lists'] = []
            changed = True
        # geo_mode/geo_countries migration
        if 'geo_mode' not in c:
            rl_now = c.get('rule_lists') or {}
            has_lists = bool(rl_now.get('lists'))
            if has_lists:
                c['geo_mode'] = 'lists'
                c['geo_countries'] = []
            elif c.get('bypass_ru'):
                c['geo_mode'] = 'direct'
                c['geo_countries'] = ['RU']
            else:
                c['geo_mode'] = 'off'
                c['geo_countries'] = []
            changed = True
        if not isinstance(c.get('geo_countries'), list):
            c['geo_countries'] = []
            changed = True
        # pending по странам (как у глобал-рул): дефолт = applied, меняется только из UI
        if 'geo_mode_pending' not in c:
            c['geo_mode_pending'] = c.get('geo_mode')
            changed = True
        if not isinstance(c.get('geo_countries_pending'), list):
            c['geo_countries_pending'] = list(c.get('geo_countries') or [])
            changed = True
        # Куда идёт трафик, НЕ попавший ни в один список (режим 'lists'):
        # 'direct' — как было (списки = что гнать в VPN), 'vpn' — наоборот,
        # всё через VPN, а списки работают как исключения (Direct/Block),
        # 'block' — режим белого списка: режем всё, кроме перечисленного.
        if c.get('lists_default') not in LISTS_DEFAULT_MODES:
            c['lists_default'] = 'direct'
            changed = True
        if c.get('lists_default_pending') not in LISTS_DEFAULT_MODES:
            c['lists_default_pending'] = c['lists_default']
            changed = True
        # DNS для клиентского конфига: бэкфилл из глоб. дефолта (по умолчанию off).
        if not isinstance(c.get('dns'), dict):
            c['dns'] = _global_dns_default()
            changed = True
        # Белый список IP: пустой = доступ с любого адреса (см. apply_allow_ip_rules).
        if not isinstance(c.get('allow_ips'), list):
            c['allow_ips'] = []
            changed = True
        # Чёрный список IP: пустой = никто не заблокирован.
        if not isinstance(c.get('block_ips'), list):
            c['block_ips'] = []
            changed = True
        # disabled / scheduled fields (lazy default)
        if 'disabled' not in c:
            c['disabled'] = False
        if 'scheduled_action' not in c:
            c['scheduled_action'] = None
        if 'scheduled_at' not in c:
            c['scheduled_at'] = None
    if changed:
        with open(XRAY_CLIENTS_DB, 'w') as f:
            json.dump(clients, f, indent=2)
    return clients

def save_xray_clients(clients):
    with open(XRAY_CLIENTS_DB, 'w') as f:
        json.dump(clients, f, indent=2)

# --- Каталог правил ---
# Сам каталог (чтение/запись, шаблоны, страны, глобальные правила) живёт в
# modules/rules.py; здесь остались только константы, которые читает и остающийся
# код — сборка профилей, реестр путей и апдейтер.

# Что выбирается на карточке клиента — единый набор 'lists' (как geo_countries).
CLIENT_RULE_PLATFORMS = ('lists',)


# === blackmatrix7 шаблоны — авто-обновление БИБЛИОТЕКИ шаблонов ===
# ВАЖНО: это обновляет только список ШАБЛОНОВ (кнопка «Шаблоны» в редакторе
# списков правил) — НЕ трогает xray_rule_lists.json (там только то, что юзер сам
# добавил/выбрал). Шаблоны — имена-папки blackmatrix7; фронт тянет их с
# /api/xray/rule-templates и строит URL сам (_tplUrlFor, генерация постоянна).
# Источник — byfox.dev/data/maxmind/blackmatrix7.txt: 1-я строка <!--DD.MM.YYYY-->,
# дальше по имени-папке на строку. Раз в N дней (server.json bm7_check_interval_days,
# дефолт 7) тихо проверяем дату; свежее локальной (server.json bm7_version) —
# перезаписываем кэш шаблонов. Период/свитч/last_check ведёт _auto_update_loop.
BM7_SERVICES_URL = GEO_BASE_URL.rstrip('/') + '/blackmatrix7.txt'
BM7_TEMPLATES_FILE = os.path.join(DATA_GEO_DIR, 'blackmatrix7_templates.json')  # {date, services[]}

# === Свои шаблоны правил (byfox.dev/data/awg-panel/rules) ===
# Структура на CDN: /rules/folders.txt (перечень папок-шаблонов) и
# /rules/<name>/{clash/rules.yaml, loon/rules.list, shadowrocket/rules.list}.
# Показываются в пикере «Шаблоны» вместе с blackmatrix7; период обновления общий
# с blackmatrix7 (_byfox_rules_sync_once дёргается из _bm7_sync_once).
BYFOX_RULES_BASE = UPDATE_BASE_URL.rstrip('/') + '/rules'
BYFOX_RULES_FILE = os.path.join(DATA_GEO_DIR, 'byfox_rules.json')  # {folders[], quic{plat:[lines]}, fetched}
# Особый шаблон: QUIC-fix. Его правила (AND,((PROTOCOL,UDP),(DEST-PORT,443),...),REJECT)
# нельзя отдать как RULE-SET (в них своя политика) — панель вставляет их ИНЛАЙНОМ
# в самое начало секции правил каждого выбравшего клиента. Кэшируются локально.
# id = имя папки на CDN. Историческое: список давно режет и TCP, и QUIC,
# но переименование папки — это миграция каталогов у всех клиентов.
ADS_TEMPLATE_ID = 'block_ads_trackers_quic'


# Периодическую проверку blackmatrix7 ведёт единый авто-апдейт-воркер
# (_auto_update_loop) — он же дёргает _bm7_sync_once (modules/rules.py) по
# интервалу/свитчу из server.json.

# === XRay Global rules (server-side routing for all VLESS clients) ===
# Двух-уровневое состояние:
#   pending — что выбрано в UI и пока не применено
#   applied — что реально записано в xray-config сейчас (last_update тут)
# Кнопка «Применить» во фронте показывается, когда pending != applied.
GLOBAL_FIELDS_DEFAULT = {
    'enabled': False,
    'mode': 'lists',          # 'lists' | 'via' | 'direct'
    'lists': [],
    'countries': [],
    # Глобальное расписание XRay (применяется ко всему сервису, переопределяет per-client)
    'scheduled_action': None,    # 'disable' | None  ('delete' для глобального не имеет смысла)
    'scheduled_at': None,        # 'YYYY-MM-DD'
    'traffic_reset_day': None,   # 1..31
    'traffic_limit_gb': None,    # >=1
    'traffic_last_reset': None,  # YYYY-MM-DD
}

def _norm_global_fields(d):
    out = dict(GLOBAL_FIELDS_DEFAULT)
    if isinstance(d, dict):
        out.update({k: d[k] for k in GLOBAL_FIELDS_DEFAULT if k in d})
    if out['mode'] not in ('lists', 'via', 'direct'):
        out['mode'] = 'lists'
    out['lists'] = [str(x) for x in out['lists']] if isinstance(out['lists'], list) else []
    out['countries'] = [str(x).upper() for x in out['countries']
                        if isinstance(x, str)] if isinstance(out['countries'], list) else []
    out['enabled'] = bool(out['enabled'])
    # Нормализация schedule-полей
    sa = out.get('scheduled_action')
    if sa not in ('disable', None):
        sa = None
    out['scheduled_action'] = sa
    sd = out.get('scheduled_at')
    if not (isinstance(sd, str) and re.match(r'^\d{4}-\d{2}-\d{2}$', sd or '')):
        sd = None
    out['scheduled_at'] = sd
    rd = out.get('traffic_reset_day')
    try:
        rd = int(rd) if rd not in (None, '', 0, '0') else None
        if rd is not None and not (1 <= rd <= 31):
            rd = None
    except Exception:
        rd = None
    out['traffic_reset_day'] = rd
    lg = out.get('traffic_limit_gb')
    try:
        lg = int(lg) if lg not in (None, '', 0, '0') else None
        if lg is not None and lg < 1:
            lg = None
    except Exception:
        lg = None
    out['traffic_limit_gb'] = lg
    tlr = out.get('traffic_last_reset')
    if not (isinstance(tlr, str) and re.match(r'^\d{4}-\d{2}-\d{2}$', tlr or '')):
        tlr = None
    out['traffic_last_reset'] = tlr
    return out

def load_xray_global():
    """Возвращает {pending, applied, last_update}. Совместимо со старым форматом одного state."""
    pending = dict(GLOBAL_FIELDS_DEFAULT)
    applied = dict(GLOBAL_FIELDS_DEFAULT)
    last_update = None
    if os.path.exists(XRAY_GLOBAL_DB):
        try:
            with open(XRAY_GLOBAL_DB, 'r') as f:
                data = json.load(f)
        except Exception:
            data = None
        if isinstance(data, dict):
            if 'pending' in data or 'applied' in data:
                pending = _norm_global_fields(data.get('pending'))
                applied = _norm_global_fields(data.get('applied'))
                last_update = data.get('last_update')
            else:
                # Старый формат: один объект — считаем, что и pending и applied равны ему.
                fields = _norm_global_fields(data)
                pending = dict(fields)
                applied = dict(fields)
                last_update = data.get('last_update')
    return {'pending': pending, 'applied': applied, 'last_update': last_update}

def save_xray_global(blob):
    tmp = XRAY_GLOBAL_DB + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(blob, f, indent=2, ensure_ascii=False)
    os.replace(tmp, XRAY_GLOBAL_DB)

_GLOBAL_MARK = '_panel_global'


def _ensure_block_outbound(cfg):
    """Гарантирует наличие outbound с tag='block' (blackhole)."""
    outbounds = cfg.setdefault('outbounds', [])
    for ob in outbounds:
        if ob.get('tag') == 'block':
            return False
    outbounds.append({
        'protocol': 'blackhole',
        'tag': 'block',
        _GLOBAL_MARK: True,
    })
    return True


def _detect_freedom_tag(cfg):
    """Возвращает tag первого freedom-аутбаунда (или 'direct' если такой есть, иначе тег первого)."""
    obs = cfg.get('outbounds') or []
    for ob in obs:
        if ob.get('protocol') == 'freedom' and ob.get('tag'):
            return ob['tag']
    for ob in obs:
        if ob.get('tag') == 'direct':
            return 'direct'
    if obs and obs[0].get('tag'):
        return obs[0]['tag']
    return 'direct'


def _xray_global_apply(pending, force_refresh=False):
    """Применить pending к xray-config и зафиксировать его как applied.

    1) Снимает прежние правила с маркером _panel_global и outbound block.
    2) Если pending.enabled: строит новые правила (используя кеш или свежие скачивания),
       добавляет outbound 'block' (blackhole). Правила вставляются после api-правил.
    3) Atomically save_xray_config + schedule_xray_restart (только при реальном diff).
    4) Сохраняет blob {pending, applied=pending, last_update} в xray_global.json.
    """
    pending = _norm_global_fields(pending)
    cfg_changed = False
    try:
        with _xray_restart_lock:
            if os.path.exists(XRAY_CONFIG):
                cfg = load_xray_config()
                before = json.dumps(cfg, sort_keys=True)
                _strip_global_rules(cfg)
                new_rules = _build_global_rules(pending, cfg, force_refresh=force_refresh) if pending.get('enabled') else []
                if new_rules:
                    routing = cfg.setdefault('routing', {})
                    if 'domainStrategy' not in routing:
                        routing['domainStrategy'] = 'IPIfNonMatch'
                    rules_arr = routing.setdefault('rules', [])
                    insert_at = 0
                    # Ниже api-правил И ниже пер-клиентских deny по IP: белый список
                    # должен резать раньше, чем global-правила уведут трафик в freedom.
                    for i, r in enumerate(rules_arr):
                        if isinstance(r, dict) and ('api' in (r.get('inboundTag') or [])
                                                    or r.get(_ALLOWIP_MARK)):
                            insert_at = i + 1
                    rules_arr[insert_at:insert_at] = new_rules
                    _ensure_block_outbound(cfg)
                after = json.dumps(cfg, sort_keys=True)
                if before != after:
                    save_xray_config(cfg)
                    cfg_changed = True
        if cfg_changed:
            schedule_xray_restart()
    except Exception as e:
        audit('error', f'Global rules apply failed: {e}')
    blob = {
        'pending': pending,
        'applied': dict(pending),
        'last_update': time.strftime('%Y-%m-%d %H:%M'),
    }
    save_xray_global(blob)
    return blob

# === Daily refresh worker ===
_GLOBAL_REFRESH_INTERVAL_SEC = 24 * 3600

def _global_refresh_loop():
    """Ежесуточно перечитывает выбранные списки (force_refresh) и пересобирает routing,
    используя applied state (то, что реально активно), а не pending."""
    while True:
        try:
            time.sleep(_GLOBAL_REFRESH_INTERVAL_SEC)
            blob = load_xray_global()
            applied = _norm_global_fields(blob.get('applied'))
            if applied.get('enabled'):
                _xray_global_apply(applied, force_refresh=True)
                audit('info', 'Global rules: ежесуточное автообновление')
        except Exception as e:
            try:
                audit('warn', f'Global rules daily refresh error: {e}')
            except Exception:
                pass

threading.Thread(target=_global_refresh_loop, daemon=True).start()


def load_xray_config():
    with open(XRAY_CONFIG, 'r') as f:
        return json.load(f)

def save_xray_config(cfg):
    with open(XRAY_CONFIG, 'w') as f:
        json.dump(cfg, f, indent=2)

def _le_cert_for(domain=''):
    """(fullchain, privkey, каталог) сертификата конкретного домена или None."""
    domain = (domain or '').strip().lower()
    base = '/etc/letsencrypt/live'
    if not domain or not os.path.isdir(base):
        return None
    try:
        for d in sorted(os.listdir(base)):
            # certbot добавляет суффикс -0001 при повторных выпусках.
            if d.lower() != domain and d.split('-0')[0].lower() != domain:
                continue
            full = os.path.join(base, d, 'fullchain.pem')
            key = os.path.join(base, d, 'privkey.pem')
            if os.path.isfile(full) and os.path.isfile(key):
                return (full, key, d)
    except Exception:
        pass
    return None


def _tls_cert_for_xray():
    """Сертификат, которым XRay будет терминировать 443.

    Сначала ищем по домену панели (SERVER_CFG['sni']) и только потом берём
    первый попавшийся. Вслепую первый брать нельзя: в /etc/letsencrypt/live
    обычно лежат ещё и серты давно переехавших доменов, и XRay поднялся бы с
    сертификатом на чужое имя — клиенты получали бы ошибку проверки, а причина
    выглядела бы как «переключение сломало VPN».
    """
    cert = _le_cert_for(SERVER_CFG.get('sni') or '') or _find_le_cert()
    if not cert:
        return {'found': False}
    full, key, dirname = cert
    # Имя каталога — не всегда домен: при повторных выпусках certbot делает
    # «домен-0001». Такой суффикс в serverName сломал бы TLS по SNI.
    domain = re.sub(r'-\d{4}$', '', dirname)
    days = None
    out, _, rc = run_cmd(f"openssl x509 -enddate -noout -in '{full}'")
    if rc == 0 and '=' in (out or ''):
        try:
            end = datetime.datetime.strptime(out.strip().split('=', 1)[1].strip(),
                                             '%b %d %H:%M:%S %Y %Z')
            days = (end - datetime.datetime.utcnow()).days
        except Exception:
            days = None
    return {'found': True, 'fullchain': full, 'privkey': key, 'domain': domain, 'days_left': days}


def _hy_public_host():
    """Адрес, по которому клиент стучится в Hysteria.

    НЕ get_xray_sni(): в Reality-режиме он отдаёт домен-прикрытие из
    realitySettings.serverNames (www.cloudflare.com и подобные) — для VLESS это
    ровно то, что нужно, а для Hysteria это чужой хост. Hysteria — собственный
    QUIC на нашем UDP-порту, никакого прикрытия в адресе быть не может: клиент
    ушёл бы пакетами в Cloudflare, и со стороны это выглядит как «протокол
    работает, но трафика нет».

    Порядок: домен сертификата (он выписан на этот сервер) → домен панели из
    server.json → IP. Тот же источник, что у ссылок на профили.
    """
    cert = _tls_cert_for_xray() or {}
    if cert.get('domain'):
        return cert['domain']
    sni = (SERVER_CFG.get('sni') or '').strip()
    if sni:
        return sni
    return get_server_ip() or ''


def xray_security_state():
    """Что сейчас на 443 и можно ли переключиться. Питает блок «Режим на 443».

    Отдельный разбор, а не голый security из инбаунда: UI обязан показать не
    только текущий режим, но и почему второй недоступен (нет сертификата,
    истёк) — иначе кнопка молча ничего не делает.
    """
    xp = get_xray_inbound_params()
    # Без установленного XRay параметры инбаунда — это дефолты функции
    # (security='tls'), и блок показал бы несуществующий режим вместе с кнопкой
    # переключения. Поэтому установку проверяем отдельно.
    installed = os.path.exists(XRAY_BIN) and os.path.isfile(XRAY_CONFIG)
    security = (xp.get('security') or '') if installed else ''
    cert = _tls_cert_for_xray()
    domain = cert.get('domain') or SERVER_CFG.get('sni') or ''
    days = cert.get('days_left')
    tls_block = ''
    if not installed:
        tls_block = 'XRay не установлен — переключать нечего'
    elif not cert.get('found'):
        tls_block = ('в /etc/letsencrypt нет сертификата для домена — TLS-режиму нечем '
                     'терминировать соединение')
    elif days is not None and days <= 0:
        tls_block = ('сертификат домена «%s» просрочен — переключение оставит 443 нерабочим. '
                     'Сначала перевыпустите его (⚠ Зависимости → «Срок сертификата домена»)'
                     % domain)
    return {
        'installed': installed,
        'security': security,
        'port': xp.get('port') or 443,
        'sni': xp.get('sni') or '',
        'dest': xp.get('dest') or '',
        'cert_domain': domain,
        'cert_days': days,
        'tls_blocked_reason': tls_block,
        'panel_port': int(SERVER_CFG.get('panel_port') or 0),
        'fake_enabled': bool(SERVER_CFG.get('fake_enabled')),
        'login_block_root': bool(SERVER_CFG.get('login_block_root')),
        'login_path': SERVER_CFG.get('login_path') or '/login.html',
    }


def _tgweb_wrap_fallbacks(fallbacks):
    """Общий фоллбек XRay → nginx Telegram WEB, если WEB-прокси установлен и
    nginx жив. Переключение режима 443 и установка XRay пишут fallbacks
    целиком — без этой обёртки WEB-прокси молча отваливался бы до ближайшего
    прохода сторожа пакета (15 с), а все клиенты WEB на это время попадали бы
    на сайт. nginx лежит — оставляем прямой фоллбек: панель на 443 важнее."""
    if not globals().get('tgweb_pkg'):
        return fallbacks
    try:
        from modules.tgweb import nginx as _tg_ng
        from modules.tgweb import xray_link as _tg_xl
        if _tg_ng.installed() and _tg_ng.active():
            return _tg_xl.wrap_fallbacks(fallbacks)
    except Exception:
        pass
    return fallbacks


def _tgweb_before_xray(mode=None):
    """Хук перед тем, как XRay займёт 443: старт, автозапуск, смена режима,
    установка. (можно, сообщение). Когда 443 держит сам Telegram WEB (XRay там
    не было), TLS-режиму он порт уступает заранее, а Reality — отказ с
    объяснением: иначе XRay упал бы на «address already in use»."""
    _panel_443_release()
    if not globals().get('tgweb_pkg'):
        return True, ''
    try:
        from modules.tgweb import front as _tg_front
        return _tg_front.before_xray_claim(mode)
    except Exception as e:
        return True, f'(проверка Telegram WEB не выполнена: {e})'


def _tgweb_xray_start_note():
    """(текст, запуск_не_пройдёт) для пункта «XRay остановлен», когда 443
    держит Telegram WEB. ('', False) — WEB тут ни при чём."""
    if not globals().get('tgweb_pkg'):
        return '', False
    try:
        from modules.tgweb import front as _tg_front
        return _tg_front.xray_start_note()
    except Exception:
        return '', False


def _tgweb_reconcile_later(delay=4):
    """Пересчитать, кто держит 443 для WEB, после действия с XRay — в фоне и
    с паузой: XRay должен успеть подняться или освободить порт."""
    if not globals().get('tgweb_pkg'):
        return

    def _bg():
        time.sleep(delay)
        try:
            from modules.tgweb import front as _tg_front
            _tg_front.reconcile()
        except Exception as e:
            print(f'[tgweb] reconcile: {e}', flush=True)
    threading.Thread(target=_bg, daemon=True).start()


def _xray_apply_security(mode):
    """Переключает инбаунд 443 между Reality и TLS. (ok, сообщение).

    Клиенты (settings.clients) переносятся как есть: меняется только транспорт,
    а UUID и имена остаются — иначе переключение означало бы пересоздание всех
    пользователей.

    Конфиг перед записью бэкапится, и если xray не поднялся — откатываем. Без
    этого неудачное переключение оставило бы сервер без 443 вообще: ни VPN, ни
    доступа к панели через фоллбек.
    """
    mode = 'tls' if mode == 'tls' else 'reality'
    state = xray_security_state()
    if state['security'] == mode:
        return False, 'на 443 уже режим %s' % mode.upper()
    if mode == 'tls' and state['tls_blocked_reason']:
        return False, state['tls_blocked_reason']
    ok, msg = _tgweb_before_xray(mode)
    if not ok:
        return False, msg

    try:
        cfg = load_xray_config()
    except Exception as e:
        return False, f'не читается {XRAY_CONFIG}: {e}'
    idx = find_xray_inbound_idx(cfg)
    if idx < 0:
        return False, 'в конфиге XRay нет инбаундов'
    inb = cfg['inbounds'][idx]
    before = json.dumps(cfg, indent=2)

    if mode == 'tls':
        cert = _tls_cert_for_xray()
        full, key = cert.get('fullchain'), cert.get('privkey')
        if not (full and key):
            return False, 'не нашлись файлы сертификата'
        inb.setdefault('settings', {})
        # Фоллбек на Flask: всё, что не VLESS, уходит в панель — так на 443
        # появляются и сайт-заглушка, и вход, и ссылки на профили без порта.
        inb['settings']['fallbacks'] = _tgweb_wrap_fallbacks([{'dest': 5000, 'xver': 0}])
        inb['streamSettings'] = {
            'network': 'tcp',
            'security': 'tls',
            'tlsSettings': {
                'serverName': cert.get('domain') or SERVER_CFG.get('sni') or '',
                # Только http/1.1: h2 в ALPN ломает фоллбек на обычный HTTP.
                'alpn': ['http/1.1'],
                'certificates': [{'certificateFile': full, 'keyFile': key}],
            },
        }
        note = 'VLESS+TLS на %s, панель и сайт доступны там же через фоллбек' % (
            cert.get('domain') or '')
    else:
        out, err, rc = run_cmd(f'{XRAY_BIN} x25519')
        r_priv, r_pub = _parse_x25519((out or '') + '\n' + (err or ''))
        if rc != 0 or not (r_priv and r_pub):
            return False, f'не удалось сгенерировать ключи Reality: {err or out}'
        # Fallbacks в Reality не нужны: TLS терминирует не XRay, а dest-сайт,
        # и оставленный fallback только сбивал бы с толку при чтении конфига.
        (inb.get('settings') or {}).pop('fallbacks', None)
        # Сайт маскировки берём тот, что уже был настроен: возврат в Reality не
        # должен молча менять прикрытие на дефолтное — клиентские ссылки завязаны
        # на serverName, и подмена сломала бы их ещё и по SNI.
        prev_dest = (state.get('dest') or '').split(':')[0] or XRAY_REALITY_DEST
        inb['streamSettings'] = {
            'network': 'tcp',
            'security': 'reality',
            'realitySettings': {
                'dest': f'{prev_dest}:443',
                'serverNames': [prev_dest],
                'privateKey': r_priv,
                'publicKey': r_pub,
                'shortIds': [secrets.token_hex(4)],
            },
        }
        note = 'VLESS+Reality (маскировка под %s)' % prev_dest

    try:
        save_xray_config(cfg)
    except Exception as e:
        return False, f'не удалось записать конфиг: {e}'
    def _xray_up(tries=5):
        """Реально ли поднялся сервис. Ждём с запасом: на медленном сервере xray
        стартует дольше, и одиночная проверка через две секунды врёт."""
        for _ in range(tries):
            time.sleep(1)
            st, _, _ = run_cmd('systemctl is-active xray')
            if st.strip() == 'active':
                return True
        return False

    run_cmd('systemctl restart xray')
    if not _xray_up():
        with open(XRAY_CONFIG, 'w') as f:
            f.write(before)
        run_cmd('systemctl restart xray')
        restored = _xray_up()
        log_out, _, _ = run_cmd('journalctl -u xray -n 20 --no-pager')
        hint = ''
        if mode == 'tls':
            # Частая причина: юнит xray работает не от root, а /etc/letsencrypt/live
            # закрыт правами 0700 — сертификат просто не читается.
            unit_user, _, _ = run_cmd(
                "systemctl show xray -p User --value 2>/dev/null")
            if (unit_user or '').strip() not in ('', 'root'):
                hint = (' Похоже, xray работает от «%s», а /etc/letsencrypt/live доступен '
                        'только root — сертификат ему не прочитать.' % unit_user.strip())
        back = ('прежний конфиг возвращён, сервис работает'
                if restored else
                'ВНИМАНИЕ: прежний конфиг возвращён, но сервис так и не поднялся — '
                'проверьте journalctl -u xray')
        return False, 'xray не поднялся с новым режимом (%s).%s %s' % (back, hint, log_out[-500:])
    audit('warn', f'Режим 443 переключён на {mode.upper()}: {note}')
    _tgweb_reconcile_later()
    return True, note


@app.route('/api/xray/security', methods=['GET'])
@login_required
def api_xray_security_get():
    return jsonify(xray_security_state())


@app.route('/api/xray/security', methods=['POST'])
@login_required
def api_xray_security_set():
    data = request.get_json(force=True, silent=True) or {}
    mode = (data.get('mode') or '').strip().lower()
    if mode not in ('tls', 'reality'):
        return jsonify({'ok': False, 'error': 'mode: tls или reality'}), 400
    ok, msg = _xray_apply_security(mode)
    if not ok:
        return jsonify({'ok': False, 'error': msg}), 409

    # Режим входа меняем той же операцией. Иначе получается ловушка: 443 уже
    # отдаёт панель, а корень по-прежнему 404 (key-only) — человек видит
    # «переключил, а сайта нет» и не связывает это с настройкой входа.
    login_mode = (data.get('login_mode') or '').strip().lower()
    if login_mode in ('fake', 'ip'):
        SERVER_CFG['fake_enabled'] = (login_mode == 'fake')
        SERVER_CFG['login_block_root'] = False
        _save_server_config(SERVER_CFG)
        audit('warn', 'Режим входа: %s (from %s)'
              % ('сайт-заглушка' if login_mode == 'fake' else 'панель на корне', _client_ip()))
        msg += '. Вход: %s' % ('сайт-заглушка на корне, панель по адресу-ключу'
                               if login_mode == 'fake' else 'панель на корне')
        # Пустая public/ — самая частая причина «переключил, а на домене 404»:
        # режим включён, отдавать нечего. Говорим сразу, а не ждём жалобы.
        if login_mode == 'fake' and not os.path.isfile(os.path.join(PUBLIC_DIR, 'index.html')):
            msg += ('. ВНИМАНИЕ: в %s нет index.html — корень будет отдавать 404, '
                    'пока туда не положены файлы сайта' % PUBLIC_DIR)
    return jsonify({'ok': True, 'message': msg, **xray_security_state()})


def find_xray_inbound_idx(cfg):
    # Prefer inbound by tag, fall back to first VLESS+Reality, then [0].
    inbounds = cfg.get('inbounds', [])
    for i, ib in enumerate(inbounds):
        if ib.get('tag') == XRAY_PARAMS['inbound_tag']:
            return i
    for i, ib in enumerate(inbounds):
        if ib.get('protocol') == 'vless' and \
           ib.get('streamSettings', {}).get('security') in ('tls', 'reality'):
            return i
    return 0 if inbounds else -1

def import_xray_clients_if_empty():
    # On first run, pull existing clients from xray config.json so the panel
    # can manage them. Names default to "client-N".
    if os.path.exists(XRAY_CLIENTS_DB):
        return
    if not os.path.exists(XRAY_CONFIG):
        save_xray_clients({})
        return
    try:
        cfg = load_xray_config()
        idx = find_xray_inbound_idx(cfg)
        if idx < 0:
            save_xray_clients({})
            return
        existing = cfg['inbounds'][idx].get('settings', {}).get('clients', [])
        imported = {}
        for n, c in enumerate(existing, start=1):
            cid = c.get('id')
            if not cid:
                continue
            imported[cid] = {
                'name': c.get('email') or f'client-{n}',
                'uuid': cid,
                'created': time.strftime('%Y-%m-%d %H:%M'),
                'bypass_ru': False,
                'rule_lists': {'lists': []}
            }
        save_xray_clients(imported)
    except Exception:
        save_xray_clients({})

def _xray_unique_email(name, client_uuid):
    # XRay требует уникальный 'email' в инбаунде. Дубли имён панель больше не
    # создаёт (_client_name_taken), но суффикс из uuid8 остаётся: на серверах,
    # заведённых раньше, двойники уже есть, а email зашит в накопленный трафик,
    # deny-правила по IP и строки логов — менять его формат значит их потерять.
    return f"{name}-{client_uuid[:8]}"

_xray_restart_lock = threading.Lock()
_xray_restart_pending = threading.Event()
# Рестарт идёт фоном, а ответ на запрос уходит раньше — UI не знает, чем всё
# кончилось. Держим результат последнего рестарта, чтобы фронт мог его дождаться
# (/api/xray/restart-status) и показать «перезапущен» или ошибку.
_xray_restart_status = {'pending': False, 'running': False, 'ok': None, 'ts': 0, 'error': ''}

def _xray_restart_worker():
    # Coalesce many close-in-time restart requests into a single restart.
    while True:
        _xray_restart_pending.wait()
        _xray_restart_pending.clear()
        _xray_restart_status.update({'pending': False, 'running': True})
        # Пауза не только склеивает пачку изменений, но и даёт ответу на запрос
        # уйти в браузер: там, где панель отдаётся фоллбеком XRay, рестарт рвёт
        # её собственное соединение, и слишком короткая задержка превращала
        # обычное создание клиента в «соединение прервано». Новая заявка во
        # время ожидания сдвигает срок — серия правок даёт один рестарт.
        started = time.time()
        deadline = started + _xray_restart_delay()
        while time.time() < deadline:
            time.sleep(0.25)
            if _xray_restart_pending.is_set():
                _xray_restart_pending.clear()
                deadline = time.time() + _xray_restart_delay()
            else:
                # Срочная заявка могла снять отложенность — тогда не тянем.
                deadline = min(deadline, time.time() + _xray_restart_delay())
            if time.time() - started > XRAY_RESTART_DEFER_CAP_SEC:
                break
        _xray_restart_deferrable.clear()
        # Остановленный руками XRay (inactive) правка конфига не поднимает —
        # изменение применится при старте. Упавший (failed) перезапускаем:
        # правка могла быть как раз починкой.
        if run_cmd('systemctl is-active xray')[0].strip() == 'inactive':
            _xray_restart_status.update({'running': False, 'ok': True, 'ts': time.time(),
                                         'error': '', 'skipped': 'stopped'})
            continue
        _xray_restart_status.pop('skipped', None)
        out, err, rc = run_cmd('systemctl restart xray')
        ok = rc == 0
        if ok:
            # systemctl отдаёт 0, даже если сервис сразу упал на старте — проверяем факт.
            ok = False
            for _ in range(10):
                if run_cmd('systemctl is-active --quiet xray')[2] == 0:
                    ok = True
                    break
                time.sleep(0.3)
        _xray_restart_status.update({
            'running': False, 'ok': ok, 'ts': time.time(),
            'error': '' if ok else (err or out or 'сервис не активен после перезапуска'),
        })
        if not ok:
            audit('error', f'XRay не поднялся после перезапуска: {_xray_restart_status["error"]}')

threading.Thread(target=_xray_restart_worker, daemon=True).start()

# Сколько ждать перед отложенным рестартом. Отложенный — это когда живому ядру
# изменение уже применено частично (VLESS через adu), а перезапуск нужен только
# второму инбаунду: adu до 26.9.30 не умеет пользователей Hysteria («unsupported
# inbound type» на 26.9.9). Пауза даёт ответу уйти в браузер и склеивает серию
# добавлений в один разрыв вместо разрыва на каждого клиента.
XRAY_RESTART_DEFER_SEC = 20
XRAY_RESTART_DEFER_CAP_SEC = 120   # поток изменений не должен откладывать вечно

_xray_restart_deferrable = threading.Event()


def schedule_xray_restart(deferred=False):
    """Запланировать перезапуск ядра. deferred=True — можно не спешить."""
    if deferred:
        if not _xray_restart_status.get('pending'):
            _xray_restart_deferrable.set()
    else:
        _xray_restart_deferrable.clear()
    _xray_restart_status['pending'] = True
    _xray_restart_pending.set()


def _xray_restart_delay():
    return XRAY_RESTART_DEFER_SEC if _xray_restart_deferrable.is_set() else 1.5


# === Пользователи на живом ядре (HandlerService) ============================
# Раньше любое изменение состава клиентов применялось перезапуском xray. На
# сервере, где панель доступна фоллбеком того же xray, это рвало её собственный
# запрос (браузер переотправлял POST и получались клиенты-двойники), а клиентам
# обрывало соединения при каждом добавлении соседа. Команды adu/rmu делают это
# без перезапуска. Формат JSON у adu — фрагмент конфига, поэтому результат мы не
# принимаем на веру: после вызова спрашиваем ядро через inbounduser, и если
# пользователя там нет — возвращаемся к прежнему поведению с рестартом.

def xray_api_add_user(tag, user, protocol='vless', settings_extra=None, port=443):
    """Добавить пользователя в инбаунд на живом ядре. (ok, ошибка).

    protocol обязателен: без него ядро не знает, во что разбирать clients — у
    VLESS это аккаунт с id, у Hysteria с auth. Команда adu при этом возвращает
    ноль и молча не добавляет никого, поэтому исход всё равно проверяется
    отдельным запросом (_xray_apply_user_live).
    """
    if not os.path.exists(XRAY_BIN) or not tag:
        return False, 'нет xray или тега'
    # adu разбирает файл как ПОЛНЫЙ конфиг и собирает инбаунд заново, поэтому
    # фрагмента «тег + клиенты» не хватает: без port сборка падает на
    # «Listen on AnyIP but no Port(s) set», без decryption — на «VLESS settings:
    # please add/set decryption». Само значение порта ядру безразлично (сверено
    # на живом 26.9.9: чужой порт тоже принимается), но пишем настоящий.
    payload = {'inbounds': [{
        'tag': tag,
        'port': int(port or 443),
        'protocol': protocol,
        'settings': dict(settings_extra or {}, clients=[user]),
    }]}
    path = os.path.join(DATA_XRAY_DIR, f'.adu-{secrets.token_hex(6)}.json')
    try:
        os.makedirs(DATA_XRAY_DIR, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(payload, f)
        out, err, rc = run_cmd(f"{XRAY_BIN} api adu -s={XRAY_API_ADDR} '{path}'")
        text = ((out or '') + ' ' + (err or '')).strip()
        if rc != 0:
            return False, (err or out or 'adu завершился ошибкой')
        # Код возврата у adu нулевой и тогда, когда сборка инбаунда провалилась:
        # причина уходит в текст, а в конце приписка «Added 0 user(s) in total».
        # Берём её как признак неудачи, иначе ошибка выглядит как успех.
        if 'Added 0 user' in text:
            return False, (text[:300] or 'ядро добавило 0 пользователей')
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        try: os.remove(path)
        except Exception: pass


def xray_api_remove_user(tag, email):
    """Убрать пользователя из инбаунда на живом ядре. (ok, ошибка)."""
    if not os.path.exists(XRAY_BIN) or not tag or not email:
        return False, 'нет xray, тега или email'
    out, err, rc = run_cmd(f"{XRAY_BIN} api rmu -s={XRAY_API_ADDR} -tag={tag} '{email}'")
    if rc != 0:
        return False, (err or out or 'rmu завершился ошибкой')
    return True, ''


def xray_api_has_user(tag, email):
    """Есть ли такой пользователь в живом инбаунде. Это и есть проверка исхода:
    rc=0 у adu ещё не значит, что ядро приняло формат."""
    if not os.path.exists(XRAY_BIN) or not tag or not email:
        return False
    out, _, rc = run_cmd(f"{XRAY_BIN} api inbounduser -s={XRAY_API_ADDR} -tag={tag} -email='{email}'")
    return rc == 0 and email in (out or '')


def _xray_live_users_supported():
    """Включён ли HandlerService в живом конфиге. Пока его нет (конфиг старый и
    ещё не перечитан), живой путь даже не пробуем — незачем тратить вызовы."""
    try:
        cfg = load_xray_config()
        return 'HandlerService' in ((cfg.get('api') or {}).get('services') or [])
    except Exception:
        return False

def xray_add_uuid(client_uuid, name):
    with _xray_restart_lock:
        cfg = load_xray_config()
        idx = find_xray_inbound_idx(cfg)
        if idx < 0:
            raise RuntimeError('No suitable inbound in XRay config')
        inbound = cfg['inbounds'][idx]
        if not inbound.get('tag'):
            inbound['tag'] = XRAY_PARAMS['inbound_tag']
        inbound.setdefault('settings', {}).setdefault('clients', [])
        clients = inbound['settings']['clients']
        if any(c.get('id') == client_uuid for c in clients):
            return
        clients.append({
            'id': client_uuid,
            'flow': XRAY_PARAMS['flow'],
            'email': _xray_unique_email(name, client_uuid)
        })
        # На каждое добавление клиента подтягиваем учёт трафика и логи — но только
        # то, что юзер «хочет» (stats по умолчанию ON, логи — ручной опт-ин). Так
        # после пересборки инбаунда под Reality stats/log больше не теряются молча.
        # Idempotent: при уже настроенном конфиге ничего не меняет.
        if _xray_stats_wanted():
            _reconcile_stats_cfg(cfg)
        if _xray_logs_wanted():
            _reconcile_access_log_cfg(cfg)
            _ensure_xray_log_dir()
        # DNS сервера — тоже часть «желаемого состояния»: после ручной пересборки
        # конфига секция не должна молча пропасть.
        _reconcile_xray_dns_cfg(cfg)
        save_xray_config(cfg)
        live_tag = inbound.get('tag')
        live_port = inbound.get('port') or 443
        live_user = {'id': client_uuid, 'flow': XRAY_PARAMS['flow'],
                     'email': _xray_unique_email(name, client_uuid)}
    _hy_sync()   # состав клиентов изменился — обновить и Hysteria-инбаунд
    # Конфиг на диске уже правильный, осталось применить. Сначала пробуем живым
    # API: тогда ни панель, ни клиенты не теряют соединения. Не получилось —
    # рестарт, как раньше.
    ok_vless = _xray_apply_user_live('add', live_tag, live_user['email'], live_user,
                                     settings_extra={'decryption': 'none'}, port=live_port)
    ok_hy = _xray_apply_hy_user_live('add', live_user['email'], client_uuid)
    if not (ok_vless and ok_hy):
        # VLESS уже применён живьём — рестарт нужен только Hysteria, значит
        # можно отложить и склеить. Не применился и VLESS — перезапускаем сразу.
        schedule_xray_restart(deferred=ok_vless)

# Протоколы, для которых ядро умеет ДОБАВЛЯТЬ пользователей через adu. Hysteria
# до 26.9.30 отвечала «unsupported inbound type» (сверено на живом 26.9.9) —
# поддержку добавил XTLS/Xray-core#6847. На старом ядре её даже не пробуем:
# это лишние два вызова и запись в журнал на каждого клиента, а исход и так
# известен — отложенный рестарт. Снятия ограничение не касается: rmu конфиг не
# собирает, ему нужны только тег и email.
XRAY_LIVE_USER_PROTOCOLS = ('vless',)
XRAY_LIVE_HY_MIN = 'v26.9.30'


def _xray_live_add_supported(protocol):
    if protocol in XRAY_LIVE_USER_PROTOCOLS:
        return True
    if protocol == 'hysteria':
        ver = _xray_core_version()
        return bool(ver) and not _semver_lt(ver, XRAY_LIVE_HY_MIN)
    return False


def _xray_apply_user_live(op, tag, email, user=None, protocol='vless', settings_extra=None,
                          port=443):
    """Применить добавление/удаление пользователя без перезапуска ядра.

    True — применено и проверено, рестарт не нужен. False — не вышло, вызывающий
    обязан запланировать рестарт. Исход проверяем запросом к ядру, потому что
    нулевой код возврата у adu не гарантирует, что формат JSON принят.
    """
    if op == 'add' and not _xray_live_add_supported(protocol):
        return False
    if not _xray_live_users_supported() or not tag or not email:
        return False
    st, _, rc = run_cmd('systemctl is-active --quiet xray')
    if rc != 0:
        return False          # ядро не запущено — применять нечему, поднимет рестарт
    try:
        if op == 'add':
            ok, err = xray_api_add_user(tag, user or {}, protocol, settings_extra, port)
            if ok and xray_api_has_user(tag, email):
                return True
        else:
            ok, err = xray_api_remove_user(tag, email)
            if ok and not xray_api_has_user(tag, email):
                return True
        audit('warn', f'XRay: живое изменение пользователя не удалось ({op} {email}): '
                      f'{err or "ядро не подтвердило"} — перезапускаю ядро')
    except Exception as e:
        audit('warn', f'XRay: живое изменение пользователя сорвалось ({op} {email}): {e}')
    return False

def _hy_apply_after_sync(op, email, client_uuid=''):
    """Применить членство клиента в инбаунде Hysteria к РАБОТАЮЩЕМУ ядру.

    _hy_sync() правит только конфиг на диске. Пока состав клиентов применялся
    безусловным рестартом, этого хватало; теперь рестарт отменяется, когда VLESS
    уехал живьём, — и без явного применения пользователь Hysteria остался бы в
    файле, но не в работающем ядре. Добавление Hysteria ядро умеет только с
    26.9.30 — на старом планируем отложенный рестарт; снятие проходит живьём.
    """
    if not _xray_apply_hy_user_live(op, email, client_uuid):
        schedule_xray_restart(deferred=True)


def _xray_apply_hy_user_live(op, email, client_uuid=''):
    """Тот же живой путь для инбаунда Hysteria: у него свои пользователи (auth
    вместо id), но тот же email — по нему у клиента общие трафик и правила.

    True — применено либо применять нечего (инбаунд выключен, модуль не загружен,
    у клиента нет пароля или он отключён).

    Заодно применяет и третий вход, XDNS: у всех вызывающих смысл один —
    «состав клиентов поменялся, донеси до вторых входов ядра».
    """
    ok_xdns = _xdns_apply_user_live(op, email, client_uuid)
    return _xray_apply_hy_only_live(op, email, client_uuid) and ok_xdns


def _xray_apply_hy_only_live(op, email, client_uuid=''):
    if not xhy:
        return True
    try:
        if not xhy.enabled():
            return True
        if op == 'add':
            c = (load_xray_clients() or {}).get(client_uuid) or {}
            pwd = xhy.client_password(c)
            if not pwd or c.get('disabled'):
                return True
            # protocol='hysteria' и version=2 — те же значения, что панель пишет
            # в сам инбаунд (xray_hysteria.build_inbound). Разойдись они, ядро
            # собрало бы аккаунт другого типа или не собрало вовсе.
            return _xray_apply_user_live('add', xhy.INBOUND_TAG, email,
                                         {'auth': pwd, 'email': email},
                                         protocol='hysteria',
                                         settings_extra={'version': 2})
        return _xray_apply_user_live('remove', xhy.INBOUND_TAG, email, protocol='hysteria')
    except Exception as e:
        audit('warn', f'Hysteria: живое изменение пользователя сорвалось: {e}')
        return False


def xray_remove_uuid(client_uuid):
    with _xray_restart_lock:
        cfg = load_xray_config()
        idx = find_xray_inbound_idx(cfg)
        if idx < 0:
            return
        inbound = cfg['inbounds'][idx]
        clients = inbound.get('settings', {}).get('clients', [])
        gone = [c for c in clients if c.get('id') == client_uuid]
        new_clients = [c for c in clients if c.get('id') != client_uuid]
        if len(new_clients) == len(clients):
            return
        inbound['settings']['clients'] = new_clients
        save_xray_config(cfg)
        live_tag = inbound.get('tag')
        live_email = (gone[0].get('email') if gone else '') or ''
    _hy_sync()   # состав клиентов изменился — обновить и Hysteria-инбаунд
    ok_vless = _xray_apply_user_live('remove', live_tag, live_email)
    ok_hy = _xray_apply_hy_user_live('remove', live_email)
    if not (ok_vless and ok_hy):
        schedule_xray_restart(deferred=ok_vless)

def xray_update_email(client_uuid, new_name):
    with _xray_restart_lock:
        cfg = load_xray_config()
        idx = find_xray_inbound_idx(cfg)
        if idx < 0:
            return
        inbound = cfg['inbounds'][idx]
        changed = False
        old_email = ''
        for c in inbound.get('settings', {}).get('clients', []):
            if c.get('id') == client_uuid:
                old_email = c.get('email') or ''
                c['email'] = _xray_unique_email(new_name, client_uuid)
                changed = True
                break
        if not changed:
            return
        save_xray_config(cfg)
        live_tag = inbound.get('tag')
        live_port = inbound.get('port') or 443
        live_user = {'id': client_uuid, 'flow': XRAY_PARAMS['flow'],
                     'email': _xray_unique_email(new_name, client_uuid)}
    _hy_sync()   # состав клиентов изменился — обновить и Hysteria-инбаунд
    # Переименование меняет email, а он для ядра и есть личность пользователя:
    # снимаем старого и заводим нового. Обе половины должны сойтись, иначе
    # рестарт — иначе в живом ядре остался бы клиент под прежним email.
    steps = [
        _xray_apply_user_live('remove', live_tag, old_email),
        _xray_apply_hy_user_live('remove', old_email),
        _xray_apply_user_live('add', live_tag, live_user['email'], live_user,
                              settings_extra={'decryption': 'none'}, port=live_port),
        _xray_apply_hy_user_live('add', live_user['email'], client_uuid),
    ]
    if not all(steps):
        schedule_xray_restart(deferred=all(steps[::2]))

# === Фильтрация IP клиента (белый + чёрный списки) ==========================
# Белый список — доступ только с указанных адресов.
# XRay не умеет «source НЕ входит в список»: отрицания в routing нет, а правило
# «разрешить» бесполезно — первое совпадение сразу уводит трафик в outbound, и
# global-правила для этого клиента были бы обойдены. Поэтому панель считает
# ДОПОЛНЕНИЕ белого списка (весь IPv4, кроме разрешённого) и вешает на него одно
# deny-правило с user=email клиента, выше global-правил. Всё остальное работает
# как раньше.
#
# Чёрный список — обратная задача, и она проще: перечисленные адреса кладём в
# source того же deny-правила, без дополнения. Оба списка ведут в один blackhole,
# поэтому порядок между ними не важен; при совпадении блокировка выигрывает.
#
# Соединение при этом устанавливается — UUID проверяется до роутинга, — режется
# только трафик: у клиента «подключено, но интернета нет».
_ALLOWIP_MARK = '_panel_allow_ip'
_ALLOWIP_DENY_TAG = 'panel-deny'
ALLOW_IPS_MAX = 32           # дополнение раздувает конфиг (~32 CIDR на каждый /32)

def _norm_allow_ip(s):
    """'1.2.3.4' → '1.2.3.4/32', '1.2.3.4/24' → '1.2.3.0/24'. Мусор → None."""
    s = str(s or '').strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', s):
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)   # хостовые биты не считаем ошибкой
    except ValueError:
        return None
    return str(net) if net.version == 4 else None

def _norm_allow_ips(lst):
    out = []
    for x in (lst or []):
        n = _norm_allow_ip(x)
        if n and n not in out:
            out.append(n)
    return out[:ALLOW_IPS_MAX]


def build_hy2_link(client_uuid, client=None):
    """hysteria2://... для карточки клиента. Пусто, когда инбаунд выключен —
    тогда в модалке конфига блока Hysteria просто нет."""
    if not xhy or not xhy.enabled():
        return ''
    try:
        c = client or (load_xray_clients().get(client_uuid) or {})
        return xhy.build_link(c, uuid=client_uuid)
    except Exception:
        return ''


def build_vless_link(client_uuid, name, token=None):
    xp = get_xray_inbound_params()
    label = quote(_profile_filename(name, token), safe='')
    parts = ['type=tcp', f"security={xp['security']}", f"sni={xp['sni']}", f"fp={xp['fingerprint']}"]
    if xp['security'] == 'reality':
        parts += [f"pbk={xp['public_key']}", f"sid={xp['short_id']}",
                  f"spx={quote(xp['spider_x'], safe='')}"]
    if xp['flow']:
        parts.append(f"flow={xp['flow']}")
    return f"vless://{client_uuid}@{get_server_ip()}:{xp['port']}?" + '&'.join(parts) + f"#{label}"


# Make sure xray_clients.json exists on first import
import_xray_clients_if_empty()
# blackmatrix7 каталог авто-синкается единым воркером _auto_update_loop
# (по интервалу/свитчу bm7_* из server.json) — отдельный поток больше не нужен.

def _strip_token_ext(token):
    if '.' in token:
        token = token.rsplit('.', 1)[0]
    return token.strip().lower()


PROFILE_TOKEN_URL_LEN = 8   # сколько символов токена оставляем в friendly-URL


def _find_client_by_name(name):
    """Lookup client by exact (sanitized) name. Used by friendly-mode public routes."""
    if not name:
        return None
    target_safe = _safe_filename(name)
    clients = load_xray_clients()
    for c in clients.values():
        if _safe_filename(c.get('name') or '') == target_safe:
            return c
    return None

def _parse_friendly_path(p):
    """Strip optional _server_<sn> suffix and the file extension; return client name.
    Also accepts legacy 'Server_X_User_Y' / 'User_Y' formats.

    Разбор регистронезависимый: имена перешли в lowercase, но у клиентов уже
    прописаны подписки со старым '_Server_' — они обязаны резолвиться дальше."""
    p = (p or '').strip()
    if '.' in p:
        p = p.rsplit('.', 1)[0]
    # New format: <client>_server_<server>
    parts = re.split(r'_server_', p, maxsplit=1, flags=re.I)
    if len(parts) == 2:
        return parts[0]
    # Legacy: Server_X_User_Y
    parts = re.split(r'_user_', p, flags=re.I)
    if len(parts) > 1:
        return parts[-1]
    # Legacy: User_Y
    if re.match(r'^user_', p, re.I):
        return p[5:]
    return p

def _find_client_by_token(token_clean):
    if not token_clean:
        return None
    clients = load_xray_clients()
    for c in clients.values():
        if (c.get('token') or '').lower() == token_clean:
            return c
    # Короткая форма: в friendly-URL токен урезан до PROFILE_TOKEN_URL_LEN.
    # Префикс принимаем, только если он указывает ровно на одного клиента —
    # иначе это чужая или битая ссылка, и молча отдать чей-то профиль нельзя.
    if len(token_clean) >= PROFILE_TOKEN_URL_LEN:
        hits = [c for c in clients.values()
                if (c.get('token') or '').lower().startswith(token_clean)]
        if len(hits) == 1:
            return hits[0]
    return None


def _ensure_xray_log_dir():
    """Создаёт каталог под access.log (идемпотентно, владельца не трогаем)."""
    try:
        os.makedirs(os.path.dirname(XRAY_ACCESS_LOG), exist_ok=True)
    except Exception:
        pass

def _reconcile_access_log_cfg(cfg):
    """Idempotently выставляет log.access/loglevel на уже загруженном cfg-dict.
    Чистая мутация — без lock и без IO. Возвращает True, если cfg изменился.
    Вынесено отдельно, чтобы вызывать из xray_add_uuid (уже под _xray_restart_lock)."""
    log = cfg.setdefault('log', {})
    changed = False
    if log.get('access') != XRAY_ACCESS_LOG:
        log['access'] = XRAY_ACCESS_LOG
        changed = True
    if log.get('loglevel') not in ('info', 'debug'):
        log['loglevel'] = 'info'
        changed = True
    return changed

def patch_xray_for_access_log():
    """Idempotently inject log.access into xray config and ensure /var/log/xray exists.

    The directory is created with default permissions (inherits from parent).
    Ownership is NOT touched — xray must be able to write there as whatever
    user it runs as. If your xray runs as a non-root user that can't write,
    `chown <xray-user>:<xray-group> /var/log/xray` manually once.
    """
    _ensure_xray_log_dir()
    with _xray_restart_lock:
        cfg = load_xray_config()
        changed = _reconcile_access_log_cfg(cfg)
        if changed:
            save_xray_config(cfg)
        return changed

def _reconcile_xray_dns_cfg(cfg):
    """Idempotently приводит секцию dns и domainStrategy freedom-аутбаунда к DNS
    из Global. Чистая мутация без IO и lock. True — если cfg изменился.

    Секцией dns владеет панель: DNS выключен в Global → секции в конфиге нет.
    """
    want = _xray_dns_section(_global_dns_default())
    changed = False
    if want is None:
        if 'dns' in cfg:
            del cfg['dns']
            changed = True
    elif cfg.get('dns') != want:
        cfg['dns'] = want
        changed = True
    # Без domainStrategy freedom работает как AsIs: отдаёт домен системному dialer'у
    # и секцию dns не задействует вовсе. UseIPv4 — панель везде IPv4-only
    # (в клиентских профилях ipv6=false, ссылки строятся по IPv4-адресу сервера).
    ftag = _detect_freedom_tag(cfg)
    for ob in (cfg.get('outbounds') or []):
        if ob.get('protocol') != 'freedom' or ob.get('tag') != ftag:
            continue
        st = ob.setdefault('settings', {})
        if want is None:
            if 'domainStrategy' in st:
                del st['domainStrategy']
                changed = True
        elif st.get('domainStrategy') != 'UseIPv4':
            st['domainStrategy'] = 'UseIPv4'
            changed = True
    return changed


def apply_xray_dns():
    """Накатывает DNS из Global в xray.json. True → конфиг изменился и xray
    отправлен на перезапуск (без него секция dns не подхватится)."""
    with _xray_restart_lock:
        cfg = load_xray_config()
        changed = _reconcile_xray_dns_cfg(cfg)
        if changed:
            save_xray_config(cfg)
    if changed:
        schedule_xray_restart()
    return changed


def _reconcile_stats_cfg(cfg):
    """Idempotently обеспечивает stats/api/policy/api-инбаунд + правило роутинга
    на уже загруженном cfg-dict. Чистая мутация — без lock и без IO. Возвращает
    True, если cfg изменился. Вынесено отдельно, чтобы (а) вызывать из xray_add_uuid
    под общим _xray_restart_lock без дедлока и (б) переиспользовать в проверке
    зависимостей (stats_ok = ничего не поменялось бы)."""
    changed = False
    if 'stats' not in cfg:
        cfg['stats'] = {}
        changed = True
    # HandlerService — добавление и удаление пользователей на живом ядре.
    # Без него единственный способ применить нового клиента — перезапуск xray,
    # а он рвёт соединения ВСЕХ клиентов сервера и саму панель там, где она
    # отдаётся фоллбеком этого же xray.
    api = cfg.get('api') or {}
    want_services = ['StatsService', 'HandlerService']
    if api.get('tag') != 'api' or [x for x in want_services if x not in (api.get('services') or [])]:
        services = list(api.get('services') or [])
        for svc in want_services:
            if svc not in services:
                services.append(svc)
        cfg['api'] = {'tag': 'api', 'services': services}
        changed = True
    pol = cfg.setdefault('policy', {})
    levels = pol.setdefault('levels', {})
    l0 = levels.setdefault('0', {})
    # statsUserOnline — счётчик активных сессий клиента (бейдж «Устройств» на
    # карточке). Без флага ядро онлайн не считает вовсе, и statsonline отдаёт
    # пусто: это не опция вывода, а опция учёта.
    if (not l0.get('statsUserUplink') or not l0.get('statsUserDownlink')
            or not l0.get('statsUserOnline')):
        l0['statsUserUplink'] = True
        l0['statsUserDownlink'] = True
        l0['statsUserOnline'] = True
        changed = True
    inbounds = cfg.setdefault('inbounds', [])
    if not any(ib.get('tag') == 'api' for ib in inbounds):
        inbounds.append({
            'tag': 'api',
            'listen': '127.0.0.1',
            'port': XRAY_API_PORT,
            'protocol': 'dokodemo-door',
            'settings': {'address': '127.0.0.1'}
        })
        changed = True
    routing = cfg.setdefault('routing', {})
    rules = routing.setdefault('rules', [])
    if not any(
        r.get('outboundTag') == 'api' and 'api' in (r.get('inboundTag') or [])
        for r in rules
    ):
        rules.insert(0, {
            'type': 'field',
            'inboundTag': ['api'],
            'outboundTag': 'api'
        })
        changed = True
    return changed

def patch_xray_for_stats():
    """Idempotently inject stats/api/policy/api-inbound + routing rule into xray config."""
    with _xray_restart_lock:
        cfg = load_xray_config()
        changed = _reconcile_stats_cfg(cfg)
        if changed:
            save_xray_config(cfg)
        return changed

def _xray_stats_wanted():
    """Хочет ли юзер учёт трафика. Дефолт True — статистика включается при установке
    панели. От этого флага зависят тумблер «Статистика», ⚠-проверка и авто-накат
    при добавлении клиента (чтобы не навязывать тем, кто сознательно выключил)."""
    v = SERVER_CFG.get('xray_stats_wanted')
    return True if v is None else bool(v)

def _xray_logs_wanted():
    """Хочет ли юзер access-логи XRay. Дефолт False — логи это ручной опт-ин.
    Если флаг ещё не сохранён, мигрируем по факту: логи уже настроены в конфиге →
    считаем, что юзер их включал."""
    v = SERVER_CFG.get('xray_logs_wanted')
    if v is not None:
        return bool(v)
    try:
        access = str((load_xray_config().get('log') or {}).get('access') or '')
        return XRAY_ACCESS_LOG in access or '/var/log/xray/access.log' in access
    except Exception:
        return False

# --- Access log parsing ---------------------------------------------------
# Sample lines (формат плавает между версиями/режимами xray):
#   TLS:     2026/05/06 12:34:56 from 1.2.3.4:54321 accepted tcp:youtube.com:443 [vless-tls -> direct] email: client1-9ccfc08e
#   Reality: 2026/06/05 15:52:59.239639 from 1.2.3.4:55473 accepted tcp:i.instagram.com:443 email: client1-2383daf5
# Отличия Reality/новых сборок: дробные секунды в ts и ОТСУТСТВИЕ секции
# [inbound -> outbound]. Поэтому "from " и скобка [in -> out] — опциональны,
# иначе строки без скобки не матчатся и пропадают онлайн/последний IP/время.
_XRAY_ACCESS_RE = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})'
    r'(?:\.\d+)?'                                       # optional fraction
    r'\s+(?:from\s+)?'
    r'(?:(?:tcp|udp):)?'                                # optional src network prefix (newer xray)
    # IPv6 xray пишет в скобках: [2a00::1]:443. Без них разбор молча терял
    # такие строки — и IPv6-клиентов, и все соединения XDNS ([fd00::…]:0).
    r'\[?(?P<src>[0-9a-fA-F\.:]+)\]?:\d+'                 # src ip:port
    r'\s+accepted\s+'
    r'(?P<proto>\w+):'
    r'(?P<dst>[^:\s\[]+)'
    r'(?::(?P<dport>\d+))?'
    r'(?:.*?\[(?P<inbound>[^\]]+?)\s*(?:->|>>)\s*(?P<outbound>[^\s\]]+)\])?'  # optional [in -> out]
    r'(?:.*?email:\s*(?P<email>\S+))?\s*$'
)

def _tail_bytes(path, max_bytes):
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    read = min(max_bytes, size)
    try:
        with open(path, 'rb') as f:
            f.seek(size - read)
            data = f.read(read)
    except OSError:
        return None
    # Drop possibly partial first line (we seeked into the middle).
    nl = data.find(b'\n')
    if nl >= 0 and read < size:
        data = data[nl + 1:]
    try:
        return data.decode('utf-8', errors='replace')
    except Exception:
        return None

def _xray_parse_access_lines(text, email_filter=None):
    """Iterate parsed records (newest first) from a chunk of access.log text."""
    if not text:
        return
    for line in reversed(text.splitlines()):
        m = _XRAY_ACCESS_RE.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        if email_filter and d['email'] != email_filter:
            continue
        yield {
            'ts': d['ts'],
            'ip': d['src'],
            'host': d['dst'],
            'port': int(d['dport']) if d.get('dport') else None,
            'proto': d.get('proto'),
            'email': d.get('email') or '',
            'outbound': d.get('outbound') or '',
            'inbound': d.get('inbound') or '',
        }

# Инкрементальный кеш для эндпоинтов логов.
# Под нагрузкой XRay access.log растёт каждую секунду — полный репарс на каждый
# запрос убивал single-worker gunicorn. Теперь:
#   • read tail bytes только с last_size до текущего size (приращение),
#   • парсим новые байты, склеиваем с уже распарсенным списком (newest-first),
#   • geo/dest cache переживает между запросами,
#   • lock сериализует одновременные реквесты (один парсит, остальные ждут).
# При ротации (size < last_size) делаем полный респарс.
_LOG_ENRICH_CACHE = {}  # path -> {sig, size, recs, geo, dest, lock}
_LOG_ENRICH_LOCK = threading.Lock()
# TTL-кеш для журналов (MTG → journald, по файлу не отследишь).
_LOG_TTL_CACHE = {}

def _xray_enrich_records(raw_iter, geo_cache, dest_cache):
    out = []
    for rec in raw_iter:
        ip = rec['ip']
        if ip not in geo_cache:
            geo_cache[ip] = geo_asn_full(ip) or {}
        r2 = dict(rec)
        r2['geo'] = geo_cache[ip]
        r2['dest_org'] = _dest_org_for_host(r2.get('host'), dest_cache)
        out.append(r2)
    return out

def _read_new_lines(path, start, end):
    """Дописанное в журнал с позиции start: (текст целых строк, новая позиция).

    start всегда стоит на границе строки (это прошлая позиция), поэтому первую
    строку не выбрасываем — а хвост без перевода строки (запись в процессе)
    оставляем на следующий раз, позиция встаёт перед ним."""
    try:
        with open(path, 'rb') as f:
            f.seek(start)
            data = f.read(end - start)
    except OSError:
        return '', start
    nl = data.rfind(b'\n')
    if nl < 0:
        return '', start
    return data[:nl + 1].decode('utf-8', errors='replace'), start + nl + 1

def _cached_xray_enriched():
    """Список записей XRay access.log, newest-first. Инкрементальный парс + lock."""
    path = XRAY_ACCESS_LOG
    if not os.path.exists(path):
        return []
    try:
        st = os.stat(path)
    except OSError:
        return []
    sig = (st.st_size, st.st_mtime_ns)
    # Кеш разделён по языку гео-имён: записи кешируются с уже вшитыми country/city,
    # поэтому RU и EN держим отдельными ветками (ckey), иначе смена языка не подхватится.
    ckey = (path, _geo_locale())
    # Быстрая проверка без лока — попадание в кеш под актуальный sig.
    entry = _LOG_ENRICH_CACHE.get(ckey)
    if entry and entry.get('sig') == sig:
        return entry['recs']
    # Захватываем лок: пока один тред парсит, остальные ждут и берут готовое.
    with _LOG_ENRICH_LOCK:
        entry = _LOG_ENRICH_CACHE.get(ckey)
        if entry and entry.get('sig') == sig:
            return entry['recs']
        size_now = st.st_size
        last_size = entry.get('size', 0) if entry else 0
        geo_cache = entry.get('geo') if entry else {}
        dest_cache = entry.get('dest') if entry else {}
        if not entry:
            geo_cache, dest_cache = {}, {}
        if entry and size_now >= last_size:
            # Инкрементальный путь: парсим только новые байты, склеиваем.
            text_new, size_now = _read_new_lines(path, last_size, size_now)
            new_recs = _xray_enrich_records(
                _xray_parse_access_lines(text_new), geo_cache, dest_cache
            )
            recs = new_recs + entry['recs']
            # Ограничиваем суммарный размер 50МБ-эквивалентом по числу записей.
            # 50МБ при ~120 байт/запись ≈ 430k. Берём 500k с запасом.
            if len(recs) > 500000:
                recs = recs[:500000]
        else:
            # Полный путь (ротация или первая инициализация).
            geo_cache, dest_cache = {}, {}
            text = _tail_bytes(path, XRAY_LOG_FULL_BYTES)
            recs = _xray_enrich_records(
                _xray_parse_access_lines(text), geo_cache, dest_cache
            )
        _LOG_ENRICH_CACHE[ckey] = {
            'sig': sig, 'size': size_now, 'recs': recs,
            'geo': geo_cache, 'dest': dest_cache,
        }
        return recs

def _awg_parse_lines(text, geo_cache):
    """Строки AWG-журнала (JSON-line) → записи панели, новые первыми."""
    out = []
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        kind = rec.get('kind') or 'snapshot'
        pk = rec.get('pubkey') or ''
        if kind == 'dest':
            src_ip = rec.get('ip') or ''
            dst_ip = rec.get('dst_ip') or ''
            if dst_ip and dst_ip not in geo_cache:
                geo_cache[dst_ip] = geo_asn_full(dst_ip) or {}
            dest_org = geo_cache.get(dst_ip, {})
            out.append({
                'ts': rec.get('ts') or '',
                'ip': src_ip,
                'host': rec.get('host') or dst_ip,
                'dst_ip': dst_ip,
                'port': rec.get('dst_port') or '',
                'email': (pk[:12] + '…') if pk else '',
                '_pubkey': pk,
                'inbound': 'awg',
                'outbound': rec.get('proto') or 'dest',
                'geo': {},
                'dest_org': {'asn': dest_org.get('asn'), 'org': dest_org.get('org')} if dest_org else {},
            })
        else:
            ip = rec.get('ip') or ''
            if ip and ip not in geo_cache:
                geo_cache[ip] = geo_asn_full(ip) or {}
            ep = rec.get('endpoint') or ''
            port = ep.rsplit(':', 1)[1] if ':' in ep else ''
            out.append({
                'ts': rec.get('ts') or '',
                'ip': ip,
                'host': '',
                'port': port,
                'email': (pk[:12] + '…') if pk else '',
                '_pubkey': pk,
                'inbound': 'awg',
                'outbound': rec.get('latest_handshake') or 'snapshot',
                'geo': geo_cache.get(ip, {}),
                'transfer': rec.get('transfer') or '',
            })
    return out


def _cached_awg_enriched():
    """Список записей AWG (JSON-line), newest-first. Как у XRay: при дописывании
    файла разбираются только новые байты, гео-кеш живёт между запросами; полный
    разбор — при первой загрузке и при ротации (файл стал меньше). Раньше на
    каждое изменение файла заново читались 10 МБ — живой лог тормозил."""
    path = AWG_ACCESS_LOG
    if not os.path.exists(path):
        return []
    try:
        st = os.stat(path)
    except OSError:
        return []
    sig = (st.st_size, st.st_mtime_ns)
    ckey = (path, _geo_locale())   # отдельная ветка кеша на язык гео-имён
    entry = _LOG_ENRICH_CACHE.get(ckey)
    if entry and entry.get('sig') == sig:
        return entry['recs']
    with _LOG_ENRICH_LOCK:
        entry = _LOG_ENRICH_CACHE.get(ckey)
        if entry and entry.get('sig') == sig:
            return entry['recs']
        size_now = st.st_size
        if entry and size_now >= entry.get('size', 0):
            geo_cache = entry.get('geo') or {}
            text_new, size_now = _read_new_lines(path, entry['size'], size_now)
            new = _awg_parse_lines(text_new, geo_cache)
            out = new + entry['recs']
            if len(out) > 200000:
                out = out[:200000]
        else:
            geo_cache = {}
            out = _awg_parse_lines(_tail_bytes(path, 10 * 1024 * 1024), geo_cache)
        _LOG_ENRICH_CACHE[ckey] = {
            'sig': sig, 'size': size_now, 'recs': out,
            'geo': geo_cache, 'dest': {},
        }
        return out

def _load_last_ips_cache():
    try:
        with open(XRAY_LAST_IPS_FILE, 'r') as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if isinstance(v, dict) and 'ip' in v and 'ts' in v}
    except (OSError, ValueError):
        pass
    return {}

def _save_last_ips_cache(cache):
    try:
        tmp = XRAY_LAST_IPS_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp, XRAY_LAST_IPS_FILE)
    except OSError:
        pass

def _xray_inbound_kind(tag):
    """Тег инбаунда из журнала → вход для UI: vless / hy / xdns; '' — служебный."""
    tag = (tag or '').strip()
    if not tag or tag == 'api':
        return ''
    if xhy and tag == getattr(xhy, 'INBOUND_TAG', 'hysteria-in'):
        return 'hy'
    if tag == 'xdns-in':
        return 'xdns'
    return 'vless'


def xray_last_ips_by_email():
    """Returns {email: {'ip', 'ts'}} merging persistent cache with fresh tail.

    The cache survives log rotation and tail eviction — once an IP is captured for an
    email, it is kept indefinitely (until overwritten by a newer entry). On first run
    (empty cache) we seed from a larger 50MB scan so existing clients get backfilled.
    """
    cache = _load_last_ips_cache()
    if os.path.exists(XRAY_ACCESS_LOG):
        seed_mode = not cache
        scan_bytes = XRAY_LOG_FULL_BYTES if seed_mode else XRAY_LOG_TAIL_BYTES
        text = _tail_bytes(XRAY_ACCESS_LOG, scan_bytes)
        changed = False
        if text:
            for rec in _xray_parse_access_lines(text):
                email = rec.get('email') or ''
                if not email:
                    continue
                cur = cache.get(email)
                kind = _xray_inbound_kind(rec.get('inbound'))
                # Через XDNS соединение приходит от DNS-резолвера (Яндекс,
                # Google), а не от клиента: его IP в «последний IP» не берём —
                # иначе гео и фильтр по IP показывали бы резолвер.
                ip = '' if kind == 'xdns' else rec['ip']
                if not cur or rec['ts'] > cur.get('ts', ''):
                    via = dict((cur or {}).get('via') or {})
                    cache[email] = {'ip': ip or (cur or {}).get('ip', ''), 'ts': rec['ts'], 'via': via}
                    cur = cache[email]
                    changed = True
                if kind:
                    via = cur.setdefault('via', {})
                    if rec['ts'] > via.get(kind, ''):
                        via[kind] = rec['ts']
                        changed = True
        if changed:
            _save_last_ips_cache(cache)
    return cache

def xray_logs_for_email(email, limit=500):
    """Returns recent log records for an email, newest first, up to `limit`.

    Использует общий кеш _cached_xray_enriched — повторные вызовы при неизменном файле
    не парсят лог заново.
    """
    all_recs = _cached_xray_enriched()
    out = []
    for rec in all_recs:
        if rec.get('email') != email:
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out

def xray_query_stats():
    """Returns dict {email: {'up': int, 'down': int}} via xray api statsquery."""
    if not os.path.exists(XRAY_BIN):
        return {}
    out, err, rc = run_cmd(
        f'{XRAY_BIN} api statsquery -s={XRAY_API_ADDR} -pattern=user -reset=false'
    )
    if rc != 0 or not out:
        return {}
    try:
        data = json.loads(out)
    except Exception:
        return {}
    result = {}
    for s in data.get('stat', []):
        # name format: "user>>>email>>>traffic>>>uplink"  / ">>>downlink"
        parts = (s.get('name') or '').split('>>>')
        if len(parts) < 4 or parts[0] != 'user':
            continue
        email = parts[1]
        direction = parts[3]  # uplink | downlink
        val = int(s.get('value') or 0)
        slot = result.setdefault(email, {'up': 0, 'down': 0})
        if direction == 'uplink':
            slot['up'] = val
        elif direction == 'downlink':
            slot['down'] = val
    return result

def xray_query_online():
    """{email: сколько сессий клиента сейчас активно}.

    Бейдж «Устройств» на карточке — то же, что показывала старая Hysteria, но
    считает уже ядро XRay (policy.levels.0.statsUserOnline; без флага счётчика
    нет вовсе, и команды отдают пусто).

    Два шага, потому что одной командой число не достать:
      statsgetallonlineusers → ИМЕНА счётчиков тех, кто сейчас онлайн
                               {"users": ["user>>>email>>>online", ...]};
      statsonline -name …    → само число сессий конкретного клиента.
    Второй вызов делаем только по тем, кто в списке: онлайн обычно единицы, а
    гонять его по всей базе на каждый опрос карточек (раз в 15 секунд) нельзя.

    У Hysteria и VLESS клиента один email — значит цифра суммарная по клиенту,
    а не по протоколу. Это следствие общего email (см. xray_hysteria.client_email),
    на котором держатся общие трафик, правила и лимиты.
    """
    if not os.path.exists(XRAY_BIN):
        return {}
    out, _, rc = run_cmd(f'{XRAY_BIN} api statsgetallonlineusers -s={XRAY_API_ADDR}')
    if rc != 0 or not out:
        return {}
    try:
        data = json.loads(out)
    except Exception:
        return {}
    names = []
    if isinstance(data, dict):
        raw = data.get('users')
        if isinstance(raw, list):
            names = [n for n in raw if isinstance(n, str)]
        elif isinstance(raw, dict):
            # Запасной разбор: часть версий отдаёт сразу {email: значение}.
            return {k: _online_count(v) for k, v in raw.items() if isinstance(k, str)}
    # Потолок на случай массового онлайна: больше 60 вызовов на один опрос
    # карточек не оправдано, бейдж не настолько важен.
    todo = []
    for name in names[:60]:
        parts = name.split('>>>')
        if len(parts) >= 3 and parts[0] == 'user':
            todo.append((parts[1], name))

    def _one(item):
        email, name = item
        o, _, orc = run_cmd(f'{XRAY_BIN} api statsonline -s={XRAY_API_ADDR} -name "{name}"')
        # Сам факт присутствия в списке уже означает «онлайн» — если число не
        # разобралось, показываем хотя бы единицу, а не прячем бейдж.
        return email, (_online_count(o) if orc == 0 else 0) or 1

    # Каждый вызов — отдельный запуск бинаря xray (~0.1 с). Подряд это секунды
    # на каждый /api/xray/status, а список клиентов ждёт именно его.
    if len(todo) <= 1:
        return dict(_one(t) for t in todo)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(8, len(todo))) as ex:
        return dict(ex.map(_one, todo))


def _online_count(raw):
    """Число сессий из ответа statsonline. Формат между версиями ядра плавает:
    {"stat":{"value":"2"}}, {"value":"2"}, голое число или список адресов."""
    if isinstance(raw, (int, float)):
        return int(raw)
    if isinstance(raw, (list, tuple)):
        return len(raw)
    if isinstance(raw, str):
        txt = raw.strip()
        if txt.isdigit():
            return int(txt)
        try:
            raw = json.loads(txt)
        except Exception:
            return 0
    if isinstance(raw, dict):
        if isinstance(raw.get('stat'), dict):
            raw = raw['stat']
        for key in ('value', 'count', 'online'):
            if key in raw:
                return _online_count(raw[key])
        if isinstance(raw.get('ips'), list):
            return len(raw['ips'])
    return 0


@app.route('/api/xray/status')
@login_required
def xray_status():
    try:
        _run_xray_scheduler()
    except Exception as _e:
        audit('warn', f'XRay scheduler error: {_e}')
    clients = load_xray_clients()
    _, _, rc = run_cmd('systemctl is-active --quiet xray')
    stats = xray_query_stats() if rc == 0 else {}
    online_devices = xray_query_online() if rc == 0 else {}
    cfg_text = ''
    try:
        with open(XRAY_CONFIG, 'r') as _f:
            cfg_text = _f.read()
    except Exception:
        pass
    has_stats_section = False
    has_access_log_section = False
    try:
        _cfg_obj_for_detect = json.loads(cfg_text) if cfg_text else {}
        api_obj = _cfg_obj_for_detect.get('api') or {}
        api_in_inbounds = any((ib.get('tag') == 'api') for ib in (_cfg_obj_for_detect.get('inbounds') or []))
        has_stats_section = (
            'stats' in _cfg_obj_for_detect
            and 'StatsService' in (api_obj.get('services') or [])
            and api_in_inbounds
        )
        log_obj = _cfg_obj_for_detect.get('log') or {}
        access_path = log_obj.get('access') or ''
        # Принимаем оба пути — новый (наш) и старый (legacy /var/log/xray).
        has_access_log_section = (
            XRAY_ACCESS_LOG in str(access_path)
            or '/var/log/xray/access.log' in str(access_path)
        )
    except Exception:
        has_stats_section = '"StatsService"' in cfg_text
        has_access_log_section = (
            XRAY_ACCESS_LOG in cfg_text or '/var/log/xray/access.log' in cfg_text
        )
    # Detect security mode (tls vs reality) by inspecting first vless inbound
    xray_security = 'tls'
    xray_dest = ''
    try:
        cfg_obj = json.loads(cfg_text) if cfg_text else {}
        for inb in cfg_obj.get('inbounds', []):
            if inb.get('protocol') == 'vless':
                ss = inb.get('streamSettings') or {}
                sec = ss.get('security') or 'tls'
                if sec == 'reality':
                    xray_security = 'reality'
                    rs = ss.get('realitySettings') or {}
                    xray_dest = (rs.get('serverNames') or [''])[0] or rs.get('dest', '')
                else:
                    xray_security = 'tls'
                break
    except Exception:
        pass
    last_ips = xray_last_ips_by_email()
    access_log_enabled = has_access_log_section
    now_ts = time.time()
    ONLINE_WINDOW_SEC = 180
    # Накопительный кеш трафика per-email: счётчики xray сбрасываются при рестарте,
    # поэтому панель сама копит totals в xray_global_totals.json. Дельта = current - last_seen.
    # При current < last_seen (xray рестартнулся) считаем что вся текущая current — новый
    # трафик после рестарта, прибавляем его к накопителю.
    persisted = {}
    try:
        if os.path.exists(XRAY_GLOBAL_TOTALS_DB):
            with open(XRAY_GLOBAL_TOTALS_DB, 'r') as _f:
                _d = json.load(_f)
            if isinstance(_d, dict) and isinstance(_d.get('per_email'), dict):
                persisted = _d['per_email']
    except Exception:
        persisted = {}
    for _email, _s in stats.items():
        cur_up = int(_s.get('up') or 0)
        cur_down = int(_s.get('down') or 0)
        prev = persisted.get(_email) or {}
        last_up = int(prev.get('up_seen') or 0)
        last_down = int(prev.get('down_seen') or 0)
        tot_up = int(prev.get('up_total') or 0)
        tot_down = int(prev.get('down_total') or 0)
        tot_up += cur_up if cur_up < last_up else (cur_up - last_up)
        tot_down += cur_down if cur_down < last_down else (cur_down - last_down)
        persisted[_email] = {
            'up_seen': cur_up, 'down_seen': cur_down,
            'up_total': tot_up, 'down_total': tot_down,
        }
    try:
        with open(XRAY_GLOBAL_TOTALS_DB + '.tmp', 'w') as _f:
            json.dump({'ts': time.strftime('%Y-%m-%d %H:%M'),
                       'per_email': persisted}, _f)
        os.replace(XRAY_GLOBAL_TOTALS_DB + '.tmp', XRAY_GLOBAL_TOTALS_DB)
    except Exception:
        pass
    enriched = []
    clients_changed = False
    hy_drop_emails = []   # кого убрать из работающего инбаунда Hysteria
    for c in clients.values():
        item = dict(c)
        email = _xray_unique_email(c.get('name', ''), c.get('uuid', ''))
        # Берём накопленные значения, а не сырой stats[email] — иначе при рестарте xray
        # карточка обнуляется.
        p = persisted.get(email) or {}
        item['up'] = int(p.get('up_total') or 0)
        item['down'] = int(p.get('down_total') or 0)
        item['total'] = item['up'] + item['down']
        # Авто-отключение по лимиту трафика (per-client).
        limit_gb = c.get('traffic_limit_gb')
        if limit_gb and not c.get('disabled') and item['total'] >= int(limit_gb) * (1024 ** 3):
            try:
                xray_remove_uuid(c.get('uuid'))
            except Exception:
                pass
            c['disabled'] = True
            c['disabled_by_limit'] = True
            item['disabled'] = True
            item['disabled_by_limit'] = True
            clients_changed = True
            hy_drop_emails.append(email)
            audit('info', f'Авто-отключение XRay по лимиту {limit_gb} GB: {c.get("name")}')
        # Сколько устройств сейчас онлайн. Ядро считает АДРЕСА: телефон и
        # ноутбук за одним роутером для него — одно. А одно устройство не
        # сидит одновременно на двух входах, поэтому VLESS на ноутбуке и
        # Hysteria на телефоне — уже два. Берём большее; via_active
        # заполняется ниже, после разбора журнала — досчитываем там.
        item['devices'] = int(online_devices.get(email) or 0)
        item['online'] = False
        last = last_ips.get(email)
        # Через какие входы клиент приходил и когда — для бейджа «VLESS ·
        # Shadowrocket» в карточке; приложение — по User-Agent последней
        # загрузки профиля/подписки (сам VPN-трафик приложение не называет).
        item['via'] = dict((last or {}).get('via') or {})
        # Входы, через которые клиент активен сейчас (окно — как у «онлайн»).
        item['via_active'] = []
        for _k, _ts in item['via'].items():
            try:
                if now_ts - time.mktime(time.strptime(_ts, '%Y/%m/%d %H:%M:%S')) <= ONLINE_WINDOW_SEC:
                    item['via_active'].append(_k)
            except Exception:
                pass
        _pf = c.get('profile_fetch') if isinstance(c.get('profile_fetch'), dict) else {}
        _app = max((v for v in _pf.values() if isinstance(v, dict) and v.get('app')),
                   key=lambda v: v.get('ts') or '', default=None)
        item['app'] = {'name': _app['app'], 'ts': _app.get('ts', '')} if _app else {}
        if item['via_active']:
            item['devices'] = max(item['devices'], len(item['via_active']))
        if last:
            item['last_ip'] = last['ip']
            item['last_seen'] = last['ts']
            try:
                last_epoch = time.mktime(time.strptime(last['ts'], '%Y/%m/%d %H:%M:%S'))
                if (now_ts - last_epoch) <= ONLINE_WINDOW_SEC:
                    item['online'] = True
            except Exception:
                pass
            geo = geo_asn_full(last['ip'])
            if geo:
                item['geo'] = geo
        elif not access_log_enabled and item['total'] > 0:
            # Fallback when access.log is off — best we can do is "ever used"
            item['online'] = True
        enriched.append(item)
    if clients_changed:
        save_xray_clients(clients)
        # Инбаунд Hysteria собирается из файла клиентов, а xray_remove_uuid
        # отработал ДО записи — тогда клиент ещё числился включённым, и его
        # пароль остался бы в инбаунде. Без этой синхронизации отключённый по
        # лимиту продолжал бы ходить через Hysteria.
        _hy_sync()
        for _email in hy_drop_emails:
            _hy_apply_after_sync('remove', _email)
    global_total_up = sum(int((p or {}).get('up_total') or 0) for p in persisted.values())
    global_total_down = sum(int((p or {}).get('down_total') or 0) for p in persisted.values())
    return jsonify({
        'running': rc == 0,
        'state': _proto_state('xray'),
        'clients': enriched,
        'rule_lists': load_rule_lists(),
        'stats_enabled': has_stats_section,
        'access_log_enabled': access_log_enabled,
        # «Намерение» (что юзер хочет) — от него зависит состояние тумблеров и ⚠.
        # Отдельно от *_enabled (фактическое наличие секций в конфиге), чтобы при
        # слетевшем stats тумблер всё равно показывал ON и проверка срабатывала.
        'stats_wanted': _xray_stats_wanted(),
        'logs_wanted': _xray_logs_wanted(),
        'xray_security': xray_security,
        'xray_dest': xray_dest,
        'port': get_xray_port(),
        'global_rules': load_xray_global(),
        'global_totals': {'up': global_total_up, 'down': global_total_down},
        'dns_default': _global_dns_default(),  # DNS-дефолт для новых юзеров (модалка Global)
        # Второй вход того же ядра. Плитка «Маскировка» показывает обе строки:
        # у VLESS и Hysteria прикрытия разные (фоллбек против masquerade).
        # Вместе со статусом идёт диагноз по порту: выключенный инбаунд плитка
        # тоже показывает, и рядом должно быть видно, почему он выключен.
        'hysteria': _hy_card_state(),
    })

@app.route('/api/xray/restart-status')
@login_required
def xray_restart_status():
    """Состояние фонового рестарта xray: busy — ещё идёт, ok — чем кончился прошлый."""
    s = dict(_xray_restart_status)
    s['busy'] = bool(s.get('pending') or s.get('running'))
    return jsonify(s)

@app.route('/api/xray/enable-stats', methods=['POST'])
@login_required
def xray_enable_stats():
    try:
        changed = patch_xray_for_stats()
    except Exception as e:
        return jsonify({'error': f'Patch failed: {e}'}), 500
    # Фиксируем намерение «хочу статистику» — теперь авто-накат и ⚠ держат её включённой.
    SERVER_CFG['xray_stats_wanted'] = True
    _save_server_config(SERVER_CFG)
    if changed:
        schedule_xray_restart()
    return jsonify({'ok': True, 'changed': changed})

# === XRay Global rules endpoints ===
def _global_pending_from_body(pending, body):
    """Применяет частичные изменения из body к pending-полям."""
    if 'enabled' in body:
        pending['enabled'] = bool(body['enabled'])
    if 'mode' in body:
        m = (body.get('mode') or '').strip()
        if m in ('lists', 'via', 'direct'):
            pending['mode'] = m
    if 'lists' in body and isinstance(body['lists'], list):
        pending['lists'] = [str(x) for x in body['lists'] if isinstance(x, (str, int))]
    if 'countries' in body and isinstance(body['countries'], list):
        pending['countries'] = [str(x).upper() for x in body['countries']
                                if isinstance(x, str) and len(x) <= 4]
    return pending

@app.route('/api/xray/global', methods=['GET'])
@login_required
def xray_global_get():
    return jsonify(load_xray_global())

@app.route('/api/xray/global', methods=['POST'])
@login_required
def xray_global_set():
    """Сохраняет pending. К xray-config НЕ применяет — нужно дождаться /apply."""
    body = request.get_json(force=True) or {}
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    before = dict(pending)
    _global_pending_from_body(pending, body)
    blob['pending'] = pending
    save_xray_global(blob)
    diff = [k for k in pending if pending.get(k) != before.get(k)]
    if diff:
        audit('info', f'Global rules pending изменён: {",".join(diff)} '
                      f'(enabled={pending["enabled"]} mode={pending["mode"]} '
                      f'lists={len(pending["lists"])} countries={len(pending["countries"])})')
    return jsonify({'ok': True, **blob})

@app.route('/api/xray/global/toggle', methods=['POST'])
@login_required
def xray_global_toggle():
    """Тоггл pending.enabled. Применяется только после /apply."""
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    pending['enabled'] = not pending['enabled']
    blob['pending'] = pending
    save_xray_global(blob)
    audit('info', f'Global rules pending.enabled → {pending["enabled"]} (нужно нажать «Применить»)')
    return jsonify({'ok': True, **blob})

@app.route('/api/xray/global/apply', methods=['POST'])
@login_required
def xray_global_apply_endpoint():
    """Применить pending к xray-config (с использованием кеша списков)."""
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    new_blob = _xray_global_apply(pending, force_refresh=False)
    audit('info', f'Global rules apply: enabled={pending["enabled"]} mode={pending["mode"]} '
                  f'lists={len(pending["lists"])} countries={len(pending["countries"])}')
    return jsonify({'ok': True, **new_blob})

@app.route('/api/xray/global/refresh', methods=['POST'])
@login_required
def xray_global_refresh():
    """Принудительно перекачивает все списки и применяет pending."""
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    new_blob = _xray_global_apply(pending, force_refresh=True)
    audit('info', 'Global rules refresh (full re-download)')
    return jsonify({'ok': True, **new_blob})

# === XRay Global rules: schedule / traffic ===
# Глобальное расписание применяется ко всему XRay. Когда задано — UI блокирует
# соответствующие per-client секции, но per-client значения НЕ обнуляются.
def _global_save_field(field, value):
    """Записывает поле сразу в pending И applied (для расписания пендинг не имеет смысла)."""
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    applied = _norm_global_fields(blob.get('applied'))
    pending[field] = value
    applied[field] = value
    blob['pending'] = pending
    blob['applied'] = applied
    save_xray_global(blob)
    return blob

@app.route('/api/xray/global/schedule', methods=['POST'])
@login_required
def xray_global_set_schedule():
    data = request.get_json(force=True) or {}
    raw_action = data.get('action')
    raw_date = data.get('date')
    if raw_action in (None, '', 'none'):
        action, date = None, None
    elif raw_action == 'disable':
        date = _validate_schedule_date(raw_date)
        if not date:
            return jsonify({'error': 'date must be future YYYY-MM-DD'}), 400
        action = raw_action
    else:
        return jsonify({'error': 'action must be disable|none'}), 400
    blob = load_xray_global()
    pending = _norm_global_fields(blob.get('pending'))
    applied = _norm_global_fields(blob.get('applied'))
    pending['scheduled_action'] = action
    pending['scheduled_at'] = date
    applied['scheduled_action'] = action
    applied['scheduled_at'] = date
    blob['pending'] = pending
    blob['applied'] = applied
    save_xray_global(blob)
    audit('info', f'XRay Global schedule: {action or "сброшено"} {date or ""}')
    return jsonify({'ok': True, 'scheduled_action': action, 'scheduled_at': date})

@app.route('/api/xray/global/traffic/reset-day', methods=['POST'])
@login_required
def xray_global_set_reset_day():
    data = request.get_json(force=True) or {}
    raw = data.get('day', None)
    if raw in (None, '', 0, '0'):
        day = None
    else:
        try:
            day = int(raw)
            if day < 1 or day > 31:
                return jsonify({'error': 'day must be 1..31'}), 400
        except Exception:
            return jsonify({'error': 'day must be integer'}), 400
    _global_save_field('traffic_reset_day', day)
    audit('info', f'XRay Global reset_day: {day}')
    return jsonify({'ok': True, 'traffic_reset_day': day})

@app.route('/api/xray/global/traffic/limit', methods=['POST'])
@login_required
def xray_global_set_limit():
    data = request.get_json(force=True) or {}
    raw = data.get('gb', None)
    if raw in (None, '', 0, '0'):
        gb = None
    else:
        try:
            gb = int(raw)
            if gb < 1:
                return jsonify({'error': 'gb must be >= 1'}), 400
        except Exception:
            return jsonify({'error': 'gb must be integer'}), 400
    _global_save_field('traffic_limit_gb', gb)
    audit('info', f'XRay Global limit: {gb} GB' if gb else 'XRay Global limit снят')
    return jsonify({'ok': True, 'traffic_limit_gb': gb})

@app.route('/api/xray/global/traffic/reset', methods=['POST'])
@login_required
def xray_global_reset_now():
    """Обнуляет xray_global_totals целиком (все email-ы). Логи не трогаются."""
    try:
        persisted_live = {}
        try:
            live = xray_query_stats() or {}
        except Exception:
            live = {}
        # Для каждого known email — обнулим up_total/down_total, up_seen/down_seen = текущие живые
        try:
            if os.path.exists(XRAY_GLOBAL_TOTALS_DB):
                with open(XRAY_GLOBAL_TOTALS_DB, 'r') as f:
                    d = json.load(f)
                emails = list((d.get('per_email') or {}).keys()) if isinstance(d, dict) else []
            else:
                emails = []
        except Exception:
            emails = []
        for em in set(list(live.keys()) + list(emails)):
            cur = live.get(em) or {}
            persisted_live[em] = {
                'up_seen': int(cur.get('up') or 0),
                'down_seen': int(cur.get('down') or 0),
                'up_total': 0, 'down_total': 0,
            }
        tmp = XRAY_GLOBAL_TOTALS_DB + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'ts': time.strftime('%Y-%m-%d %H:%M'), 'per_email': persisted_live}, f)
        os.replace(tmp, XRAY_GLOBAL_TOTALS_DB)
    except Exception as e:
        return jsonify({'error': f'reset failed: {e}'}), 500
    today = time.strftime('%Y-%m-%d')
    _global_save_field('traffic_last_reset', today)
    audit('info', 'XRay Global traffic reset (вручную)')
    return jsonify({'ok': True, 'reset_at': today})

@app.route('/api/xray/enable-access-log', methods=['POST'])
@login_required
def xray_enable_access_log():
    try:
        changed = patch_xray_for_access_log()
    except Exception as e:
        return jsonify({'error': f'Patch failed: {e}'}), 500
    # Логи — ручной опт-ин: фиксируем намерение, чтобы ⚠ и авто-накат держали их.
    SERVER_CFG['xray_logs_wanted'] = True
    _save_server_config(SERVER_CFG)
    if changed:
        schedule_xray_restart()
    return jsonify({'ok': True, 'changed': changed, 'path': XRAY_ACCESS_LOG})

@app.route('/api/xray/clients', methods=['POST'])
@login_required
def xray_create_client():
    data = request.json or {}
    name = _normalize_client_name(data.get('name'))
    bypass_ru = bool(data.get('bypass_ru', False))
    no_rules = bool(data.get('no_rules', False))
    if not name:
        return jsonify({'error': 'Name required'}), 400

    # Ключ идемпотентности. Создание клиента перезапускает XRay, а на серверах,
    # где панель отдаётся фоллбеком того же XRay, рестарт рвёт и соединение
    # самой панели — ответ до браузера не доходит. Браузер считает сокет
    # оборванным и отправляет POST заново, сервер обрабатывает его второй раз, и
    # из одного нажатия получаются два клиента. Поэтому повтор с тем же ключом
    # отдаёт уже созданного, а не делает нового.
    req_id = str(data.get('request_id') or '').strip()[:64]
    if req_id:
        for c in load_xray_clients().values():
            if c.get('request_id') == req_id:
                return jsonify(c)

    # Дубли имён запрещены: имя уходит в имя файла профиля, в публичный URL
    # подписки и в email статистики, поэтому два «test» неразличимы в карточках,
    # логах и трафике.
    if _client_name_taken(load_xray_clients(), name):
        return jsonify({'error': f'Клиент с именем «{name}» уже есть — выберите другое имя'}), 409

    raw_rule_lists = data.get('rule_lists') or {}
    catalog_full = load_rule_lists()
    rule_lists = {}
    for p in CLIENT_RULE_PLATFORMS:
        ids_in_catalog = {r['id'] for r in catalog_full.get(p, [])}
        if isinstance(raw_rule_lists, dict):
            arr = raw_rule_lists.get(p) or []
        elif isinstance(raw_rule_lists, list):
            arr = raw_rule_lists
        else:
            arr = []
        rule_lists[p] = [str(i) for i in arr if str(i) in ids_in_catalog]

    clients = load_xray_clients()
    new_uuid = str(uuid_lib.uuid4())
    try:
        xray_add_uuid(new_uuid, name)
    except Exception as e:
        return jsonify({'error': f'XRay config error: {e}'}), 500

    sub_token = secrets.token_hex(16)
    if no_rules:
        rule_lists = {p: [] for p in CLIENT_RULE_PLATFORMS}
        initial_geo_mode = 'off'
        initial_geo_countries = []
    else:
        # Ничего не включаем сами: клиент получает ровно то, что отметили в форме.
        # geo_mode='lists' означает «маршрутизировать по спискам», поэтому его
        # включают только правила с политикой VPN. Block/Direct — не маршрутизация
        # (и работают при любом режиме, см. _selected_for_mode): клиент, у которого
        # выбран один лишь ad-block, иначе получил бы 'lists' + FINAL,DIRECT, то
        # есть VPN вообще мимо.
        routing_ids = {r['id'] for r in catalog_full.get('lists', [])
                       if (r.get('policy') or 'proxy') == 'proxy'}
        has_any_list = any(
            [i for i in (rule_lists.get(p) or []) if i in routing_ids]
            for p in CLIENT_RULE_PLATFORMS
        )
        initial_geo_mode = 'lists' if has_any_list else ('direct' if bypass_ru else 'off')
        initial_geo_countries = ['RU'] if (bypass_ru and not has_any_list) else []
    clients[new_uuid] = {
        'name': name,
        'uuid': new_uuid,
        'created': time.strftime('%Y-%m-%d %H:%M'),
        'bypass_ru': bypass_ru,
        'rule_lists': rule_lists,
        'token': sub_token,
        'geo_mode': initial_geo_mode,
        'geo_countries': initial_geo_countries,
        'geo_mode_pending': initial_geo_mode,
        'geo_countries_pending': list(initial_geo_countries),
        'lists_default': 'direct',      # что делать с трафиком вне списков (см. _lists_final_policy)
        'dns': _global_dns_default(),   # новый юзер наследует глобальный DNS-дефолт
        'request_id': req_id,           # ключ идемпотентности, см. выше
    }
    save_xray_clients(clients)
    # Ещё раз: xray_add_uuid отработал ДО записи клиента в базу, поэтому первая
    # синхронизация его не увидела — без этого вызова новичок остался бы без
    # пароля Hysteria и не попал бы в её инбаунд до следующего изменения.
    _hy_sync()
    # А это применяет его к работающему ядру: пароль Hysteria появился только
    # сейчас, на прошлом шаге применять было нечего.
    _hy_apply_after_sync('add', _xray_unique_email(name, new_uuid), new_uuid)
    audit('info', f'XRay client создан: {name} (geo_mode={initial_geo_mode})')

    return jsonify({
        'ok': True,
        'uuid': new_uuid,
        'name': name,
        'bypass_ru': bypass_ru,
        'rule_lists': rule_lists,
        'token': sub_token,
        'vless': build_vless_link(new_uuid, name, sub_token),
        # Без объекта из памяти: пароль Hysteria клиенту назначается при
        # синхронизации инбаунда, уже после save_xray_clients — локальная
        # копия его ещё не видит, и ссылка вышла бы пустой.
        'hy2': build_hy2_link(new_uuid),
        'xdns': build_xdns_config(new_uuid, clients[new_uuid]),
        'xdns_link': build_xdns_link(new_uuid, clients[new_uuid]),
        'shadowrocket': build_shadowrocket_profile(clients[new_uuid]),
        'loon': build_loon_profile(clients[new_uuid]),
        'clash': build_clash_profile(clients[new_uuid])
    })

@app.route('/api/xray/clients/<client_uuid>', methods=['DELETE'])
@login_required
def xray_delete_client(client_uuid):
    # Always clean panel DB first — even if xray operation fails the panel
    # state must reflect user intent so duplicate-name errors don't haunt them.
    clients = load_xray_clients()
    deleted_name = (clients.get(client_uuid) or {}).get('name') or client_uuid[:8] + '…'
    if client_uuid in clients:
        del clients[client_uuid]
        save_xray_clients(clients)
    # Also drop any stale dict entries that point to the same UUID via 'uuid' field.
    stale = [k for k, v in clients.items() if v.get('uuid') == client_uuid]
    if stale:
        for k in stale:
            clients.pop(k, None)
        save_xray_clients(clients)
    xray_err = None
    try:
        xray_remove_uuid(client_uuid)
    except Exception as e:
        xray_err = str(e)
    # Чтобы в роутинге не оставалось deny-правило удалённого клиента.
    try:
        apply_allow_ip_rules()
    except Exception as e:
        audit('warn', f'Белый список IP после удаления не пересобран: {e}')
    audit('info', f'XRay client удалён: {deleted_name}')
    resp = {'ok': True}
    if xray_err:
        resp['warning'] = f'XRay config: {xray_err}'
    return jsonify(resp)

@app.route('/api/xray/clients/<client_uuid>/config')
@login_required
def xray_get_client_config(client_uuid):
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    c = clients[client_uuid]
    resp = jsonify({
        'name': c['name'],
        'uuid': client_uuid,
        'bypass_ru': c.get('bypass_ru', False),
        'rule_lists': c.get('rule_lists', []),
        'token': c.get('token', ''),
        'vless': build_vless_link(client_uuid, c['name'], c.get('token')),
        'hy2': build_hy2_link(client_uuid, c),
        'xdns': build_xdns_config(client_uuid, c),
        'xdns_link': build_xdns_link(client_uuid, c),
        'shadowrocket': build_shadowrocket_profile(c),
        'loon': build_loon_profile(c),
        'clash': build_clash_profile(c),
        'profile_fetch': c.get('profile_fetch') or {}
    })
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/xray/clients/<client_uuid>/geo-mode', methods=['POST'])
@login_required
def xray_set_geo_mode(client_uuid):
    data = request.json or {}
    mode = (data.get('mode') or 'off').strip()
    if mode not in ('off', 'lists', 'via', 'direct'):
        return jsonify({'error': 'Invalid mode'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    # Пишем только в PENDING — фактически правила меняются по «Применить» (как глобал-рул),
    # чтобы перебор режимов/стран не пересобирал ничего на сервере.
    clients[client_uuid]['geo_mode_pending'] = mode
    save_xray_clients(clients)
    return jsonify({'ok': True, 'geo_mode_pending': mode})


@app.route('/api/xray/clients/<client_uuid>/geo-apply', methods=['POST'])
@login_required
def xray_apply_geo(client_uuid):
    """Зафиксировать pending → applied (как «Применить» у глобал-рул). Только тут
    настройки по странам реально вступают в силу (их читают билдеры конфигов)."""
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    c = clients[client_uuid]
    mode = (c.get('geo_mode_pending') if c.get('geo_mode_pending') is not None
            else c.get('geo_mode')) or 'off'
    if mode not in ('off', 'lists', 'via', 'direct'):
        mode = 'off'
    countries = c.get('geo_countries_pending')
    if not isinstance(countries, list):
        countries = c.get('geo_countries') or []
    ld = c.get('lists_default_pending')
    if ld not in LISTS_DEFAULT_MODES:
        ld = c.get('lists_default') or 'direct'
    c['geo_mode'] = mode
    c['geo_countries'] = countries
    c['geo_mode_pending'] = mode
    c['geo_countries_pending'] = list(countries)
    c['lists_default'] = ld
    c['lists_default_pending'] = ld
    save_xray_clients(clients)
    audit('info', f'geo applied: mode={mode} countries={countries} '
                  f'lists_default={ld} for {c.get("name")}')
    return jsonify({'ok': True, 'geo_mode': mode, 'geo_countries': countries,
                    'lists_default': ld})

# === DNS-настройка клиентских конфигов =====================================
@app.route('/api/dns/templates', methods=['GET'])
@login_required
def api_dns_templates():
    """Каталог готовых резолверов для модалки DNS (Cloudflare/Google/AdGuard/…)."""
    return jsonify({'templates': DNS_TEMPLATES})

@app.route('/api/dns/default', methods=['GET', 'POST'])
@login_required
def api_dns_default():
    """DNS-дефолт для НОВЫХ юзеров (server.json). Правится из модалки Global."""
    if request.method == 'GET':
        return jsonify({'dns': _global_dns_default()})
    data = request.get_json(silent=True) or {}
    dns = _norm_dns(data.get('dns'))
    SERVER_CFG['dns_default'] = dns
    _save_server_config(SERVER_CFG)
    audit('info', f'DNS-дефолт новых юзеров → mode={dns["mode"]} tpl={dns["template"] or "custom"}')
    # Этот же резолвер использует сам xray для доменов, уходящих в VPN (их резолвит
    # сервер, а не устройство) — накатываем сразу, с перезапуском xray при изменении.
    restarted = False
    xray_err = None
    try:
        restarted = apply_xray_dns()
    except Exception as e:
        xray_err = str(e)
        audit('warn', f'DNS сервера XRay не применён: {e}')
    if restarted:
        audit('info', f'DNS сервера XRay → {dns["doh"] or ", ".join(dns["plain"]) or "системный"}')
    # При включённом каскаде дефолтный маршрут XRay — socks в mihomo, и хвост
    # MATCH,DIRECT резолвит уже он. Значит тот же DNS нужен и в его config.yaml,
    # иначе смена резолвера ни на что не влияет.
    mihomo_applied = False
    try:
        if mihomo and mihomo._mihomo_cfg().get('active_profile'):
            mihomo_applied, _msg = mihomo._mihomo_apply_active()
    except Exception as e:
        audit('warn', f'DNS для mihomo не применён: {e}')
    if mihomo_applied:
        audit('info', 'DNS сервера mihomo обновлён из Global')
    resp = {'ok': True, 'dns': dns, 'xray_restarted': restarted,
            'mihomo_applied': mihomo_applied}
    if xray_err:
        resp['warning'] = f'XRay config: {xray_err}'
    return jsonify(resp)

@app.route('/api/xray/clients/<client_uuid>/dns', methods=['POST'])
@login_required
def xray_set_dns(client_uuid):
    """Задать DNS одного XRay-клиента. Действует сразу (конфиги рендерятся на лету,
    рестарт xray не нужен — DNS живёт в клиентском профиле, не в серверном роутинге)."""
    data = request.get_json(silent=True) or {}
    dns = _norm_dns(data.get('dns'))
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['dns'] = dns
    save_xray_clients(clients)
    c = clients[client_uuid]
    audit('info', f'DNS для {c.get("name") or client_uuid[:8]} → mode={dns["mode"]} tpl={dns["template"] or "custom"}')
    return jsonify({'ok': True, 'dns': dns})

@app.route('/api/xray/clients/<client_uuid>/allow-ips', methods=['POST'])
@login_required
def xray_set_allow_ips(client_uuid):
    """Фильтрация IP клиента: белый (allow_ips) и чёрный (block_ips) списки.

    Оба поля опциональны — сохраняется то, что пришло, остальное не трогаем.
    Пустой белый список = доступ с любого адреса, пустой чёрный = блокировок нет.
    Правила живут в серверном роутинге XRay, поэтому сохранение перезапускает
    xray (см. apply_allow_ip_rules)."""
    data = request.get_json(silent=True) or {}
    fields = {}
    for key in ('allow_ips', 'block_ips'):
        raw = data.get(key)
        if raw is None:
            continue
        if not isinstance(raw, list):
            return jsonify({'error': f'{key} must be a list'}), 400
        for x in raw:
            if not _norm_allow_ip(x):
                return jsonify({'error': f'Некорректный адрес: {x}'}), 400
        fields[key] = _norm_allow_ips(raw)
    if not fields:
        return jsonify({'error': 'allow_ips or block_ips required'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid].update(fields)
    save_xray_clients(clients)
    name = clients[client_uuid].get('name') or client_uuid[:8]
    try:
        restarted = apply_allow_ip_rules()
    except Exception as e:
        audit('error', f'Списки IP для {name} не применены: {e}')
        return jsonify({'error': f'XRay config: {e}'}), 500
    if 'allow_ips' in fields:
        audit('info', f'Белый список IP для {name}: '
                      + (', '.join(fields['allow_ips']) or 'снят (доступ с любого адреса)'))
    if 'block_ips' in fields:
        audit('info', f'Чёрный список IP для {name}: '
                      + (', '.join(fields['block_ips']) or 'снят (блокировок нет)'))
    return jsonify({
        'ok': True,
        'allow_ips': clients[client_uuid].get('allow_ips') or [],
        'block_ips': clients[client_uuid].get('block_ips') or [],
        'xray_restarted': restarted,
    })

def _validate_schedule_date(s):
    """Returns 'YYYY-MM-DD' if valid future date, else None."""
    if not s:
        return None
    try:
        d = time.strptime(s, '%Y-%m-%d')
        target = time.strftime('%Y-%m-%d', d)
        today = time.strftime('%Y-%m-%d')
        if target <= today:
            return None
        return target
    except Exception:
        return None

@app.route('/api/xray/clients/<client_uuid>/disable', methods=['POST'])
@login_required
def xray_set_disabled(client_uuid):
    data = request.json or {}
    disabled = bool(data.get('disabled'))
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    c = clients[client_uuid]
    was = bool(c.get('disabled'))
    c['disabled'] = disabled
    save_xray_clients(clients)
    if disabled and not was:
        try: xray_remove_uuid(client_uuid)
        except Exception: pass
        audit('info', f'XRay client отключён: {c.get("name")}')
    elif not disabled and was:
        try: xray_add_uuid(client_uuid, c.get('name', ''))
        except Exception: pass
        audit('info', f'XRay client включён: {c.get("name")}')
    return jsonify({'ok': True, 'disabled': disabled})

@app.route('/api/xray/clients/<client_uuid>/schedule', methods=['POST'])
@login_required
def xray_set_schedule(client_uuid):
    data = request.json or {}
    raw_action = data.get('action')
    raw_date = data.get('date')
    if raw_action in (None, '', 'none'):
        action, date = None, None
    elif raw_action in ('delete', 'disable'):
        date = _validate_schedule_date(raw_date)
        if not date:
            return jsonify({'error': 'date must be future YYYY-MM-DD'}), 400
        action = raw_action
    else:
        return jsonify({'error': 'action must be delete|disable|none'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['scheduled_action'] = action
    clients[client_uuid]['scheduled_at'] = date
    save_xray_clients(clients)
    audit('info', f'XRay schedule {clients[client_uuid].get("name")}: {action or "сброшено"} {date or ""}')
    return jsonify({'ok': True, 'scheduled_action': action, 'scheduled_at': date})

def _reset_xray_traffic_for_email(email):
    """Зануляет up_total/down_total в xray_global_totals.json для одного email.
    Также подтягивает up_seen/down_seen к текущим живым счётчикам xray, чтобы
    следующая дельта не «добавила» только что обнулённое.
    Логи доступа НЕ трогаются."""
    persisted = {}
    try:
        if os.path.exists(XRAY_GLOBAL_TOTALS_DB):
            with open(XRAY_GLOBAL_TOTALS_DB, 'r') as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get('per_email'), dict):
                persisted = d['per_email']
    except Exception:
        persisted = {}
    # Снимок живых счётчиков, чтобы дельты не реанимировали трафик
    live = {}
    try:
        live = xray_query_stats() or {}
    except Exception:
        live = {}
    cur = live.get(email) or {}
    cur_up = int(cur.get('up') or 0)
    cur_down = int(cur.get('down') or 0)
    persisted[email] = {
        'up_seen': cur_up, 'down_seen': cur_down,
        'up_total': 0, 'down_total': 0,
    }
    try:
        tmp = XRAY_GLOBAL_TOTALS_DB + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'ts': time.strftime('%Y-%m-%d %H:%M'), 'per_email': persisted}, f)
        os.replace(tmp, XRAY_GLOBAL_TOTALS_DB)
    except Exception:
        pass

def _last_day_of_month(year, month):
    import calendar
    return calendar.monthrange(year, month)[1]

def _is_traffic_reset_due(reset_day, today_str):
    """True если сегодня — день ежемесячного сброса для данного reset_day.
    Если reset_day = 31 и в текущем месяце 30 дней — сбрасываем 30-го (последний день).
    Если reset_day = 29 и февраль (28 дней) — 28-го."""
    if not reset_day:
        return False
    try:
        y, m, d = today_str.split('-')
        y, m, d = int(y), int(m), int(d)
    except Exception:
        return False
    eom = _last_day_of_month(y, m)
    effective = min(int(reset_day), eom)
    return d == effective

def _reenable_if_disabled_by_limit(client_uuid, c):
    """Если клиент был отключён авто-лимитом — включаем обратно (трафик уже сброшен)."""
    if c.get('disabled') and c.get('disabled_by_limit'):
        c['disabled'] = False
        c['disabled_by_limit'] = False
        try:
            xray_add_uuid(client_uuid, c.get('name', ''))
        except Exception:
            pass
        audit('info', f'Авто-включение XRay после сброса трафика: {c.get("name")}')
        return True
    return False

@app.route('/api/xray/clients/<client_uuid>/traffic/reset', methods=['POST'])
@login_required
def xray_reset_traffic_now(client_uuid):
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    c = clients[client_uuid]
    email = _xray_unique_email(c.get('name', ''), c.get('uuid', ''))
    _reset_xray_traffic_for_email(email)
    today = time.strftime('%Y-%m-%d')
    c['traffic_last_reset'] = today
    _reenable_if_disabled_by_limit(client_uuid, c)
    save_xray_clients(clients)
    audit('info', f'Сброс трафика XRay (вручную): {c.get("name")}')
    return jsonify({'ok': True, 'reset_at': today})

@app.route('/api/xray/clients/<client_uuid>/traffic/limit', methods=['POST'])
@login_required
def xray_set_traffic_limit(client_uuid):
    data = request.json or {}
    raw = data.get('gb', None)
    if raw in (None, '', 0, '0'):
        gb = None
    else:
        try:
            gb = int(raw)
            if gb < 1:
                return jsonify({'error': 'gb must be >= 1'}), 400
        except Exception:
            return jsonify({'error': 'gb must be integer'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['traffic_limit_gb'] = gb
    save_xray_clients(clients)
    audit('info', f'Лимит трафика XRay {clients[client_uuid].get("name")}: {gb} GB' if gb else f'Лимит трафика XRay снят: {clients[client_uuid].get("name")}')
    return jsonify({'ok': True, 'traffic_limit_gb': gb})

@app.route('/api/xray/clients/<client_uuid>/traffic/reset-day', methods=['POST'])
@login_required
def xray_set_reset_day(client_uuid):
    data = request.json or {}
    raw = data.get('day', None)
    if raw in (None, '', 0, '0'):
        day = None
    else:
        try:
            day = int(raw)
            if day < 1 or day > 31:
                return jsonify({'error': 'day must be 1..31'}), 400
        except Exception:
            return jsonify({'error': 'day must be integer'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['traffic_reset_day'] = day
    save_xray_clients(clients)
    audit('info', f'Установлен день сброса трафика XRay {clients[client_uuid].get("name")}: {day}')
    return jsonify({'ok': True, 'traffic_reset_day': day})

def _run_xray_scheduler():
    """Apply due scheduled actions for XRay clients. Idempotent.
    Глобальное расписание (Global rules) использует ТОЛЬКО ежемесячный сброс трафика —
    он чистит все email-ы (и per-client счётчики тоже). Per-client расписания
    работают независимо."""
    today = time.strftime('%Y-%m-%d')

    # --- Глобальный ежемесячный сброс трафика XRay ---
    g_blob = load_xray_global()
    g_applied = _norm_global_fields(g_blob.get('applied'))
    g_rd = g_applied.get('traffic_reset_day')
    if g_rd and _is_traffic_reset_due(g_rd, today) and g_applied.get('traffic_last_reset') != today:
        try:
            persisted = {}
            try:
                live = xray_query_stats() or {}
            except Exception:
                live = {}
            if os.path.exists(XRAY_GLOBAL_TOTALS_DB):
                try:
                    with open(XRAY_GLOBAL_TOTALS_DB, 'r') as f:
                        d = json.load(f)
                    persisted = d.get('per_email') if isinstance(d, dict) else {}
                except Exception:
                    persisted = {}
            new_per_email = {}
            for em in set(list((persisted or {}).keys()) + list(live.keys())):
                cur = live.get(em) or {}
                new_per_email[em] = {
                    'up_seen': int(cur.get('up') or 0),
                    'down_seen': int(cur.get('down') or 0),
                    'up_total': 0, 'down_total': 0,
                }
            tmp = XRAY_GLOBAL_TOTALS_DB + '.tmp'
            with open(tmp, 'w') as f:
                json.dump({'ts': time.strftime('%Y-%m-%d %H:%M'), 'per_email': new_per_email}, f)
            os.replace(tmp, XRAY_GLOBAL_TOTALS_DB)
            g_applied['traffic_last_reset'] = today
            g_blob['applied'] = g_applied
            pending = _norm_global_fields(g_blob.get('pending'))
            pending['traffic_last_reset'] = today
            g_blob['pending'] = pending
            save_xray_global(g_blob)
            audit('info', f'Авто-сброс XRay Global (день {g_rd})')
        except Exception as _e:
            audit('warn', f'Ошибка глобального сброса трафика: {_e}')

    clients = load_xray_clients()
    changed = False
    to_delete = []
    hy_drop_emails = []   # кого убрать из работающего инбаунда Hysteria
    for uuid_k, c in list(clients.items()):
        # Per-client ежемесячный сброс трафика (с учётом коротких месяцев).
        rd = c.get('traffic_reset_day')
        if rd and _is_traffic_reset_due(rd, today) and c.get('traffic_last_reset') != today:
            email = _xray_unique_email(c.get('name', ''), c.get('uuid', ''))
            _reset_xray_traffic_for_email(email)
            c['traffic_last_reset'] = today
            _reenable_if_disabled_by_limit(uuid_k, c)
            changed = True
            audit('info', f'Авто-сброс трафика XRay (день {rd}): {c.get("name")}')
        sa = c.get('scheduled_action')
        sd = c.get('scheduled_at')
        if not sa or not sd or sd > today:
            continue
        if sa == 'delete':
            to_delete.append(uuid_k)
            hy_drop_emails.append(_xray_unique_email(c.get('name') or '', uuid_k))
            audit('info', f'Auto-delete (по расписанию) XRay: {c.get("name")}')
        elif sa == 'disable':
            if not c.get('disabled'):
                c['disabled'] = True
                try: xray_remove_uuid(uuid_k)
                except Exception: pass
                hy_drop_emails.append(_xray_unique_email(c.get('name') or '', uuid_k))
                audit('info', f'Auto-disable (по расписанию) XRay: {c.get("name")}')
            c['scheduled_action'] = None
            c['scheduled_at'] = None
            changed = True
    for uuid_k in to_delete:
        try: xray_remove_uuid(uuid_k)
        except Exception: pass
        clients.pop(uuid_k, None)
        changed = True
    if changed:
        save_xray_clients(clients)
        # Та же причина, что у лимита трафика: users Hysteria строятся из файла,
        # а он до этой строки ещё содержал клиента включённым (а удалённого —
        # существующим). Синхронизируем уже по записанному состоянию.
        _hy_sync()
        for _email in hy_drop_emails:
            _hy_apply_after_sync('remove', _email)

@app.route('/api/xray/clients/<client_uuid>/rename', methods=['POST'])
@login_required
def xray_rename_client(client_uuid):
    data = request.json or {}
    name = _normalize_client_name(data.get('name'))
    if not name:
        return jsonify({'error': 'Name required'}), 400

    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    if _client_name_taken(clients, name, skip_uuid=client_uuid):
        return jsonify({'error': f'Клиент с именем «{name}» уже есть — выберите другое имя'}), 409

    old_name = clients[client_uuid].get('name')
    clients[client_uuid]['name'] = name
    save_xray_clients(clients)
    try:
        xray_update_email(client_uuid, name)
    except Exception:
        pass  # name in panel is source of truth; xray email is best-effort
    if old_name != name:
        # deny-правила белого списка ссылаются на email — переклеиваем на новый.
        try:
            apply_allow_ip_rules()
        except Exception as e:
            audit('warn', f'Белый список IP после переименования не пересобран: {e}')
        audit('info', f'XRay client переименован: {old_name} → {name}')
    return jsonify({'ok': True})


# --- Rule list catalog endpoints ---


# === Path autodetect (что и где живёт на этом сервере) ===
def _run_capture(cmd, timeout=3):
    """Безопасный вызов shell-команды с захватом stdout. Возвращает строку или ''."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or '') + (r.stderr or '')
    except Exception:
        return ''

def _systemctl_cat(unit):
    """`systemctl cat` с запасом по времени.

    Команда ходит в PID 1 через D-Bus, и когда systemd занят (daemon-reload,
    рестарт соседнего сервиса, всплеск нагрузки) ответа можно ждать секунды.
    С общим таймаутом в 3 с вызов изредка обрывался, возвращал пустую строку —
    и проверка читала это как «не настроено», хотя на диске всё на месте.
    Отсюда были самоисчезающие NOT OK в «Зависимостях»."""
    return _run_capture(['systemctl', 'cat', '--no-pager', unit], timeout=10)

def _systemd_exec_start(unit):
    """Возвращает ExecStart= из юнита (или его drop-in'ов)."""
    out = _systemctl_cat(unit)
    if not out:
        return ''
    last = ''
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('ExecStart='):
            last = line[len('ExecStart='):].strip()
    # strip leading + - @ @+
    return re.sub(r'^[\+\-@!:]+\s*', '', last)

# Поиск юнитов XRay и mtg зовут проверки портов, «Зависимости», блок версий и
# модули — на каждом запросе и по нескольку раз. Каждый раз это `systemctl cat`,
# а у mtg ещё и `list-unit-files`, при котором PID 1 перечитывает все юнит-файлы.
# На слабой машине systemd от этого не вылезал из 100% CPU, и любой `systemctl`
# в панели (is-active, restart) ждал очереди секундами — кнопки висели. Ответ
# зависит только от файлов на диске, поэтому кешируем по их отпечатку: правка
# юнита, drop-in'а или конфига XRay сбрасывает кеш сразу, TTL — страховка.
_UNIT_DIRS = ('/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system')
_UNIT_PATHS_CACHE = {}
_UNIT_PATHS_LOCKS = {'xray': threading.Lock(), 'mtg': threading.Lock()}

def _stat_sig(path):
    try:
        st = os.stat(path)
        return (path, st.st_mtime_ns, st.st_size)
    except OSError:
        return (path, None)

def _unit_files_sig(prefix):
    """Отпечаток юнит-файлов с именем на prefix и их drop-in'ов. mtime самих
    каталогов ловит появление и удаление юнитов."""
    sig = []
    for d in _UNIT_DIRS:
        sig.append(_stat_sig(d))
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            if not name.startswith(prefix):
                continue
            p = os.path.join(d, name)
            sig.append(_stat_sig(p))
            if name.endswith('.d') and os.path.isdir(p):
                try:
                    for fn in sorted(os.listdir(p)):
                        sig.append(_stat_sig(os.path.join(p, fn)))
                except OSError:
                    pass
    return tuple(sig)

def _unit_paths_memo(key, compute, extra=None):
    """compute(), пока не изменились юнит-файлы key* (и то, что вернёт
    extra(результат)). Под замком: четыре потока gunicorn, пришедшие разом,
    не должны вчетвером идти в systemd — один считает, остальные берут кеш.
    «Не найдено» живёт меньше: это бывает и таймаут занятого systemd."""
    with _UNIT_PATHS_LOCKS[key]:
        sig = _unit_files_sig(key)
        ent = _UNIT_PATHS_CACHE.get(key)
        if (ent and ent['sig'] == sig and time.time() < ent['until']
                and ent['extra'] == (extra(ent['res']) if extra else None)):
            return dict(ent['res'])
        res = compute()
        _UNIT_PATHS_CACHE[key] = {
            'sig': sig, 'res': dict(res),
            'extra': extra(res) if extra else None,
            'until': time.time() + (60 if res.get('installed') else 10),
        }
        return res

def _find_xray_paths():
    # access_log и stats_ok читаются из config.json — его правка тоже сбрасывает кеш.
    return _unit_paths_memo('xray', _find_xray_paths_live,
                            extra=lambda r: _stat_sig(r['config']) if r.get('config') else None)

def _find_xray_paths_live():
    for unit in ('xray.service', 'xray'):
        es = _systemd_exec_start(unit)
        if not es:
            continue
        m = re.search(r'-c(?:onfig)?\s+(\S+)', es)
        cfg = m.group(1) if m else ''
        # Достаём log.access и наличие stats-секций из реального конфига xray.
        access_log = ''
        stats_ok = False
        if cfg and os.path.exists(cfg):
            try:
                with open(cfg, 'r') as f:
                    j = json.load(f)
                access_log = (j.get('log') or {}).get('access') or ''
                # stats настроен, если reconcile на копии ничего бы не поменял.
                stats_ok = not _reconcile_stats_cfg(json.loads(json.dumps(j)))
            except Exception:
                pass
        return {'unit': unit.replace('.service', ''), 'config': cfg,
                'access_log': access_log, 'stats_ok': stats_ok, 'installed': True}
    return {'unit': '', 'config': '', 'access_log': '', 'stats_ok': False, 'installed': False}


def _find_awg_paths():
    # Найти бинарь awg (может быть /usr/bin/awg, /usr/local/bin/awg, /usr/sbin/awg)
    awg_bin = ''
    for p in (AWG_BIN, '/usr/bin/awg', '/usr/local/bin/awg', '/usr/sbin/awg'):
        if os.path.exists(p):
            awg_bin = p
            break
    if not awg_bin:
        return {'iface': '', 'config': '', 'bin': '', 'installed': False}
    iface = ''
    out = _run_capture([awg_bin, 'show', 'interfaces'])
    if out.strip():
        iface = out.strip().split('\n')[0].split()[0]
    if not iface:
        out2 = _run_capture([awg_bin, 'show'])
        m = re.search(r'^interface:\s*(\S+)', out2, re.M)
        if m:
            iface = m.group(1)
    cfg = ''
    if iface:
        for p in (f'/etc/amnezia/amneziawg/{iface}.conf', f'/etc/wireguard/{iface}.conf'):
            if os.path.exists(p):
                cfg = p
                break
    return {'iface': iface, 'config': cfg, 'bin': awg_bin, 'installed': True}

def _hysteria_paths_blob():
    """Все пути пакета Hysteria одним словарём. Пустой — если пакет не подключён.

    Собирается здесь, а не в самом пакете: «Системные пути» — реестр панели, и
    источник значений у всех протоколов должен быть один.
    """
    try:
        from modules.hysteria import (PKG_DIR, DATA_DIR as D, LOGS_DIR, SETTINGS_FILE,
                                      CLIENTS_FILE, CONFIG_FILE, CERT_FILE, KEY_FILE,
                                      TOTALS_FILE, LASTSEEN_FILE, AUTH_SCRIPT, ACCESS_LOG,
                                      GLOBAL_FILE, ACL_FILE, BIN_PATH, UNIT_NAME, UNIT_FILE)
        from modules.hysteria import service as hy_service
    except Exception:
        return {}
    return {
        'installed': hy_service.bin_installed(),
        'pkg_dir': PKG_DIR, 'data_dir': D, 'logs_dir': LOGS_DIR,
        'settings': SETTINGS_FILE, 'clients': CLIENTS_FILE, 'config': CONFIG_FILE,
        'cert': CERT_FILE, 'key': KEY_FILE, 'totals': TOTALS_FILE, 'lastseen': LASTSEEN_FILE,
        'auth': AUTH_SCRIPT, 'access_log': ACCESS_LOG, 'global': GLOBAL_FILE, 'acl': ACL_FILE,
        'bin': BIN_PATH, 'unit_name': UNIT_NAME, 'unit_file': UNIT_FILE,
    }


def _discover_paths_detailed():
    """Возвращает структуру для UI: список словарей с key/label/description/value/default/exists/source."""
    panel_root = os.path.dirname(os.path.abspath(__file__))
    xray = _find_xray_paths()
    mtg = _find_mtg_paths()
    awg = _find_awg_paths()
    hy = _hysteria_paths_blob()

    def _proto_of(key):
        """Вкладка окна «Системные пути». Раскладка по протоколам — та же, что в
        «Зависимостях»: длинный сплошной список читать невозможно."""
        for prefix, proto in (('hy_', 'hysteria'), ('xray_', 'xray'), ('tgweb_', 'tgweb'),
                              ('mtg_', 'mtg'), ('awg_', 'awg')):
            if key.startswith(prefix):
                return proto
        return {'clients_db': 'awg'}.get(key, 'panel')

    def item(key, label, description, value, default, source, is_dir=False, not_installed=False, is_name=False, group='Другое', proto=None):
        if not value:
            exists = False
        elif is_name:
            # value — имя (systemd-юнит, интерфейс), не файл/папка
            exists = True
        elif is_dir:
            exists = os.path.isdir(value)
        else:
            exists = os.path.exists(value)
        return {
            'key': key,
            'label': label,
            'description': description,
            'value': value or '',
            'default': default,
            'is_default': (value == default) if value else None,
            'exists': exists,
            'source': source,
            'not_installed': not_installed,
            'is_name': is_name,
            'group': group,
            'proto': proto or _proto_of(key),
        }

    awg_ni = not awg.get('installed')
    xray_ni = not xray.get('installed')
    mtg_ni = not mtg.get('installed')

    items = []
    # =========================================================================
    # Группа: Код панели
    # Файлы и папки, которые обновляются при апдейте и составляют саму панель.
    # =========================================================================
    G_CODE = 'Код панели'
    items.append(item(
        'panel_root', 'Корень панели',
        'Папка, где лежит app.py и вся внутренняя структура. От неё отсчитываются все остальные пути панели.',
        panel_root, '/opt/awg-panel', 'os.path.dirname(__file__)', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_app_py', 'app.py',
        'Главный модуль панели — Flask-приложение, генератор клиентских конфигов, API.',
        os.path.join(panel_root, 'app.py'), '/opt/awg-panel/app.py', 'panel_root + /app.py', group=G_CODE))
    items.append(item(
        'panel_modules_dir', 'modules/',
        'Код панели, разнесённый по доменам (профили, правила, mihomo, mtg, бэкап/обновление и т.д.). '
        'Python-пакет, импортируется из app.py; роуты подключаются как Blueprint. Обновляется целиком при апдейте.',
        os.path.join(panel_root, 'modules'), '/opt/awg-panel/modules', 'panel_root + /modules', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_static_dir', 'static/',
        'Статика панели — index.html, app.js, logs.html, mtg_logs.html. Отдаётся Flask на корне и /sub/.',
        os.path.join(panel_root, 'static'), '/opt/awg-panel/static', 'panel_root + /static', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_static_index', 'static/index.html',
        'Главный SPA панели — разметка + CSS. Весь JS вынесен в static/app.js.',
        os.path.join(panel_root, 'static', 'index.html'), '/opt/awg-panel/static/index.html', 'panel_root + /static/index.html', group=G_CODE))
    items.append(item(
        'panel_static_appjs', 'static/app.js',
        'Клиентский JS панели: логин, рендер карточек, модалки, обновление, бэкап. Подключается из index.html.',
        os.path.join(panel_root, 'static', 'app.js'), '/opt/awg-panel/static/app.js', 'panel_root + /static/app.js', group=G_CODE))
    items.append(item(
        'panel_static_logs', 'static/logs.html',
        'Просмотрщик access-логов XRay и AWG (страница «Логи»).',
        os.path.join(panel_root, 'static', 'logs.html'), '/opt/awg-panel/static/logs.html', 'panel_root + /static/logs.html', group=G_CODE))
    items.append(item(
        'panel_static_mtg_logs', 'static/mtg_logs.html',
        'Просмотрщик access-логов mtg (Telegram-прокси).',
        os.path.join(panel_root, 'static', 'mtg_logs.html'), '/opt/awg-panel/static/mtg_logs.html', 'panel_root + /static/mtg_logs.html', group=G_CODE))
    if hy:
        items.append(item(
            'hy_pkg_dir', 'modules/hysteria/',
            'Пакет протокола Hysteria 2: весь его код изолирован здесь и подключается к панели пятью '
            'защищёнными строками. Если каталога нет — панель поднимется без Hysteria, остальное работает.',
            hy['pkg_dir'], '/opt/awg-panel/modules/hysteria', 'panel_root + /modules/hysteria',
            is_dir=True, group=G_CODE))
        items.append(item(
            'hy_static_dir', 'modules/hysteria/static/',
            'Свои JS и CSS вкладки Hysteria. Отдаются отдельным маршрутом пакета, в static/ панели их нет.',
            os.path.join(hy['pkg_dir'], 'static'), '/opt/awg-panel/modules/hysteria/static',
            'hysteria.STATIC_DIR', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_public_dir', 'public/',
        'Содержимое маскировочного сайта (фейк-лендинг). Отдаётся вместо панели на корне, если тумблер маскировки включён.',
        PUBLIC_DIR, '/opt/awg-panel/public', 'panel_root + /public', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_venv_dir', 'venv/',
        'Python venv панели — Flask, gunicorn, maxminddb. В бэкап НЕ попадает (восстанавливается заново).',
        os.path.join(panel_root, 'venv'), '/opt/awg-panel/venv', 'panel_root + /venv', is_dir=True, group=G_CODE))
    items.append(item(
        'panel_manifest', 'manifest.json',
        'Манифест с версией панели и списком файлов, которые подтягиваются с CDN при обновлении.',
        os.path.join(panel_root, 'manifest.json'), '/opt/awg-panel/manifest.json', 'panel_root + /manifest.json', group=G_CODE))
    items.append(item(
        'panel_favicon', 'fox.ico',
        'Иконка панели (favicon). Можно переопределить через public/favicon.ico при включённой маскировке.',
        os.path.join(panel_root, 'fox.ico'), '/opt/awg-panel/fox.ico', 'panel_root + /fox.ico', group=G_CODE))

    # =========================================================================
    # Группа: Данные панели (создаёт/правит сама панель)
    # Хеши, токены, конфиги настроек, базы клиентов и правил.
    # =========================================================================
    G_DATA = 'Данные панели'
    items.append(item(
        'server_config', 'data/server.json',
        'Настройки сервера: имя, SNI, server_ip_override, расписания, избранное настроек. НЕ обновляется при апдейте панели.',
        SERVER_CONFIG_FILE, '/opt/awg-panel/data/server.json', 'DATA_DIR + /server.json', group=G_DATA))
    items.append(item(
        'admin_file', 'data/admin.json',
        'Хеш пароля админа панели (sha256). Без этого файла войти в панель невозможно.',
        ADMIN_FILE, '/opt/awg-panel/data/admin.json', 'DATA_DIR + /admin.json', group=G_DATA))
    items.append(item(
        'secret_key_file', 'data/secret.key',
        'Flask session key для подписи cookies. Если файла нет — сессии всех залогиненных пользователей слетают при рестарте процесса. Путь зашит и в юнит автобэкапа — панель перепрописывает его сама.',
        SECRET_KEY_FILE, '/opt/awg-panel/data/secret.key', 'DATA_DIR + /secret.key', group=G_DATA))
    items.append(item(
        'clients_db', 'data/awg/clients.json',
        'База клиентов AmneziaWG: имена, ключи, IP-адреса, расписания, дисейблы.',
        CLIENTS_DB if awg.get('installed') else '', '/opt/awg-panel/data/awg/clients.json', 'DATA_AWG_DIR + /clients.json',
        not_installed=awg_ni, group=G_DATA))
    items.append(item(
        'xray_clients_db', 'data/xray/clients.json',
        'База клиентов XRay (VLESS+TLS+Vision): UUID, имена, лимиты, привязки к правилам.',
        XRAY_CLIENTS_DB if xray.get('installed') else '', '/opt/awg-panel/data/xray/clients.json', 'DATA_XRAY_DIR + /clients.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'xray_rule_lists_db', 'data/xray/rule_lists.json',
        'Каталог правил маршрутизации (Surge / Loon / Clash). Используется в редакторе правил XRay-клиентов.',
        XRAY_RULE_LISTS_DB if xray.get('installed') else '', '/opt/awg-panel/data/xray/rule_lists.json', 'DATA_XRAY_DIR + /rule_lists.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'blackmatrix7_templates', 'data/geo_rules/blackmatrix7_templates.json',
        'Кэш библиотеки шаблонов blackmatrix7 (имена-папки для кнопки «Шаблоны»). Раз в 7 дней тянется с byfox.dev и тихо перезаписывается. На списки правил пользователя не влияет — дата в server.json (bm7_version).',
        BM7_TEMPLATES_FILE if xray.get('installed') else '', '/opt/awg-panel/data/geo_rules/blackmatrix7_templates.json', 'DATA_GEO_DIR + /blackmatrix7_templates.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'byfox_rules', 'data/geo_rules/byfox_rules.json',
        'Кэш своих шаблонов правил с byfox.dev (перечень папок для кнопки «Шаблоны» + инлайн QUIC-fix правила block_ads_trackers_quic). Обновляется в один период с blackmatrix7.',
        BYFOX_RULES_FILE if xray.get('installed') else '', '/opt/awg-panel/data/geo_rules/byfox_rules.json', 'DATA_GEO_DIR + /byfox_rules.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'xray_global_db', 'data/xray/global.json',
        'Глобальные правила XRay: серверная маршрутизация всех VLESS-клиентов с pending/applied состоянием.',
        XRAY_GLOBAL_DB if xray.get('installed') else '', '/opt/awg-panel/data/xray/global.json', 'DATA_XRAY_DIR + /global.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'xray_global_cache_db', 'data/xray/global_cache.json',
        'Кеш скачанных рул-листов для Global Rules (обновляется по cron раз в сутки).',
        XRAY_GLOBAL_CACHE_DB if xray.get('installed') else '', '/opt/awg-panel/data/xray/global_cache.json', 'DATA_XRAY_DIR + /global_cache.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'xray_global_totals_db', 'data/xray/global_totals.json',
        'Накопительный счётчик трафика per-email. Переживает рестарт xray (он сам сбрасывает счётчики).',
        XRAY_GLOBAL_TOTALS_DB if xray.get('installed') else '', '/opt/awg-panel/data/xray/global_totals.json', 'DATA_XRAY_DIR + /global_totals.json',
        not_installed=xray_ni, group=G_DATA))
    items.append(item(
        'mtg_recipients_db', 'data/mtproto/recipients.json',
        'Список получателей MTProto-прокси (кому выдана ссылка). Раньше лежал внутри server.json — переносится автоматически при первом обращении.',
        MTG_RECIPIENTS_DB if mtg.get('installed') else '', '/opt/awg-panel/data/mtproto/recipients.json', 'DATA_MTPROTO_DIR + /recipients.json',
        not_installed=mtg_ni, group=G_DATA))
    # Hysteria: пакет изолирован, поэтому и путей у него свой набор. Показываем
    # их всегда, когда пакет подключён, — иначе вкладка «Hysteria» пустая, и
    # непонятно, где вообще лежат его клиенты и настройки.
    if hy:
        items.append(item(
            'hy_data_dir', 'data/hysteria/',
            'Всё пользовательское по Hysteria: настройки, клиенты, сертификат, счётчики. '
            'Обновление панели этот каталог не трогает, в бэкап он попадает вместе с остальным data/.',
            hy['data_dir'], '/opt/awg-panel/data/hysteria', 'константа hysteria.DATA_DIR',
            is_dir=True, group=G_DATA))
        items.append(item(
            'hy_clients_db', 'data/hysteria/clients.json',
            'База клиентов Hysteria: id, пароли, лимиты, правила, расписания.',
            hy['clients'], '/opt/awg-panel/data/hysteria/clients.json', 'константа hysteria.CLIENTS_FILE',
            group=G_DATA))
        items.append(item(
            'hy_settings_db', 'data/hysteria/settings.json',
            'Настройки протокола: порт, маскировка, обфускация, лимиты полосы, режим сертификата. '
            'Из этого файла целиком генерируется config.yaml.',
            hy['settings'], '/opt/awg-panel/data/hysteria/settings.json', 'константа hysteria.SETTINGS_FILE',
            group=G_DATA))
        items.append(item(
            'hy_global_db', 'data/hysteria/global.json',
            'Глобальные серверные правила Hysteria (pending/applied). Список доступа у неё один на сервер: '
            'в момент маршрутизации пользователь уже неизвестен, персональных правил на сервере быть не может.',
            hy['global'], '/opt/awg-panel/data/hysteria/global.json', 'константа hysteria.GLOBAL_FILE',
            group=G_DATA))
        items.append(item(
            'hy_totals_db', 'data/hysteria/totals.json',
            'Накопительный счётчик трафика. Переживает рестарт hysteria — она сама обнуляет счётчики.',
            hy['totals'], '/opt/awg-panel/data/hysteria/totals.json', 'константа hysteria.TOTALS_FILE',
            group=G_DATA))
        items.append(item(
            'hy_lastseen_db', 'data/hysteria/lastseen.json',
            'Последний IP и время входа каждого клиента. Отдельным файлом, чтобы не переписывать '
            'clients.json на каждое подключение — его пишет скрипт авторизации.',
            hy['lastseen'], '/opt/awg-panel/data/hysteria/lastseen.json', 'константа hysteria.LASTSEEN_FILE',
            group=G_DATA))
    items.append(item(
        'audit_log', 'data/logs/audit.log',
        'Журнал действий админа в панели (логины, изменения, рестарты). Своя ротация 1 МБ × 5, поэтому общий logrotate до него не доходит.',
        AUDIT_LOG_FILE, '/opt/awg-panel/data/logs/audit.log', 'DATA_LOGS_DIR + /audit.log', group=G_DATA))

    # =========================================================================
    # Группа: Логи доступа (history of connections)
    # =========================================================================
    G_LOGS = 'Логи доступа'
    items.append(item(
        'panel_logs_dir', 'Папка логов',
        'Куда панель и протоколы пишут access-логи. Должна быть root:root 755 (у xray нет CAP_DAC_OVERRIDE).',
        PANEL_LOGS_DIR, '/opt/awg-panel/data/logs', 'константа PANEL_LOGS_DIR', is_dir=True, group=G_LOGS))
    items.append(item(
        'awg_access_log', 'awg_access.log',
        'JSON-line файл со снимками `awg show`, собирается фоновым потоком панели каждые 30 секунд.',
        AWG_ACCESS_LOG if awg.get('installed') else '', '/opt/awg-panel/data/logs/awg_access.log', 'константа AWG_ACCESS_LOG',
        not_installed=awg_ni, group=G_LOGS))
    items.append(item(
        'xray_access_log', 'xray_access.log',
        'Лог подключений XRay: timestamp, src IP, домен назначения, email клиента. Читается из xray config → log.access.',
        xray.get('access_log', ''), XRAY_ACCESS_LOG, 'xray config → log.access',
        not_installed=xray_ni, group=G_LOGS))
    items.append(item(
        'mtg_access_log', 'mtg_access.log',
        'Лог подключений mtg. Захватывается через systemd drop-in (StandardOutput=append:<path>).',
        mtg.get('access_log', ''), MTG_ACCESS_LOG, 'systemctl cat → StandardOutput',
        not_installed=mtg_ni, group=G_LOGS))

    if hy:
        items.append(item(
            'hy_access_log', 'hysteria_access.log',
            'Лог Hysteria: подключения всегда, адреса назначения — только когда включён тумблер «Логи» '
            '(hysteria пишет их лишь на уровне debug). Юнит перенаправляет сюда stdout и stderr.',
            hy['access_log'], '/opt/awg-panel/data/logs/hysteria_access.log', 'константа hysteria.ACCESS_LOG',
            group=G_LOGS))

    # =========================================================================
    # Группа: Бэкапы
    # =========================================================================
    G_BACKUP = 'Бэкапы'
    items.append(item(
        'panel_backup_dir', 'Папка бэкапов',
        'Куда панель кладёт архивы .tar.gz при автоматическом или ручном бэкапе.',
        BACKUP_DIR, '/opt/awg-panel/data/backup', 'panel_root + /data/backup', is_dir=True, group=G_BACKUP))

    # =========================================================================
    # Группа: Geo-базы
    # =========================================================================
    G_GEO = 'Geo-базы'
    items.append(item(
        'panel_data_dir', 'data-папка панели',
        'Корень для всего пользовательского: настройки, клиенты, логи, бэкапы, гео. Апдейт панели её не трогает — только эти файлы и переживают обновление.',
        DATA_DIR, '/opt/awg-panel/data', 'panel_root + /data', is_dir=True, group=G_GEO))
    items.append(item(
        'geo_rules_dir', 'data/geo_rules/',
        'Гео-базы MaxMind, диапазоны стран и кэши источников правил (blackmatrix7, byfox).',
        DATA_GEO_DIR, '/opt/awg-panel/data/geo_rules', 'DATA_DIR + /geo_rules', is_dir=True, group=G_GEO))
    items.append(item(
        'geo_city_db', 'data/geo_rules/GeoLite2-City.mmdb',
        'База IP → город/страна. Подтягивается с CDN byfox.dev.',
        GEO_DB, '/opt/awg-panel/data/geo_rules/GeoLite2-City.mmdb', 'константа GEO_DB', group=G_GEO))
    items.append(item(
        'geo_asn_db', 'data/geo_rules/GeoLite2-ASN.mmdb',
        'База IP → провайдер (ASN). Используется в логах рядом со страной.',
        ASN_DB, '/opt/awg-panel/data/geo_rules/GeoLite2-ASN.mmdb', 'константа ASN_DB', group=G_GEO))
    items.append(item(
        'panel_manifest_geo', 'server.json → geo_version',
        'Метка версии установленных geo-баз (дата YYYYMMDD в поле geo_version в server.json). Сравнивается с remote-версией на CDN byfox.dev для решения «обновлять ли» (период geo_check_interval_days, дефолт 180).',
        SERVER_CONFIG_FILE, '/opt/awg-panel/data/server.json', 'константа SERVER_CONFIG_FILE', group=G_GEO))

    # =========================================================================
    # Группа: Внешние конфиги сервисов
    # =========================================================================
    G_EXT = 'Внешние конфиги сервисов'
    items.append(item(
        'awg_config', 'Конфиг AmneziaWG',
        'Файл интерфейса AWG со списком peers и обф-параметрами. У Amnezia-установок — /etc/amnezia/amneziawg/<iface>.conf, у ручных — /etc/wireguard/<iface>.conf.',
        awg['config'], '/etc/amnezia/amneziawg/awg0.conf', 'путь от имени интерфейса',
        not_installed=awg_ni, group=G_EXT))
    items.append(item(
        'xray_config', 'Конфиг XRay',
        'Файл, который читает XRay при старте. Сюда панель прописывает inbound для каждого клиента и Global Rules.',
        xray['config'], '/usr/local/etc/xray/config.json', 'ExecStart -c <path>',
        not_installed=xray_ni, group=G_EXT))
    # Сертификат Hysteria-инбаунда появляется лишь на серверах без Let's Encrypt
    # (Reality): там панель выпускает самоподписанный и пиннит его в ссылках.
    if xhy:
        _hy_cert, _hy_key = xhy.self_cert_paths()
        if os.path.isfile(_hy_cert):
            items.append(item(
                'xray_hy_cert', 'Сертификат Hysteria-инбаунда',
                "Самоподписанный сертификат для QUIC на серверах без Let's Encrypt. Его отпечаток "
                'уходит клиентам в ссылке (pinSHA256), поэтому перевыпуск сломает все выданные ссылки.',
                _hy_cert, os.path.join(DATA_XRAY_DIR, 'hysteria-self-cert.pem'),
                'xray_hysteria.SELF_CERT_NAME', group=G_DATA))
            items.append(item(
                'xray_hy_key', 'Ключ сертификата Hysteria',
                'Приватный ключ к сертификату выше, читается только ядром XRay.',
                _hy_key, os.path.join(DATA_XRAY_DIR, 'hysteria-self-key.pem'),
                'xray_hysteria.SELF_KEY_NAME', group=G_DATA))
    # Появляется, только если для XDNS нажали «Отвязать dnsmasq»: dnsmasq держал
    # 0.0.0.0:53, и вход XRay не мог занять 53-й на внешнем адресе.
    if xdns and os.path.isfile(xdns.DNSMASQ_FIX_FILE):
        items.append(item(
            'xdns_dnsmasq_fix', 'dnsmasq: освобождение 53/udp для XDNS',
            'bind-interfaces + except-interface внешнего интерфейса: dnsmasq обслуживает локальные '
            'адреса и awg0, а внешний :53 оставляет XDNS. Удалите файл и перезапустите dnsmasq, '
            'чтобы вернуть как было (XDNS тогда не поднимется).',
            xdns.DNSMASQ_FIX_FILE, '/etc/dnsmasq.d/00-awg-panel-xdns.conf',
            'xray_xdns.DNSMASQ_FIX_FILE', group=G_EXT))
    items.append(item(
        'mtg_config', 'Конфиг mtg',
        'TOML-конфиг mtg: secret (с зашитой маской), bind-to, debug.',
        mtg['config'], '/etc/mtg/config.toml', 'ExecStart args',
        not_installed=mtg_ni, group=G_EXT))
    items.append(item(
        'mtg_drop_in', 'systemd drop-in mtg',
        'Override юнита mtg — перенаправляет stdout/stderr в access-log. Без этого drop-in логов mtg не будет.',
        mtg.get('drop_in', ''), '/etc/systemd/system/mtg.service.d/logfile.conf', 'скан .service.d/',
        not_installed=mtg_ni, group=G_EXT))
    if hy:
        items.append(item(
            'hy_config', 'Конфиг Hysteria',
            'config.yaml, который читает hysteria-server при старте. Генерируется панелью целиком из '
            'settings.json и глобальных правил — ручные правки перезаписываются при первом «Сохранить».',
            hy['config'], '/opt/awg-panel/data/hysteria/config.yaml', 'ExecStart -c <path>',
            group=G_EXT))
        items.append(item(
            'hy_acl', 'ACL Hysteria',
            'Список доступа глобальных правил. Файла нет, когда Global rules выключены — это норма.',
            hy['acl'], '/opt/awg-panel/data/hysteria/acl.txt', 'константа hysteria.ACL_FILE',
            group=G_EXT))
        items.append(item(
            'hy_cert', 'Сертификат Hysteria',
            'Сертификат TLS для QUIC. Самоподписанный — свой у протокола, чтобы не зависеть от режима XRay; '
            'клиент сверяет его отпечаток (pinSHA256), поэтому перевыпуск ломает все выданные ссылки.',
            hy['cert'], '/opt/awg-panel/data/hysteria/cert.pem', 'tls.cert в config.yaml',
            group=G_EXT))
        items.append(item(
            'hy_key', 'Ключ сертификата Hysteria',
            'Приватный ключ к сертификату выше. Читается только процессом hysteria.',
            hy['key'], '/opt/awg-panel/data/hysteria/key.pem', 'tls.key в config.yaml',
            group=G_EXT))
    items.append(item(
        'logrotate_config', 'Конфиг logrotate',
        'Правило ротации всех логов панели — 10 файлов по 100MB, copytruncate. Стандартное место logrotate.d.',
        '/etc/logrotate.d/awg-panel', '/etc/logrotate.d/awg-panel', 'стандарт logrotate.d', group=G_EXT))

    # =========================================================================
    # Группа: Бинари и systemd-юниты
    # =========================================================================
    G_BIN = 'Бинари и юниты'
    items.append(item(
        'awg_bin', 'Бинарь awg',
        'Исполняемый файл `awg` — без него протокол AmneziaWG не работает.',
        awg.get('bin', ''), '/usr/bin/awg', 'поиск по стандартным путям',
        not_installed=awg_ni, group=G_BIN))
    items.append(item(
        'awg_iface', 'Интерфейс AWG',
        'Имя сетевого интерфейса AmneziaWG. Определяется через `awg show interfaces`.',
        awg['iface'], 'awg0', 'awg show interfaces',
        not_installed=awg_ni, is_name=True, group=G_BIN))
    items.append(item(
        'xray_unit', 'systemd-юнит XRay',
        'Имя systemd-сервиса XRay. Найдено через `systemctl list-unit-files`.',
        xray['unit'], 'xray', 'systemctl cat',
        not_installed=xray_ni, is_name=True, group=G_BIN))
    items.append(item(
        'mtg_unit', 'systemd-юнит mtg',
        'Имя systemd-сервиса mtg. На разных серверах может быть mtg, mtg-8443 и т.п.',
        mtg['unit'], 'mtg', 'systemctl list-unit-files',
        not_installed=mtg_ni, is_name=True, group=G_BIN))
    if hy:
        items.append(item(
            'hy_bin', 'Бинарь hysteria',
            'Исполняемый файл сервера Hysteria 2. Скачивается панелью с GitHub под архитектуру сервера.',
            hy['bin'], '/usr/local/bin/hysteria', 'константа hysteria.BIN_PATH', group=G_BIN))
        items.append(item(
            'hy_unit_file', 'Юнит-файл Hysteria',
            'Файл systemd-юнита. Панель пишет его сама: уровень логирования задаётся здесь переменной '
            'окружения, в config.yaml такого ключа у hysteria нет.',
            hy['unit_file'], '/etc/systemd/system/hysteria-server.service', 'константа hysteria.UNIT_FILE',
            group=G_BIN))
        items.append(item(
            'hy_unit', 'systemd-юнит Hysteria',
            'Имя сервиса. Одно на все установки — юнит создаёт сама панель.',
            hy['unit_name'], 'hysteria-server', 'константа hysteria.UNIT_NAME',
            is_name=True, group=G_BIN))
        items.append(item(
            'hy_auth_script', 'Скрипт авторизации Hysteria',
            'hysteria зовёт его на каждое подключение и по коду возврата решает, пускать ли клиента. '
            'Так пароли меняются без перезапуска сервиса.',
            hy['auth'], '/opt/awg-panel/modules/hysteria/auth.py', 'auth.command в config.yaml',
            group=G_BIN))
    items.extend(_tgweb_path_items(item, G_CODE, G_DATA, G_LOGS, G_EXT, G_BIN))

    return items


def _tgweb_path_items(item, G_CODE, G_DATA, G_LOGS, G_EXT, G_BIN):
    """Пути Telegram WEB для «Системных путей». Ключи с префиксом tgweb_ —
    по нему пункт попадает на свою вкладку окна."""
    if not globals().get('tgweb_pkg'):
        return []
    try:
        import modules.tgweb as tg
        from modules.tgweb import nginx as tg_ng
        from modules.tgweb import service as tg_svc
    except Exception:
        return []
    ni = not tg_svc.bin_installed()
    site = tg_ng._site_paths()[0]
    return [
        item('tgweb_pkg_dir', 'modules/tgweb/',
             'Код Telegram WEB-прокси: установка, конфиг telemt, клиенты, проверки цепочки.',
             tg.PKG_DIR, '/opt/awg-panel/modules/tgweb', 'panel_root + /modules/tgweb',
             is_dir=True, group=G_CODE),
        item('tgweb_data_dir', 'data/tgweb/',
             'Клиенты, настройки цепочки (префикс, внутренние порты, ключ API), накопленный трафик и '
             'история IP. Источник, из которого панель генерирует config.toml.',
             tg.DATA_DIR, '/opt/awg-panel/data/tgweb', 'константа tgweb.DATA_DIR',
             is_dir=True, group=G_DATA),
        item('tgweb_clients_db', 'data/tgweb/clients.json',
             'Клиенты WEB-прокси: имя, секрет (он же ссылка), лимиты, фильтр IP, расписание.',
             tg.CLIENTS_FILE, '/opt/awg-panel/data/tgweb/clients.json', 'константа tgweb.CLIENTS_FILE',
             group=G_DATA),
        item('tgweb_totals_db', 'data/tgweb/totals.json',
             'Накопительный трафик клиентов. telemt считает его только в памяти — без этого файла '
             'каждый рестарт обнулял бы счётчики.',
             tg.TOTALS_FILE, '/opt/awg-panel/data/tgweb/totals.json', 'константа tgweb.TOTALS_FILE',
             group=G_DATA),
        item('tgweb_access_log', 'tgweb_access.log',
             'Вывод telemt (юнит перенаправляет сюда stdout и stderr). Причина падения сервиса — здесь.',
             tg.ACCESS_LOG, '/opt/awg-panel/data/logs/tgweb_access.log', 'константа tgweb.ACCESS_LOG',
             not_installed=ni, group=G_LOGS),
        item('tgweb_config', 'telemt config.toml',
             'Конфиг telemt. Генерируется панелью целиком из data/tgweb — ручные правки перезапишутся.',
             tg.CONFIG_FILE, '/etc/telemt/config.toml', 'ExecStart <config>', not_installed=ni, group=G_EXT),
        item('tgweb_nginx_site', 'Блок nginx WEB-прокси',
             'Общий фоллбек XRay: префикс WEB-прокси → telemt, остальное → сайт и панель. Только 127.0.0.1, '
             'без журнала запросов.',
             site, '/etc/nginx/sites-available/awg-panel-tgweb', 'константа tgweb.NGINX_AVAILABLE',
             not_installed=ni, group=G_EXT),
        item('tgweb_bin', 'Бинарь telemt',
             'Движок WEB-прокси. Панель скачивает musl-сборку с GitHub под архитектуру сервера и обновляет '
             'с пробным запуском и откатом.',
             tg.BIN_PATH, '/usr/local/bin/telemt', 'константа tgweb.BIN_PATH', not_installed=ni, group=G_BIN),
        item('tgweb_unit_file', 'Юнит-файл telemt',
             'Файл systemd-юнита. Пишет панель: путь к конфигу, каталог состояния, вывод в лог панели.',
             tg.UNIT_FILE, '/etc/systemd/system/telemt.service', 'константа tgweb.UNIT_FILE',
             not_installed=ni, group=G_BIN),
    ]

@app.route('/api/system/paths', methods=['GET'])
@login_required
def system_paths_get():
    return jsonify({'items': _discover_paths_detailed()})

# === Dependency checks (icon-warn в шапке) ===
def _system_check_dependencies(groups=None):
    """Список проверок: каждая возвращает {id, name, ok, fix_cmd, fixable, requires_restart}.

    Перед формированием списка вызывается авто-детект путей — проверки и команды
    подставляются под реальное состояние сервера (имя mtg-юнита, путь xray config и т.д.).
    Проверки для непротоколов которые не установлены — пропускаются.
    """
    panel_root = os.path.dirname(os.path.abspath(__file__))
    panel_venv_pip = f'{panel_root}/venv/bin/pip'
    xray = _find_xray_paths()
    mtg = _find_mtg_paths()
    xray_cfg = xray['config'] or '/usr/local/etc/xray/config.json'
    mtg_unit = mtg['unit'] or 'mtg'
    mtg_cfg = mtg['config'] or '/etc/mtg/config.toml'

    awg = _find_awg_paths()
    items = []

    def _want(g):
        return groups is None or g in groups
    # Скрытый или остановленный протокол не проверяем: его «сломанные»
    # зависимости — не поломка, а следствие решения пользователя, и ⚠ в шапке
    # должна гореть только на то, что он собирался чинить. Исключение —
    # пункты proto_*_missing ниже: они как раз про «включён, но не поднят»
    # и гейтятся своим условием.
    _enabled_protos = SERVER_CFG.get('enabled_protocols')
    if not isinstance(_enabled_protos, list):
        # Совсем старый server.json: считаем включёнными все известные протоколы,
        # иначе проверки протокола молча пропали бы вместе со своей вкладкой.
        # Совсем старый server.json: считаем включёнными все известные протоколы,
        # иначе проверки Hysteria молча пропали бы вместе со своей вкладкой.
        _enabled_protos = ['awg', 'xray', 'mtg', 'hysteria', 'tgweb']
    _proto_state_cache = {}

    def _proto_checked(proto):
        """Проверки протокола имеют смысл, только если он виден в панели и реально работает."""
        if proto not in _enabled_protos:
            return False
        if proto not in _proto_state_cache:
            try:
                _proto_state_cache[proto] = _proto_state(proto)
            except Exception:
                # Состояние не определилось — молчать хуже, чем лишний пункт.
                _proto_state_cache[proto] = 'active'
        return _proto_state_cache[proto] == 'active'
    # --- Критичные файлы самой панели ---
    _panel_from = len(items)
    items.append({
        'id': 'panel_server_json',
        'name': 'Файл server.json (настройки сервера)',
        'description': 'Хранит имя сервера, SNI, server_ip_override, избранное настроек, расписания. Создаётся автоматически с дефолтами при первом запуске; пропадание означает, что что-то снесло /opt/awg-panel/data/server.json — все настройки сброшены.',
        'ok': os.path.exists(SERVER_CONFIG_FILE),
        'fix_cmd': '',
        'fixable': False,
    })
    items.append({
        'id': 'panel_admin_json',
        'name': 'Файл admin.json (хеш пароля)',
        'description': 'Хеш пароля админа панели. Без него невозможно войти в панель. Автосоздаётся при первом запуске со стандартным паролем.',
        'ok': os.path.exists(ADMIN_FILE),
        'fix_cmd': '',
        'fixable': False,
    })
    items.append({
        'id': 'panel_secret_key',
        'name': 'Файл secret.key (Flask session)',
        'description': 'Ключ подписи cookies. Если файла нет — все залогиненные пользователи получат 401 после ближайшего рестарта. Автосоздаётся при первом запуске.',
        'ok': os.path.exists(SECRET_KEY_FILE),
        'fix_cmd': '',
        'fixable': False,
    })
    # Модули панели: неполный накат обновления раньше выглядел как молча пропавшая
    # фича — причина была видна только в journalctl.
    try:
        _mods = _panel_modules_status()
        _mods_bad = [m for m in _mods if not m[2]]
        items.append({
            'id': 'panel_modules',
            'name': f'Модули панели ({len(_mods) - len(_mods_bad)} из {len(_mods)} загружены)',
            'description': (
                'Код панели разложен по modules/: app.py подключает их при старте. '
                'Если файл не долетел при обновлении, панель поднимется, но фича пропадёт '
                'целиком и без объяснений — поэтому состояние каждого модуля видно здесь.\n\n'
                + '\n'.join(
                    f'{"✓" if ok else "✗"} {path} — {purpose}'
                    + (f'\n    {err}' if err and not ok else '')
                    for path, purpose, ok, err in _mods
                )
                + ('\n\nЧинится повторным накатом обновления панели '
                   '(«Настройки → Сервер и обновления»): архив кладёт все файлы.'
                   if _mods_bad else '')
            ),
            'ok': not _mods_bad,
            'fix_cmd': '',
            'fixable': False,
        })
    except Exception as _e:
        audit('warn', f'panel_modules check: {_e}')
    if not _want('panel'):
        del items[_panel_from:]
    if _want('awg') and _proto_checked('awg'):
        has_clients_db = os.path.exists(CLIENTS_DB)
        has_peers = False
        try:
            with open(AWG_CONFIG, 'r') as _f:
                has_peers = '[Peer]' in _f.read()
        except Exception:
            pass
        if has_clients_db:
            cj_desc = 'JSON с именами/ключами/расписаниями всех клиентов AmneziaWG. Если пропадёт — список клиентов в панели опустеет, peers в awg0.conf уцелеют, но потеряется метаинформация.'
        elif has_peers:
            cj_desc = 'JSON с именами/ключами/расписаниями клиентов AmneziaWG отсутствует, но в awg0.conf уже есть peers — метаинформация потеряна.'
        else:
            cj_desc = 'JSON с именами/ключами/расписаниями клиентов AmneziaWG. Создаётся автоматически при добавлении первого клиента — отсутствие файла до этого нормально.'
        items.append({
            'id': 'panel_clients_json',
            'name': 'База клиентов AWG (data/awg/clients.json)',
            'description': cj_desc,
            'ok': has_clients_db or not has_peers,
            'fix_cmd': '',
            'fixable': False,
        })
        # Подсеть клиентов должна совпадать с [Interface] Address сервера
        try:
            import ipaddress as _ipa
            iface_addr = get_awg_interface_address()
            srv_net = _ipa.ip_interface(iface_addr).network
            bad = []
            if has_clients_db:
                _cls = load_clients()
                for _name, _c in _cls.items():
                    _ip = (_c.get('address') or '').replace('/32', '').strip()
                    if not _ip:
                        continue
                    try:
                        if _ipa.ip_address(_ip) not in srv_net:
                            bad.append(f'{_name}={_ip}')
                    except ValueError:
                        bad.append(f'{_name}={_ip}')
            subnet_ok = not bad
            subnet_desc = (
                f'Серверный интерфейс awg0 слушает на сети {iface_addr}. '
                'Все клиентские адреса должны попадать в эту сеть, иначе handshake пройдёт, но трафик не маршрутизируется. '
                + (f'Несоответствие: {", ".join(bad[:5])}' + ('…' if len(bad) > 5 else '') if bad else 'Все клиенты в правильной подсети.')
            )
        except Exception as _e:
            subnet_ok = True
            subnet_desc = f'Не удалось проверить подсеть клиентов: {_e}'
        # Пункт «Логирование destinations» собирает сам модуль: он владеет и
        # конфигом dnsmasq, и автофиксом, и знает, включён ли свитч.
        if awg_dest_log:
            try:
                _dest_item = awg_dest_log.dependency_item()
            except Exception as _e:
                # Сбой внутри модуля не должен ронять весь список проверок:
                # список — это то, чем чинят панель, он обязан открываться всегда.
                _dest_item = None
                audit('error', f'awg_dest_log.dependency_item: {_e}')
            if _dest_item:
                items.append(_dest_item)

        items.append({
            'id': 'awg_subnet_match',
            'name': 'Подсеть клиентов соответствует awg0',
            'description': subnet_desc,
            'ok': subnet_ok,
            'fix_cmd': '',
            'fixable': False,
        })
    _panel_from = len(items)
    items.append({
        'id': 'maxminddb',
        'name': 'Python-модуль maxminddb (geo+ASN)',
        'description': 'Нужен для определения страны и провайдера по IP в логах клиентов. Без него флажков и ASN не будет.',
        'ok': _maxminddb_loaded,
        'fix_cmd': f'{panel_venv_pip} install maxminddb',
        'fixable': True,
        'requires_restart': True,
    })
    items.append({
        'id': 'geo_city_mmdb',
        'name': f'Файл {GEO_DB}',
        'description': 'База GeoLite2-City для определения города/страны по IP. Скачивается с CDN byfox.dev.',
        'ok': os.path.exists(GEO_DB),
        'fix_cmd': '',
        'fix_internal': 'geo_update',
        'fixable': True,
        'requires_restart': True,
    })
    items.append({
        'id': 'geo_asn_mmdb',
        'name': f'Файл {ASN_DB}',
        'description': 'База GeoLite2-ASN для определения провайдера по IP. Скачивается с CDN byfox.dev.',
        'ok': os.path.exists(ASN_DB),
        'fix_cmd': '',
        'fix_internal': 'geo_update',
        'fixable': True,
        'requires_restart': True,
    })
    items.append({
        'id': 'logs_dir',
        'name': f'Папка {PANEL_LOGS_DIR}',
        'description': 'Единая папка для логов всех протоколов (xray, mtg, awg). Создаётся под root:root — у xray обычно нет CAP_DAC_OVERRIDE, поэтому смена владельца на nobody лишит даже root возможности туда писать.',
        'ok': os.path.isdir(PANEL_LOGS_DIR),
        'fix_cmd': f'mkdir -p {PANEL_LOGS_DIR} && chown root:root {PANEL_LOGS_DIR} && chmod 755 {PANEL_LOGS_DIR}',
        'fixable': True,
    })
    if not _want('panel'):
        del items[_panel_from:]
    # --- XRay-зависимые проверки (только если xray виден в панели и запущен) ---
    # ⚠ показываем только для того, что юзер «хочет»: статистика по умолчанию ON,
    # логи — ручной опт-ин. Иначе на свежем сервере без логов панель зря ругалась бы.
    if _want('xray') and _proto_checked('xray'):
        cfg_log = xray.get('access_log', '')
        if _xray_stats_wanted():
            items.append({
                'id': 'xray_stats',
                'name': 'XRay stats/api (учёт трафика клиентов)',
                'description': (
                    'Для подсчёта трафика по каждому клиенту в конфиге нужны блоки '
                    'stats/api/policy, инбаунд 127.0.0.1:10085 и правило роутинга на api. '
                    'Без них трафик клиентов всегда 0. Частая причина пропажи — пересборка '
                    'инбаунда под Reality без этих секций. Автофикс добавит их и перезапустит xray.'
                ),
                'ok': bool(xray.get('stats_ok')),
                'fix_internal': 'xray_enable_stats',
                'fix_cmd': '',
                'fixable': True,
                'requires_restart': True,
            })
        if _xray_logs_wanted():
            items.append({
                'id': 'xray_log_path',
                'name': 'xray.log.access указывает на нашу папку',
                'description': (
                    f'Найденный xray-конфиг: {xray_cfg}. Сейчас log.access = '
                    f'{cfg_log or "(не задан)"}. Должно быть = {XRAY_ACCESS_LOG}.'
                ),
                'ok': cfg_log == XRAY_ACCESS_LOG,
                'fix_cmd': (
                    f"python3 -c \"import json; p='{xray_cfg}'; "
                    f"c=json.load(open(p)); c.setdefault('log',{{}})['access']='{XRAY_ACCESS_LOG}'; "
                    f"json.dump(c, open(p,'w'), indent=2)\" && "
                    f"systemd-run --no-block /bin/bash -c 'sleep 3 && systemctl restart {xray['unit'] or 'xray'}'"
                ),
                'fixable': True,
            })
    # --- mtg-зависимые проверки (только если mtg виден в панели и запущен) ---
    if _want('mtg') and _proto_checked('mtg'):
        mtg_actual_log = mtg.get('access_log', '')
        has_drop_in = mtg_actual_log == MTG_ACCESS_LOG
        # Дефолтный путь к новому drop-in файлу (если его ещё нет)
        new_drop_in = mtg.get('drop_in') or f'/etc/systemd/system/{mtg_unit}.service.d/logfile.conf'
        items.append({
            'id': 'mtg_drop_in',
            'name': 'mtg systemd drop-in (запись в наш файл)',
            'description': (
                f'systemd-override должен направлять stdout/stderr {mtg_unit} в {MTG_ACCESS_LOG}. '
                f'Сейчас mtg пишет в: {mtg_actual_log or "(не настроено)"}.'
            ),
            'ok': has_drop_in,
            'fix_cmd': (
                f"mkdir -p /etc/systemd/system/{mtg_unit}.service.d && "
                f"printf '[Service]\\nStandardOutput=append:{MTG_ACCESS_LOG}\\n"
                f"StandardError=append:{MTG_ACCESS_LOG}\\n' > {new_drop_in} && "
                f"systemctl daemon-reload && "
                f"systemd-run --no-block /bin/bash -c 'sleep 3 && systemctl restart {mtg_unit}'"
            ),
            'fixable': True,
        })
        items.append({
            'id': 'mtg_debug',
            'name': 'mtg debug=true (для логирования стримов)',
            'description': f'В {mtg_cfg} должен быть debug = true — иначе mtg не пишет события подключений и в логах будет пусто.',
            'ok': _mtg_debug_enabled(mtg_cfg),
            'fix_cmd': f"echo 'debug = true' >> {mtg_cfg} && systemd-run --no-block /bin/bash -c 'sleep 3 && systemctl restart {mtg_unit}'",
            'fixable': True,
        })
    # --- Протоколы, включённые в интерфейсе, но не поднятые на сервере ---
    # Панель не решает за пользователя, какие протоколы ему нужны: набор задаётся
    # в «Скрыть протоколы / платформы». Но если протокол включён, а сервиса нет —
    # это несоответствие, и место ему здесь, рядом с остальными проверками.
    enabled = _enabled_protos
    if _want('awg') and 'awg' in enabled and awg_install:
        # Состояние AWG (ядро, заголовки, репозиторий, DKMS, конфиг, интерфейс) и
        # сценарии установки/обновления живут в awg_install.py — панель ставит модуль
        # сама, как XRay и mtg, а не отправляет пользователя в ручную инструкцию.
        try:
            for _it in awg_install.dependency_items():
                # Пункт обновления не навязываем, пока протокол остановлен: он про
                # улучшение, а не про поломку. Установку показываем всегда.
                if _it['id'] == 'awg_module_update' and not _proto_checked('awg'):
                    continue
                items.append(_it)
        except Exception as _e:
            audit('error', f'awg_install.dependency_items: {_e}')
    if _want('xray') and 'xray' in enabled and not xray.get('installed'):
        items.append({
            'id': 'proto_xray_missing',
            'name': 'XRay включён в панели, но не установлен',
            'description': 'Вкладка XRay показана, а сервиса на сервере нет. Панель поставит бинарь официальным '
                           'установщиком XTLS, подберёт свободный порт, откроет его в фаерволе и создаст рабочий '
                           'инбаунд: VLESS+TLS с фоллбеком на панель, если у сервера есть сертификат домена, '
                           'иначе VLESS+Reality. Существующий конфиг не перезаписывается.',
            'ok': False,
            # Команду для терминала не даём: официальный установщик кладёт только
            # бинарь, инбаунд всё равно пришлось бы писать руками — половинчатый
            # путь оставил бы XRay запущенным, но без единого клиента.
            'fix_cmd': '',
            'fix_internal': 'xray_install',
            'fixable': True,
        })
    if _want('mtg') and 'mtg' in enabled and not mtg.get('installed'):
        items.append({
            'id': 'proto_mtg_missing',
            'name': 'MTProto включён в панели, но не установлен',
            'description': 'Вкладка MTProto показана, а сервиса mtg на сервере нет. Панель скачает бинарь с GitHub, '
                           f'сгенерирует секрет, положит конфиг {mtg_cfg}, создаст юнит с записью логов в каталог '
                           'панели, подберёт свободный порт и откроет его в фаерволе. Существующий конфиг с секретом '
                           'не трогается.',
            'ok': False,
            'fix_cmd': '',
            'fix_internal': 'mtg_install',
            'fixable': True,
        })
    if _want('hysteria') and 'hysteria' in enabled and _hysteria_pkg_present():
        hy_ok, hy_desc = _hysteria_dep_state()
        try:
            from modules.hysteria import service as _hy_svc
            # Упала — block; не установлена или остановлена руками — совет.
            _hy_by_hand = (not hy_ok) and (not _hy_svc.bin_installed() or _hy_svc.stopped_by_hand())
        except Exception:
            _hy_by_hand = False
        items.append({
            'id': 'proto_hysteria_missing',
            'level': 'tip' if _hy_by_hand else 'block',
            'name': 'Сервис Hysteria 2 работает',
            'description': hy_desc or ('Бинарь hysteria установлен, юнит hysteria-server активен. '
                                       'Клиенты подключаются по UDP (QUIC) — с TCP-портом XRay это не пересекается.'),
            'ok': hy_ok,
            'fix_cmd': '',
            'fix_internal': 'hysteria_setup',
            'fixable': True,
            'requires_restart': False,
            # Установка тянет бинарь с GitHub, выпускает сертификат и поднимает
            # юнит — без затемнения кнопка выглядит зависшей.
            'long': True,
            'eta_hint': 'Обычно 10–40 сек: бинарь с GitHub, сертификат, запуск сервиса',
        })
        items.extend(_hysteria_runtime_deps())
        items.extend(_hysteria_cert_deps())
    if _want('tgweb') and 'tgweb' in enabled and globals().get('tgweb_pkg'):
        items.extend(_tgweb_dep_items())

    # Модуль инбаунда не загрузился. Обычно это неполный накат обновления:
    # xray_hysteria.py не долетел. Симптом со стороны пользователя — Hysteria
    # просто отсутствует в панели, и понять почему неоткуда: ошибка видна лишь
    # в journalctl. Поэтому она отдельной проверкой.
    if _want('xray') and not xhy and xray.get('bin') and _proto_checked('xray'):
        items.append({
            'id': 'xray_hy_module',
            'name': 'Модуль Hysteria (xray_hysteria.py) не загружен',
            'description': ('Панель не смогла подключить модуль инбаунда Hysteria: '
                            + (XHY_IMPORT_ERROR or 'причина неизвестна')
                            + '. Пока он не загружен, Hysteria недоступна целиком: ни настроек, ни ссылок '
                              'у клиентов, ни строки на плитке. Чаще всего файл просто не попал на сервер '
                              'при обновлении — накатите обновление панели заново '
                              '(«Настройки → Сервер и обновления»), оно кладёт все файлы из архива.'),
            'ok': False,
            'fix_cmd': '',
            'fixable': False,
            'requires_restart': True,
        })

    # Инбаунд Hysteria: UDP-порт должен быть открыт отдельно от TCP-правила XRay.
    # Без этого сервис «работает», а клиенты упираются в таймаут — самая частая
    # и самая непонятная со стороны поломка.
    if _want('xray') and xhy and _proto_checked('xray'):
        try:
            _hy_st = xhy.status()
        except Exception:
            _hy_st = {}
        if _hy_st.get('enabled'):
            _hy_port = int(_hy_st.get('port') or 0)
            _ufw_on, _ufw_status = ufw_active()
            _rule_ok = (not _ufw_on) or ufw_port_open(_hy_port, 'udp')
            items.append({
                'id': 'xray_hy_port_udp',
                'name': f'UDP-порт {_hy_port} открыт для Hysteria',
                'description': (f'Инбаунд Hysteria слушает {_hy_port}/udp. Правило XRay на том же номере '
                                'относится к TCP и на UDP не распространяется — это разные сокеты.'
                                if _rule_ok else
                                f'В ufw нет правила {_hy_port}/udp. XRay принимает инбаунд, но пакеты клиентов '
                                'до него не доходят: подключение просто висит до таймаута.'),
                'ok': _rule_ok,
                'fix_cmd': '',
                'fix_internal': 'xray_hy_open_port',
                'fixable': True,
                'requires_restart': False,
            })
            # Чужой слушатель на том же UDP-порту. Встречается после ручной
            # установки чего-нибудь на 443/udp и при живом AmneziaWG: XRay тогда
            # не поднимется целиком — вместе с VLESS.
            _hy_busy = _hy_udp_busy()
            _hy_clash = _hy_busy.get(_hy_port, '')
            if _hy_clash:
                _hy_alt, _ = pick_free_port(0, 'udp', 'hysteria', extra_busy=tuple(_hy_busy.keys()))
                items.append({
                    'id': 'xray_hy_port_clash',
                    'name': f'UDP-порт {_hy_port} занят другим сервисом',
                    'description': (f'На {_hy_port}/udp слушает {_hy_clash}. Инбаунд Hysteria прописан на этом же '
                                    'порту — XRay упадёт на «address already in use» целиком, вместе с VLESS. '
                                    + (f'Свободен {_hy_alt}/udp — перенести инбаунд туда. Клиентам после переноса '
                                       'нужно будет выдать ссылки заново: порт зашит в ссылку.'
                                       if _hy_alt else 'Свободных портов из списка кандидатов не осталось.')),
                    'ok': False,
                    'fix_cmd': '',
                    'fix_internal': 'xray_hy_move_port' if _hy_alt else '',
                    'fixable': bool(_hy_alt),
                    'requires_restart': False,
                })
        else:
            # Выключен по своей воле — это норма и в проверки не идёт. А вот
            # неудачная попытка включить сама по себе немая: человек видит
            # «выключена» и не знает, что панель пыталась и обо что споткнулась.
            _hy_note = (SERVER_CFG.get('hysteria_autoenable_note') or '').strip()
            if _hy_note:
                _hy_busy = _hy_udp_busy()
                _hy_alt, _ = pick_free_port(0, 'udp', 'hysteria', extra_busy=tuple(_hy_busy.keys()))
                items.append({
                    'id': 'xray_hy_autoenable',
                    'name': 'Hysteria не включилась автоматически',
                    'description': (f'Панель пыталась поднять инбаунд Hysteria и не смогла: {_hy_note}. '
                                    + (f'Сейчас свободен {_hy_alt}/udp — можно поднять на нём.' if _hy_alt
                                       else 'Свободных UDP-портов из списка кандидатов не нашлось.')
                                    + ' Клиенты пока подключаются только по VLESS/TCP.'),
                    'ok': False,
                    'fix_cmd': '',
                    'fix_internal': 'xray_hy_move_port' if _hy_alt else '',
                    'fixable': bool(_hy_alt),
                    'requires_restart': False,
                })

    # Живые проверки протоколов: кто слушает порт, ufw, iptables AWG, сертификат
    # и A-запись домена VLESS. Каждая своя — сбой одной не прячет остальные.
    if proto_health:
        for _g, _fn in (('awg', proto_health.awg_items), ('xray', proto_health.xray_items),
                        ('mtg', proto_health.mtg_items), ('tgweb', proto_health.tgweb_items)):
            if _want(_g) and _proto_checked(_g):
                try:
                    items.extend(_fn())
                except Exception as _e:
                    audit('error', f'proto_health.{_g}: {_e}')
        # Новая версия движка — у остановленного не навязываем, как и у AWG с WEB.
        # Hysteria нет в PROTO_BINS: _proto_checked счёл бы её неустановленной,
        # её состояние проверяет _proto_update_item через пакет.
        for _g in ('xray', 'mtg', 'hysteria'):
            if _want(_g) and (_g in _enabled_protos if _g == 'hysteria' else _proto_checked(_g)):
                try:
                    _it = _proto_update_item(_g)
                    if _it:
                        items.append(_it)
                except Exception as _e:
                    audit('error', f'proto update item {_g}: {_e}')

    lr_path = LOGROTATE_CONF
    _panel_from = len(items)
    items.append({
        'id': 'logrotate',
        'name': f'logrotate-конфиг {lr_path}',
        'description': 'Без logrotate логи разрастутся до бесконечности. Стандарт: 10 файлов × 100MB, copytruncate.',
        # Без самого logrotate или с чужим путём файл ничего не ротирует — зелёным
        # это быть не должно.
        'ok': _logrotate_conf_current() and bool(shutil.which('logrotate')),
        'fix_cmd': (
            "command -v logrotate >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y logrotate\n"
            "mkdir -p /etc/logrotate.d\n"
            f"cat > {lr_path} << 'EOF'\n"
            f"{_logrotate_conf()}"
            "EOF"
        ),
        'fixable': True,
    })
    if not _want('panel'):
        del items[_panel_from:]
    for item in items:
        item.setdefault('requires_restart', False)
        item.setdefault('group', DEP_GROUP_BY_ID.get(item['id'], _dep_group_guess(item['id'])))
    return items


# Раскладка проверок по вкладкам окна «Зависимости». Общие для панели —
# в 'panel', остальные к своему протоколу: так видно, из-за чего именно
# горит предупреждение, и не приходится перечитывать весь список.
DEP_GROUPS = [
    ('panel', 'Общие'),
    ('awg', 'AmneziaWG'),
    ('xray', 'XRay'),
    ('mtg', 'MTProto'),
    ('hysteria', 'Hysteria'),
    ('tgweb', 'Telegram WEB'),
]
DEP_GROUP_BY_ID = {
    'panel_server_json': 'panel',
    'panel_admin_json': 'panel',
    'panel_secret_key': 'panel',
    'panel_modules': 'panel',
    'maxminddb': 'panel',
    'geo_city_mmdb': 'panel',
    'geo_asn_mmdb': 'panel',
    'logs_dir': 'panel',
    'logrotate': 'panel',
    'panel_clients_json': 'awg',
    'awg_dest_logging_setup': 'awg',
    'awg_subnet_match': 'awg',
    'proto_awg_missing': 'awg',
    'xray_stats': 'xray',
    'xray_log_path': 'xray',
    'proto_xray_missing': 'xray',
    'mtg_drop_in': 'mtg',
    'mtg_debug': 'mtg',
    'proto_mtg_missing': 'mtg',
    'xray_hy_port_udp': 'xray',
    'xray_hy_port_clash': 'xray',
    'xray_hy_autoenable': 'xray',
    'xray_hy_module': 'xray',
}


def _dep_group_guess(dep_id):
    """Группа для проверок, не перечисленных явно — по префиксу id.

    Порядок важен: 'xray_hy_*' — это инбаунд внутри ядра XRay, и место ему на
    вкладке XRay, а не Hysteria. Собственные проверки протокола начинаются с
    'hy_', поэтому 'xray_' проверяется раньше.
    """
    for prefix, group in (('xray_', 'xray'), ('hy_', 'hysteria'),
                          ('proto_hysteria', 'hysteria'),
                          ('tgweb_', 'tgweb'), ('proto_tgweb', 'tgweb'),
                          ('mtg_', 'mtg'), ('awg_', 'awg')):
        if dep_id.startswith(prefix):
            return group
    return 'panel'


def _tgweb_dep_items():
    """Пункт «Telegram WEB работает» для «Зависимостей» и окна ⚙.

    Не установлен — это совет, а не авария: протокол новый и необязательный,
    и красный «!» на всех серверах сразу после обновления панели читался бы
    как поломка. Установлен, но лежит, — block (остановлен руками — tip, как
    у остальных). Живые проверки цепочки — proto_health.tgweb_items."""
    try:
        from modules.tgweb import service as tg
        installed = tg.bin_installed() and tg.load_settings().get('enabled')
        active = installed and tg.is_active()
        by_hand = installed and not active and tg.stopped_by_hand()
        mode = tg.xray_link.state().get('mode') or ''
    except Exception as e:
        return [{'id': 'proto_tgweb_missing', 'level': 'block', 'name': 'Пакет Telegram WEB',
                 'description': f'Пакет modules/tgweb не отвечает: {e}', 'ok': False,
                 'fix_cmd': '', 'fixable': False}]
    if not installed:
        desc = ('Новый тип прокси Telegram: трафик идёт обычным HTTPS через ваш домен на 443 и по отпечатку '
                'не отличается от браузера. Панель поставит движок telemt и nginx, подключит их к XRay и '
                'проверит цепочку целиком.')
        if mode != 'tls':
            desc += (' Сейчас XRay на 443 в режиме %s — установка остановится на первом шаге: нужен TLS '
                     'с сертификатом домена.' % (mode.upper() or 'не установлен'))
        return [{'id': 'proto_tgweb_missing', 'level': 'tip', 'name': 'Telegram WEB-прокси не установлен',
                 'description': desc, 'ok': False, 'fix_cmd': '', 'fix_internal': 'tgweb_setup',
                 'fixable': mode == 'tls', 'long': True,
                 'eta_hint': 'Обычно 30–90 сек: nginx, бинарь telemt, проверка цепочки через 443'}]
    return [{'id': 'proto_tgweb_missing', 'level': 'tip' if by_hand else 'block',
             'name': 'Сервис Telegram WEB (telemt) работает',
             'description': ('Сервис telemt запущен.' if active else
                             ('Сервис остановлен вручную — WEB-прокси у клиентов не работает.' if by_hand else
                              'Сервис telemt не запущен. Починка перепроверит конфиг, nginx и фоллбек XRay '
                              'и поднимет его. Причина падения — в data/logs/tgweb_access.log.')),
             'ok': bool(active), 'fix_cmd': '', 'fix_internal': 'tgweb_setup', 'fixable': not active,
             'long': True, 'eta_hint': 'Обычно 10–40 сек'}] + _tgweb_port_conflict_items()


def _tgweb_port_conflict_items():
    """Внутренний порт цепочки закреплён за другим сервисом панели или занят
    чужим процессом. Починка переберёт порты и перепишет конфиг, блок nginx и
    фоллбек XRay — клиентам ничего перевыдавать не нужно: эти порты в ссылки
    не попадают."""
    clashes = []
    for it in _tgweb_port_items():
        # 443 в режиме «сам» — не внутренний порт, и переносить его некуда. Кто
        # на нём, решает front.py: XRay при старте в TLS его получит, в Reality
        # получит отказ с объяснением (пункт об этом — у XRay).
        if it['kind'] == 'tgweb_front':
            continue
        why = port_conflict(it['port'], 'tcp', ignore_kind=it['kind'], include_idle=True)
        if why:
            clashes.append(f"{it['who']}: {why}")
    return [{'id': 'tgweb_port_conflict', 'level': 'block', 'name': 'Конфликт внутренних портов Telegram WEB',
             'description': ('Внутренние порты свободны.' if not clashes else
                             'Порт цепочки занят другим: ' + '; '.join(clashes) + '. Починка подберёт свободные '
                             'и перепишет конфиг, блок nginx и фоллбек XRay. Ссылки клиентов не меняются.'),
             'ok': not clashes, 'fix_cmd': '', 'fix_internal': 'tgweb_move_ports', 'fixable': bool(clashes),
             'long': True, 'eta_hint': 'Обычно 5–20 сек'}]


def _hysteria_pkg_present():
    """Подключён ли пакет протокола к панели. Если файлов нет или импорт упал —
    проверок Hysteria быть не должно вовсе: чинить в этой панели нечего."""
    try:
        from modules.hysteria import service as hy_service   # noqa: F401
        return True
    except Exception:
        return False


def _hysteria_dep_state():
    """(ok, описание) для пункта «Зависимостей».

    Состояние спрашиваем у самого пакета: если он не подключён (файлов нет,
    импорт упал) — чинить нечего, пункт не показываем.
    """
    try:
        from modules.hysteria import service as hy_service
        st = hy_service.status()
    except Exception:
        return True, ''
    if not st.get('installed'):
        return False, ('Вкладка Hysteria включена, но бинаря на сервере нет. Кнопка починки скачает релиз '
                       'с GitHub под архитектуру сервера, выпустит self-signed сертификат, создаст юнит '
                       'hysteria-server и запустит его на UDP-порту — трафик XRay на TCP/443 это не заденет.')
    if not st.get('active'):
        return False, ('Бинарь установлен, но сервис hysteria-server не запущен. Починка перегенерирует конфиг '
                       'и поднимет сервис заново; если он снова упадёт, причина будет в '
                       'data/logs/hysteria_access.log.')
    return True, ''


def _hysteria_runtime_deps():
    """Проверки Hysteria, которые видны ВСЕГДА, а не только когда что-то сломано.

    Вкладка «Hysteria» в «Зависимостях» иначе не появлялась бы на здоровом
    сервере: единственный пункт добавлялся бы только при поломке, а вкладка без
    пунктов не рисуется. Смотреть на список из четырёх протоколов и находить там
    три — хуже, чем видеть четвёртый с зелёными галочками.
    """
    try:
        from modules.hysteria import service as hy
        from modules.hysteria import (AUTH_SCRIPT, CONFIG_FILE, DATA_DIR as HY_DATA_DIR,
                                      ACCESS_LOG as HY_ACCESS_LOG, UNIT_NAME as HY_UNIT,
                                      load_settings)
    except Exception:
        return []
    if not hy.bin_installed():
        # Бинаря нет — остальные проверки бессмысленны, о них скажет пункт установки.
        return []
    out = []
    cfg = load_settings()
    port = int(cfg.get('port') or 443)

    out.append({
        'id': 'hy_config',
        'name': f'Конфиг Hysteria {CONFIG_FILE}',
        'description': 'Файл, который читает hysteria-server при старте. Панель генерирует его целиком из '
                       'data/hysteria/settings.json и глобальных правил — ручные правки перезаписываются.',
        'ok': os.path.isfile(CONFIG_FILE),
        'fix_cmd': '',
        'fix_internal': 'hysteria_rewrite_config',
        'fixable': True,
    })

    # Путь к скрипту авторизации в конфиге. Пакет переехал в modules/hysteria/,
    # а config.yaml на сервере писался до переезда и зовёт файл по старому
    # адресу. Панель чинит это сама на старте, но если самолечение не сработало,
    # симптом — «сервис работает, никого не пускает» — надо назвать прямо.
    cfg_auth = hy.config_auth_path()
    out.append({
        'id': 'hy_auth_path',
        'name': 'Путь скрипта авторизации в конфиге',
        'description': (f'config.yaml зовёт «{cfg_auth or "—"}», пакет лежит по «{AUTH_SCRIPT}». '
                        'Пакет переехал в modules/hysteria/, и конфиг, сгенерированный до переезда, '
                        'указывает на прежнее место. Пока пути расходятся, hysteria зовёт файл, которого '
                        'может не быть: сервис «работает», а не пускает никого. Починка перегенерирует '
                        'конфиг и перезапустит сервис.'),
        'ok': (not cfg_auth) or cfg_auth == AUTH_SCRIPT,
        'fix_cmd': '',
        'fix_internal': 'hysteria_rewrite_config',
        'fixable': True,
    })

    auth_ok = os.path.isfile(AUTH_SCRIPT) and os.access(AUTH_SCRIPT, os.X_OK)
    out.append({
        'id': 'hy_auth_script',
        'name': 'Скрипт авторизации исполняем',
        'description': f'{AUTH_SCRIPT} — hysteria зовёт его на каждое подключение и по коду возврата решает, '
                       'пускать клиента или нет. Без бита +x не пускается никто, а сервис при этом «работает».',
        'ok': auth_ok,
        'fix_cmd': f'chmod +x {AUTH_SCRIPT}',
        'fix_internal': 'hysteria_fix_auth',
        'fixable': True,
    })

    ufw_on, ufw_out = ufw_active()
    fw_ok = (not ufw_on) or ufw_port_open(port, 'udp')
    out.append({
        'id': 'hy_firewall_port',
        'name': f'UDP-порт {port} открыт в фаерволе',
        'description': ('ufw на сервере выключен — порт и так доступен снаружи.' if not ufw_on else
                        f'Hysteria слушает UDP/{port}. Если порт закрыт в ufw, сервис будет «работать», '
                        'а клиенты — молча упираться в таймаут: отличить это от поломки невозможно.'),
        'ok': fw_ok,
        'fix_cmd': f"ufw allow {port}/udp comment 'Hysteria (awg-panel)'",
        'fix_internal': 'hysteria_open_port',
        'fixable': True,
    })

    # Порт-хоппинг — главная защита UDP от удушения ТСПУ. На новых установках
    # включён сразу; на существующих — этой плашкой с кнопкой. Ссылки клиентов
    # не меняются: основной порт тот же, диапазон добавляется.
    try:
        hop = hy.hop_state()
    except Exception:
        hop = None
    if hop is not None:
        if hop['active']:
            hop_desc = (f"Клиенты меняют порт раз в {hop['interval']} с в диапазоне {hop['active']}/udp; "
                        f"сервер принимает весь диапазон и перенаправляет его на {port}.")
        elif not hop['supported']:
            hop_desc = f"Включить нельзя: {hop['why']}."
        else:
            hop_desc = ('Операторы в РФ режут или душат долгий UDP-поток на одном порту — Hysteria '
                        '«работает», но через несколько минут скорость падает до нуля. С хоппингом клиент '
                        'регулярно переходит на другой порт из диапазона. Основной порт не меняется: '
                        'выданные ссылки и QR работают как раньше, хоппинг получат профили по подписке '
                        '(обновятся сами) и новые ссылки. Починка подберёт свободный диапазон и '
                        'перезапустит Hysteria.')
        out.append({
            'id': 'hy_port_hop',
            # «Стоит поправить» (оранжевый «!» на главной), а не тихий совет: без
            # хоппинга Hysteria в РФ через несколько минут глохнет. На старом
            # бинаре включить нельзя — там только совет обновиться.
            'level': 'warn' if hop['supported'] else 'tip',
            'name': 'Порт-хоппинг (смена UDP-порта)',
            'description': hop_desc,
            'ok': bool(hop['active']),
            'fix_cmd': '',
            'fix_internal': 'hysteria_hop_on',
            'fixable': bool(hop['supported']) and not hop['active'],
            'long': True,
            'eta_hint': 'Несколько секунд: правка конфига и перезапуск Hysteria',
        })

    # Столкновение по реестру портов панели, а не только по `ss`: сосед может
    # стоять на этом же номере в своём конфиге и сейчас лежать — тогда порт
    # формально свободен, а при его старте достанется тому, кто поднимется первым.
    # Кандидата ищем только при конфликте: подбор дёргает `ss` по каждому
    # запасному порту, а список зависимостей опрашивается часто.
    clash, alt = hy.port_clash(port)
    out.append({
        'id': 'hy_port_clash',
        'name': f'UDP/{port} не делится с соседом',
        'description': (f'{clash}. Соседей по UDP двое: AmneziaWG и инбаунд Hysteria внутри XRay — '
                        'оба живут в своих файлах, и совпадение номеров видно только из реестра портов '
                        'панели. '
                        + (f'Свободен {alt}/udp — сменить порт можно карандашом на плитке '
                           '«Адрес подключения»; порт зашит в выданные ссылки, их придётся раздать заново.'
                           if alt else
                           'Свободных портов из списка кандидатов не осталось — освободите номер '
                           'или укажите свой в ⚙ «Сервис Hysteria».')
                        if clash else
                        'Ни AmneziaWG, ни инбаунд Hysteria внутри XRay этот номер не занимают.'),
        'ok': not clash,
        'fix_cmd': '',
        'fixable': False,
    })

    listener = port_owner(port, 'udp')
    ours = bool(listener) and 'hysteria' in listener.lower()
    if ours:
        listen_desc = 'Порт занят процессом hysteria — как и должно быть.'
    elif listener:
        listen_desc = f'На UDP/{port} сейчас «{listener}».'
    else:
        listen_desc = f'UDP/{port} не слушает никто — сервис не поднялся или слушает другой порт.'
    out.append({
        'id': 'hy_port_listener',
        'name': f'UDP/{port} слушает именно Hysteria',
        'description': listen_desc +
                       ' Порт проверяется через ss: чужой слушатель объясняет, почему сервис не поднимается.',
        'ok': ours,
        'fix_cmd': '',
        'fixable': False,
    })

    autostart = hy.is_enabled()
    out.append({
        'id': 'hy_autostart',
        'name': f'Автозапуск {HY_UNIT} включён',
        'description': 'Без systemctl enable протокол не поднимется после перезагрузки сервера, '
                       'и об этом станет известно только от пользователей.',
        'ok': autostart,
        'fix_cmd': f'systemctl enable {HY_UNIT}',
        'fix_internal': 'hysteria_enable_unit',
        'fixable': True,
    })

    log_dir_ok = os.path.isdir(os.path.dirname(HY_ACCESS_LOG))
    out.append({
        'id': 'hy_logs_dir',
        'name': 'Каталог логов Hysteria',
        'description': f'{HY_ACCESS_LOG} — сюда юнит перенаправляет stdout/stderr. Каталог общий с остальными '
                       'логами панели, его подхватывает logrotate по маске *.log.',
        'ok': log_dir_ok,
        'fix_cmd': f'mkdir -p {os.path.dirname(HY_ACCESS_LOG)}',
        'fix_internal': 'hysteria_mk_logdir',
        'fixable': True,
    })

    out.append({
        'id': 'hy_data_dir',
        'name': 'Каталог данных data/hysteria/',
        'description': f'{HY_DATA_DIR} — клиенты, настройки, сертификат, счётчики трафика. Обновление панели '
                       'его не трогает; попадает в бэкап вместе с остальным data/.',
        'ok': os.path.isdir(HY_DATA_DIR),
        'fix_cmd': f'mkdir -p {HY_DATA_DIR}',
        'fix_internal': 'hysteria_mk_datadir',
        'fixable': True,
    })
    return out


def _hysteria_cert_deps():
    """Проверки сертификата Hysteria: какой используется, есть ли автопродление
    и перезапуск после него.

    Самоподписанный сертификат работает, но Loon не умеет пиннинг и вынужден
    доверять любому серту. Поэтому если для домена есть сертификат Let's Encrypt,
    панель это замечает и предлагает переключиться.
    """
    try:
        from modules.hysteria import service as hy
    except Exception:
        return []
    if not hy.bin_installed():
        return []
    out = []
    cfg = hy.load_settings()
    domain = (cfg.get('sni') or '').strip()
    le_cert, _ = hy.find_le_cert(domain)
    mode = hy.cert_mode()

    if mode == 'le':
        days = hy.cert_expires_days(le_cert) if le_cert else None
        # Срок отдельным пунктом: истёкший сертификат клиенты отвергают на
        # TLS-рукопожатии молча — в логе hysteria не будет ни строчки, и без
        # этой проверки причина «просто не работает» ищется вслепую.
        if days is None:
            expiry_desc = ('Не удалось прочитать срок сертификата %s. Проверьте, что файл на месте '
                           'и читается.' % (le_cert or '—'))
        elif days <= 0:
            expiry_desc = ('Сертификат домена «%s» истёк %s. Клиенты не подключатся: приложение '
                           'видит просроченный TLS и рвёт соединение, а Hysteria об этом даже не '
                           'пишет в журнал. Починка перевыпустит сертификат через certbot тем же '
                           'методом, каким он выпускался, и перезапустит сервис.'
                           % (domain or '—',
                              'сегодня' if days == 0 else '%d дн. назад' % abs(days)))
        elif days <= 14:
            expiry_desc = ('До окончания сертификата «%s» осталось %d дн. Обычно certbot продлевает '
                           'его сам за 30 дней до конца — если счётчик дошёл сюда, автопродление не '
                           'работает. Починка перевыпустит сертификат сейчас.' % (domain or '—', days))
        else:
            expiry_desc = ('Сертификат домена «%s» действителен ещё %d дн. Кнопка перевыпуска здесь '
                           'на случай, если продлить нужно раньше срока.' % (domain or '—', days))
        out.append({
            'id': 'hy_cert_expiry',
            'level': 'block' if (days is not None and days <= 0) else 'warn',
            'name': 'Срок сертификата домена',
            'description': expiry_desc,
            'ok': bool(days is not None and days > 14),
            'fix_cmd': '',
            'fix_internal': 'hysteria_cert_renew',
            'fixable': True,
            # Перевыпуск идёт к Let's Encrypt и ждёт проверку домена — это не
            # мгновенная операция, поэтому затемнение с оценкой времени.
            'long': True,
            'eta_hint': 'Обычно 15–60 сек: certbot подтверждает домен в Let’s Encrypt, '
                        'затем перезапускается Hysteria',
        })
        acme_ok, acme_why = hy.acme_http_works(domain)
        out.append({
            'id': 'hy_cert_acme_http',
            'name': 'ACME-челлендж отдаётся по HTTP',
            'description': ('Let’s Encrypt проверяет домен запросом на '
                            'http://<домен>/.well-known/acme-challenge/…. Если 80-й порт только '
                            'редиректит на https, проверка уходит на 443 — а там XRay, и на чужом '
                            'имени (www.<домен>) он рвёт TLS-рукопожатие: продление падает, хотя '
                            'сам сайт работает. Починка публикует каталог челленджа в nginx до '
                            'редиректа и переводит продление на метод webroot, не трогая 443.'
                            + ('' if acme_ok else ' Сейчас: %s.' % acme_why)),
            'ok': acme_ok,
            'fix_cmd': '',
            'fix_internal': 'hysteria_acme_http',
            'fixable': True,
            # Правка конфига, nginx -t и reload с контрольным запросом.
            'long': True,
            'eta_hint': 'Несколько секунд: правка конфига nginx, проверка и перезагрузка',
        })
        out.append({
            'id': 'hy_cert_renew_hook',
            'name': 'Перезапуск сервисов после перевыпуска сертификата',
            'description': ('Сертификат читают при старте все, кто его использует: Hysteria, nginx '
                            '(панель на своём порту) и XRay в режиме TLS. Без deploy-hook они после '
                            'перевыпуска продолжают отдавать старый — клиенты не подключаются, а '
                            'внешний мониторинг видит CERTIFICATE_VERIFY_FAILED, хотя на диске лежит '
                            'новый сертификат. Починка создаёт %s и сразу применяет его.'
                            % hy.LE_DEPLOY_HOOK),
            'ok': hy.renew_hook_installed(),
            'fix_cmd': '',
            'fix_internal': 'hysteria_renew_hook',
            'fixable': True,
        })
        out.append({
            'id': 'hy_cert_renew_timer',
            'name': 'Автопродление сертификатов (certbot)',
            'description': ('Сертификат Let’s Encrypt живёт 90 дней. Если таймера или cron-задания '
                            'certbot нет, он однажды просто истечёт — сколько осталось, показывает '
                            'пункт «Срок сертификата домена». Продление выполняется методом «%s».'
                            % (hy.le_authenticator(domain) or 'не определён')),
            'ok': hy.renew_timer_active(),
            'fix_cmd': 'systemctl enable --now certbot.timer',
            'fixable': True,
        })
    elif le_cert:
        out.append({
            'id': 'hy_cert_le_available',
            'name': 'Для домена есть сертификат, а Hysteria на самоподписанном',
            'description': ('Найден сертификат для «%s». С ним Loon сможет проверять сервер штатно — '
                            'сейчас он вынужден доверять любому сертификату, потому что пиннинга не '
                            'поддерживает. Починка переключит Hysteria на сертификат домена, поставит '
                            'deploy-hook для перезапуска после перевыпуска и уберёт пиннинг из ссылок.'
                            % domain),
            'ok': False,
            'fix_cmd': '',
            'fix_internal': 'hysteria_cert_le',
            'fixable': True,
            # Переключение перезаписывает конфиг и перезапускает сервис.
            'long': True,
            'eta_hint': 'Несколько секунд: смена сертификата и перезапуск Hysteria',
        })
    else:
        out.append({
            'id': 'hy_cert_self',
            'name': 'Hysteria работает на самоподписанном сертификате',
            'description': ('Сертификата для домена «%s» в /etc/letsencrypt нет. Shadowrocket и Clash '
                            'проверяют отпечаток (pinSHA256/fingerprint) и защищены, а Loon пиннинг не '
                            'умеет — ему приходится доверять любому сертификату. Выпустите сертификат '
                            'для домена, и панель предложит переключиться.' % (domain or 'не задан')),
            'ok': True,
            'fix_cmd': '',
            'fixable': False,
        })
    return out


# === Установка протоколов из панели =========================================
# Каждая установка идёт по одной схеме: подобрать свободный порт → положить
# бинарь → сгенерировать конфиг (только если своего ещё нет) → написать юнит →
# открыть порт в фаерволе → запустить и проверить, что сервис действительно
# поднялся. Порт и ufw — общие механизмы (pick_free_port/ensure_firewall_port),
# чтобы правила выбора жили в одном месте для всех протоколов.

MTG_UNIT_FILE = '/etc/systemd/system/mtg.service'


# Куда Reality притворяется ходить. Сайт должен отдавать TLS 1.3 с H2 и быть
# заведомо живым — иначе маскировка разваливается при первой же проверке.
XRAY_REALITY_DEST = 'www.microsoft.com'


def _xray_base_config(port, inbound):
    """Каркас конфига: логи в наш каталог, stats+api (их ждёт панель), маршрутизация."""
    return {
        'log': {
            'access': XRAY_ACCESS_LOG,
            'error': f'{PANEL_LOGS_DIR}/xray_error.log',
            'loglevel': 'warning',
        },
        'stats': {},
        'api': {'tag': 'api', 'services': ['StatsService', 'HandlerService']},
        'policy': {
            'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True,
                             'statsUserOnline': True}},
            'system': {'statsInboundUplink': True, 'statsInboundDownlink': True},
        },
        'inbounds': [
            {
                'tag': 'api',
                'listen': '127.0.0.1',
                'port': 10085,
                'protocol': 'dokodemo-door',
                'settings': {'address': '127.0.0.1'},
            },
            inbound,
        ],
        'outbounds': [
            {'protocol': 'freedom', 'tag': 'direct'},
            {'protocol': 'blackhole', 'tag': 'block'},
        ],
        'routing': {
            'domainStrategy': 'IPIfNonMatch',
            'rules': [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'}],
        },
    }


def _install_xray():
    """Ставит XRay и поднимает рабочий инбаунд. (ok, сообщение).

    Режим выбирается по факту: есть сертификат Let's Encrypt — VLESS+TLS с
    фоллбеком на панель (тогда 443 остаётся входом и в панель тоже); нет —
    Reality, и тогда панели нужен свой порт, иначе она станет недоступна.
    """
    if not os.path.exists(XRAY_BIN):
        # Без --version установщик берёт последний НЕ-prerelease, а у XTLS
        # prerelease всё подряд — новый сервер получал ядро полугодовой давности
        # (v26.3.27 на 10.2026), без нынешних XDNS и adu для Hysteria. Ставим
        # тот же тег, что кнопка «Обновить» (см. system_update_proto).
        target = _github_latest_tag('XTLS/Xray-core')
        ver_arg = f' --version {target}' if re.match(r'^v?[\w.-]+$', target or '') else ''
        cmd = ('bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/'
               f'install-release.sh)" @ install{ver_arg}')
        proc = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=600)
        if proc.returncode != 0 or not os.path.exists(XRAY_BIN):
            return False, f'установщик XTLS не отработал: {(proc.stderr or proc.stdout)[-600:]}'
    if os.path.exists(XRAY_CONFIG):
        try:
            existing = load_xray_config()
        except Exception:
            existing = {}
        if existing.get('inbounds'):
            # Свой конфиг уже есть — перезаписать его значит выкинуть всех клиентов.
            ok, msg = _tgweb_before_xray()
            if not ok:
                return False, msg
            run_cmd('systemctl enable --now xray')
            _tgweb_reconcile_later()
            return True, 'XRay уже настроен — конфиг не трогали, сервис запущен'
    cert = _find_le_cert()
    if cert:
        # 443 может держать сам Telegram WEB (XRay не было) — TLS-режиму он
        # уступит порт и уйдёт за фоллбек. Без сертификата XRay встанет в
        # Reality и возьмёт другой свободный порт: Reality с WEB на 443 не живёт.
        _tgweb_before_xray('tls')
    port, busy = pick_free_port(443, 'tcp', 'xray')
    if not port:
        return False, f'не нашлось свободного TCP-порта под XRay ({busy})'

    uuid_str = str(uuid_lib.uuid4())
    note = ''
    if cert:
        full, key, domain = cert
        inbound = {
            'tag': 'vless-tls',
            'port': port,
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': uuid_str, 'email': 'admin', 'flow': 'xtls-rprx-vision'}],
                'decryption': 'none',
                # Фоллбек на Flask: всё, что не VLESS, уходит в панель — так 443
                # остаётся и входом в панель, как в остальной архитектуре.
                'fallbacks': _tgweb_wrap_fallbacks([{'dest': 5000, 'xver': 0}]),
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'tls',
                'tlsSettings': {
                    # Только http/1.1: h2 в ALPN ломает фоллбек на обычный HTTP.
                    'alpn': ['http/1.1'],
                    'certificates': [{'certificateFile': full, 'keyFile': key}],
                },
            },
        }
        note = f'VLESS+TLS на {domain}:{port}, панель доступна там же через фоллбек'
    else:
        out, err, rc = run_cmd(f'{XRAY_BIN} x25519')
        r_priv, r_pub = _parse_x25519((out or '') + '\n' + (err or ''))
        if rc != 0 or not (r_priv and r_pub):
            return False, f'не удалось сгенерировать ключи Reality: {err or out}'
        inbound = {
            # Тег именно 'vless-tls' и в режиме Reality: панель ищет инбаунд по
            # этому имени (XRAY_PARAMS['inbound_tag']), а не найдя — считает порт
            # равным 443, и клиентские ссылки уехали бы на несуществующий порт.
            'tag': 'vless-tls',
            'port': port,
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': uuid_str, 'email': 'admin', 'flow': 'xtls-rprx-vision'}],
                'decryption': 'none',
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'dest': f'{XRAY_REALITY_DEST}:443',
                    'serverNames': [XRAY_REALITY_DEST],
                    'privateKey': r_priv,
                    'publicKey': r_pub,
                    'shortIds': [secrets.token_hex(4)],
                },
            },
        }
        note = f'VLESS+Reality на {port} (маскировка под {XRAY_REALITY_DEST})'
    cfg = _xray_base_config(port, inbound)
    os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
    save_xray_config(cfg)
    ensure_firewall_port(port, 'tcp', 'XRay (awg-panel)')
    run_cmd('systemctl enable xray')
    run_cmd('systemctl restart xray')
    _tgweb_reconcile_later()
    time.sleep(2)
    state, _, _ = run_cmd('systemctl is-active xray')
    if state.strip() != 'active':
        out, _, _ = run_cmd('journalctl -u xray -n 20 --no-pager')
        return False, f'сервис не поднялся: {out[-800:]}'
    # Reality на 443 терминирует TLS сам и до панели уже ничего не доходит —
    # без своего порта админ потеряет доступ ровно в этот момент.
    if not cert and port == 443 and not int(SERVER_CFG.get('panel_port') or 0):
        try:
            res = _apply_panel_access_port(8081)
            SERVER_CFG['panel_port'] = 8081
            _save_server_config(SERVER_CFG)
            note += f'. Панель переведена на отдельный порт: {res.get("url") or "8081"}'
        except Exception as e:
            note += (f'. ВНИМАНИЕ: панель осталась на 443, где теперь Reality — '
                     f'включите свой порт панели вручную ({e})')
    audit('info', f'XRay установлен: {note}')
    return True, note


# Фоновые фиксы зависимостей. gunicorn запущен с --timeout 30, а certbot и
# установка бинарей столько не укладываются: воркера убивают на середине,
# клиент получает HTML-страницу 502 вместо JSON, а операция при этом
# продолжает выполняться. Поэтому долгие обработчики уходят в поток, а фронт
# опрашивает состояние.
_DEP_FIX_JOBS = {}
_DEP_FIX_LOCK = threading.Lock()
# Сколько держим завершённую задачу, чтобы фронт успел прочитать результат.
_DEP_FIX_TTL = 900


def _dep_fix_job_start(dep_id, fn, steps=None):
    """Запускает fn() в фоне и отдаёт ответ сразу. fn возвращает (ok, сообщение).

    Если передан список заголовков `steps`, операция становится пошаговой: fn
    вызывается как fn(progress), где progress(i, state, detail='') отмечает шаг
    ('run' | 'ok' | 'fail' | 'skip'). Состояние шагов уезжает во fix-status, и
    пользователь видит, на чём именно стоит установка, а не просто спиннер —
    для установки модуля ядра это разница между «панель зависла» и «идёт сборка
    DKMS, это долго».
    """
    now = int(time.time())
    with _DEP_FIX_LOCK:
        job = _DEP_FIX_JOBS.get(dep_id)
        if job and job.get('state') == 'running':
            # Повторный клик по той же кнопке не должен плодить вторую операцию.
            return {'ok': True, 'async': True, 'state': 'running'}
        # Заодно подчищаем старые записи, чтобы словарь не рос вечно.
        for k in [k for k, v in _DEP_FIX_JOBS.items()
                  if v.get('finished') and now - v['finished'] > _DEP_FIX_TTL]:
            _DEP_FIX_JOBS.pop(k, None)
        _DEP_FIX_JOBS[dep_id] = {
            'state': 'running', 'msg': '', 'started': now,
            'steps': [{'title': t, 'state': 'pending', 'detail': ''} for t in (steps or [])],
        }

    def _progress(i, state, detail=''):
        with _DEP_FIX_LOCK:
            job = _DEP_FIX_JOBS.get(dep_id) or {}
            rows = job.get('steps') or []
            if 0 <= i < len(rows):
                rows[i]['state'] = state
                if detail:
                    rows[i]['detail'] = str(detail)[-400:]

    def _worker():
        try:
            ok, msg = fn(_progress) if steps else fn()
        except Exception as e:
            ok, msg = False, str(e)
        with _DEP_FIX_LOCK:
            prev = _DEP_FIX_JOBS.get(dep_id) or {}
            _DEP_FIX_JOBS[dep_id] = {
                'state': 'done' if ok else 'error',
                'msg': msg or '',
                'started': now,
                'finished': int(time.time()),
                'steps': prev.get('steps') or [],
            }
        audit('info' if ok else 'warn',
              f'Dependency fix: {dep_id} → {"ok" if ok else "ошибка"}: {(msg or "")[:200]}')

    threading.Thread(target=_worker, daemon=True).start()
    return {'ok': True, 'async': True, 'state': 'running'}


@app.route('/api/system/dependencies/fix-status')
@login_required
def api_dep_fix_status():
    """Состояние фоновой операции: running / done / error / idle.

    Один и тот же реестр обслуживает и фиксы зависимостей, и обновления
    протоколов (ключ 'update:<proto>') — механизм ожидания на фронте общий.
    """
    dep_id = (request.args.get('id') or '').strip()
    with _DEP_FIX_LOCK:
        job = dict(_DEP_FIX_JOBS.get(dep_id) or {'state': 'idle', 'msg': ''})
    return jsonify(job)


def _system_apply_fix(dep_id):
    """Выполняет shell-команду fix_cmd для конкретного dep по id."""
    items = _system_check_dependencies()
    target = next((i for i in items if i['id'] == dep_id), None)
    if not target:
        return {'ok': False, 'error': f'Unknown dependency id: {dep_id}'}
    if not target.get('fixable'):
        return {'ok': False, 'error': 'Эту проверку нельзя починить автоматически'}
    # Internal handlers — не shell, а прямой вызов внутренней функции.
    if target.get('fix_internal') == 'hysteria_cert_le':
        try:
            from modules.hysteria import service as hy_service
            ok, err = hy_service.apply_cert_mode('le')
            if not ok:
                return {'ok': False, 'error': err}
            return {'ok': True, 'output': 'Hysteria переведена на сертификат домена'}
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
    if target.get('fix_internal') == 'hysteria_hop_on':
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}

        def _hop_on():
            ok, res = hy_service.set_hop(True)
            if not ok:
                return False, res
            return True, ('порт-хоппинг включён: %s/udp, смена раз в %d с — выданные ссылки работают '
                          'как раньше' % (res.get('active'), res.get('interval')))
        return _dep_fix_job_start(dep_id, _hop_on)
    if target.get('fix_internal') == 'hysteria_acme_http':
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
        return _dep_fix_job_start(dep_id, hy_service.ensure_acme_http)
    if target.get('fix_internal') == 'hysteria_cert_renew':
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
        # В фон: certbot ходит в Let's Encrypt и в 30-секундный таймаут gunicorn
        # укладывается не всегда.
        return _dep_fix_job_start(dep_id, hy_service.renew_cert)
    if target.get('fix_internal') == 'hysteria_renew_hook':
        try:
            from modules.hysteria import service as hy_service
            ok, err = hy_service.install_renew_hook()
            if not ok:
                return {'ok': False, 'error': err}
            return {'ok': True, 'output': 'deploy-hook certbot установлен'}
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
    if target.get('fix_internal') == 'tgweb_setup':
        try:
            from modules.tgweb import service as tg_service
        except Exception as e:
            return {'ok': False, 'error': f'Telegram WEB: {e}'}
        # Те же шаги и тот же ключ задачи, что у кнопки на вкладке и в блоке
        # версий: повторный клик не запустит вторую установку.
        return _dep_fix_job_start('install:tgweb', tg_service.setup, steps=tg_service.SETUP_STEPS)
    # Установка XRay / mtg из «Зависимостей» и баннера на вкладке. Раньше пункты
    # proto_*_missing ссылались на эти обработчики, а самих веток не было — кнопка
    # отвечала «Unknown»/пустой командой. Ключи задач — общие с блоком версий.
    if target.get('fix_internal') == 'tgweb_move_ports':
        try:
            from modules.tgweb import service as tg_service
        except Exception as e:
            return {'ok': False, 'error': f'Telegram WEB: {e}'}
        busy = [it['port'] for it in _tgweb_port_items() if it['kind'] != 'tgweb_front'
                and port_conflict(it['port'], 'tcp', ignore_kind=it['kind'], include_idle=True)]
        return _dep_fix_job_start(dep_id, lambda: tg_service.move_ports(busy))
    if target.get('fix_internal') == 'xray_install':
        return _dep_fix_job_start('install:xray', _install_xray)
    if target.get('fix_internal') == 'mtg_install':
        return _dep_fix_job_start('install:mtg', _install_mtg)
    if target.get('fix_internal') == 'hysteria_setup':
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}

        def _hy_setup_job():
            ok, note = hy_service.setup()
            if not ok:
                return False, note
            return True, ('Hysteria 2 установлена и запущена. %s' % note).strip()

        # В фон: скачивание бинаря с GitHub легко перерастает таймаут gunicorn.
        return _dep_fix_job_start(dep_id, _hy_setup_job)
    # Мелкие починки Hysteria — одним обработчиком: все они делают ровно один
    # вызов в пакет протокола, и разводить под каждую свою ветку незачем.
    _HY_SIMPLE_FIX = {
        'hysteria_rewrite_config': 'конфиг перегенерирован',
        'hysteria_fix_auth': 'скрипту авторизации возвращён бит +x',
        'hysteria_open_port': 'UDP-порт открыт в ufw',
        'hysteria_enable_unit': 'автозапуск включён',
        'hysteria_mk_logdir': 'каталог логов создан',
        'hysteria_mk_datadir': 'каталог данных создан',
    }
    if target.get('fix_internal') in _HY_SIMPLE_FIX:
        kind = target['fix_internal']
        try:
            from modules.hysteria import service as hy_service
            from modules.hysteria import (AUTH_SCRIPT, DATA_DIR as HY_DATA_DIR,
                                          ACCESS_LOG as HY_ACCESS_LOG,
                                          UNIT_NAME as HY_UNIT, load_settings)
            if kind == 'hysteria_rewrite_config':
                hy_service.write_config()
                hy_service.restart()
            elif kind == 'hysteria_fix_auth':
                os.chmod(AUTH_SCRIPT, 0o755)
            elif kind == 'hysteria_open_port':
                hy_service.ensure_firewall(int(load_settings().get('port') or 443))
            elif kind == 'hysteria_enable_unit':
                run_cmd(f'systemctl enable {HY_UNIT}')
            elif kind == 'hysteria_mk_logdir':
                os.makedirs(os.path.dirname(HY_ACCESS_LOG), exist_ok=True)
            elif kind == 'hysteria_mk_datadir':
                os.makedirs(HY_DATA_DIR, exist_ok=True)
            return {'ok': True, 'output': _HY_SIMPLE_FIX[kind]}
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
    if target.get('fix_internal') == 'xray_hy_open_port':
        try:
            port = int((xhy.status() or {}).get('port') or 0)
            ensure_firewall_port(port, 'udp', 'Hysteria (awg-panel)')
            return {'ok': True, 'output': f'UDP-порт {port} открыт в ufw'}
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
    if target.get('fix_internal') == 'xray_hy_move_port':
        # Один обработчик на два случая: инбаунд прописан на занятом порту и
        # инбаунд не поднялся вовсе. Оба лечатся одинаково — свободным портом.
        if not xhy:
            return {'ok': False, 'error': 'модуль Hysteria не подключён'}
        try:
            st = xhy.status() or {}
            busy = _hy_udp_busy()
            port, _ = pick_free_port(0, 'udp', 'hysteria', extra_busy=tuple(busy.keys()))
            if not port:
                return {'ok': False, 'error': 'свободный UDP-порт не нашёлся'}
            s = xhy.read_settings()
            s['port'] = int(port)
            ok, err = xhy.apply_inbound(s)
            if not ok:
                return {'ok': False, 'error': err}
            SERVER_CFG['hysteria_autoenable_note'] = ''
            _save_server_config(SERVER_CFG)
            was = int(st.get('port') or 0)
            # Про перевыпуск ссылок предупреждаем только если инбаунд реально
            # работал на другом порту: у выключенного ссылок ещё не было.
            moved = bool(st.get('enabled')) and was and was != int(port)
            audit('info', f'[Hysteria] инбаунд поднят на UDP {port}'
                          + (f' (был {was})' if moved else ''))
            return {'ok': True, 'output': (f'Инбаунд переехал с {was}/udp на {port}/udp. Ссылки клиентов надо '
                                           'выдать заново — порт зашит в ссылку.' if moved
                                           else f'Инбаунд поднят на {port}/udp')}
        except Exception as e:
            return {'ok': False, 'error': f'Hysteria: {e}'}
    if target.get('fix_internal') in ('awg_install', 'awg_update'):
        # Модуль ядра собирается минутами — только в фон, иначе gunicorn оборвёт
        # запрос по таймауту и пользователь увидит 502 вместо результата.
        if not awg_install:
            return {'ok': False, 'error': 'модуль awg_install.py не загружен'}
        if target['fix_internal'] == 'awg_install':
            return _dep_fix_job_start(dep_id, awg_install.install,
                                      steps=awg_install.INSTALL_STEPS)
        return _dep_fix_job_start(dep_id, awg_install.update,
                                  steps=awg_install.UPDATE_STEPS)
    if target.get('fix_internal') == 'geo_update':
        try:
            remote_v = _fetch_remote_geo_version()
            if not remote_v:
                return {'ok': False, 'error': 'Не удалось получить версию гео с CDN'}
            data_dir = DATA_GEO_DIR
            os.makedirs(data_dir, exist_ok=True)
            for local_name, remote_name in GEO_FILES.items():
                url = GEO_BASE_URL.rstrip('/') + '/' + remote_name
                data = _http_get_bytes(url, timeout=120)
                t = os.path.join(data_dir, local_name)
                tmp = t + '.tmp'
                with open(tmp, 'wb') as f:
                    f.write(data)
                os.replace(tmp, t)
            _write_local_geo_version(remote_v)
            subprocess.Popen([
                'systemd-run', '--no-block', '--collect',
                '/bin/bash', '-c',
                'sleep 2 && systemctl restart awg-panel'
            ])
            audit('info', f'Geo update via deps fix: v{remote_v}')
            return {
                'ok': True,
                'output': f'Обновлено до v{remote_v}. Панель перезапускается чтобы перечитать БД.',
                'new_status': True,
                'requires_restart': True,
            }
        except Exception as e:
            return {'ok': False, 'error': f'Geo update failed: {e}'}
    if target.get('fix_internal') == 'xray_enable_stats':
        try:
            changed = patch_xray_for_stats()
            SERVER_CFG['xray_stats_wanted'] = True
            _save_server_config(SERVER_CFG)
            if changed:
                schedule_xray_restart()
            audit('info', f'XRay stats enabled via deps fix (changed={changed})')
            return {
                'ok': True,
                'output': ('Секции stats/api/policy добавлены, xray перезапускается. '
                           'Подождите ~3 сек.' if changed else 'Статистика уже была настроена.'),
                'new_status': True,
                'requires_restart': changed,
            }
        except Exception as e:
            return {'ok': False, 'error': f'Enable stats failed: {e}'}
    if target.get('fix_internal') == 'proto_update':
        return _proto_update_start(target.get('update_proto') or '', dep_id)
    # Живые проверки протоколов (modules/proto_health.py).
    _ph_kind = target.get('fix_internal') or ''
    if _ph_kind.startswith('ph_'):
        if not proto_health:
            return {'ok': False, 'error': 'модуль proto_health.py не загружен'}
        if target.get('long'):
            # Перевыпуск сертификата ходит в Let's Encrypt — в фон, иначе
            # gunicorn оборвёт запрос по таймауту.
            return _dep_fix_job_start(dep_id, lambda: proto_health.fix(_ph_kind) or (False, 'неизвестная починка'))
        try:
            res = proto_health.fix(_ph_kind)
        except Exception as e:
            return {'ok': False, 'error': str(e)}
        if res is None:
            return {'ok': False, 'error': f'неизвестная починка {_ph_kind}'}
        ok, msg = res
        return {'ok': ok, 'output': msg if ok else '', 'error': '' if ok else msg,
                'new_status': ok, 'requires_restart': False}
    cmd = target['fix_cmd']
    # Долгие фиксы (apt install) — больше времени.
    timeout_sec = int(target.get('timeout_sec') or (240 if 'apt-get' in cmd or 'apt install' in cmd else 60))
    try:
        proc = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout_sec)
        out = (proc.stdout or '') + (proc.stderr or '')
        success = proc.returncode == 0
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    needs_restart = target.get('requires_restart', False)
    # Если фикс запланировал отложенный рестарт сервиса (systemd-run --no-block + sleep),
    # ответ должен УСПЕТЬ дойти до браузера ДО того как сервис рестартует.
    # Поэтому recheck (который сам делает systemctl-вызовы) тут пропускаем — лишний overhead.
    triggers_service_restart = 'systemd-run --no-block' in cmd
    new_state = success  # по умолчанию доверяем exit-коду
    if not triggers_service_restart and not needs_restart:
        # Безопасно — фикс не рвёт соединение, можно делать recheck.
        try:
            new_items = _system_check_dependencies()
            new_state = next((i for i in new_items if i['id'] == dep_id), {}).get('ok', False)
        except Exception:
            new_state = success
    return {
        'ok': success and (new_state or needs_restart),
        'output': out[-2000:],
        'new_status': new_state,
        'requires_restart': needs_restart,
    }

def _proto_extra_items(proto):
    """Пункты протокола, которых нет в «Зависимостях»: сервис упал или
    остановлен, выключен автозапуск, XDNS включён, а запросы не доходят.

    «Зависимости» остановленный протокол не проверяют намеренно (это решение
    пользователя), а окну ⚙ и значкам на главной состояние сервиса нужно.
    """
    out = []
    if not proto_health or proto not in SERVICE_UNITS:
        return out
    st = _proto_state(proto)
    if st == 'stopped':
        it = proto_health.service_item(proto, PROTO_TITLES.get(proto, proto), SERVICE_UNITS[proto][0])
        if proto == 'xray':
            # Пока XRay лежит, 443 может держать Telegram WEB. Это касается XRay
            # только в момент запуска — тут и говорим, уровень прежний (совет).
            note, blocked = _tgweb_xray_start_note()
            if note:
                it['description'] = it['description'] + ' ' + note
                if blocked:
                    # «Запустить» всё равно получит отказ — кнопка только путает.
                    it.pop('ui', None)
                    it.pop('ui_label', None)
        out.append(it)
    elif st == 'active' and not _service_state_blob(proto).get('autostart'):
        # Работает сейчас, но после перезагрузки сервера не поднимется —
        # клиенты узнают об этом первыми, а причину потом не найти.
        out.append({
            'id': 'svc_autostart', 'level': 'warn', 'scope': 'core' if proto == 'xray' else '*',
            'name': 'Автозапуск %s выключен' % PROTO_TITLES.get(proto, proto),
            'description': 'Сейчас сервис работает, но после перезагрузки сервера сам не поднимется — '
                           'клиенты останутся без связи, пока его не запустят вручную.',
            'ok': False, 'fixable': False, 'ui': 'autostart_on', 'ui_label': 'Включить автозапуск',
        })
    if proto == 'xray' and st == 'active' and xdns:
        # Свою цепочку XDNS показывает вкладка XDNS (scope 'xdns' в общий блок
        # не попадает), а здесь — чтобы значок на главной знал о ней.
        try:
            on = xdns.enabled()
        except Exception:
            on = False
        c = _XDNS_LAST_CHECK
        if on and c.get('ts') and not c.get('ok'):
            out.append({'id': 'xdns_chain', 'level': 'warn', 'scope': 'xdns',
                        'name': 'XDNS включён, но запросы до сервера не доходят',
                        'description': 'Подробности и что сделать — во вкладке XDNS.',
                        'ok': False, 'fixable': False})
    return out


def _proto_alert_summary(items):
    """Худший уровень непройденных пунктов протокола: для значка на главной.
    Советы на главной не сигналят."""
    lv = [proto_health.level_of(i) if proto_health else 'warn' for i in items if not i.get('ok')]
    worst = 'block' if 'block' in lv else ('warn' if 'warn' in lv else '')
    top = next((i.get('name', '') for i in items
                if not i.get('ok') and worst and (proto_health.level_of(i) if proto_health else 'warn') == worst), '')
    return {'level': worst, 'count': sum(1 for x in lv if x != 'tip'), 'top': top}


@app.route('/api/proto/health', methods=['GET'])
@login_required
def proto_health_get():
    """Что мешает протоколу работать — для блока «Чтобы … заработал» в окне ⚙.

    Те же пункты, что в «Зависимостях», но только этого протокола (прогонять все
    проверки ради одного окна незачем) и только непройденные, с уровнем
    важности и вкладкой окна XRay. Остановленный сервис — первым шагом: пока
    он лежит, остальные проверки протокола не делаются.
    """
    proto = (request.args.get('proto') or '').strip()
    if proto not in ('awg', 'xray', 'mtg', 'hysteria', 'tgweb'):
        return jsonify({'ok': False, 'error': 'Unknown protocol'}), 400
    items = [i for i in _system_check_dependencies(groups=[proto])
             if i.get('group') == proto and not i.get('ok')]
    items = _proto_extra_items(proto) + items
    order = {'block': 0, 'warn': 1, 'tip': 2}
    out = []
    for i in items:
        lvl = proto_health.level_of(i) if proto_health else 'warn'
        out.append({
            'id': i['id'], 'name': i.get('name', ''), 'description': i.get('description', ''),
            'level': lvl, 'scope': (proto_health.scope_of(i) if proto == 'xray' else '*') if proto_health else '*',
            'fixable': bool(i.get('fixable')), 'long': bool(i.get('long')),
            'eta_hint': i.get('eta_hint', ''),
            'requires_restart': bool(i.get('requires_restart')) or 'systemctl restart' in (i.get('fix_cmd') or ''),
            'ui': i.get('ui', ''), 'ui_label': i.get('ui_label', ''),
        })
    out.sort(key=lambda x: order.get(x['level'], 1))
    return jsonify({'ok': True, 'proto': proto, 'items': out, 'ts': time.time()})


@app.route('/api/system/dependencies', methods=['GET'])
@login_required
def system_dependencies_get():
    items = _system_check_dependencies()
    for i in items:
        i['level'] = proto_health.level_of(i) if proto_health else 'warn'
    # ⚠ в шапке и счётчики — только то, что надо чинить: советы не сигналят.
    important = [i for i in items if not i['ok'] and i['level'] != 'tip']
    audit_count = len(important)
    # Раскладка по вкладкам и счётчик проблем в каждой — чтобы UI подсвечивал
    # именно ту вкладку, где что-то не так, а не общий значок.
    groups = []
    for key, title in DEP_GROUPS:
        grp = [i for i in items if i.get('group') == key]
        if not grp:
            continue
        groups.append({
            'key': key,
            'title': title,
            'total': len(grp),
            'failing': sum(1 for i in grp if not i['ok'] and i['level'] != 'tip'),
            'tips': sum(1 for i in grp if not i['ok'] and i['level'] == 'tip'),
        })
    # Значки на главной: худший уровень по каждому протоколу, вместе с тем,
    # чего в «Зависимостях» нет (сервис упал, автозапуск, XDNS).
    enabled = SERVER_CFG.get('enabled_protocols')
    if not isinstance(enabled, list):
        enabled = ['awg', 'xray', 'mtg', 'hysteria', 'tgweb']
    protos = {}
    for p in ('awg', 'xray', 'mtg', 'hysteria', 'tgweb'):
        if p not in enabled:
            continue
        try:
            extra = _proto_extra_items(p)
        except Exception as e:
            audit('warn', f'proto alerts {p}: {e}')
            extra = []
        protos[p] = _proto_alert_summary(extra + [i for i in items if i.get('group') == p])
    return jsonify({'items': items, 'failing': audit_count,
                    'level': 'block' if any(i['level'] == 'block' for i in important) else
                             ('warn' if important else ''),
                    'groups': groups, 'protos': protos})

@app.route('/api/system/external-ip', methods=['GET'])
@login_required
def system_external_ip():
    """Публичный IP сервера глазами внешнего мира.
    Нужен облакам с NAT (Yandex Cloud, GCP, AWS): там белый адрес висит на NAT
    провайдера и не виден ни в `ip addr`, ни в `ip route get` — выбрать его из
    списка интерфейсов невозможно, только вписать руками. Запрос идёт с сервера
    (не из браузера админа!), поэтому возвращается именно исходящий IP сервера.
    Ничего не сохраняет — только подсказывает значение для поля override."""
    try:
        data = json.loads(_http_get_text('https://api.ru.dog/v1/me', timeout=6))
    except Exception as e:
        return jsonify({'ok': False, 'error': f'api.ru.dog недоступен: {e}'})
    ip = str((data or {}).get('ip') or '').strip()
    if not _is_valid_ipv4(ip):
        return jsonify({'ok': False, 'error': f'Ответ без IPv4 (получено: {ip or "пусто"})'})
    return jsonify({
        'ok': True,
        'ip': ip,
        'country': str((data or {}).get('country') or ''),
        'city': str((data or {}).get('city') or ''),
        'matches_local': any(a['ip'] == ip for a in _list_server_ipv4s()),
    })

def listening_sockets():
    """Кто реально слушает порты: [{proto, port, addr, process}, …] из `ss -tulnp`.

    Конфиги говорят, какой порт сервис ДОЛЖЕН занять, а это — какой занят на самом
    деле. Расхождение объясняет случаи вида «сервис не стартует, порт занят», где
    иначе видно только exit-код.
    """
    out, _, rc = run_cmd('ss -tulnp')
    if rc != 0 or not out:
        return []
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ('tcp', 'udp'):
            continue
        local = parts[4]
        # IPv6 приходит как [::]:443, IPv4 как 0.0.0.0:443 — порт всегда после последнего ':'
        if ':' not in local:
            continue
        addr, _, port = local.rpartition(':')
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        rows.append({
            'proto': proto,
            'port': int(port),
            'addr': addr,
            'process': m.group(1) if m else '',
        })
    # У сокетов ядра владельца в ss нет вовсе — так выглядит WireGuard/AmneziaWG.
    # Без этой подстановки в UI висело бы бесполезное «процесс не определён»,
    # хотя порт занят вполне конкретным, видимым в панели сервисом.
    try:
        awg_port = int(get_awg_listen_port())
    except Exception:
        awg_port = 0
    for r in rows:
        if r['process']:
            continue
        if awg_port and r['proto'] == 'udp' and r['port'] == awg_port:
            r['process'] = 'AmneziaWG (сокет ядра)'
        else:
            r['process'] = 'сокет ядра (процесса нет)'
    return rows


def port_owner(port, proto='udp'):
    """Имя процесса, слушающего порт, или '' если свободен."""
    try:
        for s in listening_sockets():
            if s['port'] == int(port) and s['proto'] == proto:
                return s['process'] or 'неизвестный процесс'
    except Exception:
        pass
    return ''


# === Подбор порта и фаервол — общий механизм для всех протоколов ==============
# Установщик любого протокола сначала спрашивает, свободен ли желаемый порт, и
# при необходимости берёт запасной, а потом открывает выбранный в ufw. Без этого
# сервис поднимался бы и тут же падал на «address already in use» либо работал
# при закрытом порте — снаружи это неотличимо от «не работает».

# Запасные порты по протоколам. Первым идёт «типовой» — тот, что меньше всего
# похож на VPN со стороны наблюдателя; дальше обычно свободные и не экзотичные.
PORT_CANDIDATES = {
    'xray': [443, 8443, 2053, 2083, 2087],
    'mtg': [8443, 8444, 2087, 2096, 9443],
    # Hysteria — UDP. 443 первым: снаружи это обычный HTTP/3, и он не мешает
    # VLESS на 443/tcp (разные сокеты). Но именно 443/udp по умолчанию берёт
    # AmneziaWG, а его сокет живёт в ядре и в `ss` бывает без имени процесса —
    # поэтому порт AWG докладывается в extra_busy отдельно, по awg0.conf.
    'hysteria': [443, 8443, 2053, 2083, 2096],
    # Порт панели: 443 сюда не входит принципиально — он и так занят XRay, ради
    # чего вся эта история и затевается.
    'panel': [2096, 8081, 2087, 2053, 9443],
}


def pick_free_port(preferred, proto='tcp', kind='', extra_busy=()):
    """(порт, кто занимал желаемый) — свободный порт для сервиса.

    extra_busy — порты, которые панель считает занятыми, даже если сейчас на них
    никто не слушает: например, порт остановленного сервиса, который вот-вот
    поднимется обратно. Возвращает (0, причина), если свободных не осталось.
    """
    preferred = int(preferred or 0)
    busy = {int(p) for p in extra_busy if p}
    taken_by = port_owner(preferred, proto) if preferred else ''
    if preferred and not taken_by and preferred not in busy:
        return preferred, ''
    for port in PORT_CANDIDATES.get(kind, []):
        if port == preferred or port in busy:
            continue
        if not port_owner(port, proto):
            return port, (taken_by or 'занят')
    return 0, (taken_by or 'свободных портов не нашлось')


def ufw_active():
    out, _, rc = run_cmd('ufw status 2>/dev/null')
    return (rc == 0 and 'Status: active' in (out or '')), (out or '')


def ufw_port_open(port, proto='tcp'):
    """Пропускает ли ufw порт для всех (True и при выключенном ufw).

    Подстрокой «53/udp» в выводе `ufw status` проверять нельзя: она находит и
    «5353/udp», и правило «53/udp on awg0» (DNS только для клиентов AWG, его
    ставит «Логи+»), — и панель рапортовала «порт открыт», а снаружи он закрыт.
    Разбор — modules/proto_health.ufw_allows: диапазоны, правила без протокола,
    профили «Nginx Full», правила на интерфейс.
    """
    ph = globals().get('proto_health')
    if ph:
        try:
            return ph.ufw_allows(port, proto)[1]
        except Exception:
            pass
    active, status = ufw_active()
    return (not active) or bool(re.search(r'(?m)^%d/%s\s+ALLOW' % (int(port), proto), status or ''))


def ensure_firewall_port(port, proto='tcp', comment='awg-panel'):
    """Открывает порт в ufw, если тот включён. (сделано, ошибка).

    Когда ufw выключен — ничего не делаем и не считаем это ошибкой: фаервола
    просто нет, порт и так открыт.
    """
    active, status = ufw_active()
    if not active or not port:
        return False, ''
    rule = f'{int(port)}/{proto}'
    if ufw_port_open(port, proto):
        return False, ''
    _, err, rc = run_cmd(f"ufw allow {rule} comment '{comment}'")
    if rc != 0:
        audit('warn', f'ufw: не удалось открыть {rule}: {err}')
        return False, err
    audit('info', f'ufw: открыт {rule} ({comment})')
    return True, ''


# === Фаервол и fail2ban ======================================================
#
# Вкладка «Фаервол» в окне «Здоровье сервера». Панель ничего не изобретает: ufw
# правится ufw-командами, fail2ban — fail2ban-client'ом, а свои настройки (список
# исключений и параметры бана) пишутся в отдельный jail.d-файл. Так ручные
# правки админа в jail.local не затираются, а изменения панели видно одним
# файлом и легко откатить.

F2B_PANEL_JAIL_FILE = '/etc/fail2ban/jail.d/awg-panel.local'

# Разрешённые значения в командах — чтобы в shell не уехало ничего лишнего.
_RE_IP4 = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
_RE_CIDR4 = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$')
_RE_IP6 = re.compile(r'^[0-9A-Fa-f:]{2,45}(/\d{1,3})?$')
_RE_JAIL = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')


def _valid_ip_or_cidr(value):
    """IPv4, IPv4/маска или IPv6 — иначе пусто. Не доверяем фронту: эта строка
    уезжает в аргумент команды."""
    v = (value or '').strip()
    m = _RE_IP4.match(v) or _RE_CIDR4.match(v)
    if m:
        octets = m.groups()[:4]
        if any(int(o) > 255 for o in octets):
            return ''
        if len(m.groups()) == 5 and int(m.group(5)) > 32:
            return ''
        return v
    if ':' in v and _RE_IP6.match(v):
        return v
    return ''


def _valid_port_spec(value):
    """`443` или `20000:20100` (диапазон в синтаксисе ufw). Иначе пусто."""
    v = (value or '').strip().replace('-', ':')
    if v.isdigit():
        return v if 1 <= int(v) <= 65535 else ''
    if ':' in v:
        a, _, b = v.partition(':')
        if a.isdigit() and b.isdigit() and 1 <= int(a) <= int(b) <= 65535:
            return '%s:%s' % (a, b)
    return ''


def _ufw_rules():
    """Пронумерованные правила ufw. Номер нужен для удаления: `ufw delete N`."""
    out, _, rc = run_cmd('ufw status numbered 2>/dev/null')
    if rc != 0 or not out:
        return []
    rules = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('['):
            continue
        try:
            num_part, rest = line.split(']', 1)
            num = int(num_part.lstrip('[').strip())
        except ValueError:
            continue
        comment = ''
        if '#' in rest:
            rest, _, comment = rest.partition('#')
            comment = comment.strip()
        # Колонки разделены двумя и более пробелами — так ufw и печатает.
        cols = [c for c in re.split(r'\s{2,}', rest.strip()) if c]
        if len(cols) < 2:
            continue
        rules.append({
            'num': num,
            'to': cols[0],
            'action': cols[1],
            'from': cols[2] if len(cols) > 2 else 'Anywhere',
            'comment': comment,
        })
    return rules


def _f2b_installed():
    return bool(shutil.which('fail2ban-client'))


def _f2b_jail_names():
    out, _, rc = run_cmd('fail2ban-client status 2>/dev/null')
    if rc != 0:
        return []
    for line in (out or '').splitlines():
        if 'Jail list' in line:
            _, _, tail = line.partition(':')
            return [j.strip() for j in tail.split(',') if j.strip()]
    return []


def _f2b_get(jail, key):
    out, _, rc = run_cmd('fail2ban-client get %s %s 2>/dev/null' % (jail, key))
    return (out or '').strip() if rc == 0 else ''


def _f2b_scalar(raw):
    """Числовой параметр jail. Обычно fail2ban печатает голое значение, но если
    вдруг обернул его во фразу — берём из строки само число, а не весь текст."""
    text = (raw or '').strip()
    if not text or ' ' not in text and '\n' not in text:
        return text
    for tok in reversed(text.split()):
        if re.match(r'^-?\d+[smhdw]?$', tok):
            return tok
    return ''


def _f2b_parse_ignoreip(raw):
    """Исключения из вывода `fail2ban-client get <jail> ignoreip`.

    Формат зависит от версии: 0.x печатает питоновский литерал списка, 1.x —
    заголовок «These IP addresses/networks are ignored:» и дерево из `|-`/`` `- ``.
    Разбираем оба текстом (eval'ить вывод команды нельзя даже своей); иначе
    заголовок вместе с ветками уезжает в UI одной строкой.
    """
    text = (raw or '').strip()
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    tree = [ln for ln in lines if ln[:2] in ('|-', '`-', '|_', '- ')]
    if tree:
        items = [ln[2:].strip() for ln in tree]
    elif lines[0][:1].isalpha():
        # Заголовок без веток — «No IP address/network is ignored».
        items = []
    else:
        items = text.strip('[]').replace(',', ' ').split()
    out = []
    for tok in items:
        tok = tok.strip().strip("'\",[]")
        if tok and tok not in out:
            out.append(tok)
    return out


def _f2b_jail(name):
    out, _, rc = run_cmd('fail2ban-client status %s 2>/dev/null' % name)
    info = {'name': name, 'banned': [], 'currently_banned': 0, 'total_banned': 0,
            'currently_failed': 0, 'total_failed': 0, 'files': ''}
    if rc != 0:
        return info
    for raw in (out or '').splitlines():
        line = raw.strip(' |`-\t')
        key, _, val = line.partition(':')
        key, val = key.strip().lower(), val.strip()
        if key == 'currently failed':
            info['currently_failed'] = int(val or 0) if val.isdigit() else 0
        elif key == 'total failed':
            info['total_failed'] = int(val or 0) if val.isdigit() else 0
        elif key == 'currently banned':
            info['currently_banned'] = int(val or 0) if val.isdigit() else 0
        elif key == 'total banned':
            info['total_banned'] = int(val or 0) if val.isdigit() else 0
        elif key == 'banned ip list':
            info['banned'] = [ip for ip in val.split() if ip]
        elif key == 'file list':
            info['files'] = val
    for key in ('bantime', 'findtime', 'maxretry'):
        info[key] = _f2b_scalar(_f2b_get(name, key))
    info['ignoreip'] = _f2b_parse_ignoreip(_f2b_get(name, 'ignoreip'))
    return info


def _f2b_panel_overrides():
    """Что панель дописала в свой jail.d-файл. Пусто — значит ничего не трогали."""
    if not os.path.isfile(F2B_PANEL_JAIL_FILE):
        return {}
    data, section = {}, ''
    try:
        with open(F2B_PANEL_JAIL_FILE, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1]
                    data.setdefault(section, {})
                elif '=' in line and section and not line.startswith('#'):
                    k, _, v = line.partition('=')
                    data[section][k.strip()] = v.strip()
    except Exception:
        return {}
    return data


def _f2b_write_overrides(data):
    """Перезапись своего jail.d-файла целиком + reload. Чужие файлы не трогаем."""
    os.makedirs(os.path.dirname(F2B_PANEL_JAIL_FILE), exist_ok=True)
    lines = ['# Файл создан панелью awg-panel (Здоровье сервера → Фаервол).',
             '# Правки здесь перезаписываются панелью; свои настройки держите в jail.local.',
             '']
    for section in sorted(data):
        vals = {k: v for k, v in (data[section] or {}).items() if str(v).strip() != ''}
        if not vals:
            continue
        lines.append('[%s]' % section)
        for k in sorted(vals):
            lines.append('%s = %s' % (k, vals[k]))
        lines.append('')
    with open(F2B_PANEL_JAIL_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    run_cmd('fail2ban-client reload')


@app.route('/api/system/firewall', methods=['GET'])
@login_required
def system_firewall_get():
    """Полная картина: что открыто, что слушает, кто забанен."""
    ufw_present = bool(shutil.which('ufw'))
    active, status_out = ufw_active() if ufw_present else (False, '')
    default_in = ''
    for line in (status_out or '').splitlines():
        if line.strip().startswith('Default:'):
            default_in = line.split(':', 1)[1].strip()
            break

    # Порты, которые панель считает своими: их закрытие ломает доступ, и в UI
    # они помечаются, чтобы такое правило не удалили случайно.
    known = {}

    def _known_add(port, title):
        """Подпись к порту. Складываем, а не затираем: на одном номере законно
        живут разные сервисы по разным протоколам — VLESS на 443/tcp и Hysteria
        на 443/udp, а на части серверов там же AmneziaWG. Затирание подписывало
        бы правило именем случайного последнего."""
        try:
            p = int(port or 0)
        except (TypeError, ValueError):
            return
        if not p:
            return
        cur = known.get(p)
        known[p] = title if not cur else (cur if title in cur else f'{cur} + {title}')

    try:
        xp = get_xray_inbound_params()
        _known_add(xp.get('port'), 'XRay')
    except Exception:
        pass
    # Инбаунд Hysteria слушает UDP рядом с VLESS на TCP: номер может совпадать,
    # и без подписи строка в «Фаерволе» выглядела бы дублем правила XRay.
    try:
        if xhy and xhy.enabled():
            _known_add(xhy.read_settings().get('port'), 'Hysteria в XRay (UDP)')
    except Exception:
        pass
    try:
        if xdns and xdns.enabled():
            _known_add(xdns.PORT, 'XDNS в XRay (DNS-туннель)')
    except Exception:
        pass
    try:
        hy_t = _hysteria_truths_blob()
        if hy_t.get('port'):
            _known_add(hy_t['port'], 'Hysteria 2 (UDP)')
    except Exception:
        pass
    # Внутренние порты Telegram WEB слушают только 127.0.0.1 — правил ufw для
    # них нет, но в таблице слушающих сокетов они видны, и без подписи
    # выглядели бы чужими процессами.
    for _it in _tgweb_port_items():
        _known_add(_it['port'], _it['who'])
    for port, title in ((get_mtg_listen_port(), 'MTProto'), (get_awg_listen_port(), 'AmneziaWG'),
                        (SERVER_CFG.get('panel_port') or 0, 'Панель')):
        try:
            _known_add(port, title)
        except Exception:
            pass

    f2b = {'installed': _f2b_installed(), 'active': False, 'jails': [],
           'overrides': _f2b_panel_overrides()}
    if f2b['installed']:
        _, _, rc = run_cmd('systemctl is-active --quiet fail2ban')
        f2b['active'] = (rc == 0)
        if f2b['active']:
            f2b['jails'] = [_f2b_jail(n) for n in _f2b_jail_names()]

    return jsonify({
        'ufw': {
            'installed': ufw_present,
            'active': active,
            'default_incoming': default_in,
            'rules': _ufw_rules(),
        },
        'listening': sorted(listening_sockets(), key=lambda s: (s['port'], s['proto'])),
        'known_ports': {str(k): v for k, v in known.items()},
        'fail2ban': f2b,
    })


@app.route('/api/system/firewall/rule', methods=['POST'])
@login_required
def system_firewall_rule():
    """allow / deny / delete правила ufw. Порт и адрес проверяются здесь же."""
    body = request.get_json(force=True) or {}
    action = (body.get('action') or '').strip()
    if not shutil.which('ufw'):
        return jsonify({'ok': False, 'error': 'ufw на сервере не установлен'}), 400

    if action == 'delete':
        try:
            num = int(body.get('num'))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'нужен номер правила'}), 400
        out, err, rc = run_cmd('yes | ufw delete %d' % num)
        if rc != 0:
            return jsonify({'ok': False, 'error': err or out or 'ufw вернул ошибку'}), 500
        audit('warn', f'ufw: удалено правило #{num}')
        return jsonify({'ok': True, 'output': out})

    if action not in ('allow', 'deny'):
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    port = _valid_port_spec(body.get('port'))
    if not port:
        return jsonify({'ok': False, 'error': 'Порт должен быть числом 1–65535 или диапазоном 20000:20100'}), 400
    proto = (body.get('proto') or 'tcp').strip().lower()
    if proto not in ('tcp', 'udp', 'any'):
        return jsonify({'ok': False, 'error': 'Протокол: tcp, udp или any'}), 400
    src = (body.get('from') or '').strip()
    if src and src.lower() not in ('any', 'anywhere'):
        src = _valid_ip_or_cidr(src)
        if not src:
            return jsonify({'ok': False, 'error': 'Источник: IP или подсеть, например 203.0.113.10 или 203.0.113.0/24'}), 400
    else:
        src = ''
    # Диапазон портов ufw принимает только с явным протоколом.
    if ':' in port and proto == 'any':
        proto = 'tcp'
    comment = re.sub(r"[^\w \-.:/()А-Яа-яЁё]", '', (body.get('comment') or 'awg-panel'))[:60] or 'awg-panel'

    spec = port if proto == 'any' else '%s/%s' % (port, proto)
    cmd = ('ufw %s from %s to any port %s%s' % (action, src, port,
                                                '' if proto == 'any' else ' proto ' + proto)
           if src else 'ufw %s %s' % (action, spec))
    out, err, rc = run_cmd("%s comment '%s'" % (cmd, comment))
    if rc != 0:
        return jsonify({'ok': False, 'error': err or out or 'ufw вернул ошибку'}), 500
    audit('info', f'ufw: {action} {spec}{" from " + src if src else ""} ({comment})')
    return jsonify({'ok': True, 'output': out})


@app.route('/api/system/fail2ban/action', methods=['POST'])
@login_required
def system_fail2ban_action():
    """ban / unban / ignore_add / ignore_remove / set_params для fail2ban."""
    body = request.get_json(force=True) or {}
    action = (body.get('action') or '').strip()
    jail = (body.get('jail') or '').strip()
    if not _f2b_installed():
        return jsonify({'ok': False, 'error': 'fail2ban на сервере не установлен'}), 400
    if jail and not _RE_JAIL.match(jail):
        return jsonify({'ok': False, 'error': 'Некорректное имя jail'}), 400

    if action in ('ban', 'unban'):
        ip = _valid_ip_or_cidr(body.get('ip'))
        if not ip or not jail:
            return jsonify({'ok': False, 'error': 'Нужны jail и корректный IP'}), 400
        out, err, rc = run_cmd('fail2ban-client set %s %sban %s' % (jail, '' if action == 'ban' else 'un', ip))
        if rc != 0:
            return jsonify({'ok': False, 'error': err or out or 'fail2ban вернул ошибку'}), 500
        audit('warn', f'fail2ban: {action} {ip} в jail {jail}')
        return jsonify({'ok': True, 'output': out})

    if action in ('ignore_add', 'ignore_remove'):
        ip = _valid_ip_or_cidr(body.get('ip'))
        if not ip:
            return jsonify({'ok': False, 'error': 'Нужен корректный IP или подсеть'}), 400
        # Исключения храним в своём jail.d-файле в секции [DEFAULT] — тогда они
        # действуют на все jail'ы и переживают рестарт fail2ban. Через
        # `fail2ban-client set ... addignoreip` правка жила бы до перезапуска.
        data = _f2b_panel_overrides()
        default = data.setdefault('DEFAULT', {})
        base = [x for x in (default.get('ignoreip', '') or '').split() if x]
        if not base:
            # Первое добавление: не потерять то, что уже настроено вне панели.
            live = _f2b_jail(_f2b_jail_names()[0])['ignoreip'] if _f2b_jail_names() else []
            base = [x for x in live if x]
        if action == 'ignore_add':
            if ip in base:
                return jsonify({'ok': True, 'output': 'уже в списке'})
            base.append(ip)
        else:
            if ip not in base:
                return jsonify({'ok': False, 'error': 'Такого адреса в исключениях нет'}), 400
            base = [x for x in base if x != ip]
        default['ignoreip'] = ' '.join(base)
        _f2b_write_overrides(data)
        audit('info', f'fail2ban: исключения → {default["ignoreip"] or "пусто"}')
        return jsonify({'ok': True, 'ignoreip': base})

    if action == 'set_params':
        if not jail:
            return jsonify({'ok': False, 'error': 'Нужен jail'}), 400
        data = _f2b_panel_overrides()
        section = data.setdefault(jail, {})
        for key, pattern in (('bantime', r'^\d+[smhdw]?$'), ('findtime', r'^\d+[smhdw]?$'),
                             ('maxretry', r'^\d{1,4}$')):
            if key not in body:
                continue
            val = str(body.get(key) or '').strip()
            if val and not re.match(pattern, val):
                return jsonify({'ok': False, 'error': f'{key}: ожидается число (можно с суффиксом m/h/d)'}), 400
            section[key] = val
        _f2b_write_overrides(data)
        audit('info', f'fail2ban: параметры jail {jail} изменены панелью')
        return jsonify({'ok': True})

    if action == 'restart':
        run_cmd('systemctl restart fail2ban')
        time.sleep(1.5)
        _, _, rc = run_cmd('systemctl is-active --quiet fail2ban')
        return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else 'fail2ban не поднялся'})

    return jsonify({'ok': False, 'error': 'Unknown action'}), 400


def _hysteria_truths_blob():
    """Live-значения Hysteria для окна «Источники правды».

    Всё читается из settings.json — того самого файла, из которого генерируется
    config.yaml. Отдельно показываем адрес подключения и маскировочный сайт:
    их постоянно путают, а это разные вещи (см. подписи ниже).
    """
    paths = _hysteria_paths_blob()
    if not paths:
        return {}
    try:
        from modules.hysteria import load_settings
        from modules.hysteria import service as hy_service
        from modules.hysteria import profiles as hy_profiles
    except Exception:
        return {}
    cfg = load_settings()
    port = int(cfg.get('port') or 443)
    masq = (cfg.get('masquerade_url') or '').strip()
    return {
        'installed': paths.get('installed'),
        'active': hy_service.is_active(),
        'port': port,
        'port_source': paths['settings'] + ' → port (в config.yaml идёт как listen: :порт)',
        'connect_host': hy_profiles.server_host(),
        'connect_host_source': (paths['settings'] + ' → sni; если пусто — общий адрес сервера панели'),
        'masquerade': masq or 'голый 404',
        'masquerade_source': (paths['settings'] + ' → masquerade_url (config.yaml → masquerade.proxy.url; '
                              'пусто = masquerade.type: string, код 404)'),
        'obfs': 'salamander' if (cfg.get('obfs_password') or '').strip() else 'выключена',
        'obfs_source': paths['settings'] + ' → obfs_password (пусто = обфускации нет)',
        'cert_mode': hy_service.cert_mode(),
        'fingerprint': hy_service.cert_fingerprint(),
        'cert_source': paths['config'] + ' → tls.cert',
        'bandwidth': ('%s / %s' % (
            ('%d Мбит/с' % int(cfg.get('down_mbps') or 0)) if int(cfg.get('down_mbps') or 0) else 'без лимита',
            ('%d Мбит/с' % int(cfg.get('up_mbps') or 0)) if int(cfg.get('up_mbps') or 0) else 'без лимита')),
        'bandwidth_source': paths['settings'] + ' → down_mbps / up_mbps',
        'config': paths['config'],
        'listener': port_owner(port, 'udp'),
        # Кто ещё претендует на этот UDP-номер по реестру портов панели.
        'conflict': port_conflict(port, 'udp', ignore_kind='hysteria', include_idle=True),
    }


def _tgweb_truths_blob():
    """Live-значения Telegram WEB для «Источников правды»: откуда что взято и
    кто сейчас держит внутренние порты цепочки. {} — пакета нет / не установлен."""
    if not globals().get('tgweb_pkg'):
        return {}
    try:
        from modules.tgweb import CONFIG_FILE as TG_CONF, SETTINGS_FILE as TG_SET
        from modules.tgweb import nginx as tg_ng
        from modules.tgweb import service as tg_svc
        st = tg_svc.status()
    except Exception:
        return {}
    if not st.get('installed'):
        return {}
    ports = []
    for it in _tgweb_port_items():
        ports.append({'who': it['who'], 'port': it['port'], 'kind': it['kind'],
                      'listener': port_owner(it['port'], 'tcp'),
                      # 443 в режиме «сам»: закреплённый за ним XRay при старте не
                      # столкнётся — порт разводит front.py. Конфликт тут только живой.
                      'conflict': port_conflict(it['port'], 'tcp', ignore_kind=it['kind'],
                                                include_idle=it['kind'] != 'tgweb_front')})
    return {
        'installed': True,
        'active': st.get('active'),
        'host': st.get('host'),
        'host_source': "домен сертификата Let's Encrypt, которым терминируется 443",
        'slug': st.get('slug'),
        'slug_source': TG_SET + ' → slug (зашит в каждую ссылку)',
        'xray_mode': st.get('xray_mode'),
        # Кто принимает 443 для WEB (modules/tgweb/front.py) и почему.
        'front': st.get('front'),
        'front_why': st.get('front_why'),
        'fallback': ('XRay на 443 нет — nginx WEB-прокси слушает 443 сам, сайт и панель дальше → '
                     '127.0.0.1:%s' % st.get('prev_dest')) if st.get('front') == 'nginx' else
                    (('общий фоллбек XRay → nginx 127.0.0.1:%s, сайт и панель дальше → 127.0.0.1:%s'
                      % (st['ports'].get('nginx_port'), st.get('prev_dest'))) if st.get('wired') else
                     'общий фоллбек XRay НЕ ведёт в WEB-прокси'),
        'fallback_source': XRAY_CONFIG + ' → inbounds[vless].settings.fallbacks (_panel_tgweb)',
        'nginx_site': tg_ng._site_paths()[0],
        'cascade': 'через ВПН2 (socks mihomo)' if st.get('cascade_live') else 'напрямую',
        'ports': ports,
        'config': TG_CONF,
        'version': st.get('version'),
    }


@app.route('/api/system/truths', methods=['GET'])
@login_required
def system_truths_get():
    """Информационная сводка: всё, что панель использует при генерации клиентских
    конфигов и отображении карточек, с пометкой источника файла/команды."""
    override = (SERVER_CFG.get('server_ip_override') or '').strip()
    live_ip = _detect_server_ip()
    ip_list = _list_server_ipv4s()
    awg_params = get_awg_params()
    # XRay — единый live-источник параметров (security/sni/flow/fp + reality pbk/sid/spx).
    xp = get_xray_inbound_params()
    eff_ip = get_server_ip()
    return jsonify({
        'server': {
            'effective_ip': eff_ip,
            'ip_override': override,
            'live_outbound': live_ip,
            'interfaces': ip_list,
            # Серый IP в клиентских ссылках = никто снаружи не подключится.
            # Типичный случай — облако с NAT, где белый адрес не виден внутри ВМ.
            'effective_is_private': _is_private_ipv4(eff_ip),
            'legacy_server_ip': (SERVER_CFG.get('server_ip') or '').strip(),
            'source': 'override (server.json)' if override else ('live (ip route get 1.1.1.1)' if live_ip else 'legacy (server.json server_ip)'),
        },
        'awg': {
            'port': get_awg_port(),
            'port_source': AWG_CONFIG + ' → [Interface] ListenPort',
            'address': get_awg_interface_address(),
            'address_source': AWG_CONFIG + ' → [Interface] Address (сеть клиентов = сеть сервера)',
            'obf': awg_params,
            'obf_source': AWG_CONFIG + ' → [Interface] H1..H4 / Jc / Jmin / Jmax / S1..S4',
            'iface_config': AWG_CONFIG,
        },
        'hysteria_inbound': (xhy.status() if xhy else {'enabled': False}),
        'xray': {
            'port': xp['port'],
            'port_source': XRAY_CONFIG + " → inbounds[vless].port",
            'security': xp['security'],
            'security_source': XRAY_CONFIG + ' → inbounds[*].streamSettings.security',
            'sni': xp['sni'],
            'sni_source': (XRAY_CONFIG + ' → realitySettings.serverNames[0]') if xp['security'] == 'reality'
                          else (XRAY_CONFIG + ' → tlsSettings.serverName (fallback server.json → sni)'),
            'flow': xp['flow'],
            'fingerprint': xp['fingerprint'],
            'flow_source': XRAY_CONFIG + ' → inbounds[vless].settings.clients[0].flow',
            # reality-only (пусто для tls)
            'reality_dest': xp['dest'],
            'reality_public_key': xp['public_key'],
            'reality_public_key_source': 'деривация из realitySettings.privateKey (xray x25519 -i)',
            'reality_short_id': xp['short_id'],
            'reality_short_id_source': XRAY_CONFIG + ' → realitySettings.shortIds[0]',
            'reality_spider_x': xp['spider_x'],
            'inbound_config': XRAY_CONFIG,
        },
        'mtg': {
            'port': get_mtg_port(),
            'port_source': MTG_CONFIG + ' → bind-to',
            'fake_host': get_mtg_fake_host(),
            'fake_host_source': MTG_CONFIG + ' → secret (hex-хвост декодируется в UTF-8)',
            'config': MTG_CONFIG,
        },
        'hysteria': _hysteria_truths_blob(),
        'tgweb': _tgweb_truths_blob(),
        # Что реально занято на сокетах — в дополнение к портам из конфигов выше.
        # Именно здесь видно, почему сервис может не подняться на «своём» порту.
        'ports': sorted(listening_sockets(), key=lambda s: (s['port'], s['proto'])),
        # Каноничные файлы — откуда панель сейчас читает значения выше.
        # Полный реестр всего, что панель использует на диске, лежит в /api/system/paths.
        'files': {
            'panel_server_json': SERVER_CONFIG_FILE,
            'panel_admin_json': ADMIN_FILE,
            'panel_secret_key': SECRET_KEY_FILE,
            'awg_config': AWG_CONFIG,
            'xray_config': XRAY_CONFIG,
            'mtg_config': MTG_CONFIG,
            'hysteria_config': (_hysteria_paths_blob() or {}).get('config', ''),
            'tgweb_config': (_tgweb_truths_blob() or {}).get('config', ''),
        },
    })

# === Здоровье сервера — RAM / CPU / диск / сеть, только stdlib (/proc, statvfs) ===
# Без внешних зависимостей: всё читается из /proc и os.statvfs. Для мгновенных
# скоростей (CPU% и сеть Б/с) берём два замера с короткой паузой внутри запроса.
@app.route('/api/system/dependencies/fix', methods=['POST'])
@login_required
def system_dependencies_fix():
    body = request.get_json(force=True) or {}
    dep_id = body.get('id') or ''
    result = _system_apply_fix(dep_id)
    # У фоновых фиксов исход на этот момент неизвестен — его пишет сам worker,
    # иначе в журнале осталось бы «ok=True» даже для операции, которая упала.
    if result.get('async'):
        audit('info', f'Dependency fix: {dep_id} → запущен в фоне')
    else:
        audit('info', f'Dependency fix: {dep_id} → ok={result.get("ok")}')
    return jsonify(result)

def panel_port_map():
    """Все порты, которые панель считает своими: [{kind, proto, port, who, active}].

    Единый реестр вместо проверок «каждый сам за себя». Конфликт возможен
    только внутри одного транспорта, но участников четверо и живут они в разных
    файлах: VLESS и Hysteria — в config.json XRay, AWG — в awg0.conf, MTProto —
    в config.toml, панель — в server.json. Порт остановленного сервиса всё
    равно перечисляем: он заберёт его обратно при старте, и занять этот номер
    значит поломать сервис позже, а не сейчас.
    """
    out = []
    try:
        xp = int((get_xray_inbound_params() or {}).get('port') or 0)
        if xp:
            st, _, _ = run_cmd('systemctl is-active xray')
            out.append({'kind': 'xray', 'proto': 'tcp', 'port': xp,
                        'who': 'XRay (VLESS)', 'active': st.strip() == 'active'})
    except Exception:
        pass
    if xhy:
        try:
            hy = xhy.status()
            hp = int(hy.get('port') or 0)
            # Выключенный инбаунд порт не держит: сам он не поднимется, а при
            # включении порт проверяется заново. Иначе его порт по умолчанию
            # (443) давал ложное «закреплён» самостоятельной Hysteria и AWG.
            if hp and hy.get('enabled'):
                # kind именно 'xray_hy', а не 'hysteria': это ВТОРОЙ претендент на
                # UDP, отдельный от самостоятельного протокола. Будь у них один
                # kind, каждый считал бы чужой порт своим и конфликт между ними
                # не показывался бы вовсе.
                out.append({'kind': 'xray_hy', 'proto': 'udp', 'port': hp,
                            'who': 'инбаунд Hysteria в XRay', 'active': bool(hy.get('enabled'))})
        except Exception:
            pass
    if xdns:
        try:
            # Только когда включён: выключенный XDNS порт не держит, а 53/udp на
            # других адресах сервера законно занимают systemd-resolved и dnsmasq.
            if xdns.enabled():
                out.append({'kind': 'xray_xdns', 'proto': 'udp', 'port': xdns.PORT,
                            'who': 'XDNS в XRay (DNS-туннель)', 'active': True})
        except Exception:
            pass
    try:
        from modules.hysteria import load_settings as _hy_load
        from modules.hysteria import service as _hy_svc
        if _hy_svc.bin_installed():
            hyp = int(_hy_load().get('port') or 0)
            if hyp:
                out.append({'kind': 'hysteria', 'proto': 'udp', 'port': hyp,
                            'who': 'Hysteria 2', 'active': _hy_svc.is_active()})
    except Exception:
        pass
    try:
        ap = int(get_awg_listen_port() or 0)
        if ap:
            out.append({'kind': 'awg', 'proto': 'udp', 'port': ap,
                        'who': 'AmneziaWG', 'active': _awg_iface_up()})
    except Exception:
        pass
    try:
        mp = int(get_mtg_listen_port() or 0)
        if mp:
            unit = (_find_mtg_paths() or {}).get('unit') or 'mtg'
            st, _, _ = run_cmd(f'systemctl is-active {unit}')
            out.append({'kind': 'mtg', 'proto': 'tcp', 'port': mp,
                        'who': 'MTProto', 'active': st.strip() == 'active'})
    except Exception:
        pass
    try:
        pp = int(SERVER_CFG.get('panel_port') or 0)
        if pp:
            out.append({'kind': 'panel', 'proto': 'tcp', 'port': pp,
                        'who': 'веб-панель', 'active': True})
    except Exception:
        pass
    out.extend(_tgweb_port_items())
    return out


def _tgweb_port_items():
    """Внутренние порты цепочки Telegram WEB (только 127.0.0.1).

    Наружу WEB-прокси ничего не открывает — клиент приходит на 443 к XRay, —
    но три номера на loopback заняты: nginx (фоллбек XRay), WEB-вход и API
    telemt. Занять любой из них другим сервисом значит молча сломать цепочку,
    поэтому они в реестре наравне с публичными. Kind у каждого свой: у nginx
    и telemt разные слушатели, и общий kind прятал бы конфликт между ними."""
    if not globals().get('tgweb_pkg'):
        return []
    try:
        from modules.tgweb import load_settings as _tg_load
        from modules.tgweb import nginx as _tg_ng
        from modules.tgweb import service as _tg_svc
        cfg = _tg_load()
        if not (cfg.get('enabled') and _tg_svc.bin_installed()):
            return []
        tg_active = _tg_svc.is_active()
        standalone = (cfg.get('front') or '') == 'nginx'
        out = []
        if standalone:
            # XRay на 443 нет — порт держит сам WEB-прокси (nginx с сертификатом).
            # В реестре он наравне с XRay: смена порта MTProto на 443 или
            # установка XRay в Reality увидят, что порт занят и кем.
            out.append({'kind': 'tgweb_front', 'proto': 'tcp', 'port': 443,
                        'who': 'Telegram WEB (nginx на 443)', 'active': _tg_ng.active()})
        for key, kind, who, active in (
                ('nginx_port', 'tgweb_nginx', 'Telegram WEB: nginx (127.0.0.1)', _tg_ng.active()),
                ('web_port', 'tgweb', 'Telegram WEB: вход telemt (127.0.0.1)', tg_active),
                ('api_port', 'tgweb_api', 'Telegram WEB: API telemt (127.0.0.1)', tg_active)):
            port = int(cfg.get(key) or 0)
            # nginx_port в режиме «сам на 443» никто не слушает — не держим его.
            if port and not (standalone and key == 'nginx_port'):
                out.append({'kind': kind, 'proto': 'tcp', 'port': port, 'who': who,
                            'active': bool(active), 'loopback': True})
        return out
    except Exception:
        return []


def _hysteria_hop_range():
    """(начало, конец) активного диапазона порт-хоппинга Hysteria или None."""
    try:
        from modules.hysteria import service as _hy_svc
        rng = _hy_svc.hop_active()
        if rng:
            a, b = rng.split('-')
            return int(a), int(b)
    except Exception:
        pass
    return None


def _udp_reserved_ports_for_hop():
    """UDP-порты чужих служб (без самой Hysteria): реестр панели, включая
    остановленные, и реальные слушатели ниже эфемерного диапазона — выше живут
    случайные исходящие сокеты, они меняются каждую минуту и ничего не держат."""
    ports = set()
    for item in panel_port_map():
        if item['proto'] == 'udp' and item['kind'] != 'hysteria':
            ports.add(int(item['port']))
    try:
        with open('/proc/sys/net/ipv4/ip_local_port_range') as f:
            eph = int(f.read().split()[0])
    except Exception:
        eph = 32768
    for s in listening_sockets():
        if s['proto'] == 'udp' and s['port'] < eph and 'hysteria' not in (s['process'] or '').lower():
            ports.add(int(s['port']))
    return sorted(ports)


def port_conflict(port, proto, ignore_kind='', include_idle=False):
    """Кто помешает занять порт. '' — свободно.

    Различаем два случая, и это принципиально. «Занят сейчас» — запрет:
    сервис не поднимется, а в случае XRay упадёт целиком, вместе с VLESS.
    «Закреплён за остановленным» — предупреждение: порт фактически свободен и
    занять его можно, но когда тот сервис запустят, номер достанется тому, кто
    стартует первым. Запрещать такое нельзя — иначе лежащий годами AmneziaWG
    навсегда держал бы за собой 443/udp, лучший порт для Hysteria.

    Сначала свои сервисы по реестру, потом фактические слушатели из `ss`: у
    своих есть название и понятно, что делать, а `ss` для AmneziaWG показывает
    сокет из ядра — нередко вовсе без имени процесса.
    """
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        return ''
    if not port:
        return ''
    # Диапазон порт-хоппинга Hysteria целиком перенаправляется в неё: чужой
    # сервис на таком порту поднимется, но пакеты к нему не дойдут.
    if proto == 'udp' and ignore_kind != 'hysteria':
        hop = _hysteria_hop_range()
        if hop and hop[0] <= port <= hop[1]:
            return (f"{port}/udp входит в диапазон порт-хоппинга Hysteria ({hop[0]}–{hop[1]}) — "
                    f"всё, что туда приходит, забирает Hysteria")
    for item in panel_port_map():
        if item['kind'] == ignore_kind or item['proto'] != proto or item['port'] != port:
            continue
        if item['active']:
            return f"{port}/{proto} занят: {item['who']}"
        if include_idle:
            return (f"{port}/{proto} закреплён за «{item['who']}» — сервис сейчас не запущен, "
                    f"но при старте заберёт порт обратно")
        return ''
    owner = port_owner(port, proto)
    if owner:
        # Свой же слушатель конфликтом не считается. Раньше в списке не было
        # AWG и инбаунда Hysteria в XRay — и каждый «конфликтовал» сам с собой
        # на собственном порту («51820/udp уже слушает AmneziaWG»).
        skip = {'xray': 'xray', 'mtg': 'mtg', 'hysteria': 'hysteria',
                'xray_hy': 'xray', 'xray_xdns': 'xray', 'awg': 'amneziawg',
                'tgweb': 'telemt', 'tgweb_api': 'telemt', 'tgweb_nginx': 'nginx',
                'tgweb_front': 'nginx'}.get(ignore_kind, '')
        if skip and skip in owner.lower():
            return ''
        # Сокет AWG живёт в ядре и в `ss` нередко идёт без имени процесса —
        # поэтому своего AWG узнаём ещё и по номеру порта из awg0.conf.
        if ignore_kind == 'awg' and proto == 'udp' and port == get_awg_listen_port():
            return ''
        return f'{port}/{proto} уже слушает {owner}'
    return ''


# Кнопка «Подобрать свободный» у всех протоколов, где порт меняется из панели.
# VLESS в списке нет намеренно: его порт из панели не меняется.
SUGGEST_PORT_KINDS = {'awg': 'udp', 'mtg': 'tcp', 'hysteria': 'udp', 'xray_hy': 'udp'}
_SUGGEST_EXTRA = {
    # У AWG своих кандидатов в PORT_CANDIDATES нет: там списки под TLS-маскировку.
    'awg': [51820, 51821, 443, 8443, 2053, 2083, 2096],
    'xray_hy': PORT_CANDIDATES.get('hysteria', []),
}


def suggest_free_port(kind, current=0):
    """Свободный порт для протокола — (порт, ошибка).

    Не pick_free_port: тот видит только тех, кто слушает прямо сейчас. Здесь
    кандидат проверяется ещё и по реестру портов панели с include_idle — порт,
    закреплённый за остановленным соседом (AWG в awg0.conf, выключенный
    инбаунд), подбор не предложит: при старте соседа они бы столкнулись.
    Текущий порт протокола тоже не предлагаем — это не «другой свободный».
    """
    proto = SUGGEST_PORT_KINDS.get(kind)
    if not proto:
        return 0, 'для этого протокола порт из панели не меняется'
    current = int(current or 0)
    seen, cands = set(), []
    for p in (PORT_CANDIDATES.get(kind, []) + _SUGGEST_EXTRA.get(kind, [])
              + list(range(20000, 20200))):
        if p not in seen:
            seen.add(p)
            cands.append(p)
    for p in cands:
        if p == current:
            continue
        if port_conflict(p, proto, ignore_kind=kind, include_idle=True):
            continue
        # port_conflict пропускает «своего» слушателя по имени процесса; для
        # подбора чужой номер, занятый даже нашим же сервисом, не годится.
        if port_owner(p, proto):
            continue
        return p, ''
    return 0, 'свободного порта не нашлось'


@app.route('/api/port/suggest', methods=['GET'])
@login_required
def api_port_suggest():
    kind = (request.args.get('kind') or '').strip()
    try:
        current = int(request.args.get('current') or 0)
    except ValueError:
        current = 0
    port, err = suggest_free_port(kind, current)
    if not port:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True, 'port': port, 'proto': SUGGEST_PORT_KINDS[kind]})


def _awg_port_state():
    """Порт AWG и кто ещё на него претендует.

    Сосед по UDP у AWG теперь есть всегда: инбаунд Hysteria живёт в том же
    пространстве портов, а по умолчанию просится на 443 — ровно туда, куда
    типовой awg0.conf ставит ListenPort. Совпадение видно только здесь: в
    выводе `ss` сокет AWG идёт из ядра и часто без имени процесса.
    """
    # Без awg0.conf у AWG нет порта вовсе — и конфликтовать ему не с кем.
    # Раньше сюда приходил запасной 443, и не настроенный AWG «спорил» с Hysteria.
    configured = os.path.isfile(AWG_CONFIG)
    try:
        port = int(get_awg_listen_port() or 0)
    except Exception:
        port = 0
    if not configured:
        return {'port': 0, 'configured': False, 'conflict': '',
                'hy_port': 0, 'hy_enabled': False, 'iface_up': False}
    hy_port, hy_on = 0, False
    if xhy:
        try:
            st = xhy.status()
            hy_port, hy_on = int(st.get('port') or 0), bool(st.get('enabled'))
        except Exception:
            pass
    return {'port': port, 'configured': True,
            'conflict': port_conflict(port, 'udp', ignore_kind='awg', include_idle=True),
            'hy_port': hy_port, 'hy_enabled': hy_on, 'iface_up': _awg_iface_up()}


@app.route('/api/awg/port', methods=['GET'])
@login_required
def awg_port_get():
    return jsonify({'ok': True, **_awg_port_state()})


@app.route('/api/awg/port', methods=['POST'])
@login_required
def awg_port_set():
    """Сменить UDP-порт AmneziaWG. POST {port}.

    Порт зашит в Endpoint каждого клиентского конфига, поэтому операция всегда
    означает перевыдачу: панель отдаёт конфиги с новым портом (Endpoint
    пересобирается при выдаче, _awg_client_config_live), но те, что уже стоят
    на устройствах, остаются со старым. UI об этом предупреждает.
    """
    data = request.get_json(silent=True) or {}
    try:
        new_port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'порт должен быть числом'}), 400
    if not 1 <= new_port <= 65535:
        return jsonify({'ok': False, 'error': 'порт вне диапазона 1–65535'}), 400
    if not os.path.exists(AWG_CONFIG):
        return jsonify({'ok': False, 'error': f'нет {AWG_CONFIG} — AmneziaWG не настроен'}), 400

    old_port = 0
    try:
        old_port = int(get_awg_port() or 0)
    except Exception:
        pass
    if new_port == old_port:
        return jsonify({'ok': True, 'unchanged': True, **_awg_port_state()})

    # Занятость: чужой слушатель уронит awg-quick на старте, а свой же инбаунд
    # Hysteria на этом порту — конфликт, который проявится при первом рестарте.
    clash = port_conflict(new_port, 'udp', ignore_kind='awg')
    if clash:
        return jsonify({'ok': False, 'error': clash}), 400
    idle_warn = port_conflict(new_port, 'udp', ignore_kind='awg', include_idle=True)

    # Патчим одну строку, а не переписываем файл: в awg0.conf лежат ключи,
    # обфускация и все пиры — потерять их нельзя.
    try:
        with open(AWG_CONFIG, 'r') as f:
            lines = f.read().splitlines()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'не прочитать {AWG_CONFIG}: {e}'}), 500

    in_iface, patched, out = False, False, []
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            in_iface = stripped.lower() == '[interface]'
        elif in_iface and not patched and stripped.lower().startswith('listenport'):
            indent = raw[:len(raw) - len(raw.lstrip())]
            raw = f'{indent}ListenPort = {new_port}'
            patched = True
        out.append(raw)
    if not patched:
        return jsonify({'ok': False, 'error': 'в [Interface] нет строки ListenPort'}), 500

    backup = AWG_CONFIG + '.portbak'
    try:
        shutil.copy2(AWG_CONFIG, backup)
        with open(AWG_CONFIG, 'w') as f:
            f.write('\n'.join(out) + '\n')
    except Exception as e:
        return jsonify({'ok': False, 'error': f'не записать {AWG_CONFIG}: {e}'}), 500

    # Живому интерфейсу порт меняем на лету: awg set не рвёт туннели и не
    # пересоздаёт awg0, в отличие от down/up.
    applied_live = False
    if _awg_iface_up():
        _, err, rc = run_cmd(f'{AWG_BIN} set awg0 listen-port {new_port}')
        if rc != 0:
            try:
                shutil.copy2(backup, AWG_CONFIG)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': f'awg set не отработал: {err or rc} — порт возвращён'}), 500
        applied_live = True

    ensure_firewall_port(new_port, 'udp', 'AmneziaWG (awg-panel)')
    if old_port:
        # Старое правило убираем только если на нём больше никого: на одном
        # номере могли сидеть и другие наши сервисы.
        try:
            if not port_owner(old_port, 'udp'):
                run_cmd(f'ufw delete allow {old_port}/udp')
        except Exception:
            pass
    try:
        os.remove(backup)
    except Exception:
        pass
    _HY_BUSY_CACHE.update({'ts': 0, 'data': {}})
    audit('warn', f'AmneziaWG: порт {old_port or "?"} → {new_port}/udp'
                  + (' (применён на живом интерфейсе)' if applied_live else ' (интерфейс опущен)')
                  + (f' — внимание: {idle_warn}' if idle_warn else ''))
    return jsonify({'ok': True, 'applied_live': applied_live, 'old_port': old_port,
                    'warning': idle_warn, **_awg_port_state()})


@app.route('/api/clients/<path:public_key>/dns-local', methods=['POST'])
@login_required
def awg_client_dns_local(public_key):
    """Per-client тумблер: DNS клиента = локальный (для логирования доменов через dnsmasq).
    POST {enabled: bool}. Регенерит DNS-строку в сохранённом конфиге, флаг кладёт в clients.json."""
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('enabled'))
    clients = load_clients()
    if public_key not in clients:
        return jsonify({'error': 'Client not found'}), 404
    c = clients[public_key]
    c['dns_local'] = enabled
    new_dns = get_awg_iface_ip() if enabled else '1.1.1.1'
    old_cfg = c.get('config') or ''
    if old_cfg:
        new_cfg = re.sub(r'^DNS\s*=.*$', f'DNS = {new_dns}', old_cfg, count=1, flags=re.M)
        c['config'] = new_cfg
    save_clients(clients)
    audit('info', f'AWG «Логи+» для {c.get("name") or public_key[:12]+"…"} → ' + ('ON (DNS=' + new_dns + ')' if enabled else 'OFF (DNS=1.1.1.1)'))
    return jsonify({'ok': True, 'enabled': enabled, 'dns': new_dns, 'config': _awg_client_config_live(c)})

@app.route('/api/awg/logs', methods=['GET'])
@login_required
def awg_logs_endpoint():
    """История AWG-снапшотов. Если задан ?pubkey=<base64> — фильтр по нему,
    иначе все peers. Источник: /opt/awg-panel/data/logs/awg_access.log (JSON-line)."""
    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 100000))
    pubkey_filter = request.args.get('pubkey') or ''
    name = ''
    if pubkey_filter:
        clients = load_clients()
        info = clients.get(pubkey_filter)
        if info:
            name = info.get('name') or ''
    if not os.path.exists(AWG_ACCESS_LOG):
        return jsonify({'access_log_enabled': False, 'name': name, 'records': []})
    all_recs = _cached_awg_enriched()
    if pubkey_filter:
        src = (r for r in all_recs if r.get('_pubkey') == pubkey_filter)
    else:
        src = iter(all_recs)
    # Срезаем до limit и убираем служебное _pubkey из вывода.
    out = []
    for r in src:
        if len(out) >= limit:
            break
        rec = {k: v for k, v in r.items() if k != '_pubkey'}
        out.append(rec)
    return jsonify({'access_log_enabled': True, 'name': name, 'records': out})

@app.route('/api/xray/global/logs', methods=['GET'])
@login_required
def xray_global_logs():
    """Все access.log записи (без фильтра по email), c полем outbound для Allow/Block."""
    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 100000))
    if not os.path.exists(XRAY_ACCESS_LOG):
        return jsonify({'access_log_enabled': False, 'records': []})
    all_recs = _cached_xray_enriched()
    return jsonify({'access_log_enabled': True, 'records': all_recs[:limit]})

@app.route('/api/xray/clients/<client_uuid>/logs', methods=['GET'])
@login_required
def xray_client_logs(client_uuid):
    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 100000))
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    c = clients[client_uuid]
    email = _xray_unique_email(c.get('name', ''), c.get('uuid', ''))
    if not os.path.exists(XRAY_ACCESS_LOG):
        return jsonify({
            'name': c.get('name'),
            'uuid': client_uuid,
            'email': email,
            'access_log_enabled': False,
            'records': []
        })
    # Записи уже обогащены в кеше (geo+dest_org), фильтр + срез — O(N).
    out = xray_logs_for_email(email, limit=limit)
    return jsonify({
        'name': c.get('name'),
        'uuid': client_uuid,
        'email': email,
        'access_log_enabled': True,
        'count': len(out),
        'records': out,
    })


# =============================================================================
# === Backup ===
# Архивирует /opt/awg-panel (без data, __pycache__, venv, *.bak) +
# /etc/amnezia/amneziawg/awg0.conf + /usr/local/etc/xray/config.json +
# /etc/mtg/config.toml в /opt/awg-panel/data/backup/awg-panel-<ts>.tar.gz.
# Расписание — systemd timer awg-panel-backup.{service,timer}, который дёргает
# /api/backup/timer-fire через curl с токеном secret.key.
# =============================================================================
# Все пути берём из существующих констант панели — если на конкретном сервере
# AWG/XRay/mtg лежат не в дефолтных местах, бэкап автоматически подхватит.
# Именно PANEL_ROOT, а не dirname(CLIENTS_DB): после переезда клиентской базы в
# data/awg/ вычисление от неё дало бы /opt/awg-panel/data/awg — и бэкап собрался бы
# не с того корня.
BACKUP_DIR = os.path.join(PANEL_ROOT, 'data', 'backup')
# Бэкапим ВСЁ из panel_root/ кроме перечисленного. Данные пользователя живут под
# data/** и ОБЯЗАНЫ попадать в архив — иначе восстановление вернёт панель без
# клиентов и настроек. Исключаем только то, что либо скачивается заново (гео-базы,
# кеши), либо бессмысленно в бэкапе (логи, сами архивы).
# Паттерны относительные: tar пишет имена без ведущего «/», абсолютный путь не совпадёт.
def _fmt_bytes(n):
    n = float(n or 0)
    if n < 1024: return f'{int(n)} B'
    if n < 1024 * 1024: return f'{n/1024:.1f} KB'
    if n < 1024 * 1024 * 1024: return f'{n/1024/1024:.2f} MB'
    return f'{n/1024/1024/1024:.2f} GB'

# Догоняем юнит автобэкапа после переезда secret.key (проверка дешёвая — чтение файла).
# === Probe API — внешний мониторинг доступности и скорости ==================
# Отдельная утилита (обычно на сервере в РФ) снаружи проверяет, открыты ли порты
# XRay/MTProto и какая до сервера скорость. Здесь только чтение live-параметров и
# отдача байтов: состояния нет, в data/ ничего не пишется.
#
# Доступ по общему токену из server.json (probe_token). Ответ на неверный токен —
# 404, а не 401: наличие эндпоинта наружу не светим.
#
# Префикс api/ уже в _RESERVED_FAKE_PREFIXES, поэтому fake-landing и режим
# login_block_root (Reality) эти маршруты не перехватывают.

MONITORING_ZIP_URL = UPDATE_BASE_URL.rstrip('/') + '/monitoring.zip'

# 64 КБ случайных байт. Повторяются по кругу: период 64 КБ больше окна deflate
# (32 КБ), поэтому поток не сожмётся, даже если где-то по пути включён gzip, и
# замер скорости не соврёт.
_PROBE_BLOB = os.urandom(65536)

def probe_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        tok = (SERVER_CFG.get('probe_token') or '').strip()
        if not tok or not hmac.compare_digest(tok, request.headers.get('X-Probe-Token', '')):
            return ('Not Found', 404)
        return f(*args, **kwargs)
    return decorated

def _hysteria_probe_info():
    """Реквизиты Hysteria для внешнего мониторинга: порт и пароль обфускации.

    Пароль отдаётся намеренно. Hysteria слушает UDP, и постучаться в неё снаружи
    можно только QUIC-пакетом; при включённом salamander сервер молча роняет всё,
    что не обфусцировано его ключом, — без пароля проверка вообще невозможна.
    Секретом в привычном смысле он не является: один на всех клиентов и лежит
    открытым текстом в каждом выданном профиле.
    """
    try:
        from modules.hysteria import load_settings as hy_settings
        from modules.hysteria import service as hy_service
    except Exception:
        # Пакета в этой панели нет вовсе. Отличать это от «есть, но не
        # установлена» важно: в мониторинге первое — «панель не знает про
        # Hysteria», второе — «протокол на сервере не поднят».
        return {'supported': False, 'installed': False, 'port': 0, 'obfs': '', 'active': False}
    try:
        if not hy_service.bin_installed():
            return {'supported': True, 'installed': False, 'port': 0, 'obfs': '', 'active': False}
        cfg = hy_settings()
        return {
            'supported': True,
            'installed': True,
            'port': int(cfg.get('port') or 0),
            'obfs': (cfg.get('obfs_password') or '').strip(),
            'active': hy_service.is_active(),
        }
    except Exception:
        return {'supported': True, 'installed': False, 'port': 0, 'obfs': '', 'active': False}


def _tgweb_probe_info():
    """Telegram WEB для внешнего мониторинга: адрес страницы моста, а не порт —
    WEB живёт на том же 443, что и XRay (подробности в tgweb.service.probe_info)."""
    try:
        from modules.tgweb import service as tg_service
    except Exception:
        return {'supported': False, 'installed': False, 'active': False, 'port': 0, 'url': ''}
    try:
        return tg_service.probe_info()
    except Exception:
        return {'supported': True, 'installed': False, 'active': False, 'port': 0, 'url': ''}


def _probe_access():
    """Как мониторингу достучаться до этой панели: хост, порт, схема.
    При Reality на 443 фоллбек до панели не доходит — нужен panel_port."""
    xp = get_xray_inbound_params()
    acc = _panel_access_info()
    reality = (xp.get('security') == 'reality')
    port = acc['port'] or (0 if reality else (xp.get('port') or 443))
    warn = ''
    if reality and not acc['port']:
        warn = ('На 443 работает Reality — HTTP-фоллбек до панели не доходит. '
                'Включите отдельный порт панели (Настройки → Доступ к панели), '
                'иначе мониторинг не сможет подключиться.')
    return {
        'host': acc['host'],
        'port': port,
        'use_https': acc['scheme'] == 'https',
        'security': xp.get('security') or '',
        'xray_port': xp.get('port'),
        'mtg_port': get_mtg_port(),
        'hysteria_port': _hysteria_probe_info().get('port') or 0,
        'tgweb_port': _tgweb_probe_info().get('port') or 0,
        'warning': warn,
    }

@app.route('/api/probe/ping')
@probe_auth
def api_probe_ping():
    """Живые порты и режим инбаунда — чтобы мониторинг не хардкодил их у себя
    и не отставал после смены порта на сервере."""
    xp = get_xray_inbound_params()
    hy = _hysteria_probe_info()
    tg = _tgweb_probe_info()
    return jsonify({
        'name': SERVER_CFG.get('server_name', ''),
        'version': PANEL_VERSION,
        'security': xp.get('security') or '',
        'ports': {
            'xray': xp.get('port'),
            'mtg': get_mtg_port(),
            'panel': SERVER_CFG.get('panel_port', 0) or None,
            # Hysteria на UDP, и мониторинг проверяет её иначе — отдаём отдельным
            # блоком с обфускацией, одного номера порта там мало.
            'hysteria': hy.get('port') or None,
            # Telegram WEB делит 443 с XRay — проверяется страницей моста по
            # адресу из блока tgweb, номер порта тут для полноты.
            'tgweb': tg.get('port') or None,
        },
        'hysteria': hy,
        'tgweb': tg,
    })

@app.route('/api/probe/blob')
@probe_auth
def api_probe_blob():
    """N МБ несжимаемых байт — замер скорости вниз."""
    mb = min(50, max(1, request.args.get('mb', 5, type=int) or 5))
    total = mb * 1024 * 1024
    def gen():
        left = total
        while left > 0:
            chunk = _PROBE_BLOB if left >= len(_PROBE_BLOB) else _PROBE_BLOB[:left]
            left -= len(chunk)
            yield chunk
    return Response(gen(), mimetype='application/octet-stream',
                    headers={'Content-Length': str(total), 'Cache-Control': 'no-store'})

@app.route('/api/probe/sink', methods=['POST'])
@probe_auth
def api_probe_sink():
    """Приём и выброс — замер скорости вверх. Тело читается кусками и никуда
    не сохраняется."""
    got = 0
    while True:
        chunk = request.stream.read(65536)
        if not chunk:
            break
        got += len(chunk)
    return jsonify({'bytes': got})

@app.route('/api/probe/info')
@login_required
def api_probe_info():
    """Реквизиты для вкладки «Мониторинг»: что вводить в утилиту."""
    acc = _probe_access()
    acc.update({
        'token': SERVER_CFG.get('probe_token') or '',
        'name': SERVER_CFG.get('server_name', ''),
        'version': PANEL_VERSION,
        'zip_url': MONITORING_ZIP_URL,
    })
    return jsonify(acc)

@app.route('/api/probe/rotate', methods=['POST'])
@login_required
def api_probe_rotate():
    """Сменить токен. Старый перестаёт работать сразу — в мониторинге токен
    придётся прописать заново."""
    SERVER_CFG['probe_token'] = secrets.token_hex(16)
    _save_server_config(SERVER_CFG)
    audit('warn', 'Токен мониторинга перевыпущен')
    return jsonify({'ok': True, 'token': SERVER_CFG['probe_token']})


# Совместимость со старым протоколом Hysteria. Он отдавал профили под своим
# префиксом: /hy/sub/<token8>/<имя>, /hy/conf/….conf, /hy/loon/….conf,
# /hy/clash/….yaml. Протокол вырезан, но эти адреса прописаны в приложениях у
# живых клиентов и опрашиваются автообновлением профиля. Миграция сохраняет
# клиенту его токен, а пути после префикса у XRay ровно те же — значит хватает
# одного редиректа, чтобы подписка продолжила обновляться уже новым профилем.
# Регистрируется до fake-landing, иначе catch-all съел бы эти адреса.
@app.route('/hy/<path:rest>')
def _legacy_hy_profile(rest):
    qs = request.query_string.decode('ascii', 'ignore')
    return redirect('/' + rest + (('?' + qs) if qs else ''), code=302)


# Fake-landing catch-all. Активен только при fake_enabled=true. Регистрируется
# последним, чтобы все ранее объявленные маршруты (api/, static/, sub/, conf/,
# clash/, loon/, /sub/<token>, /conf/..., /clash/..., /loon/...) имели приоритет.
@app.route('/<path:p>')
def _fake_or_login(p):
    cfg = SERVER_CFG
    fake_on = bool(cfg.get('fake_enabled', False))
    block_root = bool(cfg.get('login_block_root', False))
    login_path = cfg.get('login_path', '/login.html')
    req_path = '/' + p

    # Голый IP/домен (вход по IP, без маскировки и без key-only) — здесь ничего не отдаём.
    if not fake_on and not block_root:
        return ('Not Found', 404)

    # /login.html (или кастомный токен) → форма пароля панели (и в fake, и в key-only)
    if req_path == login_path:
        return send_from_directory(STATIC_DIR, 'index.html')

    # Режим «только по ключу»: всё кроме login_path закрыто, фейк-сайт не отдаём.
    if block_root:
        return ('Not Found', 404)

    # Защита: reserved-префиксы сюда не должны попадать (Flask матчит их раньше),
    # но если кто-то добавит новый api/* без листа — отрежем явно.
    if any(p.startswith(pre) for pre in _RESERVED_FAKE_PREFIXES):
        return ('Not Found', 404)

    # Ассеты фейк-сайта
    full = os.path.join(PUBLIC_DIR, p)
    if os.path.isfile(full):
        return send_from_directory(PUBLIC_DIR, p)
    return ('Not Found', 404)


# Lazy-sync таймера на старте: если в server.json расписание включено, а файла
# юнита в /etc/systemd/system/ нет (например, после ручного restore или после
# первого деплоя на новый сервер) — пересоздаём. Это идемпотентно: если файл
# уже на месте и интервал тот же, ничего не меняется.
# === Protocol versions: current vs latest ===
# Кеш версий с GitHub (latest) — 1 час в RAM, чтобы не дёргать github каждый раз.
_VERSION_CACHE = {}  # (repo, allow_prerelease) → (ts, version_str)
_VERSION_TTL_SEC = 3600

# Репозитории, где «стабильных» релизов фактически нет: XTLS помечает Pre-release
# практически всё подряд, и /releases/latest (GitHub исключает из него prerelease)
# навсегда застревает на старом теге — на 2026-09-20 он отдавал v26.3.27 при
# актуальном v26.9.9. Для таких репо смотрим полный список релизов.
# Точечно, не глобально: у 9seconds/mtg и amneziawg нормальные стабильные релизы,
# им prerelease-теги подсовывать нельзя.
_PRERELEASE_REPOS = {'XTLS/Xray-core'}

def _github_max_release_tag(repo):
    """Максимальный по семверу тег среди не-draft релизов, включая pre-release.

    GitHub отдаёт /releases в порядке даты публикации, а не версии, поэтому берём
    максимум, а не первый элемент. Один запрос в api.github.com (без токена —
    60/час на IP), вызывается только из _github_latest_tag под часовым кешем.
    На ошибке или рейт-лимите — '' (вызывающий оставит результат HEAD-редиректа)."""
    try:
        req = urllib.request.Request(
            f'https://api.github.com/repos/{repo}/releases?per_page=30',
            headers={
                'User-Agent': f'awg-panel/{PANEL_VERSION}',
                'Accept': 'application/vnd.github+json',
            },
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode('utf-8', errors='replace'))
    except Exception:
        return ''
    best = ''
    for rel in (data if isinstance(data, list) else []):
        if not isinstance(rel, dict) or rel.get('draft'):
            continue
        tag = (rel.get('tag_name') or '').strip()
        if not re.match(r'^v?\d+\.\d+', tag):
            continue
        if not tag.startswith('v'):
            tag = 'v' + tag
        if not best or _semver_lt(best, tag):
            best = tag
    return best

def _github_latest_tag(repo):
    """Возвращает 'vX.Y.Z' (или 'vX.Y.NNNNNNNN' для date-stamped релизов) с GitHub.

    Сначала пробуем /releases/latest → 302 Location. Если репо не помечает «latest»,
    fallback на API tags: https://api.github.com/repos/<repo>/tags?per_page=1.
    Для репо из _PRERELEASE_REPOS дополнительно сверяемся с полным списком релизов.
    Кеш 1 час. На ошибке — ''."""
    now = time.time()
    allow_pre = repo in _PRERELEASE_REPOS
    key = (repo, allow_pre)
    hit = _VERSION_CACHE.get(key)
    if hit and now - hit[0] < _VERSION_TTL_SEC:
        return hit[1]
    ver = ''
    # 1) /releases/latest → Location
    try:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None
        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(
            f'https://github.com/{repo}/releases/latest',
            headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'},
            method='HEAD',
        )
        try:
            with opener.open(req, timeout=6) as r:
                loc = r.headers.get('Location') or ''
        except urllib.error.HTTPError as e:
            loc = e.headers.get('Location') or ''
        m = re.search(r'/tag/(v?[\w.-]+)', loc or '')
        if m:
            ver = m.group(1)
    except Exception:
        ver = ''
    # 1b) Prerelease-репо: /releases/latest мог отдать давно устаревший стабильный тег.
    # Если полный список дал что-то новее — берём его; если API не ответил, остаётся ver.
    if allow_pre:
        newest = _github_max_release_tag(repo)
        if newest and (not ver or _semver_lt(ver, newest)):
            ver = newest
    # 2) Fallback — API tags (для репо без помеченного «latest release», напр. AWG kernel module)
    if not ver:
        try:
            req = urllib.request.Request(
                f'https://api.github.com/repos/{repo}/tags?per_page=1',
                headers={
                    'User-Agent': f'awg-panel/{PANEL_VERSION}',
                    'Accept': 'application/vnd.github+json',
                },
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode('utf-8', errors='replace'))
            if isinstance(data, list) and data and isinstance(data[0], dict):
                t = data[0].get('name') or ''
                if t:
                    ver = t
        except Exception:
            pass
    if ver and not ver.startswith('v') and re.match(r'^\d', ver):
        ver = 'v' + ver
    _VERSION_CACHE[key] = (now, ver)
    return ver

_VERSION_REFRESHING = set()

def _github_latest_tag_nowait(repo):
    """Для проверок: кеш сразу, устаревший обновляется в фоне. Синхронный поход
    на GitHub держал бы ⚠ в шапке там, где GitHub недоступен. Неудачу кеширует
    сам _github_latest_tag, так что повтор — не чаще раза в час."""
    hit = _VERSION_CACHE.get((repo, repo in _PRERELEASE_REPOS))
    if hit and time.time() - hit[0] < _VERSION_TTL_SEC:
        return hit[1]
    if repo not in _VERSION_REFRESHING:
        _VERSION_REFRESHING.add(repo)

        def _bg():
            try:
                _github_latest_tag(repo)
            finally:
                _VERSION_REFRESHING.discard(repo)
        threading.Thread(target=_bg, daemon=True).start()
    return hit[1] if hit else ''

def _get_awg_kernel_version():
    """`modinfo amneziawg | grep ^version` — возвращает 'vX.Y.Z' или ''."""
    try:
        proc = subprocess.run(['modinfo', 'amneziawg'], capture_output=True, text=True, timeout=5)
        for line in (proc.stdout or '').splitlines():
            if line.startswith('version:'):
                v = line.split(':', 1)[1].strip()
                return ('v' + v) if v and not v.startswith('v') else v
    except Exception:
        pass
    return ''

def _get_awg_apt_candidate():
    """`apt-cache policy amneziawg-dkms` → Candidate. Извлекает 8-значную дату после `~`
    (фактическая дата апстрим-релиза в PPA-версии), форматирует как 'v1.0.<YYYYMMDD>'
    чтобы сравнивалось с modinfo-версией `1.0.YYYYMMDD`."""
    try:
        proc = subprocess.run(
            ['apt-cache', 'policy', 'amneziawg-dkms'],
            capture_output=True, text=True, timeout=8,
        )
        for line in (proc.stdout or '').splitlines():
            line = line.strip()
            if line.startswith('Candidate:'):
                raw = line.split(':', 1)[1].strip()
                if not raw or raw == '(none)':
                    return ''
                # Мажор/минор берём из самой версии пакета. Раньше тут было
                # жёсткое 'v1.0.' + дата: пока PPA жил в ветке 1.0, это совпадало,
                # а после смены ветки панель показывала доступной версию НИЖЕ
                # установленной (v1.0.20260906 против стоящей 3.1.20260812).
                if awg_install:
                    v = awg_install.norm_ver(raw)
                    if v:
                        return f'v{v[0]}.{v[1]}.{v[2]}'
                m = re.search(r'~(\d{8})', raw)
                if m:
                    return 'v1.0.' + m.group(1)
                m2 = re.match(r'^(\d+(?:\.\d+)+)', raw)
                return ('v' + m2.group(1)) if m2 else raw
    except Exception:
        pass
    return ''

def _get_xray_version():
    """`xray version` → 'Xray X.Y.Z (Xray, Penetrates Everything.)...' → 'vX.Y.Z'."""
    try:
        bin_path = shutil.which('xray') or '/usr/local/bin/xray'
        proc = subprocess.run([bin_path, 'version'], capture_output=True, text=True, timeout=5)
        first = (proc.stdout or proc.stderr or '').splitlines()[0] if (proc.stdout or proc.stderr) else ''
        m = re.search(r'\bX[Rr]ay\s+(\d+\.\d+\.\d+)', first)
        return ('v' + m.group(1)) if m else ''
    except Exception:
        return ''


def _semver_lt(a, b):
    """True если a < b по семверу. Принимает 'vX.Y.Z' или 'X.Y.Z'. Пустые → False."""
    def _parse(s):
        s = (s or '').lstrip('v')
        try:
            return tuple(int(x) for x in s.split('.')[:3]) + (0, 0, 0)
        except ValueError:
            return None
    pa, pb = _parse(a), _parse(b)
    if not pa or not pb:
        return False
    return pa[:3] < pb[:3]

def _hysteria_versions_blob():
    """Блок версий Hysteria для /api/system/versions ({} если пакета нет)."""
    try:
        from modules.hysteria import service as hy_service
        cur = hy_service.installed_version()
        latest = hy_service.latest_version()
        return {'hysteria': {
            'installed': hy_service.bin_installed(),
            'installable': True,   # ставит сама панель: бинарь с GitHub + свой юнит
            'current': cur, 'latest': latest,
            'latest_source': 'GitHub',
            'has_update': _semver_lt(cur, latest),
            'updatable': True,
        }}
    except Exception:
        return {}


def _tgweb_versions_blob():
    """Блок версий Telegram WEB (движок telemt) для /api/system/versions.
    Пусто, если пакета нет. Последняя версия — только стабильные релизы:
    releases/latest пропускает pre-release."""
    if not globals().get('tgweb_pkg'):
        return {}
    try:
        from modules.tgweb import service as tg_service
        cur = tg_service.installed_version()
        latest = tg_service.latest_version()
        return {'tgweb': {
            'installed': tg_service.bin_installed(),
            'installable': True,   # ставит сама панель: telemt + nginx + обвязка XRay
            'current': cur, 'latest': latest,
            'latest_source': 'GitHub',
            'has_update': _semver_lt(cur, latest),
            'updatable': True,
        }}
    except Exception:
        return {}


def _proto_update_item(proto):
    """Пункт «движок последней версии» — как tgweb_update у Telegram WEB. Описание у
    каждого своё: откат есть не у всех, обещать его за mtg нельзя. None — версии
    пока неизвестны (нет связи с GitHub или кеш ещё не прогрет)."""
    if proto == 'xray':
        cur, latest = _get_xray_version(), _github_latest_tag_nowait('XTLS/Xray-core')
        dep_id, title = 'xray_core_update', 'XRay'
        how = ('Обновление проверит новое ядро на текущем конфиге пробным запуском и откатится само, '
               'если оно не заработает. XRay перезапустится — клиенты переподключатся сами через пару секунд.')
    elif proto == 'mtg':
        cur, latest = _get_mtg_version(), _github_latest_tag_nowait('9seconds/mtg')
        dep_id, title = 'mtg_core_update', 'mtg'
        how = 'Обновление скачает новый бинарь и перезапустит сервис — Telegram-клиенты переподключатся сами.'
    elif proto == 'hysteria':
        if not _hysteria_pkg_present():
            return None
        from modules.hysteria import service as hy_service
        if not hy_service.is_active():
            return None
        cur, latest = hy_service.installed_version(), hy_service.latest_version_nowait()
        dep_id, title = 'hy_core_update', 'Hysteria'
        how = ('Обновление заменит бинарь и перезапустит сервис, живые сессии оборвутся. '
               'Если новая версия не запустится, панель вернёт прежнюю.')
    else:
        return None
    if not cur or not latest:
        return None
    upd = _semver_lt(cur, latest)
    item = {
        'id': dep_id, 'level': 'warn', 'name': 'Движок %s последней версии' % title,
        'ok': not upd, 'fixable': upd, 'fix_internal': 'proto_update', 'fix_cmd': '',
        'update_proto': proto, 'long': True, 'eta_hint': 'Скачивание и замена бинаря — обычно до минуты',
        'description': ('Установлена %s — последняя.' % cur) if not upd
                       else ('Установлена %s, вышла %s. %s' % (cur, latest, how)),
    }
    if upd:
        item.update({'ui': 'update', 'ui_label': 'Обновить до %s' % latest})
    return item


@app.route('/api/system/versions', methods=['GET'])
@login_required
def system_versions():
    awg = _find_awg_paths()
    xray = _find_xray_paths()
    mtg = _find_mtg_paths()
    # Версии AWG считает модуль: там единственное корректное сравнение —
    # apt Installed против Candidate руками dpkg. Версия из modinfo
    # (WIREGUARD_VERSION апстрима) с apt-версией несравнима в принципе.
    awg_vi = awg_install.version_info() if (awg_install and awg.get('installed')) else {}
    awg_cur = awg_vi.get('current') or (_get_awg_kernel_version() if awg.get('installed') else '')
    xray_cur = _get_xray_version() if xray.get('installed') else ''
    mtg_cur = _get_mtg_version() if mtg.get('installed') else ''
    awg_latest = awg_vi.get('latest') or _get_awg_apt_candidate()  # apt-cache policy amneziawg-dkms
    xray_latest = _github_latest_tag('XTLS/Xray-core')
    mtg_latest = _github_latest_tag('9seconds/mtg')
    mihomo_cur = mihomo._get_mihomo_version() if mihomo else ''
    mihomo_latest = _github_latest_tag(mihomo.MIHOMO_REPO) if (mihomo and mihomo_cur) else ''
    return jsonify({
        'awg': {
            'installed': bool(awg.get('installed')),
            'current': awg_cur, 'latest': awg_latest,
            'latest_source': 'PPA',  # версия берётся из apt-cache policy amneziawg-dkms, а не с GitHub
            'installable': bool(awg_install),
            'has_update': (awg_vi.get('has_update') if awg_vi
                           else _semver_lt(awg_cur, awg_latest)),
            # Версия загруженного в ядро модуля — справочно: это внутренняя метка
            # апстрима, она не сопоставима с версией пакета.
            'module_version': awg_vi.get('module_version', ''),
            # Обновляем через apt (ppa:amnezia/ppa): пакет виден — значит панель умеет
            # пересобрать модуль сама. Если пакета нет (Debian, репо не подключён),
            # остаётся кнопка «Инструкция» и ручной путь из исходников.
            'updatable': bool(awg_install and awg_latest),
        },
        'xray': {
            'installed': bool(xray.get('installed')),
            'installable': True,   # ставится панелью официальным установщиком
            'current': xray_cur, 'latest': xray_latest,
            'latest_source': 'GitHub',
            'has_update': _semver_lt(xray_cur, xray_latest),
            'updatable': True,
        },
        'mtg': {
            'installed': bool(mtg.get('installed')),
            'installable': True,   # ставится панелью официальным установщиком
            'current': mtg_cur, 'latest': mtg_latest,
            'latest_source': 'GitHub',
            'has_update': _semver_lt(mtg_cur, mtg_latest),
            'updatable': True,
        },
        # Hysteria спрашиваем у её пакета: версии и релизы знает он сам.
        # Пакета может не быть (файлы не залиты) — тогда просто не отдаём блок.
        **_hysteria_versions_blob(),
        **_tgweb_versions_blob(),
        # Кнопка «Обновить» у mihomo не нужна: он обновляется тихо и с откатом,
        # настройка периода — в модалке Mihomo.
        'mihomo': {
            'installed': bool(mihomo and mihomo._mihomo_installed()),
            'current': mihomo_cur, 'latest': mihomo_latest,
            'latest_source': 'GitHub',
            'has_update': _semver_lt(mihomo_cur, mihomo_latest),
            'updatable': False,
            'silent_update': True,
        },
    })

AWG_UPDATE_INSTRUCTIONS_MD = """# Обновление AmneziaWG (модуль ядра) из исходников

> AWG устанавливается как DKMS-модуль. Обновление = замена исходников + пересборка.
> Во время обновления AWG-туннель будет недоступен ~10–30 секунд.

---

## 1. Узнать текущую и доступную версию

```bash
# Текущая версия модуля на сервере
modinfo amneziawg | grep '^version'

# Последний тег на GitHub
curl -sI https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/releases/latest | grep -i location | grep -oP 'v[\\d.]+'
```

Если версии совпадают — обновление не нужно.

---

## 2. Скачать исходники нужной версии

```bash
# Клонируем репозиторий во временную папку
cd /tmp && git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git

# Переключаемся на нужный тег (замените версию на актуальную)
cd amneziawg-linux-kernel-module && git checkout v1.0.20260329-2
```

---

## 3. Удалить старый модуль из DKMS

```bash
# Удаляет скомпилированный модуль для всех ядер
dkms remove amneziawg/1.0.0 --all
```

---

## 4. Заменить исходники

```bash
# Удаляем старые исходники
rm -rf /usr/src/amneziawg-1.0.0

# Копируем новые
cp -r /tmp/amneziawg-linux-kernel-module/src /usr/src/amneziawg-1.0.0
```

---

## 5. Прописать версию в исходниках

Разработчики не обновляют версию в коде между релизами — нужно прописать вручную.
Без этого `modinfo` будет показывать старую версию даже после обновления.

```bash
# Замените 1.0.20260329 на версию из тега (без "v")
sed -i 's/WIREGUARD_VERSION = .*/WIREGUARD_VERSION = 1.0.20260329/' /usr/src/amneziawg-1.0.0/Makefile
sed -i 's/#define WIREGUARD_VERSION ".*"/#define WIREGUARD_VERSION "1.0.20260329"/' /usr/src/amneziawg-1.0.0/version.h
```

---

## 6. Собрать и установить новый модуль

```bash
# Регистрируем модуль в DKMS
dkms add -m amneziawg -v 1.0.0

# Компилируем под текущее ядро
dkms build -m amneziawg -v 1.0.0

# Устанавливаем
dkms install -m amneziawg -v 1.0.0
```

---

## 7. Перезагрузить модуль и поднять интерфейс

```bash
# Опускаем интерфейс, выгружаем старый модуль, загружаем новый, поднимаем интерфейс
awg-quick down awg0 && rmmod amneziawg && modprobe amneziawg && awg-quick up awg0
```

⚠️ AWG-клиенты отключатся на несколько секунд и переподключатся автоматически.

---

## 8. Проверить

```bash
# Должна показать новую версию
modinfo amneziawg | grep '^version'

# Интерфейс поднят, порт 443
awg show awg0
```

---

## 9. Почистить временные файлы

```bash
rm -rf /tmp/amneziawg-linux-kernel-module
```
"""

@app.route('/api/system/awg-update-instructions', methods=['GET'])
@login_required
def system_awg_update_instructions():
    """Инструкция по ручному обновлению модуля AWG. Текст зашит в код панели."""
    return jsonify({'ok': True, 'markdown': AWG_UPDATE_INSTRUCTIONS_MD})

@app.route('/api/system/install/<proto>', methods=['POST'])
@login_required
def system_install_proto(proto):
    """Установка протокола прямо из блока версий — та же операция, что кнопка в
    «Зависимостях», просто под рукой: увидел «не установлен» — поставил.

    Всегда в фоне: установка XRay идёт минуты, а AWG ещё и собирает модуль ядра,
    и синхронный ответ упёрся бы в таймаут gunicorn.
    """
    if proto == 'awg':
        if not awg_install:
            return jsonify({'ok': False, 'error': 'модуль awg_install.py не загружен'}), 400
        return jsonify(_dep_fix_job_start('install:awg', awg_install.install,
                                          steps=awg_install.INSTALL_STEPS))
    if proto == 'xray':
        return jsonify(_dep_fix_job_start('install:xray', _install_xray))
    if proto == 'mtg':
        return jsonify(_dep_fix_job_start('install:mtg', _install_mtg))
    if proto == 'hysteria':
        # Установка целиком в пакете: подбор порта, бинарь с GitHub, сертификат,
        # конфиг, юнит и ufw — та же setup(), что и у кнопки в «Зависимостях».
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return jsonify({'ok': False, 'error': f'протокол Hysteria не подключён: {e}'}), 400

        def _hy_install_job():
            ok, note = hy_service.setup()
            _VERSION_CACHE.clear()
            if not ok:
                return False, note
            return True, ('Hysteria 2 установлена и запущена. %s' % note).strip()

        return jsonify(_dep_fix_job_start('install:hysteria', _hy_install_job))
    if proto == 'tgweb':
        # Установка по шагам целиком в пакете: условия, nginx, бинарь, порты,
        # конфиг, запуск, фоллбек XRay и сквозная проверка через 443.
        try:
            from modules.tgweb import service as tg_service
        except Exception as e:
            return jsonify({'ok': False, 'error': f'Telegram WEB не подключён: {e}'}), 400

        def _tg_install_job(progress):
            try:
                return tg_service.setup(progress)
            finally:
                _VERSION_CACHE.clear()

        return jsonify(_dep_fix_job_start('install:tgweb', _tg_install_job, steps=tg_service.SETUP_STEPS))
    return jsonify({'ok': False, 'error': f'proto {proto} не ставится из панели'}), 400


def _clean_installer_output(out, limit=800):
    """Хвост вывода установщика без шума: ANSI-цветов, прогресса curl и жалоб
    tput на отсутствие терминала. Для сообщения об ошибке — чтобы в нём была
    причина, а не таблица скорости загрузки."""
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', out or '').replace('\r', '\n')
    keep = []
    for line in text.splitlines():
        l = line.strip()
        if not l or l.startswith('tput:') or '% Total' in l or 'Dload' in l:
            continue
        if re.match(r'^[\d\s.:kMG%-]+$', l):        # строки прогресса curl
            continue
        keep.append(l)
    return '\n'.join(keep)[-limit:] or 'установщик завершился с ошибкой без вывода'


@app.route('/api/system/update/<proto>', methods=['POST'])
@login_required
def system_update_proto(proto):
    res = _proto_update_start(proto)
    return jsonify(res), (200 if res.get('ok') else 400)


def _proto_update_start(proto, job_id=None):
    """Запуск обновления в фоне: кнопка в окне ⚙ и починка из «Зависимостей».
    job_id — ключ задачи для fix-status: у починки это id пункта."""
    job_id = job_id or f'update:{proto}'
    if proto == 'awg':
        # Модуль ядра: пересборка идёт минутами и показывается шагами, поэтому
        # не shell-строкой, как у xray/mtg, а сценарием модуля.
        if not awg_install:
            return {'ok': False, 'error': 'модуль awg_install.py не загружен'}
        return _dep_fix_job_start(job_id, awg_install.update,
                                  steps=awg_install.UPDATE_STEPS)
    if proto == 'xray':
        # Без --version install-release.sh сам идёт в /releases/latest и на XTLS
        # откатывается к последнему не-prerelease тегу — то есть кнопка «Обновить»
        # не делала бы ничего. Ставим ровно тот тег, который панель показала в
        # блоке версий (он же из кеша, лишнего запроса нет). Префикс 'v' скрипту
        # безразличен — он нормализует сам; с --version в GitHub API не ходит.
        target = _github_latest_tag('XTLS/Xray-core')
        if xray_core_update and re.match(r'^v?[\w.-]+$', target or ''):
            # Проверка нового ядра на живом конфиге ДО установки + откат —
            # см. modules/xray_core_update.py. Установщик ниже — только запасной
            # путь, если модуль не доехал.
            def _xray_safe_job():
                try:
                    return xray_core_update.safe_update(target)
                finally:
                    _VERSION_CACHE.clear()
            return _dep_fix_job_start(job_id, _xray_safe_job)
        ver_arg = f' --version {target}' if re.match(r'^v?[\w.-]+$', target or '') else ''
        cmd = ('bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"'
               f' @ install{ver_arg}')
    elif proto == 'mtg':
        cmd = (
            'set -e\n'
            'cd /tmp\n'
            'LATEST=$(curl -sI https://github.com/9seconds/mtg/releases/latest | grep -i ^location | grep -oP "v[\\d.]+" | tr -d "\\r")\n'
            'test -n "$LATEST"\n'
            'curl -sL "https://github.com/9seconds/mtg/releases/download/${LATEST}/mtg-${LATEST#v}-linux-amd64.tar.gz" -o mtg.tar.gz\n'
            'tar xzf mtg.tar.gz\n'
            'install -m 0755 mtg-*-linux-amd64/mtg /usr/local/bin/mtg\n'
            'rm -rf mtg.tar.gz mtg-*-linux-amd64\n'
        )
    elif proto == 'hysteria':
        # Обновление живёт в самом пакете: там уже есть определение архитектуры,
        # скачивание релиза и откат на прежний бинарь, если новый не стартовал.
        try:
            from modules.hysteria import service as hy_service
        except Exception as e:
            return {'ok': False, 'error': f'протокол Hysteria не подключён: {e}'}

        def _hy_update_job():
            ok, msg = hy_service.update_binary()
            _VERSION_CACHE.clear()
            # update_binary() отдаёт либо голую версию, либо готовую фразу
            # («уже последняя версия …») — вторую оборачивать не нужно.
            if ok and msg.startswith('v'):
                msg = 'обновлён до %s' % msg
            return ok, msg

        return _dep_fix_job_start(job_id, _hy_update_job)
    elif proto == 'tgweb':
        # Безопасное обновление в пакете: sha256, пробный запуск нового бинаря
        # рядом с рабочим, замена, проверка моста через 443, откат.
        try:
            from modules.tgweb import service as tg_service
        except Exception as e:
            return {'ok': False, 'error': f'Telegram WEB не подключён: {e}'}

        def _tg_update_job():
            try:
                ok, msg = tg_service.update_binary()
            finally:
                _VERSION_CACHE.clear()
            if ok and re.match(r'^\d+\.\d+', msg or ''):
                msg = 'обновлён до %s' % msg
            return ok, msg

        return _dep_fix_job_start(job_id, _tg_update_job)
    else:
        return {'ok': False, 'error': f'proto {proto} не поддерживает обновление из панели'}

    if proto == 'xray':
        unit, get_ver = 'xray', _get_xray_version
    else:
        unit = (_find_mtg_paths() or {}).get('unit') or 'mtg'
        get_ver = _get_mtg_version

    def _shell_update_job():
        """Скачивание релиза и перезапуск сервиса — в фоне.

        Синхронно делать нельзя: gunicorn запущен с --timeout 30, а установщик
        XRay на медленном канале идёт минуты. Воркера убивали на середине, клиент
        получал HTML-страницу 502 вместо JSON, и выглядело это как «обновление
        сломалось», хотя на сервере оно продолжало идти.

        Остановленный руками сервис обновление не запускает: установщик XRay
        поднимает его сам, поэтому такой сервис после установки гасим обратно.
        В итог — короткая фраза с версиями, а не весь вывод установщика:
        прогресс curl, tput и rm по несуществующим файлам в уведомлении
        выглядели как ошибка при удачном обновлении.
        """
        was = get_ver()
        stopped = run_cmd(f'systemctl is-active {unit}')[0].strip() == 'inactive'
        try:
            proc = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=600)
            out = (proc.stdout or '') + (proc.stderr or '')
            ok = proc.returncode == 0
        except Exception as e:
            return False, str(e)
        # Сбросить кеш версий чтобы UI сразу подтянул новую.
        _VERSION_CACHE.clear()
        if not ok:
            return False, _clean_installer_output(out)
        now = get_ver()
        vers = (f'{was or "?"} → {now or "?"}' if was != now
                else f'{now or "?"} (версия не изменилась)')
        if stopped:
            run_cmd(f'systemctl stop {unit}')
            return True, f'обновлён: {vers}; сервис был остановлен — не запускали'
        run_cmd(f'systemctl restart {unit}')
        for _ in range(10):
            if run_cmd(f'systemctl is-active {unit}')[0].strip() == 'active':
                return True, f'обновлён: {vers}'
            time.sleep(0.5)
        tail, _, _ = run_cmd(f'journalctl -u {unit} -n 15 --no-pager')
        return False, (f'бинарь обновлён ({vers}), но {unit} не поднялся: '
                       + _clean_installer_output(tail))

    return _dep_fix_job_start(job_id, _shell_update_job)

# ============================================================
# Mihomo (Clash.Meta) — каскад через второй VPN
# ============================================================
# Этот сервер (ВПН1) сам становится клиентом второго сервера (ВПН2) и гоняет
# исходящий трафик своих клиентов по clash-правилам, которые ВПН2 отдаёт готовым
# профилем. Что в профиле помечено на прокси — уходит через ВПН2, всё остальное
# (принудительный MATCH,DIRECT в хвосте) идёт напрямую с IP этого сервера.
#
# Принципиально: НИ ОДНОГО правила iptables и никакого tun-режима. Трафик
# попадает в движок только потому, что XRay и mtg сами указывают на его
# socks-порт. Собственный трафик сервера (ssh, панель, nginx, apt, хендшейк с
# ВПН2) движка не касается вообще — поэтому потерять доступ к серверу этой
# фичей нельзя. Обратная сторона: если движок лёг, каскадные сервисы упираются
# в мёртвый socks, поэтому есть сторож (_mihomo_watchdog_loop), который в этом
# случае сам снимает каскад с конфигов.
#
# AWG-клиенты сознательно не заведены в каскад: для них потребовался бы TPROXY
# и перестройка DNS под fake-ip. Добавляется поверх, ничего здесь не ломая.

# Не dirname(CLIENTS_DB): клиентская база уехала в data/awg/, и профили каскада
# уехали бы вместе с ней в чужую папку. Живут в своей — data/mihomo/ (перенос
# со старого пути описан в MIGRATION_MAP).
# --- Бинарь и версия ----------------------------------------------------

# --- Профили и сборка конфига -------------------------------------------

# Из чужого профиля берём ТОЛЬКО эти секции. Всё остальное (в первую очередь
# `tun`, `external-controller`, порты) — наше, иначе присланный конфиг смог бы
# поднять tun-интерфейс и перехватить трафик всего сервера или выставить API
# наружу. Профиль второго сервера безобиден, но полагаться на это нельзя.
# --- Профили из share-ссылок --------------------------------------------
# Второй сервер не обязан быть нашей панелью: у стороннего провайдера на руках
# обычно только ссылка vless:// или hysteria2://, а не clash-конфиг. Сами эти
# протоколы mihomo умеет как есть — не хватало только конвертера ссылки в
# секцию proxies.

# --- Разбор вставленного текста -----------------------------------------
# Поле в модалке одно: ссылка на подписку, clash-yaml или ссылки на узлы.
# Разбирает панель, а не пользователь — иначе «вставь нужное в нужное поле»
# превращается в чёрную дыру, где непонятно, что вообще принято.

# --- Клиент external-controller -----------------------------------------

# --- Связь со вторым сервером и трафик каскада ---------------------------
# «Движок работает» и «API отвечает» ещё не значат, что ВПН2 доступен: узел
# может быть мёртв, а панель светила бы зелёным. Поэтому раз в минуту реально
# дозваниваемся сквозь текущий узел и заодно снимаем счётчики трафика. Проба
# дорогая (настоящее соединение), поэтому она фоновая, а не в опросе статуса.

# --- Вход трафика: XRay --------------------------------------------------

# --- Вход трафика: mtg ---------------------------------------------------

# Тумблеры каскада в server.json — это НАМЕРЕНИЕ пользователя, а не факт.
# Факт живёт в самих конфигах XRay/mtg. Расхождение штатно: включить каскад
# можно и до запуска движка — тогда намерение просто ждёт, а в конфиги ничего
# не пишется, иначе XRay перезапустился бы на мёртвый socks и клиенты
# мгновенно остались бы без интернета. Приведение факта к намерению — sync.

# --- Безопасный режим (предохранитель с автооткатом) ---------------------
# Не блокирует запуск, а даёт окно: включил движок и каскад — есть 5 минут
# проверить. Не успел или потерял связь с сервером — по истечении окна панель
# сама снимает каскад с конфигов, гасит движок и выключает автозапуск, то есть
# всё возвращается в исходное состояние без участия человека.
#
# Откат делает поток панели (_mihomo_watchdog_loop) — только он умеет править
# xray.json и config.toml. systemd-таймер оставлен грубым дублёром на случай,
# если сам процесс панели умер: он читает дедлайн из файла и гасит движок,
# когда окно вышло. Конфиги при этом не откатятся, но и править их некому.

# --- Сторож: окно безопасного режима + работоспособность движка ----------

# --- Тихое авто-обновление бинаря ---------------------------------------

# --- API ------------------------------------------------------------------

# Набор (rule-provider) движок хранит файлом рядом с конфигом: его API отдаёт
# только размер набора, а сами адреса — нет. Читаем файл, чтобы «что внутри»
# было видно из панели, не заходя на сервер.
# === Каталог правил и списков (вынесен в modules/rules.py) =================
# Подключаем до остальных модулей: backup_update получает в deps синхронизацию
# шаблонов bm7/byfox, а она теперь живёт здесь.
from modules import rules as rules_mod

rules_mod.init({
    '_detect_freedom_tag': _detect_freedom_tag,
    '_http_get_bytes': _http_get_bytes,
    '_http_get_text': _http_get_text,
    '_norm_allow_ips': _norm_allow_ips,
    '_public_access_info': _public_access_info,
    '_save_server_config': _save_server_config,
    '_xray_unique_email': _xray_unique_email,
    'audit': audit,
    'find_xray_inbound_idx': find_xray_inbound_idx,
    'load_xray_clients': load_xray_clients,
    'load_xray_config': load_xray_config,
    'save_xray_clients': save_xray_clients,
    'save_xray_config': save_xray_config,
    'schedule_xray_restart': schedule_xray_restart,
    'login_required': login_required,
    'BM7_SERVICES_URL': BM7_SERVICES_URL,
    'BM7_TEMPLATES_FILE': BM7_TEMPLATES_FILE,
    'BYFOX_RULES_BASE': BYFOX_RULES_BASE,
    'BYFOX_RULES_FILE': BYFOX_RULES_FILE,
    'CLIENT_RULE_PLATFORMS': CLIENT_RULE_PLATFORMS,
    'COUNTRIES_CACHE_DIR': COUNTRIES_CACHE_DIR,
    'COUNTRIES_SRC_DIR': COUNTRIES_SRC_DIR,
    'COUNTRIES_ZIP_URL': COUNTRIES_ZIP_URL,
    'LISTS_DEFAULT_MODES': LISTS_DEFAULT_MODES,
    'SERVER_CFG': SERVER_CFG,
    'XRAY_CONFIG': XRAY_CONFIG,
    'XRAY_GLOBAL_CACHE_DB': XRAY_GLOBAL_CACHE_DB,
    'XRAY_RULE_LISTS_DB': XRAY_RULE_LISTS_DB,
    '_ALLOWIP_DENY_TAG': _ALLOWIP_DENY_TAG,
    '_ALLOWIP_MARK': _ALLOWIP_MARK,
    '_GLOBAL_MARK': _GLOBAL_MARK,
    '_xray_restart_lock': _xray_restart_lock,
})
app.register_blueprint(rules_mod.bp)

# Остальной app.py зовёт это по имени: сборка профилей, применение глобальных
# правил, пересборка белых списков при правке клиента, синк шаблонов.
_bm7_date_tuple = rules_mod._bm7_date_tuple
_bm7_local_version = rules_mod._bm7_local_version
_bm7_sync_once = rules_mod._bm7_sync_once
_build_global_rules = rules_mod._build_global_rules
_byfox_rules_sync_once = rules_mod._byfox_rules_sync_once
_client_rule_policy_overrides = rules_mod._client_rule_policy_overrides
_countries_download_and_store = rules_mod._countries_download_and_store
_country_ruleset_available = rules_mod._country_ruleset_available
_country_ruleset_url = rules_mod._country_ruleset_url
_fetch_remote_bm7_date = rules_mod._fetch_remote_bm7_date
_lists_final_policy = rules_mod._lists_final_policy
_normalize_inline_rule_line = rules_mod._normalize_inline_rule_line
_rule_url_for_platform = rules_mod._rule_url_for_platform
_strip_global_rules = rules_mod._strip_global_rules
apply_allow_ip_rules = rules_mod.apply_allow_ip_rules
load_rule_lists = rules_mod.load_rule_lists

# === MTProto-прокси (вынесен в modules/mtg.py) ==============================
# Подключаем раньше остальных модулей: mihomo и backup_update получают
# _find_mtg_paths/mtg_restart_fast в своих deps, а они теперь живут здесь.
from modules import mtg as mtg_mod

mtg_mod.init({
    '_client_ip': _client_ip,
    '_proto_state': _proto_state,
    '_run_capture': _run_capture,
    '_save_server_config': _save_server_config,
    '_systemctl_cat': _systemctl_cat,
    '_tail_bytes': _tail_bytes,
    '_validate_schedule_date': _validate_schedule_date,
    'audit': audit,
    'ensure_firewall_port': ensure_firewall_port,
    'geo_asn_full': geo_asn_full,
    'get_server_ip': get_server_ip,
    'get_xray_inbound_params': get_xray_inbound_params,
    'pick_free_port': pick_free_port,
    'port_conflict': port_conflict,
    'port_owner': port_owner,
    'run_cmd': run_cmd,
    'login_required': login_required,
    'DATA_MTPROTO_DIR': DATA_MTPROTO_DIR,
    'MTG_ACCESS_LOG': MTG_ACCESS_LOG,
    'MTG_BIN': MTG_BIN,
    'MTG_CONFIG': MTG_CONFIG,
    'MTG_FAKE_HOST': MTG_FAKE_HOST,
    'MTG_RECIPIENTS_DB': MTG_RECIPIENTS_DB,
    'MTG_UNIT_FILE': MTG_UNIT_FILE,
    'PANEL_LOGS_DIR': PANEL_LOGS_DIR,
    'SERVER_CFG': SERVER_CFG,
    '_LOG_TTL_CACHE': _LOG_TTL_CACHE,
})
app.register_blueprint(mtg_mod.bp)

# Остальной app.py зовёт эти функции по имени (реестр путей, версии, порты,
# источники правды) и передаёт их дальше в deps других модулей — связываем.
get_mtg_port = mtg_mod.get_mtg_port
get_mtg_fake_host = mtg_mod.get_mtg_fake_host
_install_mtg = mtg_mod._install_mtg
_get_mtg_version = mtg_mod._get_mtg_version
_mtg_debug_enabled = mtg_mod._mtg_debug_enabled
mtg_restart_fast = mtg_mod.mtg_restart_fast


def _find_mtg_paths():
    # list-unit-files + systemctl cat на каждый вызов грузили PID 1 — см. _unit_paths_memo.
    return _unit_paths_memo('mtg', mtg_mod._find_mtg_paths)


# === Hysteria2 как инбаунд XRay =============================================
# Протокол поднимает само ядро XRay: клиенты, правила, профили и статистика —
# общие с VLESS, отдельного движка и своей вкладки у него нет. Сборка инбаунда
# живёт в xray_hysteria.py, здесь только проброс панельных хелперов и ручки.
try:
    from modules import xray_hysteria as xhy

    def _hy_intent_load():
        return dict(SERVER_CFG.get('hysteria_inbound') or {})

    def _hy_intent_save(settings):
        SERVER_CFG['hysteria_inbound'] = dict(settings or {})
        _save_server_config(SERVER_CFG)

    xhy.init({
        'audit': audit,
        'run_cmd': run_cmd,
        'data_dir': DATA_XRAY_DIR,
        'xray_load_config': load_xray_config,
        'xray_save_config': save_xray_config,
        # Сертификат тот же, что у VLESS в режиме TLS; на Reality-серверах его
        # нет, и модуль выпускает самоподписанный с отпечатком для pinSHA256.
        'tls_cert': lambda: (_tls_cert_for_xray() or {}),
        'load_clients': load_xray_clients,
        'save_clients': save_xray_clients,
        'unique_email': _xray_unique_email,
        'sni': get_xray_sni,
        'server_host': lambda: _hy_public_host(),
        'port_owner': port_owner,
        'open_firewall': lambda port: ensure_firewall_port(port, 'udp', 'Hysteria (awg-panel)'),
        # Намерение (порт, маскировка, обфускация) живёт в server.json: иначе
        # выключение инбаунда стирало бы настройки вместе с ним.
        'load_intent': _hy_intent_load,
        'save_intent': _hy_intent_save,
    })
except Exception as _xhy_err:   # панель должна подниматься и без модуля
    xhy = None
    # Почти всегда причина одна: файл модуля не долетел при обновлении. Пишем
    # сразу и путь, и факт наличия файла — иначе «No module named» приходится
    # проверять руками по ssh, а панель об этом молчит.
    _xhy_path = os.path.join(PANEL_ROOT, 'modules', 'xray_hysteria.py')
    XHY_IMPORT_ERROR = (f'{_xhy_err} | ожидался файл {_xhy_path} — '
                        + ('он есть, но не импортируется' if os.path.isfile(_xhy_path)
                           else 'файла нет'))
    print(f'[hysteria-inbound] отключён: {XHY_IMPORT_ERROR}', flush=True)
else:
    XHY_IMPORT_ERROR = ''


def _hy_sync():
    """Синхронизировать users инбаунда после правки списка клиентов XRay.

    Без перезапуска: вызывающий код уже планирует рестарт ядра, а второй подряд
    рвал бы соединения дважды.
    """
    # XDNS — такой же второстепенный вход с теми же клиентами: все места, где
    # меняется состав клиентов, уже зовут эту функцию, поэтому он здесь же.
    _xdns_sync()
    if not xhy:
        return
    try:
        ok, err = xhy.sync()
        if not ok and err:
            audit('warn', f'[Hysteria] инбаунд не синхронизирован: {err}')
    except Exception as e:
        audit('warn', f'[Hysteria] синхронизация не удалась: {e}')


def _hy_diag(st):
    """Диагноз по UDP-порту: кто мешает и чем это лечится.

    Считается и для выключенного инбаунда — иначе неудачное автовключение
    (типовой случай: 443/udp держит AmneziaWG) осталось бы немым, и человек
    видел бы просто «выключена» без единого намёка почему.
    """
    out = {'autoenable_note': SERVER_CFG.get('hysteria_autoenable_note') or '',
           'port_taken_by': '', 'suggested_port': 0, 'awg_port': 0, 'awg_up': False}
    try:
        out['awg_port'] = int(get_awg_listen_port() or 0)
        out['awg_up'] = _awg_iface_up()
    except Exception:
        pass
    port = int(st.get('port') or 0)
    # Сам XRay на своём же порту конфликтом не считается — он отфильтрован по
    # имени процесса внутри _hy_udp_busy. Поэтому порт инбаунда проверяется
    # наравне с остальными: чужой слушатель на нём — настоящая поломка.
    busy = _hy_udp_busy()
    who = busy.get(port, '')
    if who:
        out['port_taken_by'] = who
        alt, _ = pick_free_port(0, 'udp', 'hysteria', extra_busy=tuple(busy.keys()))
        out['suggested_port'] = alt
    return out


def _hy_card_state():
    """Состояние Hysteria для карточки XRay: статус плюс диагноз по порту.

    Отдаётся всегда, даже когда инбаунд выключен: плитка показывает строку в
    обоих состояниях, иначе о появлении Hysteria и о том, почему она не
    поднялась, узнать было бы неоткуда.
    """
    if not xhy:
        return {'enabled': False, 'module': False, 'error': XHY_IMPORT_ERROR}
    try:
        st = xhy.status()
    except Exception as e:
        return {'enabled': False, 'module': True, 'error': str(e)}
    st['module'] = True
    try:
        st.update(_hy_diag(st))
    except Exception:
        pass
    return st


@app.route('/api/xray/hysteria', methods=['GET'])
@login_required
def xray_hysteria_status():
    if not xhy:
        return jsonify({'ok': False, 'error': (
            'модуль xray_hysteria.py не загружен — обновление доехало не полностью. '
            'Накатите обновление панели заново, оно кладёт все файлы из архива. '
            + (XHY_IMPORT_ERROR or ''))}), 400
    st = xhy.status()
    return jsonify({'ok': True, **st, **_hy_diag(st)})


@app.route('/api/xray/hysteria', methods=['POST'])
@login_required
def xray_hysteria_save():
    """Включение/выключение инбаунда и его настройки одной ручкой.

    Выключение не трогает пароли клиентов: включённый обратно инбаунд отдаёт те
    же ссылки, которые уже разошлись по устройствам.
    """
    if not xhy:
        return jsonify({'ok': False, 'error': (
            'модуль xray_hysteria.py не загружен — обновление доехало не полностью. '
            'Накатите обновление панели заново, оно кладёт все файлы из архива. '
            + (XHY_IMPORT_ERROR or ''))}), 400
    data = request.get_json(silent=True) or {}
    cur = xhy.read_settings()
    settings = dict(cur)
    for key in ('port', 'up_mbps', 'down_mbps'):
        if key in data:
            try:
                settings[key] = max(0, int(data[key] or 0))
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'error': f'поле {key} должно быть числом'}), 400
    for key in ('masquerade_url', 'obfs_password'):
        if key in data:
            settings[key] = (data[key] or '').strip()
    # Смена источника сертификата. 'auto' — брать серт домена, если он есть;
    # 'self' — держаться самоподписанного. Решение осознанное: отпечаток
    # самоподписанного зашит в выданные ссылки, и переход рвёт их все.
    if 'cert_mode' in data:
        mode = (data.get('cert_mode') or '').strip() or 'auto'
        if mode not in ('auto', 'self'):
            return jsonify({'ok': False, 'error': 'cert_mode должен быть auto или self'}), 400
        if mode != settings.get('cert_mode'):
            audit('warn', f'Hysteria: сертификат переключён на «{mode}» — '
                          'ранее выданные ссылки могут перестать работать')
        settings['cert_mode'] = mode
    if not 1 <= int(settings.get('port') or 0) <= 65535:
        return jsonify({'ok': False, 'error': 'порт вне диапазона'}), 400

    want = bool(data.get('enabled')) if 'enabled' in data else xhy.enabled()
    # Рестарт ядра — не внутри запроса, а после ответа. Там, где панель отдаётся
    # фоллбеком самого XRay, синхронный restart рвёт её собственное соединение:
    # настройка применена, а браузер видит «Failed to fetch» и красное
    # «не сохранено». Планировщик перезапустит ядро через полторы секунды —
    # ответ к тому времени уже ушёл.
    if not want:
        # Сохранение при выключенном тумблере — это правка настроек на будущее,
        # а не выключение: раньше порт терялся, а XRay зря перезапускался.
        was_on = xhy.enabled()
        xhy.remember_settings(settings)
        if not was_on:
            return jsonify({'ok': True, 'restart_scheduled': False, **xhy.status()})
        ok, err = xhy.remove_inbound(restart=False)
        if not ok:
            return jsonify({'ok': False, 'error': err}), 500
        schedule_xray_restart()
        audit('warn', 'Hysteria-инбаунд выключен')
        return jsonify({'ok': True, 'restart_scheduled': True, **xhy.status()})

    # Инбаунд знает только про реальных слушателей, а по реестру видно и тех,
    # кто сейчас опущен: AmneziaWG со своим ListenPort в awg0.conf поднимется
    # позже и уронит либо себя, либо XRay целиком — вместе с VLESS.
    clash = port_conflict(settings.get('port'), 'udp', ignore_kind='xray_hy')
    if clash:
        return jsonify({'ok': False, 'error': clash}), 400
    # Порт свободен, но закреплён за остановленным соседом — разрешаем и
    # предупреждаем: столкнутся они позже, когда тот сервис запустят.
    idle = port_conflict(settings.get('port'), 'udp', ignore_kind='xray_hy', include_idle=True)

    ok, err = xhy.apply_inbound(settings, restart=False)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 500
    schedule_xray_restart()
    _HY_BUSY_CACHE.update({'ts': 0, 'data': {}})
    audit('info', f"Hysteria-инбаунд применён (UDP {settings.get('port')})"
                  + (f' — внимание: {idle}' if idle else ''))
    return jsonify({'ok': True, 'warning': idle, 'restart_scheduled': True, **xhy.status()})


# --- Порт инбаунда Hysteria: та же пара роутов, что у AWG/MTProto/Hysteria ---
# Порт зашит в каждую выданную ссылку, поэтому смена — отдельная операция с
# подтверждением и откатом, а не поле общей формы «Сохранить». UI зовёт её из
# общего блока порта (kind 'xray_hy' → /api/xray_hy/port).

def _xhy_port_state():
    s = xhy.read_settings() if xhy else {}
    port = int(s.get('port') or 0)
    return {'port': port, 'proto': 'udp',
            'enabled': bool(xhy and xhy.enabled()),
            'conflict': port_conflict(port, 'udp', ignore_kind='xray_hy', include_idle=True)}


def _xhy_close_old_port(port):
    """Снять ufw-правило со старого порта, если он больше никому не нужен:
    ни живому слушателю, ни соседу по реестру (AWG может лежать, но держать его)."""
    try:
        port = int(port or 0)
        if not port or port_owner(port, 'udp'):
            return
        if port_conflict(port, 'udp', ignore_kind='xray_hy', include_idle=True):
            return
        active, _ = ufw_active()
        if active:
            run_cmd(f'ufw delete allow {port}/udp')
    except Exception:
        pass


def _xhy_port_watch(old_settings, new_port, t0):
    """Фоном: дождаться рестарта XRay; не поднялся — вернуть прежний порт.

    Рестарт идёт после ответа (панель может отдаваться фоллбеком XRay), поэтому
    откат не может жить в самом запросе."""
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(1)
        st = _xray_restart_status
        if st.get('pending') or st.get('running') or (st.get('ts') or 0) < t0:
            continue
        if st.get('ok'):
            _xhy_close_old_port(old_settings.get('port'))
            return
        break
    else:
        return   # статуса не дождались — не трогаем, чтобы не откатить удачное
    ok, err = xhy.apply_inbound(old_settings, restart=False)
    schedule_xray_restart()
    audit('warn', f'Hysteria-инбаунд: на {new_port}/udp XRay не поднялся, порт возвращён на '
                  f"{old_settings.get('port')}" + ('' if ok else f' (откат не удался: {err})'))


@app.route('/api/xray_hy/port', methods=['GET'])
@login_required
def xhy_port_get():
    if not xhy:
        return jsonify({'ok': False, 'error': 'модуль xray_hysteria.py не загружен'}), 400
    return jsonify({'ok': True, **_xhy_port_state()})


@app.route('/api/xray_hy/port', methods=['POST'])
@login_required
def xhy_port_set():
    if not xhy:
        return jsonify({'ok': False, 'error': 'модуль xray_hysteria.py не загружен'}), 400
    data = request.get_json(silent=True) or {}
    try:
        new_port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'порт должен быть числом'}), 400
    if not 1 <= new_port <= 65535:
        return jsonify({'ok': False, 'error': 'порт вне диапазона 1–65535'}), 400
    cur = xhy.read_settings()
    old_port = int(cur.get('port') or 0)
    if new_port == old_port:
        return jsonify({'ok': True, 'unchanged': True, 'old_port': old_port, **_xhy_port_state()})
    clash = port_conflict(new_port, 'udp', ignore_kind='xray_hy')
    if clash:
        return jsonify({'ok': False, 'error': clash}), 400
    idle = port_conflict(new_port, 'udp', ignore_kind='xray_hy', include_idle=True)
    new = dict(cur, port=new_port)

    # Инбаунд выключен — только запоминаем: применится при включении.
    if not xhy.enabled():
        xhy.remember_settings(new)
        audit('info', f'Hysteria-инбаунд (выключен): порт {old_port} → {new_port}/udp')
        return jsonify({'ok': True, 'old_port': old_port, 'warning': idle,
                        'restart_scheduled': False, **_xhy_port_state()})

    ok, err = xhy.apply_inbound(new, restart=False)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 500
    t0 = time.time()
    schedule_xray_restart()
    _HY_BUSY_CACHE.update({'ts': 0, 'data': {}})
    threading.Thread(target=_xhy_port_watch, args=(dict(cur), new_port, t0), daemon=True).start()
    audit('warn', f'Hysteria-инбаунд: UDP-порт {old_port} → {new_port} — выданные ссылки нужно '
                  'раздать заново' + (f' — внимание: {idle}' if idle else ''))
    return jsonify({'ok': True, 'old_port': old_port, 'warning': idle,
                    'restart_scheduled': True, **_xhy_port_state()})


# === XDNS — третий вход XRay, через DNS-запросы ==============================
# Аварийный канал на случай «белых списков»: трафик идёт DNS-запросами через
# резолвер оператора к поддомену, делегированному этому серверу. Клиенты те же,
# что у VLESS и Hysteria. Сборка, конфиг клиента и вся диагностика — в
# modules/xray_xdns.py, здесь проброс хелперов и ручки.

_XRAY_VER_CACHE = {'key': None, 'ver': ''}


def _xray_core_version():
    """Версия установленного ядра с кешем по mtime бинаря: статус XDNS и живое
    добавление пользователей спрашивают её часто, а `xray version` — процесс."""
    try:
        key = os.path.getmtime(XRAY_BIN)
    except OSError:
        return ''
    if _XRAY_VER_CACHE['key'] != key or not _XRAY_VER_CACHE['ver']:
        _XRAY_VER_CACHE.update({'key': key, 'ver': _get_xray_version()})
    return _XRAY_VER_CACHE['ver']


try:
    from modules import xray_xdns as xdns

    def _xdns_intent_load():
        return dict(SERVER_CFG.get('xdns_inbound') or {})

    def _xdns_intent_save(settings):
        SERVER_CFG['xdns_inbound'] = dict(settings or {})
        _save_server_config(SERVER_CFG)

    def _xdns_panel_domain():
        cert = _tls_cert_for_xray() or {}
        return cert.get('domain') or (SERVER_CFG.get('sni') or '').strip()

    xdns.init({
        'audit': audit,
        'run_cmd': run_cmd,
        'data_dir': DATA_XRAY_DIR,
        'xray_bin': XRAY_BIN,
        'xray_version': _xray_core_version,
        'xray_load_config': load_xray_config,
        'xray_save_config': save_xray_config,
        'load_clients': load_xray_clients,
        'unique_email': _xray_unique_email,
        # Слушаем адрес, на который приходят пакеты (за NAT — внутренний), а в
        # A-запись NS-хоста идёт публичный.
        'outbound_ip': _detect_server_ip,
        'public_ip': get_server_ip,
        'panel_domain': _xdns_panel_domain,
        'listening_sockets': listening_sockets,
        'open_firewall': lambda port: ensure_firewall_port(port, 'udp', 'XDNS (awg-panel)'),
        'load_intent': _xdns_intent_load,
        'save_intent': _xdns_intent_save,
        'remark': lambda c, uuid: _profile_filename(c.get('name') or 'client', c.get('token')),
    })
except Exception as _xdns_err:
    xdns = None
    _xdns_path = os.path.join(PANEL_ROOT, 'modules', 'xray_xdns.py')
    XDNS_IMPORT_ERROR = (f'{_xdns_err} | ожидался файл {_xdns_path} — '
                         + ('он есть, но не импортируется' if os.path.isfile(_xdns_path)
                            else 'файла нет'))
    print(f'[xdns] отключён: {XDNS_IMPORT_ERROR}', flush=True)
else:
    XDNS_IMPORT_ERROR = ''


try:
    from modules import xray_core_update
    xray_core_update.init({
        'audit': audit,
        'run_cmd': run_cmd,
        'xray_bin': XRAY_BIN,
        'xray_config': XRAY_CONFIG,
        'get_version': _get_xray_version,
        # Известные несовместимости формата, которые чинятся без участия
        # пользователя, — прогоняются по кандидату конфига до теста ядра.
        'patchers': [p for p in (getattr(xdns, 'patch_format', None),) if p],
    })
except Exception as _xcu_err:
    xray_core_update = None
    print(f'[xray-update] отключён: {_xcu_err}', flush=True)


def _xdns_boot_heal():
    """XDNS, включённый прежней версией панели, — без шифрования VLESS, и
    клиенты на Xray ≥ 26.9 его профиль не запускают. Переводим вход на
    шифрование сами: пользователь ничего не нажимает, клиентам — новые ссылки.
    В фоне с задержкой и под блокировкой: воркеров gunicorn несколько, а ключи
    должна сгенерировать ровно одна пара."""
    time.sleep(8)
    try:
        import fcntl
        lock = open(os.path.join(DATA_XRAY_DIR, '.xdns-heal.lock'), 'w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        return
    try:
        # Формат XDNS сменился в ядре 26.10.10, и старый блок роняет XRay
        # целиком. Чиним файл всегда (двойной формат подходит любому ядру), а
        # лежащее из-за этого ядро поднимаем: failed — поднимать, inactive — нет.
        n, err = xdns.heal_format()
        if err:
            audit('warn', f'XDNS: привести формат конфига не удалось: {err}')
        elif n:
            state = run_cmd('systemctl is-active xray')[0].strip()
            if state == 'failed':
                run_cmd('systemctl reset-failed xray')
                schedule_xray_restart()
                audit('info', 'XDNS: XRay лежал из-за старого формата XDNS — формат исправлен, ядро поднимается')
        if not xdns.needs_encryption():
            return
        ok, err = xdns.apply_inbound(xdns.read_settings())
        if ok:
            audit('info', 'XDNS: вход переведён на шифрование VLESS — клиентам нужно заново выдать '
                          'ссылку или конфиг XDNS')
            schedule_xray_restart(deferred=True)
        else:
            audit('warn', f'XDNS: перевести вход на шифрование не удалось: {err}')
    except Exception as e:
        audit('warn', f'XDNS: проверка шифрования на старте: {e}')
    finally:
        try:
            lock.close()
        except Exception:
            pass


if xdns:
    threading.Thread(target=_xdns_boot_heal, daemon=True).start()


PANEL_FIRST_PORT = 8081


LOGROTATE_CONF = '/etc/logrotate.d/awg-panel'


def _logrotate_conf():
    return (f"{PANEL_LOGS_DIR}/*.log {{\n"
            "    size 100M\n    rotate 10\n    missingok\n    notifempty\n"
            "    compress\n    delaycompress\n    copytruncate\n    su root root\n}\n")


def _logrotate_conf_current():
    """Файл есть и смотрит на нынешнюю папку логов. Старые серверы хранят путь
    Data/Logs ещё с прошлой раскладки: маска ничего не находит, missingok молчит, и
    логи растут без ротации."""
    try:
        with open(LOGROTATE_CONF) as f:
            return f'{PANEL_LOGS_DIR}/' in f.read()
    except OSError:
        return False


def _logrotate_boot():
    """Ротация логов нужна всегда, решать тут нечего: панель настраивает её сама,
    иначе на каждом новом сервере горит ⚠. Файл с нынешней папкой логов не
    переписываем: его могли поправить руками."""
    try:
        if not shutil.which('logrotate'):
            subprocess.run(['apt-get', 'install', '-y', 'logrotate'], capture_output=True, timeout=240,
                           env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
        if not _logrotate_conf_current():
            os.makedirs(os.path.dirname(LOGROTATE_CONF), exist_ok=True)
            with open(LOGROTATE_CONF, 'w') as f:
                f.write(_logrotate_conf())
            audit('info', f'Ротация логов настроена: {LOGROTATE_CONF}')
    except Exception as e:
        audit('warn', f'Ротация логов не настроена: {e}')


threading.Thread(target=_logrotate_boot, daemon=True).start()


PANEL_443_SITE = '/etc/nginx/sites-available/awg-panel-443'
PANEL_443_LINK = '/etc/nginx/sites-enabled/awg-panel-443'
_PANEL_443 = {'hold_until': 0}


def _panel_443_cert():
    """Сертификат для своего входа на 443 или None, если порт занимать нельзя.

    С сертификатом сайт и панель обязаны открываться на https://домен и без XRay.
    Порт только свободный: XRay и Telegram WEB важнее, чужие сайты nginx не трогаем."""
    if time.time() < _PANEL_443['hold_until'] or not shutil.which('nginx'):
        return None
    cert = _le_cert_for(SERVER_CFG.get('sni') or '') or _find_le_cert()
    if not cert:
        return None
    if globals().get('tgweb_pkg'):
        from modules.tgweb import service as _tg
        if _tg.load_settings().get('enabled'):
            return None
    if os.path.exists(XRAY_CONFIG):
        try:
            inbounds = load_xray_config().get('inbounds') or []
        except Exception:
            return None
        if any(int(i.get('port') or 0) == 443 for i in inbounds if i.get('protocol') == 'vless'):
            act = run_cmd('systemctl is-active xray')[0].strip()
            ena = run_cmd('systemctl is-enabled xray')[0].strip()
            if act == 'active' or ena in ('enabled', 'enabled-runtime'):
                return None
    owner = port_owner(443, 'tcp') or ''
    if owner and not owner.startswith('nginx'):
        return None
    rx = re.compile(r'^\s*listen\s+(?:[^\s;]*:)?443(?:\s|;)', re.M)
    for f in glob.glob('/etc/nginx/sites-enabled/*') + glob.glob('/etc/nginx/conf.d/*.conf'):
        if os.path.basename(f).startswith('awg-panel-443'):
            continue
        try:
            with open(f, encoding='utf-8', errors='replace') as fh:
                if rx.search(fh.read()):
                    return None
        except OSError:
            continue
    return cert


def _panel_443_release():
    """Перед тем как порт займёт XRay или Telegram WEB. Придерживаем его на время их
    старта, иначе сторож забрал бы порт обратно раньше, чем они поднимутся."""
    _PANEL_443['hold_until'] = time.time() + 180
    if not os.path.lexists(PANEL_443_LINK) and not os.path.exists(PANEL_443_SITE):
        return
    for p in (PANEL_443_LINK, PANEL_443_SITE):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    run_cmd('systemctl reload nginx')
    audit('info', 'Порт 443 освобождён: его занимает другой сервис')


def _panel_443_sync():
    cert = _panel_443_cert()
    if not cert:
        if time.time() >= _PANEL_443['hold_until'] and os.path.exists(PANEL_443_SITE):
            for p in (PANEL_443_LINK, PANEL_443_SITE):
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass
            run_cmd('systemctl reload nginx')
        return
    full, key, _dom = cert
    ipv6 = '    listen [::]:443 ssl;\n' if os.path.exists('/proc/net/if_inet6') else ''
    conf = (f'# Файл генерирует панель: вход на 443, пока порт не нужен XRay или Telegram WEB.\n'
            f'server {{\n'
            f'    listen 443 ssl;\n{ipv6}'
            f'    server_name _;\n'
            f'    ssl_certificate {full};\n'
            f'    ssl_certificate_key {key};\n'
            f'    ssl_protocols TLSv1.2 TLSv1.3;\n'
            f'    location / {{\n'
            f'        proxy_pass http://127.0.0.1:5000;\n'
            f'        proxy_set_header Host $host;\n'
            f'        proxy_set_header X-Real-IP $remote_addr;\n'
            f'        proxy_set_header X-Forwarded-For $remote_addr;\n'
            f'        proxy_set_header X-Forwarded-Proto https;\n'
            f'    }}\n'
            f'}}\n')
    cur = None
    if os.path.exists(PANEL_443_SITE):
        with open(PANEL_443_SITE) as f:
            cur = f.read()
    if cur == conf and os.path.lexists(PANEL_443_LINK):
        return
    with open(PANEL_443_SITE, 'w') as f:
        f.write(conf)
    if not os.path.lexists(PANEL_443_LINK):
        os.symlink(PANEL_443_SITE, PANEL_443_LINK)
    _, err, rc = run_cmd('nginx -t')
    if rc != 0:
        for p in (PANEL_443_LINK, PANEL_443_SITE):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass
        audit('warn', f'Вход на 443 не включён: {err}')
        return
    run_cmd('systemctl reload nginx')
    ensure_firewall_port(443, 'tcp', 'Панель (awg-panel)')
    audit('info', f'Панель слушает 443: https://{_dom}/')


def _renew_hook_ensure():
    """Deploy-hook certbot: после продления сертификата nginx, XRay и Hysteria обязаны
    его перечитать. Решать тут нечего, поэтому панель ставит хук сама, как только
    появился сертификат. Только запись файла, без запуска: сервисы и так на текущем
    сертификате, а запуск перезапустил бы их без нужды."""
    if not _find_le_cert():
        return
    try:
        from modules.hysteria import service as hy
    except Exception:
        return
    if hy.renew_hook_installed():
        return
    os.makedirs(os.path.dirname(hy.LE_DEPLOY_HOOK), exist_ok=True)
    with open(hy.LE_DEPLOY_HOOK, 'w', encoding='utf-8', newline='\n') as f:
        f.write(hy.RENEW_HOOK_BODY)
    os.chmod(hy.LE_DEPLOY_HOOK, 0o755)
    audit('info', 'Установлен deploy-hook certbot: сервисы перечитают продлённый сертификат')


def _panel_443_watch():
    time.sleep(5)
    while True:
        try:
            _panel_443_sync()
            _renew_hook_ensure()
        except Exception as e:
            audit('warn', f'Вход на 443: {e}')
        time.sleep(60)


threading.Thread(target=_panel_443_watch, daemon=True).start()


def _panel_nginx_heal_redirect():
    """Дописывает редирект в уже опубликованный блок: файл лежит вне папки панели,
    обновление его не меняет. Только одной строкой и с откатом: остальное в блоке трогать незачем."""
    try:
        with open(PANEL_NGINX_SITE) as f:
            old = f.read()
    except OSError:
        return
    if ' ssl;' not in old or 'error_page 497' in old:
        return
    new = re.sub(r'(listen [^\n]* ssl;\n)', lambda m: m.group(1) + PANEL_HTTP_REDIRECT, old, count=1)
    if new == old:
        return
    with open(PANEL_NGINX_SITE, 'w') as f:
        f.write(new)
    _, err, rc = run_cmd('nginx -t')
    if rc != 0:
        with open(PANEL_NGINX_SITE, 'w') as f:
            f.write(old)
        audit('warn', f'Доступ к панели: редирект на https не добавлен: {err}')
        return
    run_cmd('systemctl reload nginx')


def _panel_port_boot():
    """Вход в панель снаружи на новом сервере — без SSH-туннеля и без XRay.

    Пока первого входа не было и XRay нет, панель сама открывает свой порт через
    nginx и пишет адрес рядом с паролем. Рабочие серверы не задеваем: must_change
    снимается первым же входом. Сертификат, выпущенный позже, подхватывается при
    рестарте, но только на порту, открытом здесь: у порта, заданного руками, http
    мог быть выбран намеренно, и переход на https оставил бы человека без входа.
    """
    time.sleep(2)  # пакеты протоколов подключаются ниже по файлу, реестру портов нужны они
    try:
        port = int(SERVER_CFG.get('panel_port') or 0)
        if port:
            _panel_nginx_heal_redirect()
            if SERVER_CFG.get('panel_port_auto') and _find_le_cert() and os.path.exists(PANEL_NGINX_SITE):
                with open(PANEL_NGINX_SITE) as f:
                    plain = ' ssl;' not in f.read()
                if plain:
                    _apply_panel_access_port(port)
                    audit('info', f'Доступ к панели: порт {port} переведён на https')
            return
        if not ADMIN.get('must_change') or not shutil.which('nginx') or os.path.exists(XRAY_BIN):
            return
        port, _ = pick_free_port(PANEL_FIRST_PORT, 'tcp', 'panel')
        if not port:
            return
        _apply_panel_access_port(port)
        SERVER_CFG['panel_port'] = port
        SERVER_CFG['panel_port_auto'] = True
        _save_server_config(SERVER_CFG)
        url = _panel_access_info()['base'] + '/'
        audit('warn', f'Первый запуск: панель открыта на {url}')
        print(f'  Адрес панели: {url}', flush=True)
        hint = os.path.join(os.path.dirname(ADMIN_FILE), 'first_login.txt')
        if os.path.exists(hint):
            with open(hint, 'a', encoding='utf-8') as f:
                f.write(f'Адрес панели: {url}\n')
    except Exception as e:
        audit('warn', f'Первый запуск: порт панели не открыт: {e}')


threading.Thread(target=_panel_port_boot, daemon=True).start()

# Живые проверки протоколов (порты, ufw, iptables, сертификат, DNS) — пункты
# «Зависимостей» и блок «Чтобы … заработал» в окне ⚙ протокола.
try:
    from modules import proto_health
    proto_health.init(
        run_cmd=run_cmd, audit=audit, listening_sockets=listening_sockets,
        awg_port=get_awg_listen_port, awg_config=AWG_CONFIG, awg_iface_addr=get_awg_interface_address,
        xray_port=get_xray_port, xray_security=xray_security_state, server_ip=get_server_ip,
        resolve_a=(xdns.resolve_a if xdns else (lambda name: ([], 'resolver'))),
        mtg_port=get_mtg_listen_port, mtg_unit=(SERVICE_UNITS.get('mtg') or ['mtg'])[0],
        schedule_xray_restart=schedule_xray_restart,
    )
except Exception as _ph_err:
    proto_health = None
    PH_IMPORT_ERROR = f'{_ph_err}'
    print(f'[proto_health] отключён: {PH_IMPORT_ERROR}', flush=True)
else:
    PH_IMPORT_ERROR = ''

# Последняя полная проверка DNS: она ходит в сеть (до ~10 с), а статус вкладки
# опрашивается часто — показываем запомненный результат, перепроверяем по кнопке
# и при открытии вкладки.
_XDNS_LAST_CHECK = {}


def _xdns_sync():
    if not xdns:
        return
    try:
        ok, err = xdns.sync()
        if not ok and err:
            audit('warn', f'[XDNS] инбаунд не синхронизирован: {err}')
    except Exception as e:
        audit('warn', f'[XDNS] синхронизация не удалась: {e}')


def _xdns_apply_user_live(op, email, client_uuid=''):
    """Тот же живой путь, что у VLESS: XDNS — это VLESS-инбаунд, и adu умеет
    его давно. True — применено либо применять нечего."""
    if not xdns:
        return True
    try:
        if not xdns.enabled():
            return True
        if op == 'add':
            c = (load_xray_clients() or {}).get(client_uuid) or {}
            if c.get('disabled'):
                return True
            return _xray_apply_user_live('add', xdns.INBOUND_TAG, email,
                                         {'id': client_uuid, 'email': email},
                                         settings_extra={'decryption': xdns.read_settings().get('vless_dec') or 'none'},
                                         port=xdns.PORT)
        return _xray_apply_user_live('remove', xdns.INBOUND_TAG, email)
    except Exception as e:
        audit('warn', f'XDNS: живое изменение пользователя сорвалось: {e}')
        return False


def _xdns_state():
    st = xdns.status()
    try:
        active, status_out = ufw_active()
        st['ufw'] = {'active': active, 'open': (not active) or ufw_port_open(xdns.PORT, 'udp')}
    except Exception:
        st['ufw'] = {'active': False, 'open': True}
    st['last_check'] = dict(_XDNS_LAST_CHECK)
    st['restart'] = {k: _xray_restart_status.get(k) for k in ('pending', 'running', 'ok', 'error')}
    return st


def _xdns_watch(t0):
    """Фоном: дождаться рестарта XRay после включения XDNS. Не поднялся — снять
    XDNS и перезапустить ещё раз: без этого неудачный вход (порт 53 занят
    процессом, которого не видно в ss, нет прав на 53) оставил бы без связи
    всех клиентов VLESS и Hysteria."""
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(1)
        st = _xray_restart_status
        if st.get('pending') or st.get('running') or (st.get('ts') or 0) < t0:
            continue
        if st.get('ok'):
            return
        break
    else:
        return
    err = _xray_restart_status.get('error') or ''
    ok, _ = xdns.remove_inbound()
    schedule_xray_restart()
    SERVER_CFG['xdns_last_failure'] = {'ts': time.time(), 'error': err[-500:]}
    _save_server_config(SERVER_CFG)
    audit('error', 'XDNS: XRay не поднялся с новым входом — вход снят, ядро перезапущено без него'
                   + (f' ({err[-300:]})' if err else '') + ('' if ok else ' (снять не удалось)'))


def _xdns_unavailable():
    return jsonify({'ok': False, 'error': (
        'модуль xray_xdns.py не загружен — обновление доехало не полностью. '
        'Накатите обновление панели заново. ' + (XDNS_IMPORT_ERROR or ''))}), 400


@app.route('/api/xray/xdns', methods=['GET'])
@login_required
def xray_xdns_status():
    if not xdns:
        return _xdns_unavailable()
    st = _xdns_state()
    st['last_failure'] = SERVER_CFG.get('xdns_last_failure') or {}
    return jsonify({'ok': True, **st})


@app.route('/api/xray/xdns', methods=['POST'])
@login_required
def xray_xdns_save():
    """Включение/выключение и настройки одной ручкой — как у Hysteria."""
    if not xdns:
        return _xdns_unavailable()
    data = request.get_json(silent=True) or {}
    cur = xdns.read_settings()
    settings = dict(cur)
    if 'domain' in data:
        settings['domain'] = xdns.normalize_domain(data.get('domain'))
    if 'ns_host' in data:
        settings['ns_host'] = xdns.normalize_domain(data.get('ns_host'))
    if 'profile' in data:
        if data['profile'] not in xdns.PROFILES:
            return jsonify({'ok': False, 'error': 'неизвестный профиль скорости'}), 400
        settings['profile'] = data['profile']
    if 'resolvers' in data:
        res = []
        for r in (data.get('resolvers') or []):
            r = str(r or '').strip()
            if r and ':' not in r:
                r += ':53'
            host, _, port = r.rpartition(':')
            if not (_is_valid_ipv4(host) and port.isdigit() and 0 < int(port) < 65536):
                return jsonify({'ok': False, 'error': f'резолвер «{r}»: нужен IPv4[:порт]'}), 400
            if r not in res:
                res.append(r)
        if not res:
            return jsonify({'ok': False, 'error': 'нужен хотя бы один резолвер для клиентов'}), 400
        settings['resolvers'] = res[:4]
    if settings.get('domain') and not xdns.valid_domain(settings['domain']):
        return jsonify({'ok': False, 'error': 'поддомен туннеля: нужен вид t.example.com — '
                                              'отдельный поддомен, не сам домен'}), 400

    want = bool(data.get('enabled')) if 'enabled' in data else xdns.enabled()
    was_on = xdns.enabled()
    if not want:
        xdns.remember_settings(settings)
        if not was_on:
            return jsonify({'ok': True, 'restart_scheduled': False, **_xdns_state()})
        ok, err = xdns.remove_inbound()
        if not ok:
            return jsonify({'ok': False, 'error': err}), 500
        schedule_xray_restart()
        audit('warn', 'XDNS выключен')
        return jsonify({'ok': True, 'restart_scheduled': True, **_xdns_state()})

    # Клиентские поля (резолверы) в конфиг сервера не входят: если поменялись
    # только они, ядро трогать незачем — достаточно перевыдать JSON клиентам.
    server_same = was_on and all(settings.get(k) == cur.get(k) for k in ('domain', 'profile'))
    if server_same:
        xdns.remember_settings(settings)
        return jsonify({'ok': True, 'restart_scheduled': False, **_xdns_state()})

    ok, err = xdns.apply_inbound(settings)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    SERVER_CFG.pop('xdns_last_failure', None)
    _save_server_config(SERVER_CFG)
    t0 = time.time()
    schedule_xray_restart()
    threading.Thread(target=_xdns_watch, args=(t0,), daemon=True).start()
    _XDNS_LAST_CHECK.clear()
    audit('info', f"XDNS {'применён' if was_on else 'включён'}: {settings.get('domain')}")
    return jsonify({'ok': True, 'restart_scheduled': True, **_xdns_state()})


@app.route('/api/xray/xdns/check', methods=['POST'])
@login_required
def xray_xdns_check():
    """Полная проверка цепочки: вход на сервере → A-запись NS-хоста →
    делегирование в зоне → сквозной путь через Google/Cloudflare/Яндекс."""
    if not xdns:
        return _xdns_unavailable()
    data = request.get_json(silent=True) or {}
    s = xdns.read_settings()
    # Проверить можно и то, что ещё не сохранено: человек ввёл домен и хочет
    # убедиться, что записи на месте, до включения.
    for key in ('domain', 'ns_host'):
        if data.get(key) is not None:
            s[key] = xdns.normalize_domain(data.get(key))
    try:
        res = xdns.check(s)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'проверка сорвалась: {e}'}), 500
    _XDNS_LAST_CHECK.clear()
    _XDNS_LAST_CHECK.update(res)
    return jsonify({'ok': True, 'check': res, 'records': xdns.records_for(s)})


@app.route('/api/xray/xdns/suggest', methods=['GET'])
@login_required
def xray_xdns_suggest():
    if not xdns:
        return _xdns_unavailable()
    try:
        return jsonify({'ok': True, **xdns.suggest()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/api/xray/xdns/fix', methods=['POST'])
@login_required
def xray_xdns_fix():
    """Починка на месте: открыть 53/udp в ufw, отвязать dnsmasq от внешнего адреса."""
    if not xdns:
        return _xdns_unavailable()
    what = ((request.get_json(silent=True) or {}).get('what') or '').strip()
    if what == 'ufw':
        done, err = ensure_firewall_port(xdns.PORT, 'udp', 'XDNS (awg-panel)')
        if err:
            return jsonify({'ok': False, 'error': err}), 500
    elif what == 'dnsmasq':
        ok, err = xdns.fix_dnsmasq()
        if not ok:
            return jsonify({'ok': False, 'error': err}), 500
    else:
        return jsonify({'ok': False, 'error': 'неизвестная починка'}), 400
    return jsonify({'ok': True, **_xdns_state()})


def build_xdns_link(client_uuid, client=None):
    """Ссылка vless:// для XDNS (с параметром fm). '' — вход выключен."""
    if not xdns or not xdns.enabled():
        return ''
    try:
        c = client or (load_xray_clients().get(client_uuid) or {})
        return xdns.client_link(c, client_uuid)
    except Exception:
        return ''


def build_xdns_config(client_uuid, client=None):
    """JSON-конфиг клиента для вкладки XDNS в «Конфиге». None — вход выключен."""
    if not xdns or not xdns.enabled():
        return None
    try:
        c = client or (load_xray_clients().get(client_uuid) or {})
        return xdns.client_config(c, client_uuid)
    except Exception:
        return None


# === Профили и подписки (вынесены в modules/profiles.py) ==================
# Ставим после секции Hysteria и до mihomo: профилям нужны имена каталога
# правил (их app.py связывает выше), узел xhy для Hysteria в профиле —
# а mihomo в свои deps получает отсюда _clash_nameserver.
from modules import profiles as profiles_mod

profiles_mod.init({
    '_apply_panel_access_port': _apply_panel_access_port,
    '_client_ip': _client_ip,
    '_dns_bootstrap_for': _dns_bootstrap_for,
    '_dns_h2_form': _dns_h2_form,
    '_dns_needs_bootstrap': _dns_needs_bootstrap,
    '_find_client_by_name': _find_client_by_name,
    '_find_client_by_token': _find_client_by_token,
    '_find_le_cert': _find_le_cert,
    '_global_dns_default': _global_dns_default,
    '_is_private_ip': _is_private_ip,
    '_norm_dns': _norm_dns,
    '_panel_port_reserved': _panel_port_reserved,
    '_parse_friendly_path': _parse_friendly_path,
    '_save_server_config': _save_server_config,
    '_strip_token_ext': _strip_token_ext,
    '_validate_safe_name': _validate_safe_name,
    'audit': audit,
    'build_vless_link': build_vless_link,
    'geoip_lookup': geoip_lookup,
    'get_server_ip': get_server_ip,
    'get_xray_inbound_params': get_xray_inbound_params,
    'load_xray_clients': load_xray_clients,
    'pick_free_port': pick_free_port,
    'run_cmd': run_cmd,
    'save_xray_clients': save_xray_clients,
    'ufw_active': ufw_active,
    'ufw_port_open': ufw_port_open,
    'xhy': xhy,
    'login_required': login_required,
    '_client_rule_policy_overrides': _client_rule_policy_overrides,
    '_country_ruleset_available': _country_ruleset_available,
    '_country_ruleset_url': _country_ruleset_url,
    '_lists_final_policy': _lists_final_policy,
    '_normalize_inline_rule_line': _normalize_inline_rule_line,
    '_rule_url_for_platform': _rule_url_for_platform,
    'load_rule_lists': load_rule_lists,
    'PANEL_NGINX_LINK': PANEL_NGINX_LINK,
    'PANEL_NGINX_SITE': PANEL_NGINX_SITE,
    'PROFILE_TOKEN_URL_LEN': PROFILE_TOKEN_URL_LEN,
    'SERVER_CFG': SERVER_CFG,
    'XRAY_PARAMS': XRAY_PARAMS,
    'XRAY_RULE_UPDATE_INTERVAL': XRAY_RULE_UPDATE_INTERVAL,
})
app.register_blueprint(profiles_mod.bp)

# Остальной app.py зовёт это по имени: карточка клиента, ссылка VLESS,
# поиск клиента по имени файла, адрес подписки в «Источниках правды».
_clash_nameserver = profiles_mod._clash_nameserver
_profile_filename = profiles_mod._profile_filename
_safe_filename = profiles_mod._safe_filename
build_clash_profile = profiles_mod.build_clash_profile
build_loon_profile = profiles_mod.build_loon_profile
build_shadowrocket_profile = profiles_mod.build_shadowrocket_profile
profile_public_base = profiles_mod.profile_public_base

# === Миграция со старого протокола Hysteria =================================
#
# ВЫКЛЮЧЕНА НАМЕРЕННО. Мастер миграции переносил клиентов в инбаунд XRay и затем
# вычищал с сервера ВСЁ, что относилось к самостоятельной Hysteria: юнит, бинарь,
# каталоги, clients.json. Протокол вернулся (modules/hysteria/), и запуск мастера
# теперь означал бы снос работающего сервиса вместе с базой клиентов.
#
# Модуль оставлен на диске и не удалён: к инбаунду Hysteria внутри XRay мы ещё
# вернёмся, и тогда мастер понадобится снова. Чтобы включить — раскомментируйте
# блок ниже. Роуты /api/hysteria-migration/* остаются на месте и при hymig=None
# отвечают {'present': False}: фронт по этому ответу прячет вкладку, а не падает.
hymig = None
HYMIG_IMPORT_ERROR = 'миграция отключена: протокол Hysteria вернулся самостоятельным'

# Как включить обратно: вернуть `from modules import hysteria_migrate as hymig`
# внутрь try/except и позвать hymig.init({...}) с deps — audit, run_cmd,
# panel_root, data_root, server_cfg, save_server_cfg, load_xray_clients,
# save_xray_clients, xray_add_uuid, new_uuid, dns_default, panel_tls_cert, xhy.
# Держать этот вызов живым «на всякий случай» нельзя: _hy_autoenable спрашивает
# hymig.present(), и мастер начинает вмешиваться в порт ещё до того, как его
# кто-то открыл.


_HY_BUSY_CACHE = {'ts': 0.0, 'data': {}}


def _awg_iface_up():
    """Поднят ли интерфейс AmneziaWG сейчас.

    Проверяем сам интерфейс, а не юнит: awg-quick@awg0 бывает неактивен, пока
    интерфейс поднят руками, и наоборот. Пока интерфейса нет, его порт свободен.
    """
    out, _, rc = run_cmd('ip -br link show awg0 2>/dev/null')
    if rc == 0 and (out or '').strip():
        return 'UP' in out.upper() or 'UNKNOWN' in out.upper()
    st, _, _ = run_cmd('systemctl is-active awg-quick@awg0')
    return st.strip() == 'active'


def _hy_udp_busy():
    """UDP-порты, которые Hysteria занимать не должна, с указанием — кем.

    Отдельный хелпер, потому что одного `ss` мало: AmneziaWG слушает из ядра,
    и в выводе `ss -ulnp` его сокет нередко идёт без имени процесса, а на части
    ядер не виден вовсе. Занять его порт значит уронить XRay целиком на
    «address already in use» — вместе с VLESS. Поэтому порт AWG читается прямо
    из awg0.conf, независимо от того, видит его ss или нет.
    """
    # Статус инбаунда опрашивается каждые 15 секунд: гонять `ss` на каждый
    # опрос незачем, картина портов так часто не меняется.
    now = time.time()
    if now - _HY_BUSY_CACHE['ts'] < 10 and _HY_BUSY_CACHE['data'] is not None:
        cached = _HY_BUSY_CACHE['data']
        return dict(cached)

    busy = {}
    # Порт AWG считаем занятым, только когда интерфейс реально поднят. Иначе
    # мёртвый сервис держал бы за собой лучший порт: на серверах без AWG в
    # awg0.conf остаётся ListenPort = 443, и Hysteria без нужды уезжала на
    # нестандартный UDP — а его мобильные операторы часто режут.
    try:
        awg_port = int(get_awg_listen_port() or 0)
    except Exception:
        awg_port = 0
    if awg_port and _awg_iface_up():
        busy[awg_port] = 'AmneziaWG (awg0.conf)'
    try:
        for s in listening_sockets():
            if s.get('proto') != 'udp':
                continue
            p = int(s.get('port') or 0)
            if not p or p in busy:
                continue
            who = s.get('process') or 'неизвестный процесс'
            if 'xray' in who.lower():
                continue          # свой же инбаунд
            busy[p] = who
    except Exception:
        pass
    _HY_BUSY_CACHE.update({'ts': now, 'data': dict(busy)})
    return dict(busy)


def _hy_pick_port(preferred):
    """(порт, кто занимал желаемый, кем занят выбранный). 0 — свободных нет."""
    busy = _hy_udp_busy()
    taken_by = busy.get(int(preferred or 0), '')
    if preferred and not taken_by:
        return int(preferred), '', ''
    port, _ = pick_free_port(0, 'udp', 'hysteria', extra_busy=tuple(busy.keys()))
    return port, taken_by, busy.get(port, '')


def _hy_autoenable():
    """Разово поднять инбаунд Hysteria там, где панель обновилась с версии без него.

    Почему само, а не тумблером: Hysteria здесь не новый сервис, а второй вход
    уже работающего ядра — тот же порт, тот же сертификат, те же клиенты и то
    же обновление. Администрировать отдельно нечего, а выключенный инбаунд
    невидим: пользователь просто не узнал бы, что у него появился UDP-транспорт.

    Ровно один раз: флаг ставится и при неудаче тоже. Снятый вручную тумблер
    обратно не включаем — это решение пользователя.
    """
    time.sleep(8)   # дать панели встать, а накату обновления — завершиться
    if not xhy or SERVER_CFG.get('hysteria_autoenabled'):
        return
    # Самостоятельный протокол вернулся и претендует на тот же UDP-порт. Поднять
    # рядом второй вход значит устроить гонку за 443/udp: кто стартует первым,
    # тот и занял, а второй молча не работает. Пока Hysteria живёт отдельным
    # сервисом, инбаунд включается только руками — тумблером в ⚙ «Сервис XRay».
    if _hysteria_pkg_present():
        return
    try:
        # Сервер со старой Hysteria ведёт мастер миграции: он поднимет инбаунд
        # на порту старого демона, чтобы уже розданные ссылки не сломались.
        # Влезать раньше него нельзя — вышел бы лишний переезд порта.
        if hymig and hymig.present():
            return
        st = xhy.status()
        if st.get('error'):
            return                       # XRay не установлен или конфиг не читается
        if st.get('enabled'):            # уже включён руками
            SERVER_CFG['hysteria_autoenabled'] = True
            _save_server_config(SERVER_CFG)
            return
        # Воркеров gunicorn несколько, и все стартуют разом. Писать конфиг и
        # перезапускать ядро должен ровно один.
        lock = os.path.join(DATA_XRAY_DIR, '.hy-autoenable.lock')
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError:
            return

        s = xhy.read_settings()
        # Обфускация: весь смысл Hysteria там, где QUIC режут по сигнатуре.
        # Пароль общий для всех клиентов и попадает в ссылки.
        if not (s.get('obfs_password') or '').strip():
            s['obfs_password'] = secrets.token_hex(8)
        # Маскировка под тот же сайт, что и у VLESS: посторонний, постучавшийся
        # по UDP, увидит ровно то же, что по TCP.
        sni = (SERVER_CFG.get('sni') or '').strip()
        if sni and (s.get('masquerade_url') or '') in ('', xhy.DEFAULT_MASQUERADE):
            s['masquerade_url'] = f'https://{sni}'

        # Порт подбираем, а не назначаем: 443/udp — типовой порт AmneziaWG, и на
        # части серверов он занят именно им. Заняли бы его — XRay не поднялся бы
        # вообще, вместе с VLESS.
        port, taken_by, _ = _hy_pick_port(s.get('port') or xhy.DEFAULT_PORT)
        note = ''
        if not port:
            SERVER_CFG['hysteria_autoenabled'] = True
            SERVER_CFG['hysteria_autoenable_note'] = (
                f'свободного UDP-порта не нашлось ({taken_by or "все кандидаты заняты"})')
            _save_server_config(SERVER_CFG)
            audit('warn', '[Hysteria] автовключение пропущено: свободный UDP-порт не нашёлся')
            return
        if int(port) != int(s.get('port') or 0):
            note = (f'порт {s.get("port")}/udp занят ({taken_by}), инбаунд поднят на {port}/udp'
                    if taken_by else f'инбаунд поднят на {port}/udp')
            s['port'] = int(port)

        ok, err = xhy.apply_inbound(s)
        SERVER_CFG['hysteria_autoenabled'] = True
        SERVER_CFG['hysteria_autoenable_note'] = '' if ok else str(err or '')
        _save_server_config(SERVER_CFG)
        if ok:
            audit('info', f"[Hysteria] инбаунд включён автоматически: UDP {s.get('port')}"
                          + (f' ({note})' if note else ''))
        else:
            # Инбаунда нет, но на плитке XRay видно «выключена» с причиной и
            # кнопкой — провал не немой.
            audit('warn', f'[Hysteria] автовключение не удалось: {err}')
    except Exception as e:
        try:
            audit('warn', f'[Hysteria] автовключение не удалось: {e}')
        except Exception:
            pass


threading.Thread(target=_hy_autoenable, daemon=True).start()


def _xray_stats_reconcile():
    """Дописать в конфиг XRay недостающие секции учёта — разово, на старте.

    Раньше секции появлялись только при включении статистики кнопкой. Значит на
    серверах, где она включена давно, новые поля (statsUserOnline для бейджа
    «Устройств») не появились бы никогда: тумблер уже включён, чинить нечего, а
    сама панель конфиг не пересобирала. Функция идемпотентная — если всё на
    месте, конфиг не трогается и рестарта не будет.
    """
    time.sleep(12)   # после автовключения Hysteria, чтобы не было двух рестартов подряд
    try:
        if not os.path.exists(XRAY_CONFIG) or not _xray_stats_wanted():
            return
        if patch_xray_for_stats():
            audit('info', 'XRay: дописаны недостающие секции учёта (statsUserOnline)')
            schedule_xray_restart()
    except Exception as e:
        try:
            audit('warn', f'XRay: сверка секций учёта не удалась: {e}')
        except Exception:
            pass


threading.Thread(target=_xray_stats_reconcile, daemon=True).start()


@app.route('/api/hysteria-migration', methods=['GET'])
@login_required
def hysteria_migration_status():
    if not hymig:
        return jsonify({'ok': False, 'present': False}), 200
    return jsonify({'ok': True, **hymig.status()})


@app.route('/api/hysteria-migration/migrate', methods=['POST'])
@login_required
def hysteria_migration_migrate():
    """Перенос клиентов. Порядок жёсткий и важен:

    1) гасим старый демон — иначе он держит UDP-порт и инбаунд не поднимется;
    2) поднимаем инбаунд на ТОМ ЖЕ порту с той же обфускацией — только так уже
       розданные ссылки hysteria2:// продолжат работать;
    3) переносим клиентов с их паролями.
    """
    if not hymig:
        return jsonify({'ok': False, 'error': 'модуль миграции не подключён'}), 400
    data = request.get_json(silent=True) or {}
    ids = data.get('ids') or None

    stopped = hymig.stop_services()

    # systemctl возвращается раньше, чем ядро освобождает UDP-сокет. Инбаунд на
    # занятый порт не встанет, а старый демон уже погашен — клиенты остались бы
    # без Hysteria до ручного повтора. Поэтому ждём, пока порт отпустят.
    try:
        old_port = int((hymig.read_settings() or {}).get('port') or 0)
    except (TypeError, ValueError):
        old_port = 0
    if old_port:
        for _ in range(12):
            owner = port_owner(old_port, 'udp') or ''
            if not owner or 'xray' in owner.lower():
                break
            time.sleep(0.5)

    # Сертификат — до подъёма инбаунда: в розданных ссылках зашит pinSHA256
    # старого самоподписанного серта, и инбаунд обязан встать именно на нём,
    # иначе у всех клиентов разом ломается handshake.
    cert_ok, cert_note, cert_err = hymig.adopt_cert()
    if not cert_ok and not data.get('ignore_cert'):
        return jsonify({'ok': False, 'error': f'сертификат: {cert_err}',
                        'cert_blocked': True, 'stopped': stopped}), 409

    adopted, settings = hymig.adopt_settings()
    inbound_note = ''
    if adopted and xhy:
        ok, err = xhy.apply_inbound(settings)
        if not ok:
            return jsonify({'ok': False, 'error': f'инбаунд не поднялся: {err}',
                            'stopped': stopped}), 500
        inbound_note = f"инбаунд поднят на {settings.get('port')}/udp"
    elif not adopted:
        inbound_note = f'настройки старого протокола не перенесены: {settings}'

    ok, report, err = hymig.migrate(ids)
    if not ok:
        return jsonify({'ok': False, 'error': err, 'stopped': stopped,
                        'inbound_note': inbound_note}), 400
    # Пароли перенесённых должны попасть в инбаунд немедленно.
    if xhy:
        xhy.sync(restart=True)
    return jsonify({'ok': True, 'stopped': stopped, 'inbound_note': inbound_note,
                    'cert_note': cert_note or cert_err,
                    **report, **hymig.status()})


@app.route('/api/hysteria-migration/purge', methods=['POST'])
@login_required
def hysteria_migration_purge():
    if not hymig:
        return jsonify({'ok': False, 'error': 'модуль миграции не подключён'}), 400
    data = request.get_json(silent=True) or {}
    ok, report, err = hymig.purge(keep_clients=bool(data.get('keep_clients')))
    if not ok:
        return jsonify({'ok': False, 'error': 'удалено не всё', **report}), 500
    return jsonify({'ok': True, **report, **hymig.status()})


@app.route('/api/hysteria-migration/dismiss', methods=['POST'])
@login_required
def hysteria_migration_dismiss():
    if not hymig:
        return jsonify({'ok': False, 'error': 'модуль миграции не подключён'}), 400
    ok, err = hymig.dismiss()
    return jsonify({'ok': ok, 'error': err}), (200 if ok else 500)


# === Логирование destinations AWG (вынесено в awg_dest_log.py) ==============
# Подключаем в конце файла: к этому моменту все зависимости уже определены, и
# модулю не важен порядок определений в app.py. Зависимости отдаём словарём —
# так модуль ничего не импортирует обратно из app.py и цикла не возникает.
try:
    from modules import awg_dest_log

    awg_dest_log.init({
        'cfg': SERVER_CFG,
        'save_cfg': _save_server_config,
        'audit': audit,
        'login_required': login_required,
        'load_clients': load_clients,
        'awg_network_str': get_awg_network_str,
        'awg_iface_ip': get_awg_iface_ip,
        'tail_bytes': _tail_bytes,
        'logs_dir': PANEL_LOGS_DIR,
        'access_log': AWG_ACCESS_LOG,
        'awg_config': AWG_CONFIG,
    })
    app.register_blueprint(awg_dest_log.bp)
    awg_dest_log.start_background()
except Exception as _adl_err:
    # Панель должна подниматься и без модуля — теряется только сбор destinations.
    # Пишем путь и факт наличия файла: почти всегда причина одна — файл не долетел
    # при обновлении, а «No module named» иначе приходится проверять руками по ssh.
    awg_dest_log = None
    _adl_path = os.path.join(PANEL_ROOT, 'modules', 'awg_dest_log.py')
    ADL_IMPORT_ERROR = (f'{_adl_err} | ожидался файл {_adl_path} — '
                        + ('он есть, но не импортируется' if os.path.isfile(_adl_path)
                           else 'файла нет'))
    print(f'[awg-dest-log] отключён: {ADL_IMPORT_ERROR}', flush=True)
else:
    ADL_IMPORT_ERROR = ''


def _panel_modules_status():
    """Состояние подключаемых модулей: [(файл, назначение, загружен, ошибка)].

    Нужен, потому что неполный накат обновления раньше выглядел как «фича просто
    исчезла»: модуль не долетел, панель поднялась, а причина видна только в
    journalctl. Один пункт зависимостей показывает все модули разом.
    proxy_links.py здесь нет намеренно — он импортируется жёстко в шапке, и без
    него панель вообще не стартует, проверять нечего.
    """
    return [
        ('modules/hysteria/', 'протокол Hysteria 2', bool(hysteria_pkg), HY_IMPORT_ERROR),
        ('modules/tgweb/', 'Telegram WEB-прокси (движок telemt)',
         bool(globals().get('tgweb_pkg')), globals().get('TGWEB_IMPORT_ERROR', '')),
        ('modules/xray_hysteria.py', 'инбаунд Hysteria в XRay', bool(xhy), XHY_IMPORT_ERROR),
        ('modules/xray_xdns.py', 'вход XDNS в XRay (DNS-туннель)', bool(xdns), XDNS_IMPORT_ERROR),
        ('modules/proto_health.py', 'проверки портов, фаервола и сертификатов протоколов',
         bool(proto_health), PH_IMPORT_ERROR),
        # hysteria_migrate.py в список не входит: он выключен намеренно (см. блок
        # «Миграция со старого протокола Hysteria»), и красный крест здесь означал
        # бы поломку там, где всё как задумано.
        ('modules/awg_dest_log.py', 'логирование destinations AWG', bool(awg_dest_log), ADL_IMPORT_ERROR),
        ('modules/awg_install.py', 'установка и обновление AmneziaWG', bool(awg_install), AWI_IMPORT_ERROR),
        ('modules/sys_health.py', 'здоровье сервера', bool(sys_health), SH_IMPORT_ERROR),
        ('modules/mihomo.py', 'каскад через ВПН2 (mihomo)', bool(mihomo), MIHOMO_IMPORT_ERROR),
        ('modules/backup_update.py', 'бэкапы и обновление панели', bool(backup_update), BU_IMPORT_ERROR),
    ]


# === Бэкапы и обновление панели (вынесено в modules/backup_update.py) =======
try:
    from modules import backup_update

    backup_update.init({
        'audit': audit,
        'run_cmd': run_cmd,
        '_save_server_config': _save_server_config,
        '_fmt_bytes': _fmt_bytes,
        '_restart_panel_soon': _restart_panel_soon,
        '_vtuple': _vtuple,
        '_http_get_text': _http_get_text,
        '_http_get_bytes': _http_get_bytes,
        '_local_manifest': _local_manifest,
        '_bm7_sync_once': _bm7_sync_once,
        '_bm7_local_version': _bm7_local_version,
        '_bm7_date_tuple': _bm7_date_tuple,
        '_fetch_remote_bm7_date': _fetch_remote_bm7_date,
        '_byfox_rules_sync_once': _byfox_rules_sync_once,
        '_fetch_remote_geo_version': _fetch_remote_geo_version,
        '_read_local_geo_version': _read_local_geo_version,
        '_geo_newer': _geo_newer,
        '_do_geo_update': _do_geo_update,
        '_do_geo_update_response': _do_geo_update_response,
        '_find_awg_paths': _find_awg_paths,
        '_find_xray_paths': _find_xray_paths,
        '_find_mtg_paths': _find_mtg_paths,
        'login_required': login_required,
        'SERVER_CFG': SERVER_CFG,
        'SERVER_CONFIG_FILE': SERVER_CONFIG_FILE,
        'SECRET_KEY_FILE': SECRET_KEY_FILE,
        'BACKUP_DIR': BACKUP_DIR,
        'UPDATE_BASE_URL': UPDATE_BASE_URL,
        'UPDATE_ZIP_URL': UPDATE_ZIP_URL,
        'PANEL_ROOT': PANEL_ROOT,
        'PANEL_VERSION': PANEL_VERSION,
        'PANEL_RELEASED': PANEL_RELEASED,
    })
    app.register_blueprint(backup_update.bp)
    backup_update.start_background()
except Exception as _bu_err:
    # Без модуля панель работает, но пропадают бэкапы и кнопка обновления кода.
    backup_update = None
    _bu_path = os.path.join(PANEL_ROOT, 'modules', 'backup_update.py')
    BU_IMPORT_ERROR = (f'{_bu_err} | ожидался файл {_bu_path} — '
                       + ('он есть, но не импортируется' if os.path.isfile(_bu_path)
                          else 'файла нет'))
    print(f'[backup-update] отключён: {BU_IMPORT_ERROR}', flush=True)
else:
    BU_IMPORT_ERROR = ''


# === Каскад через ВПН2: mihomo (вынесено в modules/mihomo.py) ===============
try:
    from modules import mihomo

    mihomo.init({
        'audit': audit,
        'run_cmd': run_cmd,
        '_github_latest_tag': _github_latest_tag,
        '_validate_safe_name': _validate_safe_name,
        '_semver_lt': _semver_lt,
        'load_xray_config': load_xray_config,
        'save_xray_config': save_xray_config,
        '_save_server_config': _save_server_config,
        '_global_dns_default': _global_dns_default,
        '_dns_needs_bootstrap': _dns_needs_bootstrap,
        '_dns_h2_form': _dns_h2_form,
        '_dns_bootstrap_for': _dns_bootstrap_for,
        '_clash_nameserver': _clash_nameserver,
        '_dns_is_ip': _dns_is_ip,
        'schedule_xray_restart': schedule_xray_restart,
        'mtg_restart_fast': mtg_restart_fast,
        '_find_mtg_paths': _find_mtg_paths,
        'login_required': login_required,
        # Ссылки на те же объекты, а не копии: словарь настроек в app.py никогда
        # не переприсваивается, кеш версий и замок рестарта xray должны быть общими.
        'SERVER_CFG': SERVER_CFG,
        'DEFAULT_SERVER_CONFIG': DEFAULT_SERVER_CONFIG,
        'XRAY_CONFIG': XRAY_CONFIG,
        'DATA_MIHOMO_DIR': DATA_MIHOMO_DIR,
        'MTG_CONFIG': MTG_CONFIG,
        'PANEL_VERSION': PANEL_VERSION,
        '_VERSION_CACHE': _VERSION_CACHE,
        '_xray_restart_lock': _xray_restart_lock,
    })
    app.register_blueprint(mihomo.bp)
    mihomo.start_background()
except Exception as _mh_err:
    # Без модуля панель живёт, но вкладка каскада и его watchdog пропадают.
    mihomo = None
    _mh_path = os.path.join(PANEL_ROOT, 'modules', 'mihomo.py')
    MIHOMO_IMPORT_ERROR = (f'{_mh_err} | ожидался файл {_mh_path} — '
                           + ('он есть, но не импортируется' if os.path.isfile(_mh_path)
                              else 'файла нет'))
    print(f'[mihomo] отключён: {MIHOMO_IMPORT_ERROR}', flush=True)
else:
    MIHOMO_IMPORT_ERROR = ''


# === Установка/обновление AmneziaWG (awg_install.py) ========================
try:
    from modules import awg_install

    awg_install.init({
        'audit': audit,
        'run_cmd': run_cmd,
        'awg_config': AWG_CONFIG,
        'awg_bin': AWG_BIN,
        'get_awg_port': get_awg_port,
        'pick_free_port': pick_free_port,
        'ensure_firewall_port': ensure_firewall_port,
        'awg_params_fallback': _AWG_PARAMS_FALLBACK,
        'awg_param_keys': _AWG_PARAM_KEYS,
        'port_fallback': _AWG_PORT_FALLBACK,
    })
except Exception as _awi_err:
    # Без модуля панель работает, но установка AWG кнопкой недоступна.
    awg_install = None
    _awi_path = os.path.join(PANEL_ROOT, 'modules', 'awg_install.py')
    AWI_IMPORT_ERROR = (f'{_awi_err} | ожидался файл {_awi_path} — '
                        + ('он есть, но не импортируется' if os.path.isfile(_awi_path)
                           else 'файла нет'))
    print(f'[awg-install] отключён: {AWI_IMPORT_ERROR}', flush=True)
else:
    AWI_IMPORT_ERROR = ''


# === Здоровье сервера (вынесено в sys_health.py) ============================
try:
    from modules import sys_health

    sys_health.init({'login_required': login_required})
    app.register_blueprint(sys_health.bp)
except Exception as _sh_err:
    # Панель поднимается и без модуля — пропадает только вкладка «Здоровье сервера».
    sys_health = None
    _sh_path = os.path.join(PANEL_ROOT, 'modules', 'sys_health.py')
    SH_IMPORT_ERROR = (f'{_sh_err} | ожидался файл {_sh_path} — '
                       + ('он есть, но не импортируется' if os.path.isfile(_sh_path)
                          else 'файла нет'))
    print(f'[sys-health] отключён: {SH_IMPORT_ERROR}', flush=True)
else:
    SH_IMPORT_ERROR = ''


# === Протокол Hysteria 2 (modules/hysteria/) ================================
# Самостоятельный протокол: свой сервис hysteria-server, свой UDP-порт, свои
# клиенты в data/hysteria/ и своя вкладка. Пакет изолирован — панель отдаёт ему
# только хелперы, ничего из него не импортируя, поэтому цикла не возникает.
#
# Подключаем последним: ему нужны построенные профили (profiles_mod), каталог
# правил (rules_mod) и адрес socks движка каскада (mihomo). Всё это связывается
# выше по файлу, и раньше этого места ссылок на них ещё нет.
#
# Обёрнуто в try: если пакет отсутствует или сломан при заливке — панель
# поднимается без него, а не падает целиком.
try:
    from modules import hysteria as hysteria_pkg

    hysteria_pkg.register(app, {
        'login_required': login_required,
        'audit': audit,
        # Не get_xray_sni(): в Reality он отдаёт домен прикрытия, и ссылки
        # Hysteria уходили бы на чужой хост. Источник тот же, что у инбаунда.
        'server_host': _hy_public_host,
        # Занятость портов, подбор свободного и ufw — общие панельные методы,
        # те же, что используют установщики XRay и mtg. port_conflict сверяется
        # с реестром портов панели: сосед по UDP может быть не виден в `ss`
        # (AmneziaWG слушает из ядра) или сейчас лежать, но при старте забрать
        # номер обратно.
        'port_owner': port_owner,
        'port_conflict': port_conflict,
        'pick_free_port': lambda preferred: pick_free_port(preferred, 'udp', 'hysteria'),
        # Что диапазон порт-хоппинга задевать не должен: всё, что на него придёт,
        # hysteria перенаправит себе.
        'udp_reserved_ports': _udp_reserved_ports_for_hop,
        # Фоновый запуск долгих операций — общий реестр панели. Установка тянет
        # бинарь с GitHub и в таймаут gunicorn не укладывается; ключи задач те
        # же, что у /api/system/install|update/hysteria, поэтому кнопка в блоке
        # версий и кнопка на вкладке не запустят две установки разом.
        'job_start': _dep_fix_job_start,
        'open_firewall': lambda port: ensure_firewall_port(port, 'udp', 'Hysteria (awg-panel)'),
        # Имена клиентов по общим правилам панели: латиница/цифры/_/-, нижний регистр.
        'safe_name': lambda s: _normalize_client_name(_validate_safe_name(s)),
        # Сегмент публичного URL профиля — тот же генератор, что у XRay. Иначе
        # настройка «Имя конфига» (friendly/token) работала бы у одних протоколов
        # и молча игнорировалась у других, а имя сервера не попадало бы в профиль.
        'profile_url_seg': profiles_mod._profile_url_seg,
        # Гео по IP — панельные базы MaxMind, свои Hysteria не заводит.
        'geo_lookup': geo_asn_full,
        'geo_locale': _geo_locale,
        # Каталог правил в панели один на все протоколы: серверный acl Hysteria
        # собирается из тех же списков «Global», что и правила XRay, и через
        # тот же кеш скачанных файлов.
        'aggregate_lists': rules_mod._aggregate_global_lists,
        # Куда отправлять трафик при каскаде через ВПН2 — адрес socks движка.
        # Через lambda, а не значением: modules/mihomo.py мог не загрузиться, и
        # тогда каскад просто не включится, а панель поднимется.
        'mihomo_socks': lambda: (f'127.0.0.1:{mihomo.MIHOMO_MIXED_PORT}'
                                 if mihomo else '127.0.0.1:7890'),
        # Генераторы DNS-блоков для клиентских профилей — те же, что у XRay,
        # чтобы синтаксис DoH/DoH3/DoQ везде совпадал.
        'dns_loon': profiles_mod._render_dns_loon,
        'dns_clash': profiles_mod._render_dns_clash,
        'dns_sr': profiles_mod._render_dns_shadowrocket,
        # Полные профили с правилами каталога, странами и группами: узел свой,
        # остальное — общий код панели, тот же что у XRay.
        'loon_profile': build_loon_profile,
        'clash_profile': build_clash_profile,
        'sr_profile': build_shadowrocket_profile,
        # Публичная база ссылок на профили — общая для всех протоколов
        # (profile_public_base): TLS-фоллбек на 443 либо свой порт панели при
        # Reality. Пусто = снаружи панель не опубликована, и UI объясняет, чем
        # именно, через /api/profile-access.
        'panel_public_base': lambda: profile_public_base()[0],
        # Старое имя оставлено для совместимости: пакет может оказаться версией,
        # которая про базу ещё не знает.
        'panel_public_host': lambda: (get_xray_inbound_params().get('sni') or ''
                                      if get_xray_inbound_params().get('security') == 'tls' else ''),
    })
except Exception as _hy_err:
    hysteria_pkg = None
    _hy_path = os.path.join(PANEL_ROOT, 'modules', 'hysteria')
    HY_IMPORT_ERROR = (f'{_hy_err} | ожидался пакет {_hy_path} — '
                       + ('он есть, но не импортируется' if os.path.isdir(_hy_path)
                          else 'каталога нет'))
    print(f'[hysteria] отключена: {HY_IMPORT_ERROR}', flush=True)
else:
    HY_IMPORT_ERROR = ''


# === Telegram WEB-прокси (modules/tgweb/) ===================================
# Новый тип прокси Telegram: кадры MTProxy внутри обычного HTTPS через WebView
# клиента, на нашем домене и 443. Движок telemt, цепочка XRay → nginx →
# telemt; всё про неё — в пакете. Панель отдаёт ему только хелперы.
#
# В try: сломанный или недолитый пакет не должен ронять панель.
try:
    from modules import tgweb as tgweb_pkg

    tgweb_pkg.register(app, {
        'panel_443_release': _panel_443_release,
        'login_required': login_required,
        'audit': audit,
        'job_start': _dep_fix_job_start,
        'geo_lookup': geo_asn_full,
        'safe_name': lambda s: _normalize_client_name(_validate_safe_name(s)),
        # Домен WEB-прокси = домен сертификата, которым XRay терминирует 443:
        # WebView проверяет сертификат, ничего другого там быть не может.
        'tls_domain': lambda: (_tls_cert_for_xray() or {}).get('domain') or '',
        # Тот же сертификат целиком — когда XRay на 443 нет, им терминирует
        # 443 сам nginx WEB-прокси (modules/tgweb/front.py).
        'tls_cert': _tls_cert_for_xray,
        'ensure_fw': ensure_firewall_port,
        # public_addr vhost-а в telemt — конкретный IP сервера.
        'server_ip': get_server_ip,
        'port_owner': port_owner,
        'port_map': panel_port_map,
        'xray_paths': lambda: {'config': (_find_xray_paths() or {}).get('config') or XRAY_CONFIG,
                               'bin': XRAY_BIN},
        # Выход telemt через socks движка каскада. lambda — mihomo может не
        # загрузиться, тогда каскад просто не включится.
        'mihomo_socks': lambda: (f'127.0.0.1:{mihomo.MIHOMO_MIXED_PORT}'
                                 if mihomo else '127.0.0.1:7890'),
        # Установка: напрямую до Telegram не достать (сервер в РФ ходит наружу
        # через каскад) — telemt сразу заводится в движок, если тот отвечает.
        # Намерение пишется и в mihomo, иначе его сверка сняла бы upstream.
        'mihomo_ready': lambda: bool(mihomo and mihomo._mihomo_is_active()
                                     and mihomo._mihomo_api_ok()),
        'mihomo_want_tgweb': lambda on: (mihomo._mihomo_save_cfg({'cascade_tgweb': bool(on)})
                                         if mihomo else None),
    })
except Exception as _tg_err:
    tgweb_pkg = None
    _tg_path = os.path.join(PANEL_ROOT, 'modules', 'tgweb')
    TGWEB_IMPORT_ERROR = (f'{_tg_err} | ожидался пакет {_tg_path} — '
                          + ('он есть, но не импортируется' if os.path.isdir(_tg_path)
                             else 'каталога нет'))
    print(f'[tgweb] отключён: {TGWEB_IMPORT_ERROR}', flush=True)
else:
    TGWEB_IMPORT_ERROR = ''


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
