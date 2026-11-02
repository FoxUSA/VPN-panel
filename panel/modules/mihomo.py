"""Каскад через ВПН2: mihomo — конфиг, профили, узлы, правила, мониторинг, обновление.

Вынесено из app.py. Самый крупный домен панели: 23 роута и весь цикл жизни
mihomo — от установки бинаря до safe-window с автооткатом.

Как связан с app.py. Зависимости приезжают в init() и раскладываются в модульные
переменные с теми же именами, что были в app.py, — поэтому тела функций перенесены
без единой правки внутри. Для 1400 строк это главное: любая «заодно» правка при
переносе превращает отладку в поиск иголки.

SERVER_CFG, _VERSION_CACHE и _xray_restart_lock приезжают как ссылки на те же самые
объекты, что живут в app.py: словарь настроек там никогда не переприсваивается
(при restore делается clear+update), общий кеш версий и замок рестарта xray обязаны
быть одни на процесс.

Фоновые треды (watchdog и проверка обновлений) НЕ стартуют на импорте — только из
start_background(), которую зовёт app.py.
"""

import gzip
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import threading
import time
import urllib.request
import uuid as uuid_lib
from urllib.parse import parse_qs, quote, unquote, urlsplit

from flask import Blueprint, jsonify, request, Response

from modules.proxy_links import (
    _b64text, _yaml_proxy, _yaml_scalar, _yaml_top_sections,
    _link_vless, _link_vmess, _link_trojan, _link_ss,
    _link_hy2, _link_hy1, _link_tuic, _link_anytls,
)

bp = Blueprint('mihomo', __name__)

# Зависимости из app.py: имена те же, что там, — чтобы перенесённый код работал
# без правок. До init() они None/пустые, и модуль умеет только импортироваться.
audit = None
run_cmd = None
_github_latest_tag = None
_validate_safe_name = None
_semver_lt = None
load_xray_config = None
save_xray_config = None
_save_server_config = None
_global_dns_default = None
_dns_needs_bootstrap = None
_dns_h2_form = None
_dns_bootstrap_for = None
_clash_nameserver = None
_dns_is_ip = None
schedule_xray_restart = None
mtg_restart_fast = None
_find_mtg_paths = None
login_required = None
SERVER_CFG = {}
DEFAULT_SERVER_CONFIG = {}
XRAY_CONFIG = ''
DATA_MIHOMO_DIR = ''
MTG_CONFIG = ''
PANEL_VERSION = ''
_VERSION_CACHE = {}
_xray_restart_lock = None

REQUIRED_DEPS = [
    'audit',
    'run_cmd',
    '_github_latest_tag',
    '_validate_safe_name',
    '_semver_lt',
    'load_xray_config',
    'save_xray_config',
    '_save_server_config',
    '_global_dns_default',
    '_dns_needs_bootstrap',
    '_dns_h2_form',
    '_dns_bootstrap_for',
    '_clash_nameserver',
    '_dns_is_ip',
    'schedule_xray_restart',
    'mtg_restart_fast',
    '_find_mtg_paths',
    'SERVER_CFG',
    'DEFAULT_SERVER_CONFIG',
    'XRAY_CONFIG',
    'DATA_MIHOMO_DIR',
    'MTG_CONFIG',
    'PANEL_VERSION',
    '_VERSION_CACHE',
    '_xray_restart_lock',
    'login_required',
]

_started = False


def init(deps):
    """Принять зависимости из app.py (см. REQUIRED_DEPS) в одноимённые глобалы."""
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('mihomo.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    if not DATA_MIHOMO_DIR:
        raise RuntimeError('mihomo.init: пустой DATA_MIHOMO_DIR — пути данных не построить')
    # Пути, растущие из каталога данных, пересчитываем ЗДЕСЬ, а не на импорте:
    # на импорте DATA_MIHOMO_DIR ещё пуст, и os.path.join дал бы относительный
    # 'profiles.json' — файл искался бы рядом с рабочим каталогом процесса.
    # Профили при этом выглядят «слетевшими», хотя лежат на месте.
    global MIHOMO_PROFILES_DB, MIHOMO_SAFE_DEADLINE_FILE
    MIHOMO_PROFILES_DB = os.path.join(DATA_MIHOMO_DIR, 'profiles.json')
    MIHOMO_SAFE_DEADLINE_FILE = os.path.join(DATA_MIHOMO_DIR, 'safe_deadline')


def start_background():
    """Поднять watchdog и проверку обновлений. На импорте ничего не стартует."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_mihomo_watchdog_loop, daemon=True).start()
    threading.Thread(target=_mihomo_update_loop, daemon=True).start()


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роуты объявлены раньше."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


MIHOMO_BIN = '/usr/local/bin/mihomo'

MIHOMO_DIR = '/etc/mihomo'

MIHOMO_CONFIG = os.path.join(MIHOMO_DIR, 'config.yaml')

MIHOMO_UNIT_NAME = 'mihomo'

MIHOMO_UNIT_FILE = '/etc/systemd/system/mihomo.service'

MIHOMO_PROFILES_DB = ''          # реальный путь строится в init() от DATA_MIHOMO_DIR

MIHOMO_REPO = 'MetaCubeX/mihomo'

MIHOMO_MIXED_PORT = 7890          # socks5+http, слушает только 127.0.0.1 (allow-lan: false)

MIHOMO_CTRL_PORT = 9090           # external-controller, тоже только на loopback

MIHOMO_CTRL = f'127.0.0.1:{MIHOMO_CTRL_PORT}'

MIHOMO_SOCKS_URL = f'socks5://127.0.0.1:{MIHOMO_MIXED_PORT}'

MIHOMO_XRAY_TAG = 'mihomo-cascade'

_MIHOMO_MARK = '_panel_mihomo'    # маркер наших вставок в xray-конфиге

MIHOMO_GUARD_NAME = 'awg-panel-mihomo-guard.timer'

MIHOMO_GUARD_SERVICE_FILE = '/etc/systemd/system/awg-panel-mihomo-guard.service'

MIHOMO_GUARD_TIMER_FILE = '/etc/systemd/system/awg-panel-mihomo-guard.timer'

MIHOMO_DELAY_TEST_URL = 'http://www.gstatic.com/generate_204'

def _mihomo_cfg():
    """Настройки каскада из server.json, добитые дефолтами."""
    base = dict(DEFAULT_SERVER_CONFIG['mihomo'])
    cur = SERVER_CFG.get('mihomo')
    if isinstance(cur, dict):
        base.update({k: v for k, v in cur.items() if k in base})
    return base

def _mihomo_save_cfg(patch):
    cfg = _mihomo_cfg()
    cfg.update(patch)
    SERVER_CFG['mihomo'] = cfg
    _save_server_config(SERVER_CFG)
    return cfg

def _mihomo_secret():
    """Ключ к external-controller. Генерится один раз и живёт в server.json."""
    cfg = _mihomo_cfg()
    if not cfg.get('secret'):
        cfg = _mihomo_save_cfg({'secret': secrets.token_hex(16)})
    return cfg['secret']

def _mihomo_installed():
    return os.path.exists(MIHOMO_BIN)

def _get_mihomo_version():
    """`mihomo -v` → 'vX.Y.Z' (или '' если не установлен / не отвечает)."""
    if not _mihomo_installed():
        return ''
    for args in (['-v'], ['-version']):
        try:
            proc = subprocess.run([MIHOMO_BIN] + args, capture_output=True, text=True, timeout=5)
            txt = (proc.stdout or '') + (proc.stderr or '')
            m = re.search(r'\bv?(\d+\.\d+\.\d+)\b', txt)
            if m:
                return 'v' + m.group(1)
        except Exception:
            continue
    return ''

def _mihomo_asset_name(tag):
    """Имя релизного ассета под архитектуру этой машины.

    Для amd64 берём вариант `-compatible`: он собран без требований к
    расширениям процессора (v2/v3) и потому заводится на любой VPS."""
    try:
        machine = (os.uname().machine or '').lower()
    except Exception:
        machine = ''
    if machine in ('x86_64', 'amd64'):
        return f'mihomo-linux-amd64-compatible-{tag}.gz'
    if machine in ('aarch64', 'arm64'):
        return f'mihomo-linux-arm64-{tag}.gz'
    if machine.startswith('armv7') or machine.startswith('armv8l'):
        return f'mihomo-linux-armv7-{tag}.gz'
    return ''

def _mihomo_fetch_binary(tag):
    """Качает и распаковывает бинарь релиза. Возвращает bytes."""
    asset = _mihomo_asset_name(tag)
    if not asset:
        raise RuntimeError('архитектура сервера не поддерживается сборками mihomo')
    url = f'https://github.com/{MIHOMO_REPO}/releases/download/{tag}/{asset}'
    req = urllib.request.Request(url, headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'})
    with urllib.request.urlopen(req, timeout=180) as r:
        blob = r.read()
    data = gzip.decompress(blob)
    # Бинарь mihomo — десятки мегабайт. Если прилетело сильно меньше, это
    # страница ошибки, а не программа: лучше упасть, чем положить мусор.
    if len(data) < 5 * 1024 * 1024:
        raise RuntimeError('скачанный файл слишком мал — похоже, релиз недоступен')
    return data

def _mihomo_write_binary(data):
    """Кладёт новый бинарь, сохраняя предыдущий рядом для отката."""
    os.makedirs(os.path.dirname(MIHOMO_BIN), exist_ok=True)
    if os.path.exists(MIHOMO_BIN):
        try:
            shutil.copy2(MIHOMO_BIN, MIHOMO_BIN + '.prev')
        except Exception:
            pass
    tmp = MIHOMO_BIN + '.new'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, MIHOMO_BIN)

def _mihomo_rollback_binary():
    """Возвращает предыдущий бинарь. True если откат состоялся."""
    prev = MIHOMO_BIN + '.prev'
    if not os.path.exists(prev):
        return False
    try:
        shutil.copy2(prev, MIHOMO_BIN)
        os.chmod(MIHOMO_BIN, 0o755)
        return True
    except Exception:
        return False

def _mihomo_write_unit():
    body = (
        '[Unit]\n'
        'Description=Mihomo cascade (managed by awg-panel)\n'
        'After=network-online.target\n'
        'Wants=network-online.target\n'
        '\n'
        '[Service]\n'
        'Type=simple\n'
        f'ExecStart={MIHOMO_BIN} -d {MIHOMO_DIR}\n'
        'Restart=on-failure\n'
        'RestartSec=3\n'
        'LimitNOFILE=1048576\n'
        '\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
    )
    with open(MIHOMO_UNIT_FILE, 'w') as f:
        f.write(body)
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)

def _mihomo_service(action):
    out, err, rc = run_cmd(f'systemctl {action} {MIHOMO_UNIT_NAME}')
    return rc == 0, (out or err or '')

def _mihomo_is_active():
    out, _, _ = run_cmd(f'systemctl is-active {MIHOMO_UNIT_NAME}')
    return out.strip() == 'active'

def _mihomo_is_enabled():
    out, _, _ = run_cmd(f'systemctl is-enabled {MIHOMO_UNIT_NAME}')
    return out.strip() == 'enabled'

_MIHOMO_KEEP_SECTIONS = ('proxies', 'proxy-providers', 'proxy-groups', 'rule-providers', 'rules')

def _mihomo_match_target(raw, sections=None):
    """Куда уходит всё неперечисленное. По умолчанию DIRECT: профиль, выданный
    клиенту, может заканчиваться `MATCH,<группа>`, и тогда через ВПН2 ушло бы
    вообще всё, включая российские сервисы.

    Исключение — профиль, собранный нами из ссылок в режиме «всё через второй
    VPN»: у него нет правил вовсе, и DIRECT сделал бы каскад пустышкой. Такой
    профиль помечен в шапке `# awg-panel: match=<группа>`. Имя всё равно
    сверяем с тем, что реально объявлено в профиле."""
    m = re.search(r'^#\s*awg-panel:\s*match\s*=\s*([^\s#]+)\s*$', raw or '', re.M)
    if not m:
        return 'DIRECT'
    t = m.group(1).strip()
    if t.upper() in _MIHOMO_BUILTIN_TARGETS:
        return t.upper()
    sections = _yaml_top_sections(raw) if sections is None else sections
    known = set()
    for sec in ('proxies', 'proxy-groups'):
        for line in (sections.get(sec) or [])[1:]:
            mm = re.match(r'^\s*-?\s*name\s*:\s*[\'"]?(.+?)[\'"]?\s*$', line)
            if mm:
                known.add(mm.group(1))
    return t if t in known else 'DIRECT'

def _mihomo_normalize_rules(lines, target='DIRECT'):
    """Хвост правил принудительно переписывается на MATCH,<target>.

    Через каскад должно идти только то, что явно перечислено, поэтому чужой
    MATCH из профиля выбрасывается, а свой дописывается."""
    body = [l for l in lines[1:] if not re.match(r'^\s*-\s*MATCH\s*,', l)]
    while body and not body[-1].strip():
        body.pop()
    return ['rules:'] + body + ['  - MATCH,' + target]

def _mihomo_dns_lines():
    """Секция `dns:` для серверного config.yaml — из DNS Global.

    Нужна потому, что каскадом ходит ВЕСЬ трафик: правила профиля отправляют на
    ВПН2 только перечисленное, а хвост `MATCH,DIRECT` mihomo выпускает сам — и
    для DIRECT резолвит тоже сам. Без этой секции он берёт /etc/resolv.conf
    сервера, и DNS-провайдер клиента (NextDNS) проксируемого трафика не видит.

    Пусто → секции нет, поведение как раньше (системный резолвер).
    """
    d = _global_dns_default()
    if not isinstance(d, dict) or d.get('mode') != 'set':
        return []
    # Как в клиентском конфиге Clash: при заданном DoH plain-IP в nameserver НЕ идут —
    # mihomo опрашивает серверы параллельно и берёт быстрейший, а UDP :53 всегда
    # обгонит TLS-хендшейк, и весь резолв ушёл бы открытым текстом мимо DoH.
    # Место plain-адресов — default-nameserver (бутстрап имени резолвера).
    ns = ([_clash_nameserver(d['doh'])] if d.get('doh')                # h3://X → https://X#h3=true
          else [x for x in (d.get('plain') or []) if _dns_is_ip(x)])
    is_h3 = (d.get('doh') or '').startswith('h3://')
    if is_h3 and d.get('fallback'):
        # Резерв на случай, где режут QUIC. Тот же резолвер и тот же профиль,
        # просто по HTTP/2 — параллельный опрос тут утечкой не грозит.
        h2 = _dns_h2_form(d['doh'])
        if h2:
            ns.append(h2)
    if not ns:
        return []
    # enhanced-mode: redir-host — на сервере нужен НАСТОЯЩИЙ ответ. fake-ip (как в
    # клиентских конфигах) отдал бы 198.18.x.x, и DIRECT-соединения ушли бы в никуда.
    out = ['dns:', '  enable: true', '  ipv6: false', '  enhanced-mode: redir-host']
    if is_h3:
        out.append('  prefer-h3: true')     # DoH-запросы по HTTP/3, как в настройке
    if _dns_needs_bootstrap(ns):
        boot = _dns_bootstrap_for(d)
        if boot:
            out.append('  default-nameserver:')     # чем резолвить имя самого резолвера
            out += [f'    - {x}' for x in boot]
    out.append('  nameserver:')
    out += [f'    - {x}' for x in ns]
    return out

def _mihomo_render_config(raw):
    """Собирает серверный config.yaml из присланного профиля."""
    sections = _yaml_top_sections(raw)
    if 'proxies' not in sections and 'proxy-providers' not in sections:
        raise RuntimeError('в профиле нет секции proxies — это не clash-конфиг')
    target = _mihomo_match_target(raw, sections)
    out = [
        '# Сгенерировано awg-panel. Ручные правки будут перезаписаны при смене профиля.',
        '#',
        '# Из профиля второго сервера взяты только proxies / proxy-groups /',
        '# rule-providers / rules. Порты, контроллер и режим — всегда наши.',
        f'mixed-port: {MIHOMO_MIXED_PORT}',
        'mode: rule',
        'log-level: info',
        'ipv6: false',
        'allow-lan: false',        # socks/API торчат только в loopback
        'unified-delay: true',
        'tcp-concurrent: true',
        'find-process-mode: off',  # PROCESS-NAME-правила на сервере бессмысленны
        'geodata-mode: false',
        'geo-auto-update: true',
        'geo-update-interval: 168',
        f'external-controller: {MIHOMO_CTRL}',
        f'secret: "{_mihomo_secret()}"',
        '',
    ]
    dns_lines = _mihomo_dns_lines()
    if dns_lines:
        out.extend(dns_lines)
        out.append('')
    for name in _MIHOMO_KEEP_SECTIONS:
        if name not in sections:
            continue
        lines = _mihomo_normalize_rules(sections[name], target) if name == 'rules' else sections[name]
        out.extend(lines)
        out.append('')
    if 'rules' not in sections:
        out.extend(['rules:', '  - MATCH,' + target, ''])
    return '\n'.join(out).rstrip('\n') + '\n'

def _mihomo_dns_kind(v):
    """Тип резолвера по схеме URL — так же, как их различает сам mihomo."""
    s = (v or '').strip().lower()
    if s.startswith('h3://'):
        return 'DoH3'
    if s.startswith('https://'):
        # У mihomo DoH3 задаётся либо схемой h3://, либо параметром #h3=true.
        return 'DoH3' if 'h3=true' in s else 'DoH'
    if s.startswith('quic://'):
        return 'DoQ'
    if s.startswith('tls://'):
        return 'DoT'
    if s.startswith('dhcp://'):
        return 'DHCP'
    if s.startswith('system'):
        return 'системный'
    return 'IP'

def _mihomo_profile_summary(raw):
    """Достаёт из профиля адрес второго сервера и его DNS.

    Адрес — чтобы было видно, к какому именно серверу мы подключены: имя узла
    в профиле произвольное («Yandex», «node-1») и о сервере ничего не говорит.
    DNS показываем справочно: секция dns из профиля при сборке отбрасывается —
    движок резолвит DNS'ом из Global (_mihomo_dns_lines), а если тот выключен —
    системным резолвером."""
    sections = _yaml_top_sections(raw)
    out = {'server': '', 'port': '', 'type': '', 'dns': []}
    for line in (sections.get('proxies') or [])[1:]:
        for key in ('type', 'server', 'port'):
            if out[key]:
                continue
            m = re.match(r'^\s*-?\s*' + key + r'\s*:\s*"?([^"\s#]+)"?\s*$', line)
            if m:
                out[key] = m.group(1)
        if out['server'] and out['port'] and out['type']:
            break
    # В секции dns списков несколько, и резолверы — только часть из них.
    # fake-ip-filter, например, это маски доменов-исключений; выгребать всё
    # подряд означало показать вместо DNS кашу из *.lan и +.xboxlive.com.
    resolver_keys = {'nameserver', 'default-nameserver', 'fallback',
                     'proxy-server-nameserver', 'direct-nameserver'}
    seen = set()
    cur_key = ''
    for line in (sections.get('dns') or [])[1:]:
        km = re.match(r'^\s{2}([A-Za-z0-9_.-]+)\s*:\s*(.*)$', line)
        if km:
            cur_key = km.group(1)
            rest = (km.group(2) or '').strip()
            if cur_key == 'enhanced-mode' and rest:
                out['enhanced_mode'] = rest
            # инлайн-список: nameserver: [1.1.1.1, 8.8.8.8]
            if cur_key in resolver_keys and rest.startswith('['):
                for v in rest.strip('[]').split(','):
                    v = v.strip().strip('"\'')
                    if v and v not in seen:
                        seen.add(v)
                        out['dns'].append({'value': v, 'kind': _mihomo_dns_kind(v)})
            continue
        if cur_key not in resolver_keys:
            continue
        m = re.match(r'^\s*-\s+"?\'?([^"\'\s#]+)\'?"?\s*$', line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out['dns'].append({'value': m.group(1), 'kind': _mihomo_dns_kind(m.group(1))})
    # Шифрованные резолверы вперёд: голые IP в профиле обычно бутстрап для них.
    out['dns'].sort(key=lambda d: d['kind'] == 'IP')
    return out

def _mihomo_count_rules(raw):
    """Сколько строк-правил в секции rules профиля (до раскрытия провайдеров)."""
    lines = _yaml_top_sections(raw).get('rules') or []
    return sum(1 for l in lines[1:] if re.match(r'^\s*-\s+\S', l))

def _mihomo_count_nodes(raw):
    lines = _yaml_top_sections(raw).get('proxies') or []
    return sum(1 for l in lines[1:] if re.match(r'^\s*-\s+\S', l))

_MIHOMO_BUILTIN_TARGETS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'}

_MIHOMO_LINK_SCHEMES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://',
                        'hy2://', 'hysteria://', 'tuic://', 'anytls://')

def _mihomo_link_text(text):
    """Текст со ссылками: как есть либо раскодированный base64-блок подписки."""
    txt = (text or '').strip()
    if txt and '://' not in txt:
        try:
            return _b64text(txt)
        except Exception:
            return txt
    return txt

def _mihomo_parse_links(text):
    """Ссылки → список прокси в терминах mihomo. Возвращает (proxies, problems),
    где problems — по записи на непонятую строку: {line, text, reason}.

    Битая строка не роняет разбор целиком: с подписки часто прилетает мусор
    вперемешку с рабочими узлами, но и молча её глотать нельзя — узел просто
    исчез бы без следа."""
    txt = _mihomo_link_text(text)
    proxies, errors, used = [], [], set()
    for i, line in enumerate(txt.replace('\r\n', '\n').split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        low = line.lower()
        short = line if len(line) <= 60 else line[:57] + '…'
        if not low.startswith(_MIHOMO_LINK_SCHEMES):
            errors.append({'line': i, 'text': short, 'reason': 'неизвестный протокол'})
            continue
        fallback = f'node-{len(proxies) + 1}'
        try:
            if low.startswith('vmess://'):
                p = _link_vmess(line, fallback)
            elif low.startswith('ss://'):
                p = _link_ss(line, fallback)
            else:
                u = urlsplit(line)
                qs = parse_qs(u.query)
                name = unquote(u.fragment or '').strip() or fallback
                if low.startswith('vless://'):
                    p = _link_vless(u, qs, name)
                elif low.startswith('trojan://'):
                    p = _link_trojan(u, qs, name)
                elif low.startswith(('hysteria2://', 'hy2://')):
                    p = _link_hy2(u, qs, name)
                elif low.startswith('hysteria://'):
                    p = _link_hy1(u, qs, name)
                elif low.startswith('tuic://'):
                    p = _link_tuic(u, qs, name)
                else:
                    p = _link_anytls(u, qs, name)
        except Exception as e:
            errors.append({'line': i, 'text': short, 'reason': f'не разобрана: {e}'})
            continue
        if not p.get('server'):
            errors.append({'line': i, 'text': short, 'reason': 'не разобран адрес сервера'})
            continue
        # Имена узлов в mihomo обязаны быть уникальными, запятая в имени ломает
        # ссылки на узел из правил.
        base = re.sub(r'[,\r\n]+', ' ', p['name']).strip() or fallback
        name, n = base, 2
        while name in used:
            name = f'{base}-{n}'
            n += 1
        used.add(name)
        p['name'] = name
        proxies.append(p)
    return proxies, errors

def _mihomo_rule_targets(lines):
    """Имена групп/узлов, на которые ссылаются правила (кроме встроенных)."""
    out = []
    for line in (lines or [])[1:]:
        m = re.match(r'^\s*-\s+(.+?)\s*$', line)
        if not m:
            continue
        parts = [x.strip() for x in m.group(1).split(',')]
        if len(parts) < 2 or parts[0].upper() == 'MATCH':
            continue
        t = parts[2] if len(parts) >= 3 else parts[1]
        if t.upper() in _MIHOMO_BUILTIN_TARGETS or t in out:
            continue
        out.append(t)
    return out

def _mihomo_build_from_links(text, rules_from=''):
    """Собирает clash-профиль из ссылок.

    Без правил узел бесполезен: хвост правил панель переписывает на
    MATCH,DIRECT, и через каскад не пошло бы вообще ничего. Поэтому либо
    забираем правила из уже добавленного профиля второго сервера, либо
    честно гоним всё через второй VPN — маркером `match=` в шапке."""
    proxies, errors = _mihomo_parse_links(text)
    if not proxies:
        why = (': ' + errors[0]['reason']) if errors else ''
        raise RuntimeError('не разобрано ни одной ссылки' + why)
    names = [p['name'] for p in proxies]
    borrowed, targets = {}, []
    if rules_from:
        src = _mihomo_find_profile(rules_from)
        if not src:
            raise RuntimeError('профиль с правилами не найден')
        borrowed = _yaml_top_sections(src.get('raw') or '')
        targets = _mihomo_rule_targets(borrowed.get('rules'))
        if not borrowed.get('rules'):
            raise RuntimeError('в выбранном профиле нет правил')
    if not targets:
        targets = ['VPN2']
    head = ['# Сгенерировано awg-panel из ссылок. Правится списком ссылок, не текстом.']
    if not borrowed:
        head.append('# awg-panel: match=' + targets[0])
    out = head + ['', 'proxies:']
    for p in proxies:
        out.extend(_yaml_proxy(p))
    out += ['', 'proxy-groups:']
    for t in targets:
        out.append('  - name: ' + _yaml_scalar(t))
        out.append('    type: select')
        out.append('    proxies: [' + ', '.join(_yaml_scalar(n) for n in names) + ']')
    out.append('')
    if borrowed:
        for sec in ('rule-providers', 'rules'):
            if sec in borrowed:
                out.extend(borrowed[sec])
                out.append('')
    else:
        out += ['rules:', '  - MATCH,' + targets[0], '']
    return '\n'.join(out).rstrip('\n') + '\n', errors

def _mihomo_looks_like_links(text):
    return any(l.strip().lower().startswith(_MIHOMO_LINK_SCHEMES)
               for l in (text or '').replace('\r\n', '\n').split('\n'))

def _mihomo_detect_kind(text):
    """url | clash | links | empty | unknown — что нам вставили."""
    t = (text or '').strip()
    if not t:
        return 'empty'
    if '\n' not in t and re.match(r'^https?://\S+$', t, re.I):
        return 'url'
    if _mihomo_looks_like_links(t):
        return 'links'
    sections = _yaml_top_sections(t)
    if 'proxies' in sections or 'proxy-providers' in sections:
        return 'clash'
    # подписка часто отдаётся одним base64-блоком
    if len(t) > 24 and re.match(r'^[A-Za-z0-9+/=_\-\s]+$', t) and _mihomo_looks_like_links(_mihomo_link_text(t)):
        return 'links'
    return 'unknown'

def _mihomo_list_nodes(raw, limit=200):
    """Узлы из готового профиля — для показа «что мы приняли». Формат записи
    бывает и блочный, и однострочный (`- {name: x, type: vless, …}`)."""
    lines = (_yaml_top_sections(raw).get('proxies') or [])[1:]
    chunks, cur = [], None
    for line in lines:
        if re.match(r'^\s*-\s', line):
            if cur is not None:
                chunks.append(cur)
            cur = [re.sub(r'^\s*-\s*', '', line)]
        elif cur is not None:
            cur.append(line)
    if cur is not None:
        chunks.append(cur)
    out = []
    for ch in chunks[:limit]:
        txt = '\n'.join(ch)
        node = {}
        for key in ('name', 'type', 'server', 'port'):
            m = re.search(r'(?:^|[\s{,])' + key + r'\s*:\s*[\'"]?([^\'",}\n]+)', txt)
            node[key] = m.group(1).strip() if m else ''
        if node['name'] or node['server']:
            out.append(node)
    return out

def _mihomo_body_to_raw(body, rules_from=''):
    """Тело (скачанное или вставленное) → профиль. Возвращает (raw, kind, problems)."""
    kind = _mihomo_detect_kind(body)
    if kind == 'clash':
        return body, 'clash', []
    if kind == 'links':
        raw, problems = _mihomo_build_from_links(body, rules_from)
        return raw, 'links', problems
    raise RuntimeError('не похоже ни на clash-конфиг, ни на ссылки на узлы')

def _mihomo_ingest(text, rules_from='', fetch=True):
    """Единственная точка входа для вставленного текста.

    Ничего не сохраняет — только разбирает, поэтому годится и для проверки
    «на лету» в модалке, и для сохранения профиля."""
    info = {'kind': _mihomo_detect_kind(text), 'inner': '', 'url': '', 'raw': '',
            'nodes': [], 'problems': [], 'rules_count': 0, 'providers': 0,
            'needs_rules': False, 'size': 0, 'error': ''}
    if info['kind'] == 'empty':
        return info
    if info['kind'] == 'unknown':
        info['error'] = 'не похоже ни на ссылку, ни на clash-конфиг, ни на ссылки на узлы'
        return info
    body = text.strip()
    if info['kind'] == 'url':
        info['url'] = body
        if not fetch:
            return info
        try:
            body = _mihomo_fetch_url(info['url'])
        except Exception as e:
            info['error'] = f'не удалось скачать: {e}'
            return info
        info['size'] = len(body)
    try:
        raw, inner, problems = _mihomo_body_to_raw(body, rules_from)
    except Exception as e:
        info['error'] = str(e)
        return info
    info['inner'] = inner
    info['raw'] = raw
    info['problems'] = problems
    info['nodes'] = _mihomo_list_nodes(raw)
    info['rules_count'] = _mihomo_count_rules(raw)
    info['providers'] = len([l for l in (_yaml_top_sections(raw).get('rule-providers') or [])[1:]
                             if re.match(r'^\s{2}[A-Za-z0-9_.-]+\s*:', l)])
    # Свои правила есть только у clash-профиля. У списка узлов их нет — значит
    # надо спросить, что вообще гнать через второй VPN.
    info['needs_rules'] = inner == 'links'
    try:
        _mihomo_render_config(raw)
    except Exception as e:
        info['error'] = str(e)
    return info

def _mihomo_profiles():
    if os.path.exists(MIHOMO_PROFILES_DB):
        try:
            with open(MIHOMO_PROFILES_DB, 'r') as f:
                db = json.load(f)
            if isinstance(db, dict) and isinstance(db.get('profiles'), list):
                return db
        except Exception:
            pass
    return {'profiles': []}

def _mihomo_save_profiles(db):
    with open(MIHOMO_PROFILES_DB, 'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def _mihomo_find_profile(pid):
    for p in _mihomo_profiles()['profiles']:
        if p.get('id') == pid:
            return p
    return None

def _mihomo_fetch_url(url):
    req = urllib.request.Request(url, headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(8 * 1024 * 1024).decode('utf-8', errors='replace')

def _mihomo_apply_active():
    """Пишет config.yaml из активного профиля и просит движок перечитать его.

    Возвращает (ok, сообщение)."""
    cfg = _mihomo_cfg()
    prof = _mihomo_find_profile(cfg.get('active_profile') or '')
    if not prof:
        return False, 'активный профиль не выбран'
    try:
        body = _mihomo_render_config(prof.get('raw') or '')
    except Exception as e:
        return False, str(e)
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    with open(MIHOMO_CONFIG, 'w') as f:
        f.write(body)
    if _mihomo_is_active():
        try:
            _mihomo_api('/configs?force=true', method='PUT', payload={'path': MIHOMO_CONFIG})
        except Exception:
            # reload по API не прошёл — перезапускаем юнит, это всегда срабатывает
            _mihomo_service('restart')
    return True, 'применён'

def _mihomo_api(path, method='GET', payload=None, timeout=6):
    url = f'http://{MIHOMO_CTRL}{path}'
    headers = {'Content-Type': 'application/json'}
    sec = _mihomo_cfg().get('secret') or ''
    if sec:
        headers['Authorization'] = 'Bearer ' + sec
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode('utf-8', errors='replace')
    return json.loads(body) if body.strip() else {}

def _mihomo_api_ok():
    try:
        _mihomo_api('/version', timeout=4)
        return True
    except Exception:
        return False

_MIHOMO_UPSTREAM = {
    'name': '', 'delay': 0, 'ok': False, 'checked': 0,
    'session_dl': 0, 'session_ul': 0,   # с последнего запуска движка
    'speed_dl': 0, 'speed_ul': 0,       # байт/с между двумя пробами
}

_MIHOMO_UPSTREAM_INTERVAL_SEC = 60

_MIHOMO_TRAFFIC_LAST = {'dl': 0, 'ul': 0, 'ts': 0}

def _mihomo_current_node():
    """Узел, через который сейчас реально пойдёт трафик: выбранный в группе-
    селекторе, а если групп нет — первый обычный прокси."""
    builtin = {'DIRECT', 'REJECT', 'REJECT-DROP', 'COMPATIBLE', 'PASS', 'GLOBAL'}
    try:
        data = _mihomo_api('/proxies', timeout=4).get('proxies') or {}
    except Exception:
        return ''
    for p in data.values():
        now = p.get('now')
        if p.get('all') and now and now not in builtin:
            return now
    for name, p in data.items():
        if not p.get('all') and name not in builtin:
            return name
    return ''

def _mihomo_sample_traffic():
    """Счётчики /connections монотонны и обнуляются при рестарте движка.
    Дельту копим в активный профиль, чтобы «всего» переживало перезапуски."""
    try:
        conns = _mihomo_api('/connections', timeout=6)
    except Exception:
        return
    dl = int(conns.get('downloadTotal') or 0)
    ul = int(conns.get('uploadTotal') or 0)
    now = time.time()
    prev = _MIHOMO_TRAFFIC_LAST
    # Счётчик поехал назад — движок перезапускали, считаем всё текущее дельтой.
    d_dl = dl - prev['dl'] if dl >= prev['dl'] else dl
    d_ul = ul - prev['ul'] if ul >= prev['ul'] else ul
    elapsed = max(1.0, now - prev['ts']) if prev['ts'] else 0
    _MIHOMO_UPSTREAM['session_dl'] = dl
    _MIHOMO_UPSTREAM['session_ul'] = ul
    if elapsed:
        _MIHOMO_UPSTREAM['speed_dl'] = int(max(0, d_dl) / elapsed)
        _MIHOMO_UPSTREAM['speed_ul'] = int(max(0, d_ul) / elapsed)
    prev.update({'dl': dl, 'ul': ul, 'ts': now})
    # Первая проба тоже засчитывается целиком: движок мог прогнать трафик
    # до того, как панель сняла первый отсчёт, и терять его незачем.
    if d_dl > 0 or d_ul > 0:
        _mihomo_add_profile_traffic(max(0, d_dl), max(0, d_ul))

def _mihomo_add_profile_traffic(d_dl, d_ul):
    """Накопительный счётчик на активном профиле — переживает рестарт движка."""
    pid = _mihomo_cfg().get('active_profile') or ''
    if not pid:
        return
    db = _mihomo_profiles()
    for p in db['profiles']:
        if p.get('id') == pid:
            p['bytes_dl'] = int(p.get('bytes_dl') or 0) + int(d_dl)
            p['bytes_ul'] = int(p.get('bytes_ul') or 0) + int(d_ul)
            _mihomo_save_profiles(db)
            return

def _mihomo_probe_upstream():
    """Дозвон сквозь текущий узел до тестового адреса + снятие счётчиков."""
    name = _mihomo_current_node()
    if not name:
        _MIHOMO_UPSTREAM.update({'name': '', 'delay': 0, 'ok': False,
                                 'checked': int(time.time())})
        return _MIHOMO_UPSTREAM
    path = ('/proxies/' + quote(name, safe='') + '/delay?timeout=5000&url='
            + quote(MIHOMO_DELAY_TEST_URL, safe=''))
    try:
        delay = int(_mihomo_api(path, timeout=12).get('delay') or 0)
    except Exception:
        delay = 0
    _MIHOMO_UPSTREAM.update({
        'name': name, 'delay': delay, 'ok': delay > 0, 'checked': int(time.time()),
    })
    _mihomo_sample_traffic()
    return _MIHOMO_UPSTREAM

def _xray_cascade_state():
    """True если в xray-конфиге стоит наш socks-outbound."""
    if not os.path.exists(XRAY_CONFIG):
        return False
    try:
        cfg = load_xray_config()
    except Exception:
        return False
    return any(isinstance(ob, dict) and ob.get('tag') == MIHOMO_XRAY_TAG
               for ob in (cfg.get('outbounds') or []))

def _xray_cascade_set(on):
    """Ставит/снимает каскад для XRay-клиентов.

    Наш socks-outbound кладётся ПЕРВЫМ в списке: в XRay первый outbound —
    маршрут по умолчанию, то есть туда уходит всё, что не поймали явные
    routing-правила. Правила Global rules и per-client гео адресуют outbound по
    тегу, так что порядок их не задевает; менять routing.rules не нужно —
    иначе пришлось бы следить за приоритетом при каждой их пересборке."""
    if not os.path.exists(XRAY_CONFIG):
        return False, 'конфиг XRay не найден'
    changed = False
    with _xray_restart_lock:
        cfg = load_xray_config()
        before = json.dumps(cfg, sort_keys=True)
        obs = [ob for ob in (cfg.get('outbounds') or [])
               if not (isinstance(ob, dict) and ob.get(_MIHOMO_MARK))]
        if on:
            obs.insert(0, {
                'tag': MIHOMO_XRAY_TAG,
                'protocol': 'socks',
                'settings': {'servers': [{
                    'address': '127.0.0.1',
                    'port': MIHOMO_MIXED_PORT,
                }]},
                _MIHOMO_MARK: True,
            })
        cfg['outbounds'] = obs
        if json.dumps(cfg, sort_keys=True) != before:
            save_xray_config(cfg)
            changed = True
    if changed:
        schedule_xray_restart()
    return True, ('включён' if on else 'снят')

def _mtg_cascade_state():
    """True если в config.toml прописан наш socks-апстрим."""
    if not os.path.exists(MTG_CONFIG):
        return False
    try:
        with open(MTG_CONFIG, 'r') as f:
            for line in f:
                if re.match(r'^\s*proxies\s*=', line) and MIHOMO_SOCKS_URL in line:
                    return True
    except Exception:
        pass
    return False

def _mtg_cascade_set(on):
    """Правит только строку proxies в секции [network], остальной конфиг
    сохраняем построчно — в mtg-конфиге живут secret, bind-to, debug и
    prefer-ip, и переписывать файл целиком нельзя."""
    if not os.path.exists(MTG_CONFIG):
        return False, 'конфиг mtg не найден'
    try:
        with open(MTG_CONFIG, 'r') as f:
            existing = f.readlines()
    except Exception as e:
        return False, str(e)
    out = []
    in_network = False
    seen_network = False
    inserted = False
    for line in existing:
        stripped = line.strip()
        if stripped.startswith('['):
            # начинается новая секция — если уходим из [network], дописать proxies
            if in_network and on and not inserted:
                out.append(f'proxies = ["{MIHOMO_SOCKS_URL}"]\n')
                inserted = True
            in_network = (stripped == '[network]')
            if in_network:
                seen_network = True
            out.append(line if line.endswith('\n') else line + '\n')
            continue
        if in_network and re.match(r'^\s*proxies\s*=', line):
            if on and not inserted:
                out.append(f'proxies = ["{MIHOMO_SOCKS_URL}"]\n')
                inserted = True
            # выключение — строку просто выбрасываем
            continue
        out.append(line if line.endswith('\n') else line + '\n')
    if on and not inserted:
        if not seen_network:
            if out and out[-1].strip():
                out.append('\n')
            out.append('[network]\n')
        out.append(f'proxies = ["{MIHOMO_SOCKS_URL}"]\n')
    try:
        with open(MTG_CONFIG, 'w') as f:
            f.writelines(out)
    except Exception as e:
        return False, str(e)
    try:
        mtg_restart_fast(_find_mtg_paths().get('unit') or 'mtg')
    except Exception:
        pass
    return True, ('включён' if on else 'снят')

# --- Вход трафика: Hysteria ---------------------------------------------------
#
# У Hysteria каскад — это ПЕРВЫЙ аутбаунд в её config.yaml: он же маршрут по
# умолчанию. Поэтому включение переписывает конфиг и перезапускает сервис, в
# отличие от XRay, где достаточно дописать outbound. Сам механизм живёт в пакете
# протокола — здесь только защищённый вызов: пакета может не быть, и его
# отсутствие не должно ломать каскад остальных протоколов.

def _hysteria_rules():
    """Модуль правил Hysteria или None, если протокол не подключён."""
    try:
        from modules.hysteria import rules as _hy_rules
        return _hy_rules
    except Exception:
        return None


def _tgweb_service():
    """Сервис Telegram WEB (telemt) или None, если пакет не подключён / не установлен.

    У telemt каскад — это socks-upstream в его config.toml: через него он ходит
    к DC Telegram. upstreams на лету он не перечитывает, поэтому включение и
    снятие перезапускают сервис (живые сессии WEB переподключаются сами)."""
    try:
        from modules.tgweb import service as _tg_svc
        return _tg_svc if _tg_svc.bin_installed() else None
    except Exception:
        return None


def _tgweb_cascade_state():
    mod = _tgweb_service()
    if not mod:
        return False
    try:
        return bool(mod.cascade_live())
    except Exception:
        return False


def _tgweb_cascade_set(on):
    mod = _tgweb_service()
    if not mod:
        return False, 'Telegram WEB не установлен'
    try:
        return mod.set_cascade(on)
    except Exception as e:
        return False, str(e)


def _unit_active(unit):
    out, _, _ = run_cmd(f'systemctl is-active {unit}')
    return out.strip() == 'active'


def _proto_states():
    """Установлен ли и запущен ли каждый протокол каскада.

    UI гасит тумблер по этому состоянию: включать каскад протоколу, которого
    нет или который лежит, нельзя — у Hysteria включение ещё и перезапускает
    сервис, то есть подняло бы остановленный руками. Опрос статуса идёт
    каждые 15 с, так что тумблер оживает сам, когда протокол запустят."""
    states = {}
    states['xray'] = {'installed': os.path.exists(XRAY_CONFIG),
                      'running': _unit_active('xray')}
    try:
        mtg_unit = (_find_mtg_paths() or {}).get('unit') or 'mtg'
    except Exception:
        mtg_unit = 'mtg'
    states['mtg'] = {'installed': os.path.exists(MTG_CONFIG),
                     'running': _unit_active(mtg_unit)}
    try:
        from modules.hysteria import service as _hy_svc
        states['hysteria'] = {'installed': bool(_hy_svc.bin_installed()),
                              'running': bool(_hy_svc.is_active())}
    except Exception:
        states['hysteria'] = {'installed': False, 'running': False}
    tg = _tgweb_service()
    try:
        states['tgweb'] = {'installed': bool(tg and tg.load_settings().get('enabled')),
                           'running': bool(tg and tg.is_active())}
    except Exception:
        states['tgweb'] = {'installed': False, 'running': False}
    for st in states.values():
        st['running'] = st['installed'] and st['running']
    return states


def _hysteria_cascade_state():
    """True если в config.yaml Hysteria прописан socks-аутбаунд движка."""
    mod = _hysteria_rules()
    if not mod:
        return False
    try:
        return bool(mod.cascade_live())
    except Exception:
        return False


def _hysteria_cascade_set(on):
    """Включает/снимает каскад Hysteria. (ok, текст)."""
    mod = _hysteria_rules()
    if not mod:
        return False, 'протокол Hysteria не подключён'
    try:
        return mod.set_cascade(on)
    except Exception as e:
        return False, str(e)


def _mihomo_cascade_unwire(reason=''):
    """Убирает каскад из живых конфигов, НЕ трогая намерение. Так после
    остановки движка клиенты сразу возвращаются к прямому выходу, а галочки
    пользователя сохраняются и применятся при следующем запуске."""
    touched = []
    if _xray_cascade_state():
        _xray_cascade_set(False)
        touched.append('XRay')
    if _mtg_cascade_state():
        _mtg_cascade_set(False)
        touched.append('mtg')
    if _hysteria_cascade_state():
        _hysteria_cascade_set(False)
        touched.append('Hysteria')
    if _tgweb_cascade_state():
        _tgweb_cascade_set(False)
        touched.append('Telegram WEB')
    if touched:
        audit('warn', f'Mihomo: каскад снят с конфигов ({", ".join(touched)})'
                      + (f' — {reason}' if reason else ''))
    return touched

def _mihomo_cascade_off_all(reason=''):
    """Снимает каскад и обнуляет намерение — полный отказ от каскада."""
    touched = _mihomo_cascade_unwire(reason)
    _mihomo_save_cfg({'cascade_xray': False, 'cascade_mtg': False,
                      'cascade_hysteria': False, 'cascade_tgweb': False})
    return touched

def _mihomo_sync_cascade():
    """Приводит конфиги к намерению. Включение пишется только когда движок
    реально отвечает по API; выключение применяется всегда."""
    cfg = _mihomo_cfg()
    ready = _mihomo_is_active() and _mihomo_api_ok()
    applied = []
    for kind, want, live, setter in (
        ('XRay', bool(cfg.get('cascade_xray')), _xray_cascade_state(), _xray_cascade_set),
        ('mtg', bool(cfg.get('cascade_mtg')), _mtg_cascade_state(), _mtg_cascade_set),
        ('Hysteria', bool(cfg.get('cascade_hysteria')), _hysteria_cascade_state(),
         _hysteria_cascade_set),
        ('Telegram WEB', bool(cfg.get('cascade_tgweb')), _tgweb_cascade_state(),
         _tgweb_cascade_set),
    ):
        if want == live:
            continue
        if want and not ready:
            continue          # намерение ждёт запуска движка
        ok, _ = setter(want)
        if ok:
            applied.append(kind + (' включён' if want else ' снят'))
    if applied:
        audit('info', 'Mihomo: каскад приведён к настройкам — ' + ', '.join(applied))
    return applied

MIHOMO_SAFE_WINDOW_SEC = 300

MIHOMO_SAFE_DEADLINE_FILE = ''   # реальный путь строится в init() от DATA_MIHOMO_DIR

def _mihomo_write_deadline(ts):
    """Дублирует дедлайн в файл — его читает systemd-сторож."""
    try:
        os.makedirs(os.path.dirname(MIHOMO_SAFE_DEADLINE_FILE), exist_ok=True)
        with open(MIHOMO_SAFE_DEADLINE_FILE, 'w') as f:
            f.write(str(int(ts)))
    except Exception:
        pass

def _mihomo_arm_safe_window():
    """Открывает (или продлевает) окно пробного запуска. Вне безопасного режима
    ничего не делает."""
    if not _mihomo_cfg().get('safe_mode'):
        return 0
    dl = int(time.time()) + MIHOMO_SAFE_WINDOW_SEC
    _mihomo_save_cfg({'safe_deadline': dl})
    _mihomo_write_deadline(dl)
    return dl

def _mihomo_disarm_safe_window():
    _mihomo_save_cfg({'safe_deadline': 0})
    _mihomo_write_deadline(0)

def _mihomo_safe_seconds_left():
    dl = int(_mihomo_cfg().get('safe_deadline') or 0)
    return max(0, dl - int(time.time())) if dl else 0

def _mihomo_safe_revert(reason):
    """Полный возврат в исходное: каскад с конфигов, движок вниз, автозапуск off.
    Безопасный режим остаётся включённым, галочки пользователя — тоже: откат
    возвращает сервер в рабочее состояние, а не стирает настройки."""
    _mihomo_cascade_unwire(reason=reason)
    _mihomo_service('stop')
    subprocess.run(['systemctl', 'disable', MIHOMO_UNIT_NAME],
                   check=False, capture_output=True, timeout=15)
    _mihomo_save_cfg({'autostart': False})
    _mihomo_disarm_safe_window()
    audit('warn', f'Mihomo: безопасный режим вернул всё в исходное — {reason}')

def _mihomo_guard_enable():
    """systemd-дублёр на случай смерти панели: раз в минуту смотрит дедлайн в
    файле и гасит движок, если окно пробного запуска вышло."""
    service = (
        '[Unit]\n'
        'Description=awg-panel: mihomo safe-mode guard\n'
        '\n'
        '[Service]\n'
        'Type=oneshot\n'
        'ExecStart=/bin/bash -c "'
        f'D=$(cat {MIHOMO_SAFE_DEADLINE_FILE} 2>/dev/null || echo 0); '
        'N=$(date +%%s); '
        'if [ \\"$N\\" -ge \\"$D\\" ]; then '
        f'systemctl stop {MIHOMO_UNIT_NAME} 2>/dev/null; '
        f'systemctl disable {MIHOMO_UNIT_NAME} 2>/dev/null; '
        'fi; true"\n'
    )
    timer = (
        '[Unit]\n'
        'Description=awg-panel: mihomo safe-mode guard\n'
        '\n'
        '[Timer]\n'
        'OnBootSec=1min\n'
        'OnUnitActiveSec=1min\n'
        'AccuracySec=15s\n'
        '\n'
        '[Install]\n'
        'WantedBy=timers.target\n'
    )
    with open(MIHOMO_GUARD_SERVICE_FILE, 'w') as f:
        f.write(service)
    with open(MIHOMO_GUARD_TIMER_FILE, 'w') as f:
        f.write(timer)
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)
    subprocess.run(['systemctl', 'enable', '--now', MIHOMO_GUARD_NAME],
                   check=False, capture_output=True, timeout=15)

def _mihomo_guard_disable():
    subprocess.run(['systemctl', 'disable', '--now', MIHOMO_GUARD_NAME],
                   check=False, capture_output=True, timeout=15)
    for p in (MIHOMO_GUARD_SERVICE_FILE, MIHOMO_GUARD_TIMER_FILE):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)

_MIHOMO_TICK_SEC = 15

_MIHOMO_HEALTH_GRACE_SEC = 180

def _mihomo_watchdog_loop():
    """Две обязанности:

    1) Безопасный режим — по истечении окна пробного запуска вернуть всё как было.
    2) Всегда — если каскад включён, а движок не отвечает три минуты подряд,
       снять каскад. Иначе XRay и mtg продолжали бы стучаться в мёртвый socks,
       и клиенты остались бы без интернета до ручного вмешательства."""
    fail_since = 0
    last_probe = 0
    while True:
        time.sleep(_MIHOMO_TICK_SEC)
        try:
            cfg = _mihomo_cfg()
            # Живость ВПН2 и счётчики трафика — раз в минуту и только при
            # работающем движке, чтобы не дёргать сеть впустую.
            if _mihomo_installed() and time.time() - last_probe >= _MIHOMO_UPSTREAM_INTERVAL_SEC:
                last_probe = time.time()
                if _mihomo_api_ok():
                    _mihomo_probe_upstream()
                elif _MIHOMO_UPSTREAM['checked']:
                    _MIHOMO_UPSTREAM.update({'ok': False, 'delay': 0, 'speed_dl': 0,
                                             'speed_ul': 0, 'checked': int(time.time())})
            if cfg.get('safe_mode'):
                dl = int(cfg.get('safe_deadline') or 0)
                if dl and time.time() >= dl:
                    _mihomo_safe_revert('истекло окно пробного запуска')
                    fail_since = 0
                    continue
                # Смотрим ТОЛЬКО на факты: работающий процесс и каскад в конфигах.
                # Намерение (галочка в панели) фактом не является — иначе
                # включённый заранее тумблер сбрасывался бы сторожем через 15 секунд.
                if not dl and (_mihomo_is_active() or _xray_cascade_state() or _mtg_cascade_state()
                               or _hysteria_cascade_state() or _tgweb_cascade_state()):
                    _mihomo_safe_revert('движок поднят вне окна пробного запуска')
                    fail_since = 0
                    continue
            if not (cfg.get('cascade_xray') or cfg.get('cascade_mtg')
                    or cfg.get('cascade_hysteria') or cfg.get('cascade_tgweb')):
                fail_since = 0
                continue
            if _mihomo_api_ok():
                fail_since = 0
                continue
            if not fail_since:
                fail_since = time.time()
            elif time.time() - fail_since >= _MIHOMO_HEALTH_GRACE_SEC:
                # Снимаем с конфигов, но галочки оставляем: движок починится —
                # каскад вернётся при следующем запуске сам.
                _mihomo_cascade_unwire(
                    reason=f'движок не отвечает {_MIHOMO_HEALTH_GRACE_SEC // 60} минуты подряд')
                fail_since = 0
        except Exception:
            fail_since = 0

def _mihomo_do_update(tag):
    """Ставит указанный релиз с проверкой и откатом. Возвращает (ok, msg)."""
    was_active = _mihomo_is_active()
    try:
        data = _mihomo_fetch_binary(tag)
    except Exception as e:
        return False, f'скачивание не удалось: {e}'
    try:
        _mihomo_write_binary(data)
    except Exception as e:
        return False, f'установка не удалась: {e}'
    # Health-check: бинарь должен запускаться, а если движок работал — снова
    # подняться и ответить по API. Иначе откатываемся на прошлую версию.
    ok = bool(_get_mihomo_version())
    if ok and was_active:
        _mihomo_service('restart')
        ok = False
        for _ in range(10):
            time.sleep(1)
            if _mihomo_api_ok():
                ok = True
                break
    if not ok:
        rolled = _mihomo_rollback_binary()
        if was_active:
            _mihomo_service('restart')
        audit('error', f'Mihomo {tag}: обновление не прошло проверку, '
                       + ('откатились на прошлую версию' if rolled else 'откат невозможен'))
        return False, 'новая версия не запустилась, выполнен откат'
    _VERSION_CACHE.clear()
    _mihomo_save_cfg({'last_check': int(time.time())})
    audit('info', f'Mihomo обновлён до {tag}')
    return True, tag

_MIHOMO_UPDATE_CHECK_SEC = 6 * 3600

def _mihomo_update_loop():
    """Раз в 6 часов смотрит, не пора ли проверить релизы. Обновляет тихо —
    пользователь узнаёт из журнала. Молчание оправдано только потому, что
    неудачная версия автоматически откатывается."""
    time.sleep(120)
    while True:
        try:
            cfg = _mihomo_cfg()
            if _mihomo_installed() and cfg.get('auto_update') and not cfg.get('safe_mode'):
                days = max(1, int(cfg.get('check_interval_days') or 7))
                if time.time() - float(cfg.get('last_check') or 0) >= days * 86400:
                    latest = _github_latest_tag(MIHOMO_REPO)
                    cur = _get_mihomo_version()
                    _mihomo_save_cfg({'last_check': int(time.time())})
                    if latest and _semver_lt(cur, latest):
                        _mihomo_do_update(latest)
        except Exception:
            pass
        time.sleep(_MIHOMO_UPDATE_CHECK_SEC)

def _mihomo_status_blob():
    """Статус для UI. Дёргается каждым refreshAll (раз в 15 с), поэтому когда
    движка нет — не лезем ни в systemctl, ни в конфиги XRay/mtg."""
    cfg = _mihomo_cfg()
    installed = _mihomo_installed()
    if not installed:
        return {
            'installed': False,
            'current': '', 'latest': '', 'has_update': False,
            'running': False, 'autostart': False, 'api_ok': False,
            'safe_mode': bool(cfg.get('safe_mode')),
            'auto_update': bool(cfg.get('auto_update')),
            'check_interval_days': int(cfg.get('check_interval_days') or 7),
            'last_check': int(cfg.get('last_check') or 0),
            'cascade_xray': False, 'cascade_mtg': False, 'cascade_hysteria': False,
            'cascade_xray_live': False, 'cascade_mtg_live': False,
            'cascade_hysteria_live': False,
            'cascade_xray_pending': False, 'cascade_mtg_pending': False,
            'cascade_hysteria_pending': False,
            'hysteria_available': _hysteria_rules() is not None,
            'cascade_tgweb': False, 'cascade_tgweb_live': False, 'cascade_tgweb_pending': False,
            'tgweb_available': _tgweb_service() is not None,
            'upstream': dict(_MIHOMO_UPSTREAM),
            'active_profile_dl': 0,
            'active_profile_server': '',
            'safe_deadline': 0, 'safe_seconds_left': 0,
            'safe_window_sec': MIHOMO_SAFE_WINDOW_SEC,
            'active_profile': '', 'active_profile_name': '',
            'profiles_count': len(_mihomo_profiles()['profiles']),
            'mtg_available': os.path.exists(MTG_CONFIG),
            'xray_available': os.path.exists(XRAY_CONFIG),
            'proto_state': _proto_states(),
        }
    active = _mihomo_find_profile(cfg.get('active_profile') or '')
    cur = _get_mihomo_version()
    latest = _github_latest_tag(MIHOMO_REPO)
    want_x, want_m = bool(cfg.get('cascade_xray')), bool(cfg.get('cascade_mtg'))
    live_x, live_m = _xray_cascade_state(), _mtg_cascade_state()
    want_h = bool(cfg.get('cascade_hysteria'))
    hy = _hysteria_rules()
    live_h = _hysteria_cascade_state()
    want_t = bool(cfg.get('cascade_tgweb'))
    live_t = _tgweb_cascade_state()
    return {
        'installed': installed,
        'current': cur,
        'latest': latest,
        'has_update': _semver_lt(cur, latest),
        'running': _mihomo_is_active(),
        'autostart': _mihomo_is_enabled(),
        'api_ok': _mihomo_api_ok(),
        'safe_mode': bool(cfg.get('safe_mode')),
        'safe_deadline': int(cfg.get('safe_deadline') or 0),
        'safe_seconds_left': _mihomo_safe_seconds_left(),
        'safe_window_sec': MIHOMO_SAFE_WINDOW_SEC,
        'auto_update': bool(cfg.get('auto_update')),
        'check_interval_days': int(cfg.get('check_interval_days') or 7),
        'last_check': int(cfg.get('last_check') or 0),
        'cascade_xray': want_x,
        'cascade_mtg': want_m,
        'cascade_hysteria': want_h,
        'cascade_xray_live': live_x,
        'cascade_mtg_live': live_m,
        'cascade_hysteria_live': live_h,
        # «Включено, но ещё не в конфигах» — ждём запуска движка.
        'cascade_xray_pending': want_x and not live_x,
        'cascade_mtg_pending': want_m and not live_m,
        'cascade_hysteria_pending': want_h and not live_h,
        'hysteria_available': hy is not None,
        'cascade_tgweb': want_t,
        'cascade_tgweb_live': live_t,
        'cascade_tgweb_pending': want_t and not live_t,
        'tgweb_available': _tgweb_service() is not None,
        'upstream': dict(_MIHOMO_UPSTREAM),
        'active_profile': cfg.get('active_profile') or '',
        'active_profile_name': (active or {}).get('name') or '',
        # Накопительно скачано через активный профиль — то же число, что на его карточке.
        'active_profile_dl': int((active or {}).get('bytes_dl') or 0),
        'active_profile_server': _mihomo_profile_summary((active or {}).get('raw') or '')['server'],
        'profiles_count': len(_mihomo_profiles()['profiles']),
        'mtg_available': os.path.exists(MTG_CONFIG),
        'xray_available': os.path.exists(XRAY_CONFIG),
        'proto_state': _proto_states(),
    }

@bp.route('/api/mihomo/status', methods=['GET'])
@_auth
def mihomo_status():
    return jsonify({'ok': True, **_mihomo_status_blob()})

@bp.route('/api/mihomo/install', methods=['POST'])
@_auth
def mihomo_install():
    data = request.get_json(silent=True) or {}
    tag = (data.get('tag') or '').strip() or _github_latest_tag(MIHOMO_REPO)
    if not tag:
        return jsonify({'ok': False, 'error': 'не удалось узнать последний релиз mihomo'}), 502
    try:
        blob = _mihomo_fetch_binary(tag)
        _mihomo_write_binary(blob)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    _mihomo_secret()
    _mihomo_write_unit()
    # Движок намеренно НЕ стартуем: сначала профиль и правила, потом запуск.
    _VERSION_CACHE.clear()
    _mihomo_save_cfg({'last_check': int(time.time())})
    audit('info', f'Mihomo установлен ({tag}), движок не запущен')
    return jsonify({'ok': True, 'version': _get_mihomo_version() or tag})

@bp.route('/api/mihomo/uninstall', methods=['POST'])
@_auth
def mihomo_uninstall():
    # Сначала снять каскад — иначе XRay и mtg останутся указывать в никуда.
    _mihomo_cascade_off_all(reason='удаление движка')
    _mihomo_guard_disable()
    _mihomo_service('stop')
    subprocess.run(['systemctl', 'disable', MIHOMO_UNIT_NAME],
                   check=False, capture_output=True, timeout=15)
    for p in (MIHOMO_UNIT_FILE, MIHOMO_BIN, MIHOMO_BIN + '.prev'):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    try:
        shutil.rmtree(MIHOMO_DIR, ignore_errors=True)
    except Exception:
        pass
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)
    _mihomo_save_cfg({'safe_mode': False, 'autostart': False, 'active_profile': ''})
    _VERSION_CACHE.clear()
    audit('warn', 'Mihomo удалён с сервера')
    return jsonify({'ok': True})

@bp.route('/api/mihomo/update', methods=['POST'])
@_auth
def mihomo_update():
    if not _mihomo_installed():
        return jsonify({'ok': False, 'error': 'движок не установлен'}), 400
    latest = _github_latest_tag(MIHOMO_REPO)
    if not latest:
        return jsonify({'ok': False, 'error': 'не удалось узнать последний релиз'}), 502
    ok, msg = _mihomo_do_update(latest)
    return jsonify({'ok': ok, 'error': None if ok else msg, 'version': _get_mihomo_version()})

@bp.route('/api/mihomo/settings', methods=['POST'])
@_auth
def mihomo_settings():
    data = request.get_json(silent=True) or {}
    patch = {}
    if 'auto_update' in data:
        patch['auto_update'] = bool(data['auto_update'])
    if 'check_interval_days' in data:
        try:
            patch['check_interval_days'] = max(1, min(365, int(data['check_interval_days'])))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'период должен быть числом'}), 400
    if 'autostart' in data:
        want = bool(data['autostart'])
        if want and _mihomo_cfg().get('safe_mode'):
            return jsonify({'ok': False, 'error': 'включён безопасный режим'}), 400
        subprocess.run(['systemctl', 'enable' if want else 'disable', MIHOMO_UNIT_NAME],
                       check=False, capture_output=True, timeout=15)
        patch['autostart'] = want
    _mihomo_save_cfg(patch)
    return jsonify({'ok': True, **_mihomo_status_blob()})

@bp.route('/api/mihomo/service', methods=['POST'])
@_auth
def mihomo_service_ctl():
    data = request.get_json(silent=True) or {}
    action = (data.get('action') or '').strip()
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'ok': False, 'error': 'действие должно быть start/stop/restart'}), 400
    if action in ('start', 'restart') and not os.path.exists(MIHOMO_CONFIG):
        return jsonify({'ok': False, 'error': 'сначала выберите профиль'}), 400
    ok, out = _mihomo_service(action)
    audit('info', f'Mihomo: {action} (ok={ok})')
    applied = []
    if ok and action in ('start', 'restart'):
        # Безопасный режим не запрещает запуск — он открывает окно, по истечении
        # которого всё откатится само.
        _mihomo_arm_safe_window()
        # Дожидаемся API и доводим до конфигов то, что юзер уже включил заранее.
        for _ in range(10):
            time.sleep(1)
            if _mihomo_api_ok():
                break
        applied = _mihomo_sync_cascade()
    elif ok and action == 'stop':
        # Останов без снятия каскада оставил бы клиентов в мёртвом socks.
        _mihomo_cascade_unwire(reason='движок остановлен')
        _mihomo_disarm_safe_window()
        # Счётчики сессии обнуляются вместе с движком; накопленное уже в профиле.
        _MIHOMO_UPSTREAM.update({'ok': False, 'delay': 0, 'session_dl': 0,
                                 'session_ul': 0, 'speed_dl': 0, 'speed_ul': 0})
        _MIHOMO_TRAFFIC_LAST.update({'dl': 0, 'ul': 0, 'ts': 0})
    return jsonify({
        'ok': ok,
        'error': None if ok else (out or 'systemctl вернул ошибку'),
        'applied': applied,
        **_mihomo_status_blob(),
    })

@bp.route('/api/mihomo/safe-extend', methods=['POST'])
@_auth
def mihomo_safe_extend():
    if not _mihomo_cfg().get('safe_mode'):
        return jsonify({'ok': False, 'error': 'безопасный режим выключен'}), 400
    dl = _mihomo_arm_safe_window()
    audit('info', 'Mihomo: окно пробного запуска продлено')
    return jsonify({'ok': True, 'safe_deadline': dl, **_mihomo_status_blob()})

@bp.route('/api/mihomo/safe-mode', methods=['POST'])
@_auth
def mihomo_safe_mode():
    data = request.get_json(silent=True) or {}
    want = bool(data.get('enabled'))
    if want:
        # Ничего не гасим: режим только взводит предохранитель. Если движок уже
        # работает, ему тоже даётся окно — иначе включение режима само по себе
        # оборвало бы клиентов, а он задуман ровно для обратного.
        subprocess.run(['systemctl', 'disable', MIHOMO_UNIT_NAME],
                       check=False, capture_output=True, timeout=15)
        _mihomo_save_cfg({'safe_mode': True, 'autostart': False})
        _mihomo_guard_enable()
        if (_mihomo_is_active() or _xray_cascade_state() or _mtg_cascade_state()
                or _hysteria_cascade_state() or _tgweb_cascade_state()):
            _mihomo_arm_safe_window()
        else:
            _mihomo_disarm_safe_window()
        audit('info', f'Mihomo: включён безопасный режим (окно {MIHOMO_SAFE_WINDOW_SEC // 60} мин)')
    else:
        _mihomo_guard_disable()
        _mihomo_save_cfg({'safe_mode': False, 'safe_deadline': 0})
        _mihomo_write_deadline(0)
        audit('info', 'Mihomo: безопасный режим выключен')
    return jsonify({'ok': True, **_mihomo_status_blob()})

@bp.route('/api/mihomo/profiles', methods=['GET'])
@_auth
def mihomo_profiles_get():
    cfg = _mihomo_cfg()
    items = []
    for p in _mihomo_profiles()['profiles']:
        raw = p.get('raw') or ''
        summary = _mihomo_profile_summary(raw)
        items.append({
            'id': p.get('id'),
            'name': p.get('name'),
            'source': p.get('source'),
            'url': p.get('url') or '',
            'server': summary['server'],
            'port': summary['port'],
            'proxy_type': summary['type'],
            'dns': summary['dns'],
            'added': p.get('added') or 0,
            'updated': p.get('updated') or 0,
            'size': len(raw),
            'rules_count': _mihomo_count_rules(raw),
            'nodes_count': _mihomo_count_nodes(raw),
            # Куда уходит всё неперечисленное: DIRECT или (для профиля из
            # ссылок без правил) группа второго VPN.
            'match': _mihomo_match_target(raw),
            # Накопительно за всё время, переживает рестарты движка.
            'bytes_dl': int(p.get('bytes_dl') or 0),
            'bytes_ul': int(p.get('bytes_ul') or 0),
            'active': p.get('id') == cfg.get('active_profile'),
        })
    return jsonify({'ok': True, 'profiles': items, 'active': cfg.get('active_profile') or ''})

@bp.route('/api/mihomo/inspect', methods=['POST'])
@_auth
def mihomo_inspect():
    """Что вставили в поле — до сохранения. Модалка дёргает на каждый ввод."""
    data = request.get_json(silent=True) or {}
    info = _mihomo_ingest(data.get('text') or '', (data.get('rules_from') or '').strip())
    info.pop('raw', None)   # тело в UI не нужно, а весит до мегабайта
    return jsonify({'ok': True, **info})

def _mihomo_text_of(prof):
    """Что показать в редакторе: ровно то, что пользователь вставлял."""
    if prof.get('text'):
        return prof['text']
    src = prof.get('source') or 'yaml'
    if src == 'url':
        return prof.get('url') or ''
    if src == 'links':
        return prof.get('links') or ''
    return prof.get('raw') or ''

@bp.route('/api/mihomo/profiles', methods=['POST'])
@_auth
def mihomo_profiles_add():
    data = request.get_json(silent=True) or {}
    name = _validate_safe_name(data.get('name') or '') or 'profile'
    text = (data.get('text') or '').strip()
    rules_from = (data.get('rules_from') or '').strip()
    info = _mihomo_ingest(text, rules_from)
    if info['error'] or not info['raw']:
        return jsonify({'ok': False, 'error': info['error'] or 'профиль пустой'}), 400
    db = _mihomo_profiles()
    pid = uuid_lib.uuid4().hex[:12]
    db['profiles'].append({
        'id': pid, 'name': name,
        'source': 'url' if info['kind'] == 'url' else info['inner'],
        'url': info['url'], 'text': text, 'raw': info['raw'],
        'rules_from': rules_from if info['needs_rules'] else '',
        'added': int(time.time()), 'updated': int(time.time()),
    })
    _mihomo_save_profiles(db)
    audit('info', f'Mihomo: добавлен профиль «{name}»')
    # Первый профиль сразу делаем активным — иначе движку нечего читать.
    if not _mihomo_cfg().get('active_profile'):
        _mihomo_save_cfg({'active_profile': pid})
        _mihomo_apply_active()
    return jsonify({'ok': True, 'id': pid, 'warn': info['problems']})

@bp.route('/api/mihomo/profiles/<pid>/activate', methods=['POST'])
@_auth
def mihomo_profile_activate(pid):
    prof = _mihomo_find_profile(pid)
    if not prof:
        return jsonify({'ok': False, 'error': 'профиль не найден'}), 404
    _mihomo_save_cfg({'active_profile': pid})
    ok, msg = _mihomo_apply_active()
    if not ok:
        return jsonify({'ok': False, 'error': msg}), 400
    audit('info', f'Mihomo: активен профиль «{prof.get("name")}»')
    return jsonify({'ok': True})

@bp.route('/api/mihomo/profiles/<pid>/refresh', methods=['POST'])
@_auth
def mihomo_profile_refresh(pid):
    db = _mihomo_profiles()
    prof = next((p for p in db['profiles'] if p.get('id') == pid), None)
    if not prof:
        return jsonify({'ok': False, 'error': 'профиль не найден'}), 404
    if prof.get('source') != 'url' or not prof.get('url'):
        return jsonify({'ok': False, 'error': 'профиль добавлен текстом — обновлять нечего'}), 400
    info = _mihomo_ingest(prof['url'], prof.get('rules_from') or '')
    if info['error'] or not info['raw']:
        return jsonify({'ok': False, 'error': info['error'] or 'пустой ответ'}), 502
    prof['raw'] = info['raw']
    prof['updated'] = int(time.time())
    _mihomo_save_profiles(db)
    if _mihomo_cfg().get('active_profile') == pid:
        _mihomo_apply_active()
    audit('info', f'Mihomo: профиль «{prof.get("name")}» перекачан')
    return jsonify({'ok': True})

@bp.route('/api/mihomo/profiles/<pid>/raw', methods=['GET'])
@_auth
def mihomo_profile_raw(pid):
    """Тело профиля для редактора. В общий список не кладём — профили бывают
    на сотни килобайт, а список опрашивается каждые 15 секунд."""
    prof = _mihomo_find_profile(pid)
    if not prof:
        return jsonify({'ok': False, 'error': 'профиль не найден'}), 404
    return jsonify({
        'ok': True,
        'name': prof.get('name') or '',
        'source': prof.get('source') or 'yaml',
        'text': _mihomo_text_of(prof),
        'rules_from': prof.get('rules_from') or '',
    })

@bp.route('/api/mihomo/profiles/<pid>', methods=['PUT'])
@_auth
def mihomo_profile_update(pid):
    db = _mihomo_profiles()
    prof = next((p for p in db['profiles'] if p.get('id') == pid), None)
    if not prof:
        return jsonify({'ok': False, 'error': 'профиль не найден'}), 404
    data = request.get_json(silent=True) or {}
    name = _validate_safe_name(data.get('name') or '') or prof.get('name') or 'profile'
    text = data.get('text')
    if text is None:
        text = _mihomo_text_of(prof)
    text = (text or '').strip()
    rules_from = (data.get('rules_from') or '').strip()
    info = _mihomo_ingest(text, rules_from)
    if info['error'] or not info['raw']:
        return jsonify({'ok': False, 'error': info['error'] or 'профиль пустой'}), 400
    warn = info['problems']
    prof.update({'name': name,
                 'source': 'url' if info['kind'] == 'url' else info['inner'],
                 'url': info['url'], 'text': text, 'raw': info['raw'],
                 'links': '',
                 'rules_from': rules_from if info['needs_rules'] else '',
                 'updated': int(time.time())})
    _mihomo_save_profiles(db)
    audit('info', f'Mihomo: профиль «{name}» изменён')
    # Активный правим — значит и конфиг движка надо пересобрать.
    if _mihomo_cfg().get('active_profile') == pid:
        ok, msg = _mihomo_apply_active()
        if not ok:
            return jsonify({'ok': False, 'error': msg}), 400
    return jsonify({'ok': True, 'warn': warn})

@bp.route('/api/mihomo/profiles/<pid>', methods=['DELETE'])
@_auth
def mihomo_profile_delete(pid):
    cfg = _mihomo_cfg()
    is_active = cfg.get('active_profile') == pid
    # Запрещаем только когда каскад реально стоит в конфигах: тогда сервисы
    # смотрят в socks движка, и без профиля клиенты остались бы без выхода.
    # Раньше проверялось намерение (тумблеры), и при опущенном движке — когда
    # каскад уже снят с конфигов — удалить профиль было нельзя без причины.
    live = (_xray_cascade_state() or _mtg_cascade_state() or _hysteria_cascade_state()
            or _tgweb_cascade_state())
    if is_active and live:
        return jsonify({'ok': False, 'error': 'каскад сейчас работает через этот профиль — '
                                              'сначала выключите каскад'}), 400
    wanted = bool(cfg.get('cascade_xray') or cfg.get('cascade_mtg') or cfg.get('cascade_hysteria')
                  or cfg.get('cascade_tgweb'))
    db = _mihomo_profiles()
    before = len(db['profiles'])
    db['profiles'] = [p for p in db['profiles'] if p.get('id') != pid]
    if len(db['profiles']) == before:
        return jsonify({'ok': False, 'error': 'профиль не найден'}), 404
    _mihomo_save_profiles(db)
    note = ''
    if is_active:
        upd = {'active_profile': ''}
        # Тумблеры, ждавшие запуска движка, без активного профиля включать
        # нечем — гасим их, иначе они висели бы «включёнными» впустую.
        if wanted:
            upd.update({'cascade_xray': False, 'cascade_mtg': False, 'cascade_hysteria': False,
                        'cascade_tgweb': False})
            note = 'каскад выключен — активного профиля больше нет'
        _mihomo_save_cfg(upd)
    audit('info', 'Mihomo: профиль удалён' + (f' ({note})' if note else ''))
    return jsonify({'ok': True, 'note': note})

def _mihomo_rules_from_profile():
    """Разбор секций rules / rule-providers активного профиля — чтобы видеть,
    что именно прислал второй сервер, не поднимая движок."""
    cfg = _mihomo_cfg()
    prof = _mihomo_find_profile(cfg.get('active_profile') or '')
    if not prof:
        return [], []
    sections = _yaml_top_sections(prof.get('raw') or '')
    rules = []
    for line in (sections.get('rules') or [])[1:]:
        m = re.match(r'^\s*-\s+(.+?)\s*$', line)
        if not m:
            continue
        parts = [p.strip() for p in m.group(1).split(',')]
        if len(parts) == 1:
            rules.append({'type': parts[0], 'payload': '', 'proxy': ''})
        elif len(parts) == 2:
            # MATCH,DIRECT — у такого правила нет условия
            rules.append({'type': parts[0], 'payload': '', 'proxy': parts[1]})
        else:
            rules.append({'type': parts[0], 'payload': parts[1], 'proxy': parts[2]})
    # Хвост профиля панель всё равно переписывает — показываем правду.
    rules = [r for r in rules if (r.get('type') or '').upper() != 'MATCH']
    rules.append({'type': 'MATCH', 'payload': '',
                  'proxy': _mihomo_match_target(prof.get('raw') or '', sections)})

    providers = []
    name = None
    for line in (sections.get('rule-providers') or [])[1:]:
        m = re.match(r'^\s{2}([A-Za-z0-9_.-]+)\s*:\s*$', line)
        if m:
            name = m.group(1)
            providers.append({'name': name, 'behavior': '', 'type': '', 'count': None, 'updated': ''})
            continue
        if providers:
            b = re.match(r'^\s*behavior\s*:\s*(\S+)', line)
            if b:
                providers[-1]['behavior'] = b.group(1)
            t = re.match(r'^\s*type\s*:\s*(\S+)', line)
            if t:
                providers[-1]['type'] = t.group(1)
    return rules, providers

@bp.route('/api/mihomo/rules', methods=['GET'])
@_auth
def mihomo_rules():
    """Пока движок работает — читаем у него: видно то, что реально загружено,
    включая раскрытые rule-provider'ы и их размер. Когда опущен — разбираем
    активный профиль, чтобы список правил второго сервера был виден всегда."""
    try:
        rules = _mihomo_api('/rules').get('rules') or []
        providers = (_mihomo_api('/providers/rules').get('providers') or {})
        return jsonify({
            'ok': True,
            'source': 'engine',
            'rules': rules,
            'providers': [
                {
                    'name': k,
                    'behavior': v.get('behavior'),
                    'type': v.get('vehicleType') or v.get('type'),
                    'count': v.get('ruleCount') or 0,
                    'updated': v.get('updatedAt') or '',
                }
                for k, v in providers.items()
            ],
        })
    except Exception:
        pass
    rules, providers = _mihomo_rules_from_profile()
    if not rules and not providers:
        return jsonify({'ok': False, 'error': 'движок не отвечает и активный профиль не выбран'}), 502
    return jsonify({'ok': True, 'source': 'profile', 'rules': rules, 'providers': providers})

MIHOMO_PROVIDER_SHOW_LIMIT = 5000

def _mihomo_provider_source(name):
    """path/behavior/format/url набора — из живого config.yaml движка.

    Конфиг и есть источник истины: именно его читает движок, а профиль в панели
    мог уехать вперёд. Если конфига нет — разбираем активный профиль."""
    text = ''
    try:
        with open(MIHOMO_CONFIG, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception:
        prof = _mihomo_find_profile(_mihomo_cfg().get('active_profile') or '')
        text = (prof or {}).get('raw') or ''
    out = {'name': name, 'path': '', 'behavior': '', 'format': '', 'url': ''}
    keys = ('path', 'behavior', 'format', 'url')
    cur = None
    for line in (_yaml_top_sections(text).get('rule-providers') or [])[1:]:
        # Блочная запись: «  name:», поля с отступом ниже.
        m = re.match(r'^\s{2}([A-Za-z0-9_.-]+)\s*:\s*$', line)
        if m:
            cur = m.group(1)
            continue
        # Однострочная: «  name: {type: http, path: ./x.yaml, …}».
        m = re.match(r'^\s{2}([A-Za-z0-9_.-]+)\s*:\s*\{(.+)\}\s*$', line)
        if m:
            cur = None
            if m.group(1) != name:
                continue
            for key in keys:
                k = re.search(r'(?:^|[\s,{])' + key + r'\s*:\s*([^,}]+)', m.group(2))
                if k:
                    out[key] = k.group(1).strip().strip('\'"')
            continue
        if cur != name:
            continue
        for key in keys:
            k = re.match(r'^\s+' + key + r'\s*:\s*(.+?)\s*$', line)
            if k:
                out[key] = k.group(1).strip().strip('\'"')
    return out

def _mihomo_provider_items(src):
    """Адреса набора с диска: (items, error).

    Формат бывает yaml (`payload:` списком) и text (строка на правило); .mrs —
    двоичный, его разбирает только сам движок."""
    path = (src.get('path') or '').strip()
    if not path:
        return None, 'у набора нет path — содержимое есть только в памяти движка'
    full = path if os.path.isabs(path) else os.path.join(MIHOMO_DIR, path.lstrip('./'))
    if full.lower().endswith('.mrs'):
        return None, 'набор в двоичном формате .mrs — его читает только движок'
    if not os.path.isfile(full):
        return None, f'файл набора ещё не скачан: {full}'
    try:
        with open(full, 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read(16 * 1024 * 1024)
    except Exception as e:
        return None, f'не удалось прочитать {full}: {e}'
    items = []
    for line in raw.replace('\r\n', '\n').split('\n'):
        t = line.strip()
        if not t or t.startswith('#') or t.startswith('//') or t == 'payload:':
            continue
        if t.startswith('- '):
            t = t[2:].strip()
        t = t.strip('\'"')
        if t:
            items.append(t)
    return items, ''

@bp.route('/api/mihomo/providers/<name>/payload', methods=['GET'])
@_auth
def mihomo_provider_payload(name):
    """Что лежит внутри набора. Имя приходит от клиента, путь берётся из
    конфига — подсунуть через имя произвольный файл нельзя."""
    src = _mihomo_provider_source(name)
    items, err = _mihomo_provider_items(src)
    if items is None:
        return jsonify({'ok': False, 'error': err, 'name': name,
                        'behavior': src['behavior'], 'format': src['format'],
                        'url': src['url'], 'path': src['path']}), 404
    return jsonify({'ok': True, 'name': name, 'behavior': src['behavior'],
                    'format': src['format'], 'url': src['url'], 'path': src['path'],
                    'total': len(items), 'items': items[:MIHOMO_PROVIDER_SHOW_LIMIT]})

@bp.route('/api/mihomo/providers/<name>/refresh', methods=['POST'])
@_auth
def mihomo_provider_refresh(name):
    try:
        _mihomo_api('/providers/rules/' + quote(name, safe=''), method='PUT', timeout=30)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502
    return jsonify({'ok': True})

@bp.route('/api/mihomo/proxies', methods=['GET'])
@_auth
def mihomo_proxies():
    try:
        data = _mihomo_api('/proxies').get('proxies') or {}
    except Exception as e:
        return jsonify({'ok': False, 'error': f'движок не отвечает: {e}'}), 502
    groups, nodes = [], []
    for name, p in data.items():
        item = {
            'name': name,
            'type': p.get('type'),
            'now': p.get('now') or '',
            'options': p.get('all') or [],
            'delay': (p.get('history') or [{}])[-1].get('delay') if p.get('history') else None,
        }
        (groups if item['options'] else nodes).append(item)
    return jsonify({'ok': True, 'groups': groups, 'nodes': nodes})

@bp.route('/api/mihomo/select', methods=['POST'])
@_auth
def mihomo_select():
    data = request.get_json(silent=True) or {}
    group = (data.get('group') or '').strip()
    name = (data.get('name') or '').strip()
    if not group or not name:
        return jsonify({'ok': False, 'error': 'нужны группа и узел'}), 400
    try:
        _mihomo_api('/proxies/' + quote(group, safe=''), method='PUT', payload={'name': name})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502
    audit('info', f'Mihomo: в группе «{group}» выбран узел «{name}»')
    return jsonify({'ok': True})

@bp.route('/api/mihomo/test', methods=['POST'])
@_auth
def mihomo_test():
    """Проверка связи со вторым сервером — реальный дозвон через узел, а не
    пинг до него: /delay заставляет движок открыть соединение сквозь прокси."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'не указан узел'}), 400
    path = ('/proxies/' + quote(name, safe='') + '/delay?timeout=5000&url='
            + quote(MIHOMO_DELAY_TEST_URL, safe=''))
    try:
        res = _mihomo_api(path, timeout=12)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502
    delay = int(res.get('delay') or 0)
    # Ручная проверка тоже обновляет плитку связи — иначе она бы ещё минуту
    # показывала прошлый результат.
    if name == _MIHOMO_UPSTREAM.get('name') or not _MIHOMO_UPSTREAM.get('name'):
        _MIHOMO_UPSTREAM.update({'name': name, 'delay': delay, 'ok': delay > 0,
                                 'checked': int(time.time())})
    return jsonify({'ok': True, 'delay': delay, 'name': name})

@bp.route('/api/mihomo/cascade', methods=['POST'])
@_auth
def mihomo_cascade():
    """Задаёт намерение и, если движок готов, сразу доводит его до конфигов.

    Включать можно и при опущенном движке — тогда галочка просто ждёт запуска.
    Писать socks-outbound в XRay заранее нельзя: рестарт увёл бы всех клиентов
    в мёртвый порт до того, как движок вообще поднимется."""
    data = request.get_json(silent=True) or {}
    cfg = _mihomo_cfg()
    want_xray = bool(data['xray']) if 'xray' in data else bool(cfg.get('cascade_xray'))
    want_mtg = bool(data['mtg']) if 'mtg' in data else bool(cfg.get('cascade_mtg'))
    want_hy = bool(data['hysteria']) if 'hysteria' in data else bool(cfg.get('cascade_hysteria'))
    want_tg = bool(data['tgweb']) if 'tgweb' in data else bool(cfg.get('cascade_tgweb'))
    want_any = want_xray or want_mtg or want_hy or want_tg
    if want_any and not _mihomo_installed():
        return jsonify({'ok': False, 'error': 'движок не установлен'}), 400
    if want_any and not cfg.get('active_profile'):
        return jsonify({'ok': False, 'error': 'сначала выберите профиль'}), 400
    # Включить (не выключить) каскад можно только живому протоколу: выключение
    # оставляем всегда, иначе залипший каскад у упавшего сервиса не снять.
    states = _proto_states()
    names = {'xray': 'XRay', 'mtg': 'MTProto', 'hysteria': 'Hysteria', 'tgweb': 'Telegram WEB'}
    for kind, want in (('xray', want_xray), ('mtg', want_mtg), ('hysteria', want_hy),
                       ('tgweb', want_tg)):
        if want and not cfg.get('cascade_' + kind) and not states[kind]['running']:
            why = 'не установлен' if not states[kind]['installed'] else 'не запущен'
            return jsonify({'ok': False, 'error': '%s %s' % (names[kind], why)}), 400
    _mihomo_save_cfg({'cascade_xray': want_xray, 'cascade_mtg': want_mtg,
                      'cascade_hysteria': want_hy, 'cascade_tgweb': want_tg})
    applied = _mihomo_sync_cascade()
    blob = _mihomo_status_blob()
    pending = (blob.get('cascade_xray_pending') or blob.get('cascade_mtg_pending')
               or blob.get('cascade_hysteria_pending') or blob.get('cascade_tgweb_pending'))
    return jsonify({'ok': True, 'applied': applied, 'pending': bool(pending), **blob})
