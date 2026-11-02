"""Установка, конфиг и жизненный цикл telemt + обвязка цепочки.

config.toml генерируется целиком из наших JSON (settings.json + clients.json):
источник правды — панель, TOML лишь производная. telemt сам следит за файлом
(inotify) и подхватывает правки клиентов и [web] на лету — без рестарта и без
обнуления счётчиков. Части, которые он берёт только при старте (listeners, api,
upstreams, user_source_deny), сводятся в отпечаток restart_sig: изменился —
сервис перезапускается.

POST /v1/system/reload НЕ используем: он строит новое «поколение» рантайма с
новой статистикой — счётчики трафика всех клиентов обнулились бы.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import tarfile
import tempfile
import time
import urllib.request

from . import (ACCESS_LOG, BIN_PATH, CONFIG_DIR, CONFIG_FILE, DATA_DIR, DEPS, GITHUB_REPO,
               UNIT_FILE, UNIT_NAME, audit, load_clients, load_settings, run_cmd, save_settings)
from . import nginx, xray_link

STATE_DIR = '/var/lib/telemt'
# Служебный пользователь самопроверки. Не клиент: в списке не показывается и
# в ссылки не попадает — им панель проверяет мост через 443.
PROBE_USER = 'awgprobe'
# Внутренние порты цепочки — только 127.0.0.1. Наружу ничего не открываем.
PORT_CANDIDATES = {
    'nginx_port': [18443, 18444, 18445, 28443, 38443],
    'web_port': [18480, 18481, 18482, 28480, 38480],
    'api_port': [18491, 18492, 18493, 28491, 38491],
}

_LATEST = {'value': '', 'ts': 0, 'busy': False}
_LATEST_TTL = 3600


def _http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': 'awg-panel'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# --- бинарь ---------------------------------------------------------------------

def bin_installed():
    return os.path.isfile(BIN_PATH) and os.access(BIN_PATH, os.X_OK)


def binary_version(path=BIN_PATH):
    """`telemt --version` → «telemt 3.5.14» → «3.5.14». Теги без «v»."""
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        return ''
    out, err, rc = run_cmd('%s --version' % path, timeout=15)
    m = re.search(r'(\d+\.\d+\.\d+)', (out or '') + ' ' + (err or ''))
    return m.group(1) if (rc == 0 and m) else ''


def installed_version():
    return binary_version(BIN_PATH)


def _ver_tuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or '')[:3]) or (0,)


def latest_version(force=False):
    """Последний СТАБИЛЬНЫЙ релиз: releases/latest пропускает pre-release
    (3.5.8–3.5.11 были помечены так). Кеш на час."""
    now = int(time.time())
    if not force and _LATEST['value'] and now - _LATEST['ts'] < _LATEST_TTL:
        return _LATEST['value']
    try:
        raw = _http_get('https://api.github.com/repos/%s/releases/latest' % GITHUB_REPO, timeout=15)
        tag = (json.loads(raw.decode('utf-8')) or {}).get('tag_name') or ''
        m = re.search(r'(\d+\.\d+\.\d+)', tag)
        val = m.group(1) if m else ''
        if val:
            _LATEST.update({'value': val, 'ts': now})
        return val
    except Exception as e:
        audit('warn', 'не удалось узнать последнюю версию telemt: %s' % e)
        return _LATEST['value']


def latest_version_nowait():
    """Для /status: кеш сразу, устаревший — обновляется в фоне. Синхронный
    поход на GitHub держал бы вкладку при недоступном GitHub."""
    now = int(time.time())
    if now - _LATEST['ts'] >= _LATEST_TTL and not _LATEST['busy']:
        _LATEST['busy'] = True

        def _bg():
            try:
                latest_version()
            finally:
                _LATEST['ts'] = max(_LATEST['ts'], int(time.time()) - _LATEST_TTL + 600)
                _LATEST['busy'] = False
        import threading
        threading.Thread(target=_bg, daemon=True).start()
    return _LATEST['value']


def update_available():
    cur, last = installed_version(), latest_version_nowait()
    return bool(cur and last and _ver_tuple(last) > _ver_tuple(cur))


def _arch():
    out, _, _ = run_cmd('uname -m')
    return {'x86_64': 'x86_64', 'amd64': 'x86_64', 'aarch64': 'aarch64', 'arm64': 'aarch64'}.get(
        out.strip(), '')


def download_binary(dest, version=''):
    """Скачать релиз под архитектуру, сверить sha256, распаковать в dest.

    musl-сборка — статическая: не зависит от версии glibc на сервере (Debian 11
    и Ubuntu 20.04 с gnu-сборкой новых релизов могли бы не запуститься)."""
    arch = _arch()
    if not arch:
        return False, 'архитектура сервера не поддерживается telemt (нужна x86_64 или aarch64)'
    version = version or latest_version(force=True)
    if not version:
        return False, 'не удалось узнать версию telemt на GitHub'
    name = 'telemt-%s-linux-musl.tar.gz' % arch
    base = 'https://github.com/%s/releases/download/%s/' % (GITHUB_REPO, version)
    try:
        blob = _http_get(base + name, timeout=180)
        sha_line = _http_get(base + name + '.sha256', timeout=30).decode('utf-8', 'replace')
    except Exception as e:
        return False, 'скачивание не удалось: %s' % e
    want = (sha_line.split() or [''])[0].lower()
    got = hashlib.sha256(blob).hexdigest()
    if not want or want != got:
        return False, 'контрольная сумма не сошлась (%s ≠ %s)' % (got[:12], want[:12])
    tmpdir = tempfile.mkdtemp(prefix='tgweb-')
    try:
        tgz = os.path.join(tmpdir, name)
        with open(tgz, 'wb') as f:
            f.write(blob)
        with tarfile.open(tgz) as tf:
            member = next((m for m in tf.getmembers()
                           if m.isfile() and os.path.basename(m.name) == 'telemt'), None)
            if not member:
                return False, 'в архиве нет бинаря telemt'
            src = tf.extractfile(member)
            tmp = dest + '.tmp'
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(tmp, 'wb') as f:
                shutil.copyfileobj(src, f)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dest)
    except Exception as e:
        return False, 'распаковка не удалась: %s' % e
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    ver = binary_version(dest)
    if not ver:
        return False, 'скачанный бинарь не запускается (telemt --version)'
    return True, ver


# --- адреса и префикс -----------------------------------------------------------

def public_host():
    """Домен WEB-прокси = домен сертификата, которым терминируется 443 (XRay в
    TLS или наш nginx, когда XRay там нет): WebView проверяет сертификат, и
    ничего другого там быть не может."""
    cfg = load_settings()
    if (cfg.get('host') or '').strip():
        return cfg['host'].strip().lower()
    fn = DEPS.get('tls_domain')
    if fn:
        try:
            return (fn() or '').strip().lower()
        except Exception:
            pass
    return ''


def public_ip():
    fn = DEPS.get('server_ip')
    if fn:
        try:
            ip = (fn() or '').strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            pass
    return ''


def load_slug():
    return (load_settings().get('slug') or '').strip().strip('/')


def _new_slug():
    """16 символов [a-z2-7] — как предлагает tproxy-server (base32 от 10 байт)."""
    return base64.b32encode(secrets.token_bytes(10)).decode('ascii').lower().rstrip('=')


def _listening(port):
    fn = DEPS.get('port_owner')
    if fn:
        try:
            return fn(port, 'tcp') or ''
        except Exception:
            pass
    out, _, _ = run_cmd("ss -ltnH 'sport = :%d'" % int(port))
    return out.strip()


def _registry_busy(ignore=()):
    """Порты, закреплённые за сервисами панели (даже лежащими)."""
    fn = DEPS.get('port_map')
    busy = set()
    if fn:
        try:
            for item in fn() or []:
                if item.get('proto') == 'tcp' and item.get('kind') not in ignore:
                    busy.add(int(item.get('port') or 0))
        except Exception:
            pass
    busy.update({22, 80, 443, 5000, 8444})
    return busy


def _pick_port(key, taken):
    busy = _registry_busy(ignore=('tgweb', 'tgweb_nginx', 'tgweb_api')) | set(taken)
    for p in PORT_CANDIDATES[key] + list(range(18500, 18600)):
        if p not in busy and not _listening(p):
            return p
    return 0


def ensure_settings():
    """Досоздать то, что генерируется один раз: префикс, порты, ключи. (cfg, ошибка)."""
    cfg = load_settings()
    changed = False
    if not cfg.get('slug'):
        cfg['slug'] = _new_slug()
        changed = True
    taken = []
    for key in ('nginx_port', 'web_port', 'api_port'):
        cur = int(cfg.get(key) or 0)
        # Свой порт, который уже слушаем мы же, — не конфликт.
        if cur and cur not in taken:
            taken.append(cur)
            continue
        p = _pick_port(key, taken)
        if not p:
            return cfg, 'не нашлось свободного внутреннего порта для %s' % key
        cfg[key] = p
        taken.append(p)
        changed = True
    if not cfg.get('api_key'):
        cfg['api_key'] = 'Bearer ' + secrets.token_urlsafe(24)
        changed = True
    if not cfg.get('probe_secret'):
        cfg['probe_secret'] = secrets.token_hex(16)
        changed = True
    if changed:
        save_settings(cfg)
    return cfg, ''


def move_ports(busy_ports):
    """Перенести внутренние порты, которые заняли другие. (ok, сообщение).

    Ссылки клиентов не меняются: эти порты живут только на 127.0.0.1. Меняются
    конфиг telemt (рестарт), блок nginx и фоллбек XRay (его рестарт)."""
    cfg = load_settings()
    busy = {int(p) for p in (busy_ports or []) if p}
    moved = []
    taken = [int(cfg.get(k) or 0) for k in ('nginx_port', 'web_port', 'api_port')
             if int(cfg.get(k) or 0) not in busy]
    for key in ('nginx_port', 'web_port', 'api_port'):
        cur = int(cfg.get(key) or 0)
        if cur in busy:
            p = _pick_port(key, taken + list(busy))
            if not p:
                return False, 'не нашлось свободного внутреннего порта для %s' % key
            cfg[key] = p
            taken.append(p)
            moved.append('%s → %s' % (cur, p))
    if not moved:
        return True, 'конфликтов нет'
    save_settings(cfg)
    ok, err = apply_all()
    if not ok:
        return False, err
    audit('warn', 'внутренние порты перенесены: %s' % ', '.join(moved))
    return True, 'порты перенесены: %s' % ', '.join(moved)


def regenerate_slug():
    """Новый префикс. Все выданные ссылки перестают работать."""
    cfg = load_settings()
    cfg['slug'] = _new_slug()
    save_settings(cfg)
    ok, err = apply_all()
    if not ok:
        return False, err
    audit('warn', 'новый префикс пути — все выданные ссылки WEB-прокси перевыпущены')
    return True, cfg['slug']


# --- конфиг telemt -----------------------------------------------------------------

def _q(s):
    """TOML basic string. JSON-экранирование для строк совместимо с TOML."""
    return json.dumps(str(s), ensure_ascii=False)


def _complement(nets, version):
    """Всё адресное пространство версии минус перечисленные сети."""
    full = ipaddress.ip_network('0.0.0.0/0' if version == 4 else '::/0')
    remaining = [full]
    for a in ipaddress.collapse_addresses(nets):
        nxt = []
        for r in remaining:
            if a.subnet_of(r):
                nxt.extend(r.address_exclude(a))
            elif not r.subnet_of(a):
                nxt.append(r)
        remaining = nxt
    return [str(n) for n in ipaddress.collapse_addresses(remaining)] if remaining else []


def deny_list(c):
    """Запрет для user_source_deny: чёрный список + всё вне белого.

    У telemt есть только запрет, поэтому белый список превращается в «запретить
    всё остальное» — тот же приём, что у фильтра IP XRay. Белый список только
    из IPv4 запрещает весь IPv6 целиком, и наоборот."""
    out = []
    for raw in c.get('block_ips') or []:
        try:
            out.append(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            pass
    allow = []
    for raw in c.get('allow_ips') or []:
        try:
            allow.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            pass
    if allow:
        for ver in (4, 6):
            nets = [n for n in allow if n.version == ver]
            out.extend(_complement(nets, ver) if nets else
                       ['0.0.0.0/0' if ver == 4 else '::/0'])
    seen, uniq = set(), []
    for n in out:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _mihomo_socks():
    fn = DEPS.get('mihomo_socks')
    if fn:
        try:
            return fn() or ''
        except Exception:
            pass
    return ''


def _mihomo_ready():
    """Движок каскада запущен и отвечает — через его socks можно выходить."""
    fn = DEPS.get('mihomo_ready')
    try:
        return bool(fn and fn())
    except Exception:
        return False


def _mihomo_want_cascade(on):
    """Намерение «Telegram WEB через каскад» у самого mihomo. Без него сверка
    каскада (_mihomo_sync_cascade) сочла бы upstream лишним и сняла его."""
    fn = DEPS.get('mihomo_want_tgweb')
    if fn:
        try:
            fn(bool(on))
        except Exception:
            pass


# --- связь с Telegram ---------------------------------------------------------------
# Серверы в РФ часто не достают до дата-центров Telegram напрямую — наружу они
# ходят через каскад mihomo. telemt без связи с DC поднимается, но клиенты WEB
# никуда не подключатся, поэтому установка проверяет связь заранее и, если
# напрямую её нет, сразу заводит telemt в каскад.

# DC1–DC5 Telegram — к ним telemt ходит за клиентов.
TG_DCS = ('149.154.175.53', '149.154.167.51', '149.154.175.100', '149.154.167.91',
          '91.108.56.130')
# Так telemt пишет в лог, что ни один DC не ответил.
TG_NO_DC_MARK = 'No DC connectivity'


def _dc_direct(ip, timeout=5):
    try:
        socket.create_connection((ip, 443), timeout=timeout).close()
        return True
    except OSError:
        return False


def tg_reach_direct():
    """Сколько DC отвечает напрямую. Разом: недоступный ждёт полный таймаут."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(len(TG_DCS)) as ex:
        return sum(1 for ok in ex.map(_dc_direct, TG_DCS) if ok)


def _log_size():
    try:
        return os.path.getsize(ACCESS_LOG)
    except OSError:
        return 0


def _log_since(pos):
    """Что telemt дописал в лог с позиции pos (после ротации — с начала)."""
    try:
        if os.path.getsize(ACCESS_LOG) < pos:
            pos = 0
        with open(ACCESS_LOG, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(pos)
            return _strip_ansi(f.read(200000))
    except OSError:
        return ''


def render_config(cfg=None, clients=None):
    """(текст config.toml, отпечаток частей, требующих рестарта)."""
    cfg = cfg or load_settings()
    clients = clients if clients is not None else load_clients()
    host, ip, slug = public_host(), public_ip(), (cfg.get('slug') or '').strip('/')
    users = [(c['id'], c['secret'], bool(c.get('disabled')), c) for c in clients
             if c.get('id') and re.match(r'^[0-9a-f]{32}$', c.get('secret') or '')]
    users.append((PROBE_USER, cfg.get('probe_secret') or secrets.token_hex(16), False, {}))
    socks = _mihomo_socks() if cfg.get('cascade') else ''

    head = [
        '# Генерирует awg-panel (Telegram WEB-прокси). Ручные правки перезапишутся:',
        '# источник — data/tgweb/settings.json и clients.json.',
        '',
        '[general]',
        '# Напрямую к DC Telegram: middle-proxy через socks каскада не работает',
        '# (ему нужен публичный адрес в ответе socks), а рекламный тег WEB не нужен.',
        'use_middle_proxy = false',
        '',
        '[general.modes]',
        'classic = false',
        'secure = true',
        'tls = false',
        '',
        '[general.links]',
        'show = []',
        '',
        '[censorship]',
        '# Профиль TLS чужого сайта нужен только классическому FakeTLS — не WEB.',
        'tls_emulation = false',
        '',
        '[server.api]',
        'enabled = true',
        'listen = %s' % _q('127.0.0.1:%d' % int(cfg.get('api_port') or 0)),
        'whitelist = ["127.0.0.0/8"]',
        'auth_header = %s' % _q(cfg.get('api_key') or ''),
        '',
        '[server.conntrack_control]',
        '# Не трогать netfilter сервера: фаерволом и conntrack управляет панель.',
        'inline_conntrack_control = false',
        '',
        '[[server.listeners]]',
        'ip = "127.0.0.1"',
        'port = %d' % int(cfg.get('web_port') or 0),
        'transport = "web"',
        'proxy_protocol = false',
        'web_client_ip_source = "x_forwarded_for"',
        'web_trusted_proxy_cidrs = ["127.0.0.1/32"]',
        '',
    ]
    restart_part = list(head)
    if socks:
        up = ['[[upstreams]]', 'type = "socks5"', 'address = %s' % _q(socks), '']
        head += up
        restart_part += up

    acc = ['[access.users]']
    acc += ['%s = %s' % (_q(u), _q(s)) for u, s, _, _ in users]
    acc += ['', '[access.user_enabled]']
    acc += ['%s = %s' % (_q(u), 'false' if off else 'true') for u, _, off, _ in users]
    lim = [(u, int(c.get('max_ips') or 0)) for u, _, _, c in users if int(c.get('max_ips') or 0) > 0]
    acc += ['', '[access.user_max_unique_ips]'] + ['%s = %d' % (_q(u), n) for u, n in lim]
    deny = [(u, deny_list(c)) for u, _, _, c in users if c]
    deny = [(u, d) for u, d in deny if d]
    deny_lines = ['', '[access.user_source_deny]'] + [
        '%s = [%s]' % (_q(u), ', '.join(_q(x) for x in d)) for u, d in deny]
    acc += deny_lines
    restart_part += deny_lines

    web = [
        '',
        '[web]',
        'enabled = true',
        '# iOS понимает только https; WebSocket в РФ режут после ~2 МиБ, а',
        '# https-lanes нужен HTTP/2, которого XRay с ALPN http/1.1 не даёт.',
        'carrier = "https"',
        '',
        '[[web.vhosts]]',
        'host = %s' % _q(host),
        'base_path = %s' % _q(slug),
        'public_addr = %s' % _q('%s:443' % ip),
        '',
        '[web.vhosts.decoy]',
        'mode = "http_upstream"',
        'upstream = %s' % _q('http://127.0.0.1:%d' % xray_link.prev_dest_port()),
        '',
    ]
    for u, _, _, _ in users:
        web += ['[[web.vhosts.profiles]]', 'user = %s' % _q(u), 'secret_mode = "plain"', '']

    text = '\n'.join(head + acc + web) + '\n'
    sig = hashlib.sha256('\n'.join(restart_part).encode('utf-8')).hexdigest()[:16]
    return text, sig


def config_problems(cfg=None):
    """Чего не хватает, чтобы конфиг вообще имел смысл. Пусто — всё есть."""
    cfg = cfg or load_settings()
    out = []
    if not public_host():
        out.append('нет домена: WEB-прокси живёт только на домене с сертификатом Let\'s Encrypt')
    if not public_ip():
        out.append('не определился IP сервера')
    for key in ('nginx_port', 'web_port', 'api_port'):
        if not int(cfg.get(key) or 0):
            out.append('не выбран внутренний порт %s' % key)
    return out


def write_config():
    """(записан ли новый текст, нужен ли рестарт)."""
    cfg = load_settings()
    text, sig = render_config(cfg)
    cur = ''
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            cur = f.read()
    except Exception:
        pass
    changed = cur != text
    if changed:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = CONFIG_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        # replace — атомарно: наблюдатель telemt не увидит полуфайл.
        os.replace(tmp, CONFIG_FILE)
    need_restart = sig != (cfg.get('restart_sig') or '')
    return changed, need_restart


# telemt открывает API только после проверки связи с дата-центрами Telegram.
# Где они напрямую не отвечают (сервер в РФ), проверка ждёт свой таймаут:
# «DC/ME Initialized in 38 seconds». Десяти секунд ожидания не хватало —
# установка падала на «Запуск telemt», хотя сервис через полминуты поднимался.
START_WAIT = 75
# Из запроса дольше нельзя: gunicorn --timeout 30.
REQUEST_WAIT = 20


def _mark_restarted():
    cfg = load_settings()
    _, sig = render_config(cfg)
    if cfg.get('restart_sig') != sig:
        cfg['restart_sig'] = sig
        save_settings(cfg)


def apply_clients(wait=REQUEST_WAIT):
    """Перенести клиентов и настройки в telemt. (ok, ошибка).

    Обычно хватает записи файла — telemt перечитает его сам. Рестарт — только
    если поменялось то, что он берёт при старте (фильтр IP, каскад, порты).
    wait короткий: зовут в основном из запросов."""
    if not bin_installed() or not load_settings().get('enabled'):
        return True, ''
    try:
        _, need_restart = write_config()
    except Exception as e:
        return False, 'не удалось записать конфиг: %s' % e
    if need_restart and not stopped_by_hand():
        return restart(wait)
    if need_restart:
        # Остановлен руками — применится при запуске; отпечаток не трогаем.
        return True, ''
    return True, ''


def apply_all():
    """Конфиг + nginx + фоллбек XRay — после смены префикса, портов, домена."""
    ok, err = apply_clients()
    if not ok:
        return False, err
    ok, err = nginx.apply()
    if not ok:
        return False, err
    if (load_settings().get('front') or '') == 'xray':
        xray_link.sync()
    return True, ''


# --- юнит и жизненный цикл ------------------------------------------------------

def write_unit():
    body = (
        '[Unit]\n'
        'Description=telemt - Telegram WEB proxy (awg-panel)\n'
        'Wants=network-online.target\n'
        'After=network-online.target\n'
        '\n'
        '[Service]\n'
        'Type=simple\n'
        'WorkingDirectory=%(state)s\n'
        # --data-path явно: иначе состояние (кеш, квоты) легло бы рядом с
        # конфигом или в cwd, а пробный запуск при обновлении затёр бы его.
        'ExecStart=%(bin)s %(cfg)s --data-path %(state)s\n'
        'Restart=on-failure\n'
        'RestartSec=5\n'
        'LimitNOFILE=65536\n'
        'NoNewPrivileges=true\n'
        'StandardOutput=append:%(log)s\n'
        'StandardError=append:%(log)s\n'
        '\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
    ) % {'state': STATE_DIR, 'bin': BIN_PATH, 'cfg': CONFIG_FILE, 'log': ACCESS_LOG}
    cur = ''
    try:
        with open(UNIT_FILE, 'r', encoding='utf-8') as f:
            cur = f.read()
    except Exception:
        pass
    if cur == body:
        return False
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    with open(UNIT_FILE, 'w', encoding='utf-8') as f:
        f.write(body)
    run_cmd('systemctl daemon-reload')
    return True


def is_active():
    out, _, _ = run_cmd('systemctl is-active %s' % UNIT_NAME)
    return out.strip() == 'active'


def is_enabled():
    out, _, _ = run_cmd('systemctl is-enabled %s' % UNIT_NAME)
    return out.strip() in ('enabled', 'enabled-runtime')


def stopped_by_hand():
    """inactive (остановлен штатно), а не failed (упал): упавший правка
    настроек поднимает, остановленный руками — нет."""
    out, _, _ = run_cmd('systemctl is-active %s' % UNIT_NAME)
    return out.strip() == 'inactive'


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _strip_ansi(text):
    """Лог telemt цветной — без этого в окне ошибки сыпались «[2m», «[32m»."""
    return _ANSI_RE.sub('', text or '')


def _api_ok(wait=START_WAIT):
    """API отвечает. Ждём до wait секунд, но сразу бросаем, если юнит упал."""
    from . import stats
    deadline = time.time() + wait
    while True:
        try:
            stats.api('/v1/health', timeout=3)
            return True
        except Exception:
            pass
        if time.time() >= deadline or not is_active():
            return False
        time.sleep(1)


def restart(wait=START_WAIT):
    """Рестарт с проверкой исхода по факту: unit active И API отвечает.

    С коротким wait (из запроса) живой, но ещё не открывший API сервис —
    не ошибка: он проверяет связь с Telegram, итог покажет опрос статуса."""
    run_cmd('systemctl restart %s' % UNIT_NAME)
    if is_active() and _api_ok(wait):
        _mark_restarted()
        return True, ''
    alive = is_active()
    if wait < START_WAIT and alive:
        _mark_restarted()
        return True, ''
    # Первая строка — что случилось, ниже хвост лога: UI покажет его по кнопке
    # «Подробности», а не вывалит в уведомление целиком.
    head = ('telemt запущен, но за %d с так и не открыл API' % wait if alive
            else 'telemt упал при запуске')
    out, _, _ = run_cmd('tail -n 25 %s' % ACCESS_LOG)
    tail = _strip_ansi(out).strip()[-1500:]
    return False, head + ('\n' + tail if tail else '')


def stop():
    run_cmd('systemctl stop %s' % UNIT_NAME)
    return not is_active()


def set_autostart(on):
    run_cmd('systemctl %s %s' % ('enable' if on else 'disable', UNIT_NAME))


# --- самопроверка через 443 --------------------------------------------------------

def capability(secret_hex, host, slug):
    """Ключ моста — то же, что считает клиент Telegram (telemt runtime_web.rs):
    HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v2\\n" + host + "\\n" + base_path)."""
    key = bytes.fromhex(secret_hex)
    if slug:
        msg = b'tdesktop-web-proxy-bridge-v2\n' + host.encode() + b'\n' + slug.encode()
    else:
        msg = b'tdesktop-web-proxy-bridge-v1\n' + host.encode()
    return base64.urlsafe_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode().rstrip('=')


def self_test():
    """Живая проверка всей цепочки через 443: XRay → фоллбек → nginx → telemt.

    Служебным ключом запрашиваем страницу моста — ровно то, что делает клиент
    первым запросом. Успех: 200 + CSP с nonce + маркер TelemtBridgeResponse.
    Неверный ключ telemt отдал бы сайту-заглушке, и маркера бы не было.
    (ok, пояснение)."""
    cfg = load_settings()
    host, slug = public_host(), (cfg.get('slug') or '').strip('/')
    if not (host and slug and cfg.get('probe_secret')):
        return False, 'цепочка не настроена'
    cap = capability(cfg['probe_secret'], host, slug)
    fd, body = tempfile.mkstemp(prefix='tgweb-probe-')
    os.close(fd)
    try:
        out, err, rc = run_cmd(
            "curl -sk --max-time 10 --resolve %s:443:127.0.0.1 -D - -o %s "
            "'https://%s/%s/?bridge=%s'" % (host, body, host, slug, cap), timeout=20)
        try:
            with open(body, 'r', encoding='utf-8', errors='replace') as f:
                page = f.read(200000)
        except Exception:
            page = ''
    finally:
        try:
            os.remove(body)
        except Exception:
            pass
    if rc != 0:
        return False, 'curl до 443 не прошёл: %s' % (err or out or 'нет ответа')[-200:]
    status = (out.splitlines() or [''])[0]
    if ' 200' in status and "'nonce-" in out and 'TelemtBridgeResponse' in page:
        return True, 'мост отвечает через 443'
    if ' 200' in status:
        return False, 'на префикс отвечает сайт, а не telemt — запрос не дошёл до WEB-входа'
    return False, 'ответ %s вместо страницы моста' % (status.strip() or 'пустой')


def probe_info():
    """Реквизиты для внешнего мониторинга (/api/probe/ping панели).

    Своего порта у WEB нет — он на 443 вместе с XRay, и «порт открыт» ничего не
    говорит о telemt. Поэтому мониторинг проверяет то же, что self_test(), но
    снаружи: страницу моста по адресу со служебным ключом. Ключ — capability
    пользователя awgprobe: по нему отдаётся только страница моста, а сам
    MTProto-обмен без секрета не начать, так что клиентские ключи не светятся.

    Адрес отдаём, пока WEB установлен и включён, даже если telemt сейчас лежит:
    именно это мониторинг и должен увидеть."""
    cfg = load_settings()
    host, slug = public_host(), (cfg.get('slug') or '').strip('/')
    installed = bin_installed()
    ready = bool(installed and cfg.get('enabled') and host and slug and cfg.get('probe_secret'))
    url = ''
    if ready:
        url = 'https://%s/%s/?bridge=%s' % (host, slug, capability(cfg['probe_secret'], host, slug))
    return {
        'supported': True,
        'installed': installed,
        'active': is_active() if installed else False,
        'port': 443 if ready else 0,
        'url': url,
        # Маркер страницы моста: по нему мониторинг отличает telemt от сайта,
        # который nginx отдал бы на тот же адрес.
        'marker': 'TelemtBridgeResponse',
    }


# --- обвязка: nginx + фоллбек XRay, сторож ----------------------------------------

def watch():
    """Сторож (раз в 15 с из планировщика пакета).

    1. Режим входа на 443 (front.reconcile): XRay в TLS встал на 443 — WEB
       уходит за его фоллбек; XRay выключили или удалили — WEB занимает 443
       сам; на 443 Reality или чужой сервис — WEB порт отпускает.
    2. Вход через XRay, а nginx упал — общий фоллбек ведёт в никуда, и сайт,
       вход в панель и ссылки на профили на 443 легли бы. Возвращаем прежний
       адрес; nginx поднялся — подключаем обратно. Так WEB-прокси никогда не
       утянет за собой доступ к панели."""
    cfg = load_settings()
    if not cfg.get('enabled'):
        return
    from . import front
    try:
        front.reconcile()
    except Exception as e:
        audit('warn', 'сторож: режим входа не применён: %s' % e)
    if (load_settings().get('front') or '') != 'xray':
        return
    st = xray_link.state()
    if st['mode'] != 'tls':
        return
    ng_ok = nginx.installed() and nginx.active()
    if st['wired'] and not ng_ok:
        changed, _ = xray_link.sync(remove=True)
        if changed:
            audit('warn', 'nginx не работает — общий фоллбек XRay возвращён напрямую, '
                          'WEB-прокси приостановлен до подъёма nginx')


def heal(force=False, wait=START_WAIT):
    """Вернуть всё, что живёт вне папки панели и могло размыться: юнит,
    config.toml, блок nginx, фоллбек XRay. (ok, сообщение).
    Из запроса — wait=REQUEST_WAIT."""
    cfg = load_settings()
    if not cfg.get('enabled') or not bin_installed():
        return (False, 'WEB-прокси не установлен') if force else (True, '')
    notes = []
    if write_unit():
        notes.append('юнит')
    try:
        changed, need_restart = write_config()
        if changed:
            notes.append('конфиг')
        if (need_restart or force) and not stopped_by_hand():
            ok, err = restart(wait)
            if not ok:
                return False, 'telemt не поднялся: %s' % err
    except Exception as e:
        return False, 'конфиг не записан: %s' % e
    if not nginx.installed():
        return (False, 'nginx не установлен') if force else (True, '')
    from . import front
    changed, err = front.reconcile()
    if err:
        return False, err
    if changed:
        notes.append('вход на 443: %s' % {'xray': 'через XRay', 'nginx': 'сам (nginx)'}.get(
            front.applied(), 'отпущен'))
    if not nginx.in_sync():
        ok, err = nginx.apply()
        if not ok:
            return False, err
        notes.append('nginx')
    if front.applied() == 'xray' and nginx.active():
        changed, err = xray_link.sync()
        if err:
            return False, err
        if changed:
            notes.append('фоллбек XRay')
    if notes:
        audit('info', 'починено: %s' % ', '.join(notes))
    if force and not front.applied():
        # Звенья на месте, но 443 не наш (Reality, чужой сервис, нет серта) —
        # честно говорим, почему WEB всё равно не работает.
        _, _, why = front.decide()
        return False, why
    return True, ('починено: %s' % ', '.join(notes)) if notes else 'всё на месте'


# --- установка / обновление / удаление ---------------------------------------------

SETUP_STEPS = [
    'Проверка условий: кто на 443, домен, сертификат, IP',
    'Связь с Telegram: напрямую или через каскад',
    'nginx',
    'Бинарь telemt с GitHub',
    'Внутренние порты, префикс и ключи',
    'Конфиг telemt и юнит',
    'Запуск telemt',
    'Вход на 443: блок nginx (и фоллбек XRay)',
    'Проверка цепочки через 443',
]


def setup(progress=None):
    """Полная установка по шагам. (ok, сообщение). Повторный запуск безопасен:
    существующие клиенты, префикс и порты сохраняются."""
    p = progress or (lambda *a, **k: None)
    step = [0]

    def run(i, fn):
        step[0] = i
        p(i, 'run')
        ok, detail = fn()
        p(i, 'ok' if ok else 'fail', detail)
        return ok, detail

    def s0():
        from . import front
        want, _, why = front.decide()
        if not want:
            return False, why
        if not public_host():
            return False, 'не найден домен сертификата Let\'s Encrypt'
        if not public_ip():
            return False, 'не определился IP сервера'
        return True, '%s, IP %s — %s' % (public_host(), public_ip(), why)

    def s_tg():
        n = tg_reach_direct()
        if n:
            # Каскад, если его уже включили в mihomo руками, не трогаем.
            return True, 'напрямую: отвечают %d из %d дата-центров' % (n, len(TG_DCS))
        if not _mihomo_ready():
            return False, ('сервер не достаёт до дата-центров Telegram напрямую (149.154.x.x:443 '
                           'режет хостинг или провайдер), а каскад mihomo не запущен — запустите '
                           'движок каскада с профилем ВПН2 и повторите установку')
        cfg = load_settings()
        cfg['cascade'] = True
        save_settings(cfg)
        _mihomo_want_cascade(True)
        return True, 'напрямую недоступно — telemt пойдёт к Telegram через каскад mihomo'

    def s1():
        if nginx.installed():
            if not nginx.active():
                run_cmd('systemctl enable --now nginx')
            return nginx.active(), 'уже установлен' if nginx.active() else 'не запускается'
        return nginx.install_package()

    def s2():
        if bin_installed():
            return True, 'уже установлен: %s' % installed_version()
        return download_binary(BIN_PATH)

    def s3():
        cfg, err = ensure_settings()
        if err:
            return False, err
        return True, 'nginx %s, вход %s, API %s' % (cfg['nginx_port'], cfg['web_port'], cfg['api_port'])

    def s4():
        cfg = load_settings()
        cfg['enabled'] = True
        save_settings(cfg)
        probs = config_problems(cfg)
        if probs:
            return False, '; '.join(probs)
        write_config()
        write_unit()
        return True, CONFIG_FILE

    def s5():
        run_cmd('systemctl enable %s' % UNIT_NAME)
        pos = _log_size()
        ok, err = restart()
        if not ok:
            return ok, err
        # Последнее слово за самим telemt: свою проверку DC он пишет в лог до
        # того, как открыть API, — к этому моменту она уже там.
        via = 'через каскад mihomo' if load_settings().get('cascade') else 'напрямую'
        if TG_NO_DC_MARK in _log_since(pos):
            hint = ('проверьте, что профиль ВПН2 в каскаде рабочий' if via != 'напрямую'
                    else 'запустите каскад mihomo с профилем ВПН2 и повторите установку')
            return False, 'telemt запущен, но не достал до дата-центров Telegram %s — %s' % (via, hint)
        return True, 'к Telegram — %s' % via

    def s6():
        from . import front
        # Рестарт XRay здесь синхронный (restart_xray=False + свой restart):
        # запрос установки идёт в фоне, и ждать подъёма надо до самопроверки.
        _, err = front.reconcile(restart_xray=False)
        if err:
            return False, err
        mode = front.applied()
        if mode == 'xray':
            if xray_link.state()['wired'] and front.xray_facts()['active']:
                run_cmd('systemctl restart xray')
                time.sleep(3)
            return True, 'общий фоллбек XRay → 127.0.0.1:%s' % load_settings().get('nginx_port')
        if mode == 'nginx':
            return True, 'XRay на 443 нет — nginx слушает 443 сам'
        _, _, why = front.decide()
        return False, why

    def s7():
        for _ in range(5):
            ok, msg = self_test()
            if ok:
                return True, msg
            time.sleep(2)
        return False, msg

    for i, fn in enumerate((s0, s_tg, s1, s2, s3, s4, s5, s6, s7)):
        ok, detail = run(i, fn)
        if not ok:
            for j in range(i + 1, len(SETUP_STEPS)):
                p(j, 'skip')
            return False, '%s: %s' % (SETUP_STEPS[i], detail)
    audit('info', 'установлен и запущен (telemt %s, домен %s)' % (installed_version(), public_host()))
    return True, 'Telegram WEB-прокси работает: %s' % public_host()


def _trial_run(new_bin):
    """Пробный запуск нового бинаря рядом с рабочим: копия конфига на запасных
    портах, свой каталог состояния. Рабочий сервис не трогается.

    Отдельной проверки конфига у telemt нет: невалидный конфиг — выход с
    ошибкой до bind. Поэтому «проверка» = поднялся и ответил API."""
    cfg = dict(load_settings())
    taken = [int(cfg.get(k) or 0) for k in ('nginx_port', 'web_port', 'api_port')]
    trial = {}
    for key in ('web_port', 'api_port'):
        port = _pick_port(key, taken + list(trial.values()))
        if not port:
            return False, 'нет свободного порта для пробного запуска'
        trial[key] = port
    cfg.update(trial)
    text, _ = render_config(cfg)
    tmpdir = tempfile.mkdtemp(prefix='tgweb-trial-')
    conf = os.path.join(tmpdir, 'config.toml')
    with open(conf, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(conf, 0o600)
    log = os.path.join(tmpdir, 'trial.log')
    import subprocess
    proc = None
    try:
        with open(log, 'w') as lf:
            proc = subprocess.Popen([new_bin, conf, '--data-path', tmpdir], cwd=tmpdir,
                                    stdout=lf, stderr=subprocess.STDOUT)
        ok = False
        # Столько же, сколько ждём рабочий сервис: API пробного запуска тоже
        # откроется только после проверки связи с Telegram.
        for _ in range(START_WAIT):
            time.sleep(1)
            if proc.poll() is not None:
                break
            try:
                req = urllib.request.Request('http://127.0.0.1:%d/v1/health' % trial['api_port'])
                req.add_header('Authorization', cfg.get('api_key') or '')
                with urllib.request.urlopen(req, timeout=2) as r:
                    ok = r.status == 200
                if ok:
                    break
            except Exception:
                continue
        if ok:
            return True, ''
        try:
            with open(log, 'r', encoding='utf-8', errors='replace') as f:
                tail = _strip_ansi(f.read())[-800:]
        except Exception:
            tail = ''
        return False, 'новая версия не поднялась с текущим конфигом: %s' % (tail or 'без вывода')
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


def update_binary():
    """Безопасное обновление: скачать → пробный запуск рядом → замена → рестарт →
    проверка через 443; не поднялось — откат на прежний бинарь. (ok, сообщение)."""
    was = installed_version()
    latest = latest_version(force=True)
    if latest and was and _ver_tuple(latest) <= _ver_tuple(was):
        return True, 'уже последняя версия (%s)' % was
    tmp_bin = BIN_PATH + '.new'
    ok, res = download_binary(tmp_bin, latest)
    if not ok:
        return False, res
    ok, err = _trial_run(tmp_bin)
    if not ok:
        try:
            os.remove(tmp_bin)
        except Exception:
            pass
        audit('warn', 'обновление до %s отменено: %s' % (res, err[:200]))
        return False, err
    backup = BIN_PATH + '.prev'
    was_active = not stopped_by_hand()
    try:
        if bin_installed():
            shutil.copy2(BIN_PATH, backup)
        os.replace(tmp_bin, BIN_PATH)
    except Exception as e:
        return False, 'замена бинаря не удалась: %s' % e
    if not was_active:
        audit('info', 'бинарь обновлён: %s → %s (сервис остановлен, не запускали)' % (was or '?', res))
        return True, res
    ok, err = restart()
    if ok:
        t_ok, t_msg = self_test()
        if t_ok:
            audit('info', 'бинарь обновлён: %s → %s' % (was or '?', res))
            return True, res
        err = t_msg
    if os.path.isfile(backup):
        os.replace(backup, BIN_PATH)
        os.chmod(BIN_PATH, 0o755)
        restart()
        audit('warn', 'обновление до %s откачено: %s' % (res, err[:200]))
        return False, 'новая версия не заработала, вернули %s: %s' % (was or 'прежнюю', err)
    return False, 'новая версия не заработала: %s' % err


def uninstall(purge_data=False):
    """Снять всё, что ставили: фоллбек XRay (первым — чтобы сайт и панель на
    443 не остались смотреть в выключенный nginx-блок), блок nginx, сервис,
    бинарь, конфиг."""
    xray_link.sync(remove=True)
    nginx.remove()                     # в режиме «nginx» этим же освобождается 443
    run_cmd('systemctl disable --now %s' % UNIT_NAME)
    for path in (UNIT_FILE, BIN_PATH, BIN_PATH + '.prev', BIN_PATH + '.new'):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    run_cmd('systemctl daemon-reload')
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(STATE_DIR, ignore_errors=True)
    cfg = load_settings()
    cfg['enabled'] = False
    cfg['restart_sig'] = ''
    cfg['front'] = ''
    save_settings(cfg)
    if purge_data:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
    audit('warn', 'удалён%s' % (' вместе с клиентами' if purge_data else ''))
    return True


# --- каскад через mihomo ------------------------------------------------------------

def cascade_live():
    """Есть ли socks-upstream в живом config.toml (факт, а не намерение)."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            text = f.read()
        return '[[upstreams]]' in text and 'type = "socks5"' in text
    except Exception:
        return False


def set_cascade(on):
    """Включить/снять выход telemt через socks движка каскада. Требует
    рестарта telemt — upstreams на лету он не перечитывает. (ok, сообщение)."""
    cfg = load_settings()
    cfg['cascade'] = bool(on)
    save_settings(cfg)
    if not bin_installed() or not cfg.get('enabled'):
        return True, ''
    ok, err = apply_clients()
    return ok, err


# --- статус ------------------------------------------------------------------------

def status():
    cfg = load_settings()
    st = xray_link.state()
    from . import front
    try:
        fr = front.describe()
        xf = front.xray_facts()
    except Exception as e:
        fr = {'front': cfg.get('front') or '', 'want': '', 'reason': 'error', 'why': str(e)}
        xf = {}
    return {
        # Кто держит 443 для WEB (front.py): 'xray' | 'nginx' | '' и почему.
        'front': fr.get('front') or '',
        'front_want': fr.get('want') or '',
        'front_reason': fr.get('reason') or '',
        'front_why': fr.get('why') or '',
        'xray': {k: xf.get(k) for k in ('installed', 'port', 'mode', 'active', 'enabled')},
        'installed': bin_installed(),
        'enabled': bool(cfg.get('enabled')),
        'active': is_active(),
        'autostart': is_enabled(),
        'version': installed_version(),
        'host': public_host(),
        'slug': (cfg.get('slug') or ''),
        'xray_mode': st['mode'],
        'wired': st['wired'],
        'wired_in_sync': st['in_sync'],
        'nginx_installed': nginx.installed(),
        'nginx_active': nginx.active(),
        'nginx_in_sync': nginx.in_sync() if cfg.get('enabled') else False,
        'cascade': bool(cfg.get('cascade')),
        'cascade_live': cascade_live(),
        'ports': {k: int(cfg.get(k) or 0) for k in ('nginx_port', 'web_port', 'api_port')},
        'prev_dest': st.get('prev') or int(cfg.get('prev_dest') or 0),
    }
