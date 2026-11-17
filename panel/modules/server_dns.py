"""DNS самого сервера: через какой резолвер идёт ВСЁ, что резолвит сервер.

Зачем. Всё, что проходит через сервер, резолвит системный резолвер VPS: XRay
(freedom без domainStrategy отдаёт имя системе), Hysteria, mtg, сама панель. По
умолчанию это DNS хостера — он и видит все домены клиентов. Здесь администратор
выбирает свой резолвер (AdGuard, NextDNS, любой), и система начинает ходить к нему.

Как устроено.
* Движок — AdGuard dnsproxy: понимает адрес в любой форме (plain, tcp://, tls://,
  https://, h3://, quic://, sdns:// включая DNSCrypt) и умеет запасной резолвер,
  который спрашивается ТОЛЬКО при отказе основного (у mihomo резолверы опрашиваются
  параллельно — запасной смешивался бы с основным).
* Слушает 127.0.0.2:53. Там нет ни systemd-resolved (127.0.0.53/54), ни dnsmasq
  («Логи+» и XDNS привязаны bind-interfaces к адресам интерфейсов, у lo это только
  127.0.0.1), ни XDNS (внешний IP).
* Система переключается штатно: с systemd-resolved — drop-in `DNS=127.0.0.2` +
  `Domains=~.` (всё идёт только в глобальный резолвер, DNS хостера с линков не
  спрашивается); без resolved — /etc/resolv.conf `nameserver 127.0.0.2` (старый
  сохраняется для отката).
* Перед переключением dnsproxy гоняется на пробном порту и должен ответить; после —
  проверяется, что система резолвит, иначе всё откатывается. Сервер без DNS — это
  отвал всех клиентов, поэтому «сломалось на полпути» не допускается.
* Сторож раз в 30 с спрашивает 127.0.0.2: не отвечает — кнопка DNS в шапке краснеет.
  Пропал drop-in или resolv.conf перезаписал DHCP — возвращает на место.

Разбор адресов — порт `DirectDns.Parse/Label` из for_mom (MihomoLauncher), только
вывод в синтаксисе dnsproxy.
"""
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify, request

bp = Blueprint('server_dns', __name__)

# --- зависимости из app.py (init) ---------------------------------------------
audit = None
login_required = None
_save_server_config = None
apply_xray_dns = None
asn_lookup = None
_github_latest_tag = None     # необязательная: без неё — только зашитая версия
SERVER_CFG = {}
DATA_DIR = ''
PANEL_VERSION = ''

REQUIRED_DEPS = ['audit', 'login_required', '_save_server_config', 'apply_xray_dns',
                 'asn_lookup', 'SERVER_CFG', 'DATA_DIR', 'PANEL_VERSION']

DNSPROXY_VERSION = 'v0.86.0'
DNSPROXY_REPO = 'AdguardTeam/dnsproxy'
DNSPROXY_BIN = '/usr/local/bin/dnsproxy'
CONF_DIR = '/etc/awg-panel-dns'
CONF_FILE = CONF_DIR + '/dnsproxy.yaml'
UNIT_NAME = 'awg-panel-dns'
UNIT_FILE = '/etc/systemd/system/awg-panel-dns.service'
LISTEN_IP = '127.0.0.2'
RESOLVED_STUB = '127.0.0.53'
# Имя на «zz-»: drop-in'ы читаются по алфавиту, наш должен идти последним — его
# пустые `DNS=`/`FallbackDNS=` сбрасывают то, что прописали до него (resolved.conf
# хостера с `DNS=1.1.1.1 8.8.8.8` иначе СКЛАДЫВАЕТСЯ с нашим, и при первом же
# таймауте resolved уходит на 1.1.1.1 и там остаётся).
RESOLVED_DROPIN = '/etc/systemd/resolved.conf.d/zz-awg-panel-dns.conf'
RESOLVED_DROPIN_OLD = ['/etc/systemd/resolved.conf.d/awg-panel-dns.conf']
RESOLV_CONF = '/etc/resolv.conf'
STATE_DIR = ''            # data/server_dns — строится в init()
RESOLV_BACKUP = ''

HEALTH_EVERY = 30
QUERY_TIMEOUT = 3.0
PROBE_OK = 'example.com'
PROBE_ADS = 'doubleclick.net'
PROBE_ADULT = 'pornhub.com'
PROBE_ADULT2 = 'xvideos.com'
PROBE_EGRESS = 'o-o.myaddr.l.google.com'   # TXT с адресом резолвера, который спросил
STUB_IPS = {'0.0.0.0', '::', '127.0.0.1', '::1'}

DEFAULTS = {
    'enabled': False,
    'main': '',            # как ввёл пользователь
    'fallback': '',
    'show_button': True,   # кнопка DNS в шапке
    'sys_upstream': [],    # DNS хостера, снятый ДО переключения: бутстрап и откат
    'mode': '',            # 'resolved' | 'resolvconf' — как переключена система
    'auto_failover': True, # наш DNS лёг — временно отдать систему DNS хостера
    'failover_since': 0,   # >0 — сейчас в таком откате (unix-время начала)
    'auto_update': True,   # сам обновлять dnsproxy до проверенной версии
    'update_last_check': 0,
}

# Готовые варианты — кнопки над полем. Только крупные, как в клиентской модалке.
TEMPLATES = [
    {'name': 'AdGuard', 'value': 'https://dns.adguard-dns.com/dns-query'},
    {'name': 'Cloudflare', 'value': 'https://1.1.1.1/dns-query'},
    {'name': 'Google', 'value': 'https://8.8.8.8/dns-query'},
    {'name': 'Quad9', 'value': 'https://9.9.9.9/dns-query'},
    {'name': 'NextDNS', 'value': 'https://dns.nextdns.io/'},
]

# Чем резолвить ИМЯ самого резолвера — plain-адреса того же провайдера (по докам
# провайдеров). Для незнакомого — DNS хостера, снятый до переключения.
PROVIDER_BOOT = {
    'NextDNS': ['45.90.28.0:53', '45.90.30.0:53'],
    'AdGuard DNS': ['94.140.14.14:53', '94.140.15.15:53'],
    'Cloudflare': ['1.1.1.1:53', '1.0.0.1:53'],
    'Google': ['8.8.8.8:53', '8.8.4.4:53'],
    'Quad9': ['9.9.9.9:53', '149.112.112.112:53'],
    'Яндекс': ['77.88.8.8:53', '77.88.8.1:53'],
    'Control D': ['76.76.2.0:53', '76.76.10.0:53'],
    'Mullvad': ['194.242.2.2:53'],
}

PROTO_TEXT = {
    'plain': 'Обычный DNS (UDP)', 'tcp': 'Обычный DNS (TCP)', 'dot': 'DoT — DNS через TLS',
    'doh': 'DoH — DNS через HTTPS', 'doh3': 'DoH3 — DNS через HTTP/3', 'doq': 'DoQ — DNS через QUIC',
    'dnscrypt': 'DNSCrypt',
}

_lock = threading.Lock()          # одна операция с системой за раз
_job = {}                         # текущая/последняя фоновая операция
_health = {'ok': None, 'ts': 0, 'error': '', 'ms': 0, 'fails': 0}
_started = False


def init(deps):
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('server_dns.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    global STATE_DIR, RESOLV_BACKUP
    STATE_DIR = os.path.join(DATA_DIR, 'server_dns')
    RESOLV_BACKUP = os.path.join(STATE_DIR, 'resolv.conf.bak')


def _auth(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


def settings():
    cur = SERVER_CFG.get('server_dns')
    out = dict(DEFAULTS)
    if isinstance(cur, dict):
        out.update({k: cur[k] for k in DEFAULTS if k in cur})
    return out


def _save(patch):
    cur = settings()
    cur.update(patch)
    SERVER_CFG['server_dns'] = cur
    _save_server_config(SERVER_CFG)
    return cur


def is_enabled():
    """Для app.py: при включённом DNS сервера XRay не держит свою секцию dns."""
    try:
        return bool(settings().get('enabled'))
    except Exception:
        return False


# =============================================================================
# Разбор того, что вставили
# =============================================================================

def _entry(raw):
    return {'raw': raw, 'ok': False, 'error': '', 'proto': '', 'upstream': '', 'host': '',
            'is_ip': False, 'ipv6': False, 'provider': '', 'warning': ''}


def _fail(e, why):
    e['ok'] = False
    e['error'] = why
    return e


def parse_many(text):
    out = []
    for tok in re.split(r'[\s,;]+', text or ''):
        e = parse(tok)
        if e:
            out.append(e)
    # Одинаковые адреса в списке — один раз.
    seen, uniq = set(), []
    for e in out:
        key = e['upstream'] or e['raw']
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    return uniq


def parse(token):
    t = (token or '').strip().strip('"\'<>')
    if not t:
        return None
    e = _entry(t)
    try:
        _recognise(e, t, 0)
    except Exception:
        _fail(e, 'не похоже на адрес DNS')
    if e['ok']:
        _label(e)
        _sanity(e)
    return e


def _recognise(e, t, depth):
    low = t.lower()
    if low.startswith('sdns://'):
        _from_stamp(e, t, depth)
        return
    scheme, rest = None, t
    if '://' in t:
        scheme, rest = low.split('://', 1)[0], t.split('://', 1)[1]
    if scheme in ('https', 'doh'):
        _doh(e, rest, h3=bool(re.search(r'#.*h3=true', rest, re.I)))
        return
    if scheme in ('h3', 'doh3'):
        _doh(e, rest, h3=True)
        return
    if scheme in ('tls', 'dot'):
        _host_only(e, rest, 'dot', 'tls://')
        return
    if scheme in ('quic', 'doq'):
        _host_only(e, rest, 'doq', 'quic://')
        return
    if scheme in ('udp', 'dns'):
        _host_only(e, rest, 'plain', 'udp://')
        return
    if scheme == 'tcp':
        _host_only(e, rest, 'tcp', 'tcp://')
        return
    if scheme is not None:
        _fail(e, 'незнакомая схема %s://' % scheme)
        return

    ip, port = _split_address(t)
    if ip is not None:
        _set_address(e, ip, port, 'plain', '')
        return
    # ID профиля NextDNS сам по себе — то, что крупно показывает их кабинет.
    if re.fullmatch(r'[0-9a-f]{6}', t, re.I):
        _doh(e, 'dns.nextdns.io/' + t.lower(), h3=False)
        return
    if '/' in t.strip('/'):
        _doh(e, t, h3=False)
        return
    # Голое имя — «Частный DNS» Android, то есть DoT. Порт подсказывает протокол.
    host, port = t, 0
    if ':' in t:
        h, _, p = t.rpartition(':')
        if p.isdigit():
            host, port = h, int(p)
    if port == 53:
        _host_only(e, t, 'plain', 'udp://')
        return
    if port == 443:
        _doh(e, host + '/dns-query', h3=False)
        return
    _host_only(e, t, 'dot', 'tls://')


def _split_address(s):
    """'1.1.1.1', '1.1.1.1:5353', '2a07::1', '[2a07::1]:53' → (ip, port) либо (None, 0)."""
    s = (s or '').strip()
    try:
        if s.startswith('['):
            host, _, tail = s[1:].partition(']')
            port = 0
            if tail:
                if not tail.startswith(':') or not tail[1:].isdigit():
                    return None, 0
                port = int(tail[1:])
            ip = ipaddress.ip_address(host)
            return (ip, port) if ip.version == 6 else (None, 0)
        if s.count(':') >= 2:
            ip = ipaddress.ip_address(s)
            return (ip, 0) if ip.version == 6 else (None, 0)
        addr, port = s, 0
        if s.count(':') == 1:
            addr, p = s.split(':')
            if not p.isdigit():
                return None, 0
            port = int(p)
        if addr.count('.') != 3:
            return None, 0
        return ipaddress.IPv4Address(addr), port
    except ValueError:
        return None, 0


def _set_address(e, ip, port, proto, prefix):
    if port < 0 or port > 65535:
        return _fail(e, 'неверный порт')
    if ip.is_loopback:
        return _fail(e, 'это адрес самого сервера — DNS замкнулся бы сам на себя')
    if ip.is_unspecified:
        return _fail(e, 'не похоже на адрес DNS')
    e.update(ok=True, proto=proto, is_ip=True, ipv6=ip.version == 6, host=str(ip))
    hp = '[%s]' % ip if ip.version == 6 else str(ip)
    if proto == 'plain' and not prefix:
        e['upstream'] = '%s:%d' % (hp, port or 53)
    else:
        e['upstream'] = prefix + hp + (':%d' % port if port else '')
    return e


def _valid_host(h):
    return bool(h) and '.' in h and bool(re.fullmatch(r'(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}', h, re.I))


def _host_only(e, rest, proto, prefix):
    hp = re.split(r'[/#?]', rest, 1)[0]
    ip, port = _split_address(hp)
    if ip is not None:
        return _set_address(e, ip, port, proto, prefix)
    host, port = hp, 0
    if ':' in hp:
        h, _, p = hp.rpartition(':')
        if not p.isdigit() or not 0 < int(p) <= 65535:
            return _fail(e, 'неверный порт')
        host, port = h, int(p)
    if not _valid_host(host):
        return _fail(e, 'неверное имя сервера: %s' % host)
    e.update(ok=True, proto=proto, host=host.lower())
    e['upstream'] = prefix + e['host'] + (':%d' % port if port else '')
    return e


def _doh(e, rest, h3):
    r = rest.split('#', 1)[0]
    hp, slash, path = r.partition('/')
    path = '/' + path if slash else '/dns-query'
    if path == '/':
        path = '/dns-query'
    host, port = hp, ''
    if hp.startswith('['):
        host, _, tail = hp[1:].partition(']')
        port = tail[1:] if tail.startswith(':') else ''
    elif hp.count(':') == 1:
        host, port = hp.split(':')
    if port and (not port.isdigit() or not 0 < int(port) <= 65535):
        return _fail(e, 'неверный порт')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and not _valid_host(host):
        return _fail(e, 'неверное имя сервера: %s' % (host or rest))
    if ip is not None and ip.is_loopback:
        return _fail(e, 'это адрес самого сервера — DNS замкнулся бы сам на себя')
    hostpart = ('[%s]' % ip if ip is not None and ip.version == 6 else (str(ip) if ip else host.lower()))
    e.update(ok=True, proto='doh3' if h3 else 'doh', host=str(ip) if ip else host.lower(),
             is_ip=ip is not None, ipv6=bool(ip is not None and ip.version == 6))
    e['upstream'] = ('h3://' if h3 else 'https://') + hostpart + (':' + port if port else '') + path
    return e


def _from_stamp(e, t, depth):
    """sdns:// отдаём dnsproxy как есть — он понимает все виды штампов, включая
    DNSCrypt. Разбираем только чтобы показать протокол и провайдера."""
    if depth:
        return _fail(e, 'не похоже на адрес DNS')
    b64 = t[7:].replace('-', '+').replace('_', '/')
    b64 += '=' * (-len(b64) % 4)
    try:
        b = base64.b64decode(b64)
    except Exception:
        return _fail(e, 'не удалось разобрать DNS-штамп sdns://')
    if len(b) < 10:
        return _fail(e, 'не удалось разобрать DNS-штамп sdns://')
    pos = [9]

    def lp():
        if pos[0] >= len(b):
            return ''
        n = b[pos[0]]
        pos[0] += 1
        s = b[pos[0]:pos[0] + n].decode('utf-8', 'replace')
        pos[0] += n
        return s

    def skip_vlp():
        while pos[0] < len(b):
            n = b[pos[0]]
            pos[0] += 1 + (n & 0x7f)
            if not n & 0x80:
                break

    kind = b[0]
    if kind == 0x00:
        _recognise(e, lp(), depth + 1)
    elif kind == 0x01:
        addr = lp()
        ip, _p = _split_address(addr)
        e.update(ok=True, proto='dnscrypt', host=str(ip) if ip else addr, is_ip=ip is not None)
    elif kind == 0x02:
        addr = lp(); skip_vlp(); host = lp(); path = lp()
        _doh(e, (host or addr) + path, h3=False)
    elif kind == 0x03:
        addr = lp(); skip_vlp(); host = lp()
        _host_only(e, host or addr, 'dot', 'tls://')
    elif kind == 0x04:
        addr = lp(); skip_vlp(); host = lp()
        _host_only(e, host or addr, 'doq', 'quic://')
    else:
        return _fail(e, 'не удалось разобрать DNS-штамп sdns://')
    if e['ok']:
        e['upstream'] = t     # dnsproxy получает исходный штамп
    return e


def _label(e):
    h = e['host'] or ''
    up = e['upstream']

    def path0():
        m = re.match(r'^(?:https|h3)://[^/]+/([^/#?]+)', up)
        return m.group(1) if m else ''

    if h.endswith('nextdns.io') or h.startswith(('45.90.28.', '45.90.30.', '2a07:a8c0:', '2a07:a8c1:')):
        pid = ''
        m = re.match(r'^([0-9a-z]+)\.dns\d?\.nextdns\.io$', h)
        if m:
            pid = m.group(1)
        elif e['proto'] in ('doh', 'doh3'):
            pid = path0()
        elif e['ipv6']:
            g = h.split(':')
            if len(g) >= 2:
                pid = (g[-2] + g[-1]).rjust(6, '0')
        if pid == 'dns-query':
            pid = ''
        e['provider'] = 'NextDNS · профиль %s' % pid if pid else 'NextDNS'
        e['_prov'] = 'NextDNS'
        if not pid and e['is_ip'] and not e['ipv6']:
            e['warning'] = 'NextDNS по IP без профиля работает только с привязанного IP — лучше адрес с ID'
        elif not pid:
            e['warning'] = 'В адресе нет ID профиля NextDNS — фильтры профиля не применятся'
        return
    pairs = [
        (('adguard-dns.com', 'adguard.com'), ('94.140.14.', '94.140.15.', '2a10:50c0:'), 'AdGuard DNS'),
        (('cloudflare', 'one.one.one.one'), ('1.1.1.', '1.0.0.', '2606:4700:4700:'), 'Cloudflare'),
        (('dns.google',), ('8.8.8.8', '8.8.4.4', '2001:4860:4860:'), 'Google'),
        (('quad9.net',), ('9.9.9.', '149.112.112.', '2620:fe:'), 'Quad9'),
        (('yandex',), ('77.88.8.',), 'Яндекс'),
        (('controld.com',), ('76.76.2.', '76.76.10.'), 'Control D'),
        (('mullvad.net',), ('194.242.2.',), 'Mullvad'),
    ]
    for names, prefixes, prov in pairs:
        if any(n in h for n in names) or h.startswith(prefixes):
            e['provider'] = prov
            e['_prov'] = prov
            return
    try:
        if ipaddress.ip_address(h).is_private:
            e['provider'] = 'локальная сеть хостера'
    except ValueError:
        pass


def _sanity(e):
    if e['ipv6'] and not _has_ipv6():
        e['warning'] = (e['warning'] + '; ' if e['warning'] else '') + 'у сервера нет IPv6 — этот адрес не ответит'


_v6_cache = {}


def _has_ipv6():
    if 'v' in _v6_cache:
        return _v6_cache['v']
    ok = False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(('2001:4860:4860::8888', 53))
        ok = not ipaddress.ip_address(s.getsockname()[0]).is_link_local
        s.close()
    except Exception:
        ok = False
    _v6_cache['v'] = ok
    return ok


def describe(e):
    if not e.get('ok'):
        return e.get('error') or ''
    parts = [PROTO_TEXT.get(e['proto'], e['proto'])]
    if e.get('provider'):
        parts.append(e['provider'])
    if e.get('ipv6'):
        parts.append('IPv6')
    return ' · '.join(parts)


def _public(e):
    d = {k: v for k, v in e.items() if not k.startswith('_')}
    d['text'] = describe(e)
    return d


# =============================================================================
# DNS-запросы (свои, без системного резолвера)
# =============================================================================

def _packet(name, qtype):
    qid = random.randint(0, 0xFFFF)
    q = b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.strip('.').split('.')) + b'\0'
    return qid, struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', qtype, 1)


def _skip_name(msg, off):
    while True:
        n = msg[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n


def _parse_reply(msg, qid):
    rid, fl, qd, an, _ns, _ar = struct.unpack('!HHHHHH', msg[:12])
    if rid != qid:
        raise ValueError('чужой ответ')
    off = 12
    for _ in range(qd):
        off = _skip_name(msg, off) + 4
    ips, txt = [], []
    for _ in range(an):
        off = _skip_name(msg, off)
        rtype, _c, _ttl, rdlen = struct.unpack('!HHIH', msg[off:off + 10])
        off += 10
        rd = msg[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            ips.append('.'.join(str(x) for x in rd))
        elif rtype == 16:
            i = 0
            while i < len(rd):
                n = rd[i]
                txt.append(rd[i + 1:i + 1 + n].decode('utf-8', 'replace'))
                i += 1 + n
        off += rdlen
    return fl & 0x0F, ips, txt


def query(server, port, name, qtype=1, timeout=QUERY_TIMEOUT):
    """UDP-запрос к server:port → (rcode, [A], [TXT], мс)."""
    qid, pkt = _packet(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(pkt, (server, port))
        deadline = t0 + timeout
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack('!H', data[:2])[0] == qid:
                rc, ips, txt = _parse_reply(data, qid)
                return rc, ips, txt, int((time.time() - t0) * 1000)
            if time.time() > deadline:
                raise socket.timeout()
    finally:
        s.close()


def _human(e):
    s = str(e)
    low = s.lower()
    if isinstance(e, (socket.timeout, TimeoutError)) or 'timed out' in low:
        return 'нет ответа за %d с' % QUERY_TIMEOUT
    if 'refused' in low:
        return 'соединение отклонено'
    return s[:200] or e.__class__.__name__


def probe(server, port):
    """Что умеет резолвер за server:port. → dict для UI."""
    res = {'ok': False, 'ms': 0, 'error': '', 'ads': False, 'adult': False,
           'egress_ip': '', 'egress_org': ''}
    try:
        rc, ips, _t, ms = query(server, port, PROBE_OK)
    except Exception as e:
        res['error'] = _human(e)
        return res
    res['ms'] = ms
    if rc or not ips:
        res['error'] = 'сервер ответил ошибкой' if rc else 'пустой ответ'
        return res
    res['ok'] = True
    if ms < 2:
        # example.com пришёл из кеша (0 мс) — это не скорость резолвера. Мерим на
        # случайном имени, которого в кеше быть не может.
        try:
            t0 = time.time()
            query(server, port, 'awgp-%08x.example.com' % random.getrandbits(32))
            res['ms'] = max(1, int((time.time() - t0) * 1000))
        except Exception:
            pass

    def answer(name):
        try:
            rc2, ips2, _t2, _m = query(server, port, name)
            return rc2, set(ips2)
        except Exception:
            return None, set()

    def stub(a):
        return a[0] == 3 or (bool(a[1]) and a[1] <= STUB_IPS)
    res['ads'] = stub(answer(PROBE_ADS))
    # Семейные фильтры часто отвечают не 0.0.0.0, а адресом своей страницы-заглушки
    # (AdGuard 94.140.14.35, Яндекс 93.158.134.250, OpenDNS 146.112.61.106). У двух
    # разных сайтов адреса разные, у заглушки — один и тот же.
    a1, a2 = answer(PROBE_ADULT), answer(PROBE_ADULT2)
    res['adult'] = stub(a1) or (bool(a1[1]) and a1[1] == a2[1])
    eg = egress(server, port)
    res.update(egress_ip=eg[0], egress_org=eg[1])
    return res


def egress(server, port):
    """Адрес, с которого реально уходит запрос к авторитетным серверам, и его владелец."""
    try:
        _rc, _ips, txt, _ms = query(server, port, PROBE_EGRESS, qtype=16)
    except Exception:
        return '', ''
    ip = ''
    for t in txt:
        try:
            ipaddress.ip_address(t.strip())
            ip = t.strip()
            break
        except ValueError:
            continue
    org = ''
    if ip and asn_lookup:
        try:
            a = asn_lookup(ip) or {}
            org = a.get('org') or ''
        except Exception:
            org = ''
    return ip, org


# =============================================================================
# dnsproxy: бинарь, конфиг, пробный запуск, сервис
# =============================================================================

def _arch():
    try:
        m = (os.uname().machine or '').lower()
    except Exception:
        m = ''
    if m in ('x86_64', 'amd64'):
        return 'amd64'
    if m in ('aarch64', 'arm64'):
        return 'arm64'
    if m.startswith('armv7') or m.startswith('armv8l'):
        return 'arm7'
    return ''


def engine_version():
    if not os.path.exists(DNSPROXY_BIN):
        return ''
    try:
        out = subprocess.run([DNSPROXY_BIN, '--version'], capture_output=True, text=True, timeout=5)
        m = re.search(r'v?\d+\.\d+\.\d+', out.stdout + out.stderr)
        return m.group(0) if m else ''
    except Exception:
        return ''


def _ver(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or '')[:3])


def _latest_tag():
    fn = globals().get('_github_latest_tag')
    try:
        return (fn(DNSPROXY_REPO) or '') if fn else ''
    except Exception:
        return ''


def _download(tag, dest):
    """Скачать бинарь релиза tag в dest (0755). Ничего установленного не трогает."""
    arch = _arch()
    if not arch:
        raise RuntimeError('архитектура сервера не поддерживается сборками dnsproxy')
    asset = 'dnsproxy-linux-%s-%s.tar.gz' % (arch, tag)
    url = 'https://github.com/%s/releases/download/%s/%s' % (DNSPROXY_REPO, tag, asset)
    req = urllib.request.Request(url, headers={'User-Agent': 'awg-panel/%s' % PANEL_VERSION})
    with urllib.request.urlopen(req, timeout=120) as r:
        blob = r.read()
    d = tempfile.mkdtemp(prefix='awgp-dnsproxy-')
    try:
        arc = os.path.join(d, asset)
        with open(arc, 'wb') as f:
            f.write(blob)
        with tarfile.open(arc) as tf:
            member = next((m for m in tf.getmembers() if m.isfile() and m.name.endswith('/dnsproxy')), None)
            if member is None:
                raise RuntimeError('в архиве релиза нет dnsproxy')
            data = tf.extractfile(member).read()
        if len(data) < 2 * 1024 * 1024:
            raise RuntimeError('скачанный dnsproxy слишком мал — похоже, релиз недоступен')
        with open(dest, 'wb') as f:
            f.write(data)
        os.chmod(dest, 0o755)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _bin_version(path):
    try:
        out = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=5)
        m = re.search(r'v?\d+\.\d+\.\d+', out.stdout + out.stderr)
        return m.group(0) if m else ''
    except Exception:
        return ''


def ensure_binary(step=None):
    """Первая установка: потолок из proto_limits (проверенная версия), без него —
    зашитая DNSPROXY_VERSION."""
    if engine_version():
        return
    tag = DNSPROXY_VERSION
    try:
        from modules import proto_limits
        tag = proto_limits.pick('dnsproxy', _latest_tag()) or DNSPROXY_VERSION
    except Exception:
        pass
    if not tag.startswith('v'):
        tag = 'v' + tag
    if step:
        step('Скачиваю dnsproxy %s…' % tag)
    tmp = DNSPROXY_BIN + '.new'
    _download(tag, tmp)
    os.replace(tmp, DNSPROXY_BIN)
    if not engine_version():
        raise RuntimeError('dnsproxy скачан, но не запускается')


# --- тихое обновление -----------------------------------------------------------
# Только до потолка из proto_limits: версию открывает разработчик панели. Новая
# сборка сначала отвечает с ТЕКУЩИМ конфигом на свободном порту, потом подменяет
# бинарь; не поднялась на 127.0.0.2 — возвращается прежний (.prev).

UPDATE_EVERY = 86400
_updating = {'on': False}


def safe_update():
    """(обновлено?, текст)."""
    cur = engine_version()
    if not cur:
        return False, 'dnsproxy не установлен'
    try:
        from modules import proto_limits
        target, hold = proto_limits.update_target('dnsproxy', cur, _latest_tag())
    except Exception as e:
        return False, 'нет таблицы проверенных версий: %s' % e
    if not target or _ver(target) <= _ver(cur):
        return False, hold or 'установлена проверенная версия'
    if not _lock.acquire(blocking=False):
        return False, 'идёт другая операция с DNS'
    _updating['on'] = True
    cand = DNSPROXY_BIN + '.cand'
    try:
        _download(target, cand)
        if not _bin_version(cand):
            raise RuntimeError('новый dnsproxy не запускается')
        s = settings()
        live = s.get('enabled') and os.path.exists(CONF_FILE)
        if live:
            main, fb = parse_many(s['main']), parse_many(s['fallback'])
            t = trial([e for e in main if e['ok']], s.get('sys_upstream') or [], full=False, binary=cand)
            if not t.get('ok'):
                raise RuntimeError('новый dnsproxy не ответил с вашим DNS: %s' % (t.get('error') or '?'))
        shutil.copy2(DNSPROXY_BIN, DNSPROXY_BIN + '.prev')
        os.replace(cand, DNSPROXY_BIN)
        if live:
            _sh(['systemctl', 'restart', UNIT_NAME], 20)
            ok, err = _wait_listen()
            if not ok:
                os.replace(DNSPROXY_BIN + '.prev', DNSPROXY_BIN)
                _sh(['systemctl', 'restart', UNIT_NAME], 20)
                back, _e = _wait_listen()
                audit('error', 'dnsproxy %s не ответил (%s) — возвращён %s%s'
                      % (target, err, cur, '' if back else ', но и он не отвечает'))
                return False, 'новая версия не ответила — возвращена %s' % cur
        audit('info', 'dnsproxy обновлён: %s → %s' % (cur, target))
        return True, '%s → %s' % (cur, target)
    except Exception as e:
        audit('warn', 'dnsproxy не обновлён: %s' % (str(e)[:200] or e.__class__.__name__))
        return False, str(e)[:200]
    finally:
        try:
            if os.path.exists(cand):
                os.remove(cand)
        except OSError:
            pass
        _updating['on'] = False
        _lock.release()


def _update_loop():
    time.sleep(600)
    while True:
        try:
            s = settings()
            due = time.time() - float(s.get('update_last_check') or 0) >= UPDATE_EVERY
            if s.get('auto_update', True) and due and engine_version():
                _save({'update_last_check': int(time.time())})
                safe_update()
        except Exception:
            pass
        time.sleep(3600)


def _yaml_list(items):
    return '[' + ', '.join(json.dumps(x) for x in items) + ']'


def _bootstrap_for(entries, sys_upstream):
    """Plain-адреса, которыми dnsproxy найдёт ИМЕНА резолверов. Свои у известных
    провайдеров, иначе DNS хостера. Никогда не системный резолвер: после
    переключения он — это мы сами."""
    boot = []
    for e in entries:
        if e.get('is_ip'):
            continue
        boot += PROVIDER_BOOT.get(e.get('_prov') or '', [])
    if any(not e.get('is_ip') and not PROVIDER_BOOT.get(e.get('_prov') or '') for e in entries):
        boot += ['%s:53' % ('[%s]' % ip if ':' in ip else ip) for ip in (sys_upstream or [])]
    if not boot and any(not e.get('is_ip') for e in entries):
        # Хостер не дал DNS, провайдер незнакомый — без бутстрапа имя не найти.
        boot = ['9.9.9.9:53', '1.1.1.1:53']
    return list(dict.fromkeys(boot))


def render_config(main, fallback, sys_upstream, listen_ip=LISTEN_IP, port=53):
    lines = [
        '# Управляется awg-panel («Настройки → DNS сервера»). Ручные правки затрутся.',
        'listen-addrs: %s' % _yaml_list([listen_ip]),
        'listen-ports: [%d]' % port,
        'upstream: %s' % _yaml_list([e['upstream'] for e in main]),
    ]
    if fallback:
        lines.append('fallback: %s' % _yaml_list([e['upstream'] for e in fallback]))
    boot = _bootstrap_for(main + fallback, sys_upstream)
    if boot:
        lines.append('bootstrap: %s' % _yaml_list(boot))
    lines += [
        'upstream-mode: "load_balance"',
        'timeout: "5s"',
        'cache: true',
        'cache-size: 4194304',
        'hosts-file-enabled: false',
        'pending-requests-enabled: true',
        '',
    ]
    return '\n'.join(lines)


def _free_port():
    for _ in range(30):
        port = random.randint(20000, 60000)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.bind(('127.0.0.1', port))
            with socket.socket() as t:
                t.bind(('127.0.0.1', port))
            return port
        except OSError:
            continue
    raise RuntimeError('не нашлось свободного порта для пробного запуска')


def trial(entries, sys_upstream, full=True, binary=None):
    """Пробный dnsproxy на 127.0.0.1:<свободный> с этими резолверами → probe()."""
    port = _free_port()
    d = tempfile.mkdtemp(prefix='awgp-dnstrial-')
    p = None
    try:
        cfg = os.path.join(d, 'c.yaml')
        with open(cfg, 'w') as f:
            f.write(render_config(entries, [], sys_upstream, '127.0.0.1', port))
        logf = open(os.path.join(d, 'out.log'), 'w')
        p = subprocess.Popen([binary or DNSPROXY_BIN, '--config-path=' + cfg], stdout=logf, stderr=subprocess.STDOUT)
        res = None
        until = time.time() + 4
        while time.time() < until:
            if p.poll() is not None:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.3)
                    qid, pkt = _packet('localhost', 1)
                    s.sendto(pkt, ('127.0.0.1', port))
                    s.recvfrom(512)
                break
            except Exception:
                time.sleep(0.2)
        if p.poll() is not None:
            logf.close()
            tail = open(os.path.join(d, 'out.log'), errors='replace').read().strip().splitlines()[-3:]
            return {'ok': False, 'error': 'dnsproxy не принял адрес: ' + ' / '.join(tail)[-300:]}
        res = probe('127.0.0.1', port) if full else None
        if res is None:
            rc, ips, _t, ms = query('127.0.0.1', port, PROBE_OK)
            res = {'ok': not rc and bool(ips), 'ms': ms, 'error': '' if ips else 'пустой ответ'}
        return res
    except Exception as e:
        return {'ok': False, 'error': _human(e)}
    finally:
        if p is not None:
            try:
                p.kill()
                p.wait(3)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)


def _sh(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except Exception as e:
        return 1, str(e)


def _write_unit():
    body = (
        '[Unit]\n'
        'Description=DNS сервера (dnsproxy, managed by awg-panel)\n'
        'After=network-online.target\n'
        'Wants=network-online.target\n'
        '\n'
        '[Service]\n'
        'Type=simple\n'
        'ExecStart=%s --config-path=%s\n'
        'Restart=always\n'
        'RestartSec=2\n'
        'DynamicUser=yes\n'
        'AmbientCapabilities=CAP_NET_BIND_SERVICE\n'
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
        'NoNewPrivileges=yes\n'
        'LimitNOFILE=65536\n'
        '\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
    ) % (DNSPROXY_BIN, CONF_FILE)
    old = ''
    try:
        old = open(UNIT_FILE).read()
    except OSError:
        pass
    if old != body:
        with open(UNIT_FILE, 'w') as f:
            f.write(body)
        _sh(['systemctl', 'daemon-reload'])


def _write_conf(text):
    os.makedirs(CONF_DIR, exist_ok=True)
    os.chmod(CONF_DIR, 0o755)
    tmp = CONF_FILE + '.new'
    with open(tmp, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, CONF_FILE)


def _wait_listen(secs=6):
    until = time.time() + secs
    err = ''
    while time.time() < until:
        try:
            rc, ips, _t, _ms = query(LISTEN_IP, 53, PROBE_OK, timeout=1.5)
            if not rc and ips:
                return True, ''
            err = 'пустой ответ'
        except Exception as e:
            err = _human(e)
        time.sleep(0.5)
    return False, err


def _unit_journal():
    _rc, out = _sh(['journalctl', '-u', UNIT_NAME, '-n', '5', '--no-pager', '-o', 'cat'])
    return out.strip()[-400:]


# =============================================================================
# Система: systemd-resolved или /etc/resolv.conf
# =============================================================================

def _resolved_active():
    rc, out = _sh(['systemctl', 'is-active', 'systemd-resolved'], 5)
    return out.strip() == 'active'


def _ips_in(text):
    out = []
    for tok in re.split(r'[\s,]+', text or ''):
        tok = tok.split('%')[0].strip('[]')
        if '#' in tok:
            tok = tok.split('#')[0]
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified:
            continue
        out.append(str(ip))
    return out


def system_upstream():
    """DNS хостера — то, куда система ходит, пока мы не вмешались."""
    ips = []
    if _resolved_active():
        _rc, out = _sh(['resolvectl', 'dns'], 5)
        for line in out.splitlines():
            if ':' in line:
                ips += _ips_in(line.split(':', 1)[1])
    if not ips:
        try:
            for line in open(RESOLV_CONF):
                if line.strip().startswith('nameserver'):
                    ips += _ips_in(line.split(None, 1)[1] if len(line.split()) > 1 else '')
        except OSError:
            pass
    return [ip for ip in dict.fromkeys(ips) if ip != LISTEN_IP]


DROPIN_BODY = (
    '# Управляется awg-panel («Настройки → DNS сервера»).\n'
    '# Все запросы системы — в dnsproxy на 127.0.0.2; Domains=~. не даёт resolved\n'
    '# спрашивать DNS хостера с сетевых интерфейсов.\n'
    '[Resolve]\n'
    'DNS=\n'
    'DNS=%s\n'
    'FallbackDNS=\n'
    'Domains=~.\n'
    'DNSOverTLS=no\n' % LISTEN_IP
)

RESOLV_BODY = (
    '# Управляется awg-panel («Настройки → DNS сервера»). Исходный файл сохранён панелью.\n'
    'nameserver %s\n'
    'options edns0 trust-ad\n' % LISTEN_IP
)


def system_points_to_us(mode=None):
    mode = mode or settings().get('mode')
    if mode == 'resolved':
        try:
            return open(RESOLVED_DROPIN).read() == DROPIN_BODY
        except OSError:
            return False
    if mode == 'resolvconf':
        try:
            return ('nameserver %s' % LISTEN_IP) in open(RESOLV_CONF).read()
        except OSError:
            return False
    return False


def _switch_system():
    """→ mode. Переключить систему на 127.0.0.2."""
    if _resolved_active():
        os.makedirs(os.path.dirname(RESOLVED_DROPIN), exist_ok=True)
        for old in RESOLVED_DROPIN_OLD:
            try:
                os.remove(old)
            except OSError:
                pass
        with open(RESOLVED_DROPIN, 'w') as f:
            f.write(DROPIN_BODY)
        rc, out = _sh(['systemctl', 'restart', 'systemd-resolved'], 20)
        if rc:
            raise RuntimeError('systemd-resolved не перезапустился: ' + out.strip()[-200:])
        return 'resolved'
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(RESOLV_BACKUP):
        meta = {'link': os.readlink(RESOLV_CONF) if os.path.islink(RESOLV_CONF) else '',
                'body': open(RESOLV_CONF).read() if os.path.exists(RESOLV_CONF) else ''}
        with open(RESOLV_BACKUP, 'w') as f:
            json.dump(meta, f)
    if os.path.islink(RESOLV_CONF):
        os.unlink(RESOLV_CONF)
    with open(RESOLV_CONF + '.awgp', 'w') as f:
        f.write(RESOLV_BODY)
    os.replace(RESOLV_CONF + '.awgp', RESOLV_CONF)
    return 'resolvconf'


def _restore_system(mode):
    paths = [RESOLVED_DROPIN] + RESOLVED_DROPIN_OLD
    if mode == 'resolved' or any(os.path.exists(x) for x in paths):
        for x in paths:
            try:
                os.remove(x)
            except OSError:
                pass
        if _resolved_active():
            _sh(['systemctl', 'restart', 'systemd-resolved'], 20)
    if mode == 'resolvconf' and os.path.exists(RESOLV_BACKUP):
        try:
            meta = json.load(open(RESOLV_BACKUP))
            if os.path.lexists(RESOLV_CONF):
                os.remove(RESOLV_CONF)
            if meta.get('link'):
                os.symlink(meta['link'], RESOLV_CONF)
            else:
                with open(RESOLV_CONF, 'w') as f:
                    f.write(meta.get('body') or '')
            os.remove(RESOLV_BACKUP)
        except Exception:
            pass


def _system_resolves():
    """Резолвит ли система (тот путь, которым ходят xray/hysteria/панель)."""
    if _resolved_active():
        try:
            rc, ips, _t, _ms = query(RESOLVED_STUB, 53, PROBE_OK)
            return (not rc and bool(ips)), ''
        except Exception as e:
            return False, _human(e)
    try:
        socket.getaddrinfo(PROBE_OK, 443, socket.AF_INET)
        return True, ''
    except Exception as e:
        return False, _human(e)


def _system_server():
    return RESOLVED_STUB if _resolved_active() else LISTEN_IP


# =============================================================================
# Фоновые операции
# =============================================================================

def _start_job(kind, fn):
    with _lock:
        if _job.get('state') == 'running':
            return False
        _job.clear()
        _job.update(id='%x' % random.getrandbits(40), kind=kind, state='running', steps=[],
                    result=None, error='', ts=int(time.time()))

    def step(text):
        _job['steps'].append(text)

    def run():
        try:
            _job['result'] = fn(step)
            _job['state'] = 'done'
        except Exception as e:
            _job['error'] = str(e)[:500] or e.__class__.__name__
            _job['state'] = 'error'
    threading.Thread(target=run, daemon=True).start()
    return True


def _parse_both(main_text, fb_text):
    main = parse_many(main_text)
    fb = parse_many(fb_text)
    bad = [e for e in main + fb if not e['ok']]
    if bad:
        raise RuntimeError('не разобран адрес «%s»: %s' % (bad[0]['raw'], bad[0]['error']))
    if not main:
        raise RuntimeError('введите адрес DNS')
    return main, fb


def _job_check(main_text, fb_text):
    def fn(step):
        main, fb = _parse_both(main_text, fb_text)
        ensure_binary(step)
        sysup = settings().get('sys_upstream') or system_upstream()
        out = {'main': None, 'fallback': None}
        step('Пробный запуск с вашим DNS…')
        with ThreadPoolExecutor(max_workers=2) as ex:
            fm = ex.submit(trial, main, sysup)
            ff = ex.submit(trial, fb, sysup) if fb else None
            out['main'] = fm.result()
            out['fallback'] = ff.result() if ff else None
        return out
    return fn


def _job_apply(main_text, fb_text):
    def fn(step):
        main, fb = _parse_both(main_text, fb_text)
        cur = settings()
        was_on = bool(cur.get('enabled')) and system_points_to_us(cur.get('mode'))
        ensure_binary(step)
        sysup = cur.get('sys_upstream') or []
        if not was_on or not sysup:
            sysup = system_upstream() or sysup
        step('Пробный запуск с вашим DNS…')
        t = trial(main, sysup, full=False)
        if not t.get('ok'):
            raise RuntimeError('DNS не ответил при пробном запуске: %s. Ничего не изменено.' % (t.get('error') or '?'))
        old_conf = ''
        try:
            old_conf = open(CONF_FILE).read()
        except OSError:
            pass
        step('Запускаю dnsproxy на %s…' % LISTEN_IP)
        _write_conf(render_config(main, fb, sysup))
        _write_unit()
        _sh(['systemctl', 'enable', UNIT_NAME], 15)
        _sh(['systemctl', 'restart', UNIT_NAME], 20)
        ok, err = _wait_listen()
        if not ok:
            jr = _unit_journal()
            if was_on and old_conf:
                _write_conf(old_conf)
                _sh(['systemctl', 'restart', UNIT_NAME], 20)
            else:
                _sh(['systemctl', 'disable', '--now', UNIT_NAME], 20)
            raise RuntimeError('dnsproxy не ответил на %s:53 (%s). Возвращено как было.\n%s' % (LISTEN_IP, err, jr))
        mode = cur.get('mode') if was_on else ''
        if not was_on:
            step('Переключаю систему на свой DNS…')
            try:
                mode = _switch_system()
            except Exception as e:
                _restore_system('resolved' if _resolved_active() else 'resolvconf')
                _sh(['systemctl', 'disable', '--now', UNIT_NAME], 20)
                raise RuntimeError('не удалось переключить систему: %s. Возвращено как было.' % e)
        step('Проверяю, что сервер резолвит…')
        time.sleep(0.5)
        ok, err = _system_resolves()
        if not ok:
            if not was_on:
                _restore_system(mode)
                _sh(['systemctl', 'disable', '--now', UNIT_NAME], 20)
            raise RuntimeError('после переключения система не резолвит (%s). Возвращено как было.' % err)
        _save({'enabled': True, 'main': main_text.strip(), 'fallback': fb_text.strip(),
               'sys_upstream': sysup, 'mode': mode, 'failover_since': 0})
        _health.update(ok=True, ts=int(time.time()), error='', fails=0, oks=0)
        step('Перевожу XRay на DNS сервера…')
        try:
            apply_xray_dns()
        except Exception:
            pass
        step('Проверяю, кто резолвит на самом деле…')
        report = _verify_report()
        audit('info', 'DNS сервера %s: %s' % ('изменён' if was_on else 'включён',
                                             ', '.join(e['upstream'] for e in main)[:200]))
        return report
    return fn


def _job_disable():
    def fn(step):
        cur = settings()
        step('Возвращаю системе DNS хостера…')
        _restore_system(cur.get('mode') or '')
        step('Останавливаю dnsproxy…')
        _sh(['systemctl', 'disable', '--now', UNIT_NAME], 20)
        _save({'enabled': False, 'mode': '', 'failover_since': 0})
        _health.update(ok=None, ts=0, error='', fails=0, oks=0)
        step('Возвращаю XRay его DNS из Global…')
        try:
            apply_xray_dns()
        except Exception:
            pass
        ok, err = _system_resolves()
        audit('info', 'DNS сервера выключен — снова DNS хостера')
        if not ok:
            raise RuntimeError('DNS хостера сейчас не отвечает: %s' % err)
        return {'system_ok': True}
    return fn


def _verify_report():
    """Сравнить, кто резолвит через dnsproxy напрямую и через системный путь:
    разные владельцы = часть запросов идёт мимо."""
    direct = probe(LISTEN_IP, 53)
    sys_ip, sys_org = egress(_system_server(), 53)
    leak = bool(direct.get('egress_org') and sys_org and direct['egress_org'] != sys_org)
    # Лишние глобальные DNS у resolved: при сбое 127.0.0.2 он уйдёт на них и там останется.
    extra = []
    if _resolved_active():
        _rc, out = _sh(['resolvectl', 'dns'], 5)
        for line in out.splitlines():
            if line.strip().startswith('Global:'):
                extra = [ip for ip in _ips_in(line.split(':', 1)[1]) if ip != LISTEN_IP]
    return {'direct': direct, 'system_egress_ip': sys_ip, 'system_egress_org': sys_org, 'leak': leak,
            'extra_dns': extra}


# =============================================================================
# Сторож
# =============================================================================

FAIL_TO_RED = 2        # промахов подряд до красной кнопки (один — сеть могла мигнуть)
FAIL_TO_FAILOVER = 3   # промахов подряд до авто-отката на DNS хостера
OK_TO_RETURN = 2       # удачных ответов подряд, чтобы вернуться обратно
HEALTH_FAST = 10       # шаг сторожа, пока что-то не так (обычный — HEALTH_EVERY)


def _probe_dnsproxy():
    """(ok, мс, причина) — отвечает ли наш dnsproxy на 127.0.0.2 по-настоящему."""
    try:
        rc, ips, _t, ms = query(LISTEN_IP, 53, PROBE_OK)
        if rc or not ips:
            return False, 0, 'сервер ответил ошибкой' if rc else 'пустой ответ'
        return True, ms, ''
    except Exception as e:
        return False, 0, _human(e)


def _health_tick():
    s = settings()
    if not s.get('enabled'):
        _health.update(ok=None, ts=0, error='', fails=0, oks=0)
        return
    if _job.get('state') == 'running' or _updating['on']:
        return     # включение/выключение или обновление идёт прямо сейчас — не мешать
    now = int(time.time())
    ok, ms, err = _probe_dnsproxy()
    if not ok and not engine_version():
        err = 'dnsproxy не найден на сервере'

    if not system_points_to_us(s.get('mode')):
        # Система сейчас на DNS хостера: авто-откат после сбоя, восстановленный на
        # новом сервере бэкап (dnsproxy там ещё нет), DHCP перезаписал resolv.conf.
        # Возвращаем ТОЛЬКО когда dnsproxy реально отвечает — иначе сервер остался бы
        # вовсе без DNS. После отката — два удачных ответа подряд, чтобы не качелить.
        if ok:
            _health['oks'] = _health.get('oks', 0) + 1
            need = OK_TO_RETURN if s.get('failover_since') else 1
            if _health['oks'] < need:
                _health.update(ok=False, ts=now)
                return
            was_fo = bool(s.get('failover_since'))
            try:
                with _lock:
                    mode = _switch_system()
                good, e2 = _system_resolves()
                if not good:
                    _restore_system(mode)
                    raise RuntimeError('после переключения система не резолвит (%s)' % e2)
                _save({'mode': mode, 'failover_since': 0})
                _health.update(ok=True, ts=now, error='', ms=ms, fails=0, oks=0)
                audit('info' if was_fo else 'warn',
                      'DNS сервера снова отвечает — система возвращена на него' if was_fo
                      else 'DNS сервера: система ушла с dnsproxy — возвращена')
            except Exception as e:
                _health.update(ok=False, ts=now, error='система не переключена: %s' % e)
            return
        _health['oks'] = 0
        if engine_version() and os.path.exists(CONF_FILE):
            _rc, out = _sh(['systemctl', 'is-active', UNIT_NAME], 5)
            if out.strip() != 'active':
                _sh(['systemctl', 'enable', '--now', UNIT_NAME], 15)
        if s.get('failover_since'):
            _health.update(ok=False, ts=now, error=err)
        else:
            _health.update(ok=False, ts=now,
                           error='dnsproxy не запущен — откройте «DNS сервера» и нажмите «Применить»')
        return

    # Система на dnsproxy.
    _health['oks'] = 0
    if ok:
        _health.update(ok=True, ts=now, error='', ms=ms, fails=0)
        return
    _health['fails'] = _health.get('fails', 0) + 1
    _health.update(ts=now, error=err)
    if _health['fails'] >= FAIL_TO_RED:
        if _health.get('ok') is not False:
            audit('warn', 'DNS сервера не отвечает: %s' % err)
        _health['ok'] = False
        if _health['fails'] == FAIL_TO_RED:
            # Завис или упал — перезапуск; не поможет, если лёг сам провайдер.
            _sh(['systemctl', 'restart', UNIT_NAME], 20)
    if _health['fails'] >= FAIL_TO_FAILOVER and s.get('auto_failover', True):
        # Свой DNS лёг всерьёз — без DNS у клиентов VPN пропал бы интернет. Временно
        # отдаём систему DNS хостера; настройка остаётся включённой, и как только
        # dnsproxy снова ответит, сторож вернёт систему сам (ветка выше).
        try:
            with _lock:
                _restore_system(s.get('mode') or '')
            _save({'failover_since': now})
            good, e2 = _system_resolves()
            audit('warn', 'DNS сервера не отвечает (%s) — система временно на DNS хостера%s'
                  % (err, '' if good else '; DNS хостера тоже не отвечает: %s' % e2))
        except Exception as e:
            audit('warn', 'DNS сервера: не удалось перейти на DNS хостера: %s' % e)


def _health_loop():
    time.sleep(5)
    while True:
        try:
            _health_tick()
        except Exception:
            pass
        # Пока что-то не так — чаще: откат через ~20 с после второго промаха,
        # возврат через ~20 с после того, как DNS ожил.
        trouble = _health.get('fails', 0) > 0 or _health.get('ok') is False
        time.sleep(HEALTH_FAST if trouble else HEALTH_EVERY)


def start_background():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_health_loop, daemon=True).start()
    threading.Thread(target=_update_loop, daemon=True).start()


# =============================================================================
# Роуты
# =============================================================================

def probe_info():
    """Блок для /api/probe/ping внешнего мониторинга: есть ли что проверять."""
    s = settings()
    return {'supported': True, 'enabled': bool(s['enabled']), 'port': 53 if s['enabled'] else 0}


def probe_state():
    """Для /api/probe/dns внешнего мониторинга. up — свой DNS отвечает и система
    ходит через него; «временно на DNS хостера» — это тоже сбой."""
    st = _state()
    if not st['enabled']:
        return {'enabled': False, 'up': None}
    fo = bool(st['failover_since'])
    up = st['ok'] is True and not fo
    if st['ok'] is None and not fo:
        up = None          # сторож ещё не успел проверить — данных нет
    return {'enabled': True, 'up': up, 'ms': st['ms'] if up else None,
            'failover': fo, 'error': st['error'], 'checked_at': st['checked_at']}


def _state():
    s = settings()
    return {'enabled': bool(s['enabled']), 'show_button': bool(s['show_button']),
            'ok': _health.get('ok'), 'error': _health.get('error') or '',
            'checked_at': _health.get('ts') or 0, 'ms': _health.get('ms') or 0,
            'auto_failover': bool(s.get('auto_failover', True)),
            'failover_since': int(s.get('failover_since') or 0) if s['enabled'] else 0}


@bp.route('/api/server-dns/state')
@_auth
def api_state():
    return jsonify(_state())


@bp.route('/api/server-dns')
@_auth
def api_get():
    s = settings()
    return jsonify({
        'settings': {k: s[k] for k in ('enabled', 'main', 'fallback', 'show_button', 'mode', 'auto_failover', 'auto_update')},
        'state': _state(),
        'main': [_public(e) for e in parse_many(s['main'])],
        'fallback': [_public(e) for e in parse_many(s['fallback'])],
        'engine': engine_version(),
        'engine_target': DNSPROXY_VERSION,
        'system': 'resolved' if _resolved_active() else 'resolvconf',
        'system_upstream': s.get('sys_upstream') if s.get('enabled') else system_upstream(),
        'templates': TEMPLATES,
        'job': _job_public(),
    })


@bp.route('/api/server-dns/parse', methods=['POST'])
@_auth
def api_parse():
    d = request.get_json(silent=True) or {}
    return jsonify({'main': [_public(e) for e in parse_many(str(d.get('main') or '')[:2000])],
                    'fallback': [_public(e) for e in parse_many(str(d.get('fallback') or '')[:2000])]})


def _job_public():
    if not _job:
        return None
    return {k: _job.get(k) for k in ('id', 'kind', 'state', 'steps', 'result', 'error', 'ts')}


@bp.route('/api/server-dns/job')
@_auth
def api_job():
    return jsonify({'job': _job_public(), 'state': _state()})


@bp.route('/api/server-dns/check', methods=['POST'])
@_auth
def api_check():
    d = request.get_json(silent=True) or {}
    main, fb = str(d.get('main') or '')[:2000], str(d.get('fallback') or '')[:2000]
    if not _start_job('check', _job_check(main, fb)):
        return jsonify({'error': 'уже идёт другая операция с DNS — дождитесь её'}), 409
    return jsonify({'ok': True, 'job': _job_public()})


@bp.route('/api/server-dns/apply', methods=['POST'])
@_auth
def api_apply():
    d = request.get_json(silent=True) or {}
    if not d.get('enabled'):
        if not settings().get('enabled'):
            return jsonify({'ok': True, 'job': None, 'state': _state()})
        started = _start_job('disable', _job_disable())
    else:
        main, fb = str(d.get('main') or '')[:2000], str(d.get('fallback') or '')[:2000]
        started = _start_job('apply', _job_apply(main, fb))
    if not started:
        return jsonify({'error': 'уже идёт другая операция с DNS — дождитесь её'}), 409
    return jsonify({'ok': True, 'job': _job_public()})


@bp.route('/api/server-dns/button', methods=['POST'])
@_auth
def api_button():
    """Тумблеры окна, которые систему не трогают: кнопка в шапке и авто-откат."""
    d = request.get_json(silent=True) or {}
    patch = {k: bool(d[k]) for k in ('show_button', 'auto_failover', 'auto_update') if k in d}
    if patch:
        _save(patch)
    return jsonify({'ok': True, 'state': _state()})


@bp.route('/api/server-dns/verify', methods=['POST'])
@_auth
def api_verify():
    """Кнопка «Проверить» при включённом DNS: живой dnsproxy и системный путь."""
    if not settings().get('enabled'):
        return jsonify({'error': 'DNS сервера выключен'}), 400

    def fn(step):
        step('Спрашиваю dnsproxy и систему…')
        return _verify_report()
    if not _start_job('verify', fn):
        return jsonify({'error': 'уже идёт другая операция с DNS — дождитесь её'}), 409
    return jsonify({'ok': True, 'job': _job_public()})
