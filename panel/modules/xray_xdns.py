"""XDNS — аварийный вход XRay через DNS-запросы.

Зачем. При «белых списках» телефон может ходить только на разрешённые адреса,
и до нашего сервера напрямую не достучаться ничем — ни VLESS, ни Hysteria.
Но DNS при этом работает: резолвер оператора разрешён всегда. XDNS прячет
трафик в имена DNS-запросов к поддомену, который делегирован нашему серверу
(NS-запись), — резолвер оператора сам доносит их до нас и сам несёт ответ
обратно. Телефон ни разу не обращается к нашему IP. Цена — скорость:
в один запрос влезает пара сотен байт, это канал для мессенджеров.

Как устроено в ядре (сверено с исходниками Xray-core v26.9.30 и v26.10.10,
finalmask/xdns и infra/conf/transport_finalmask.go):
  inbound: protocol vless, port 53/udp, streamSettings.network = "kcp"
  streamSettings.finalmask.udp = [{type: "xdns", settings: {domains: [...]}}]
  клиент: те же domains + resolvers
  Формат domains/resolvers в 26.10.10 сменился снова — пишем оба сразу, см.
  patch_format().
XDNS работает только поверх mKCP (QUIC автор так и не завёл). MTU задаётся
только на сервере: клиент сам режет пакеты на фрагменты по ёмкости запроса.

Клиенты и их email — общие с VLESS: тот же UUID, тот же email, поэтому трафик,
лимиты, правила и логи у клиента одни на все три входа ядра.

Формат XDNS сломали в 26.9.30 (domains стал списком объектов), и ядро старше
не разберёт конфиг вовсе — а невалидный конфиг роняет XRay целиком, вместе с
VLESS. Поэтому: включение запрещено на старом ядре, кандидат конфига
прогоняется через `xray run -test`, а после перезапуска панель проверяет, что
ядро поднялось, и иначе сама снимает XDNS (см. app.py, _xdns_watch).
"""

import json
import os
import urllib.parse
import random
import re
import socket
import string
import struct
import subprocess
import threading
import time

DEPS = {}

INBOUND_TAG = 'xdns-in'
PORT = 53                         # DNS — только 53: резолверы ходят к NS-серверу на него
MIN_CORE = 'v26.9.30'             # новый формат domains/resolvers

# Типы записей. Сервер принимает только TXT: при нескольких типах MTU сервера
# обязан быть по самому «узкому» из них (A — 39 байт при EDNS 512), а TXT несёт
# почти сырые байты. Клиент спрашивает тем же типом.
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_TXT, TYPE_AAAA = 1, 2, 5, 6, 16, 28
QUERY_TYPES = [TYPE_TXT]

# MTU сервера по таблице автора XDNS (TXT): EDNS 512 → 215, EDNS 1232 → 932.
# Слишком большой MTU не «чуть медленнее», а не работает вовсе: ответ не влезает
# в UDP резолвера, тот уходит на TCP, а XDNS слушает только UDP. Google, к
# примеру, держит EDNS 512 — поэтому по умолчанию совместимый режим.
PROFILES = {
    'compat': {'mtu': 215, 'title': 'Совместимость', 'note': 'TXT · MTU 215 — проходит через любой резолвер'},
    'fast':   {'mtu': 932, 'title': 'Скорость',      'note': 'TXT · MTU 932 — только резолверы с EDNS 1232'},
}
DEFAULT_PROFILE = 'compat'
KCP_TTI = 200                     # рекомендация автора XDNS для обеих сторон
CLIENT_EDNS0 = 1232
CLIENT_EXTRA_POLL = 1             # лишний опрос на каждый пакет — быстрее приходят ответы

# Резолверы, через которые ходит клиент. Клиент рассылает запросы по ВСЕМ
# поровну (resolverSends в client.go), поэтому заблокированный резолвер в
# списке теряет свою долю пакетов — по умолчанию один, проверенный.
RESOLVER_PRESETS = [
    {'addr': '77.88.8.8:53', 'title': 'Яндекс DNS'},
    {'addr': '8.8.8.8:53', 'title': 'Google'},
    {'addr': '1.1.1.1:53', 'title': 'Cloudflare'},
    {'addr': '9.9.9.9:53', 'title': 'Quad9'},
]
DEFAULT_RESOLVERS = ['77.88.8.8:53']

# Через кого проверяем делегирование и сквозной путь.
CHECK_RESOLVERS = [('8.8.8.8', 'Google'), ('1.1.1.1', 'Cloudflare'), ('77.88.8.8', 'Яндекс')]
LOOKUP_RESOLVERS = ['1.1.1.1', '8.8.8.8']


def init(deps):
    DEPS.update(deps or {})
    return True


def audit(level, msg):
    fn = DEPS.get('audit')
    if fn:
        try:
            fn(level, '[XDNS] %s' % msg)
        except Exception:
            pass


def run_cmd(cmd):
    fn = DEPS.get('run_cmd')
    return fn(cmd) if fn else ('', 'run_cmd не проброшен', 1)


# --- версия ядра -------------------------------------------------------------

def _ver_tuple(v):
    m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', str(v or '').strip())
    return tuple(int(x) for x in m.groups()) if m else None


def core_version():
    fn = DEPS.get('xray_version')
    try:
        return (fn() if fn else '') or ''
    except Exception:
        return ''


def core_supported(ver=None):
    t = _ver_tuple(ver if ver is not None else core_version())
    return bool(t) and t >= _ver_tuple(MIN_CORE)


# --- намерение и живой конфиг -----------------------------------------------

def default_settings():
    return {'domain': '', 'ns_host': '', 'profile': DEFAULT_PROFILE,
            'resolvers': list(DEFAULT_RESOLVERS), 'vless_dec': ''}


# --- VLESS Encryption ----------------------------------------------------------
# VLESS внутри XDNS идёт через чужой DNS-резолвер (Яндекс, Google): без
# шифрования тот видит UUID клиента и может подключаться от его имени. Поэтому
# Xray ≥ 26.9 и отказывается запускать VLESS без TLS/шифрования на публичный
# адрес («vless without TLS or other encryption is prohibited»), а адрес у XDNS
# всегда публичный — первый резолвер. Шифрование — штатное (xray vlessenc,
# вариант X25519: ключи короткие, ссылка и QR остаются компактными).
# Источник правды — decryption в живом инбаунде; ключ клиента из него
# выводится однозначно (xray x25519 -i), поэтому ссылки не расходятся с сервером.

_ENC_CACHE = {}


def _xray_bin():
    return DEPS.get('xray_bin') or '/usr/local/bin/xray'


def gen_keys():
    """(decryption, encryption) — новая пара X25519 от самого ядра."""
    try:
        p = subprocess.run([_xray_bin(), 'vlessenc'], capture_output=True, text=True, timeout=20)
        out = p.stdout or ''
    except Exception:
        return '', ''
    dec = re.findall(r'"decryption":\s*"([^"]+)"', out)
    enc = re.findall(r'"encryption":\s*"([^"]+)"', out)
    return (dec[0], enc[0]) if dec and enc else ('', '')


def enc_from_dec(dec):
    """Строка encryption для клиента из decryption сервера."""
    if not dec or not dec.startswith('mlkem768x25519plus.'):
        return ''
    if dec in _ENC_CACHE:
        return _ENC_CACHE[dec]
    parts = dec.split('.')
    priv = parts[-1]
    # Ключ X25519 — 43 символа base64url; ML-KEM-вариант длиннее, его не выводим.
    if len(priv) != 43:
        return ''
    try:
        p = subprocess.run([_xray_bin(), 'x25519', '-i', priv], capture_output=True, text=True, timeout=10)
        m = re.search(r'Password[^:\n]*:\s*(\S+)', p.stdout or '')
    except Exception:
        m = None
    if not m:
        return ''
    enc = '.'.join([parts[0], parts[1], '0rtt', m.group(1)])
    _ENC_CACHE[dec] = enc
    return enc


def ensure_keys(settings):
    """Настройки с ключами: свои, если уже есть, иначе — новая пара."""
    if (settings.get('vless_dec') or '').startswith('mlkem768x25519plus.') and enc_from_dec(settings['vless_dec']):
        return settings
    dec, enc = gen_keys()
    if dec:
        _ENC_CACHE[dec] = enc
        return dict(settings, vless_dec=dec)
    return settings


def needs_encryption(cfg_x=None):
    """Вход включён, но без шифрования — так его включала панель до этой правки."""
    if cfg_x is None:
        cfg_x, err = _load_cfg()
        if err:
            return False
    idx = find_idx(cfg_x)
    if idx < 0:
        return False
    return ((cfg_x['inbounds'][idx].get('settings') or {}).get('decryption') or 'none') == 'none'


def _load_intent():
    fn = DEPS.get('load_intent')
    try:
        return (fn() or {}) if fn else {}
    except Exception:
        return {}


def _save_intent(settings):
    fn = DEPS.get('save_intent')
    if fn:
        try:
            fn({k: settings.get(k) for k in default_settings()})
        except Exception:
            pass


def remember_settings(settings):
    _save_intent(settings)


# --- формат блока finalmask/xdns ----------------------------------------------
# Формат ломают от релиза к релизу. 26.9.30: domains [{name}], resolvers
# [{type, settings: {addr}}]. 26.10.10: domains [{names: [..]}], resolvers
# [{addrs: ["udp://h:p"]}], а старые ключи ядро молча пропускает — и падает
# с «xdns: empty domains», унося VLESS и Hysteria. Лоадер Xray незнакомые поля
# игнорирует (encoding/json без DisallowUnknownFields), поэтому пишем ОБА
# варианта в один объект: такой конфиг понимают и старое, и новое ядро, а
# профиль клиента — приложения на любом из них.

def _domain_entry(dom, **extra):
    d = {'name': dom, 'names': [dom], 'types': list(QUERY_TYPES)}
    d.update(extra)
    return d


def _resolver_entry(addr, kind='udp'):
    return {'type': kind, 'settings': {'addr': addr}, 'addrs': ['%s://%s' % (kind, addr)]}


def patch_format(cfg_x):
    """Довести все блоки xdns в конфиге (входы и выходы) до двойного формата —
    на месте, остальные ключи не трогаем. Возвращает число исправленных блоков."""
    fixed = 0
    for ib in ((cfg_x or {}).get('inbounds') or []) + ((cfg_x or {}).get('outbounds') or []):
        for m in (((ib.get('streamSettings') or {}).get('finalmask') or {}).get('udp') or []):
            if m.get('type') != 'xdns':
                continue
            s = m.setdefault('settings', {})
            touched = False
            for d in s.get('domains') or []:
                if not isinstance(d, dict):
                    continue
                if d.get('name') and not d.get('names'):
                    d['names'] = [d['name']]; touched = True
                elif d.get('names') and not d.get('name'):
                    d['name'] = d['names'][0]; touched = True
                if not d.get('types'):
                    d['types'] = list(QUERY_TYPES); touched = True
            for r in s.get('resolvers') or []:
                if not isinstance(r, dict):
                    continue
                addr = (r.get('settings') or {}).get('addr')
                if addr and not r.get('addrs'):
                    r['addrs'] = ['%s://%s' % (r.get('type') or 'udp', addr)]; touched = True
                elif r.get('addrs') and not addr:
                    a = str(r['addrs'][0])
                    kind, _, hp = a.partition('://') if '://' in a else ('udp', '', a)
                    r['type'] = kind
                    r['settings'] = {'addr': hp if ':' in hp.rsplit(']', 1)[-1] else hp + ':53'}
                    touched = True
            fixed += touched
    return fixed


def heal_format():
    """Живой config.json → двойной формат XDNS. (исправлено_блоков, ошибка)."""
    cfg_x, err = _load_cfg()
    if err:
        return 0, err
    n = patch_format(cfg_x)
    if not n:
        return 0, ''
    try:
        DEPS['xray_save_config'](cfg_x)
    except Exception as e:
        return 0, 'не удалось записать конфиг XRay: %s' % e
    audit('info', 'формат XDNS в конфиге приведён к совместимому со всеми версиями ядра')
    return n, ''


def _load_cfg():
    load = DEPS.get('xray_load_config')
    if not load:
        return None, 'нет доступа к конфигу XRay'
    try:
        return load(), ''
    except Exception as e:
        return None, 'не удалось прочитать конфиг XRay: %s' % e


def find_idx(cfg_x):
    for i, ib in enumerate((cfg_x or {}).get('inbounds') or []):
        if ib.get('tag') == INBOUND_TAG:
            return i
    return -1


def enabled():
    cfg_x, err = _load_cfg()
    return (find_idx(cfg_x) >= 0) if not err else False


def normalize_domain(d):
    d = (d or '').strip().lower().rstrip('.')
    d = re.sub(r'^https?://', '', d).split('/')[0]
    return d


def valid_domain(d):
    if not d or len(d) > 200 or '..' in d:
        return False
    labels = d.split('.')
    if len(labels) < 3:
        # Делегировать можно только поддомен: t.example.com, а не example.com —
        # NS самого домена держит регистратор, и сайт/почта на нём умерли бы.
        return False
    return all(re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', x) for x in labels)


def read_settings(cfg_x=None):
    """Намерение (server.json) поверх дефолтов, а домен и MTU — из живого
    инбаунда, если он есть: источник правды — то, чем реально работает ядро."""
    s = default_settings()
    s.update({k: v for k, v in (_load_intent() or {}).items() if k in s and v not in (None, '')})
    if not isinstance(s.get('resolvers'), list) or not s['resolvers']:
        s['resolvers'] = list(DEFAULT_RESOLVERS)
    if s.get('profile') not in PROFILES:
        s['profile'] = DEFAULT_PROFILE
    if cfg_x is None:
        cfg_x, err = _load_cfg()
        if err:
            return s
    idx = find_idx(cfg_x)
    if idx < 0:
        return s
    stream = (cfg_x['inbounds'][idx].get('streamSettings') or {})
    for m in ((stream.get('finalmask') or {}).get('udp') or []):
        if m.get('type') == 'xdns':
            doms = ((m.get('settings') or {}).get('domains') or [])
            d0 = doms[0] if doms and isinstance(doms[0], dict) else {}
            name = d0.get('name') or ((d0.get('names') or [''])[0])
            if name:
                s['domain'] = name
    mtu = int(((stream.get('kcpSettings') or {}).get('mtu')) or 0)
    for key, p in PROFILES.items():
        if p['mtu'] == mtu:
            s['profile'] = key
    live_dec = (cfg_x['inbounds'][idx].get('settings') or {}).get('decryption') or ''
    if live_dec.startswith('mlkem768x25519plus.'):
        s['vless_dec'] = live_dec
    return s


# --- адрес, на котором слушать ----------------------------------------------

def listen_ip():
    """Конкретный адрес, а не 0.0.0.0.

    На 53-м порту почти всегда кто-то уже есть: systemd-resolved на
    127.0.0.53, dnsmasq «Логов+» AWG на адресе awg0. Шаблон 0.0.0.0:53
    столкнулся бы с ними (EADDRINUSE), а заодно не дал бы им подняться позже.
    Слушаем ровно адрес, на который приходят пакеты снаружи, — источник
    маршрута по умолчанию. За NAT это внутренний адрес интерфейса: хостер
    пробрасывает на него публичный.
    """
    fn = DEPS.get('outbound_ip')
    try:
        ip = (fn() if fn else '') or ''
    except Exception:
        ip = ''
    return ip


def public_ip():
    fn = DEPS.get('public_ip')
    try:
        return (fn() if fn else '') or ''
    except Exception:
        return ''


# --- сборка ------------------------------------------------------------------

def client_email(client, uuid):
    fn = DEPS.get('unique_email')
    if fn:
        return fn(client.get('name') or '', uuid)
    return '%s-%s' % ((client.get('name') or 'client'), uuid[:8])


def build_users(clients):
    """Те же клиенты, что у VLESS, без flow: XTLS Vision поверх mKCP не работает."""
    users = []
    for uuid, c in (clients or {}).items():
        if c.get('disabled'):
            continue
        users.append({'id': uuid, 'email': client_email(c, uuid)})
    return users


def build_inbound(settings, users, listen=''):
    prof = PROFILES.get(settings.get('profile')) or PROFILES[DEFAULT_PROFILE]
    return {
        'tag': INBOUND_TAG,
        'listen': listen or listen_ip() or '0.0.0.0',
        'port': PORT,
        'protocol': 'vless',
        'settings': {'clients': list(users or []), 'decryption': settings.get('vless_dec') or 'none'},
        'streamSettings': {
            'network': 'kcp',
            'kcpSettings': {'mtu': prof['mtu'], 'tti': KCP_TTI},
            'finalmask': {'udp': [{
                'type': 'xdns',
                'settings': {'domains': [_domain_entry(settings['domain'])]},
            }]},
        },
        # Как у остальных входов: без sniffing в access.log одни IP.
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic']},
    }


def _test_config(cfg_x):
    """(ok, текст). Прогон кандидата через `xray run -test` до записи на диск:
    невалидный конфиг роняет XRay целиком, вместе с VLESS и Hysteria."""
    xray_bin = DEPS.get('xray_bin') or '/usr/local/bin/xray'
    if not os.path.exists(xray_bin):
        return True, ''               # ядра нет — проверять нечем, рестарт и не случится
    tmp_dir = DEPS.get('data_dir') or '/tmp'
    path = os.path.join(tmp_dir, '.xdns-test-%d.json' % os.getpid())
    try:
        os.makedirs(tmp_dir, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(cfg_x, f)
        p = subprocess.run([xray_bin, 'run', '-test', '-c', path],
                           capture_output=True, text=True, timeout=20)
        out = ((p.stdout or '') + '\n' + (p.stderr or '')).strip()
        if p.returncode == 0:
            return True, ''
        # Хвост с причиной, без баннера версии.
        lines = [l for l in out.splitlines() if l.strip() and not l.startswith('Xray ')]
        return False, '\n'.join(lines[-6:])[-700:] or 'xray -test завершился с ошибкой'
    except subprocess.TimeoutExpired:
        return True, ''               # не дождались проверки — не блокируем, сторож после рестарта
    except Exception as e:
        return True, 'проверка не выполнена: %s' % e
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def apply_inbound(settings=None):
    """Добавить/обновить инбаунд в config.json. (ok, ошибка). Без рестарта —
    его планирует вызывающий, после ответа браузеру."""
    if not core_supported():
        return False, ('XDNS нужен XRay %s или новее, установлен %s — сначала обновите ядро'
                       % (MIN_CORE, core_version() or 'неизвестно'))
    cfg_x, err = _load_cfg()
    if err:
        return False, err
    settings = settings or read_settings(cfg_x)
    dom = normalize_domain(settings.get('domain'))
    if not valid_domain(dom):
        return False, 'укажите поддомен для туннеля, например t.example.com'
    settings = ensure_keys(dict(settings, domain=dom))
    if not settings.get('vless_dec'):
        return False, ('не удалось сгенерировать ключи шифрования (xray vlessenc) — без них Xray '
                       'не примет VLESS через DNS-резолвер')
    listen = listen_ip()
    clash = port53_state(listen).get('conflict')
    if clash:
        return False, clash

    clients = (DEPS.get('load_clients') or (lambda: {}))() or {}
    inb = build_inbound(settings, build_users(clients), listen)
    cfg_x.setdefault('inbounds', [])
    idx = find_idx(cfg_x)
    if idx < 0:
        cfg_x['inbounds'].append(inb)
    else:
        cfg_x['inbounds'][idx] = inb
    ok, why = _test_config(cfg_x)
    if not ok:
        return False, 'XRay не принял конфиг XDNS — ничего не изменено:\n%s' % why
    _save_intent(settings)
    try:
        DEPS['xray_save_config'](cfg_x)
    except Exception as e:
        return False, 'не удалось записать конфиг XRay: %s' % e
    opener = DEPS.get('open_firewall')
    if opener:
        try:
            opener(PORT)
        except Exception:
            pass
    audit('info', 'инбаунд применён (%s, %s:%d/udp, MTU %d, клиентов %d)'
          % (dom, listen or '0.0.0.0', PORT, PROFILES[settings['profile']]['mtu'],
             len(inb['settings']['clients'])))
    return True, ''


def remove_inbound():
    cfg_x, err = _load_cfg()
    if err:
        return False, err
    idx = find_idx(cfg_x)
    if idx < 0:
        return True, ''
    cfg_x['inbounds'].pop(idx)
    try:
        DEPS['xray_save_config'](cfg_x)
    except Exception as e:
        return False, 'не удалось записать конфиг XRay: %s' % e
    audit('info', 'инбаунд удалён')
    return True, ''


def sync():
    """Пересобрать users под базу клиентов (добавление/удаление/переименование).
    Только файл: живое ядро применяет вызывающий (adu/rmu или рестарт)."""
    cfg_x, err = _load_cfg()
    if err:
        return False, err
    idx = find_idx(cfg_x)
    if idx < 0:
        return True, ''
    clients = (DEPS.get('load_clients') or (lambda: {}))() or {}
    users = build_users(clients)
    inb = cfg_x['inbounds'][idx]
    if (inb.get('settings') or {}).get('clients') == users:
        return True, ''
    inb.setdefault('settings', {})['clients'] = users
    try:
        DEPS['xray_save_config'](cfg_x)
    except Exception as e:
        return False, 'не удалось записать конфиг XRay: %s' % e
    return True, ''


# --- конфиг клиента ----------------------------------------------------------

PRIVATE_NETS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16',
                '100.64.0.0/10', '::1/128', 'fc00::/7', 'fe80::/10')


def client_link(client, uuid, settings=None):
    """Ссылка vless:// для XDNS — по стандарту ссылок Xray (XTLS/Xray-core
    discussion #716): type=kcp, tti, и параметр fm — весь блок finalmask
    JSON-ом через encodeURIComponent. Строится из того же outbound, что и
    JSON-конфиг, чтобы ссылка и конфиг не разошлись. Её же панель кладёт в QR."""
    cfg = client_config(client, uuid, settings)
    if not cfg:
        return ''
    ob = cfg['outbounds'][0]
    vn = ob['settings']['vnext'][0]
    ss = ob['streamSettings']
    fm = json.dumps(ss['finalmask'], separators=(',', ':'), ensure_ascii=False)
    q = [('encryption', vn['users'][0]['encryption']), ('security', 'none'), ('type', 'kcp'),
         ('tti', str((ss.get('kcpSettings') or {}).get('tti') or KCP_TTI)), ('fm', fm)]
    # encodeURIComponent: оставляет только A-Z a-z 0-9 - _ . ! ~ * ' ( )
    qs = '&'.join('%s=%s' % (k, urllib.parse.quote(v, safe="-_.!~*'()")) for k, v in q)
    host = vn['address']
    host = '[%s]' % host if ':' in host else host
    return 'vless://%s@%s:%d?%s#%s' % (uuid, host, int(vn['port']), qs,
                                       urllib.parse.quote(cfg.get('remarks') or 'XDNS', safe=''))


def client_config(client, uuid, settings=None):
    """Полный JSON-конфиг Xray для клиента. Запасной путь к ссылке
    (client_link): для приложений, которые параметр fm ещё не понимают, —
    импорт «из буфера» в любом клиенте на ядре Xray ≥ 26.9.30."""
    settings = settings or read_settings()
    dom = settings.get('domain') or ''
    if not dom or client.get('disabled'):
        return None
    resolvers = [r for r in (settings.get('resolvers') or []) if r] or list(DEFAULT_RESOLVERS)
    enc = enc_from_dec(settings.get('vless_dec') or '')
    if not enc:
        # Без шифрования клиент на Xray ≥ 26.9 конфиг не запустит — не выдаём
        # заведомо нерабочий профиль.
        return None
    first = resolvers[0]
    host, _, port = first.rpartition(':')
    remark_fn = DEPS.get('remark')
    try:
        remark = remark_fn(client, uuid) if remark_fn else (client.get('name') or 'client')
    except Exception:
        remark = client.get('name') or 'client'
    return {
        'remarks': '%s · XDNS' % remark,
        'log': {'loglevel': 'warning'},
        'inbounds': [
            {'tag': 'socks', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True},
             'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}},
            {'tag': 'http', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']}},
        ],
        'outbounds': [
            {'tag': 'proxy', 'protocol': 'vless',
             # Адрес ядру для XDNS безразличен — пакеты уходят на resolvers, —
             # но поле обязательное. Пишем первый резолвер: так строка в
             # списке серверов приложения не вводит в заблуждение.
             'settings': {'vnext': [{'address': host or '77.88.8.8', 'port': int(port or 53),
                                     'users': [{'id': uuid, 'encryption': enc}]}]},
             'streamSettings': {
                 'network': 'kcp',
                 'kcpSettings': {'tti': KCP_TTI},
                 'finalmask': {'udp': [{
                     'type': 'xdns',
                     'settings': {
                         'domains': [_domain_entry(dom, edns0=CLIENT_EDNS0)],
                         'resolvers': [_resolver_entry(r) for r in resolvers],
                         'extraPoll': CLIENT_EXTRA_POLL,
                     },
                 }]},
             }},
            {'tag': 'direct', 'protocol': 'freedom'},
            {'tag': 'block', 'protocol': 'blackhole'},
        ],
        # Локальные сети — напрямую. Диапазоны явно, а не geoip:private: в
        # части приложений файла geoip.dat нет, и ядро отвергает весь профиль
        # («failed to open geoip.dat»).
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'ip': list(PRIVATE_NETS), 'outboundTag': 'direct'},
        ]},
    }


# --- порт 53 -----------------------------------------------------------------

_WILDCARDS = ('0.0.0.0', '*', '[::]', '::', '[::ffff:0.0.0.0]')


def port53_state(listen=None):
    """Кто сидит на 53/udp и мешает ли он нам.

    {conflict: '' | текст, holders: [{addr, process, blocks, note}], listen}.
    Мешает только тот, кто держит НАШ адрес или все адреса сразу (0.0.0.0, [::]).
    systemd-resolved на 127.0.0.53 и dnsmasq на адресе awg0 — соседи, не помеха.
    """
    listen = listen if listen is not None else listen_ip()
    rows = []
    try:
        rows = [s for s in ((DEPS.get('listening_sockets') or (lambda: []))() or [])
                if s.get('proto') == 'udp' and int(s.get('port') or 0) == PORT]
    except Exception:
        rows = []
    holders, conflict = [], ''
    for s in rows:
        addr = (s.get('addr') or '').strip()
        proc = s.get('process') or 'неизвестный процесс'
        bare = addr.strip('[]').split('%')[0]
        ours = 'xray' in proc.lower()
        blocks = (not ours) and (addr in _WILDCARDS or bare == listen or bare == '::ffff:%s' % listen)
        note = ''
        if ours:
            note = 'это XDNS — вход XRay'
        elif blocks:
            note = 'держит %s — XRay на %s:53 не поднимется' % (
                'все адреса' if addr in _WILDCARDS else 'наш адрес', listen or '?')
        elif bare.startswith('127.'):
            note = 'локальный DNS системы — не мешает'
        else:
            note = 'слушает только %s — не мешает' % bare
        holders.append({'addr': addr, 'process': proc, 'blocks': blocks, 'ours': ours, 'note': note})
        if blocks and not conflict:
            conflict = ('53/udp на %s уже занят: %s слушает %s' %
                        (listen or 'внешнем адресе', proc, 'все адреса' if addr in _WILDCARDS else addr))
    fix = ''
    for h in holders:
        if h['blocks'] and 'dnsmasq' in h['process'].lower():
            fix = 'dnsmasq'
    return {'conflict': conflict, 'holders': holders, 'listen': listen, 'fix': fix}


DNSMASQ_FIX_FILE = '/etc/dnsmasq.d/00-awg-panel-xdns.conf'


def fix_dnsmasq(listen=None):
    """dnsmasq без bind-interfaces занимает 0.0.0.0:53. Велим ему привязываться
    к адресам поштучно и не трогать внешний интерфейс — его собственная работа
    (локальный кеш, AWG «Логи+» на awg0) не меняется."""
    listen = listen or listen_ip()
    iface = ''
    out, _, rc = run_cmd("ip -4 -o addr show | awk '$4 ~ /^%s\\// {print $2}'" % re.escape(listen or 'x'))
    if rc == 0:
        iface = (out or '').strip().splitlines()[0] if (out or '').strip() else ''
    if not iface:
        return False, 'не нашёл интерфейс с адресом %s' % (listen or '?')
    body = ('# awg-panel: освобождает %s:53 для XDNS (вход XRay через DNS).\n'
            'bind-interfaces\nexcept-interface=%s\n' % (listen, iface))
    try:
        with open(DNSMASQ_FIX_FILE, 'w') as f:
            f.write(body)
    except Exception as e:
        return False, 'не удалось записать %s: %s' % (DNSMASQ_FIX_FILE, e)
    run_cmd('systemctl restart dnsmasq')
    st, _, _ = run_cmd('systemctl is-active dnsmasq')
    audit('info', 'dnsmasq отвязан от %s (%s)' % (iface, DNSMASQ_FIX_FILE))
    if st.strip() != 'active':
        return False, 'dnsmasq не поднялся после правки — смотрите journalctl -u dnsmasq'
    return True, ''


# --- минимальный DNS-клиент ---------------------------------------------------
# dnspython на серверах нет, а dig есть не везде. Нужно немного: отправить
# запрос, разобрать заголовок и записи (NS, A, SOA) со сжатием имён.

def _enc_name(name):
    out = b''
    for label in name.strip('.').split('.'):
        if label:
            out += bytes([len(label)]) + label.encode('ascii', 'ignore')
    return out + b'\x00'


def _dec_name(msg, off, depth=0):
    labels, jumped, end = [], False, off
    while depth < 20:
        if off >= len(msg):
            raise ValueError('обрезанное имя')
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode('ascii', 'replace'))
        off += 1 + ln
    return '.'.join(labels).lower(), (end if jumped else off)


def _parse_rr(msg, off):
    name, off = _dec_name(msg, off)
    rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', msg[off:off + 10])
    off += 10
    rdata = msg[off:off + rdlen]
    val = None
    if rtype == TYPE_A and rdlen == 4:
        val = '.'.join(str(b) for b in rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        val, _ = _dec_name(msg, off)
    elif rtype == TYPE_SOA:
        val, _ = _dec_name(msg, off)          # MNAME; сам владелец записи — name
    return {'name': name, 'type': rtype, 'value': val}, off + rdlen


def dns_query(server, name, qtype, rd=True, timeout=2.0, port=53):
    """{'rcode', 'aa', 'answer', 'authority', 'additional'} либо {'error'}."""
    qid = random.randint(0, 0xFFFF)
    flags = 0x0100 if rd else 0x0000
    pkt = struct.pack('!HHHHHH', qid, flags, 1, 0, 0, 0) + _enc_name(name) + struct.pack('!HH', qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, port))
        deadline = time.time() + timeout
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack('!H', data[:2])[0] == qid:
                break
            if time.time() > deadline:
                raise socket.timeout()
    except socket.timeout:
        return {'error': 'нет ответа за %.0f с' % timeout}
    except OSError as e:
        return {'error': str(e)}
    finally:
        sock.close()
    try:
        _, fl, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
        off = 12
        for _ in range(qd):
            _, off = _dec_name(data, off)
            off += 4
        sections = []
        for count in (an, ns, ar):
            items = []
            for _ in range(count):
                rr, off = _parse_rr(data, off)
                items.append(rr)
            sections.append(items)
        return {'rcode': fl & 0x0F, 'aa': bool(fl & 0x0400), 'tc': bool(fl & 0x0200),
                'answer': sections[0], 'authority': sections[1], 'additional': sections[2]}
    except Exception as e:
        return {'error': 'не разобрал ответ: %s' % e}


RCODES = {0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}


def _lookup(name, qtype):
    """Рекурсивный запрос через публичный резолвер (с запасным)."""
    last = {'error': 'нет резолверов'}
    for r in LOOKUP_RESOLVERS:
        res = dns_query(r, name, qtype)
        if 'error' not in res:
            return res
        last = res
    return last


def resolve_a(name):
    res = _lookup(name, TYPE_A)
    if 'error' in res:
        return [], res['error']
    ips = [rr['value'] for rr in res['answer'] if rr['type'] == TYPE_A and rr['value']]
    if not ips:
        return [], ('имя не существует' if res.get('rcode') == 3 else 'у имени нет A-записи')
    return ips, ''


def zone_apex(name):
    """Вершина зоны, в которой живёт имя: владелец SOA из ответа или из
    authority. Нужна, чтобы спросить родительские NS про делегирование."""
    name = name.strip('.').lower()
    for _ in range(6):
        if name.count('.') < 1:
            return ''
        res = _lookup(name, TYPE_SOA)
        if 'error' in res:
            return ''
        for rr in res['answer'] + res['authority']:
            if rr['type'] == TYPE_SOA:
                return rr['name']
        name = name.split('.', 1)[1]
    return ''


def _rand_label(n=12):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# --- диагностика делегирования ------------------------------------------------

def zone_info(apex):
    """Авторитетные серверы зоны: имена, по одному IP на каждый и признак
    Cloudflare — у него свои правила (прокси-облако), у остальных их нет."""
    res = _lookup(apex, TYPE_NS) if apex else {}
    names = [rr['value'] for rr in res.get('answer', []) if rr['type'] == TYPE_NS]
    servers = []
    for n in names[:3]:
        ips, _ = resolve_a(n)
        if ips:
            servers.append((n, ips[0]))
    return {'apex': apex, 'ns': names, 'servers': servers,
            'cloudflare': any(n.endswith('.ns.cloudflare.com') for n in names)}


def delegation(dom, zinfo):
    """Что про имя знает сама зона (не кеш резолверов — свежая запись видна сразу).

    state: delegated (to — куда), absent (имени нет), taken (имя занято
    обычной записью или шаблоном *), unknown (серверы зоны не ответили).
    """
    for nsn, ip in (zinfo or {}).get('servers') or []:
        ref = dns_query(ip, dom, TYPE_NS, rd=False, timeout=2.0)
        if 'error' in ref:
            continue
        got = [rr['value'] for rr in ref['answer'] + ref['authority']
               if rr['type'] == TYPE_NS and rr['name'] == dom]
        if got:
            return {'state': 'delegated', 'to': got, 'via': nsn}
        if ref.get('rcode') == 3:
            return {'state': 'absent', 'via': nsn}
        if ref.get('rcode') == 0 and (ref['answer'] or any(
                rr['type'] == TYPE_SOA for rr in ref['authority'])):
            return {'state': 'taken', 'via': nsn}
        return {'state': 'unknown', 'via': nsn,
                'rcode': RCODES.get(ref.get('rcode'), ref.get('rcode'))}
    return {'state': 'unknown', 'via': ''}


def a_state(host):
    """A-запись NS-хоста: ok (смотрит на сервер), wrong (на чужой IP), missing."""
    pub = public_ip()
    ips, err = resolve_a(host)
    if not ips:
        return {'state': 'missing', 'ips': [], 'error': err}
    return {'state': 'ok' if (pub and pub in ips) else 'wrong', 'ips': ips}


def suggest(settings=None):
    """Что подставить в поля, пока человек ничего не ввёл. Не придумываем
    записи, а смотрим, что уже есть в DNS: NS-хостом берём имя, которое УЖЕ
    указывает на этот сервер (домен панели, сам домен, ns.*), — тогда создавать
    нужно одну NS-запись. Поддомен — первое свободное имя или уже наше."""
    base = (DEPS.get('panel_domain') or (lambda: ''))() or ''
    out = {'domain': '', 'ns_host': '', 'apex': '', 'base': base, 'ns_a_ok': False, 'cloudflare': False}
    if not base or re.match(r'^\d+\.\d+\.\d+\.\d+$', base):
        return out
    apex = zone_apex(base)
    out['apex'] = apex
    if not apex:
        return out
    zinfo = zone_info(apex)
    out['cloudflare'] = zinfo['cloudflare']
    out['ns_host'] = 'ns.%s' % apex
    for cand in (base, apex, 'ns.%s' % apex):
        if a_state(cand)['state'] == 'ok':
            out['ns_host'], out['ns_a_ok'] = cand, True
            break
    out['domain'] = 't.%s' % apex
    for label in ('t', 'tun', 'x', 'dns1', 'tn'):
        cand = '%s.%s' % (label, apex)
        d = delegation(cand, zinfo)
        if d['state'] == 'absent' or (d['state'] == 'delegated' and out['ns_host'] in d['to']):
            out['domain'] = cand
            break
    return out


def records_for(settings):
    """Какие записи должны быть в DNS у регистратора — для показа и для сверки."""
    dom = settings.get('domain') or ''
    ns_host = (settings.get('ns_host') or '').strip().lower().rstrip('.')
    pub = public_ip()
    recs = []
    if dom and ns_host:
        recs.append({'name': dom, 'type': 'NS', 'value': ns_host})
        recs.append({'name': ns_host, 'type': 'A', 'value': pub or '<IP сервера>'})
    return recs


def check(settings=None):
    """Полная проверка цепочки. Каждый шаг — {id, ok, title, detail}.
    ok: True/False/None (None — не проверялось, потому что раньше оборвалось).
    plan — что из записей уже есть, а что добавить или исправить: UI показывает
    человеку только недостающее."""
    settings = settings or read_settings()
    dom = normalize_domain(settings.get('domain'))
    ns_host = (settings.get('ns_host') or '').strip().lower().rstrip('.')
    pub = public_ip()
    listen = listen_ip()
    steps = []

    def add(sid, ok, title, detail=''):
        steps.append({'id': sid, 'ok': ok, 'title': title, 'detail': detail})

    if not valid_domain(dom):
        add('domain', False, 'Поддомен туннеля не задан',
            'Нужен поддомен вашего домена, например t.example.com.')
        return {'ts': time.time(), 'domain': dom, 'steps': steps, 'ok': False}

    parent = dom.split('.', 1)[1]
    apex = zone_apex(parent)
    zinfo = zone_info(apex) if apex else {'apex': '', 'ns': [], 'servers': [], 'cloudflare': False}
    cf = zinfo['cloudflare']
    plan = {'apex': apex, 'cloudflare': cf, 'zone_ns': zinfo['ns'], 'public_ip': pub,
            'domain': dom, 'ns_host': ns_host, 'a': {}, 'ns': {}}

    # 1. Сам вход: спрашиваем свой адрес напрямую, без резолверов. Тип NS ядро
    # не обслуживает, и отвечает «пусто, но я авторитетен» — значит, XDNS жив
    # и знает этот домен.
    on = enabled()
    if on:
        r = dns_query(listen or '127.0.0.1', '%s.%s' % (_rand_label(), dom), TYPE_NS, rd=False, timeout=1.5)
        if 'error' in r:
            add('local', False, 'XDNS на сервере не отвечает',
                'Запрос на %s:53 остался без ответа (%s). XRay не поднял вход — смотрите журнал XRay.'
                % (listen, r['error']))
        elif r.get('aa') and r.get('rcode') == 0:
            add('local', True, 'XDNS на сервере отвечает', 'Вход XRay слушает %s:53/udp и обслуживает %s.' % (listen, dom))
        else:
            add('local', False, 'На 53-м порту отвечает кто-то другой',
                'Ответ %s без признака авторитетности — это не XDNS.' % RCODES.get(r.get('rcode'), r.get('rcode')))
    else:
        add('local', None, 'Вход XDNS выключен', 'Включите его — тогда проверится и сам сервер.')

    # 2. NS-хост и его A-запись.
    if ns_host:
        if ns_host == dom or ns_host.endswith('.' + dom):
            plan['a'] = {'state': 'inside'}
            add('ns_a', False, 'Имя сервера лежит внутри туннельного поддомена',
                '%s лежит внутри %s — так нельзя: резолвер не сможет узнать его адрес. '
                'Возьмите имя вне туннеля, например ns.%s.' % (ns_host, dom, parent))
        else:
            st = a_state(ns_host)
            plan['a'] = st
            if st['state'] == 'missing':
                add('ns_a', False, 'У %s нет A-записи' % ns_host,
                    'Нужна A-запись %s → %s.' % (ns_host, pub or 'IP сервера'))
            elif st['state'] == 'ok':
                add('ns_a', True, '%s указывает на этот сервер' % ns_host, 'A → %s' % ', '.join(st['ips']))
            else:
                add('ns_a', False, '%s указывает не на этот сервер' % ns_host,
                    'A → %s, а IP сервера %s.' % (', '.join(st['ips']), pub or '?') +
                    (' Домен на Cloudflare: у этой записи облако должно быть серым (DNS only) — с оранжевым '
                     'вместо сервера отвечает Cloudflare.' if cf else ''))

    # 3. Делегирование: спрашиваем авторитетные серверы зоны напрямую, без кеша
    # резолверов, — так видно запись сразу после добавления.
    delegated_to = []
    if not apex:
        plan['ns'] = {'state': 'unknown'}
        add('ns', False, 'Не удалось найти зону домена %s' % parent,
            'Публичные резолверы не знают такой зоны — проверьте, что домен существует.')
    else:
        d = delegation(dom, zinfo)
        plan['ns'] = d
        if d['state'] == 'delegated':
            delegated_to = d['to']
            good = (not ns_host) or ns_host in d['to']
            if not good:
                d['state'] = 'elsewhere'
            add('ns', good,
                'NS-запись %s есть' % dom if good else 'NS-запись %s смотрит не туда' % dom,
                ('Делегирован на %s (по данным %s).' % (', '.join(d['to']), d['via'])) +
                ('' if good else ' Ожидался %s — поправьте NS-запись или поле «Имя этого сервера».' % ns_host))
        elif d['state'] == 'absent':
            add('ns', False, 'NS-записи для %s нет' % dom,
                'Нужна NS-запись %s → %s.' % (dom, ns_host or 'имя этого сервера'))
        elif d['state'] == 'taken':
            add('ns', False, 'Имя %s уже занято другой записью' % dom,
                'В зоне %s для этого имени заведена обычная запись (A/CNAME) или работает шаблон *. '
                'Удалите её или возьмите другой поддомен.' % apex)
        else:
            add('ns', None, 'Серверы зоны %s не ответили' % apex,
                'Повторите проверку позже.')

    # 4. Сквозной путь через публичные резолверы — ровно так пойдут клиенты.
    results = {}

    def probe(ip, title):
        q = '%s.%s' % (_rand_label(), dom)
        results[ip] = (title, dns_query(ip, q, TYPE_TXT, rd=True, timeout=3.0))

    threads = [threading.Thread(target=probe, args=(ip, t)) for ip, t in CHECK_RESOLVERS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(4)
    passed = 0
    for ip, title in CHECK_RESOLVERS:
        title, r = results.get(ip, (title, {'error': 'нет ответа'}))
        if not on and r.get('rcode') != 0 and r.get('rcode') != 3:
            # Вход выключен — отвечать резолверу на сервере некому, SERVFAIL и
            # таймаут тут ожидаемы и ошибкой не являются.
            add('e2e_' + ip, None, 'Через %s (%s): сервер пока молчит' % (title, ip),
                'Так и должно быть, пока вход XDNS выключен: резолвер дошёл до сервера, '
                'но на 53/udp ещё никто не слушает.')
        elif 'error' in r:
            add('e2e_' + ip, False, 'Через %s (%s): нет ответа' % (title, ip),
                'Резолвер не ответил: %s.' % r['error'])
        elif r.get('rcode') == 0:
            passed += 1
            add('e2e_' + ip, True, 'Через %s (%s): доходит до сервера' % (title, ip), '')
        elif r.get('rcode') == 3:
            add('e2e_' + ip, False, 'Через %s (%s): домена не существует' % (title, ip),
                'Резолвер не видит делегирования. Если NS-запись только что добавлена — '
                'подождите: резолверы помнят старый ответ до часа.')
        else:
            add('e2e_' + ip, False, 'Через %s (%s): %s' % (title, ip, RCODES.get(r.get('rcode'), r.get('rcode'))),
                'Делегирование есть, но наш сервер резолверу не ответил: закрыт 53/udp у хостера '
                '(облачный фаервол в панели провайдера), не совпадает A-запись имени сервера '
                'или вход XDNS выключен.')
    all_ok = bool(steps) and all(s['ok'] is not False for s in steps) and passed > 0
    # DNS готов, осталось только включить вход — отдельный исход, а не «ошибки».
    ready = (not on) and bool(steps) and all(s['ok'] is not False for s in steps)
    return {'ready_to_enable': ready, 'ts': time.time(), 'domain': dom, 'ns_host': ns_host, 'delegated_to': delegated_to,
            'steps': steps, 'ok': all_ok, 'passed': passed, 'apex': apex, 'plan': plan}


# --- состояние для UI ----------------------------------------------------------

def status():
    cfg_x, err = _load_cfg()
    present = (find_idx(cfg_x) >= 0) if not err else False
    s = read_settings(cfg_x if not err else None)
    ver = core_version()
    p53 = port53_state()
    st, _, _ = run_cmd('systemctl is-active xray')
    return {
        'enabled': present,
        'xray_active': st.strip() == 'active',
        'domain': s['domain'],
        'ns_host': s.get('ns_host') or '',
        'profile': s['profile'],
        'profiles': PROFILES,
        'resolvers': s['resolvers'],
        'resolver_presets': RESOLVER_PRESETS,
        'port': PORT,
        'listen': p53['listen'],
        'public_ip': public_ip(),
        'port53': p53,
        'core_version': ver,
        'core_min': MIN_CORE,
        'core_ok': core_supported(ver),
        'records': records_for(s),
        'error': err,
    }
