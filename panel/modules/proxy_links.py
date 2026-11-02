"""Ссылки на прокси и YAML-хелперы — чистые функции, без состояния и без Flask.

Вынесено из app.py вторым шагом разбиения. Этот модуль — лист: он ничего не зовёт
из app.py и не трогает ни одного глобала, поэтому импортируется откуда угодно и не
создаёт циклов. Ради этого свойства сюда же переехал _mihomo_transport: его зовут
и построители ссылок, и код каскада, и пока он жил в app.py, между ними был цикл.

Внутри две группы:
  * разбор ссылок подписок (vless/vmess/trojan/ss/hysteria/tuic/anytls) в узлы
    clash-формата — _link_*, плюс общий для них транспорт и мелкие парсеры
    query-строки (_q, _uhost, _uport, _truthy, _alpn_list, _b64text);
  * сборка и грубый разбор clash-yaml без PyYAML — _yaml_*.

Имена оставлены как были, с подчёркиванием: app.py импортирует их по именам, и
все вызовы на местах остались нетронутыми.
"""

import base64
import json
import re
from urllib.parse import parse_qs, unquote


def _yaml_top_sections(text):
    """Грубо режет clash-yaml на секции верхнего уровня. Без PyYAML — его в
    зависимостях панели нет, а тащить ради четырёх секций не стоит.

    Возвращает dict имя → список строк, включая строку-заголовок. Верхний
    уровень clash-конфига всегда плоский, так что распознавания `^name:` без
    отступа достаточно."""
    sections = {}
    cur = None
    for raw in (text or '').replace('\r\n', '\n').split('\n'):
        if raw[:1] not in (' ', '\t', '') and re.match(r'^[A-Za-z0-9_.-]+\s*:', raw):
            cur = raw.split(':', 1)[0].strip()
            sections[cur] = [raw]
            continue
        if cur is not None:
            sections[cur].append(raw)
    return sections

def _b64text(s):
    """base64 без разбора алфавита и padding'а — ссылки в дикой природе бывают
    и url-safe, и без '='."""
    s = re.sub(r'\s+', '', s or '').replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s).decode('utf-8', errors='replace')

def _yaml_scalar(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    s = str(v)
    plain = (re.match(r'^[A-Za-z0-9_./:@+-]+$', s) and not s.isdigit()
             and s.lower() not in ('true', 'false', 'null', 'yes', 'no', 'on', 'off'))
    return s if plain else "'" + s.replace("'", "''") + "'"

def _yaml_lines(d, indent):
    out = []
    for k, v in d.items():
        if isinstance(v, dict):
            if not v:
                continue
            out.append(f'{indent}{k}:')
            out.extend(_yaml_lines(v, indent + '  '))
        elif isinstance(v, list):
            if not v:
                continue
            out.append(f'{indent}{k}: [' + ', '.join(_yaml_scalar(x) for x in v) + ']')
        elif v is None or v == '':
            continue
        else:
            out.append(f'{indent}{k}: ' + _yaml_scalar(v))
    return out

def _yaml_proxy(d):
    lines = _yaml_lines(d, '    ')
    lines[0] = '  - ' + lines[0].strip()
    return lines

def _uhost(u):
    hostport = u.netloc.rsplit('@', 1)[-1]
    return (hostport.rpartition(':')[0] or hostport).strip('[]')

def _uport(u, default=443):
    """Порт из netloc руками: у hysteria2 бывает диапазон (`:443,4000-5000`),
    на котором urlsplit().port падает."""
    tail = u.netloc.rsplit('@', 1)[-1].rpartition(':')[2]
    m = re.match(r'^\d+', tail)
    return int(m.group(0)) if m else default

def _q(qs, *keys):
    for k in keys:
        v = qs.get(k)
        if v and str(v[0]).strip():
            return str(v[0]).strip()
    return ''

def _truthy(v):
    return str(v).strip().lower() in ('1', 'true', 'yes')

def _alpn_list(qs):
    v = _q(qs, 'alpn')
    return [x.strip() for x in unquote(v).split(',') if x.strip()] if v else []

def _mihomo_transport(p, qs):
    """Сетевой транспорт (ws/grpc/h2/http) — общий кусок vless/vmess/trojan."""
    net = (_q(qs, 'type') or 'tcp').lower()
    path = unquote(_q(qs, 'path'))
    host = _q(qs, 'host')
    if net in ('ws', 'httpupgrade'):
        p['network'] = 'ws'
        opts = {}
        if path:
            opts['path'] = path
        if host:
            opts['headers'] = {'Host': host}
        if net == 'httpupgrade':
            opts['v2ray-http-upgrade'] = True
        if opts:
            p['ws-opts'] = opts
    elif net == 'grpc':
        p['network'] = 'grpc'
        sn = unquote(_q(qs, 'serviceName', 'servicename')) or path
        if sn:
            p['grpc-opts'] = {'grpc-service-name': sn}
    elif net in ('h2', 'http'):
        p['network'] = 'h2' if net == 'h2' else 'http'
        opts = {}
        if path:
            opts['path'] = path if net == 'h2' else [path]
        if host:
            opts['host'] = [h.strip() for h in host.split(',') if h.strip()]
        if opts:
            p['h2-opts' if net == 'h2' else 'http-opts'] = opts

def _link_vless(u, qs, name):
    sec = (_q(qs, 'security') or 'none').lower()
    p = {'name': name, 'type': 'vless', 'server': _uhost(u), 'port': _uport(u),
         'uuid': unquote(u.username or ''), 'udp': True}
    flow = _q(qs, 'flow')
    if flow:
        p['flow'] = flow
    if sec in ('tls', 'reality', 'xtls'):
        p['tls'] = True
    sni = _q(qs, 'sni', 'peer')
    if sni:
        p['servername'] = sni
    fp = _q(qs, 'fp')
    if fp:
        p['client-fingerprint'] = fp
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    if _truthy(_q(qs, 'allowInsecure', 'insecure', 'allow_insecure')):
        p['skip-cert-verify'] = True
    if sec == 'reality':
        p['reality-opts'] = {'public-key': _q(qs, 'pbk'), 'short-id': _q(qs, 'sid')}
    _mihomo_transport(p, qs)
    return p

def _link_vmess(raw, fallback):
    body = raw.split('://', 1)[1]
    frag = ''
    if '#' in body:
        body, frag = body.split('#', 1)
    j = json.loads(_b64text(body))
    p = {'name': (str(j.get('ps') or '').strip() or unquote(frag).strip() or fallback),
         'type': 'vmess', 'server': str(j.get('add') or ''),
         'port': int(re.sub(r'\D', '', str(j.get('port') or '')) or 443),
         'uuid': str(j.get('id') or ''),
         'alterId': int(re.sub(r'\D', '', str(j.get('aid') or '')) or 0),
         'cipher': str(j.get('scy') or 'auto'), 'udp': True}
    if str(j.get('tls') or '').lower() in ('tls', 'reality', 'true', '1'):
        p['tls'] = True
    if j.get('sni'):
        p['servername'] = str(j['sni'])
    if j.get('fp'):
        p['client-fingerprint'] = str(j['fp'])
    al = [x.strip() for x in str(j.get('alpn') or '').split(',') if x.strip()]
    if al:
        p['alpn'] = al
    _mihomo_transport(p, {'type': [str(j.get('net') or 'tcp')],
                          'path': [str(j.get('path') or '')],
                          'host': [str(j.get('host') or '')]})
    return p

def _link_trojan(u, qs, name):
    p = {'name': name, 'type': 'trojan', 'server': _uhost(u), 'port': _uport(u),
         'password': unquote(u.username or ''), 'udp': True}
    sni = _q(qs, 'sni', 'peer')
    if sni:
        p['sni'] = sni
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    fp = _q(qs, 'fp')
    if fp:
        p['client-fingerprint'] = fp
    if _truthy(_q(qs, 'allowInsecure', 'insecure', 'allow_insecure')):
        p['skip-cert-verify'] = True
    _mihomo_transport(p, qs)
    return p

def _link_ss(raw, fallback):
    body = raw.split('://', 1)[1]
    frag = ''
    if '#' in body:
        body, frag = body.split('#', 1)
    query = ''
    if '?' in body:
        body, query = body.split('?', 1)
    if '@' in body:
        userinfo, hostport = body.rsplit('@', 1)
        try:
            userinfo = _b64text(userinfo)
        except Exception:
            userinfo = unquote(userinfo)
    else:
        # legacy-форма: base64 целиком, включая адрес
        userinfo, _, hostport = _b64text(body).rpartition('@')
    method, _, password = userinfo.partition(':')
    host, _, port = hostport.rpartition(':')
    p = {'name': unquote(frag).strip() or fallback, 'type': 'ss',
         'server': (host or hostport).strip('[]'),
         'port': int(re.sub(r'\D', '', port) or 8388),
         'cipher': method.strip() or 'aes-256-gcm', 'password': password, 'udp': True}
    plugin = unquote(parse_qs(query).get('plugin', [''])[0])
    if plugin:
        parts = plugin.split(';')
        opts = dict(x.split('=', 1) for x in parts[1:] if '=' in x)
        flags = set(x for x in parts[1:] if '=' not in x)
        if 'obfs' in parts[0]:
            p['plugin'] = 'obfs'
            p['plugin-opts'] = {'mode': opts.get('obfs', 'http'),
                                'host': opts.get('obfs-host', '')}
        elif 'v2ray' in parts[0]:
            p['plugin'] = 'v2ray-plugin'
            p['plugin-opts'] = {'mode': opts.get('mode', 'websocket'),
                                'host': opts.get('host', ''),
                                'path': opts.get('path', ''),
                                'tls': 'tls' in flags}
    return p

def _link_hy2(u, qs, name):
    p = {'name': name, 'type': 'hysteria2', 'server': _uhost(u), 'port': _uport(u),
         'password': unquote(u.username or '') or _q(qs, 'auth', 'password')}
    sni = _q(qs, 'sni', 'peer')
    if sni:
        p['sni'] = sni
    if _truthy(_q(qs, 'insecure', 'allowInsecure', 'allow_insecure')):
        p['skip-cert-verify'] = True
    obfs = _q(qs, 'obfs')
    if obfs:
        p['obfs'] = obfs
        op = _q(qs, 'obfs-password', 'obfs_password')
        if op:
            p['obfs-password'] = op
    # port hopping: диапазон бывает и параметром, и прямо в адресе (`:443,4000-5000`)
    tail = u.netloc.rsplit('@', 1)[-1].rpartition(':')[2]
    mp = _q(qs, 'mport', 'ports') or (tail if re.search(r'[,-]', tail) else '')
    if mp:
        p['ports'] = mp
    up, down = _q(qs, 'up', 'upmbps'), _q(qs, 'down', 'downmbps')
    if up:
        p['up'] = up
    if down:
        p['down'] = down
    pin = _q(qs, 'pinSHA256', 'pinsha256')
    if pin:
        p['fingerprint'] = pin.replace('sha256/', '')
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    return p

def _link_hy1(u, qs, name):
    p = {'name': name, 'type': 'hysteria', 'server': _uhost(u), 'port': _uport(u),
         'protocol': _q(qs, 'protocol') or 'udp',
         'up': _q(qs, 'upmbps', 'up') or '50',
         'down': _q(qs, 'downmbps', 'down') or '100'}
    auth = _q(qs, 'auth', 'auth-str', 'auth_str') or unquote(u.username or '')
    if auth:
        p['auth-str'] = auth
    sni = _q(qs, 'peer', 'sni')
    if sni:
        p['sni'] = sni
    obfs = _q(qs, 'obfs')
    if obfs:
        p['obfs'] = _q(qs, 'obfsParam', 'obfs-password') or obfs
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    if _truthy(_q(qs, 'insecure', 'allowInsecure', 'allow_insecure')):
        p['skip-cert-verify'] = True
    return p

def _link_tuic(u, qs, name):
    p = {'name': name, 'type': 'tuic', 'server': _uhost(u), 'port': _uport(u), 'udp': True}
    user, pwd = unquote(u.username or ''), unquote(u.password or '')
    if pwd:
        p['uuid'] = user
        p['password'] = pwd
    else:
        p['token'] = user
    sni = _q(qs, 'sni', 'peer')
    if sni:
        p['sni'] = sni
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    p['congestion-controller'] = _q(qs, 'congestion_control', 'congestion-controller') or 'bbr'
    p['udp-relay-mode'] = _q(qs, 'udp_relay_mode', 'udp-relay-mode') or 'native'
    if _truthy(_q(qs, 'allow_insecure', 'insecure', 'allowInsecure')):
        p['skip-cert-verify'] = True
    return p

def _link_anytls(u, qs, name):
    p = {'name': name, 'type': 'anytls', 'server': _uhost(u), 'port': _uport(u),
         'password': unquote(u.username or '') or _q(qs, 'password'), 'udp': True}
    sni = _q(qs, 'sni', 'peer')
    if sni:
        p['sni'] = sni
    al = _alpn_list(qs)
    if al:
        p['alpn'] = al
    if _truthy(_q(qs, 'insecure', 'allowInsecure', 'allow_insecure')):
        p['skip-cert-verify'] = True
    return p
