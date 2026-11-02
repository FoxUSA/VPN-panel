"""Клиентские профили и подписки: сборка конфигов и раздача по ссылке.

Здесь клиент превращается в файл для Shadowrocket, Loon или Clash: выбор узлов
и правил под режим клиента, DNS-секция, имя файла и токен-ссылка, публичные
роуты /sub /conf /clash /loon (резолв идёт ПО ТОКЕНУ, имя в пути — только для
красоты) и диагностика доступности этих ссылок снаружи.

Контракт модуля — как у остальных (см. modules/__init__.py): зависимости от
app.py приезжают в init() одним словарём и ложатся в одноимённые глобалы, роуты
объявлены в Blueprint без url_prefix (URL те же), побочных эффектов на импорте
нет. Часть зависимостей — имена из modules/rules.py, которые app.py связывает у
себя: каталог правил профилям нужен, но ходить в соседний модуль напрямую
модули не должны.
"""

import base64
import datetime
import os
import re
import socket
import time

from flask import Blueprint, jsonify, request

bp = Blueprint('profiles', __name__)

# === Зависимости от app.py ==================================================
# До init() модуль умеет только импортироваться. Имена совпадают с теми, что
# были в app.py, поэтому тела функций переехали байт в байт.
_apply_panel_access_port = None
xhy = None
_client_ip = None
_dns_bootstrap_for = None
_dns_h2_form = None
_dns_needs_bootstrap = None
_find_client_by_name = None
_find_client_by_token = None
_find_le_cert = None
_global_dns_default = None
_is_private_ip = None
_norm_dns = None
_panel_port_reserved = None
_parse_friendly_path = None
_save_server_config = None
_strip_token_ext = None
_validate_safe_name = None
audit = None
build_vless_link = None
geoip_lookup = None
get_server_ip = None
get_xray_inbound_params = None
load_xray_clients = None
pick_free_port = None
run_cmd = None
save_xray_clients = None
ufw_active = None
login_required = None
_client_rule_policy_overrides = None
_country_ruleset_available = None
_country_ruleset_url = None
_lists_final_policy = None
_normalize_inline_rule_line = None
_rule_url_for_platform = None
load_rule_lists = None
SERVER_CFG = {}
XRAY_PARAMS = {}
PANEL_NGINX_LINK = ''
PANEL_NGINX_SITE = ''
PROFILE_TOKEN_URL_LEN = 0
XRAY_RULE_UPDATE_INTERVAL = 0
XRAY_GEOIP_MMDB_URL = ''
XRAY_GEOIP_ASN_MMDB_URL = ''

REQUIRED_DEPS = [
    'PANEL_NGINX_LINK',
    'PANEL_NGINX_SITE',
    'PROFILE_TOKEN_URL_LEN',
    'SERVER_CFG',
    'XRAY_PARAMS',
    'XRAY_RULE_UPDATE_INTERVAL',
    'XRAY_GEOIP_MMDB_URL',
    'XRAY_GEOIP_ASN_MMDB_URL',
    '_apply_panel_access_port',
    '_client_ip',
    '_client_rule_policy_overrides',
    '_country_ruleset_available',
    '_country_ruleset_url',
    '_dns_bootstrap_for',
    '_dns_h2_form',
    '_dns_needs_bootstrap',
    '_find_client_by_name',
    '_find_client_by_token',
    '_find_le_cert',
    '_global_dns_default',
    '_is_private_ip',
    '_lists_final_policy',
    '_norm_dns',
    '_normalize_inline_rule_line',
    '_panel_port_reserved',
    '_parse_friendly_path',
    '_rule_url_for_platform',
    '_save_server_config',
    '_strip_token_ext',
    '_validate_safe_name',
    'audit',
    'build_vless_link',
    'geoip_lookup',
    'get_server_ip',
    'get_xray_inbound_params',
    'load_rule_lists',
    'load_xray_clients',
    'login_required',
    'pick_free_port',
    'run_cmd',
    'save_xray_clients',
    'ufw_active',
    'xhy',
]


def init(deps):
    """Принять зависимости из app.py (см. REQUIRED_DEPS) в одноимённые глобалы."""
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('profiles.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    if not PROFILE_TOKEN_URL_LEN:
        raise RuntimeError('profiles.init: пустой PROFILE_TOKEN_URL_LEN — ссылки будут битыми')


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роуты объявлены раньше."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


# fake-ip ломает локальные имена: им нужен настоящий ответ (или NXDOMAIN), а не
# адрес из 198.18.0.0/16. Без фильтра отваливаются роутер/NAS по имени, captive-
# портальные пробы Windows и NTP.
CLASH_FAKE_IP_FILTER = [
    '*.lan', '*.local', '*.localdomain', '*.home.arpa', '*.localhost',
    '*.in-addr.arpa', '*.ip6.arpa',
    '+.msftconnecttest.com', '+.msftncsi.com', 'localhost.ptlogin2.qq.com',
    '+.pool.ntp.org', 'time.*.com',
    '+.stun.playstation.net', '+.srv.nintendo.net', '+.xboxlive.com',
]


def _dns_for_client(client):
    """Нормализованный DNS-объект клиента; если не задан — глобальный дефолт."""
    d = client.get('dns')
    return _norm_dns(d) if isinstance(d, dict) else _global_dns_default()


def _render_dns_loon(client):
    """Строки для [General] Loon. off → пусто: Loon оставит свой app-level DNS.
    Зашифрованный URL раскладывается по ключу под свою схему (док LoonManual):
      https:// → doh-server, h3:// → doh3-server, quic:// → doq-server."""
    d = _dns_for_client(client)
    if d['mode'] != 'set':
        return ''
    # Свитч «системный DNS» на странице DNS приложения — это не отдельная настройка,
    # а значение `system` в этом ключе; пока строки в профиле нет, импорт её не
    # трогает и свитч остаётся взведённым с прошлого раза. Пишем IP выбранного
    # резолвера (никогда `system` и никогда чужой) — свитч гаснет, а имя DoH-хоста
    # резолвится им же. Утечки нет: при настроенном шифрованном DNS Loon делает
    # ТОЛЬКО шифрованные запросы, обычные — резерв при их отказе.
    out = ''
    boot = _dns_bootstrap_for(d)
    if boot:
        out += 'dns-server = ' + ','.join(boot) + '\n'
    u = d['doh']
    if u.startswith('h3://'):
        out += 'doh3-server = ' + u + '\n'
        h2 = _dns_h2_form(u) if d['fallback'] else None
        if h2:  # Loon шлёт во все серверы параллельно → при блоке QUIC ответит h2
            out += 'doh-server = ' + h2 + '\n'
    elif u.startswith('quic://'):
        out += 'doq-server = ' + u + '\n'
    elif u.startswith('https://'):
        out += 'doh-server = ' + u + '\n'
    return out


def _render_dns_shadowrocket(client):
    """Значение для `dns-server =` в Shadowrocket. SR принимает в этой строке любую
    схему: https:// (DoH), h3:// (DoH3), quic:// (DoQ) и обычные IP.
    off → None: строку не пишем, SR остаётся на своём DNS."""
    d = _dns_for_client(client)
    if d['mode'] != 'set':
        return None
    parts = []
    if d['doh']:
        h2 = _dns_h2_form(d['doh']) if d['fallback'] else None
        # SR на https:// сам поднимает HTTP/3 где можно и откатывается на h2 —
        # поэтому при фолбэке отдаём https-форму (h3-с-откатом в одной строке).
        parts.append(h2 or d['doh'])
    else:
        # plain дописываем ТОЛЬКО когда шифрованного нет. Рядом с DoH они бы его
        # похоронили: SR опрашивает серверы строки параллельно и берёт быстрейший,
        # а UDP :53 всегда обгоняет TLS-хендшейк → запросы шли бы открытым текстом.
        # Бутстрап-ключа у SR нет: имя DoH-хоста он резолвит системным резолвером.
        parts += d['plain']
    return ','.join(parts) if parts else None


def _clash_nameserver(u):
    """URL зашифрованного DNS → синтаксис nameserver Clash.Meta.
    h3:// у Clash задаётся как https://<host>/…#h3=true; https:// и quic:// — как есть."""
    if u.startswith('h3://'):
        return 'https://' + u[len('h3://'):] + '#h3=true'
    return u


def _render_dns_clash(client):
    """Список YAML-строк блока `dns:` для Clash. off → enable:false (системный DNS)."""
    d = _dns_for_client(client)
    if d['mode'] != 'set':
        return ['dns:', '  enable: false']
    enc = []
    if d['doh']:
        enc.append(_clash_nameserver(d['doh']))     # h3://X → https://X#h3=true
        h2 = _dns_h2_form(d['doh']) if d['fallback'] else None
        if h2:  # второй сервер — plain h2; Clash опросит оба, при блоке QUIC ответит он
            enc.append(h2)
    # При заданном DoH plain-резолверы в nameserver НЕ идут: mihomo спрашивает всех
    # параллельно и берёт быстрейшего — UDP :53 всегда обгонит TLS, DoH стал бы
    # мёртвым грузом. Их место — bootstrap (default-nameserver), он используется
    # только для резолва имён самих резолверов.
    ns = enc if enc else list(d['plain'])
    if not ns:
        return ['dns:', '  enable: false']
    out = ['dns:', '  enable: true', '  ipv6: false']
    if _dns_needs_bootstrap(ns):
        # Чем резолвить имя резолвера — plain-IP его же провайдера. Пусто бывает
        # только у кастомного хоста, для которого юзер не задал plain: тогда строку
        # не пишем вовсе, чужой резолвер в конфиг не попадает.
        boot = _dns_bootstrap_for(d)
        if boot:
            out.append('  default-nameserver:')
            out += [f'    - {x}' for x in boot]
    out.append('  nameserver:')
    out += [f'    - {x}' for x in ns]
    out += ['  enhanced-mode: fake-ip', '  fake-ip-range: 198.18.0.1/16']
    out.append('  fake-ip-filter:')
    out += [f'    - "{x}"' for x in CLASH_FAKE_IP_FILTER]
    return out


# Профиль содержит UUID клиента или пароль Hysteria-инбаунда, поэтому по HTTP он не
# отдаётся: это выдача учётки открытым текстом любому, кто слушает канал.
# Осознанно включается флагом profile_links_insecure.
PROFILE_INSECURE_KEY = 'profile_links_insecure'


def _cert_info():
    """Что известно про LE-сертификат: домен, срок, ведёт ли домен на нас.

    Домен проверяется резолвом: в /etc/letsencrypt/live нередко лежит серт от
    давно переехавшего домена, и ссылка на него выглядит рабочей, а не открывается
    ни у кого."""
    cert = _find_le_cert()
    if not cert:
        return {'found': False}
    full, key, domain = cert
    info = {'found': True, 'domain': domain, 'fullchain': full, 'privkey': key,
            'days_left': None, 'resolves': '', 'points_here': None}
    out, _, rc = run_cmd(f"openssl x509 -enddate -noout -in '{full}'")
    if rc == 0 and '=' in (out or ''):
        try:
            end = datetime.datetime.strptime(out.strip().split('=', 1)[1].strip(),
                                             '%b %d %H:%M:%S %Y %Z')
            info['days_left'] = (end - datetime.datetime.utcnow()).days
        except Exception:
            pass
    try:
        socket.setdefaulttimeout(3)
        info['resolves'] = socket.gethostbyname(domain)
    except Exception:
        info['resolves'] = ''
    finally:
        socket.setdefaulttimeout(None)
    if info['resolves']:
        info['points_here'] = (info['resolves'] == get_server_ip())
    return info


def profile_public_base():
    """('https://host[:порт]' или '', причина пустоты).

    Единственный источник правды по адресу профилей — им пользуются все
    протоколы, чтобы ссылка, показанная в UI, и ссылка, зашитая в профиль
    (update-url), не разъезжались."""
    try:
        xp = get_xray_inbound_params()
    except Exception:
        xp = {}
    port = int(SERVER_CFG.get('panel_port') or 0)
    # 443 через TLS-фоллбек — первый выбор даже когда свой порт поднят: он
    # стандартный, заведомо не прикрыт фаерволом у клиента и не зависит от
    # нашего nginx-блока. Свой порт нужен там, где этого пути нет.
    if xp.get('security') == 'tls' and xp.get('sni'):
        # Порт указываем, только когда он нестандартный: XRay не обязан сидеть на
        # 443, а ссылка без порта в этом случае просто не открывается.
        xport = int(xp.get('port') or 443)
        return f"https://{xp['sni']}" + ('' if xport == 443 else f':{xport}'), ''
    if port:
        cert = _cert_info()
        if cert.get('found'):
            return f"https://{cert['domain']}:{port}", ''
        if SERVER_CFG.get(PROFILE_INSECURE_KEY):
            return f'http://{get_server_ip()}:{port}', ''
        return '', 'no_cert'
    if xp.get('security') == 'reality':
        return '', 'reality_no_port'
    return '', 'no_entrypoint'


def _profile_access_report():
    """Полный разбор: что мешает ссылкам и что панель может сделать сама."""
    try:
        xp = get_xray_inbound_params()
    except Exception:
        xp = {}
    security = xp.get('security') or ''
    port = int(SERVER_CFG.get('panel_port') or 0)
    cert = _cert_info()
    base, why = profile_public_base()
    steps = []

    # 1. вход снаружи
    if security == 'reality':
        steps.append({'key': 'entry', 'state': 'ok' if port else 'bad',
                      'title': 'Вход в панель снаружи',
                      'detail': (f'Свой порт панели :{port} — при Reality это единственный путь'
                                 if port else
                                 'На 443 Reality: он отдаёт всё постороннее на dest-сайт, '
                                 'до панели запрос не доходит. Нужен отдельный порт панели.')})
    elif security == 'tls':
        steps.append({'key': 'entry', 'state': 'ok',
                      'title': 'Вход в панель снаружи',
                      'detail': (f'TLS на 443, панель отвечает фоллбеком на {xp.get("sni") or "serverName"}'
                                 + (f'; дополнительно свой порт :{port}' if port else ''))})
    else:
        steps.append({'key': 'entry', 'state': 'ok' if port else 'warn',
                      'title': 'Вход в панель снаружи',
                      'detail': (f'Свой порт панели :{port}' if port else
                                 'XRay не настроен, отдельного порта панели тоже нет — '
                                 'снаружи панель ничем не опубликована.')})

    # 2. сертификат
    if security == 'tls' and not port:
        steps.append({'key': 'cert', 'state': 'ok', 'title': 'Сертификат',
                      'detail': f'Ссылка идёт на 443, сертификат там держит сам XRay '
                                f'({xp.get("sni") or "serverName"}).'})
    elif not cert.get('found'):
        steps.append({'key': 'cert', 'state': 'bad', 'title': 'Сертификат',
                      'detail': 'В /etc/letsencrypt/live сертификатов нет. Без него порт панели '
                                'поднимается только по HTTP, а профиль содержит пароль — '
                                'по HTTP панель его не отдаёт.'})
    else:
        d = cert.get('days_left')
        bad_domain = cert.get('points_here') is False
        state = 'bad' if bad_domain else ('warn' if (d is not None and d < 14) else 'ok')
        det = f"Домен {cert['domain']}"
        det += f", осталось {d} дн" if d is not None else ''
        if bad_domain:
            det += (f". Домен резолвится в {cert['resolves']}, а сервер — {get_server_ip()}: "
                    f"сертификат от чужого/переехавшего домена, ссылка по нему не откроется.")
        elif cert.get('points_here'):
            det += '. Домен ведёт на этот сервер.'
        elif not cert.get('resolves'):
            det += '. Домен не резолвится — проверить не удалось.'
        steps.append({'key': 'cert', 'state': state, 'title': 'Сертификат', 'detail': det})

    # 3. публикация порта: nginx-блок и ufw
    if port:
        published = os.path.exists(PANEL_NGINX_LINK)
        steps.append({'key': 'nginx', 'state': 'ok' if published else 'bad',
                      'title': 'nginx-блок панели',
                      'detail': (f'{PANEL_NGINX_SITE} на месте' if published else
                                 f'Порт :{port} записан в настройках, но блока {PANEL_NGINX_LINK} '
                                 f'нет — снаружи порт не отвечает.')})
        active, status_txt = ufw_active()
        if active:
            _open = globals().get('ufw_port_open')
            opened = _open(port, 'tcp') if _open else (f'{port}/tcp' in (status_txt or ''))
            steps.append({'key': 'ufw', 'state': 'ok' if opened else 'bad',
                          'title': 'Фаервол',
                          'detail': (f'ufw пропускает {port}/tcp' if opened else
                                     f'ufw включён, но {port}/tcp закрыт.')})
        else:
            steps.append({'key': 'ufw', 'state': 'ok', 'title': 'Фаервол',
                          'detail': 'ufw выключен — порт снаружи не блокируется.'})

    # 4. итог + что панель готова сделать сама
    fixes = []
    if base:
        steps.append({'key': 'result', 'state': 'ok', 'title': 'Ссылки на профили',
                      'detail': f'Работают, база {base}'})
    else:
        steps.append({'key': 'result', 'state': 'bad', 'title': 'Ссылки на профили',
                      'detail': 'Не выдаются — профиль можно только скопировать текстом.'})
        if why in ('reality_no_port', 'no_entrypoint', 'no_cert'):
            free, taken = pick_free_port(port or 2096, 'tcp', 'panel',
                                         extra_busy=_panel_port_reserved())
            if not port and free:
                fixes.append({
                    'action': 'enable_port', 'port': free,
                    'title': f'Включить порт панели :{free}',
                    'detail': (f'Панель поднимет свой nginx-блок на :{free}'
                               + (f' с сертификатом {cert["domain"]}' if cert.get('found')
                                  else ' (без сертификата — только HTTP)')
                               + ', откроет порт в ufw и начнёт отдавать профили по ссылке.'
                               + (f' Порт {port or 2096} занят ({taken}) — взят следующий свободный.'
                                  if taken else '')),
                    'needs_insecure': not cert.get('found'),
                })
            if port and not os.path.exists(PANEL_NGINX_LINK):
                fixes.append({
                    'action': 'enable_port', 'port': port,
                    'title': f'Опубликовать панель на :{port}',
                    'detail': f'Порт задан, но nginx-блока нет — панель поднимет его заново.',
                    'needs_insecure': not cert.get('found'),
                })
            if not cert.get('found'):
                fixes.append({
                    'action': 'allow_http',
                    'title': 'Отдавать профили по HTTP',
                    'detail': 'Без сертификата ссылка будет http:// — пароль из профиля пойдёт '
                              'открытым текстом. Годится в локальной сети или как разовая мера.',
                    'danger': True,
                })

    manual = []
    if not cert.get('found'):
        manual.append({
            'title': 'Выпустить сертификат (нужен домен, направленный на этот сервер)',
            # certonly --standalone, а не --nginx: плагин nginx дописывает
            # `listen 443 ssl` и роняет конфликт с XRay на 443.
            'cmd': f'certbot certonly --standalone -d ВАШ.ДОМЕН --agree-tos -m admin@ВАШ.ДОМЕН',
        })
    return {'ok': bool(base), 'base': base, 'reason': why, 'security': security,
            'panel_port': port, 'cert': cert, 'steps': steps, 'fixes': fixes,
            'manual': manual, 'insecure_allowed': bool(SERVER_CFG.get(PROFILE_INSECURE_KEY))}


@bp.route('/api/profile-access')
@_auth
def api_profile_access():
    return jsonify(_profile_access_report())


@bp.route('/api/profile-access/fix', methods=['POST'])
@_auth
def api_profile_access_fix():
    """Чинит прямо здесь, без похода в другие разделы."""
    data = request.get_json(force=True, silent=True) or {}
    action = (data.get('action') or '').strip()

    if action == 'allow_http':
        SERVER_CFG[PROFILE_INSECURE_KEY] = 1
        _save_server_config(SERVER_CFG)
        audit('warn', f'Профили: разрешена отдача по HTTP (from {_client_ip()})')
        return jsonify({'ok': True, **_profile_access_report()})

    if action == 'enable_port':
        try:
            port = int(data.get('port') or 0)
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'порт должен быть числом'}), 400
        if not port:
            port, _ = pick_free_port(2096, 'tcp', 'panel', extra_busy=_panel_port_reserved())
        if not port:
            return jsonify({'ok': False, 'error': 'свободный порт не нашёлся'}), 409
        cert = _cert_info()
        # Порт без серта = профиль по HTTP. Молча так не делаем: фронт обязан
        # прислать insecure=true, показав пользователю, чем это грозит.
        if not cert.get('found'):
            if not data.get('insecure'):
                return jsonify({'ok': False, 'error': 'no_cert',
                                'message': 'Сертификата нет — панель поднимется по HTTP. '
                                           'Подтвердите отдачу профилей по HTTP.'}), 409
            SERVER_CFG[PROFILE_INSECURE_KEY] = 1
        try:
            result = _apply_panel_access_port(port)
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
        SERVER_CFG['panel_port'] = port
        _save_server_config(SERVER_CFG)
        audit('warn', f'Профили: включён порт панели {port} (from {_client_ip()})')
        return jsonify({'ok': True, 'applied': result, **_profile_access_report()})

    return jsonify({'ok': False, 'error': 'неизвестное действие'}), 400


def _client_selected_ids(client):
    rl = client.get('rule_lists') or {}
    if isinstance(rl, dict):
        ids = rl.get('lists')
        if ids is None:
            ids = list(dict.fromkeys((rl.get('shadowrocket') or []) + (rl.get('loon') or []) + (rl.get('clash') or [])))
        return [str(i) for i in (ids or [])]
    if isinstance(rl, list):
        return [str(i) for i in rl]
    return []


def _client_proxy_name(client):
    return re.sub(r'\s+', '-', client.get('name') or 'PROXY') or 'PROXY'


def _client_selected_for(platform, client):
    """Выбранные клиентом записи единого каталога 'lists', с URL, приведённым к
    формату запрашиваемой платформы. platform тут — формат вывода (shadowrocket/
    loon/clash), а не отдельное хранилище.

    Единственная воронка, через которую записи каталога попадают в билдеры
    профилей, поэтому персональные политики (rule_policy) подменяются здесь —
    дальше по коду разницы между каталожной и персональной политикой нет."""
    rl = client.get('rule_lists') or {}
    if isinstance(rl, dict):
        ids = rl.get('lists')
        if ids is None:  # back-compat: старое per-platform хранилище → объединяем
            ids = list(dict.fromkeys(
                (rl.get('shadowrocket') or []) + (rl.get('loon') or []) + (rl.get('clash') or [])))
    elif isinstance(rl, list):
        ids = rl
    else:
        ids = []
    # Приоритет правил в конфиге = порядок каталога 'lists' (управляется нумерацией
    # в менеджере списков), а НЕ порядок, в котором клиент их выбирал. Так «поднять
    # правило вверх» в каталоге делает его первым в конфиге у всех клиентов.
    sel = {str(i) for i in ids}
    overrides = _client_rule_policy_overrides(client)
    out = []
    for e in load_rule_lists().get('lists', []):
        if str(e['id']) not in sel:
            continue
        e = dict(e)
        if str(e['id']) in overrides:
            e['policy'] = overrides[str(e['id'])]
        if e.get('url'):
            e['url'] = _rule_url_for_platform(e['url'], platform)
        out.append(e)
    return out


def _selected_for_mode(selected, geo_mode):
    """Какие из выбранных правил вообще попадают в конфиг при данном geo_mode.
    Порядок каталога сохраняется — он задаёт приоритет.

    geo_mode — это выбор СТРАТЕГИИ маршрутизации: по спискам / по странам /
    напрямую / всё через VPN. Правило с политикой VPN — часть стратегии «по
    спискам», поэтому в других режимах его быть не должно: клиент, выбравший
    страны, не просил ещё и маршрутизацию по спискам.

    А Block и Direct — не маршрутизация. Резать телеметрию и пускать домен мимо
    VPN нужно одинаково при любом режиме, иначе ad-block молча исчезал бы у всех,
    кто не в режиме 'lists' (так и было, пока список вставлялся инлайном в обход
    каталога).
    """
    if geo_mode == 'lists':
        return selected
    return [e for e in selected if (e.get('policy') or 'proxy') in ('direct', 'reject')]


def _entry_policy(entry, group_name):
    """Политика записи каталога → токен для конфига клиента.

    Токены DIRECT/REJECT одинаковы у Shadowrocket, Loon и Clash, поэтому
    хелпер один на все три билдера. Пустое/неизвестное значение → 'proxy',
    то есть прежнее поведение (всё в группу прокси) — старые записи каталога
    поля не имеют и продолжают работать как работали.
    """
    p = (entry.get('policy') or 'proxy')
    p = p.strip().lower() if isinstance(p, str) else 'proxy'
    if p == 'reject':
        return 'REJECT'
    if p == 'direct':
        return 'DIRECT'
    return group_name


def _hy_node_name(proxy_name):
    """Имя узла Hysteria в профиле: видно, что это второй способ подключения
    того же клиента, а не другой сервер."""
    return f'{proxy_name}_HY2'


def _hy_profile_node(client, kind, proxy_name):
    """Узел Hysteria для клиентского профиля или пусто, если инбаунд выключен.

    Оба протокола ведут к одному клиенту на одном сервере, поэтому лежат в
    профиле рядом и выбираются одной группой: VLESS по TCP, Hysteria по UDP —
    душат одно, человек переключается в приложении, новый конфиг не нужен.
    """
    empty = [] if kind == 'clash' else ''
    if not xhy or not xhy.enabled():
        return empty
    try:
        if not xhy.client_password(client):
            return empty
        name = _hy_node_name(proxy_name)
        if kind == 'sr':
            return xhy.sr_node(client, name)
        if kind == 'loon':
            return xhy.loon_node(client, name)
        if kind == 'clash':
            body = xhy.clash_lines(client)
            return ([f'  - name: "{name}"'] + body) if body else []
    except Exception as e:
        audit('warn', f'[Hysteria] узел для профиля не собрался: {e}')
    return empty



def _is_domain_set_url(url):
    """Список из одних доменов (blackmatrix7 `<Имя>_Domain.yaml|.list|.txt`).

    Такой файл подключается не как обычный набор правил: у Clash —
    `behavior: domain` (строки вида `+.example.com`; при `classical` движок
    отвергает их все, и список молча пустеет), у Shadowrocket — `DOMAIN-SET`
    вместо `RULE-SET`. Так велит README самого bm7."""
    return bool(re.search(r'_Domain\.(?:yaml|list|txt)(?:[?#].*)?$', url or ''))


def build_shadowrocket_profile(client, proxy_line=None, update_url_override=None):
    """
    Shadowrocket .conf. RULE-SET с force-remote-dns, поддерживает update-url
    и update-interval в [General]. Без geoip-maxmind-* (Shadowrocket их
    не подхватывает).

    proxy_line — готовая строка узла другого протокола, как
    в build_loon_profile. update_url_override — свой адрес автообновления
    профиля: у него публичные URL могут жить под своим префиксом.
    """
    p = XRAY_PARAMS
    name = client.get('name') or 'PROXY'
    proxy_name = _client_proxy_name(client)
    client_uuid = client.get('uuid') or ''
    token = client.get('token') or ''
    geo_mode = (client.get('geo_mode') or 'off').strip()
    geo_countries = [c.upper() for c in (client.get('geo_countries') or []) if isinstance(c, str)]
    # В режиме 'lists' — все выбранные правила; в остальных только Block/Direct.
    selected = _selected_for_mode(_client_selected_for('shadowrocket', client), geo_mode)

    _sr_xp = get_xray_inbound_params()
    # update-url (авто-обновление правил с панели) работает только в TLS-режиме:
    # sni = домен сертификата = адрес панели. При Reality sni — чужой dest-сайт
    # (cloudflare), панель там не отвечает → битый URL не отдаём.
    update_url = (f"https://{_sr_xp['sni']}/conf/{_profile_url_seg(name, token)}.conf"
                  if token and _sr_xp['security'] == 'tls' else '')
    if update_url_override is not None:
        update_url = update_url_override

    # DNS — из per-client настройки (_render_dns_shadowrocket). off → строку не пишем.
    general = "[General]\n"
    _sr_dns = _render_dns_shadowrocket(client)
    if _sr_dns:
        general += f"dns-server = {_sr_dns}\n"
    general += f"update-interval = {XRAY_RULE_UPDATE_INTERVAL}\n"
    if update_url:
        general += f"update-url = {update_url}\n"
    general += "\n"

    xp = _sr_xp
    sr_opts = f"username={client_uuid}, tls=true, sni={xp['sni']}"
    if xp['flow']:
        sr_opts += f", flow={xp['flow']}"
    if xp['security'] == 'reality':
        sr_opts += f", public-key={xp['public_key']}, short-id={xp['short_id']}"
    proxy_block = (
        "[Proxy]\n" + (
            (proxy_line.strip() + "\n") if proxy_line else
            f"{proxy_name} = vless, {get_server_ip()}, {xp['port']}, {sr_opts}\n"
        ) + "\n"
    )

    # Второй узел того же клиента: Hysteria по UDP рядом с VLESS по TCP.
    # Душат одно — человек переключается в приложении, новый конфиг не нужен.
    _hy_line = _hy_profile_node(client, 'sr', proxy_name)
    if _hy_line and not proxy_line:
        proxy_block = proxy_block.rstrip("\n") + "\n" + _hy_line + "\n\n"

    group_name = f"{proxy_name}_group"
    group_block = (
        "[Proxy Group]\n"
        f"{group_name} = select, {proxy_name}"
        + (f", {_hy_node_name(proxy_name)}" if _hy_line and not proxy_line else "")
        + ", DIRECT\n"
        "\n"
    )

    rules = "[Rule]\n"
    # Правила каталога: в 'lists' все, иначе только Block/Direct. Идут первыми и в
    # порядке каталога — он и есть приоритет.
    for r in selected:
        if r.get('url'):
            kind = 'DOMAIN-SET' if _is_domain_set_url(r['url']) else 'RULE-SET'
            rules += (
                f"{kind},{r['url']},{_entry_policy(r, group_name)},"
                f"force-remote-dns,update-interval={XRAY_RULE_UPDATE_INTERVAL}\n"
            )
        elif r.get('rules'):
            for raw in r['rules']:
                norm = _normalize_inline_rule_line(raw)
                if norm:
                    rules += f"{norm},{_entry_policy(r, group_name)}\n"
    if geo_mode == 'lists':
        rules += f"FINAL,{_lists_final_policy(client, group_name)}\n"
    elif geo_mode == 'via' and geo_countries:
        # выбранные страны → через VPN, остальное → direct. Диапазоны — RULE-SET панели
        # (countries.zip → CIDR); если справочника ещё нет, мягкий фолбэк на GEOIP.
        for cc in geo_countries:
            if _country_ruleset_available(cc):
                rules += (f"RULE-SET,{_country_ruleset_url(cc, 'list')},{group_name},"
                          f"update-interval={XRAY_RULE_UPDATE_INTERVAL}\n")
            else:
                rules += f"GEOIP,{cc},{group_name}\n"
        rules += "FINAL,DIRECT\n"
    elif geo_mode == 'direct' and geo_countries:
        # выбранные страны → direct (мимо VPN), остальное → через VPN.
        for cc in geo_countries:
            if _country_ruleset_available(cc):
                rules += (f"RULE-SET,{_country_ruleset_url(cc, 'list')},DIRECT,"
                          f"update-interval={XRAY_RULE_UPDATE_INTERVAL}\n")
            else:
                rules += f"GEOIP,{cc},DIRECT\n"
        rules += f"FINAL,{group_name}\n"
    else:
        rules += f"FINAL,{group_name}\n"

    return general + proxy_block + group_block + rules


def build_clash_profile(client, proxy_lines=None):
    """
    Clash.Meta (mihomo) YAML config. Targets Clash Verge Rev / Clash.Meta on
    Win/Mac/Linux. VLESS+TLS+Vision via the native vless proxy type.

    Format:
      proxies: — single VLESS entry
      rule-providers: — remote .yaml lists, format=yaml, behavior=classical
                        (у списков из одних доменов, *_Domain, — domain)
      rules: — RULE-SET refs + inline DOMAIN-SUFFIX/IP-CIDR + GEOIP/MATCH

    Modes (same logic as other platforms):
      - rule_lists non-empty → RULE-SET → proxy, MATCH,DIRECT
      - bypass_ru only       → GEOIP,RU,DIRECT, MATCH,proxy
      - both off             → MATCH,proxy
    """
    p = XRAY_PARAMS
    proxy_name = _client_proxy_name(client)
    client_uuid = client.get('uuid') or ''
    geo_mode = (client.get('geo_mode') or 'off').strip()
    geo_countries = [c.upper() for c in (client.get('geo_countries') or []) if isinstance(c, str)]
    # В режиме 'lists' — все выбранные правила; в остальных только Block/Direct.
    selected = _selected_for_mode(_client_selected_for('clash', client), geo_mode)

    def _slug(s):
        return re.sub(r'[^a-zA-Z0-9_-]+', '_', s or 'rule').strip('_') or 'rule'

    out = []
    out.append("mixed-port: 7890")
    out.append("mode: rule")
    out.append("log-level: info")
    out.append("ipv6: false")
    out.append("allow-lan: false")
    # Базы для GEOIP и IP-ASN (последние есть в списках bm7, например Telegram и
    # OpenAI) — с нашего зеркала. По умолчанию mihomo тянет их с GitHub, а
    # оттуда из РФ скачивание бывает закрыто: IP-правила тогда молча не
    # работают, остаются только доменные. Формат MaxMind mihomo читает как есть.
    out.append("geox-url:")
    out.append(f'  mmdb: "{XRAY_GEOIP_MMDB_URL}"')
    out.append(f'  asn: "{XRAY_GEOIP_ASN_MMDB_URL}"')
    out.append("")
    # DNS-блок — из per-client настройки (_render_dns_clash). off → dns: {enable:false}.
    out.extend(_render_dns_clash(client))
    out.append("")
    out.append("proxies:")
    out.append(f'  - name: "{proxy_name}"')
    if proxy_lines:
        # Узел другого протокола: описание прокси приходит готовым,
        # а правила/DNS/группы ниже собираются общим кодом — они одинаковы для всех.
        out.extend(proxy_lines)
        out.append("")
    else:
        xp = get_xray_inbound_params()
        out.append(f"    type: vless")
        out.append(f"    server: {get_server_ip()}")
        out.append(f"    port: {xp['port']}")
        out.append(f"    uuid: {client_uuid}")
        out.append(f"    network: tcp")
        out.append(f"    tls: true")
        out.append(f"    servername: {xp['sni']}")
        if xp['flow']:
            out.append(f"    flow: {xp['flow']}")
        out.append(f"    client-fingerprint: {xp['fingerprint']}")
        if xp['security'] == 'reality':
            out.append(f"    reality-opts:")
            out.append(f"      public-key: {xp['public_key']}")
            out.append(f"      short-id: {xp['short_id']}")
        out.append(f"    packet-encoding: xudp")
        out.append(f"    udp: true")
        out.append("")

    # Второй узел того же клиента: Hysteria по UDP рядом с VLESS по TCP.
    # Душат одно — человек переключается в приложении, новый конфиг не нужен.
    _hy_lines = _hy_profile_node(client, 'clash', proxy_name) if not proxy_lines else []
    if _hy_lines:
        out.extend(_hy_lines)
        out.append("")

    group_name = f"{proxy_name}_group"
    out.append("proxy-groups:")
    out.append(f'  - name: "{group_name}"')
    out.append(f"    type: select")
    out.append(f"    proxies:")
    out.append(f'      - "{proxy_name}"')
    if _hy_lines:
        out.append(f'      - "{_hy_node_name(proxy_name)}"')
    out.append(f"      - DIRECT")
    out.append("")

    url_entries    = [r for r in selected if r.get('url')]
    inline_entries = [r for r in selected if r.get('rules')]
    # Для режимов стран: какие страны есть в справочнике (rule-provider), а какие — фолбэк GEOIP.
    country_avail = ([cc for cc in geo_countries if _country_ruleset_available(cc)]
                     if geo_mode in ('via', 'direct') else [])
    country_fallback = ([cc for cc in geo_countries if not _country_ruleset_available(cc)]
                        if geo_mode in ('via', 'direct') else [])

    if url_entries or country_avail:
        out.append("rule-providers:")
        for r in url_entries:
            slug = _slug(r.get('id'))
            out.append(f"  {slug}:")
            out.append(f"    type: http")
            out.append(f"    behavior: {'domain' if _is_domain_set_url(r['url']) else 'classical'}")
            out.append(f"    format: yaml")
            out.append(f'    url: "{r["url"]}"')
            out.append(f"    path: ./ruleset/{slug}.yaml")
            out.append(f"    interval: {XRAY_RULE_UPDATE_INTERVAL}")
        for cc in country_avail:
            # CIDR-список страны как ipcidr-провайдер (format: text → голые CIDR построчно).
            out.append(f"  cc_{cc}:")
            out.append(f"    type: http")
            out.append(f"    behavior: ipcidr")
            out.append(f"    format: text")
            out.append(f'    url: "{_country_ruleset_url(cc, "clash")}"')
            out.append(f"    path: ./ruleset/cc_{cc}.txt")
            out.append(f"    interval: {XRAY_RULE_UPDATE_INTERVAL}")
        out.append("")

    out.append("rules:")
    # Один проход по selected, а не url_entries → inline_entries: у Clash обе
    # разновидности живут в одной секции rules:, и порядок каталога = приоритет.
    # Раздельные циклы поднимали все URL-правила над рукописными независимо от
    # нумерации в менеджере.
    for r in selected:
        if r.get('url'):
            out.append(f"  - RULE-SET,{_slug(r.get('id'))},{_entry_policy(r, group_name)}")
        elif r.get('rules'):
            for raw in r['rules']:
                norm = _normalize_inline_rule_line(raw)
                if norm:
                    out.append(f"  - {norm},{_entry_policy(r, group_name)}")
    if geo_mode == 'lists':
        out.append(f"  - MATCH,{_lists_final_policy(client, group_name)}")
    elif geo_mode == 'via' and geo_countries:
        # выбранные → через VPN, остальное → direct
        for cc in country_avail:
            out.append(f"  - RULE-SET,cc_{cc},{group_name}")
        for cc in country_fallback:
            out.append(f"  - GEOIP,{cc},{group_name}")
        out.append(f"  - MATCH,DIRECT")
    elif geo_mode == 'direct' and geo_countries:
        # выбранные → direct (мимо VPN), остальное → через VPN
        for cc in country_avail:
            out.append(f"  - RULE-SET,cc_{cc},DIRECT")
        for cc in country_fallback:
            out.append(f"  - GEOIP,{cc},DIRECT")
        out.append(f"  - MATCH,{group_name}")
    else:
        out.append(f"  - MATCH,{group_name}")

    return "\n".join(out) + "\n"


def build_loon_profile(client, proxy_line=None):
    """
    Loon .conf. У Loon — отдельная секция [Remote Rule] вместо RULE-SET-строк
    в [Rule]. В [General] поддерживаются geoip-url и ipasn-url. VLESS-формат
    отличается от Shadowrocket: позиционные IP/port, потом именованные
    transport/over-tls/sni/flow/udp.

    proxy_line — готовая строка узла для [Proxy] от другого протокола.
    Правила, DNS, группы и страны при этом собираются тем же кодом, что для XRay:
    они от протокола не зависят, и дублировать их не нужно.
    """
    p = XRAY_PARAMS
    proxy_name = _client_proxy_name(client)
    client_uuid = client.get('uuid') or ''
    geo_mode = (client.get('geo_mode') or 'off').strip()
    geo_countries = [c.upper() for c in (client.get('geo_countries') or []) if isinstance(c, str)]
    # В режиме 'lists' — все выбранные правила; в остальных только Block/Direct.
    selected = _selected_for_mode(_client_selected_for('loon', client), geo_mode)

    # geoip-url не нужен: правила по странам идут нашими rule-set'ами
    # ([Remote Rule], CIDR из countries.zip). А ipasn-url нужен: в списках bm7
    # (Telegram, OpenAI и др.) есть IP-ASN, и базу для них Loon должен качать
    # с нашего зеркала, а не с GitHub, который из РФ бывает закрыт.
    # DNS больше не хардкодим: строку(и) даёт per-client настройка (_render_dns_loon).
    # mode='off' → вообще ничего не пишем, Loon оставляет свой app-level DNS/DoH.
    general = (
        "[General]\n"
        "ipv6 = false\n"
        f"ipasn-url = {XRAY_GEOIP_ASN_MMDB_URL}\n"
    )
    general += _render_dns_loon(client)
    general += "\n"

    # Loon VLESS-синтаксис: тип VLESS заглавными; UUID — позиционный, в кавычках;
    # после него пустое поле encryption (двойная запятая); далее именованные параметры.
    # Источник: https://github.com/Loon0x00/LoonExampleConfig/blob/master/example.conf
    xp = get_xray_inbound_params()
    loon_opts = f'transport=tcp,over-tls=true,sni={xp["sni"]}'
    if xp['flow']:
        loon_opts += f',flow={xp["flow"]}'
    if xp['security'] == 'reality':
        loon_opts += f',public-key={xp["public_key"]},short-id={xp["short_id"]}'
    proxy_block = (
        "[Proxy]\n" + (
            (proxy_line.strip() + "\n") if proxy_line else
            f'{proxy_name} = VLESS,{get_server_ip()},{xp["port"]},'
            f'"{client_uuid}",,{loon_opts},udp=true\n'
        ) + "\n"
    )

    # Второй узел того же клиента: Hysteria по UDP рядом с VLESS по TCP.
    # Душат одно — человек переключается в приложении, новый конфиг не нужен.
    _hy_line = _hy_profile_node(client, 'loon', proxy_name)
    if _hy_line and not proxy_line:
        proxy_block = proxy_block.rstrip("\n") + "\n" + _hy_line + "\n\n"

    group_name = f"{proxy_name}_group"
    group_block = (
        "[Proxy Group]\n"
        f"{group_name} = select,{proxy_name}"
        + (f",{_hy_node_name(proxy_name)}" if _hy_line and not proxy_line else "")
        + ",DIRECT\n"
        "\n"
    )

    remote_rule = ""
    inline_rules = []
    remote_rule_lines = []
    country_avail = ([cc for cc in geo_countries if _country_ruleset_available(cc)]
                     if geo_mode in ('via', 'direct') else [])
    # Правила каталога. selected уже отфильтрован по режиму (_selected_for_mode):
    # в 'lists' — все, иначе только Block/Direct. Порядок = порядок каталога.
    for r in selected:
        if r.get('url'):
            tag = re.sub(r'[,\s]+', '_', (r.get('name') or r.get('id') or 'rule'))
            remote_rule_lines.append(
                f"{r['url']}, policy={_entry_policy(r, group_name)}, tag={tag}, enabled=true")
        elif r.get('rules'):
            for raw in r['rules']:
                norm = _normalize_inline_rule_line(raw)
                if norm:
                    inline_rules.append(f"{norm},{_entry_policy(r, group_name)}")
    # Страны — своя стратегия, к каталогу отношения не имеет; в режиме 'lists'
    # country_avail пуст, так что ветки не конфликтуют.
    if geo_mode in ('via', 'direct') and country_avail:
        cc_policy = group_name if geo_mode == 'via' else 'DIRECT'
        for cc in country_avail:
            remote_rule_lines.append(
                f"{_country_ruleset_url(cc, 'list')}, policy={cc_policy}, tag=cc_{cc}, enabled=true")
    if remote_rule_lines:
        remote_rule = "[Remote Rule]\n" + "\n".join(remote_rule_lines) + "\n\n"

    rules = "[Rule]\n"
    for line in inline_rules:
        rules += line + "\n"
    if geo_mode == 'lists':
        rules += f"FINAL,{_lists_final_policy(client, group_name)}\n"
    elif geo_mode == 'via' and geo_countries:
        # выбранные страны → VPN через [Remote Rule] (наши CIDR); остальное → direct.
        # Без GEOIP-фолбэка: у Loon нет geoip-url, страны без справочника просто не
        # фильтруются до его готовности (бутстрап скачивает countries.zip на старте).
        rules += "FINAL,DIRECT\n"
    elif geo_mode == 'direct' and geo_countries:
        # выбранные → direct через [Remote Rule]; остальное → VPN.
        rules += f"FINAL,{group_name}\n"
    else:
        rules += f"FINAL,{group_name}\n"

    return general + proxy_block + group_block + remote_rule + rules


def _safe_filename(name):
    """Sanitize a single name segment to [a-z0-9._-].
    Нижний регистр обязателен: сегмент уходит в публичный URL профиля, а тот по
    конвенции lowercase (см. пути панели). Заодно делает поиск клиента по имени
    регистронезависимым — 'Fox' и 'fox' резолвятся в одного."""
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', (name or 'profile').strip()) or 'profile'
    return s[:64].lower()


def _profile_filename(client_name, token=None):
    """ЧЕЛОВЕЧЕСКОЕ имя профиля: Content-Disposition и метка vless-ссылки.

    Формат `<server>-<client>` (сервер первым — так профили разных серверов
    группируются в списке подписок). Ключом резолва это имя больше НЕ является:
    публичный URL несёт токен отдельным сегментом (см. _profile_url_seg), поэтому
    переименование и клиента, и сервера ссылку не рвёт, а обрезка тут безопасна.
    Имя сервера режем до 32 — чтобы имя клиента всегда было видно целиком.
    """
    mode = SERVER_CFG.get('profile_naming') or 'friendly'
    if mode == 'token' and token:
        return token[:96]
    sn = (SERVER_CFG.get('server_name') or '').strip()
    cn = _safe_filename(client_name)
    if sn:
        sn = _validate_safe_name(sn).lower()[:32]
        return f"{sn}-{cn}"[:96]
    return cn[:96]


def _profile_url_seg(client_name, token=None):
    """Путь публичного профиля: `<token8>/<имя>` либо `<token>` в token-режиме.

    ПОРЯДОК СЕГМЕНТОВ ВАЖЕН: Loon показывает профиль под именем ПОСЛЕДНЕГО
    сегмента URL, а Content-Disposition игнорирует (проверено живым импортом —
    форма `<имя>/<token>` дала в списке профилей голый токен). Поэтому имя идёт
    последним, а укороченный токен — перед ним. Резолв всё равно по токену
    (_resolve_client перебирает сегменты), так что переименование ссылку не рвёт.
    Без токена — односегментная форма для _parse_friendly_path.
    """
    if not token:
        return _profile_filename(client_name)
    mode = SERVER_CFG.get('profile_naming') or 'friendly'
    if mode == 'token':
        return token[:96]
    return f"{token[:PROFILE_TOKEN_URL_LEN]}/{_profile_filename(client_name, None)}"


@bp.route('/sub/<path:token>', methods=['GET'])
def public_subscription(token):
    """
    Shadowrocket / v2rayN / etc. subscription endpoint.
    Returns base64 of newline-separated proxy URIs (Shadowrocket Subscribe format).
    Accepts /sub/<token>, /sub/<token>.txt, /sub/<token>.conf — all equivalent.
    """
    target = _resolve_client(token)
    if not target:
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    links = [build_vless_link(target['uuid'], target.get('name', 'PROXY'), target.get('token'))]
    # Hysteria отдаём вторым узлом. Без этого подписка молчит о втором входе:
    # приложения на sing-box (v2RayTun, Streisand, NekoBox) импортируют именно
    # этот список, узла Hysteria в нём не было — и человек «пользовался
    # Hysteria», фактически сидя на VLESS. В Shadowrocket/Loon/Clash узел был,
    # потому что у них свои форматы профиля (_hy_profile_node).
    if xhy and xhy.enabled():
        try:
            if xhy.client_password(target):
                # Имя узла — как у VLESS в этой же подписке, плюс «_HY2»: в
                # приложении узлы стоят подряд, и должно быть видно, что это
                # один сервер, а не два разных. Голое имя клиента не годится —
                # у VLESS в метке ещё и имя сервера (_profile_filename).
                vless_label = _profile_filename(target.get('name') or 'PROXY',
                                                target.get('token'))
                hy_client = dict(target, name=_hy_node_name(vless_label))
                hy_link = xhy.build_link(hy_client, uuid=target.get('uuid') or '')
                if hy_link:
                    links.append(hy_link)
        except Exception as e:
            audit('warn', f'[Hysteria] ссылка для подписки не собралась: {e}')
    body = base64.b64encode(('\n'.join(links) + '\n').encode('utf-8')).decode('ascii')
    _record_profile_fetch(target, 'sub')
    headers = {
        'Content-Type': 'text/plain; charset=utf-8',
        'subscription-userinfo': 'upload=0; download=0; total=0; expire=0',
        'Cache-Control': 'no-store'
    }
    return (body, 200, headers)


def _resolve_client(seg):
    """Lookup client: try token first, fall back to friendly-name parse.

    Путь бывает многосегментным: сейчас `<token8>/<имя>`, а до 30.07.2026 панель
    умела отдавать `<имя>/<token>`. Перебираем ВСЕ сегменты, поэтому порядок не
    важен и резолв не зависит от того, какое из правил выберет Werkzeug
    (`<path:token>` умеет съесть весь путь со слешами целиком).
    """
    segs = [s for s in (seg or '').split('/') if s]
    if not segs:
        return None
    for s in segs:
        by_tok = _find_client_by_token(_strip_token_ext(s))
        if by_tok:
            return by_tok
    for s in segs:
        by_name = _find_client_by_name(_parse_friendly_path(s))
        if by_name:
            return by_name
    return None


# Приложение по User-Agent запроса профиля/подписки. Сам VPN-трафик
# приложение не называет — узнать его можно только здесь. Порядок важен:
# «clash-verge» раньше «clash», «v2rayng» раньше «v2rayn».
_UA_APPS = (
    ('shadowrocket', 'Shadowrocket'), ('loon', 'Loon'), ('stash', 'Stash'),
    ('quantumult', 'Quantumult X'), ('surge', 'Surge'),
    ('clash-verge', 'Clash Verge'), ('clashverge', 'Clash Verge'), ('clashx', 'ClashX'),
    ('flclash', 'FlClash'), ('clashmetaforandroid', 'Clash Meta'), ('mihomo', 'Mihomo'), ('clash.meta', 'Clash Meta'), ('clash', 'Clash'),
    ('happ', 'Happ'), ('v2rayng', 'v2rayNG'), ('v2rayn', 'v2rayN'), ('v2raytun', 'v2RayTun'),
    ('streisand', 'Streisand'), ('v2box', 'V2Box'), ('onexray', 'OneXray'), ('foxray', 'FoXray'),
    ('hiddify', 'Hiddify'), ('karing', 'Karing'), ('nekobox', 'NekoBox'), ('nekoray', 'NekoRay'),
    ('sing-box', 'sing-box'), ('sfi/', 'sing-box'), ('sfa/', 'sing-box'), ('incy', 'INCY'),
)


def _app_from_ua(ua):
    low = (ua or '').lower()
    if not low:
        return ''
    for needle, name in _UA_APPS:
        if needle in low:
            return name
    if low.startswith('mozilla'):
        return 'браузер'
    # Сетевые библиотеки — не приложения: по ним не понять, кто это.
    if re.match(r'^(okhttp|dalvik|cfnetwork|curl|wget|python|go-http-client|java|axios|node)', low):
        return ''
    # Незнакомое приложение — его же имя до «/» или пробела, но не мусор.
    head = re.split(r'[/\s;(]', ua.strip(), 1)[0]
    return head[:24] if re.match(r'^[A-Za-z][\w.\-]{1,23}$', head) else ''


def _record_profile_fetch(target, platform):
    """Фиксирует дату/время/IP/гео последнего запроса профиля клиентом
    (SR/Loon/Clash тянут конфиг с панели — внутри свежие ссылки на правила).
    Best-effort: любые ошибки глотаем, отдачу конфига не ломаем."""
    try:
        uuid = (target or {}).get('uuid')
        if not uuid:
            return
        ip = _client_ip()
        if _is_private_ip(ip):
            ip = ''  # реальный IP недоступен (фолбэк без заголовков) — не показываем
        geo = (geoip_lookup(ip) or {}) if ip else {}
        clients = load_xray_clients()
        c = clients.get(uuid)
        if not c:
            return
        pf = c.get('profile_fetch')
        if not isinstance(pf, dict):
            pf = {}
        pf[platform] = {
            'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
            'app': _app_from_ua(request.headers.get('User-Agent', '')),
            'ip': ip,
            'country': geo.get('country') or '',
            'city': geo.get('city') or '',
        }
        c['profile_fetch'] = pf
        save_xray_clients(clients)
    except Exception:
        pass


# Old token-bearing URLs (kept for backward compat & 'token' mode)
@bp.route('/sub/<safename>/<path:token>', methods=['GET'])
def public_subscription_named(safename, token):
    # Оба сегмента отдаём резолверу целиком: где токен, а где имя — решает он
    # (форма менялась с `<имя>/<token>` на `<token8>/<имя>`).
    return public_subscription(f"{safename}/{token}")


@bp.route('/conf/<safename>/<path:token>', methods=['GET'])
def public_shadowrocket_config_named(safename, token):
    return public_shadowrocket_config(f"{safename}/{token}")


@bp.route('/clash/<safename>/<path:token>', methods=['GET'])
def public_clash_config_named(safename, token):
    return public_clash_config(f"{safename}/{token}")


@bp.route('/loon/<safename>/<path:token>', methods=['GET'])
def public_loon_config_named(safename, token):
    return public_loon_config(f"{safename}/{token}")


@bp.route('/conf/<path:token>', methods=['GET'])
def public_shadowrocket_config(token):
    """Shadowrocket-flavored .conf (no geoip-maxmind-* keys, Shadowrocket .list URLs)."""
    target = _resolve_client(token)
    if not target:
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    body = build_shadowrocket_profile(target)
    _record_profile_fetch(target, 'shadowrocket')
    fname = _profile_filename(target.get('name'), target.get('token'))
    return (body, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Disposition': f'inline; filename={fname}',
    })


@bp.route('/clash/<path:token>', methods=['GET'])
def public_clash_config(token):
    """Clash.Meta YAML profile."""
    target = _resolve_client(token)
    if not target:
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    body = build_clash_profile(target)
    _record_profile_fetch(target, 'clash')
    fname = _profile_filename(target.get('name'), target.get('token'))
    return (body, 200, {
        'Content-Type': 'application/x-yaml; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Disposition': f'inline; filename={fname}',
        'Profile-Update-Interval': '24',
    })


@bp.route('/loon/<path:token>', methods=['GET'])
def public_loon_config(token):
    """Loon-flavored .conf (ipasn-url, [Remote Rule], Loon .list URLs)."""
    target = _resolve_client(token)
    if not target:
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    body = build_loon_profile(target)
    _record_profile_fetch(target, 'loon')
    fname = _profile_filename(target.get('name'), target.get('token'))
    return (body, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Disposition': f'inline; filename={fname}',
    })


@bp.route('/api/xray/clients/<client_uuid>/profile-fetch')
@_auth
def xray_get_profile_fetch(client_uuid):
    """Лёгкий поллинг для живого обновления блока «Последний запрос» в окне конфига."""
    clients = load_xray_clients()
    c = clients.get(client_uuid)
    if not c:
        return jsonify({'error': 'Client not found'}), 404
    resp = jsonify({'profile_fetch': c.get('profile_fetch') or {}})
    resp.headers['Cache-Control'] = 'no-store'
    return resp
