"""Hysteria2 как инбаунд ядра XRay.

Протокол поднимает само ядро XRay (с 26.x оно умеет Hysteria2 своим инбаундом),
поэтому отдельного движка, своего хранилища и своей вкладки здесь нет: клиенты
живут в общей базе XRay, настройки — в его же config.json, правила и профили
общие. Панель управляет всем этим с карточки XRay.

Формат инбаунда сверен с исходниками Xray-core v26.9.9 и проверен парсером:
  streamSettings.network              = "hysteria"
  streamSettings.hysteriaSettings     = {version: 2, masquerade: {...}}
  streamSettings.finalmask.udp        = [{type: "salamander", settings: {password}}]
  streamSettings.finalmask.quicParams = {congestion: "brutal", brutalUp, brutalDown}
  settings                            = {version: 2, clients: [{auth, email}]}

Сертификат. Hysteria2 — это QUIC, TLS обязателен. Если у панели есть серт
Let's Encrypt (режим TLS у VLESS) — берём его. На Reality-серверах серта нет
вовсе, поэтому панель выпускает самоподписанный и отдаёт клиенту его отпечаток:
в ссылке появляются insecure=1 и pinSHA256, и клиент сверяет конкретный
сертификат. Безопасность даёт пиннинг, а не проверка цепочки.
"""

import json
import os
import re
import secrets

# Хелперы панели кладёт сюда init(). Импортировать app.py напрямую нельзя — цикл.
DEPS = {}

# Тег инбаунда: по нему модуль находит своё в чужом конфиге, по нему же routing
# и statsquery отличают трафик Hysteria от VLESS.
INBOUND_TAG = 'hysteria-in'

# Порт по умолчанию. 443/udp не конфликтует с VLESS на 443/tcp — это разные
# сокеты, — и снаружи выглядит обычным HTTP/3, а не VPN на странном порту.
DEFAULT_PORT = 443

DEFAULT_MASQUERADE = 'https://www.bing.com'

# Самоподписанный сертификат и ключ для серверов без Let's Encrypt.
SELF_CERT_NAME = 'hysteria-self-cert.pem'
SELF_KEY_NAME = 'hysteria-self-key.pem'


def init(deps):
    DEPS.update(deps or {})
    return True


def audit(level, msg):
    fn = DEPS.get('audit')
    if fn:
        try:
            return fn(level, '[Hysteria] %s' % msg)
        except Exception:
            pass


def run_cmd(cmd):
    fn = DEPS.get('run_cmd')
    return fn(cmd) if fn else ('', 'run_cmd не проброшен', 1)


def _data_dir():
    return DEPS.get('data_dir') or '.'


# --- сертификат -------------------------------------------------------------

def self_cert_paths():
    return (os.path.join(_data_dir(), SELF_CERT_NAME),
            os.path.join(_data_dir(), SELF_KEY_NAME))


_FP_CACHE = {}


def cert_fingerprint(cert_path):
    """SHA256-отпечаток в виде AB:CD:... — формат, который ждёт pinSHA256 у
    клиентов Hysteria. Пусто, если прочитать не удалось.

    Кешируем по (пути, mtime): статус инбаунда опрашивается каждые 15 секунд
    вместе с карточкой, и запускать openssl на каждый опрос незачем.
    """
    try:
        key = (cert_path, os.path.getmtime(cert_path))
    except OSError:
        return ''
    if key in _FP_CACHE:
        return _FP_CACHE[key]
    out, _, rc = run_cmd("openssl x509 -in '%s' -noout -fingerprint -sha256" % cert_path)
    if rc != 0:
        return ''
    m = re.search(r'=\s*([0-9A-Fa-f:]{20,})', out or '')
    val = m.group(1).strip() if m else ''
    _FP_CACHE[key] = val
    return val


def ensure_self_cert(sni=''):
    """(cert, key, ошибка). Генерируем один раз и переиспользуем: перевыпуск
    менял бы отпечаток, а он зашит в уже розданные клиентам ссылки."""
    cert, key = self_cert_paths()
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key, ''
    try:
        os.makedirs(_data_dir(), exist_ok=True)
    except Exception:
        pass
    cn = (sni or 'hysteria.local').strip() or 'hysteria.local'
    # 10 лет: серт самоподписанный и проверяется по отпечатку, срок роли не
    # играет, а истёкший заставил бы перевыпускать и менять все ссылки.
    cmd = ("openssl req -x509 -newkey rsa:2048 -keyout '%s' -out '%s' "
           "-days 3650 -nodes -subj '/CN=%s'" % (key, cert, cn))
    out, err, rc = run_cmd(cmd)
    if rc != 0 or not (os.path.isfile(cert) and os.path.isfile(key)):
        return '', '', 'не удалось выпустить самоподписанный сертификат: %s' % (err or out)
    try:
        os.chmod(key, 0o600)
    except Exception:
        pass
    audit('info', 'выпущен самоподписанный сертификат (CN=%s)' % cn)
    return cert, key, ''


def resolve_cert(sni='', mode=''):
    """Каким сертификатом терминировать QUIC.

    {'mode': 'le'|'self', 'fullchain', 'privkey', 'domain', 'fingerprint'}.
    'le' — обычная проверка цепочки у клиента; 'self' — клиенту нужны
    insecure=1 и pinSHA256, иначе handshake не состоится.

    mode: 'auto' (по умолчанию) — есть серт Let's Encrypt, берём его; 'self' —
    держаться самоподписанного, даже если LE появился. Второе нужно там, где
    клиентам уже розданы ссылки с pinSHA256: отпечаток зашит в ссылку, и любая
    смена сертификата рвёт handshake у всех разом. Режим не передали — берём из
    намерения (server.json), чтобы вызовы без настроек не теряли выбор.
    """
    if not mode:
        mode = (_load_intent() or {}).get('cert_mode') or 'auto'
    if mode != 'self':
        le = (DEPS.get('tls_cert') or (lambda: {}))() or {}
        if le.get('fullchain') and le.get('privkey'):
            return {'mode': 'le', 'fullchain': le['fullchain'], 'privkey': le['privkey'],
                    'domain': le.get('domain') or '', 'fingerprint': ''}
    cert, key, err = ensure_self_cert(sni)
    if err:
        return {'mode': '', 'error': err}
    return {'mode': 'self', 'fullchain': cert, 'privkey': key,
            'domain': sni or '', 'fingerprint': cert_fingerprint(cert)}


def link_sni(sni, cert):
    """Имя, которое должно попасть в ссылку клиента и в serverName инбаунда.

    В режиме 'le' это ОБЯЗАТЕЛЬНО домен сертификата, а не SNI панели: клиент
    Hysteria проверяет цепочку против имени из ссылки, и на Reality-сервере,
    где get_xray_sni() отдаёт домен-прикрытие realitySettings, проверка упала бы
    на несовпадении имён. В режиме 'self' имя косметическое — работает пиннинг,
    поэтому оставляем SNI панели.
    """
    if (cert or {}).get('mode') == 'le':
        return (cert.get('domain') or sni or '')
    return sni or (cert or {}).get('domain') or ''


# --- клиенты ----------------------------------------------------------------

def client_password(client):
    """Пароль Hysteria конкретного клиента. Хранится в общей базе XRay рядом с
    uuid — отдельной базы у протокола нет."""
    return (client.get('hy2_password') or '').strip()


def new_password():
    return secrets.token_urlsafe(16)


def client_email(client, uuid=''):
    """Ключ клиента в статистике, правилах и логах.

    ТОТ ЖЕ, что у VLESS, а не отдельный: панель связывает с клиентом всё именно
    по email — statsquery агрегирует трафик как user>>>email, routing матчит
    правила и фильтры IP по `user`, карточка и логи ищут по нему же. Дай
    Hysteria свой email — и её трафик не попал бы ни в счётчик клиента, ни под
    его лимиты, ни под его правила. Ядро одинаковый email в двух инбаундах
    принимает и складывает трафик.
    """
    fn = DEPS.get('unique_email')
    uid = uuid or client.get('uuid') or ''
    if fn:
        return fn(client.get('name') or '', uid)
    name = (client.get('name') or 'client').strip() or 'client'
    return '%s-%s' % (name, uid[:8])


def build_users(clients):
    """users инбаунда из общей базы клиентов XRay.

    Отключённых пропускаем: их не должно быть в конфиге вовсе, иначе «выключен»
    в панели ничего не значит.
    """
    users = []
    for uuid, c in (clients or {}).items():
        if c.get('disabled'):
            continue
        pwd = client_password(c)
        if not pwd:
            continue
        users.append({'auth': pwd, 'email': client_email(c, uuid)})
    return users


def ensure_passwords(clients):
    """Раздать пароль тем, у кого его ещё нет. (clients, изменилось ли).

    Hysteria выдаётся всем клиентам, поэтому пароль появляется и у заведённых
    раньше — при первом же применении инбаунда.
    """
    changed = False
    for c in (clients or {}).values():
        if not client_password(c):
            c['hy2_password'] = new_password()
            changed = True
    return clients, changed


# --- настройки инбаунда -----------------------------------------------------

def _load_intent():
    fn = DEPS.get('load_intent')
    try:
        return (fn() or {}) if fn else {}
    except Exception:
        return {}


def _save_intent(settings):
    fn = DEPS.get('save_intent')
    if not fn:
        return
    try:
        fn({k: settings.get(k) for k in default_settings()})
    except Exception:
        pass


def remember_settings(settings):
    """Запомнить настройки выключенного инбаунда: в config.json их хранить
    негде, а без этого порт, введённый при выключенном тумблере, пропадал."""
    _save_intent(settings)


def default_settings():
    # cert_mode: 'auto' — предпочитать серт Let's Encrypt, 'self' — держаться
    # самоподписанного (см. resolve_cert). В инбаунде этого поля нет, оно живёт
    # только в намерении, поэтому read_settings его оттуда и не перетирает.
    return {'port': DEFAULT_PORT, 'masquerade_url': DEFAULT_MASQUERADE,
            'obfs_password': '', 'up_mbps': 0, 'down_mbps': 0, 'cert_mode': 'auto'}


def read_settings(cfg_x=None):
    """Настройки инбаунда.

    Источник правды — живой config.json, как и для порта с SNI у VLESS. Когда
    инбаунда там нет (выключен), берём намерение из server.json: иначе
    выключение стирало бы маскировку и пароль обфускации, и включать пришлось
    бы заново с нуля. Своего файла настроек протокол не заводит.
    """
    s = default_settings()
    s.update({k: v for k, v in (_load_intent() or {}).items() if k in s})
    if cfg_x is None:
        cfg_x, err = _load_cfg()
        if err:
            return s
    idx = find_idx(cfg_x)
    if idx < 0:
        return s
    inb = cfg_x['inbounds'][idx]
    stream = inb.get('streamSettings') or {}
    s['port'] = int(inb.get('port') or DEFAULT_PORT)
    masq = ((stream.get('hysteriaSettings') or {}).get('masquerade') or {})
    s['masquerade_url'] = masq.get('url') or ''
    mask = stream.get('finalmask') or {}
    for m in (mask.get('udp') or []):
        if m.get('type') == 'salamander':
            s['obfs_password'] = ((m.get('settings') or {}).get('password') or '')
    quic = mask.get('quicParams') or {}
    s['up_mbps'] = _mbps(quic.get('brutalUp'))
    s['down_mbps'] = _mbps(quic.get('brutalDown'))
    return s


def _mbps(val):
    m = re.match(r'^\s*(\d+)', str(val or ''))
    return int(m.group(1)) if m else 0


def _bandwidth(mbps):
    """0/пусто → '' (без ограничения). Xray ждёт строку вида '100 mbps'."""
    try:
        val = int(mbps or 0)
    except (TypeError, ValueError):
        return ''
    return ('%d mbps' % val) if val > 0 else ''


def _masquerade(settings):
    """Блок пишем всегда: тип по умолчанию у Xray — 404, и забытая маскировка
    деградирует молча (протокол работает, прикрытия нет)."""
    url = (settings.get('masquerade_url') or '').strip()
    if not url:
        return {'type': '404'}
    return {'type': 'proxy', 'url': url, 'rewriteHost': True}


# --- сборка и применение ----------------------------------------------------

def build_inbound(settings=None, users=None, cert=None, sni=''):
    """(инбаунд, ошибка)."""
    settings = settings or default_settings()
    cert = cert if cert is not None else resolve_cert(sni, settings.get('cert_mode'))
    if not (cert.get('fullchain') and cert.get('privkey')):
        return None, (cert.get('error') or 'нет сертификата для Hysteria')

    stream = {
        'network': 'hysteria',
        'security': 'tls',
        'tlsSettings': {
            'serverName': link_sni(sni, cert),
            'certificates': [{'certificateFile': cert['fullchain'],
                              'keyFile': cert['privkey']}],
        },
        'hysteriaSettings': {'version': 2, 'masquerade': _masquerade(settings)},
    }

    # salamander и лимиты — две части finalmask. Пустые блоки не пишем: в конфиге
    # они читаются как «настроено», хотя не настроено ничего.
    mask = {}
    obfs = (settings.get('obfs_password') or '').strip()
    if obfs:
        mask['udp'] = [{'type': 'salamander', 'settings': {'password': obfs}}]
    up, down = _bandwidth(settings.get('up_mbps')), _bandwidth(settings.get('down_mbps'))
    if up or down:
        quic = {'congestion': 'brutal'}
        if up:
            quic['brutalUp'] = up
        if down:
            quic['brutalDown'] = down
        mask['quicParams'] = quic
    if mask:
        stream['finalmask'] = mask

    return {
        'tag': INBOUND_TAG,
        'listen': '0.0.0.0',
        'port': int(settings.get('port') or DEFAULT_PORT),
        'protocol': 'hysteria',
        'settings': {'version': 2, 'clients': list(users or [])},
        'streamSettings': stream,
        # Тот же sniffing, что у VLESS: без него в access.log попадут одни IP,
        # а диагностика назначений останется пустой.
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic']},
    }, ''


def _load_cfg():
    load = DEPS.get('xray_load_config')
    if not load:
        return None, 'нет доступа к конфигу XRay'
    try:
        return load(), ''
    except Exception as e:
        return None, 'не удалось прочитать конфиг XRay: %s' % e


def find_idx(cfg_x):
    """Индекс своего инбаунда или -1. Строго по тегу: чужие инбаунды (VLESS,
    api) трогать нельзя ни при каких условиях."""
    for i, ib in enumerate((cfg_x or {}).get('inbounds') or []):
        if ib.get('tag') == INBOUND_TAG:
            return i
    return -1


def enabled():
    cfg_x, err = _load_cfg()
    return (find_idx(cfg_x) >= 0) if not err else False


def apply_inbound(settings=None, restart=True):
    """Добавить/обновить инбаунд. (ok, ошибка).

    Патчим конфиг, а не пересобираем: рядом живут другие инбаунды, routing,
    stats и log.
    """
    cfg_x, err = _load_cfg()
    if err:
        return False, err
    if settings is None:
        settings = read_settings(cfg_x)

    clients_fn = DEPS.get('load_clients')
    save_clients = DEPS.get('save_clients')
    clients = clients_fn() if clients_fn else {}
    clients, changed = ensure_passwords(clients)
    if changed and save_clients:
        save_clients(clients)

    sni = (DEPS.get('sni') or (lambda: ''))()
    cert = resolve_cert(sni, settings.get('cert_mode'))
    # Самоподписанный «залипает» сам, без миграции: как только его отпечаток
    # уехал клиентам в ссылках (pinSHA256), появление серта Let's Encrypt не
    # должно молча подменить сертификат — это оборвало бы подключение у всех
    # разом. Переход панель предлагает отдельно (cert_offer) и делает только по
    # кнопке.
    if cert.get('mode') == 'self' and settings.get('cert_mode') != 'self':
        settings = dict(settings, cert_mode='self')
    inb, err = build_inbound(settings=settings, users=build_users(clients),
                             cert=cert, sni=sni)
    if err:
        return False, err

    port = inb['port']
    owner = (DEPS.get('port_owner') or (lambda p, pr='udp': ''))(port, 'udp')
    # Чужой слушатель на этом UDP-порту не даст инбаунду подняться, и XRay
    # упадёт целиком — вместе с VLESS.
    if owner and 'xray' not in owner.lower():
        return False, ('UDP-порт %d занят: %s' % (port, owner))

    _save_intent(settings)
    cfg_x.setdefault('inbounds', [])
    idx = find_idx(cfg_x)
    if idx < 0:
        cfg_x['inbounds'].append(inb)
    else:
        cfg_x['inbounds'][idx] = inb
    try:
        DEPS['xray_save_config'](cfg_x)
    except Exception as e:
        return False, 'не удалось записать конфиг XRay: %s' % e

    opener = DEPS.get('open_firewall')
    if opener:
        try:
            opener(port)
        except Exception:
            pass

    if restart:
        ok, err = restart_xray()
        if not ok:
            return False, err
    audit('info', 'инбаунд применён (UDP %d, клиентов %d)'
          % (port, len(inb['settings']['clients'])))
    return True, ''


def remove_inbound(restart=True):
    """Убрать инбаунд. Ядро и остальные инбаунды не трогаются, пароли клиентов
    остаются в базе — повторное включение не меняет выданные ссылки."""
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
    if restart:
        ok, err = restart_xray()
        if not ok:
            return False, err
    audit('info', 'инбаунд удалён')
    return True, ''


def sync(restart=False):
    """Пересобрать users инбаунда под текущую базу клиентов. Вызывается после
    добавления, удаления, переименования и включения/выключения клиента.

    По умолчанию без перезапуска: вызывающий код у VLESS и так планирует
    рестарт XRay, второй подряд рвал бы соединения дважды.
    """
    if not enabled():
        return True, ''
    return apply_inbound(restart=restart)


def restart_xray():
    """(ok, ошибка). Исход проверяем по is-active: systemctl возвращает 0 и
    тогда, когда сервис упал сразу после старта. Остановленный руками XRay
    (inactive) не поднимаем — конфиг применится при его старте."""
    if run_cmd('systemctl is-active xray')[0].strip() == 'inactive':
        return True, ''
    out, err, rc = run_cmd('systemctl restart xray')
    if rc != 0:
        return False, (err or out or 'systemctl restart xray завершился ошибкой')
    st, _, _ = run_cmd('systemctl is-active xray')
    if st.strip() != 'active':
        return False, 'XRay не поднялся после перезапуска — смотрите journalctl -u xray'
    return True, ''


# --- ссылки клиентам --------------------------------------------------------

def build_link(client, uuid='', host='', settings=None, cert=None):
    """hysteria2://... для карточки клиента и профилей. Пусто, если инбаунд
    выключен или у клиента нет пароля."""
    from urllib.parse import quote
    pwd = client_password(client)
    if not pwd:
        return ''
    settings = settings or read_settings()
    host = host or (DEPS.get('server_host') or (lambda: ''))()
    if not host:
        return ''
    sni = (DEPS.get('sni') or (lambda: ''))()
    cert = cert if cert is not None else resolve_cert(sni, settings.get('cert_mode'))
    sni = link_sni(sni, cert)

    params = []
    if sni:
        params.append('sni=%s' % quote(sni))
    obfs = (settings.get('obfs_password') or '').strip()
    if obfs:
        params.append('obfs=salamander')
        params.append('obfs-password=%s' % quote(obfs))
    if cert.get('mode') == 'self':
        # insecure=1 обязателен даже с пиннингом: обычная проверка цепочки идёт
        # своим чередом и на самоподписанном серте валит handshake. Защиту даёт
        # pinSHA256 — клиент сверяет конкретный сертификат.
        params.append('insecure=1')
        fp = cert.get('fingerprint') or ''
        if fp:
            params.append('pinSHA256=%s' % quote(fp))
    query = ('?%s' % '&'.join(params)) if params else ''
    name = (client.get('name') or 'client')
    return 'hysteria2://%s@%s:%d/%s#%s' % (
        quote(pwd, safe=''), host, int(settings.get('port') or DEFAULT_PORT),
        query, quote(name))


# --- узлы для клиентских профилей -------------------------------------------
# Синтаксис у каждого клиента свой и в мануалах описан не полностью — значения
# ниже проверены на живых приложениях: чужое имя ключа приложение не игнорирует,
# а отбраковывает узел целиком или собирает его без пароля.

def fingerprint_hex():
    """Отпечаток без двоеточий — в таком виде его ждут Loon и mihomo."""
    fp = (resolve_cert((DEPS.get('sni') or (lambda: ''))()) or {}).get('fingerprint') or ''
    return fp.replace(':', '').lower()


def _node_common(client, host=None, settings=None):
    settings = settings or read_settings()
    host = host or (DEPS.get('server_host') or (lambda: ''))()
    sni = (DEPS.get('sni') or (lambda: ''))() or host
    cert = resolve_cert(sni, settings.get('cert_mode'))
    sni = link_sni(sni, cert) or host
    return {
        'host': host,
        'port': int(settings.get('port') or DEFAULT_PORT),
        'password': client_password(client),
        'sni': sni,
        'obfs': (settings.get('obfs_password') or '').strip(),
        'self_signed': cert.get('mode') == 'self',
        'up': int(settings.get('up_mbps') or 0),
        'down': int(settings.get('down_mbps') or 0),
    }


def sr_node(client, name, host=None, settings=None):
    """Строка узла для [Proxy] Shadowrocket.

    Ключи у него свои и не совпадают ни с URI-схемой, ни с Loon/Clash:
    auth (не password), peer (не sni), obfsParam (не obfs-password), udp=1.
    Пиннинг по отпечатку в .conf не поддерживается — только allowInsecure.
    """
    n = _node_common(client, host, settings)
    if not (n['host'] and n['password']):
        return ''
    parts = ['%s = hysteria2' % name, n['host'], str(n['port']),
             'auth=%s' % n['password'], 'peer=%s' % n['sni']]
    if n['obfs']:
        parts.append('obfsParam=%s' % n['obfs'])
    if n['self_signed']:
        parts.append('allowInsecure=1')
    parts.append('udp=1')
    return ', '.join(parts)


def loon_node(client, name, host=None, settings=None):
    """Строка узла для [Proxy] Loon.

    SNI здесь называется tls-name, обфускация — salamander-password (сам
    obfs=salamander не пишется), отпечаток — tls-cert-sha256 без двоеточий.
    """
    n = _node_common(client, host, settings)
    if not (n['host'] and n['password']):
        return ''
    parts = ['%s = Hysteria2' % name, n['host'], str(n['port']), '"%s"' % n['password']]
    if n['self_signed']:
        parts.append('skip-cert-verify=true')
        fp = fingerprint_hex()
        if fp:
            parts.append('tls-cert-sha256=%s' % fp)
    parts.append('tls-name=%s' % n['sni'])
    parts.append('udp=true')
    parts.append('fast-open=true')
    if n['obfs']:
        parts.append('salamander-password=%s' % n['obfs'])
    return ','.join(parts)


def clash_lines(client, host=None, settings=None):
    """Тело узла hysteria2 для proxies: в Clash.Meta (без строки name — её
    пишет вызывающий, чтобы имя совпало с группой и правилами).

    `udp: true` не пишем: у hysteria2 в mihomo такого поля нет, а лишний ключ
    строгий парсер отвергает вместе со всем профилем.
    """
    n = _node_common(client, host, settings)
    if not (n['host'] and n['password']):
        return []
    lines = ['    type: hysteria2',
             '    server: %s' % n['host'],
             '    port: %d' % n['port'],
             '    password: "%s"' % n['password'],
             '    sni: %s' % n['sni']]
    fp = fingerprint_hex()
    if n['self_signed']:
        if fp:
            lines.append('    fingerprint: %s' % fp)
        else:
            lines.append('    skip-cert-verify: true')
    if n['obfs']:
        lines.append('    obfs: salamander')
        lines.append('    obfs-password: "%s"' % n['obfs'])
    if n['up']:
        lines.append('    up: "%d Mbps"' % n['up'])
    if n['down']:
        lines.append('    down: "%d Mbps"' % n['down'])
    return lines


def status():
    """Состояние для карточки XRay и модалки настроек."""
    cfg_x, err = _load_cfg()
    present = (find_idx(cfg_x) >= 0) if not err else False
    s = read_settings(cfg_x if not err else None)
    sni = (DEPS.get('sni') or (lambda: ''))()
    cert = resolve_cert(sni, s.get('cert_mode')) if present else {}
    st, _, _ = run_cmd('systemctl is-active xray')
    return {
        'enabled': present,
        'xray_active': st.strip() == 'active',
        'port': s['port'],
        'masquerade_url': s['masquerade_url'],
        'obfs': bool(s['obfs_password']),
        'obfs_password': s['obfs_password'],
        'up_mbps': s['up_mbps'],
        'down_mbps': s['down_mbps'],
        'cert_mode': cert.get('mode') or '',
        'cert_intent': s.get('cert_mode') or 'auto',
        'fingerprint': cert.get('fingerprint') or '',
        'cert_offer': cert_offer(s, cert) if present else {},
        'error': err,
    }


def cert_offer(settings=None, cert=None):
    """Есть ли смысл предложить смену сертификата. {} — нечего предлагать.

    Панель не переключает сама: отпечаток самоподписанного зашит в выданные
    ссылки (pinSHA256), и любая смена сертификата рвёт подключение у всех
    разом. Но и молчать нельзя — админ иначе не узнает, что сидит на
    самоподписанном, когда домен и серт уже есть. Поэтому: находим, объясняем
    цену, решает человек.
    """
    settings = settings or read_settings()
    sni = (DEPS.get('sni') or (lambda: ''))()
    cert = cert if cert is not None else resolve_cert(sni, settings.get('cert_mode'))
    if (cert or {}).get('mode') != 'self':
        return {}
    le = (DEPS.get('tls_cert') or (lambda: {}))() or {}
    if not (le.get('fullchain') and le.get('privkey')):
        return {}
    clients_fn = DEPS.get('load_clients')
    clients = (clients_fn() if clients_fn else {}) or {}
    affected = sum(1 for c in clients.values()
                   if client_password(c) and not c.get('disabled'))
    return {
        'to': 'le',
        'domain': le.get('domain') or '',
        'days_left': le.get('days_left'),
        'clients': affected,
    }
