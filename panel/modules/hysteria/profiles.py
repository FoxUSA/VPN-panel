"""Клиентские профили Hysteria: ссылка, Loon, Clash.

Три клиента понимают протокол по-разному:

* Shadowrocket — принимает URI hysteria2:// и умеет pinSHA256, поэтому
  самоподписанный сертификат проверяется по отпечатку;
* Loon — URI для hysteria2 НЕ принимает, нужен профиль со строкой
  `Hysteria2, host, port, "пароль", …`; пиннинга у него нет, только
  skip-cert-verify;
* Clash/mihomo — YAML с полем fingerprint, тот же отпечаток, что и pinSHA256,
  но в hex без двоеточий.
"""
from urllib.parse import quote

from . import DEPS, load_settings
from . import service


def server_host():
    """Внешний адрес сервера: сначала SNI из настроек Hysteria, затем то, что
    подсказывает панель (её собственный источник правды по IP/домену)."""
    cfg = load_settings()
    sni = (cfg.get('sni') or '').strip()
    if sni:
        return sni
    fn = DEPS.get('server_host')
    if fn:
        try:
            host = (fn() or '').strip()
            if host:
                return host
        except Exception:
            pass
    return ''


# Длина токена в «человеческой» ссылке — как у XRay (PROFILE_TOKEN_URL_LEN).
TOKEN_URL_LEN = 8
# Префикс публичных профилей Hysteria. Свой, чтобы не пересекаться с /conf,
# /loon, /clash XRay: у протоколов разные наборы клиентов и разные токены.
URL_PREFIX = '/hy'


def panel_base():
    """База ссылок на профили ('https://host[:порт]') или '' — тогда ссылок не
    будет вовсе: битый URL хуже отсутствующего.

    Считает панель (profile_public_base): она одна знает про режим XRay, свой
    порт, сертификат и то, разрешено ли отдавать профиль по HTTP. Здесь только
    берём результат — иначе Hysteria и XRay разъезжаются в том, какая ссылка
    рабочая."""
    fn = DEPS.get('panel_public_base')
    if fn:
        try:
            base = (fn() or '').strip().rstrip('/')
            if base:
                return base
        except Exception:
            pass
    host = panel_host()
    return ('https://%s' % host) if host else ''


def panel_host():
    """Запасной путь для старой панели, которая про базу ещё не знает: там
    ссылка возможна только в TLS-режиме, по домену без порта."""
    fn = DEPS.get('panel_public_host')
    if not fn:
        return ''
    try:
        return (fn() or '').strip()
    except Exception:
        return ''


def _url_seg(client):
    """`<token8>/<имя>` — имя ОБЯЗАНО быть последним сегментом: Loon берёт имя
    профиля из хвоста URL и Content-Disposition игнорирует.

    Сегмент строит панельный генератор — тот же, что у XRay: он знает про режим
    «Имя конфига» (friendly/token) и подставляет имя сервера. Свой путь остаётся
    как запасной, если панель старая и хелпера не пробросила.
    """
    from . import DEPS as _d
    token = (client.get('token') or '')
    fn = _d.get('profile_url_seg')
    if fn:
        try:
            seg = fn(client.get('name') or 'profile', token)
            if seg:
                return seg
        except Exception:
            pass
    name = (client.get('name') or 'profile').strip().lower()
    safe = _d.get('safe_name')
    if safe:
        try:
            name = (safe(name) or name).lower()
        except Exception:
            pass
    return '%s/%s' % (token[:TOKEN_URL_LEN], name)


def profile_urls(client):
    """Публичные ссылки профилей. Пустой словарь, если панель снаружи не
    опубликована или у клиента ещё нет токена — почему именно, разбирает
    /api/profile-access, и UI показывает это на месте."""
    root = panel_base()
    if not root or not client.get('token'):
        return {}
    seg = _url_seg(client)
    base = '%s%s' % (root, URL_PREFIX)
    return {
        # .txt — как у подписки XRay (/sub/<seg>.txt); без расширения тоже
        # отдаётся: клиент ищется по токену в любом сегменте пути.
        'sub': '%s/sub/%s.txt' % (base, seg),
        'shadowrocket': '%s/conf/%s.conf' % (base, seg),
        'loon': '%s/loon/%s.conf' % (base, seg),
        'clash': '%s/clash/%s.yaml' % (base, seg),
    }


def _fp_hex():
    """Отпечаток в виде hex без двоеточий — формат поля fingerprint у mihomo.
    Для сертификата домена пиннинг не нужен: проверяется цепочка."""
    if service.cert_mode() == 'le':
        return ''
    return service.cert_fingerprint().replace(':', '').lower()


def _hop(cfg):
    """(диапазон, интервал) порт-хоппинга или ('', 0). Основной порт в профиле
    остаётся прежним — диапазон идёт отдельным полем, поэтому клиент, не
    знающий хоппинга, просто подключится на основной порт."""
    rng = service.hop_active(cfg)
    return (rng, service.hop_interval(cfg)) if rng else ('', 0)


def build_link(client, host=None):
    """URI для Shadowrocket и совместимых."""
    cfg = load_settings()
    host = host or server_host()
    if not host:
        return ''
    params = []
    sni = (cfg.get('sni') or '').strip()
    if sni:
        params.append('sni=%s' % quote(sni))
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        params.append('obfs=salamander')
        params.append('obfs-password=%s' % quote(obfs))
    if service.cert_mode() != 'le':
        # insecure=1 обязателен даже с пиннингом: у клиента hysteria pinSHA256
        # вешается на VerifyPeerCertificate, а обычная проверка цепочки при
        # insecure=0 идёт своим чередом и на самоподписанном серте падает —
        # handshake не состоится вовсе (app/cmd/client.go::fillTLSConfig).
        # Безопасность даёт не insecure, а сам пиннинг: клиент сверяет отпечаток
        # конкретного сертификата, подменить его нельзя. С сертификатом домена
        # не пишем ни того ни другого — там работает штатная проверка цепочки,
        # а отпечаток менялся бы при каждом перевыпуске.
        params.append('insecure=1')
        fp = service.cert_fingerprint()
        if fp:
            params.append('pinSHA256=%s' % quote(fp))
    # Хоппинг — параметром mport, а не портами в адресе (второй вариант
    # официального URI). Так пишет Sub-Store (producers/uri.js), и клиент, не
    # знающий параметра, его просто пропустит и подключится на основной порт;
    # «host:443,20000-29999» в адресе ломал бы разбор ссылки у таких клиентов.
    hop_rng, hop_iv = _hop(cfg)
    if hop_rng:
        params.append('mport=%s' % hop_rng)
        params.append('hop-interval=%d' % hop_iv)
    query = ('?%s' % '&'.join(params)) if params else ''
    return 'hysteria2://%s@%s:%d/%s#%s' % (
        quote(client.get('password') or '', safe=''),
        host,
        int(cfg.get('port') or 443),
        query,
        quote(client.get('name') or 'client'),
    )


def build_loon_proxy(client, host=None):
    """Одна строка узла для секции [Proxy] в Loon."""
    cfg = load_settings()
    host = host or server_host()
    if not host:
        return ''
    parts = ['%s = Hysteria2' % (client.get('name') or 'hysteria'),
             host,
             str(int(cfg.get('port') or 443)),
             '"%s"' % (client.get('password') or '')]
    # Самоподписанный сертификат: цепочку проверить нечем, поэтому отключаем
    # проверку и вместо неё пиннуем отпечаток — клиент сверяет именно этот
    # сертификат, подмена невозможна (так же, как pinSHA256 в ссылке и
    # fingerprint у mihomo). Ключ tls-cert-sha256 в мануале Loon не описан, но
    # парсер его принимает (грамматика Sub-Store, правило hysteria2), значение —
    # hex без двоеточий. С сертификатом домена не пишем ничего: проверка
    # цепочки работает штатно, а отпечаток меняется при каждом перевыпуске.
    if service.cert_mode() != 'le':
        parts.append('skip-cert-verify=true')
        fp = _fp_hex()
        if fp:
            parts.append('tls-cert-sha256=%s' % fp)
    # SNI у Loon называется tls-name, а не sni: с чужим ключом он отбраковывает
    # строку целиком, и профиль не импортируется вовсе.
    # Формат из мануала Loon (docs/cn/node.md):
    #   name = Hysteria2,host,port,"password",skip-cert-verify=,tls-name=,udp=,fast-open=
    sni = (cfg.get('sni') or '').strip() or host
    parts.append('tls-name=%s' % sni)
    parts.append('udp=true')
    parts.append('fast-open=true')
    # Обфускация: ключ называется salamander-password, сам obfs=salamander не
    # пишется — у Loon других обфускаторов для Hysteria2 нет. В мануале ключ не
    # описан, но парсер Loon его принимает (грамматика Sub-Store, правило
    # hysteria2: .../salamander_password/...).
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        parts.append('salamander-password=%s' % obfs)
    # Хоппинг: server-ports в кавычках и hop-interval в секундах — в мануале
    # Loon не описаны, грамматика Sub-Store (peggy/loon.js, server_ports /
    # hop_interval) их принимает.
    hop_rng, hop_iv = _hop(cfg)
    if hop_rng:
        parts.append('server-ports="%s"' % hop_rng)
        parts.append('hop-interval=%d' % hop_iv)
    return ','.join(parts)


def build_loon(client, host=None):
    """Готовый профиль Loon: узел, DNS, группы и правила каталога."""
    node = build_loon_proxy(client, host)
    if not node:
        return ''
    # Основной путь — панельный билдер: он приносит правила каталога, страны,
    # политики и DNS ровно в том виде, в каком их получают клиенты XRay.
    fn = DEPS.get('loon_profile')
    if fn:
        try:
            return fn(client, proxy_line=node)
        except Exception:
            pass  # что-то в общем билдере не сошлось — отдаём минимальный профиль
    name = client.get('name') or 'hysteria'
    lines = [
        '#!name=%s (Hysteria2)' % name,
        '#!desc=Профиль сгенерирован панелью awg-panel',
        '',
    ]
    # DNS-блок собирает та же функция панели, что и для XRay-профилей —
    # синтаксис doh-server/doh3-server/doq-server должен совпадать везде.
    dns = _dns_block('dns_loon', client)
    if dns:
        lines += ['[General]', dns.rstrip(), '']
    lines += [
        '[Proxy]',
        node,
        '',
        '[Proxy Group]',
        'PROXY = select,%s' % name,
        '',
        '[Rule]',
        'GEOIP,CN,DIRECT',
        'FINAL,PROXY',
        '',
    ]
    return '\n'.join(lines)


def _dns_block(dep_key, client):
    """DNS-блок из панельного генератора; пусто, если DNS у клиента не задан."""
    fn = DEPS.get(dep_key)
    if not fn:
        return ''
    try:
        res = fn(client)
    except Exception:
        return ''
    if isinstance(res, (list, tuple)):
        return '\n'.join(res)
    return res or ''


def _clash_proxy_lines(client, host, cfg):
    """Описание узла hysteria2 для секции proxies (без строки name — её пишет
    вызывающий, чтобы имя прокси совпадало с именем в группах и правилах)."""
    lines = [
        '    type: hysteria2',
        '    server: %s' % host,
        '    port: %d' % int(cfg.get('port') or 443),
        '    password: "%s"' % (client.get('password') or ''),
        '    sni: %s' % ((cfg.get('sni') or '').strip() or host),
    ]
    fp = _fp_hex()
    if fp:
        lines.append('    fingerprint: %s' % fp)
    elif service.cert_mode() != 'le':
        lines.append('    skip-cert-verify: true')
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        lines.append('    obfs: salamander')
        lines.append('    obfs-password: "%s"' % obfs)
    # mihomo: ports + hop-interval (wiki hysteria2). При заданных ports поле
    # port клиентом не используется — но весь диапазон и так ведёт в сервер.
    hop_rng, hop_iv = _hop(cfg)
    if hop_rng:
        lines.append('    ports: "%s"' % hop_rng)
        lines.append('    hop-interval: %d' % hop_iv)
    up, down = int(cfg.get('up_mbps') or 0), int(cfg.get('down_mbps') or 0)
    if up:
        lines.append('    up: "%d Mbps"' % up)
    if down:
        lines.append('    down: "%d Mbps"' % down)
    # `udp: true` здесь НЕ пишется: у hysteria2 в mihomo такого поля нет
    # (протокол и так поверх QUIC, UDP-релей всегда включён), а лишний ключ
    # строгий парсер профиля отвергает целиком.
    return lines


def build_clash(client, host=None):
    """Профиль Clash/mihomo. fingerprint = тот же отпечаток, что pinSHA256."""
    cfg = load_settings()
    host = host or server_host()
    if not host:
        return ''
    fn = DEPS.get('clash_profile')
    if fn:
        try:
            return fn(client, proxy_lines=_clash_proxy_lines(client, host, cfg))
        except Exception:
            pass  # общий билдер не сошёлся — ниже минимальный профиль
    name = client.get('name') or 'hysteria'
    sni = (cfg.get('sni') or '').strip() or host
    lines = [
        '# Профиль сгенерирован панелью awg-panel',
        'mixed-port: 7890',
        'allow-lan: false',
        'mode: rule',
        'log-level: info',
        '',
        'proxies:',
        '  - name: "%s"' % name,
        '    type: hysteria2',
        '    server: %s' % host,
        '    port: %d' % int(cfg.get('port') or 443),
        '    password: "%s"' % (client.get('password') or ''),
        '    sni: %s' % sni,
    ]
    fp = _fp_hex()
    if fp:
        lines.append('    fingerprint: %s' % fp)
    elif service.cert_mode() != 'le':
        # Только для самоподписанного: с сертификатом домена проверка цепочки
        # обязана работать, иначе профиль молча слабее, чем должен быть.
        lines.append('    skip-cert-verify: true')
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        lines.append('    obfs: salamander')
        lines.append('    obfs-password: "%s"' % obfs)
    # mihomo: ports + hop-interval (wiki hysteria2). При заданных ports поле
    # port клиентом не используется — но весь диапазон и так ведёт в сервер.
    hop_rng, hop_iv = _hop(cfg)
    if hop_rng:
        lines.append('    ports: "%s"' % hop_rng)
        lines.append('    hop-interval: %d' % hop_iv)
    up, down = int(cfg.get('up_mbps') or 0), int(cfg.get('down_mbps') or 0)
    if up:
        lines.append('    up: "%d Mbps"' % up)
    if down:
        lines.append('    down: "%d Mbps"' % down)
    dns = _dns_block('dns_clash', client)
    if dns:
        lines += ['', dns]
    lines += [
        '',
        'proxy-groups:',
        '  - name: PROXY',
        '    type: select',
        '    proxies:',
        '      - "%s"' % name,
        '      - DIRECT',
        '',
        'rules:',
        '  - GEOIP,CN,DIRECT',
        '  - MATCH,PROXY',
        '',
    ]
    return '\n'.join(lines)


def build_sr_proxy(client, host=None):
    """Строка узла для секции [Proxy] Shadowrocket."""
    cfg = load_settings()
    host = host or server_host()
    if not host:
        return ''
    # Ключи в .conf у Shadowrocket СВОИ и не совпадают ни с URI-схемой hysteria2,
    # ни с Loon/Clash. По его мануалу («编写本地节点», раздел Hysteria2类型):
    #   имя=hysteria2,адрес,порт,auth=пароль,obfsParam=обфускация,udp=1,
    #                 прочее (peer=example.com, alpn=h3)
    # Отсюда: auth (не password), peer (не sni), obfsParam (не obfs-password),
    # udp=1 (не true). С «правильными» по другим клиентам именами узел молча
    # собирается без пароля и обфускации и не подключается.
    parts = ['%s = hysteria2' % (client.get('name') or 'hysteria'),
             host,
             str(int(cfg.get('port') or 443)),
             'auth=%s' % (client.get('password') or '')]
    sni = (cfg.get('sni') or '').strip() or host
    parts.append('peer=%s' % sni)
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        # Тип обфускации отдельным ключом не задаётся: у hysteria2 она одна —
        # salamander, и Shadowrocket ждёт только сам пароль.
        parts.append('obfsParam=%s' % obfs)
    if service.cert_mode() != 'le':
        # В .conf у Shadowrocket пиннинг по отпечатку не документирован — в
        # отличие от hysteria2://-ссылки, где работает pinSHA256. Ставим
        # allowInsecure: непонятый ключ означал бы не «менее строгую проверку»,
        # а полный отказ подключаться. Пиннинг остаётся во вкладке «Ссылка + QR»,
        # и это ещё один довод за режим «сертификат домена».
        parts.append('allowInsecure=1')
    parts.append('udp=1')
    return ', '.join(parts)


def build_shadowrocket(client, host=None):
    """Профиль Shadowrocket с правилами каталога — тем же билдером, что у XRay."""
    node = build_sr_proxy(client, host)
    if not node:
        return ''
    fn = DEPS.get('sr_profile')
    if fn:
        try:
            return fn(client, proxy_line=node,
                      update_url_override=(profile_urls(client).get('shadowrocket') or ''))
        except Exception:
            pass
    # Общий билдер не сошёлся — отдаём хотя бы рабочий узел без правил.
    return '[Proxy]\n%s\n\n[Rule]\nFINAL,%s\n' % (node, client.get('name') or 'hysteria')


def build_all(client, host=None):
    host = host or server_host()
    return {
        'link': build_link(client, host),
        'shadowrocket': build_shadowrocket(client, host),
        'loon': build_loon(client, host),
        'clash': build_clash(client, host),
        'loon_node': build_loon_proxy(client, host),
        'fingerprint': service.cert_fingerprint(),
        'urls': profile_urls(client),
    }
