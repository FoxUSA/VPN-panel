"""Наш server-блок nginx — общий фоллбек XRay на 443 (см. xray_link).

Две задачи:
1. Разводка по КАЖДОМУ запросу: /<slug>/ → telemt, всё остальное → туда, куда
   фоллбек XRay вёл до нас (Flask :5000 или свой nginx :8444). Сам XRay умеет
   разводить только целое соединение по первому запросу.
2. Реальный адрес клиента: XRay передаёт его PROXY-протоколом (xver 1), а
   WEB-вход telemt хочет X-Forwarded-For от доверенного прокси. Без этого все
   клиенты выглядели бы как 127.0.0.1 — не было бы «онлайн / IP+гео», лимита
   и фильтра IP. Заодно панель получает X-Real-IP посетителя вместо 127.0.0.1.

Файл целиком наш (awg-panel-tgweb), чужие конфиги nginx не трогаем. Слушает
127.0.0.1 за фоллбеком XRay, а когда XRay на 443 нет — сам 443 с сертификатом
домена (режимы входа — в front.py). Журнал запросов выключен: в строке запроса
моста лежит ?bridge=<ключ>, и access.log превратился бы в список ключей.
"""
import os
import shutil
import time

from . import (DEPS, NGINX_AVAILABLE, NGINX_BACKUP_DIR, NGINX_ENABLED, audit, load_settings,
               run_cmd)

MARK = '# awg-panel: Telegram WEB-прокси'


def installed():
    out, _, rc = run_cmd('command -v nginx')
    return rc == 0 and bool(out)


def active():
    out, _, _ = run_cmd('systemctl is-active nginx')
    return out.strip() == 'active'


def _site_paths():
    """(где лежит файл, куда ставить ссылку или '' если ссылка не нужна).

    Debian/Ubuntu — sites-available + симлинк в sites-enabled. Где этой пары
    нет (сборки nginx.org, RHEL), подключается conf.d/*.conf."""
    if os.path.isdir(os.path.dirname(NGINX_ENABLED)):
        return NGINX_AVAILABLE, NGINX_ENABLED
    return '/etc/nginx/conf.d/%s.conf' % os.path.basename(NGINX_AVAILABLE), ''


def _ipv6_on():
    """Есть ли на сервере IPv6: `listen [::]:443` на ядре без него не даст
    nginx подняться вовсе."""
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as f:
            return f.read().strip() == '0' and os.path.exists('/proc/net/if_inet6')
    except Exception:
        return False


def render(cfg=None, prev_port=None):
    """Текст блока. Режим входа (front.py) задаёт заголовок server:
    'nginx' — сами слушаем 443 с сертификатом домена, адрес клиента берём из
    соединения; иначе — 127.0.0.1:<nginx_port> за фоллбеком XRay, адрес клиента
    из PROXY-заголовка."""
    cfg = cfg or load_settings()
    nport = int(cfg.get('nginx_port') or 0)
    wport = int(cfg.get('web_port') or 0)
    slug = (cfg.get('slug') or '').strip().strip('/')
    if prev_port is None:
        from . import xray_link
        prev_port = xray_link.prev_dest_port()
    standalone = (cfg.get('front') or '') == 'nginx'
    if standalone:
        from . import front
        cert = front.tls_cert()
        listen = ('    listen 443 ssl;\n' + ('    listen [::]:443 ssl;\n' if _ipv6_on() else '') +
                  '    server_name %s;\n'
                  '    ssl_certificate %s;\n'
                  '    ssl_certificate_key %s;\n'
                  '    ssl_protocols TLSv1.2 TLSv1.3;\n'
                  % (cert.get('domain') or '_', cert.get('fullchain') or '', cert.get('privkey') or ''))
        client = '$remote_addr'
        head = ('    # XRay на 443 нет — WEB-прокси слушает порт сам (режим входа «nginx»).\n'
                '    # HTTP/2 не включаем: ровно как XRay с ALPN http/1.1, к которому\n'
                '    # привязаны и сайт, и carrier «https» у telemt.\n')
    else:
        listen = ('    listen 127.0.0.1:%d proxy_protocol;\n'
                  '    server_name _;\n' % nport)
        client = '$proxy_protocol_addr'
        head = ''
    # Метка доверенного прокси: по ней панель верит X-Real-IP (вход по IP без
    # пароля). Секрет знает только панель — берём строку у неё.
    trust = ''
    try:
        fn = DEPS.get('proxy_trust_line')
        trust = fn(client) if fn else ''
    except Exception:
        trust = ''
    # map — уровень http; файлы sites-enabled подключаются внутри http, так что
    # ему здесь место. Имя переменной своё, чтобы не столкнуться с чужим
    # $connection_upgrade из соседних конфигов.
    return (
        '%(mark)s. Файл генерирует панель — ручные правки перезапишутся.\n'
        'map $http_upgrade $awg_tgweb_upgrade {\n'
        '    default upgrade;\n'
        "    ''      '';\n"
        '}\n'
        '\n'
        'server {\n'
        '%(head)s'
        '%(listen)s'
        '    # Журнала нет на всём блоке: в строках запросов лежат ключи моста\n'
        '    # (?bridge=) и секретный адрес входа в панель. До WEB-прокси эти\n'
        '    # запросы шли из XRay прямо во Flask и в журналы nginx не попадали.\n'
        '    access_log off;\n'
        '\n'
        '    # WEB-прокси Telegram. Префикс без ручных правок не менять: он зашит\n'
        '    # в каждую выданную ссылку.\n'
        '    location ^~ /%(slug)s/ {\n'
        '        # Пакеты аплинка до 2 МиБ — меньший лимит рвал бы передачу файлов.\n'
        '        client_max_body_size 4m;\n'
        '        proxy_pass http://127.0.0.1:%(wport)d;\n'
        '        proxy_http_version 1.1;\n'
        '        proxy_set_header Host $host;\n'
        '        # Ровно один адрес: telemt отвергает цепочку через запятую.\n'
        '        proxy_set_header X-Forwarded-For %(client)s;\n'
        '        proxy_set_header Upgrade $http_upgrade;\n'
        '        proxy_set_header Connection $awg_tgweb_upgrade;\n'
        '        # long-poll держит запрос до 25 с, плюс запас; повторов к\n'
        '        # бэкенду быть не должно — повтор кадра ломает поток.\n'
        '        proxy_read_timeout 90s;\n'
        '        proxy_send_timeout 90s;\n'
        '        proxy_next_upstream off;\n'
        '        proxy_buffering off;\n'
        '        proxy_request_buffering off;\n'
        '    }\n'
        '\n'
        '    # Всё остальное — туда же, куда общий фоллбек XRay вёл до WEB-прокси:\n'
        '    # сайт, вход в панель и ссылки на профили работают как раньше.\n'
        '    location / {\n'
        '        client_max_body_size 0;\n'
        '        proxy_pass http://127.0.0.1:%(prev)d;\n'
        '        proxy_http_version 1.1;\n'
        '        proxy_set_header Host $host;\n'
        '        proxy_set_header X-Real-IP %(client)s;\n'
        '        proxy_set_header X-Forwarded-For %(client)s;\n'
        '        proxy_set_header X-Forwarded-Proto https;\n'
        '%(trust)s'
        '        proxy_set_header Upgrade $http_upgrade;\n'
        '        proxy_set_header Connection $awg_tgweb_upgrade;\n'
        '        proxy_read_timeout 300s;\n'
        '    }\n'
        '}\n'
    ) % {'mark': MARK, 'head': head, 'listen': listen, 'client': client, 'wport': wport,
         'slug': slug, 'prev': int(prev_port or 5000), 'trust': trust}


def current_text():
    path, _ = _site_paths()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ''


def in_sync(cfg=None):
    """Файл совпадает с тем, что генерирует панель, И подключён: после
    восстановления из бэкапа файл в sites-available есть, а ссылки в
    sites-enabled нет — nginx его не видит."""
    _, link = _site_paths()
    if link and not os.path.islink(link):
        return False
    return current_text() == render(cfg)


def _backup(path):
    if not os.path.isfile(path):
        return ''
    os.makedirs(NGINX_BACKUP_DIR, exist_ok=True)
    dst = os.path.join(NGINX_BACKUP_DIR, '%s.%d' % (os.path.basename(path), int(time.time())))
    try:
        shutil.copy2(path, dst)
    except Exception:
        return ''
    return dst


def apply(cfg=None):
    """Записать блок, проверить nginx -t, перечитать. (ok, ошибка).

    При провале проверки возвращаем прежнее состояние: сломанный конфиг в
    sites-enabled уронил бы nginx целиком при следующем reload, вместе с
    чужими сайтами на этом сервере."""
    if not installed():
        return False, 'nginx не установлен'
    path, link = _site_paths()
    text = render(cfg)
    prev = current_text() if os.path.isfile(path) else None
    if prev == text and (not link or os.path.islink(link)):
        return True, ''
    _backup(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    made_link = False
    if link and not os.path.lexists(link):
        try:
            os.symlink(path, link)
            made_link = True
        except FileExistsError:
            pass
    out, err, rc = run_cmd('nginx -t')
    if rc != 0:
        if prev is not None:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(prev)
        else:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        if made_link:
            try:
                os.remove(link)
            except FileNotFoundError:
                pass
        return False, 'nginx -t не прошёл: %s' % ((err or out)[-600:])
    if active():
        run_cmd('systemctl reload nginx')
    else:
        run_cmd('systemctl enable --now nginx')
    c = cfg or load_settings()
    audit('info', 'блок nginx обновлён (%s → telemt)' % (
        '443 с сертификатом домена' if (c.get('front') or '') == 'nginx' else '127.0.0.1:%s' % c.get('nginx_port')))
    return True, ''


def remove():
    path, link = _site_paths()
    touched = False
    for p in (link, path):
        if p and os.path.lexists(p):
            _backup(p) if p == path else None
            try:
                os.remove(p)
                touched = True
            except FileNotFoundError:
                pass
    if touched and installed():
        out, err, rc = run_cmd('nginx -t')
        if rc == 0 and active():
            run_cmd('systemctl reload nginx')
    return touched


def install_package():
    """apt install nginx — для пункта «nginx не установлен». Долго, только в фоне."""
    out, err, rc = run_cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y nginx', timeout=600)
    if rc != 0:
        return False, (err or out)[-600:]
    # Свежий nginx из пакета слушает 80 дефолтным сайтом. Порт 80 на наших
    # серверах обычно свободен или занят им же — но если его держит кто-то
    # другой, пакет не поднимется; это покажет проверка «nginx активен».
    run_cmd('systemctl enable --now nginx')
    return active(), '' if active() else 'nginx установлен, но не запустился'
