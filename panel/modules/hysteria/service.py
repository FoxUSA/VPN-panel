"""Установка, конфиг и жизненный цикл сервиса hysteria.

config.yaml генерируется целиком из наших JSON-ов, а не патчится: источник
правды — settings.json + clients.json, YAML лишь производная. Поэтому pyyaml
в venv панели не нужен, а ручные правки config.yaml будут перезаписаны (о чём
в файл пишется предупреждение первой строкой).
"""
import os
import re
import time
import urllib.request

from . import (ACCESS_LOG, AUTH_SCRIPT, BIN_PATH, CERT_FILE, CONFIG_FILE, DATA_DIR, DEPS,
               GITHUB_REPO, KEY_FILE, STATS_ADDR, UNIT_FILE, UNIT_NAME,
               audit, load_settings, run_cmd, save_settings)

_LATEST_CACHE = {'value': '', 'ts': 0}
_LATEST_TTL = 3600


def _http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': 'awg-panel'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# --- бинарь -----------------------------------------------------------------

def bin_installed():
    return os.path.isfile(BIN_PATH) and os.access(BIN_PATH, os.X_OK)


def installed_version():
    if not bin_installed():
        return ''
    out, _, rc = run_cmd('%s version' % BIN_PATH)
    if rc != 0:
        return ''
    m = re.search(r'v?(\d+\.\d+\.\d+)', out)
    return ('v%s' % m.group(1)) if m else ''


def latest_version_nowait():
    """Для /status: отдаёт кеш сразу, а устаревший обновляет в фоне. Синхронный
    поход на GitHub (таймаут 15 с) держал список клиентов вкладки; неудача не
    кешировалась, и при недоступном GitHub так ждал каждый заход."""
    now = int(time.time())
    if now - _LATEST_CACHE['ts'] >= _LATEST_TTL and not _LATEST_CACHE.get('busy'):
        _LATEST_CACHE['busy'] = True

        def _bg():
            try:
                latest_version()
            finally:
                # Неудача тоже ставит метку — повтор не раньше, чем через TTL.
                _LATEST_CACHE['ts'] = max(_LATEST_CACHE['ts'], int(time.time()) - _LATEST_TTL + 600)
                _LATEST_CACHE['busy'] = False
        import threading
        threading.Thread(target=_bg, daemon=True).start()
    return _LATEST_CACHE['value']


def latest_version(force=False):
    """Последний релиз с GitHub. Кеш на час — как у остальных протоколов панели."""
    now = int(time.time())
    if not force and _LATEST_CACHE['value'] and now - _LATEST_CACHE['ts'] < _LATEST_TTL:
        return _LATEST_CACHE['value']
    try:
        import json as _json
        raw = _http_get('https://api.github.com/repos/%s/releases/latest' % GITHUB_REPO, timeout=15)
        tag = (_json.loads(raw.decode('utf-8')) or {}).get('tag_name') or ''
        # У HyNetworks/hysteria (бывш. apernet) теги вида «app/v2.6.0» — вытаскиваем только версию.
        m = re.search(r'v?(\d+\.\d+\.\d+)', tag)
        val = ('v%s' % m.group(1)) if m else ''
        if val:
            _LATEST_CACHE.update({'value': val, 'ts': now})
        return val
    except Exception as e:
        audit('warn', 'не удалось узнать последнюю версию: %s' % e)
        return _LATEST_CACHE['value']


def _arch_suffix():
    out, _, _ = run_cmd('uname -m')
    return {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'arm'}.get(out.strip(), 'amd64')


def install_binary():
    """Качает релизный бинарь с GitHub. Возвращает (ok, сообщение)."""
    url = 'https://github.com/%s/releases/latest/download/hysteria-linux-%s' % (
        GITHUB_REPO, _arch_suffix())
    try:
        data = _http_get(url, timeout=180)
    except Exception as e:
        return False, 'скачивание не удалось: %s' % e
    if len(data) < 1024 * 1024:
        # Меньше мегабайта — почти наверняка HTML-страница ошибки, а не бинарь.
        return False, 'скачан подозрительно маленький файл (%d Б)' % len(data)
    tmp = '%s.tmp' % BIN_PATH
    try:
        os.makedirs(os.path.dirname(BIN_PATH), exist_ok=True)
        with open(tmp, 'wb') as f:
            f.write(data)
        os.chmod(tmp, 0o755)
        os.replace(tmp, BIN_PATH)
    except Exception as e:
        try:
            os.remove(tmp)
        except Exception:
            pass
        return False, 'запись бинаря не удалась: %s' % e
    ver = installed_version()
    audit('info', 'бинарь установлен (%s)' % (ver or 'версия не определилась'))
    return True, ver


def update_binary():
    """Обновление до последнего релиза с откатом. (ok, сообщение).

    Прежний бинарь сохраняем рядом: если новая версия не стартует с нашим
    конфигом, сервис останется лежать, а вернуть его будет нечем.
    """
    was = installed_version()
    was_active = not stopped_by_hand()
    latest = latest_version(force=True)
    if latest and was and latest == was:
        return True, 'уже последняя версия (%s)' % was
    backup = '%s.prev' % BIN_PATH
    if bin_installed():
        try:
            import shutil
            shutil.copy2(BIN_PATH, backup)
        except Exception:
            backup = ''
    ok, msg = install_binary()
    if not ok:
        return False, msg
    # Остановленный руками сервис обновление не запускает: проверяем только,
    # что новый бинарь вообще исполняется, остальное — при следующем старте.
    if not was_active:
        if installed_version():
            audit('info', 'бинарь обновлён: %s → %s (сервис остановлен, не запускали)'
                  % (was or '?', installed_version()))
            return True, installed_version()
        err = 'новый бинарь не отвечает на version'
    else:
        ok, err = restart()
    if ok and was_active:
        audit('info', 'бинарь обновлён: %s → %s' % (was or '?', installed_version() or '?'))
        return True, installed_version() or latest
    if backup and os.path.isfile(backup):
        try:
            os.replace(backup, BIN_PATH)
            os.chmod(BIN_PATH, 0o755)
            if was_active:
                restart()
            audit('warn', 'обновление откачено: новая версия не запустилась')
            return False, 'новая версия не запустилась, вернули %s: %s' % (was or 'прежнюю', err)
        except Exception:
            pass
    return False, 'новая версия не запустилась: %s' % err


# --- сертификат -------------------------------------------------------------

def cert_fingerprint(path=None):
    """SHA-256 отпечаток сертификата в формате pinSHA256 (AA:BB:…).

    Считаем по тому файлу, который реально отдаётся клиентам. Для сертификата
    Let's Encrypt отпечаток в ссылки не идёт: он меняется при каждом перевыпуске,
    и закреплённые ссылки перестали бы работать раз в два месяца.
    """
    path = path or active_cert_paths()[0]
    if not path or not os.path.isfile(path):
        return ''
    out, _, rc = run_cmd('openssl x509 -in %s -noout -fingerprint -sha256' % path)
    if rc != 0:
        return ''
    return out.split('=', 1)[1].strip() if '=' in out else ''


def cert_mode():
    """'le' — сертификат домена, 'self' — самоподписанный."""
    cfg = load_settings()
    if (cfg.get('cert_mode') or 'self') != 'le':
        return 'self'
    return 'le' if find_le_cert(cfg.get('sni'))[0] else 'self'


def apply_cert_mode(mode):
    """Переключает источник сертификата и поднимает сервис на новом."""
    cfg = load_settings()
    mode = 'le' if mode == 'le' else 'self'
    if mode == 'le':
        cert, _ = find_le_cert(cfg.get('sni'))
        if not cert:
            return False, ('в /etc/letsencrypt нет сертификата для домена «%s»'
                           % (cfg.get('sni') or '—'))
        install_renew_hook()
    cfg['cert_mode'] = mode
    save_settings(cfg)
    write_config(cfg)
    ok, err = apply_changes()
    if not ok:
        return False, 'сервис не поднялся: %s' % err
    audit('info', 'сертификат переключён на «%s»' % ('домена' if mode == 'le' else 'самоподписанный'))
    return True, ''


LE_LIVE_DIR = '/etc/letsencrypt/live'
# Хук certbot: после каждого перевыпуска сертификата hysteria должна его перечитать.
# Файлы читаются при старте, поэтому без перезапуска сервис остался бы на старом.
LE_DEPLOY_HOOK = '/etc/letsencrypt/renewal-hooks/deploy/awg-panel-hysteria.sh'


def find_le_cert(domain=''):
    """Пути к сертификату Let's Encrypt для домена или ('', '').

    В live/ обычно валяются каталоги мёртвых доменов, поэтому ищем строго по
    имени: домен берём из настроек Hysteria (sni) или у панели.
    """
    domain = (domain or '').strip().lower()
    if not domain or not os.path.isdir(LE_LIVE_DIR):
        return '', ''
    for name in os.listdir(LE_LIVE_DIR):
        base = name.split('-0')[0].lower()   # certbot добавляет суффикс -0001 при дублях
        if base != domain and name.lower() != domain:
            continue
        cert = os.path.join(LE_LIVE_DIR, name, 'fullchain.pem')
        key = os.path.join(LE_LIVE_DIR, name, 'privkey.pem')
        if os.path.isfile(cert) and os.path.isfile(key):
            return cert, key
    return '', ''


def cert_expires_days(path):
    """Сколько дней осталось сертификату; None — если не прочитался."""
    out, _, rc = run_cmd('openssl x509 -in %s -noout -enddate' % path)
    if rc != 0 or '=' not in out:
        return None
    import calendar
    import email.utils as _eu
    try:
        ts = _eu.parsedate_tz(out.split('=', 1)[1].strip().replace(' GMT', ' +0000'))
        if not ts:
            return None
        exp = calendar.timegm(ts[:9]) - (ts[9] or 0)
        return int((exp - time.time()) // 86400)
    except Exception:
        return None


# Сертификат читают при старте все, кто его использует, а не одна Hysteria:
# nginx (панель на своём порту и локальный фоллбек-блок) и XRay в режиме TLS.
# Пока хук трогал только Hysteria, после перевыпуска nginx продолжал отдавать
# просроченный серт — внешний мониторинг падал с CERTIFICATE_VERIFY_FAILED,
# хотя сертификат на диске был уже новый.
RENEW_HOOK_BODY = (
    '#!/bin/sh\n'
    '# Создано панелью awg-panel: сертификат перечитывается только при старте,\n'
    '# поэтому после перевыпуска надо поднять всех его потребителей.\n'
    'systemctl try-restart %s.service\n'
    'systemctl reload nginx 2>/dev/null || true\n'
    '# XRay держит сертификат только в режиме TLS; при Reality файла в конфиге\n'
    '# нет и перезапуск не нужен — лишний разрыв сессий ни к чему.\n'
    'if grep -q certificateFile /usr/local/etc/xray/config.json 2>/dev/null; then\n'
    '    systemctl try-restart xray.service\n'
    'fi\n' % UNIT_NAME
)


def renew_hook_installed():
    """Хук есть, исполняем и умеет поднимать не только Hysteria."""
    if not (os.path.isfile(LE_DEPLOY_HOOK) and os.access(LE_DEPLOY_HOOK, os.X_OK)):
        return False
    try:
        with open(LE_DEPLOY_HOOK, 'r', encoding='utf-8') as f:
            body = f.read()
    except Exception:
        return False
    # Старый вариант хука (только hysteria) считаем неполным: он и приводил к
    # тому, что nginx оставался на просроченном сертификате.
    return 'nginx' in body


def install_renew_hook():
    """Ставит deploy-hook certbot и сразу применяет его к текущему сертификату."""
    try:
        os.makedirs(os.path.dirname(LE_DEPLOY_HOOK), exist_ok=True)
        with open(LE_DEPLOY_HOOK, 'w', encoding='utf-8') as f:
            f.write(RENEW_HOOK_BODY)
        os.chmod(LE_DEPLOY_HOOK, 0o755)
    except Exception as e:
        return False, str(e)
    # Выполняем сразу: сертификат мог быть перевыпущен до появления хука, и
    # тогда сервисы прямо сейчас работают на старом.
    run_cmd(LE_DEPLOY_HOOK)
    audit('info', 'установлен deploy-hook certbot (hysteria + nginx + xray) и применён')
    return True, 'хук установлен, сервисы перечитали сертификат'


def heal_renew_hook():
    """Переписать deploy-hook, если он лежит от прошлой версии панели.

    Хук живёт вне папки панели, и обновление его не трогает: старый вариант
    (только hysteria, без nginx) так и остался бы, пока кто-то не нажмёт кнопку.
    Только перезапись файла, без запуска: запуск перезапустил бы сервисы на
    каждом старте панели. Нет хука — не создаём: значит LE тут не используется.
    """
    try:
        if not os.path.isfile(LE_DEPLOY_HOOK):
            return False
        with open(LE_DEPLOY_HOOK, 'r', encoding='utf-8') as f:
            if f.read() == RENEW_HOOK_BODY and os.access(LE_DEPLOY_HOOK, os.X_OK):
                return False
        with open(LE_DEPLOY_HOOK, 'w', encoding='utf-8', newline='\n') as f:
            f.write(RENEW_HOOK_BODY)
        os.chmod(LE_DEPLOY_HOOK, 0o755)
        audit('info', 'deploy-hook certbot обновлён до текущей версии')
        return True
    except Exception:
        return False


def renew_timer_active():
    """Есть ли автообновление сертификатов (systemd-таймер certbot или cron)."""
    out, _, _ = run_cmd('systemctl list-timers --all --no-pager 2>/dev/null | grep -i certbot')
    if out.strip():
        return True
    out, _, _ = run_cmd('ls /etc/cron.d/certbot /etc/cron.daily/certbot 2>/dev/null')
    return bool(out.strip())


LE_RENEWAL_DIR = '/etc/letsencrypt/renewal'


def le_renewal_conf(domain=''):
    """(путь_к_renewal_конфигу, имя_сертификата) или ('', '').

    Имя сертификата не всегда равно домену: при повторных выпусках certbot
    добавляет суффикс -0001, а `certbot renew --cert-name` ждёт именно его.
    """
    domain = (domain or '').strip().lower()
    if not domain or not os.path.isdir(LE_RENEWAL_DIR):
        return '', ''
    for name in sorted(os.listdir(LE_RENEWAL_DIR)):
        if not name.endswith('.conf'):
            continue
        base = name[:-5]
        if base.lower() != domain and base.split('-0')[0].lower() != domain:
            continue
        return os.path.join(LE_RENEWAL_DIR, name), base
    return '', ''


def le_authenticator(domain=''):
    """Плагин, которым сертификат выпускался: 'nginx' / 'standalone' / 'webroot' / ''."""
    path, _ = le_renewal_conf(domain)
    if not path:
        return ''
    try:
        with open(path, 'r', encoding='utf-8') as f:
            m = re.search(r'^\s*authenticator\s*=\s*(\S+)', f.read(), re.M)
        return m.group(1).strip().lower() if m else ''
    except Exception:
        return ''


def tcp_port_owner(port):
    """Кто слушает TCP-порт: имя процесса или '' если свободен."""
    fn = DEPS.get('port_owner')
    if fn:
        try:
            return fn(port, 'tcp') or ''
        except Exception:
            pass
    out, _, _ = run_cmd("ss -tlnp 2>/dev/null | grep -E ':%d\\b'" % int(port))
    if not out.strip():
        return ''
    m = re.search(r'users:\(\("([^"]+)"', out)
    return m.group(1) if m else 'неизвестный процесс'


# --- ACME-челлендж по HTTP ---------------------------------------------------
#
# Продление ломается там, где 80-й порт занят голым `return 301 https://...`:
# Let's Encrypt идёт за челленджем по HTTP, получает редирект на 443, а там
# XRay — он обслуживает только свой serverName и на любом другом имени (www.…)
# рвёт рукопожатие. Лечится тем, что каталог челленджа отдаётся по HTTP до
# редиректа, и тогда 443 в проверке вообще не участвует.
ACME_WEBROOT = '/var/www/acme'
ACME_MARK = 'awg-panel: acme-challenge'
ACME_LOCATION = (
    '\n    # %s — челлендж обязан отдаваться по HTTP ДО редиректа на https,\n'
    '    # иначе проверка домена упирается в TLS на 443 (там XRay) и падает.\n'
    '    location ^~ /.well-known/acme-challenge/ {\n'
    '        root %s;\n'
    '        default_type "text/plain";\n'
    '        try_files $uri =404;\n'
    '    }\n' % (ACME_MARK, ACME_WEBROOT)
)


def _nginx_conf_files():
    """Файлы конфигов nginx, которые могут содержать server-блоки."""
    out = []
    for d in ('/etc/nginx/sites-enabled', '/etc/nginx/conf.d'):
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.realpath(os.path.join(d, name))
            if os.path.isfile(p) and p not in out:
                out.append(p)
    return out


def _server_blocks(text):
    """Границы всех server{...} в конфиге: [(start, end), ...]."""
    blocks = []
    for m in re.finditer(r'\bserver\s*\{', text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    blocks.append((m.start(), i + 1))
                    break
            i += 1
    return blocks


def _find_http_block(domain=''):
    """(файл, текст, начало, конец) server-блока на 80 порту или (None,...).

    Предпочитаем блок, где домен указан в server_name: на сервере может быть
    несколько сайтов, и класть челлендж в чужой — значит не починить свой.
    """
    domain = (domain or '').strip().lower()
    fallback = None
    for path in _nginx_conf_files():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception:
            continue
        for start, end in _server_blocks(text):
            block = text[start:end]
            if not re.search(r'^\s*listen\s+(?:[\d.:\[\]]*:)?80\b', block, re.M):
                continue
            names = ' '.join(re.findall(r'^\s*server_name\s+([^;]+);', block, re.M)).lower()
            if domain and domain in names:
                return path, text, start, end
            if fallback is None:
                fallback = (path, text, start, end)
    return fallback if fallback else (None, '', 0, 0)


def _wrap_server_return(block):
    """Переносит `return 301 …` с уровня server внутрь `location /`.

    Без этого челлендж недостижим: `return` на уровне server отрабатывает в
    rewrite-фазе, ДО того как nginx выберет location, поэтому редирект съедает
    и запросы к /.well-known/. Внутри `location /` он ведёт себя как обычно —
    редиректит всё, кроме путей с более точным совпадением.
    """
    depth = 0
    for m in re.finditer(r'[{}]|^[ \t]*(return\s+30[12]\s+[^;]+;)[ \t]*$', block, re.M):
        tok = m.group(0)
        if tok == '{':
            depth += 1
            continue
        if tok == '}':
            depth -= 1
            continue
        # return нашёлся, но только на верхнем уровне блока (depth == 1)
        if depth != 1:
            continue
        stmt = m.group(1)
        wrapped = ('location / {\n        %s\n    }' % stmt)
        return block[:m.start(1)] + wrapped + block[m.end(1):]
    return block


def cert_domains(domain=''):
    """Имена из сертификата (SAN). Пусто — если прочитать не удалось.

    Проверять надо ровно те имена, которые Let's Encrypt будет валидировать при
    продлении. Хардкодить пару «домен + www» нельзя: у большинства сертификатов
    www нет вовсе, и проверка вечно показывала бы несуществующую проблему.
    """
    cert, _ = find_le_cert(domain or load_settings().get('sni') or '')
    if not cert:
        return []
    out, _, rc = run_cmd("openssl x509 -noout -ext subjectAltName -in '%s'" % cert)
    if rc != 0:
        return []
    names = re.findall(r'DNS:([^,\s]+)', out or '')
    seen, uniq = set(), []
    for n in names:
        n = n.strip().lower()
        # Wildcard проверять запросом бессмысленно, да и валидируется он только
        # через DNS-01, к HTTP-челленджу отношения не имеет.
        if not n or n.startswith('*') or n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


def acme_http_works(domain=''):
    """Реально ли челлендж отдаётся по HTTP. (ok, пояснение).

    Проверяем не наличием строки в конфиге, а живым запросом: кладём файл и
    забираем его через nginx под каждым именем сертификата. Продление валит
    любое из них, а не только основное: у этого сервера падал www, хотя сам
    домен отвечал нормально.
    """
    domain = (domain or load_settings().get('sni') or '').strip()
    if not domain:
        return False, 'домен не задан'
    hosts = cert_domains(domain) or [domain]
    d = os.path.join(ACME_WEBROOT, '.well-known', 'acme-challenge')
    probe = 'awg-panel-probe'
    path = os.path.join(d, probe)
    try:
        os.makedirs(d, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('ok')
    except Exception as e:
        return False, 'не удалось создать %s: %s' % (d, e)
    try:
        bad = []
        for host in hosts:
            # Таймаут короткий: проверка идёт на каждый показ списка зависимостей,
            # и запрос к своему же nginx по localhost либо отвечает сразу, либо
            # не ответит вовсе — ждать тут нечего.
            out, _, _ = run_cmd(
                "curl -s -m 2 -o /dev/null -w '%%{http_code}' -H 'Host: %s' "
                "http://127.0.0.1/.well-known/acme-challenge/%s" % (host, probe))
            if out.strip() != '200':
                bad.append('%s → %s' % (host, out.strip() or 'нет ответа'))
        if bad:
            return False, 'челлендж не отдаётся: %s' % '; '.join(bad)
        return True, ''
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def _acme_wait(domain, tries=8):
    """Ждёт, пока челлендж начнёт отдаваться. (ok, последняя_причина).

    `systemctl reload nginx` возвращает управление сразу, а воркеры перечитывают
    конфиг с задержкой — одиночная проверка сразу после reload успевает попасть
    на старые и увидеть прежний редирект.
    """
    why = ''
    for i in range(tries):
        ok, why = acme_http_works(domain)
        if ok:
            return True, ''
        time.sleep(1)
    return False, why


def ensure_acme_http(domain=''):
    """Публикует каталог челленджа в nginx до редиректа. (ok, сообщение).

    Конфиг правится с бэкапом и проверкой `nginx -t`: неудачная правка откатится,
    иначе падение nginx унесло бы с собой и доступ к панели.
    """
    domain = (domain or load_settings().get('sni') or '').strip()
    ok, _ = acme_http_works(domain)
    if ok:
        return True, 'челлендж уже отдаётся по HTTP'
    path, text, start, end = _find_http_block(domain)
    if not path:
        return False, ('в конфигах nginx нет server-блока на 80 порту — '
                       'добавить челлендж некуда')
    block = text[start:end]
    if ACME_MARK in block:
        # Строка есть, а запрос не проходит: правил её кто-то ещё или nginx не
        # перечитал конфиг. Перезагружаем и проверяем ещё раз.
        run_cmd('systemctl reload nginx')
        ok2, why = _acme_wait(domain)
        return (True, 'nginx перечитал конфиг') if ok2 else (False, why)
    block = _wrap_server_return(block)
    brace = block.find('{')
    if brace < 0:
        return False, 'не разобрал server-блок в %s' % path
    new_text = text[:start] + block[:brace + 1] + ACME_LOCATION + block[brace + 1:] + text[end:]
    backup = os.path.join(DATA_DIR, 'nginx-backup')
    stamp = time.strftime('%Y%m%d-%H%M%S')
    try:
        # Бэкап кладём в data/, а НЕ рядом с конфигом: nginx читает в
        # sites-enabled все файлы подряд и подхватил бы копию как второй сайт.
        os.makedirs(backup, exist_ok=True)
        with open(os.path.join(backup, '%s.%s' % (os.path.basename(path), stamp)),
                  'w', encoding='utf-8') as f:
            f.write(text)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_text)
    except Exception as e:
        return False, 'не удалось записать %s: %s' % (path, e)
    _, err, rc = run_cmd('nginx -t')
    if rc != 0:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        return False, 'nginx -t не прошёл, правка откачена: %s' % (err or '')[-400:]
    _, rerr, rrc = run_cmd('systemctl reload nginx')
    if rrc != 0:
        return False, 'nginx не перечитал конфиг: %s' % (rerr or '')[-300:]
    ok3, why = _acme_wait(domain)
    if not ok3:
        # Правка легла в конфиг, но запрос всё равно уходит не туда: значит Host
        # обслуживает другой server-блок (default_server из nginx.conf, отдельный
        # сайт). Показываем, что именно правили, чтобы не гадать.
        total, _, _ = run_cmd("nginx -T 2>/dev/null | grep -c 'acme-challenge'")
        return False, ('конфиг %s обновлён (вхождений acme-challenge в nginx -T: %s), но челлендж '
                       'всё равно не отдаётся: %s' % (path, total.strip() or '?', why))
    audit('info', 'в %s опубликован ACME-челлендж по HTTP' % os.path.basename(path))
    return True, 'челлендж опубликован в %s' % os.path.basename(path)


def _run_long(cmd, timeout=300):
    """Как run_cmd, но с большим таймаутом и понятной ошибкой вместо голого
    'timeout': у пакетного run_cmd потолок 120 с, а обращение к Let's Encrypt
    вместе с проверкой домена может идти дольше."""
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired as e:
        partial = ''
        for chunk in (e.stdout, e.stderr):
            if chunk:
                partial += chunk.decode('utf-8', 'replace') if isinstance(chunk, bytes) else chunk
        return partial.strip(), 'команда не завершилась за %d с' % timeout, 124


def renew_cert(domain='', force=False):
    """Перевыпуск сертификата Let's Encrypt из панели. (ok, сообщение).

    Метод выпуска не выбираем сами, а берём тот, что записан в renewal-конфиге:
    `certbot --nginx` дописывает в конфиг `listen 443 ssl`, а 443 занят XRay —
    после такого nginx не поднимется и панель отвалится вместе с ним. При
    renew плагин лишь подтверждает владение доменом, конфиг не переписывая.
    """
    cfg = load_settings()
    domain = (domain or cfg.get('sni') or '').strip()
    if not domain:
        return False, 'домен не задан — заполните SNI в настройках Hysteria'
    out, _, rc = run_cmd('command -v certbot')
    if rc != 0 or not out.strip():
        return False, 'certbot не установлен: apt install certbot'
    _, cert_name = le_renewal_conf(domain)
    if not cert_name:
        return False, ('в %s нет конфига для «%s» — этот сертификат certbot не выпускал'
                       % (LE_RENEWAL_DIR, domain))
    # --no-random-sleep-on-renew обязателен: в неинтерактивном режиме certbot
    # засыпает на случайное время до 8 минут, размазывая нагрузку от cron'ов по
    # всему миру. Здесь перевыпуск запустил человек и ждёт ответа — сон только
    # съедает таймаут и выглядит как зависание.
    cmd = ('certbot renew --cert-name %s --non-interactive --no-random-sleep-on-renew'
           % cert_name)
    # Если челлендж отдаётся по HTTP — валидируем через него, каким бы плагином
    # сертификат ни выпускался. Это единственный путь, не задевающий 443: там
    # XRay, и на именах вроде www.<домен> он рвёт TLS, заваливая проверку.
    # Не отдаётся — публикуем сами, а не ждём, пока пользователь найдёт
    # отдельную починку во вкладке Hysteria: перевыпуск зовут и из карточки
    # VLESS, и там certbot шёл по старому webroot, 80-й редиректил на https,
    # а панель за фоллбеком XRay отвечала 404 — «unauthorized».
    acme_ok = acme_http_works(domain)[0]
    owner80 = '' if acme_ok else tcp_port_owner(80)
    if not acme_ok and owner80:
        # На 80 кто-то есть (nginx) — standalone там не встанет, а webroot
        # заработает, как только каталог отдаётся до редиректа.
        acme_ok, acme_msg = ensure_acme_http(domain)
        if not acme_ok:
            return False, ('Let’s Encrypt проверяет домен по http://%s/.well-known/acme-challenge/, '
                           'а этот путь сейчас не отдаётся (80-й занят «%s», обычно он редиректит '
                           'на https). Опубликовать каталог в nginx не вышло: %s'
                           % (domain, owner80, acme_msg))
    if acme_ok:
        # Именно --webroot-map, а не --webroot-path: при renew certbot
        # восстанавливает webroot_map из renewal-конфига, а path применяет
        # только к именам, которых в карте нет (setdefault в webroot.py). У
        # выпущенных с `-w /var/www/html` карта есть — файл челленджа ложился
        # туда, nginx отдавал /var/www/acme, и проверка снова падала. Новую
        # карту certbot запишет в renewal-конфиг — продлит сам и cron.
        import json as _json
        import shlex as _shlex
        names = ','.join(cert_domains(domain) or [domain])
        cmd += ' --webroot --webroot-map %s' % _shlex.quote(_json.dumps({names: ACME_WEBROOT}))
    if force:
        cmd += ' --force-renewal'
    out, err, rc = _run_long(cmd)
    tail = ((out or '') + '\n' + (err or '')).strip()[-1200:]
    if rc == 124:
        # Чаще всего это чужой процесс certbot держит свой лок и наш ждёт его.
        return False, ('certbot не ответил вовремя. Обычно так бывает, когда уже идёт другое '
                       'продление (certbot держит блокировку) — подождите пару минут и '
                       'повторите. Подробности: journalctl -u certbot, /var/log/letsencrypt/')
    if rc != 0:
        return False, 'certbot: %s' % (tail or 'ошибка без вывода')
    cert, _ = find_le_cert(domain)
    days = cert_expires_days(cert) if cert else None
    if days is not None and days <= 0:
        return False, ('certbot отработал, но сертификат всё ещё просрочен. %s' % tail)
    # Перезапуск нужен и при живом deploy-hook: hook мог быть поставлен только что,
    # а сервис всё ещё держит в памяти старый сертификат.
    if is_active():
        ok, err2 = restart()
        if not ok:
            return False, 'сертификат обновлён, но сервис не поднялся: %s' % err2
    audit('info', 'сертификат «%s» перевыпущен, осталось %s дн.' % (cert_name, days))
    return True, ('сертификат обновлён, срок — %d дн.' % days if days is not None
                  else 'сертификат обновлён')


def active_cert_paths():
    """Какие cert/key реально прописаны в конфиге сейчас."""
    cfg = load_settings()
    if (cfg.get('cert_mode') or 'self') == 'le':
        cert, key = find_le_cert(cfg.get('sni'))
        if cert:
            return cert, key
    return CERT_FILE, KEY_FILE


def ensure_cert(sni=''):
    """Самоподписанный сертификат в data/hysteria/.

    Свой, а не общий с XRay: иначе Hysteria зависела бы от режима XRay (при
    Reality живого серта нет вовсе) и ломалась бы при его обновлении. Клиент
    проверяет не цепочку, а pinSHA256 — подмена невозможна и без CA.
    """
    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        return True, cert_fingerprint()
    os.makedirs(DATA_DIR, exist_ok=True)
    cn = sni or 'hysteria.local'
    cmd = ('openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 '
           '-days 3650 -keyout %s -out %s -subj "/CN=%s" 2>/dev/null' % (KEY_FILE, CERT_FILE, cn))
    _, err, rc = run_cmd(cmd)
    if rc != 0:
        return False, 'openssl: %s' % (err or 'ошибка')
    os.chmod(KEY_FILE, 0o600)
    fp = cert_fingerprint()
    audit('info', 'выпущен self-signed сертификат (CN=%s)' % cn)
    return True, fp


# --- конфиг -----------------------------------------------------------------

def masquerade_block(cfg):
    """Секция masquerade для config.yaml.

    Два режима, и в конфиге это разные типы, а не разные значения одного поля:
    непустой адрес — `type: proxy` (hysteria сходит на чужой сайт и вернёт его
    ответ), пустой — `type: string` с кодом 404. Второй нужен там, где ходить
    наружу с сервера нельзя: проксирование выдаёт себя исходящими запросами к
    одному и тому же сайту с каждого чужого коннекта.
    """
    url = (cfg.get('masquerade_url') or '').strip()
    if url:
        return ['masquerade:', '  type: proxy', '  proxy:',
                '    url: %s' % url, '    rewriteHost: true']
    return ['masquerade:', '  type: string', '  string:',
            '    content: 404 page not found',
            '    headers:', '      content-type: text/plain; charset=utf-8',
            '    statusCode: 404']


def render_config(cfg=None):
    cfg = cfg or load_settings()
    # Свой self-signed или сертификат домена — решает cert_mode в настройках.
    _cert, _key = active_cert_paths()
    lines = [
        '# Файл создан панелью awg-panel из data/hysteria/settings.json.',
        '# Ручные правки будут перезаписаны при следующем применении настроек.',
        '',
        # Хоппинг — диапазон через запятую после основного порта: hysteria
        # слушает наименьший (основной), остальные перенаправляет на него.
        'listen: :%d%s' % (int(cfg.get('port') or 443),
                           (',' + hop_active(cfg)) if hop_active(cfg) else ''),
        '',
        'tls:',
        '  cert: %s' % _cert,
        '  key: %s' % _key,
        '',
        'auth:',
        '  type: command',
        '  command: %s' % AUTH_SCRIPT,
        '',
        'trafficStats:',
        '  listen: %s' % STATS_ADDR,
        '  secret: %s' % (cfg.get('stats_secret') or ''),
        '',
    ]
    lines += masquerade_block(cfg)
    obfs = (cfg.get('obfs_password') or '').strip()
    if obfs:
        lines += ['', 'obfs:', '  type: salamander', '  salamander:', '    password: %s' % obfs]
    # sniff — сервер вычитывает домен из начала соединения (TLS SNI, HTTP Host,
    # QUIC), когда клиент прислал голый IP. Тогда доменные правила (acl) и
    # журнал назначений работают и для такого трафика. По умолчанию выключен:
    # Shadowrocket/Loon/Clash обычно и так шлют домен, а на старте TCP sniff
    # ждёт первые байты (timeout — только TCP с 2.13.0).
    if cfg.get('sniff'):
        lines += ['', 'sniff:', '  enable: true', '  timeout: 2s']
    up, down = int(cfg.get('up_mbps') or 0), int(cfg.get('down_mbps') or 0)
    if up or down:
        lines += ['', 'bandwidth:']
        if up:
            lines.append('  up: %d mbps' % up)
        if down:
            lines.append('  down: %d mbps' % down)
    # Аутбаунды и acl — из глобальных правил. Импорт локальный: rules зовёт
    # service.write_config(), и на верхнем уровне это был бы цикл.
    try:
        from . import rules
        lines += rules.config_block()
    except Exception as e:
        audit('warn', 'блок правил не собрался, конфиг без него: %s' % e)
    return '\n'.join(lines) + '\n'


def write_config(cfg=None):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = '%s.tmp' % CONFIG_FILE
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(render_config(cfg))
    os.replace(tmp, CONFIG_FILE)


def write_unit(cfg=None):
    cfg = cfg or load_settings()
    # Уровень лога задаётся только переменными окружения — в config.yaml такого
    # ключа у hysteria нет. Назначения (куда именно ходил клиент) пишутся лишь
    # на debug, поэтому журнал включается сменой уровня, а json-формат берём
    # чтобы парсить строки, а не разбирать текст zap-консоли.
    env = ''
    if cfg.get('access_log'):
        env = 'Environment=HYSTERIA_LOG_LEVEL=debug\nEnvironment=HYSTERIA_LOG_FORMAT=json\n'
    body = (
        '[Unit]\n'
        'Description=Hysteria 2 server (awg-panel)\n'
        'After=network.target\n'
        '\n'
        '[Service]\n'
        'Type=simple\n'
        '%s'
        'ExecStart=%s server -c %s\n'
        'WorkingDirectory=%s\n'
        'Restart=on-failure\n'
        'RestartSec=5\n'
        'LimitNOFILE=infinity\n'
        # Логи идём в общий каталог логов панели: там их подхватывает logrotate
        # по маске *.log, отдельное правило не нужно.
        'StandardOutput=append:%s\n'
        'StandardError=append:%s\n'
        '\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
    ) % (env, BIN_PATH, CONFIG_FILE, DATA_DIR, ACCESS_LOG, ACCESS_LOG)
    with open(UNIT_FILE, 'w', encoding='utf-8') as f:
        f.write(body)
    run_cmd('systemctl daemon-reload')


# --- жизненный цикл ---------------------------------------------------------

def is_active():
    out, _, _ = run_cmd('systemctl is-active %s' % UNIT_NAME)
    return out.strip() == 'active'


def is_enabled():
    out, _, _ = run_cmd('systemctl is-enabled %s' % UNIT_NAME)
    return out.strip() in ('enabled', 'enabled-runtime')


def restart():
    """Перезапуск с реальной проверкой исхода, а не по коду возврата systemctl."""
    run_cmd('systemctl restart %s' % UNIT_NAME)
    time.sleep(2)
    if is_active():
        return True, ''
    out, _, _ = run_cmd('journalctl -u %s -n 20 --no-pager' % UNIT_NAME)
    return False, out[-1500:]


def stopped_by_hand():
    """Сервис остановлен штатно (inactive), а не упал (failed).

    Различие важно: упавший сервис правка настроек как раз должна поднять
    (типично — сменили занятый порт), а остановленный руками — нет."""
    out, _, _ = run_cmd('systemctl is-active %s' % UNIT_NAME)
    return out.strip() == 'inactive'


def apply_changes():
    """Подхватить изменённый конфиг. (ok, ошибка).

    Остановленный руками сервис не поднимаем: правка настроек — не команда
    «запустить», а раньше любое сохранение молча запускало его. Конфиг к этому
    моменту уже записан — применится при следующем старте. Упавший (failed)
    перезапускаем: правка могла быть как раз починкой."""
    if stopped_by_hand():
        return True, ''
    return restart()


def stop():
    run_cmd('systemctl stop %s' % UNIT_NAME)
    return not is_active()


def udp_port_owner(port):
    """Кто слушает UDP-порт: имя процесса или '' если свободен.

    Берём панельный метод (тот же, что питает «Источники правды»), чтобы
    занятость портов считалась в одном месте. Проверяем ДО запуска: иначе
    hysteria падает с exit 1, а причина остаётся закопанной в логе сервиса.
    """
    fn = DEPS.get('port_owner')
    if fn:
        try:
            return fn(port, 'udp') or ''
        except Exception:
            pass
    out, _, _ = run_cmd("ss -ulnp 2>/dev/null | grep -E ':%d\\b'" % int(port))
    if not out.strip():
        return ''
    m = re.search(r'users:\(\("([^"]+)"', out)
    return m.group(1) if m else 'неизвестный процесс'


# Запасные UDP-порты, если основной занят. 443 стоит первым не случайно: он
# меньше всего похож на VPN со стороны наблюдателя. Дальше — порты, которые
# обычно свободны и не выглядят экзотикой в трафике.
PORT_CANDIDATES = [443, 2096, 8443, 20443, 36712]


def pick_free_port(preferred=443):
    """Свободный UDP-порт: сначала желаемый, потом запасные из списка.

    Подбор общий с остальными протоколами — панель отдаёт его через DEPS, чтобы
    список запасных портов и правила выбора жили в одном месте. Свой перебор
    остаётся запасным путём: пакет должен работать и при старой панели.
    """
    preferred = int(preferred or 443)
    fn = DEPS.get('pick_free_port')
    if fn:
        try:
            port, why = fn(preferred)
            return port, ('' if port else (why or 'свободных UDP-портов не нашлось'))
        except Exception:
            pass
    for port in [preferred] + [p for p in PORT_CANDIDATES if p != preferred]:
        if not udp_port_owner(port):
            return port, ''
    return 0, 'все запасные UDP-порты заняты'


def port_conflict(port, include_idle=False):
    """Кто помешает занять UDP-порт, словами панели. '' — свободно.

    Ответ даёт реестр портов панели (port_conflict в app.py), а не свой `ss`:
    участников у UDP теперь трое — Hysteria, AmneziaWG и инбаунд Hysteria внутри
    XRay, — и каждый лежит в своём файле. Сокет AWG вдобавок живёт в ядре и в
    `ss -ulnp` нередко идёт без имени процесса, так что «никто не слушает» там
    не означает «порт свободен».
    """
    fn = DEPS.get('port_conflict')
    if fn:
        try:
            return fn(int(port or 0), 'udp', 'hysteria', include_idle) or ''
        except Exception:
            pass
    owner = udp_port_owner(port)
    return ('%s/udp уже слушает %s' % (int(port or 0), owner)) if owner else ''


def port_clash(port=None):
    """(конфликт, кандидат) по UDP-порту. Один расчёт на плитку, форму и модалку.

    Конфликт считаем всегда, даже когда сервис лежит: именно так он и всплывает —
    при старте, когда номер уже занял сосед.

    Кандидата ищем ТОЛЬКО при конфликте. Иначе подбор всегда возвращал бы
    запасной номер: на рабочем сервере наш же порт слушает сама hysteria, и для
    pick_free_port он выглядит занятым — кнопка «Подобрать свободный» уводила бы
    с исправного порта на другой.
    """
    port = int(port or load_settings().get('port') or 443)
    clash = port_conflict(port, include_idle=True)
    if not clash:
        return '', 0
    alt, _ = pick_free_port(0)
    alt = int(alt or 0)
    return clash, (alt if alt != port else 0)


def port_state():
    """Состояние порта для плитки и модалки смены: сам порт, конфликт и кандидат."""
    port = int(load_settings().get('port') or 443)
    clash, suggested = port_clash(port)
    return {
        'port': port,
        'proto': 'udp',
        'conflict': clash,
        'suggested_port': suggested,
        'active': is_active(),
        'installed': bin_installed(),
        'listener': udp_port_owner(port),
    }


def set_port(new_port):
    """Сменить UDP-порт: конфиг → фаервол → рестарт, с откатом. (ok, blob|ошибка).

    Порт зашит в каждую выданную ссылку, поэтому операция всегда означает
    перевыдачу — об этом предупреждает UI. Откат обязателен: если сервис не
    поднялся на новом номере, оставить его лежащим хуже, чем вернуть старый.
    """
    try:
        new_port = int(new_port or 0)
    except (TypeError, ValueError):
        return False, 'порт должен быть числом'
    if not 1 <= new_port <= 65535:
        return False, 'порт вне диапазона 1–65535'
    cfg = load_settings()
    old_port = int(cfg.get('port') or 443)
    if new_port == old_port:
        return True, dict(port_state(), unchanged=True, old_port=old_port)
    clash = port_conflict(new_port)
    if clash:
        return False, clash
    # Закреплён за остановленным соседом — не запрет, а предупреждение: занять
    # можно, но при его старте номер достанется тому, кто поднимется первым.
    idle_warn = port_conflict(new_port, include_idle=True)

    cfg['port'] = new_port
    save_settings(cfg)
    heal_hop_range()
    cfg = load_settings()
    if not bin_installed():
        # Сервиса ещё нет — намерение сохранено, применится при установке.
        return True, dict(port_state(), old_port=old_port, warning=idle_warn)
    write_config(cfg)
    # Порт открываем ДО старта: иначе сервис поднимется, а клиенты будут молча
    # упираться в таймаут — снаружи это неотличимо от «не работает».
    ensure_firewall(new_port)
    # Остановленный руками сервис не поднимаем — порт применится при старте.
    if stopped_by_hand():
        _close_firewall(old_port)
        audit('warn', 'UDP-порт %d → %d (сервис остановлен) — выданные ссылки нужно раздать заново'
              % (old_port, new_port))
        return True, dict(port_state(), old_port=old_port, warning=idle_warn)
    ok, err = restart()
    if not ok:
        cfg['port'] = old_port
        save_settings(cfg)
        write_config(cfg)
        restart()
        audit('warn', 'смена порта откачена: на %d сервис не поднялся' % new_port)
        return False, 'на %d/udp сервис не поднялся, порт возвращён на %d: %s' % (
            new_port, old_port, (err or '')[-400:])
    _close_firewall(old_port)
    audit('warn', 'UDP-порт %d → %d — выданные ссылки нужно раздать заново' % (old_port, new_port))
    return True, dict(port_state(), old_port=old_port, warning=idle_warn)


def _close_firewall(port):
    """Снимает правило ufw со старого порта, если на нём больше никого нет.

    Проверка обязательна: на одном номере могли сидеть и другие наши сервисы
    (UDP-порт делится с AmneziaWG), и снятое правило оставило бы их снаружи
    недоступными.
    """
    try:
        port = int(port or 0)
        if not port or udp_port_owner(port):
            return
        # Порт может держать и лежащий сосед (AWG в awg0.conf): снимем правило —
        # при его старте клиенты упрутся в закрытый фаервол.
        if port_conflict(port, include_idle=True):
            return
        state, _ = firewall_state()
        if state != 'active':
            return
        run_cmd('ufw delete allow %d/udp' % port)
    except Exception:
        pass


def firewall_state():
    """('active'|'inactive'|'absent', правило_есть) — состояние ufw по нашему порту."""
    out, _, rc = run_cmd('ufw status 2>/dev/null')
    if rc != 0 or not out:
        return 'absent', False
    return ('active' if 'Status: active' in out else 'inactive'), out


def ensure_firewall(port):
    """Открывает UDP-порт в ufw, если тот включён. Возвращает (сделано, текст).

    Как и подбор порта, это общий панельный механизм; свой путь — на случай
    старой панели, где его ещё нет.
    """
    fn = DEPS.get('open_firewall')
    if fn:
        try:
            return fn(port)
        except Exception:
            pass
    state, out = firewall_state()
    if state != 'active':
        return False, ''
    rule = '%d/udp' % int(port)
    if out and rule in out:
        return False, ''
    _, err, rc = run_cmd("ufw allow %s comment 'Hysteria (awg-panel)'" % rule)
    if rc != 0:
        audit('warn', 'не удалось открыть %s в ufw: %s' % (rule, err))
        return False, err
    audit('info', 'в ufw открыт %s' % rule)
    return True, ''


# --- порт-хоппинг ------------------------------------------------------------
#
# ТСПУ режет и душит долгий UDP-поток на одном порту. С хоппингом клиент раз в
# hop_interval секунд переходит на другой порт диапазона, а сервер принимает их
# все: hysteria слушает ОДИН порт и сама ставит nft/iptables-редирект с остальных
# (app/internal/firewall), снимая его при остановке.
#
# Основной порт при этом не меняется — диапазон только добавляется. Старые
# ссылки и QR работают как работали; хоппинг получают профили по подписке
# (обновляются сами) и новые ссылки. Перевыдавать никому ничего не нужно.
#
# Тонкости, сверенные по исходникам hysteria:
# * порты в listen сортируются (PortUnion.Normalize), и слушает сервер НАИМЕНЬШИЙ.
#   Поэтому весь диапазон обязан лежать выше основного порта — иначе hysteria
#   переедет на начало диапазона и старые ссылки умрут;
# * всё, что пришло на порт диапазона, уходит в hysteria — диапазон не должен
#   задевать чужие UDP-службы (AWG, XDNS, Hysteria в XRay);
# * до 2.12.3 правило в OUTPUT заворачивало и исходящий UDP самого сервера на
#   порты диапазона (исправлено в 2.12.3) — на старом бинаре не включаем.
HOP_MIN_VERSION = 'v2.12.3'
HOP_DEFAULT_INTERVAL = 30
HOP_SIZE = 10000
# Кандидаты по порядку. Ниже 32768: там начинаются эфемерные порты, с которых
# сам сервер ходит наружу, — держимся от них подальше, хоть ответы на свои
# запросы conntrack и не перенаправляет.
HOP_CANDIDATES = [(20000, 29999), (10000, 19999), (30000, 32767), (40000, 49999)]


def _ver_tuple(v):
    m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', str(v or ''))
    return tuple(int(x) for x in m.groups()) if m else None


def hop_supported():
    """(можно, почему нет). Бинарь достаточно свежий и есть чем ставить редирект."""
    ver = installed_version()
    if ver and _ver_tuple(ver) < _ver_tuple(HOP_MIN_VERSION):
        return False, ('нужна Hysteria %s или новее (установлена %s) — обновите её в блоке версий'
                       % (HOP_MIN_VERSION, ver))
    out, _, _ = run_cmd('command -v nft || command -v iptables')
    if not out.strip():
        return False, 'нет ни nft, ни iptables — hysteria нечем перенаправить диапазон портов'
    return True, ''


def _parse_range(text):
    m = re.match(r'^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$', str(text or ''))
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if not (1 <= a < b <= 65535):
        return None
    return a, b


def _reserved_udp_ports():
    """UDP-порты, которые диапазон задевать не должен: реестр панели (включая
    остановленные сервисы — они заберут порт при старте) и реальные слушатели.
    Самой hysteria в списке нет."""
    fn = DEPS.get('udp_reserved_ports')
    if fn:
        try:
            return set(int(p) for p in (fn() or []))
        except Exception:
            pass
    out, _, _ = run_cmd('ss -ulnp 2>/dev/null')
    ports = set()
    for line in (out or '').splitlines()[1:]:
        if 'hysteria' in line:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[4].rpartition(':')[2].isdigit():
            ports.add(int(parts[4].rpartition(':')[2]))
    return ports


def pick_hop_range(port=None):
    """Свободный диапазон выше основного порта. ('20000-29999', '') или ('', почему)."""
    port = int(port or load_settings().get('port') or 443)
    busy = _reserved_udp_ports()
    for a, b in HOP_CANDIDATES:
        if a <= port:
            continue
        if any(a <= p <= b for p in busy):
            continue
        return '%d-%d' % (a, b), ''
    # Основной порт высокий — пробуем окно сразу над ним.
    a = port + 1
    b = min(65535, a + HOP_SIZE - 1)
    if b - a >= 99 and not any(a <= p <= b for p in busy):
        return '%d-%d' % (a, b), ''
    return '', 'не нашлось диапазона выше основного порта %d без чужих UDP-служб' % port


def hop_active(cfg=None):
    """Диапазон, который реально идёт в конфиг и профили, или ''. Включено, бинарь
    подходит, диапазон валиден и лежит выше основного порта."""
    cfg = cfg or load_settings()
    if not cfg.get('hop_enabled'):
        return ''
    rng = _parse_range(cfg.get('hop_range'))
    if not rng or rng[0] <= int(cfg.get('port') or 443):
        return ''
    if not hop_supported()[0]:
        return ''
    return '%d-%d' % rng


def hop_interval(cfg=None):
    cfg = cfg or load_settings()
    try:
        return max(5, int(cfg.get('hop_interval') or HOP_DEFAULT_INTERVAL))
    except (TypeError, ValueError):
        return HOP_DEFAULT_INTERVAL


def _ufw_range(rng):
    return rng.replace('-', ':') + '/udp'


def _hop_firewall(rng, open_=True):
    """Диапазон в ufw. Редирект стоит в nat PREROUTING, и до INPUT пакет доходит
    уже с основным портом, — но правило не мешает и страхует от конфигураций,
    где фильтр стоит раньше nat."""
    if not rng:
        return
    state, out = firewall_state()
    if state != 'active':
        return
    rule = _ufw_range(rng)
    if open_:
        if out and rule in out:
            return
        _, err, rc = run_cmd("ufw allow %s comment 'Hysteria port hopping (awg-panel)'" % rule)
        if rc != 0:
            audit('warn', 'не удалось открыть %s в ufw: %s' % (rule, err))
    else:
        run_cmd('ufw delete allow %s' % rule)


def set_hop(enabled):
    """Включить/выключить хоппинг: диапазон → конфиг → ufw → рестарт, с откатом.
    (ok, состояние|ошибка). Ссылки клиентов не меняются — основной порт тот же."""
    cfg = load_settings()
    old = dict(cfg)
    old_rng = hop_active(cfg)
    if enabled:
        ok, why = hop_supported()
        if not ok:
            return False, why
        rng = _parse_range(cfg.get('hop_range'))
        port = int(cfg.get('port') or 443)
        busy = _reserved_udp_ports()
        if not rng or rng[0] <= port or any(rng[0] <= p <= rng[1] for p in busy):
            new_rng, why = pick_hop_range(port)
            if not new_rng:
                return False, why
            cfg['hop_range'] = new_rng
        cfg['hop_enabled'] = True
        cfg.setdefault('hop_interval', HOP_DEFAULT_INTERVAL)
    else:
        cfg['hop_enabled'] = False
    save_settings(cfg)
    if not bin_installed():
        return True, hop_state()
    new_rng = hop_active(cfg)
    write_config(cfg)
    _hop_firewall(new_rng, True)
    if not stopped_by_hand():
        ok, err = restart()
        if not ok:
            save_settings(old)
            write_config(old)
            restart()
            if new_rng and new_rng != old_rng:
                _hop_firewall(new_rng, False)
            audit('warn', 'хоппинг не применён: сервис не поднялся — возвращено как было')
            return False, 'сервис не поднялся, вернули как было: %s' % (err or '')[-400:]
    if old_rng and old_rng != new_rng:
        _hop_firewall(old_rng, False)
    audit('info', ('порт-хоппинг включён: %s/udp → %s, смена раз в %d с'
                   % (new_rng, cfg.get('port'), hop_interval(cfg))) if new_rng
          else 'порт-хоппинг выключен')
    return True, hop_state()


def hop_state():
    cfg = load_settings()
    ok, why = hop_supported() if bin_installed() else (True, '')
    return {
        'enabled': bool(cfg.get('hop_enabled')),
        'active': hop_active(cfg),
        'range': cfg.get('hop_range') or '',
        'interval': hop_interval(cfg),
        'supported': ok,
        'why': why,
    }


def heal_hop_range():
    """Диапазон после смены основного порта: оказался ниже порта или налез на
    чужой — подбираем заново. Иначе hysteria переехала бы на начало диапазона."""
    cfg = load_settings()
    if not cfg.get('hop_enabled'):
        return False
    rng = _parse_range(cfg.get('hop_range'))
    port = int(cfg.get('port') or 443)
    if rng and rng[0] > port and not any(rng[0] <= p <= rng[1] for p in _reserved_udp_ports()):
        return False
    new_rng, _ = pick_hop_range(port)
    old = cfg.get('hop_range') or ''
    cfg['hop_range'] = new_rng
    if not new_rng:
        cfg['hop_enabled'] = False
    save_settings(cfg)
    if old and old != new_rng:
        _hop_firewall(old.replace(' ', ''), False)
    if new_rng:
        _hop_firewall(new_rng, True)
    audit('warn', 'диапазон хоппинга %s → %s' % (old or '—', new_rng or 'выключен: нет места'))
    return True


def setup(cfg=None):
    """Полная установка: порт → бинарь → сертификат → конфиг → юнит → запуск."""
    cfg = cfg or load_settings()
    wanted = int(cfg.get('port') or 443)
    note = ''
    # Спрашиваем реестр панели, а не только `ss`: сосед по UDP может быть не
    # виден в сокетах (AmneziaWG слушает из ядра) либо стоять на этом же номере
    # в своём конфиге, но сейчас лежать — оба случая ломают старт позже.
    busy_by = port_conflict(wanted) if not is_active() else ''
    if busy_by:
        port, err = pick_free_port(wanted)
        if not port:
            return False, ('UDP-порт %d занят («%s»), и свободных запасных не нашлось. '
                           'Укажите порт вручную в настройках Hysteria.' % (wanted, busy_by))
        note = ('UDP-порт %d занят («%s») — Hysteria поднята на %d.' % (wanted, busy_by, port))
        audit('warn', note)
        cfg['port'] = port
        save_settings(cfg)
    if not cfg.get('stats_secret'):
        import secrets
        cfg['stats_secret'] = secrets.token_hex(16)
        save_settings(cfg)
    fresh = not bin_installed()
    if fresh:
        ok, msg = install_binary()
        if not ok:
            return False, msg
    # Новая установка — сразу с хоппингом: ссылок ещё никто не получал, а для РФ
    # это главная защита UDP от удушения. На существующих серверах включается
    # кнопкой (плашка в «Чтобы Hysteria заработала»), молча не трогаем.
    if fresh and 'hop_enabled' not in cfg and hop_supported()[0]:
        rng, _ = pick_hop_range(cfg.get('port'))
        if rng:
            cfg.update({'hop_enabled': True, 'hop_range': rng, 'hop_interval': HOP_DEFAULT_INTERVAL})
            save_settings(cfg)
    if cfg.get('hop_enabled'):
        heal_hop_range()
        cfg = load_settings()
    ok, fp = ensure_cert(cfg.get('sni'))
    if not ok:
        return False, fp
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    try:
        os.chmod(AUTH_SCRIPT, 0o755)
    except Exception:
        pass
    write_config(cfg)
    write_unit(cfg)
    # Порт открываем ДО старта: если фаервол закрыт, сервис поднимется, но
    # клиенты будут молча получать таймаут — и это не отличить от «не работает».
    ensure_firewall(cfg.get('port'))
    _hop_firewall(hop_active(cfg), True)
    run_cmd('systemctl enable %s' % UNIT_NAME)
    ok, err = restart()
    if not ok:
        return False, 'сервис не поднялся: %s' % err
    audit('info', 'сервис установлен и запущен на UDP/%s' % cfg.get('port'))
    return True, note


def uninstall(purge_data=False):
    run_cmd('systemctl disable --now %s' % UNIT_NAME)
    for p in (UNIT_FILE,):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    run_cmd('systemctl daemon-reload')
    try:
        if os.path.exists(BIN_PATH):
            os.remove(BIN_PATH)
    except Exception:
        pass
    if purge_data:
        import shutil
        shutil.rmtree(DATA_DIR, ignore_errors=True)
    audit('warn', 'сервис удалён%s' % (' вместе с данными' if purge_data else ''))
    return True


def config_auth_path():
    """Какой скрипт авторизации прописан в существующем config.yaml. '' — нет файла."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('command:'):
                    return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return ''


def heal_auth_exec():
    """Вернуть auth.py бит +x. Обновление панели кладёт файлы из zip, а zipfile
    права не восстанавливает: после каждого наката скрипт приезжает 0644, hysteria
    не может его запустить и не пускает никого, хотя сервис «работает».
    Перезапуск не нужен — скрипт зовётся заново на каждое подключение."""
    try:
        if os.path.isfile(AUTH_SCRIPT) and not os.access(AUTH_SCRIPT, os.X_OK):
            os.chmod(AUTH_SCRIPT, 0o755)
            audit('warn', 'скрипту авторизации возвращён бит +x (слетел при обновлении)')
            return True
    except Exception:
        pass
    return False


def heal_auth_path():
    """Переписать конфиг, если в нём остался путь к auth.py из прошлой раскладки.

    Пакет переехал из <panel_root>/hysteria/ в <panel_root>/modules/hysteria/, а
    config.yaml на сервере генерировался до переезда и продолжает звать старый
    файл. Сам себя конфиг не перепишет: панель трогает его только при «Сохранить»
    и установке. Пока путь не поправлен, hysteria зовёт скрипт, которого может
    уже не быть, — сервис при этом «работает», а не пускает никого.
    """
    cur = config_auth_path()
    if not cur or cur == AUTH_SCRIPT:
        return False
    if not os.path.isfile(CONFIG_FILE):
        return False
    write_config()
    try:
        os.chmod(AUTH_SCRIPT, 0o755)
    except Exception:
        pass
    audit('warn', 'путь скрипта авторизации обновлён: %s → %s' % (cur, AUTH_SCRIPT))
    if is_active():
        restart()
    return True


def status():
    cfg = load_settings()
    _st_clash = port_clash(cfg.get('port'))
    return {
        'installed': bin_installed(),
        'active': is_active(),
        'enabled': is_enabled(),
        'version': installed_version(),
        'port': int(cfg.get('port') or 443),
        'has_cert': os.path.isfile(CERT_FILE),
        'fingerprint': cert_fingerprint(),
        'obfs': bool((cfg.get('obfs_password') or '').strip()),
        'cascade': bool(cfg.get('cascade')),
        'access_log': bool(cfg.get('access_log')),
        'sniff': bool(cfg.get('sniff')),
        # Маскировочный сайт — то, что hysteria отдаёт чужому HTTP/3-запросу на
        # этот же порт. С адресом подключения его постоянно путают, поэтому он
        # едет в статус и показывается отдельной плиткой.
        'masquerade': (cfg.get('masquerade_url') or '').strip(),
        # Пустой адрес — это не «не задано», а выбранный режим: ядро отдаёт
        # посторонним голый 404. Плитка и настройки показывают разное, поэтому
        # режим едет отдельным полем, а не угадывается из пустой строки.
        'masquerade_mode': 'proxy' if (cfg.get('masquerade_url') or '').strip() else '404',
        'sni': (cfg.get('sni') or ''),
        # Конфликт по UDP — на плитку и в форму настроек: иначе столкновение
        # видно только тогда, когда сервис уже не поднялся. Кандидат едет рядом,
        # чтобы кнопке «Подобрать свободный» не нужен был отдельный запрос.
        'conflict': _st_clash[0],
        'suggested_port': _st_clash[1],
        'up_mbps': int(cfg.get('up_mbps') or 0),
        'down_mbps': int(cfg.get('down_mbps') or 0),
        'hop': hop_state(),
    }
