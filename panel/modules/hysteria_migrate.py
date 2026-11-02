"""Мастер миграции: старый протокол Hysteria → инбаунд Hysteria внутри XRay.

Панель больше не умеет Hysteria отдельным движком — протокол вырезан, его код и
вкладка удалены. Но на серверах, где он работал, остались клиенты, файлы, юниты
и сам демон, который держит UDP-порт. Этот модуль — временная вкладка, которая
появляется ТОЛЬКО там, где такие остатки найдены, и исчезает, когда их не стало.

Что он делает:
  1. читает старых клиентов прямо из JSON (код модуля уже удалён);
  2. переносит их в XRay, сохраняя пароль, имя и правила, — старые ссылки
     hysteria2:// продолжают работать, потому что инбаунд поднимается на том же
     порту, с той же обфускацией и тем же сертификатом;
  3. гасит демон и вычищает с сервера всё, что от него осталось;
  4. убирает сам себя.

Инвентарь не захардкожен: на разных серверах Hysteria ставили по-разному
(панелью и руками), поэтому следы ищутся по факту — каталоги, бинари, юниты и
deploy-хуки Let's Encrypt.
"""

import json
import os
import re
import secrets
import time

DEPS = {}

# Где искать остатки. Панельная установка — первые два, ручная — /etc/hysteria*.
PANEL_PKG_DIRNAME = 'hysteria'
PANEL_DATA_DIRNAME = 'hysteria'

EXTRA_DIRS = ['/etc/hysteria', '/etc/hysteria2']
BIN_GLOBS = ['/usr/local/bin/hysteria', '/usr/local/bin/hysteria.prev',
             '/usr/bin/hysteria', '/usr/local/bin/hysteria2']
UNIT_DIR = '/etc/systemd/system'
LE_HOOK_DIR = '/etc/letsencrypt/renewal-hooks/deploy'

# Флаг в server.json: вкладку закрыли руками, больше не показывать.
DISMISS_KEY = 'hysteria_migration_done'


def init(deps):
    DEPS.update(deps or {})
    return True


def audit(level, msg):
    fn = DEPS.get('audit')
    if fn:
        try:
            return fn(level, '[Миграция Hysteria] %s' % msg)
        except Exception:
            pass


def run_cmd(cmd):
    fn = DEPS.get('run_cmd')
    return fn(cmd) if fn else ('', 'run_cmd не проброшен', 1)


def _panel_root():
    return DEPS.get('panel_root') or os.path.dirname(os.path.abspath(__file__))


def _data_root():
    return DEPS.get('data_root') or os.path.join(_panel_root(), 'data')


def pkg_dir():
    return os.path.join(_panel_root(), PANEL_PKG_DIRNAME)


def data_dir():
    return os.path.join(_data_root(), PANEL_DATA_DIRNAME)


# --- инвентарь --------------------------------------------------------------

def _units():
    """Юниты systemd, похожие на Hysteria. Ищем по каталогу, а не по списку:
    панель ставила hysteria-server, руками обычно ставят hysteria2."""
    found = []
    try:
        for name in sorted(os.listdir(UNIT_DIR)):
            if not name.endswith('.service'):
                continue
            if 'hysteria' not in name.lower():
                continue
            path = os.path.join(UNIT_DIR, name)
            unit = name[:-len('.service')]
            st, _, _ = run_cmd('systemctl is-active %s' % unit)
            en, _, _ = run_cmd('systemctl is-enabled %s' % unit)
            found.append({'unit': unit, 'path': path,
                          'active': st.strip() == 'active',
                          'enabled': en.strip() == 'enabled'})
    except Exception:
        pass
    return found


def _le_hooks():
    out = []
    try:
        for name in sorted(os.listdir(LE_HOOK_DIR)):
            if 'hysteria' in name.lower():
                out.append(os.path.join(LE_HOOK_DIR, name))
    except Exception:
        pass
    return out


def _logs():
    out = []
    logs = os.path.join(_data_root(), 'logs')
    try:
        for name in sorted(os.listdir(logs)):
            if name.startswith('hysteria_access.log'):
                out.append(os.path.join(logs, name))
    except Exception:
        pass
    return out


def inventory():
    """Всё, что осталось от Hysteria на этом сервере.

    Отдельно помечаем панельную установку и ручную: у ручной свои каталог и
    юнит, панель про неё раньше не знала, но порт она занимает так же.
    """
    dirs, files = [], []
    for d in (pkg_dir(), data_dir()):
        if os.path.isdir(d):
            dirs.append({'path': d, 'kind': 'panel'})
    for d in EXTRA_DIRS:
        if os.path.isdir(d):
            dirs.append({'path': d, 'kind': 'manual'})
    for f in BIN_GLOBS:
        if os.path.isfile(f):
            files.append({'path': f, 'kind': 'bin'})
    for f in _le_hooks():
        files.append({'path': f, 'kind': 'le-hook'})
    for f in _logs():
        files.append({'path': f, 'kind': 'log'})
    units = _units()
    return {
        'dirs': dirs,
        'files': files,
        'units': units,
        'any': bool(dirs or files or units),
        'running': [u['unit'] for u in units if u['active']],
    }


def present():
    """Показывать ли вкладку. Скрытая руками вкладка больше не возвращается,
    даже если файлы ещё лежат — решение пользователя важнее находок."""
    cfg = DEPS.get('server_cfg') or {}
    if cfg.get(DISMISS_KEY):
        return False
    return inventory()['any']


# --- клиенты старого протокола ----------------------------------------------

def clients_file():
    return os.path.join(data_dir(), 'clients.json')


def settings_file():
    return os.path.join(data_dir(), 'settings.json')


def read_clients():
    """Клиенты из data/hysteria/clients.json. Код модуля удалён, поэтому читаем
    файл напрямую — формат простой список словарей."""
    try:
        with open(clients_file(), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def read_settings():
    """Настройки старого демона: порт, обфускация, маскировка, SNI.

    Нужны не для истории: чтобы клиент продолжил работать по старой ссылке,
    инбаунд XRay надо поднять ровно на этом порту и с этим salamander-паролем.
    """
    out = {}
    try:
        with open(settings_file(), encoding='utf-8') as f:
            out = json.load(f) or {}
    except Exception:
        out = {}
    # У ручной установки настройки лежат в своём yaml — вытащим хотя бы порт.
    if not out.get('port'):
        for d in EXTRA_DIRS:
            y = os.path.join(d, 'server.yaml')
            if not os.path.isfile(y):
                continue
            try:
                with open(y, encoding='utf-8') as f:
                    txt = f.read()
                m = re.search(r'^\s*listen:\s*:?(\d+)', txt, re.M)
                if m:
                    out['port'] = int(m.group(1))
                m2 = re.search(r'password:\s*(\S+)', txt)
                if m2 and not out.get('obfs_password'):
                    out['obfs_password'] = m2.group(1)
            except Exception:
                pass
    return out


LE_LIVE_DIR = '/etc/letsencrypt/live'


def old_cert_paths():
    """Самоподписанный серт старого демона — тот, отпечаток которого зашит в
    уже розданные ссылки (pinSHA256)."""
    return (os.path.join(data_dir(), 'cert.pem'),
            os.path.join(data_dir(), 'key.pem'))


def _find_le_cert(domain=''):
    """Повтор логики вырезанного service.find_le_cert: строго по домену, потому
    что в live/ обычно валяются каталоги давно мёртвых доменов."""
    domain = (domain or '').strip().lower()
    if not domain or not os.path.isdir(LE_LIVE_DIR):
        return '', ''
    try:
        names = os.listdir(LE_LIVE_DIR)
    except Exception:
        return '', ''
    for name in names:
        base = name.split('-0')[0].lower()   # certbot добавляет -0001 при дублях
        if base != domain and name.lower() != domain:
            continue
        cert = os.path.join(LE_LIVE_DIR, name, 'fullchain.pem')
        key = os.path.join(LE_LIVE_DIR, name, 'privkey.pem')
        if os.path.isfile(cert) and os.path.isfile(key):
            return cert, key
    return '', ''


def old_cert_mode():
    """Чем старый демон терминировал QUIC: 'le' или 'self'.

    Повторяет вырезанный service.cert_mode(): режим «домена» действовал только
    тогда, когда для sni реально находился сертификат Let's Encrypt, иначе
    демон молча работал на самоподписанном.
    """
    s = read_settings()
    if (s.get('cert_mode') or 'self') != 'le':
        return 'self'
    return 'le' if _find_le_cert(s.get('sni'))[0] else 'self'


def _fingerprint(path):
    if not path or not os.path.isfile(path):
        return ''
    out, _, rc = run_cmd("openssl x509 -in '%s' -noout -fingerprint -sha256" % path)
    if rc != 0:
        return ''
    m = re.search(r'=\s*([0-9A-Fa-f:]{20,})', out or '')
    return m.group(1).strip() if m else ''


def cert_plan():
    """Что будет с сертификатом при переносе — для отчёта и для самой миграции.

    Это самое опасное место всей миграции. В ссылке hysteria2:// у клиента
    зашит либо ничего (серт домена — проверяется цепочка), либо pinSHA256 —
    отпечаток конкретного самоподписанного сертификата. Подними инбаунд с
    другим сертификатом, и все 50 ссылок отвалятся на handshake одновременно,
    причём выглядеть это будет как «не работает интернет», а не как ошибка.
    """
    s = read_settings()
    sni = (s.get('sni') or '').strip()
    mode = old_cert_mode()
    plan = {'mode': mode, 'sni': sni, 'action': '', 'warning': '', 'fingerprint': ''}
    if mode == 'le':
        # Серт домена лежит в /etc/letsencrypt — панель найдёт его сама. Ссылки
        # без пиннинга, проверяется цепочка: важно лишь, чтобы XRay поднялся с
        # сертификатом на ТОТ ЖЕ домен, что записан в ссылке (sni=...).
        panel = (DEPS.get('panel_tls_cert') or (lambda: {}))() or {}
        pdomain = (panel.get('domain') or '').strip().lower()
        plan['action'] = 'le'
        plan['panel_domain'] = pdomain
        if not panel.get('fullchain'):
            plan['warning'] = ('старый протокол работал на сертификате Let\'s Encrypt для «%s», '
                               'а панель сертификата не нашла — инбаунд поднимется на '
                               'самоподписанном, и старые ссылки перестанут проходить проверку '
                               'сертификата' % (sni or '—'))
        elif sni and pdomain and pdomain != sni.lower():
            plan['warning'] = ('в старых ссылках sni=%s, а панель терминирует QUIC '
                               'сертификатом домена %s — имена не совпадают, клиенты получат '
                               'ошибку проверки сертификата' % (sni, pdomain))
        return plan
    cert, key = old_cert_paths()
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        plan['action'] = 'missing'
        plan['warning'] = ('самоподписанный сертификат старого протокола не найден (%s) — '
                           'отпечаток в розданных ссылках восстановить нечем, клиентам '
                           'придётся раздать новые' % cert)
        return plan
    plan['action'] = 'copy'
    plan['fingerprint'] = _fingerprint(cert)
    return plan


XRAY_LE_HOOK = os.path.join(LE_HOOK_DIR, 'awg-panel-xray.sh')

XRAY_LE_HOOK_BODY = """#!/bin/sh
# awg-panel: после перевыпуска сертификата XRay должен перечитать его с диска.
# Инбаунд Hysteria терминирует QUIC этим же сертификатом, а файлы читаются при
# старте процесса — без перезапуска клиенты упрутся в просроченный сертификат.
systemctl is-active --quiet xray && systemctl restart xray
exit 0
"""


def install_xray_le_hook():
    """Поставить deploy-хук certbot, перезапускающий XRay. (ok, ошибка).

    Пока Hysteria была отдельным демоном, её перезапускал собственный хук — а
    его снесёт purge. Сертификат остаётся тот же, меняется только кто его
    держит, поэтому хук нужен снова, уже на xray. Имя намеренно без слова
    «hysteria»: иначе его подберёт инвентарь и удалит вместе с остальным.
    """
    try:
        os.makedirs(LE_HOOK_DIR, exist_ok=True)
        with open(XRAY_LE_HOOK, 'w', encoding='utf-8', newline='\n') as f:
            f.write(XRAY_LE_HOOK_BODY)
        os.chmod(XRAY_LE_HOOK, 0o755)
    except Exception as e:
        return False, str(e)
    return True, ''


def adopt_cert():
    """Отдать инбаунду XRay сертификат старого демона. (ok, заметка, ошибка).

    Для серта домена копировать нечего — источник общий, /etc/letsencrypt, —
    но нужен deploy-хук: перезапускать после перевыпуска теперь придётся xray.
    """
    xhy = DEPS.get('xhy')
    if not xhy:
        return False, '', 'модуль инбаунда не подключён'
    plan = cert_plan()
    if plan['action'] == 'le':
        hook_ok, hook_err = install_xray_le_hook()
        note = 'сертификат домена — общий с панелью'
        note += (', хук перевыпуска переставлен на xray' if hook_ok
                 else ', хук перевыпуска поставить не удалось: %s' % hook_err)
        if plan['warning']:
            note += ', ВНИМАНИЕ: ' + plan['warning']
        return True, note, ''
    if plan['action'] == 'missing':
        return False, '', plan['warning']

    src_cert, src_key = old_cert_paths()
    dst_cert, dst_key = xhy.self_cert_paths()
    if os.path.isfile(dst_cert):
        if _fingerprint(dst_cert) == plan['fingerprint']:
            return True, 'сертификат старого протокола уже стоит у инбаунда', ''
        # Свой серт инбаунд выпускает при первом включении. Если он уже поднят,
        # его отпечаток мог уехать в чужие ссылки — молча подменять нельзя.
        try:
            if (xhy.status() or {}).get('enabled'):
                return False, '', ('у инбаунда Hysteria уже свой сертификат и он включён — '
                                   'подмена сломает ссылки, выданные после его включения')
        except Exception:
            pass
    import shutil
    try:
        os.makedirs(os.path.dirname(dst_cert), exist_ok=True)
        shutil.copy2(src_cert, dst_cert)
        shutil.copy2(src_key, dst_key)
        os.chmod(dst_key, 0o600)
    except Exception as e:
        return False, '', 'не удалось скопировать сертификат: %s' % e
    audit('info', 'сертификат старого протокола передан инбаунду (отпечаток %s)'
          % (plan['fingerprint'] or '—'))
    return True, 'самоподписанный сертификат перенесён, pinSHA256 в старых ссылках сходится', ''


def clients_view():
    """Список для вкладки: то же, что показывала старая карточка."""
    out = []
    for c in read_clients():
        lists = ((c.get('rule_lists') or {}).get('lists') or [])
        out.append({
            'id': c.get('id') or '',
            'name': c.get('name') or '',
            'created': c.get('created') or 0,
            'disabled': bool(c.get('disabled')),
            'rules': len(lists),
            'rule_lists': lists,
            'geo_mode': c.get('geo_mode') or 'off',
            'has_password': bool((c.get('password') or '').strip()),
        })
    return out


# --- перенос ----------------------------------------------------------------

def _uniq_name(name, taken):
    """Имя для XRay. При совпадении добавляем _hy, дальше _hy2, _hy3 — молча
    перезаписать чужого клиента нельзя."""
    base = (name or 'client').strip() or 'client'
    if base.lower() not in taken:
        return base
    cand = '%s_hy' % base
    n = 2
    while cand.lower() in taken:
        cand = '%s_hy%d' % (base, n)
        n += 1
    return cand


def migrate(ids=None, drop_after=True):
    """Перенести клиентов в XRay. (ok, отчёт, ошибка).

    Переносим ровно то, что имеет смысл: пароль (по нему клиент подключается),
    имя и правила. Трафик, логи и токены профиля не тащим — у XRay всё своё, а
    старые счётчики к новым инбаундам отношения не имеют.
    """
    load_x = DEPS.get('load_xray_clients')
    save_x = DEPS.get('save_xray_clients')
    add_uuid = DEPS.get('xray_add_uuid')
    if not (load_x and save_x and add_uuid):
        return False, {}, 'панель не пробросила доступ к клиентам XRay'

    old = read_clients()
    if ids:
        want = set(ids)
        old = [c for c in old if c.get('id') in want]
    if not old:
        return False, {}, 'нечего переносить'

    xclients = load_x()
    taken = {(c.get('name') or '').lower() for c in xclients.values()}
    taken_tokens = {(c.get('token') or '') for c in xclients.values()}
    moved, renamed = [], []

    done_ids = []
    for c in old:
        pwd = (c.get('password') or '').strip()
        if not pwd:
            # Без пароля клиента не воссоздать — оставляем его в старом списке,
            # чтобы запись не исчезла молча вместе с возможностью разобраться.
            continue
        name = _uniq_name(c.get('name') or '', taken)
        if name != (c.get('name') or ''):
            renamed.append({'from': c.get('name'), 'to': name})
        taken.add(name.lower())
        uuid = str(_new_uuid())
        # Токен профиля переносим, а не выдаём новый: по нему собран публичный
        # адрес подписки, который уже стоит у клиента в приложении. Новый токен
        # молча превратил бы все подписки в 404. Совпасть с чужим он не может —
        # это 32 hex-символа, — но если вдруг, выдаём новый.
        token = (c.get('token') or '').strip()
        if not token or token in taken_tokens:
            token = secrets.token_hex(16)
        taken_tokens.add(token)
        rec = {
            'name': name,
            'uuid': uuid,
            'created': time.strftime('%Y-%m-%d %H:%M'),
            'bypass_ru': False,
            # Формат каталога правил у протоколов совпадает — переносим как есть.
            'rule_lists': c.get('rule_lists') or {'lists': []},
            'token': token,
            'geo_mode': c.get('geo_mode') or 'off',
            'geo_countries': [],
            'geo_mode_pending': c.get('geo_mode_pending') or c.get('geo_mode') or 'off',
            'geo_countries_pending': [],
            # Режим списков: «direct» — в VPN только перечисленное, «vpn» —
            # наоборот. Не перенеси его, и у клиента с режимом исключений весь
            # трафик после миграции пошёл бы мимо VPN.
            'lists_default': c.get('lists_default') or 'direct',
            # Тот самый пароль: по нему клиент подключается сейчас и будет
            # подключаться после переноса — ссылку менять не придётся.
            'hy2_password': pwd,
            'disabled': bool(c.get('disabled')),
        }
        dns_default = DEPS.get('dns_default')
        if dns_default:
            try:
                rec['dns'] = dns_default()
            except Exception:
                pass
        xclients[uuid] = rec
        done_ids.append(c.get('id'))
        moved.append({'name': name, 'uuid': uuid, 'was': c.get('name')})

    if not moved:
        return False, {}, 'ни у одного клиента нет ключа — переносить нечего'
    save_x(xclients)
    # Клиент должен получить и VLESS: перенос делает его полноценным клиентом
    # панели, а не только «хистерийным».
    for m in moved:
        try:
            add_uuid(m['uuid'], m['name'])
        except Exception as e:
            audit('warn', 'клиент %s не попал в инбаунд VLESS: %s' % (m['name'], e))

    if drop_after:
        # Удаляем ровно перенесённых: пропущенные (без пароля) обязаны остаться.
        moved_ids = set(done_ids)
        keep = [c for c in read_clients() if c.get('id') not in moved_ids]
        _write_clients(keep)

    audit('info', 'перенесено клиентов: %d' % len(moved))
    return True, {'moved': moved, 'renamed': renamed, 'left': len(read_clients())}, ''


def _new_uuid():
    fn = DEPS.get('new_uuid')
    if fn:
        return fn()
    import uuid as _u
    return _u.uuid4()


def _write_clients(items):
    try:
        tmp = clients_file() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        os.replace(tmp, clients_file())
    except Exception as e:
        audit('warn', 'не удалось обновить старый список клиентов: %s' % e)


def adopt_settings():
    """Перенести порт и обфускацию старого демона в инбаунд XRay.

    Без этого старые ссылки перестанут подходить: у клиента в ссылке зашиты
    порт и salamander-пароль, и инбаунд обязан совпасть с ними.
    """
    xhy = DEPS.get('xhy')
    if not xhy:
        return False, 'модуль инбаунда не подключён'
    old = read_settings()
    if not old.get('port'):
        return False, 'не нашлись настройки старого протокола'
    cur = xhy.read_settings()
    cur.update({
        'port': int(old.get('port') or cur.get('port')),
        'obfs_password': (old.get('obfs_password') or '').strip(),
        # Старый демон работал на самоподписанном — инбаунд обязан остаться на
        # нём же, даже если у панели есть серт Let's Encrypt: в ссылках зашит
        # pinSHA256, и переход на другой сертификат рвёт handshake у всех.
        'cert_mode': 'self' if old_cert_mode() == 'self' else 'auto',
    })
    if old.get('masquerade_url'):
        cur['masquerade_url'] = old['masquerade_url']
    for k in ('up_mbps', 'down_mbps'):
        if old.get(k):
            try:
                cur[k] = int(old[k])
            except (TypeError, ValueError):
                pass
    return True, cur


# --- гашение и уборка -------------------------------------------------------

def stop_services():
    """Погасить все найденные юниты. Делается первым: пока демон жив, он держит
    UDP-порт, и инбаунд XRay на этот порт не поднимется."""
    stopped = []
    for u in _units():
        run_cmd('systemctl disable --now %s' % u['unit'])
        st, _, _ = run_cmd('systemctl is-active %s' % u['unit'])
        stopped.append({'unit': u['unit'], 'stopped': st.strip() != 'active'})
    if stopped:
        audit('warn', 'остановлены сервисы: %s' % ', '.join(s['unit'] for s in stopped))
    return stopped


def purge(keep_clients=False):
    """Удалить с сервера всё, что нашли. (ok, отчёт, ошибка).

    keep_clients — не трогать data/hysteria/clients.json: страховка, если часть
    людей ещё не перевели на новые ссылки.
    """
    inv = inventory()
    stop_services()
    removed, failed = [], []

    for u in inv['units']:
        _rm(u['path'], removed, failed)
    for f in inv['files']:
        _rm(f['path'], removed, failed)
    for d in inv['dirs']:
        if keep_clients and d['path'] == data_dir():
            # Оставляем только клиентов, остальное внутри каталога чистим.
            for name in ('settings.json', 'config.yaml', 'acl.txt', 'global.json',
                         'totals.json', 'lastseen.json', 'cert.pem', 'key.pem'):
                p = os.path.join(d['path'], name)
                if os.path.exists(p):
                    _rm(p, removed, failed)
            continue
        _rm(d['path'], removed, failed, recursive=True)

    run_cmd('systemctl daemon-reload')
    audit('warn', 'удалено объектов: %d' % len(removed))
    return (not failed), {'removed': removed, 'failed': failed}, ''


def _rm(path, removed, failed, recursive=False):
    try:
        if recursive:
            import shutil
            shutil.rmtree(path, ignore_errors=False)
        else:
            os.remove(path)
        removed.append(path)
    except FileNotFoundError:
        pass
    except Exception as e:
        failed.append({'path': path, 'error': str(e)})


def dismiss():
    """Скрыть вкладку навсегда. Файлы не трогает — их могли оставить намеренно."""
    save = DEPS.get('save_server_cfg')
    cfg = DEPS.get('server_cfg')
    if not (save and cfg is not None):
        return False, 'нет доступа к настройкам панели'
    cfg[DISMISS_KEY] = True
    save(cfg)
    audit('info', 'вкладка миграции скрыта')
    return True, ''


def status():
    inv = inventory()
    old = read_settings()
    xhy = DEPS.get('xhy')
    return {
        'present': present(),
        'inventory': inv,
        'clients': clients_view(),
        'old_settings': {'port': old.get('port') or 0,
                         'obfs': bool((old.get('obfs_password') or '').strip()),
                         'sni': old.get('sni') or '',
                         'masquerade_url': old.get('masquerade_url') or ''},
        # Что станет с сертификатом — единственное, что миграция не может
        # починить сама, если серт потерян. Показываем до нажатия кнопки.
        'cert': cert_plan(),
        'inbound': (xhy.status() if xhy else {'enabled': False}),
    }
