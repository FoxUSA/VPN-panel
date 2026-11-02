"""Потолок версий протоколов: до какой версии каждый проверен с этой панелью.

10.10.2026 новое ядро XRay сменило формат XDNS и не поднялось на живом конфиге:
легли VLESS, Hysteria и фоллбек на панель. Пробный запуск такое ловит, но не всё:
базу geoip.dat, которую Hysteria читает только при своём старте, он не видит.
Поэтому панель не верит «вышла новая версия на GitHub», а сначала смотрит в манифест.

Таблица лежит в manifest.json, ключ — версия панели:

    "proto_limits": {
      "2.3.10": {"xray": "26.10.31", "hysteria": "2.13.0", "tgweb": "3.5.16", ...},
      "2.3.11": {"xray": "26.12.1"}
    }

Правила:
  * Панель берёт все записи не новее себя, младшие перекрываются старшими: в новой
    записи достаточно указать только то, что изменилось.
  * Манифест с CDN накладывается на локальный по записям. CDN недоступен или в его
    манифесте нет таблицы — работает локальная, она приехала вместе с панелью.
  * Вышла версия выше потолка: обновление идёт до потолка, если он ещё не стоит.
    Запись новой панели с потолком выше — значит, нужно сначала обновить панель.
  * Протокола нет в таблице — никто его не проверял: обновление не предлагаем, а
    на новый сервер ставим последнюю версию, другой всё равно нет.

Побочных эффектов на импорте нет: сервисы протоколов импортируют модуль напрямую.
"""

import re
import threading
import time

KEY = 'proto_limits'

# AWG ставится через apt: выбрать версию нельзя, только кандидата из PPA.
_NO_PIN = {'awg'}
# Теги telemt без «v», остальные с ним. Версия в ответе — в формате протокола.
_PLAIN_TAG = {'tgweb'}

_TTL = 3600
_RETRY = 600

_panel = (0, 0, 0)
_fetch_remote = None
_local = {}
_remote = {}
_checked = 0
_busy = False


def _ver(s):
    """(a, b, c) или None: чужие теги вроде «Prerelease-Alpha» не сравниваем."""
    m = re.fullmatch(r'v?(\d+)\.(\d+)(?:\.(\d+))?', str(s or '').strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None


def _clean(table):
    """Только осмысленные записи. Значение потом попадает в URL и shell-команду."""
    out = {}
    for panel, caps in (table if isinstance(table, dict) else {}).items():
        if not _ver(panel) or not isinstance(caps, dict):
            continue
        good = {p: str(c).strip() for p, c in caps.items() if _ver(c)}
        if good:
            out[str(panel).strip()] = good
    return out


def init(deps):
    """deps: panel_version, read_local — fn() → локальный манифест,
    fetch_remote — fn() → манифест с CDN (исключение при ошибке)."""
    global _panel, _fetch_remote, _local
    _panel = _ver(deps.get('panel_version')) or (0, 0, 0)
    _fetch_remote = deps.get('fetch_remote')
    try:
        _local = _clean((deps['read_local']() or {}).get(KEY))
    except Exception:
        _local = {}


def _pull():
    global _remote, _checked, _busy
    try:
        table = _clean((_fetch_remote() or {}).get(KEY))
        if table:
            _remote = table
        _checked = time.time()
    except Exception:
        # Неудача тоже ставит метку: при лежащем CDN не ждём его на каждый запрос.
        _checked = time.time() - _TTL + _RETRY
    finally:
        _busy = False


def refresh(force=False, wait=True):
    """Перечитать манифест с CDN, если кеш устарел. wait=False — в фоне: проверки
    значков не должны ждать CDN, им достаточно кеша."""
    global _busy
    if not _fetch_remote or (not force and time.time() - _checked < _TTL):
        return
    if wait:
        _pull()
    elif not _busy:
        _busy = True
        threading.Thread(target=_pull, daemon=True).start()


def _caps_at(panel, table):
    caps = {}
    for key in sorted(table, key=_ver):
        if _ver(key) <= panel:
            caps.update(table[key])
    return caps


def _tag(proto, ver):
    bare = ver.lstrip('v')
    return bare if proto in _PLAIN_TAG else 'v' + bare


def decide(proto, cur, latest):
    """Что делать с обновлением протокола.

    target — версия, которую можно ставить ('' — ставить нечего или нельзя выбрать);
    hold — почему не последняя: 'wait' (ждём проверки) или 'panel' (нужна панель
    need_panel); text — то же для человека."""
    refresh(wait=False)
    table = {**_local, **_remote}
    cap = _caps_at(_panel, table).get(proto, '')
    res = {'target': '', 'hold': '', 'need_panel': '', 'limit': cap, 'text': ''}
    v_cur, v_lat, v_cap = _ver(cur), _ver(latest), _ver(cap)

    if v_cap and proto not in _NO_PIN:
        res['target'] = _tag(proto, cap)
    if not v_lat:
        return res
    if v_cap and v_lat <= v_cap:
        res['target'] = latest
        return res
    if not v_cap and not v_cur:
        # Новый сервер и потолка нет: ставить больше нечего.
        res['target'] = latest
    if v_cur and v_cur >= v_lat:
        res['target'] = res['target'] or latest
        return res

    # Вышло то, что выше потолка. Панель новее поможет, только если её потолок выше.
    res['hold'] = 'wait'
    for key in sorted(table, key=_ver):
        if _ver(key) <= _panel:
            continue
        above = _ver(_caps_at(_ver(key), table).get(proto, ''))
        if above and (not v_cap or above > v_cap):
            res['hold'], res['need_panel'] = 'panel', key
            break
    if res['hold'] == 'panel':
        res['text'] = ('Вышла %s. С вашей версией панели она не проверена. '
                       'Обновите панель до %s или новее, а потом обновите протокол.' % (latest, res['need_panel']))
    else:
        res['text'] = ('Вышла %s, но разработчик панели её ещё не проверил, поэтому обновление пока закрыто: '
                       'непроверенная версия может уронить сервис. Ничего делать не нужно: '
                       'после проверки обновление откроется здесь само.' % latest)
    return res


def update_target(proto, cur, latest):
    """Перед обновлением: (версия, '') или ('', почему нельзя). Манифест читаем
    заново: если версию только что признали плохой, кеш на час её бы пропустил."""
    refresh(force=True)
    d = decide(proto, cur, latest)
    target = d['target']
    v_cur, v_target = _ver(cur), _ver(target)
    if d['hold'] and not (v_target and (not v_cur or v_cur < v_target)):
        return '', d['text']
    if not target:
        return '', 'Не удалось узнать доступную версию: нет связи с GitHub и нет записи в манифесте.'
    return target, ''


def pick(proto, latest=''):
    """Что ставить на новый сервер: потолок, а без него — последнюю."""
    return decide(proto, '', latest)['target'] or latest
