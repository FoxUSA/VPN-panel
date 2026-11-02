"""Трафик и онлайн-статус через Traffic Stats API hysteria.

Схема накопления: читаем /traffic с clear=1 (сервер отдаёт счётчики и обнуляет
их у себя), а сумму копим в data/hysteria/totals.json. Иначе перезапуск сервиса
обнулял бы трафик — та же причина, по которой панель ведёт свои счётчики для
XRay и AWG.

Ключ везде — неизменяемый id клиента (его печатает auth.py), а не имя:
переименование не должно сбрасывать накопленное.
"""
import json
import threading
import time
import urllib.error
import urllib.request

from . import STATS_ADDR, TOTALS_FILE, _read_json, _write_json, audit, load_clients, load_settings

_LOCK = threading.Lock()
_LAST_COLLECT = {'ts': 0}
# Чаще раза в 5 секунд дёргать API незачем: карточки обновляются реже.
_COLLECT_MIN_INTERVAL = 5


def _api(path, method='GET', payload=None, timeout=5):
    cfg = load_settings()
    secret = cfg.get('stats_secret') or ''
    url = 'http://%s%s' % (STATS_ADDR, path)
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if secret:
        req.add_header('Authorization', secret)
    if data:
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return json.loads(body.decode('utf-8')) if body else {}


def load_totals():
    data = _read_json(TOTALS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_totals(totals):
    _write_json(TOTALS_FILE, totals)


def collect(force=False):
    """Забирает дельту трафика и прибавляет к накопленному. Возвращает totals.

    clear=1 нужен именно потому, что счётчики сервера живут только до его
    перезапуска: забрав дельту, мы переносим её в свой файл.
    """
    now = int(time.time())
    with _LOCK:
        if not force and now - _LAST_COLLECT['ts'] < _COLLECT_MIN_INTERVAL:
            return load_totals()
        _LAST_COLLECT['ts'] = now
        totals = load_totals()
        try:
            delta = _api('/traffic?clear=1')
        except Exception:
            # Сервис остановлен или API недоступен — отдаём то, что накоплено.
            return totals
        if not isinstance(delta, dict):
            return totals
        changed = False
        for cid, val in delta.items():
            if not isinstance(val, dict):
                continue
            rec = totals.get(cid) or {'tx': 0, 'rx': 0}
            rec['tx'] = int(rec.get('tx') or 0) + int(val.get('tx') or 0)
            rec['rx'] = int(rec.get('rx') or 0) + int(val.get('rx') or 0)
            rec['updated'] = now
            totals[cid] = rec
            changed = True
        if changed:
            save_totals(totals)
        return totals


def online():
    """{id: число устройств}. У hysteria это именно клиентские экземпляры,
    а не количество соединений."""
    try:
        data = _api('/online')
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def kick(ids):
    """Рвёт активные сессии клиентов. Без этого отключённый клиент продолжал бы
    работать до собственного реконнекта: auth.py спрашивают только при подключении."""
    ids = [i for i in (ids or []) if i]
    if not ids:
        return False
    try:
        _api('/kick', method='POST', payload=ids)
        return True
    except Exception as e:
        audit('warn', 'kick не удался: %s' % e)
        return False


def streams(client_id=None):
    """Снимок открытых потоков: {items:[{user, addr, sniffed, tx, rx, state}]}.

    Журнала назначений у hysteria нет — /dump/streams отдаёт только то, что
    открыто сейчас. Поэтому это «что качает прямо сейчас», а не история.
    """
    try:
        data = _api('/dump/streams', timeout=6)
    except Exception as e:
        return {'items': [], 'error': str(e)}
    raw = data.get('streams') if isinstance(data, dict) else data
    items = []
    for s in (raw or []):
        if not isinstance(s, dict):
            continue
        user = s.get('auth') or s.get('user') or s.get('id') or ''
        if client_id and user != client_id:
            continue
        items.append({
            'user': user,
            'addr': s.get('reqAddr') or s.get('addr') or '',
            'sniffed': s.get('sniffedAddr') or s.get('sniffed') or '',
            'tx': int(s.get('tx') or 0),
            'rx': int(s.get('rx') or 0),
            'state': s.get('state') or '',
        })
    return {'items': items}


def reset(client_id):
    """Обнуляет накопленный трафик одного клиента (логи не трогает)."""
    with _LOCK:
        totals = load_totals()
        if client_id in totals:
            totals[client_id] = {'tx': 0, 'rx': 0, 'updated': int(time.time())}
            save_totals(totals)
            return True
    return False


def reset_all():
    """Обнуляет накопленный трафик ВСЕХ клиентов (кнопка в Global rules).

    Дельту с сервера сначала забираем и выбрасываем: без этого следующий
    collect() принёс бы уже накрученные с прошлого раза байты и сброс выглядел
    бы неполным.
    """
    try:
        _api('/traffic?clear=1')
    except Exception:
        pass
    with _LOCK:
        now = int(time.time())
        save_totals({cid: {'tx': 0, 'rx': 0, 'updated': now} for cid in load_totals()})
    audit('info', 'трафик всех клиентов обнулён')
    return True


def usage_bytes(client_id, totals=None):
    rec = (totals if totals is not None else load_totals()).get(client_id) or {}
    return int(rec.get('tx') or 0) + int(rec.get('rx') or 0)


def enforce_limits():
    """Отключает клиентов, превысивших лимит, и включает обратно после сброса.

    Возвращает список id, чей статус изменился. Отключение — это правка
    clients.json плюс kick: без kick уже установленная сессия продолжила бы
    качать сверх лимита.
    """
    from . import clients as cl
    totals = collect()
    changed = []
    clients = load_clients()
    dirty = False
    for c in clients:
        limit_gb = float(c.get('limit_gb') or 0)
        if limit_gb <= 0:
            continue
        used = usage_bytes(c.get('id'), totals)
        over = used >= limit_gb * 1024 ** 3
        if over and not c.get('disabled'):
            c['disabled'] = True
            c['disabled_by_limit'] = True
            dirty = True
            changed.append(c.get('id'))
            audit('warn', 'клиент %s отключён: исчерпан лимит %.0f ГБ' % (c.get('name'), limit_gb))
        elif not over and c.get('disabled') and c.get('disabled_by_limit'):
            c['disabled'] = False
            c['disabled_by_limit'] = False
            dirty = True
            changed.append(c.get('id'))
            audit('info', 'клиент %s включён: лимит сброшен' % c.get('name'))
    if dirty:
        cl.save_clients(clients)
        kick([c.get('id') for c in clients if c.get('disabled')])
    return changed


def _reset_due(day):
    """Сегодня ли день ежемесячного сброса. День 31 в коротком месяце
    отрабатывает в последний день — иначе в феврале сброса не было бы вовсе
    (та же логика, что _is_traffic_reset_due у XRay)."""
    import calendar
    try:
        day = int(day or 0)
    except (TypeError, ValueError):
        return False
    if not day:
        return False
    y, m, d = int(time.strftime('%Y')), int(time.strftime('%m')), int(time.strftime('%d'))
    return d == min(day, calendar.monthrange(y, m)[1])


def monthly_reset():
    """Сбрасывает счётчики тем, у кого сегодня день сброса. Раз в сутки."""
    stamp = time.strftime('%Y-%m')
    clients = load_clients()
    dirty = False
    for c in clients:
        if not _reset_due(c.get('traffic_reset_day')):
            continue
        if c.get('last_reset_month') == stamp:
            continue           # уже сбрасывали в этом месяце
        reset(c.get('id'))
        c['last_reset_month'] = stamp
        dirty = True
        audit('info', 'трафик клиента %s сброшен по расписанию' % c.get('name'))
    if dirty:
        from . import clients as cl
        cl.save_clients(clients)
    global_monthly_reset()


def global_monthly_reset():
    """Общий ежемесячный сброс из Global rules: чистит счётчики всех клиентов.

    Тот же смысл, что у глобального сброса XRay, — один день на весь протокол,
    независимо от персональных дней сброса.
    """
    from . import rules
    blob = rules.load_global()
    applied = blob['applied']
    today = time.strftime('%Y-%m-%d')
    if not _reset_due(applied.get('traffic_reset_day')):
        return False
    if applied.get('traffic_last_reset') == today:
        return False
    reset_all()
    rules.save_field('traffic_last_reset', today)
    audit('info', 'глобальный сброс трафика Hysteria (день %s)' % applied.get('traffic_reset_day'))
    return True
