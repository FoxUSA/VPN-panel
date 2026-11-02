"""Трафик, онлайн и история IP через API telemt.

telemt отдаёт по пользователю total_octets — счётчик с момента старта
процесса — и списки IP: активные сейчас и недавние. Чтобы трафик переживал
рестарт сервиса, копим дельты в data/tgweb/totals.json (тот же приём, что у
Hysteria и XRay): помним последнее сырое значение и uptime процесса; uptime
уменьшился — процесс перезапускался, и сырое значение целиком считается
приростом.

История «когда и откуда заходил» — data/tgweb/seen.json: telemt помнит IP
лишь в коротком окне, а карточке нужен последний вход и гео.
"""
import json
import threading
import time
import urllib.error
import urllib.request

from . import SEEN_FILE, TOTALS_FILE, _read_json, _write_json, audit, load_clients, load_settings

_LOCK = threading.Lock()
_LAST = {'ts': 0, 'users': {}}
_MIN_INTERVAL = 5
# Сколько IP помним на клиента в истории.
_SEEN_KEEP = 30


def api(path, method='GET', payload=None, timeout=5):
    """Запрос к Control API telemt на 127.0.0.1. Тело ответа — JSON.

    Ключ доступа — точное значение Authorization (server.api.auth_header),
    API слушает только loopback."""
    cfg = load_settings()
    port = int(cfg.get('api_port') or 0)
    if not port:
        raise RuntimeError('API telemt не настроен')
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), data=data, method=method)
    if cfg.get('api_key'):
        req.add_header('Authorization', cfg['api_key'])
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return json.loads(body.decode('utf-8')) if body else {}


def _unwrap(obj):
    """telemt заворачивает ответы в {ok, data} — достаём полезную часть, не
    полагаясь на точную форму конверта."""
    if isinstance(obj, dict) and 'data' in obj and len(obj) <= 4:
        return obj['data']
    return obj


def users_raw():
    """[{username, total_octets, current_connections, active_unique_ips_list, …}]."""
    data = _unwrap(api('/v1/users'))
    if isinstance(data, dict):
        data = data.get('users') or data.get('items') or []
    return [u for u in (data or []) if isinstance(u, dict)]


def uptime():
    try:
        data = _unwrap(api('/v1/stats/summary'))
        return int((data or {}).get('uptime_seconds') or 0)
    except Exception:
        return 0


def load_totals():
    data = _read_json(TOTALS_FILE, {})
    return data if isinstance(data, dict) else {}


def load_seen():
    data = _read_json(SEEN_FILE, {})
    return data if isinstance(data, dict) else {}


def _ip_list(u, key):
    out = []
    for x in (u.get(key) or []):
        if isinstance(x, dict):
            x = x.get('ip') or x.get('addr') or ''
        x = str(x or '').strip()
        if x and x not in out:
            out.append(x)
    return out


def collect(force=False):
    """Забрать дельты трафика и онлайн. Возвращает {'totals', 'live'}.

    live: {id: {'conns': n, 'ips': [...]}} — текущее состояние, его не копим."""
    now = int(time.time())
    with _LOCK:
        if not force and now - _LAST['ts'] < _MIN_INTERVAL:
            return {'totals': load_totals(), 'live': _LAST.get('live') or {}}
        _LAST['ts'] = now
        totals = load_totals()
        try:
            users = users_raw()
        except Exception:
            _LAST['live'] = {}
            return {'totals': totals, 'live': {}}
        up = uptime()
        meta = totals.get('__meta__') or {}
        restarted = bool(up and meta.get('uptime') and up < int(meta['uptime']))
        seen = load_seen()
        live = {}
        changed = seen_changed = False
        for u in users:
            cid = str(u.get('username') or '')
            # Служебный пользователь самопроверки (service.PROBE_USER) — не клиент.
            if not cid or cid == 'awgprobe':
                continue
            raw = int(u.get('total_octets') or 0)
            rec = totals.get(cid) or {'bytes': 0, 'raw': 0}
            prev_raw = int(rec.get('raw') or 0)
            delta = raw if (restarted or raw < prev_raw) else raw - prev_raw
            if delta:
                rec['bytes'] = int(rec.get('bytes') or 0) + delta
                rec['updated'] = now
                changed = True
            if raw != prev_raw:
                rec['raw'] = raw
                changed = True
            totals[cid] = rec
            ips = _ip_list(u, 'active_unique_ips_list')
            conns = int(u.get('current_connections') or 0)
            live[cid] = {'conns': conns, 'ips': ips}
            if ips:
                hist = seen.get(cid) or {'last_ip': '', 'last_ts': 0, 'ips': {}}
                for ip in ips:
                    hist['ips'][ip] = now
                hist['last_ip'] = ips[0]
                hist['last_ts'] = now
                if len(hist['ips']) > _SEEN_KEEP:
                    keep = sorted(hist['ips'].items(), key=lambda kv: -kv[1])[:_SEEN_KEEP]
                    hist['ips'] = dict(keep)
                seen[cid] = hist
                seen_changed = True
        if up:
            totals['__meta__'] = {'uptime': up, 'ts': now}
            changed = True
        if changed:
            _write_json(TOTALS_FILE, totals)
        if seen_changed:
            _write_json(SEEN_FILE, seen)
        _LAST['live'] = live
        return {'totals': totals, 'live': live}


def usage_bytes(client_id, totals=None):
    rec = (totals if totals is not None else load_totals()).get(client_id) or {}
    return int(rec.get('bytes') or 0)


def reset(client_id):
    """Обнулить накопленный трафик клиента. Сырое значение оставляем: следующая
    дельта считается от него, а не от нуля."""
    with _LOCK:
        totals = load_totals()
        rec = totals.get(client_id) or {'raw': 0}
        rec['bytes'] = 0
        rec['updated'] = int(time.time())
        totals[client_id] = rec
        _write_json(TOTALS_FILE, totals)
    return True


def forget(client_id):
    with _LOCK:
        totals = load_totals()
        if totals.pop(client_id, None) is not None:
            _write_json(TOTALS_FILE, totals)
        seen = load_seen()
        if seen.pop(client_id, None) is not None:
            _write_json(SEEN_FILE, seen)


def enforce_limits():
    """Отключить превысивших лимит, включить обратно после сброса. True —
    кто-то поменял статус (тогда планировщик перенесёт это в telemt)."""
    from . import save_clients
    totals = load_totals()
    clients = load_clients()
    dirty = False
    for c in clients:
        limit_gb = float(c.get('limit_gb') or 0)
        if limit_gb <= 0:
            if c.get('disabled_by_limit'):
                c['disabled'] = False
                c['disabled_by_limit'] = False
                dirty = True
            continue
        over = usage_bytes(c.get('id'), totals) >= limit_gb * 1024 ** 3
        if over and not c.get('disabled'):
            c['disabled'] = True
            c['disabled_by_limit'] = True
            dirty = True
            audit('warn', 'клиент %s отключён: исчерпан лимит %.0f ГБ' % (c.get('name'), limit_gb))
        elif not over and c.get('disabled') and c.get('disabled_by_limit'):
            c['disabled'] = False
            c['disabled_by_limit'] = False
            dirty = True
            audit('info', 'клиент %s включён: лимит сброшен' % c.get('name'))
    if dirty:
        save_clients(clients)
    return dirty


def _reset_due(day):
    """День 31 в коротком месяце срабатывает в последний день месяца — та же
    логика, что _is_traffic_reset_due у XRay."""
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
    from . import save_clients
    stamp = time.strftime('%Y-%m')
    clients = load_clients()
    dirty = False
    for c in clients:
        if not _reset_due(c.get('traffic_reset_day')) or c.get('last_reset_month') == stamp:
            continue
        reset(c.get('id'))
        c['last_reset_month'] = stamp
        dirty = True
        audit('info', 'трафик клиента %s сброшен по расписанию' % c.get('name'))
    if dirty:
        save_clients(clients)
    return dirty


def sessions(client_id=None):
    """Живые WEB-сессии из API: для окна логов «Онлайн». Без байтов — их
    telemt по сессиям не отдаёт."""
    path = '/v1/runtime/web/sessions'
    if client_id:
        path += '?user=%s' % client_id
    try:
        data = _unwrap(api(path, timeout=6))
    except Exception as e:
        return {'items': [], 'error': str(e)}
    rows = data.get('sessions') if isinstance(data, dict) else data
    if rows is None and isinstance(data, dict):
        rows = data.get('items') or data.get('rows') or []
    items = []
    for s in (rows or []):
        if not isinstance(s, dict):
            continue
        items.append({
            'user': s.get('user') or s.get('username') or '',
            'ip': s.get('client_ip') or s.get('peer_ip') or s.get('ip') or '',
            'carrier': s.get('carrier') or '',
            'state': s.get('state') or '',
            'ua': s.get('user_agent') or '',
            'streams': s.get('streams') or s.get('stream_count') or 0,
        })
    return {'items': items}
