"""Журнал назначений Hysteria.

Своего access.log у hysteria нет: адреса запросов она пишет в обычный лог и
только на уровне debug. Поэтому «Логи» здесь — это тумблер уровня логирования
(HYSTERIA_LOG_LEVEL=debug + json-формат в юните), а этот модуль разбирает
получившиеся строки в те же записи, что панель показывает для XRay и AWG.

Разбор кешируется и дочитывается, как журнал XRay в панели: страница логов
опрашивает эндпоинт раз в две секунды, а hysteria дописывает файл каждую
секунду — перечитывать 12 МБ и заново искать гео на каждый опрос нельзя.
Разбираются только новые строки, гео-кеш живёт между запросами; полный разбор —
при первой загрузке, ротации (файл стал меньше) и смене языка.
"""
import json
import os
import threading
import time

from . import ACCESS_LOG, DEPS, load_clients

_CACHE = {}
_LOCK = threading.Lock()
# Сколько хвоста читаем. Лог ротируется logrotate'ом по 100 МБ, но держать в
# памяти столько разобранных записей незачем — страница показывает последние.
TAIL_BYTES = 12 * 1024 * 1024
# Предел записей в памяти при дочитывании (≈ те же 12 МБ хвоста с запасом).
MAX_RECS = 200000


def _tail(path, limit):
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            if size > limit:
                f.seek(size - limit)
                f.readline()          # обрезанную первую строку выбрасываем
            return f.read().decode('utf-8', 'replace')
    except Exception:
        return ''


def _read_new_lines(path, start, end):
    """Дописанное с позиции start: (текст целых строк, новая позиция). Хвост без
    перевода строки — запись в процессе — остаётся на следующий раз."""
    try:
        with open(path, 'rb') as f:
            f.seek(start)
            data = f.read(end - start)
    except OSError:
        return '', start
    nl = data.rfind(b'\n')
    if nl < 0:
        return '', start
    return data[:nl + 1].decode('utf-8', 'replace'), start + nl + 1


def _split_addr(addr):
    """'example.com:443' / '[::1]:443' → (хост, порт)."""
    addr = (addr or '').strip()
    if not addr:
        return '', ''
    if addr.startswith('['):
        host, _, rest = addr[1:].partition(']')
        return host, rest.lstrip(':')
    if addr.count(':') == 1:
        host, _, port = addr.rpartition(':')
        return host, port
    return addr, ''          # голый IPv6 без порта


def _is_ip(s):
    return bool(s) and (s.replace('.', '').isdigit() or ':' in s)


def _fmt_ts(v):
    """Время записи → 'YYYY-MM-DD HH:MM:SS'.

    Формат метки зависит от версии hysteria: где-то RFC3339-строка, где-то
    epoch-число. Страница логов умеет только строку и по ней же группирует
    повторы, поэтому приводим здесь, а не гадаем на фронте.
    """
    if isinstance(v, (int, float)):
        # hysteria (zap) пишет epoch в миллисекундах: 1.79e12 как секунды —
        # это 58780-й год. Мельче секунд приводим по порядку величины.
        while v > 1e11:
            v = v / 1000.0
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(v))
    s = str(v or '')
    if not s:
        return ''
    # '2026-08-04T12:00:00.123+03:00' → '2026-08-04 12:00:00'
    s = s.replace('T', ' ')
    return s[:19]


def _parse(text, names, geo_cache, dest_cache):
    """JSON-строки лога → записи панели, новые первыми."""
    geo_fn = DEPS.get('geo_lookup')
    out = []
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        msg = (rec.get('msg') or '').lower()
        if 'request' not in msg and 'error' not in msg:
            continue
        req = rec.get('reqAddr') or ''
        if not req:
            continue
        cid = rec.get('id') or ''
        src_ip, _ = _split_addr(rec.get('addr') or '')
        host, port = _split_addr(req)
        err = (rec.get('error') or rec.get('err') or '').lower()
        if 'error' in msg:
            # Отказ по acl hysteria отдаёт как ошибку соединения «rejected» —
            # это и есть наш Block. Прочие ошибки блоком не считаем: обрыв связи
            # и запрет правилами — разные события.
            outbound = 'block' if 'reject' in err else 'error'
        else:
            outbound = 'direct'
        if src_ip and src_ip not in geo_cache:
            geo_cache[src_ip] = (geo_fn(src_ip) or {}) if geo_fn else {}
        dest_org = {}
        if _is_ip(host):
            if host not in dest_cache:
                dest_cache[host] = (geo_fn(host) or {}) if geo_fn else {}
            d = dest_cache[host]
            if d:
                dest_org = {'asn': d.get('asn'), 'org': d.get('org')}
        out.append({
            'ts': _fmt_ts(rec.get('time', rec.get('ts'))),
            'ip': src_ip,
            'host': host,
            'port': port,
            'email': names.get(cid) or (cid[:8] + '…' if cid else ''),
            '_cid': cid,
            'inbound': 'hysteria',
            'outbound': outbound,
            # Текст ошибки hysteria как есть — страница логов покажет причину
            # («клиент закрыл», «таймаут»…) под словом error.
            'err': (rec.get('error') or rec.get('err') or '') if outbound != 'direct' else '',
            'geo': geo_cache.get(src_ip, {}),
            'dest_org': dest_org,
        })
    return out


def records():
    """Все записи журнала, новые первыми. Пустой список — журнал не пишется."""
    if not os.path.exists(ACCESS_LOG):
        return []
    try:
        st = os.stat(ACCESS_LOG)
    except OSError:
        return []
    sig = (st.st_size, st.st_mtime_ns)
    locale_fn = DEPS.get('geo_locale')
    # Гео-имена кешируются вместе с записями, поэтому язык — часть ключа кеша:
    # иначе после переключения RU/EN страна осталась бы на прежнем языке.
    try:
        key = ('log', locale_fn() if callable(locale_fn) else '')
    except Exception:
        key = ('log', '')
    entry = _CACHE.get(key)
    if entry and entry.get('sig') == sig:
        return entry['recs']
    with _LOCK:
        entry = _CACHE.get(key)
        if entry and entry.get('sig') == sig:
            return entry['recs']
        size_now = st.st_size
        if entry and size_now >= entry['size']:
            # Дописали: разбираем только новые строки и кладём сверху.
            geo_cache, dest_cache = entry['geo'], entry['dest']
            text, size_now = _read_new_lines(ACCESS_LOG, entry['size'], size_now)
            recs = _parse(text, {}, geo_cache, dest_cache) + entry['recs']
            if len(recs) > MAX_RECS:
                recs = recs[:MAX_RECS]
        else:
            # Первая загрузка, ротация или другой язык гео — с нуля.
            geo_cache, dest_cache = {}, {}
            recs = _parse(_tail(ACCESS_LOG, TAIL_BYTES), {}, geo_cache, dest_cache)
        _CACHE.clear()          # держим только текущую ветку: файл один
        _CACHE[key] = {'sig': sig, 'size': size_now, 'recs': recs,
                       'geo': geo_cache, 'dest': dest_cache}
        return recs


def for_client(client_id=None, limit=500):
    recs = records()
    if client_id:
        recs = [r for r in recs if r.get('_cid') == client_id]
    # Имена — на момент запроса, а не разбора: записи в кеше живут долго, и
    # переименованный клиент иначе остался бы под старым именем.
    names = {c.get('id'): c.get('name') for c in load_clients() if c.get('id')}
    out = []
    for r in recs[:limit]:
        o = {k: v for k, v in r.items() if k != '_cid'}
        cid = r.get('_cid') or ''
        if names.get(cid):
            o['email'] = names[cid]
        out.append(o)
    return out
