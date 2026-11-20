"""Статистика «DNS сервера» (modules/server_dns.py): что резолвил сервер и что заблокировано.

Блокирует не наш сервер, а выбранный провайдер (AdGuard DNS и т.п.): на рекламу
и трекеры он отвечает 0.0.0.0, на 18+ — адресом своей страницы-заглушки. dnsproxy
только пересылает, счётчиков у него нет. Поэтому dnsproxy пишет подробный журнал
(verbose) в QUERY_LOG, а мы раз в 10 с дочитываем его, считаем и тут же обнуляем
файл: домены на диске не копятся. Если панель лежит и не читает, файл не даст
разрасти таймер awg-panel-dns-trim (обрезает больше TRIM_MB).

Что считается (это оценка, не точный счёт):
* только запросы типа A — так A/AAAA/HTTPS одного домена не считаются трижды;
* «всего» — A-запросы, дошедшие до dnsproxy. Повторы, отданные из кеша
  systemd-resolved, до него не доходят;
* «реклама и трекеры» — ответ A 0.0.0.0; «18+» — ответ адресом известной заглушки;
* страны — по GeoIP первого настоящего адреса в ответе (у заблокированных страны нет);
* компании — по встроенному списку доменов (COMPANIES), остальное — «Другие»;
* клиенты — DNS клиента не видит (все запросы идут от самого сервера), поэтому
  клиентов считаем по журналам XRay и Hysteria: соединение клиента к домену, который
  DNS заблокировал, — блок у этого клиента. Это соединения, а не DNS-запросы;
* example.com — проба сторожа раз в 30 с, в счёт не идёт, но по ней видно, что
  журнал вообще читается (формат строк dnsproxy — отладочный текст, после
  обновления dnsproxy он может поменяться — тогда UI скажет, а не покажет ноль).

Формат строки журнала (dnsproxy v0.86.0, golibs slogutil default; проверено на сервере):
  2026/11/17 09:03:37.315889 DEBUG out prefix=dnsproxy line_num=8 line="doubleclick.net.\\t10\\tIN\\tA\\t0.0.0.0"
Сообщение DNS печатается построчно (msg in = запрос, out = ответ); строка вопроса
`;имя.\\tIN\\t A`, строка ответа `имя.\\tTTL\\tIN\\tA\\tадрес` — каждая самодостаточна,
поэтому перемешивание строк параллельных запросов счёту не мешает.
"""
import json
import os
import re
import threading
import time

LOG_DIR = '/var/lib/awg-panel-dns'           # StateDirectory юнита (DynamicUser)
QUERY_LOG = LOG_DIR + '/query.log'
TRIM_MB = 32
READ_EVERY = 10
SAVE_EVERY = 60
KEEP_DAYS = 62
TOP_KEEP = 1000              # заблокированных доменов за день (после усечения)
QT_KEEP = 3000               # всех доменов за день (после усечения)
LIST_MAX = 1000              # строк любого списка в ответе API
WATCHDOG_NAME = 'example.com.'
LOG_STALE = 180              # сек без строк сторожа при включённом DNS = журнал не читается
BLOCKED_TTL = 2 * 86400      # сколько помнить, что домен блокировался (для клиентов)

# Адреса страниц-заглушек семейных фильтров (не 0.0.0.0).
ADULT_STUBS = {'94.140.14.35', '93.158.134.250'}
ADULT_STUB_PREFIXES = ('146.112.61.',)       # OpenDNS block pages

# Компании по доменам: (название, буква значка, цвет значка, суффиксы).
COMPANIES = [
    ('Yandex', 'Я', '#fc3f1d', ['yandex.ru', 'yandex.net', 'yandex.com', 'yandex.by', 'yandex.kz', 'ya.ru',
                                'yastatic.net', 'yandex-team.ru', 'yandexcloud.net', 'adfox.ru', 'kinopoisk.ru',
                                'webvisor.org', 'yango.com']),
    ('Google', 'G', '#4285f4', ['google.com', 'google.ru', 'googleapis.com', 'gstatic.com', 'googlevideo.com',
                                'youtube.com', 'ytimg.com', 'youtu.be', 'youtube-nocookie.com', 'ggpht.com',
                                'googleusercontent.com', 'doubleclick.net', 'googlesyndication.com',
                                'googleadservices.com', 'google-analytics.com', 'googletagmanager.com',
                                'googletagservices.com', 'app-measurement.com', 'gvt1.com', 'gvt2.com',
                                'firebaseio.com', 'firebaseinstallations.googleapis.com', 'crashlytics.com',
                                'android.com', 'gmail.com', '1e100.net', 'withgoogle.com', 'blogger.com']),
    ('Apple', 'A', '#e2e8f0', ['apple.com', 'icloud.com', 'icloud-content.com', 'mzstatic.com', 'apple-dns.net',
                               'cdn-apple.com', 'aaplimg.com', 'apple-cloudkit.com', 'me.com', 'itunes.com',
                               'apple.news', 'apple-mapkit.com']),
    ('Meta', 'M', '#0866ff', ['facebook.com', 'facebook.net', 'fbcdn.net', 'fb.com', 'fbsbx.com', 'instagram.com',
                              'cdninstagram.com', 'whatsapp.net', 'whatsapp.com', 'messenger.com', 'meta.com',
                              'threads.net', 'oculus.com']),
    ('Microsoft', 'MS', '#7fba00', ['microsoft.com', 'msftncsi.com', 'msftconnecttest.com', 'live.com', 'live.net',
                                    'office.com', 'office.net', 'office365.com', 'windows.com', 'windows.net',
                                    'windowsupdate.com', 'bing.com', 'bing.net', 'msn.com', 'skype.com',
                                    'xboxlive.com', 'microsoftonline.com', 'outlook.com', 'azure.com',
                                    'azureedge.net', 'msedge.net', 'sharepoint.com', 'onedrive.com',
                                    'linkedin.com', 'github.com', 'githubusercontent.com', 'visualstudio.com']),
    ('Telegram', 'T', '#27a7e7', ['telegram.org', 't.me', 'telegram.me', 'telesco.pe', 'tdesktop.com',
                                  'cdn-telegram.org', 'telegra.ph']),
    ('TikTok', 'Tk', '#ee1d52', ['tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'tiktokcdn-us.com', 'byteoversea.com',
                                 'ibytedtos.com', 'ibyteimg.com', 'musical.ly', 'tiktokw.us', 'byteimg.com',
                                 'bytedance.com', 'capcut.com']),
    ('VK', 'VK', '#0077ff', ['vk.com', 'vk.ru', 'userapi.com', 'vkuser.net', 'vk-cdn.net', 'vkuseraudio.net',
                             'vkuservideo.net', 'mail.ru', 'imgsmail.ru', 'ok.ru', 'mycdn.me', 'vk-portal.net',
                             'mradx.net', 'my.com', 'vkontakte.ru', 'dzen.ru', 'rustore.ru']),
    ('Amazon', 'Am', '#ff9900', ['amazon.com', 'amazonaws.com', 'cloudfront.net', 'amazon-adsystem.com',
                                 'media-amazon.com', 'ssl-images-amazon.com', 'primevideo.com', 'twitch.tv',
                                 'ttvnw.net', 'jtvnw.net']),
    ('Cloudflare', 'CF', '#f38020', ['cloudflare.com', 'cloudflare-dns.com', 'cloudflareinsights.com',
                                     'cloudflare.net', 'one.one.one.one', 'workers.dev', 'pages.dev']),
    ('Samsung', 'S', '#1428a0', ['samsung.com', 'samsungapps.com', 'samsungcloud.com', 'samsungosp.com',
                                 'samsungqbe.com', 'samsungdm.com']),
    ('Xiaomi', 'Mi', '#ff6900', ['xiaomi.com', 'xiaomi.net', 'miui.com', 'mi.com', 'mi-img.com']),
    ('Huawei', 'H', '#cf0a2c', ['huawei.com', 'hicloud.com', 'dbankcloud.com', 'dbankcdn.com']),
    ('X / Twitter', 'X', '#94a3b8', ['twitter.com', 'twimg.com', 'x.com', 't.co']),
    ('Netflix', 'N', '#e50914', ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxext.com', 'nflxso.net']),
    ('Spotify', 'Sp', '#1db954', ['spotify.com', 'scdn.co', 'spotifycdn.com']),
    ('Discord', 'D', '#5865f2', ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media']),
    ('OpenAI', 'AI', '#10a37f', ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com']),
]
_COMPANY_BY_SUFFIX = {sfx: i for i, (_n, _l, _c, sfxs) in enumerate(COMPANIES) for sfx in sfxs}

_LINE = re.compile(r'\s(in|out)\s.*?\bline_num=\d+\s+line=(.*)$')
_XRAY = re.compile(r'\saccepted\s+(?:tcp|udp):(\S+?):\d+\s.*?email:\s*(\S+)')
_HEX_SUFFIX = re.compile(r'-[0-9a-f]{8}$')
_IP = re.compile(r'^[0-9.]+$|:')

STATE_FILE = ''             # старый единый файл (до 17.11.2026) — переносится в STATS_DIR
STATS_DIR = ''              # data/server_dns/stats/YYYY-MM-DD.json — по файлу на день
_lock = threading.Lock()
# days[YYYY-MM-DD] = {q,b,x: [24 часа], top: {блок-имя: n}, topx: {имя: n 18+}, qt: {имя: n запросов},
#                     cn: {cc: n}, dc: {имя: cc — страна его адреса, для поиска по маске},
#                     cl: {"proto:имя": [соединений, из них на заблокированные]},
#                     cd: {"proto:имя": {t, b, x, d: {домен: [соединений, блок]}, cn: {cc: n}}}}
# cd (подробно по клиентам) держим в памяти только за сегодня и вчера: старые дни
# читаются с диска, когда открывают конкретного клиента.
_data = {'since': '', 'days': {}}
_dirty = False
_dirty_days = set()
_name_cc = {}               # домен → страна его адреса (из ответов DNS) — для стран клиента
_cd_cache = {}              # (день, клиент) → его данные за прошлый день (дни не меняются)
_tail = b''
_last_watch = 0              # когда последний раз видели пробу сторожа
_last_read_err = ''
_started = False
_boot = time.time()
_settings = None             # функция → настройки server_dns
_geo = None                  # функция ip → {'cc': ...} (GeoLite2-City панели)
_geo_cache = {}
_blocked_seen = {}           # имя → когда DNS последний раз его заблокировал (для клиентов)
_client_logs = []            # [{'proto', 'path', 'pos', 'ino', 'names'}]


def _day_file(day):
    return os.path.join(STATS_DIR, day + '.json')


def _write_day(day, b):
    os.makedirs(STATS_DIR, exist_ok=True)
    tmp = _day_file(day) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(json.dumps(b, ensure_ascii=False, separators=(',', ':')))
    os.replace(tmp, _day_file(day))


def _read_day(day):
    try:
        with open(_day_file(day), encoding='utf-8') as f:
            b = json.load(f)
        return b if isinstance(b, dict) else None
    except Exception:
        return None


def _load_days():
    """Все дни с диска; подробности по клиентам (cd) — только за сегодня и вчера."""
    now = time.time()
    keep_cd = {_day(now)[0], _day(now - 86400)[0]}
    days = {}
    try:
        names = sorted(n for n in os.listdir(STATS_DIR) if re.match(r'^\d{4}-\d{2}-\d{2}\.json$', n))
    except OSError:
        names = []
    for n in names[-KEEP_DAYS:]:
        k = n[:-5]
        b = _read_day(k)
        if not b:
            continue
        if k not in keep_cd:
            b.pop('cd', None)
        days[k] = b
    _data['days'] = days
    _data['since'] = min(days) if days else ''


def init(state_dir, settings_fn, geo_fn=None, xray_log='', hy_log='', hy_names=None):
    """hy_names — функция → {id клиента Hysteria: имя} (журнал Hysteria пишет id)."""
    global STATE_FILE, STATS_DIR, _settings, _geo
    STATE_FILE = os.path.join(state_dir, 'blocked.json')
    STATS_DIR = os.path.join(state_dir, 'stats')
    _settings = settings_fn
    _geo = geo_fn
    del _client_logs[:]
    if xray_log:
        _client_logs.append({'proto': 'xray', 'path': xray_log, 'pos': None, 'ino': None, 'names': None})
    if hy_log:
        _client_logs.append({'proto': 'hy', 'path': hy_log, 'pos': None, 'ino': None, 'names': hy_names})
    # Перенос единого blocked.json (первые часы счётчика) в файлы по дням.
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding='utf-8') as f:
                d = json.load(f)
            for k, b in ((d or {}).get('days') or {}).items():
                if isinstance(b, dict) and not os.path.exists(_day_file(k)):
                    _write_day(k, b)
            os.remove(STATE_FILE)
        except Exception:
            pass
    _load_days()
    # Что блокировалось за последние дни — чтобы клиенты сразу считались после рестарта.
    now = time.time()
    for k in sorted(_data['days']):
        _name_cc.update(_data['days'][k].get('dc') or {})
    for k in sorted(_data['days'])[-2:]:
        b = _data['days'][k]
        tx = b.get('topx') or {}
        for n in (b.get('top') or {}):
            _blocked_seen[n] = (now, bool(tx.get(n)))


def _go_unquote(s):
    """Строковое значение из лога: Go strconv.Quote → обычная строка."""
    s = s.strip()
    if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
        return s
    s = s[1:-1]
    out, i, n = [], 0, len(s)
    simple = {'t': '\t', 'n': '\n', 'r': '\r', '"': '"', '\\': '\\', "'": "'",
              'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v'}
    while i < n:
        c = s[i]
        if c != '\\' or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = s[i + 1]
        if e in simple:
            out.append(simple[e])
            i += 2
        elif e in 'xuU':
            w = {'x': 2, 'u': 4, 'U': 8}[e]
            try:
                out.append(chr(int(s[i + 2:i + 2 + w], 16)))
            except ValueError:
                out.append(s[i:i + 2 + w])
            i += 2 + w
        else:
            out.append(e)
            i += 2
    return ''.join(out)


def _day(ts):
    lt = time.localtime(ts)
    return time.strftime('%Y-%m-%d', lt), lt.tm_hour


def _bucket(day):
    b = _data['days'].get(day)
    if not b:
        b = {'q': [0] * 24, 'b': [0] * 24, 'x': [0] * 24, 'top': {}}
        _data['days'][day] = b
        if not _data['since'] or day < _data['since']:
            _data['since'] = day
    return b


def _add(dst, src):
    for k, v in src.items():
        dst[k] = dst.get(k, 0) + v


def _trim(d, keep):
    if len(d) > keep * 2:
        return dict(sorted(d.items(), key=lambda kv: -kv[1])[:keep])
    return d


def _country(ip):
    if not _geo:
        return ''
    cc = _geo_cache.get(ip)
    if cc is None:
        try:
            cc = ((_geo(ip) or {}).get('cc') or '').upper()
        except Exception:
            cc = ''
        if len(_geo_cache) > 20000:
            _geo_cache.clear()
        _geo_cache[ip] = cc
    return cc


def company_of(name):
    """Индекс компании в COMPANIES по домену или None."""
    parts = name.split('.')
    for i in range(len(parts) - 1):
        idx = _COMPANY_BY_SUFFIX.get('.'.join(parts[i:]))
        if idx is not None:
            return idx
    return None


def parse_lines(lines, now=None, keep_top=True):
    """Разобрать строки журнала dnsproxy и добавить в счётчики. Возвращает (q, b, x)."""
    global _last_watch, _dirty
    now = now or time.time()
    day, hour = _day(now)
    q = blk = adl = 0
    top, topx, qt, cn, dc = {}, {}, {}, {}, {}
    watch = False
    last_geo = ''                # имя, по которому страну уже взяли (в ответе бывает несколько A)
    for raw in lines:
        m = _LINE.search(raw)
        if not m:
            continue
        kind, val = m.group(1), _go_unquote(m.group(2))
        if not val or val.startswith(';;'):
            continue
        if kind == 'in':
            if not val.startswith(';'):
                continue
            p = val[1:].split()
            if len(p) >= 3 and p[1] == 'IN' and p[2] == 'A':
                name = p[0].lower()
                if name == WATCHDOG_NAME:
                    watch = True
                    continue
                q += 1
                if keep_top:
                    n = name.rstrip('.')
                    qt[n] = qt.get(n, 0) + 1
            continue
        if val.startswith(';'):
            continue
        p = val.split()
        if len(p) < 5 or p[2] != 'IN' or p[3] != 'A':
            continue
        name, ip = p[0].lower(), p[4]
        if name == WATCHDOG_NAME:
            continue
        n = name.rstrip('.')
        adult = False
        if ip == '0.0.0.0':
            blk += 1
        elif ip in ADULT_STUBS or ip.startswith(ADULT_STUB_PREFIXES):
            adl += 1
            adult = True
        else:
            if n != last_geo:
                last_geo = n
                cc = _country(ip)
                if cc:
                    cn[cc] = cn.get(cc, 0) + 1
                    if len(_name_cc) > 100000:
                        _name_cc.clear()
                    _name_cc[n] = cc
                    if keep_top:
                        dc[n] = cc
            continue
        _blocked_seen[n] = (now, adult)
        if keep_top:
            top[n] = top.get(n, 0) + 1
            if adult:
                topx[n] = topx.get(n, 0) + 1
    with _lock:
        if watch:
            _last_watch = now
        if q or blk or adl or top or qt or cn:
            b = _bucket(day)
            b['q'][hour] += q
            b['b'][hour] += blk
            b['x'][hour] += adl
            _add(b['top'], top)
            _add(b.setdefault('topx', {}), topx)
            _add(b.setdefault('qt', {}), qt)
            _add(b.setdefault('cn', {}), cn)
            if dc:
                b.setdefault('dc', {}).update(dc)
            if len(b['top']) > TOP_KEEP * 2:
                b['top'] = _trim(b['top'], TOP_KEEP)
                b['topx'] = {k: v for k, v in b['topx'].items() if k in b['top']}
            b['qt'] = _trim(b['qt'], QT_KEEP)
            if len(b.get('dc') or {}) > QT_KEEP * 2:
                b['dc'] = {k: v for k, v in b['dc'].items() if k in b['qt'] or k in b['top']}
            _dirty = True
            _dirty_days.add(day)
    return q, blk, adl


def read_once():
    """Дочитать журнал dnsproxy, посчитать и обнулить файл."""
    global _tail, _last_read_err
    try:
        with open(QUERY_LOG, 'rb') as f:
            data = f.read(64 * 1024 * 1024)
        os.truncate(QUERY_LOG, 0)
    except FileNotFoundError:
        _last_read_err = 'нет файла журнала'
        return
    except Exception as e:
        _last_read_err = str(e)
        return
    _last_read_err = ''
    if not data and not _tail:
        return
    data = _tail + data
    cut = data.rfind(b'\n')
    if cut < 0:
        _tail = data[-65536:]
        return
    _tail = data[cut + 1:][-65536:]
    s = _settings() if _settings else {}
    parse_lines(data[:cut].decode('utf-8', 'replace').splitlines(),
                keep_top=bool(s.get('stats_top', True)))


# --- клиенты: журналы XRay и Hysteria -------------------------------------------

def _blocked_kind(host, now):
    """'' — не блокировался; 'b' — реклама/трекеры; 'x' — 18+ (заглушка)."""
    v = _blocked_seen.get(host)
    if not v or now - v[0] >= BLOCKED_TTL:
        return ''
    return 'x' if v[1] else 'b'


def client_lines(proto, lines, names=None, now=None, keep_top=True):
    """Строки журнала XRay/Hysteria → счётчики клиентов. Считаются только соединения
    к домену (по IP DNS не спрашивается). Возвращает {ключ: [всего, блок]}."""
    global _dirty
    now = now or time.time()
    acc = {}
    det = {}        # ключ → {'x': n 18+, 'd': {домен: [t, b]}, 'cn': {cc: n}}
    for line in lines:
        host = who = ''
        if proto == 'xray':
            m = _XRAY.search(line)
            if not m:
                continue
            host, who = m.group(1).lower(), _HEX_SUFFIX.sub('', m.group(2))
        else:
            line = line.strip()
            if not line.startswith('{') or '"reqAddr"' not in line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if 'request' not in (rec.get('msg') or '').lower():
                continue
            req = rec.get('reqAddr') or ''
            host = req.rsplit(':', 1)[0].strip('[]').lower()
            cid = rec.get('id') or ''
            who = (names or {}).get(cid) or (cid[:8] if cid else '')
        if not host or not who or _IP.search(host):
            continue
        k = '%s:%s' % (proto, who)
        a = acc.setdefault(k, [0, 0])
        a[0] += 1
        kind = _blocked_kind(host, now)
        dt = det.setdefault(k, {'x': 0, 'd': {}, 'cn': {}})
        if kind:
            a[1] += 1
            if kind == 'x':
                dt['x'] += 1
        if keep_top:
            dv = dt['d'].setdefault(host, [0, 0, 0])      # соединений, блок, из них 18+
            dv[0] += 1
            if kind:
                dv[1] += 1
            if kind == 'x':
                dv[2] += 1
        cc = _name_cc.get(host)
        if cc:
            dt['cn'][cc] = dt['cn'].get(cc, 0) + 1
    if acc:
        day = _day(now)[0]
        with _lock:
            b = _bucket(day)
            cl = b.setdefault('cl', {})
            cd = b.setdefault('cd', {})
            for k, (t, bl) in acc.items():
                v = cl.setdefault(k, [0, 0])
                v[0] += t
                v[1] += bl
                c = cd.setdefault(k, {'t': 0, 'b': 0, 'x': 0, 'd': {}, 'cn': {}})
                c['t'] += t
                c['b'] += bl
                c['x'] += det[k]['x']
                for h, hd in det[k]['d'].items():
                    hv = c['d'].setdefault(h, [0, 0, 0])
                    while len(hv) < 3:
                        hv.append(0)
                    for i in range(3):
                        hv[i] += hd[i]
                _add(c['cn'], det[k]['cn'])
            _dirty = True
            _dirty_days.add(day)
    return acc


def _read_client_logs():
    """Дописанное в журналы XRay/Hysteria с прошлого раза. Первый проход только
    запоминает конец файла: историю до включения счётчика не пересчитываем."""
    now = time.time()
    for lg in _client_logs:
        try:
            st = os.stat(lg['path'])
        except OSError:
            lg['pos'] = None
            continue
        if lg['pos'] is None or lg['ino'] != st.st_ino or st.st_size < lg['pos']:
            # Первый проход, ротация или обрезка — начать с конца (или с начала нового файла).
            first = lg['pos'] is None
            lg['ino'] = st.st_ino
            lg['pos'] = st.st_size if first else 0
            if first:
                continue
        if st.st_size <= lg['pos']:
            continue
        try:
            with open(lg['path'], 'rb') as f:
                f.seek(lg['pos'])
                data = f.read(min(st.st_size - lg['pos'], 32 * 1024 * 1024))
        except OSError:
            continue
        cut = data.rfind(b'\n')
        if cut < 0:
            continue
        lg['pos'] += cut + 1
        names = None
        if lg['proto'] == 'hy' and lg['names']:
            try:
                names = lg['names']()
            except Exception:
                names = None
        s = _settings() if _settings else {}
        client_lines(lg['proto'], data[:cut].decode('utf-8', 'replace').splitlines(), names, now,
                     keep_top=bool(s.get('stats_top', True)))
    for n in [n for n, v in _blocked_seen.items() if now - v[0] > BLOCKED_TTL]:
        _blocked_seen.pop(n, None)


# --- хранение -------------------------------------------------------------------

def save(force=False):
    """Записать изменившиеся дни (обычно только сегодняшний), старые — удалить."""
    global _dirty
    if not STATS_DIR or not (_dirty or force):
        return
    now = time.time()
    keep_cd = {_day(now)[0], _day(now - 86400)[0]}
    with _lock:
        days = sorted(_data['days'])
        drop = days[:-KEEP_DAYS] if len(days) > KEEP_DAYS else []
        for k in drop:
            _data['days'].pop(k, None)
        if _data['days'] and _data['since'] < min(_data['days']):
            _data['since'] = min(_data['days'])
        todo = {k: json.loads(json.dumps(_data['days'][k])) for k in (_dirty_days if not force else _data['days'])
                if k in _data['days']}
        _dirty_days.clear()
        _dirty = False
        # Подробности клиентов за позавчера и раньше в памяти не держим — они на диске.
        for k, b in _data['days'].items():
            if k not in keep_cd and 'cd' in b and k not in todo:
                b.pop('cd', None)
    for k, b in todo.items():
        if 'cd' not in b and os.path.exists(_day_file(k)):
            old = _read_day(k) or {}
            if 'cd' in old:
                b['cd'] = old['cd']
        _write_day(k, b)
    for k in drop:
        try:
            os.remove(_day_file(k))
        except OSError:
            pass


def forget_top():
    """Тумблер «запоминать домены» выключили — стереть уже накопленные имена (и на диске)."""
    global _dirty
    with _lock:
        _name_cc.clear()
        for b in _data['days'].values():
            b['top'] = {}
            b['topx'] = {}
            b['qt'] = {}
            b.pop('dc', None)
            for c in (b.get('cd') or {}).values():
                c['d'] = {}
        _cd_cache.clear()
        days = list(_data['days'])
    for k in days:
        b = _read_day(k)
        if not b:
            continue
        b['top'], b['topx'], b['qt'] = {}, {}, {}
        b.pop('dc', None)
        for c in (b.get('cd') or {}).values():
            c['d'] = {}
        _write_day(k, b)
    with _lock:
        _dirty = True
        _dirty_days.update(_data['days'])
    save()


def _loop():
    last_save = time.time()
    while True:
        time.sleep(READ_EVERY)
        try:
            s = _settings() if _settings else {}
            if s.get('enabled'):
                read_once()            # сначала DNS: он обновляет «что блокировалось»
                _read_client_logs()
            if time.time() - last_save >= SAVE_EVERY:
                save()
                last_save = time.time()
        except Exception:
            pass


def start_background():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, daemon=True).start()


# --- выдача ---------------------------------------------------------------------

def _range_days(now, rng):
    return [_day(now - i * 86400)[0] for i in range(rng)]


def _lists(q, top, topx, qt, cn, cl):
    """Списки карточек из сумм за период."""
    blocked = sorted(top.items(), key=lambda kv: (-kv[1], kv[0]))
    alln = set(qt) | set(top)
    domains = sorted(([n, max(qt.get(n, 0), top.get(n, 0)), top.get(n, 0)] for n in alln),
                     key=lambda r: (-r[1], r[0]))
    comp, known = {}, 0
    for n, tot, bl in domains:
        i = company_of(n)
        if i is None:
            continue
        v = comp.setdefault(i, [0, 0])
        v[0] += tot
        v[1] += bl
        known += tot
    companies = sorted(([COMPANIES[i][0], COMPANIES[i][1], COMPANIES[i][2], t, b] for i, (t, b) in comp.items()),
                       key=lambda r: -r[3])
    other = max(0, q - known)
    if other and companies:
        ob = max(0, sum(top.values()) - sum(r[4] for r in companies))
        companies.append(['', '…', '#334155', other, ob])     # «Другие» — имя переведёт UI
    return {
        'blocked': [[n, c, topx.get(n, 0)] for n, c in blocked[:LIST_MAX]],
        'blocked_count': len(blocked),
        'domains': domains[:LIST_MAX],
        'domains_count': len(domains),
        'companies': companies,
        'countries': sorted(([c, n] for c, n in cn.items()), key=lambda r: -r[1])[:60],
        'clients': sorted(([k.split(':', 1)[0], k.split(':', 1)[1], v[0], v[1]] for k, v in cl.items()),
                          key=lambda r: (-r[2], r[1]))[:200],
    }


def mask_fn(q):
    """Маска поиска (как в окне): * — любые символы, ? — один, без них — подстрока.
    Несколько масок через запятую/пробел — подходит любая. Пусто → None."""
    parts = [x for x in re.split(r'[\s,;]+', (q or '').lower()) if x][:20]
    if not parts:
        return None
    res = []
    for x in parts:
        body = re.escape(x).replace(r'\*', '.*').replace(r'\?', '.')
        res.append(re.compile('^' + body + '$' if ('*' in x or '?' in x) else body))
    return lambda n: any(r.search(n) for r in res)


def _sub(d, m):
    return {k: v for k, v in (d or {}).items() if m(k)}


def _masked_day(b, m):
    """День сервера только по доменам под маску: суммы и словари."""
    qt, top, topx = _sub(b.get('qt'), m), _sub(b.get('top'), m), _sub(b.get('topx'), m)
    dc = b.get('dc') or {}
    q, cn = 0, {}
    for n in set(qt) | set(top):
        t = max(qt.get(n, 0), top.get(n, 0))
        q += t
        ok = t - top.get(n, 0)          # страну считали только по незаблокированным ответам
        cc = dc.get(n) or _name_cc.get(n)
        if cc and ok > 0:
            cn[cc] = cn.get(cc, 0) + ok
    nb = sum(top.values())
    nx = min(sum(topx.values()), nb)
    return {'q': q, 'b': nb - nx, 'x': nx}, qt, top, topx, cn


def _masked_cl(cd, m):
    """Клиенты за день только по соединениям к доменам под маску."""
    out = {}
    for k, c in (cd or {}).items():
        t = bl = 0
        for h, v in (c.get('d') or {}).items():
            if m(h):
                t += v[0]
                bl += v[1]
        if t:
            out[k] = [t, bl]
    return out


def _snapshot_masked(m, rngs=(1, 7, 30)):
    now = time.time()
    need = set(_range_days(now, max(rngs)))
    days, per, cds = {}, {}, {}
    with _lock:
        for k, b in _data['days'].items():
            days[k], qt, top, topx, cn = _masked_day(b, m)
            if k in need:
                per[k] = (qt, top, topx, cn)
                if 'cd' in b:
                    cds[k] = _masked_cl(b.get('cd'), m)
        since = _data['since']
    # Клиенты за прошлые дни — с диска (в памяти только сегодня и вчера).
    for k in need:
        if k in per and k not in cds:
            cds[k] = _masked_cl((_read_day(k) or {}).get('cd'), m)
    ranges = {}
    for rng in rngs:
        top, topx, qt, cn, cl = {}, {}, {}, {}, {}
        q = 0
        for k in _range_days(now, rng):
            if k not in per:
                continue
            dq, dt, dx, dn = per[k]
            _add(qt, dq)
            _add(top, dt)
            _add(topx, dx)
            _add(cn, dn)
            q += days[k]['q']
            for c, (t, bl) in (cds.get(k) or {}).items():
                v = cl.setdefault(c, [0, 0])
                v[0] += t
                v[1] += bl
        ranges[str(rng)] = _lists(q, top, topx, qt, cn, cl)
    return {'since': since, 'today': _day(now)[0], 'days': days, 'ranges': ranges, 'now': int(now)}


def snapshot(mask=None, rngs=(1, 7, 30)):
    """Для /api/server-dns/blocked: суммы по дням и списки за 1/7/30 дней.
    mask — функция mask_fn(): всё только по доменам под маску; rngs — какие
    периоды собрать (поиску нужен только открытый: клиенты за прошлые дни с диска)."""
    if mask:
        return _snapshot_masked(mask, rngs)
    now = time.time()
    with _lock:
        days = {k: {'q': sum(b['q']), 'b': sum(b['b']), 'x': sum(b['x'])} for k, b in _data['days'].items()}
        ranges = {}
        for rng in (1, 7, 30):
            top, topx, qt, cn, cl = {}, {}, {}, {}, {}
            q = 0
            for k in _range_days(now, rng):
                b = _data['days'].get(k)
                if not b:
                    continue
                q += sum(b['q'])
                _add(top, b.get('top') or {})
                _add(topx, b.get('topx') or {})
                _add(qt, b.get('qt') or {})
                _add(cn, b.get('cn') or {})
                for c, (t, bl) in (b.get('cl') or {}).items():
                    v = cl.setdefault(c, [0, 0])
                    v[0] += t
                    v[1] += bl
            ranges[str(rng)] = _lists(q, top, topx, qt, cn, cl)
        since = _data['since']
        watch = _last_watch
    # Сразу после старта панели сторож мог ещё не спросить — «не знаем», а не «сломано».
    log_ok = True if (watch and now - watch < LOG_STALE) else (None if now - _boot < LOG_STALE else False)
    return {'since': since, 'today': _day(now)[0], 'days': days, 'ranges': ranges,
            'clients_src': [lg['proto'] for lg in _client_logs if os.path.exists(lg['path'])],
            'log_ok': log_ok, 'log_seen': int(watch), 'log_error': _last_read_err, 'now': int(now)}


def _client_day(day, key):
    """Данные клиента за день: из памяти (сегодня/вчера) или с диска (с кешем)."""
    with _lock:
        b = _data['days'].get(day)
        if b is not None and 'cd' in b:
            c = (b.get('cd') or {}).get(key)
            return json.loads(json.dumps(c)) if c else None
    ck = (day, key)
    if ck in _cd_cache:
        return _cd_cache[ck]
    c = ((_read_day(day) or {}).get('cd') or {}).get(key)
    if len(_cd_cache) > 2000:
        _cd_cache.clear()
    _cd_cache[ck] = c
    return c


def _client_masked(c, m):
    """День клиента только по доменам под маску; страны — по стране домена."""
    d = _sub(c.get('d'), m)
    t = sum(v[0] for v in d.values())
    bl = sum(v[1] for v in d.values())
    x = sum(v[2] for v in d.values() if len(v) > 2)
    cn = {}
    for h, v in d.items():
        cc = _name_cc.get(h)
        if cc:
            cn[cc] = cn.get(cc, 0) + v[0]
    return {'t': t, 'b': bl, 'x': x, 'd': d, 'cn': cn}


def client_snapshot(key, mask=None):
    """То же, что snapshot(), но по одному клиенту ("proto:имя"): соединения из журналов.
    mask — только соединения к доменам под маску."""
    now = time.time()
    with _lock:
        all_days = sorted(_data['days'])
    per = {k: _client_day(k, key) for k in all_days[-60:]}
    if mask:
        per = {k: _client_masked(c, mask) for k, c in per.items() if c}
    days = {k: {'q': c['t'], 'b': max(0, c['b'] - c.get('x', 0)), 'x': c.get('x', 0)}
            for k, c in per.items() if c}
    ranges = {}
    for rng in (1, 7, 30):
        top, topx, qt, cn = {}, {}, {}, {}
        q = 0
        for k in _range_days(now, rng):
            c = per.get(k)
            if not c:
                continue
            q += c['t']
            for h, v in (c.get('d') or {}).items():
                qt[h] = qt.get(h, 0) + v[0]
                if v[1]:
                    top[h] = top.get(h, 0) + v[1]
                if len(v) > 2 and v[2]:
                    topx[h] = topx.get(h, 0) + v[2]
            _add(cn, c.get('cn') or {})
        r = _lists(q, top, topx, qt, cn, {})
        r.pop('clients', None)
        ranges[str(rng)] = r
    return {'client': key, 'days': days, 'ranges': ranges, 'now': int(now)}
