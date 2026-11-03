"""Здоровье сервера: CPU, память, диски, сеть, процессы — чтение /proc и /sys.

Вынесено из app.py третьим шагом разбиения. Модуль самодостаточен: из app.py ему
нужен ровно один login_required, всё остальное он читает у ядра сам. Роут отдаёт
те же поля и по тому же URL, что и раньше.

Паттерн тот же, что в awg_dest_log.py: Blueprint без url_prefix, login_required
приезжает в init() уже после объявления роутов и подставляется прокси _auth.
"""

import functools
import json
import os
import threading
import time

from flask import Blueprint, jsonify, request

bp = Blueprint('sys_health', __name__)

_D = {}


def init(deps):
    """Принять зависимости от app.py: login_required и data_dir (история нагрузки)."""
    _D.clear()
    _D.update(deps or {})
    _mon_start()


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роут объявлен раньше."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        guard = _D.get('login_required')
        if not guard:
            return jsonify({'error': 'module not initialized'}), 503
        return guard(fn)(*a, **kw)
    return wrapper


def _health_read_meminfo():
    info = {}
    with open('/proc/meminfo') as f:
        for line in f:
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue
            key = parts[0].strip()
            chunks = parts[1].split()
            if not chunks:
                continue
            try:
                info[key] = int(chunks[0]) * 1024  # значения в kB → байты
            except ValueError:
                pass
    return info

def _health_read_cpu_stat():
    """{'cpu': (total, idle), 'cpu0': (...), ...} из /proc/stat."""
    res = {}
    with open('/proc/stat') as f:
        for line in f:
            if not line.startswith('cpu'):
                break
            parts = line.split()
            try:
                vals = [int(x) for x in parts[1:]]
            except ValueError:
                continue
            if len(vals) < 4:
                continue
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
            res[parts[0]] = (sum(vals), idle)
    return res

def _health_cpu_pct(a, b):
    if not a or not b:
        return None
    dt = b[0] - a[0]
    di = b[1] - a[1]
    if dt <= 0:
        return None
    return round(max(0.0, min(100.0, (1 - di / dt) * 100)), 1)

def _health_read_net_dev():
    """{iface: (rx_bytes, tx_bytes)} из /proc/net/dev, без loopback."""
    res = {}
    with open('/proc/net/dev') as f:
        for line in f.readlines()[2:]:
            if ':' not in line:
                continue
            name, data = line.split(':', 1)
            name = name.strip()
            if name == 'lo':
                continue
            fields = data.split()
            if len(fields) < 16:
                continue
            try:
                res[name] = (int(fields[0]), int(fields[8]))  # rx_bytes, tx_bytes
            except ValueError:
                pass
    return res

def _health_cpuinfo():
    model, cores = None, 0
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if model is None and line.startswith('model name'):
                    model = line.split(':', 1)[1].strip()
                elif line.startswith('processor'):
                    cores += 1
    except Exception:
        pass
    return model, cores

def _health_read_int(path, scale=1.0):
    try:
        with open(path) as f:
            return int(f.read().strip()) * scale
    except Exception:
        return None

def _health_cpu_temp():
    """°C из thermal_zone / hwmon, если доступно."""
    try:
        import glob as _glob
        for p in sorted(_glob.glob('/sys/class/thermal/thermal_zone*/temp')):
            v = _health_read_int(p)
            if v and 0 < v < 200000:
                return round(v / 1000.0, 1)
    except Exception:
        pass
    return None

def _health_net_speed(iface):
    """Заявленная пропускная способность линка в Мбит/с (или None для виртуальных)."""
    v = _health_read_int('/sys/class/net/%s/speed' % iface)
    if v is None or v <= 0:
        return None
    return int(v)

def _health_disks():
    real_fs = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'vfat', 'exfat',
               'ntfs', 'f2fs', 'zfs', 'reiserfs', 'jfs', 'ext'}
    seen_dev = set()
    disks = []
    try:
        with open('/proc/mounts') as f:
            mounts = f.readlines()
    except Exception:
        mounts = []
    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mount, fstype = parts[0], parts[1], parts[2]
        if fstype not in real_fs or dev in seen_dev:
            continue
        seen_dev.add(dev)
        mount_disp = mount.replace('\\040', ' ')  # /proc/mounts экранирует пробелы
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total == 0:
            continue
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        disks.append({
            'mount': mount_disp, 'device': dev, 'fstype': fstype,
            'total': total, 'used': used, 'free': free,
            'percent': round(used / total * 100, 1),
        })
    disks.sort(key=lambda d: d['mount'])
    return disks

def _health_proc_count():
    try:
        return sum(1 for n in os.listdir('/proc') if n.isdigit())
    except Exception:
        return None

def _read_system_health():
    out = {}
    # uptime
    try:
        with open('/proc/uptime') as f:
            out['uptime_sec'] = float(f.read().split()[0])
    except Exception:
        out['uptime_sec'] = None
    # память + swap
    try:
        mi = _health_read_meminfo()
        total = mi.get('MemTotal', 0)
        avail = mi.get('MemAvailable', mi.get('MemFree', 0))
        used = total - avail
        out['mem'] = {
            'total': total, 'available': avail, 'used': used,
            'free': mi.get('MemFree', 0),
            'buffers': mi.get('Buffers', 0),
            'cached': mi.get('Cached', 0),
            'percent': round(used / total * 100, 1) if total else None,
        }
        st_total = mi.get('SwapTotal', 0)
        st_free = mi.get('SwapFree', 0)
        out['swap'] = {
            'total': st_total, 'free': st_free, 'used': st_total - st_free,
            'percent': round((st_total - st_free) / st_total * 100, 1) if st_total else None,
        }
    except Exception:
        out['mem'] = None
        out['swap'] = None
    # два замера для мгновенных скоростей CPU/сети
    try:
        cpu0 = _health_read_cpu_stat()
    except Exception:
        cpu0 = {}
    try:
        net0 = _health_read_net_dev()
    except Exception:
        net0 = {}
    t0 = time.monotonic()
    time.sleep(0.3)
    try:
        cpu1 = _health_read_cpu_stat()
    except Exception:
        cpu1 = {}
    try:
        net1 = _health_read_net_dev()
    except Exception:
        net1 = {}
    dt = max(1e-6, time.monotonic() - t0)
    # CPU
    model, cores = _health_cpuinfo()
    per_core = []
    for k in sorted(k for k in cpu1 if k != 'cpu' and k.startswith('cpu')):
        p = _health_cpu_pct(cpu0.get(k), cpu1.get(k))
        if p is not None:
            per_core.append(p)
    try:
        load = list(os.getloadavg())
    except Exception:
        load = None
    freq = _health_read_int('/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq', 1 / 1000.0)
    out['cpu'] = {
        'model': model,
        'cores': cores or (len(per_core) or None),
        'usage_pct': _health_cpu_pct(cpu0.get('cpu'), cpu1.get('cpu')),
        'per_core': per_core,
        'load': [round(x, 2) for x in load] if load else None,
        'load_pct': round(load[0] / cores * 100, 1) if (load and cores) else None,
        'freq_mhz': round(freq) if freq else None,
        'temp_c': _health_cpu_temp(),
    }
    # сеть
    ifaces = []
    tot_rx_rate = tot_tx_rate = 0
    for name in sorted(net1):
        rx1, tx1 = net1[name]
        rx0, tx0 = net0.get(name, (rx1, tx1))
        rx_rate = max(0, rx1 - rx0) / dt
        tx_rate = max(0, tx1 - tx0) / dt
        tot_rx_rate += rx_rate
        tot_tx_rate += tx_rate
        ifaces.append({
            'iface': name,
            'rx_bytes': rx1, 'tx_bytes': tx1,
            'rx_rate': rx_rate, 'tx_rate': tx_rate,
            'speed_mbps': _health_net_speed(name),
        })
    out['net'] = {
        'interfaces': ifaces,
        'total_rx_rate': tot_rx_rate,
        'total_tx_rate': tot_tx_rate,
    }
    # диски и процессы
    out['disks'] = _health_disks()
    out['proc_count'] = _health_proc_count()
    return out

@bp.route('/api/system/health', methods=['GET'])
@_auth
def system_health_get():
    try:
        data = _read_system_health()
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    data['ok'] = True
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# === История нагрузки: графики за 1 ч … 90 дн ================================
# Порт сборщика servermon (.dev/здоровье сервера): раз в 10 с замер из /proc,
# раз в минуту — точка «среднее + пик», раз в час — часовая точка из минутных.
# Всё лежит в data/sysmon/:
#   minute.jsonl — минутные точки, 48 ч (сравнение «сутки / прошлые сутки»);
#   hour.jsonl   — часовые точки, 180 дн («90 дн / прошлые 90 дн»);
#   records.json — рекорды за всё время по 10-сек замерам;
#   live.json    — последний замер и замеры незакрытой минуты.
# Сборщик живёт в одном процессе (flock), а запрос может прийти в любой воркер —
# поэтому роут читает только файлы, включая live.json.
# Имена полей точки (c, cm, l, …) — формат файлов, менять нельзя: история перестанет читаться.

_MON_EVERY = 10
_MON_KEEP = {'minute': 48 * 60, 'hour': 180 * 24}
_MON_RANGES = {            # окно, шаг графика (с), часовые точки
    '1h': (3600, 60, False),
    '24h': (86400, 300, False),
    '7d': (7 * 86400, 3600, True),
    '30d': (30 * 86400, 7200, True),
    '90d': (90 * 86400, 21600, True),
}
# Разделы и loop/zram/dm-* не считаем — одни и те же байты попали бы дважды.
_MON_SKIP_DISK = ('loop', 'ram', 'zram', 'dm-', 'sr', 'fd', 'md')
_MON_STARTED = False
_MON_LOCK_FD = None        # держим открытым всю жизнь процесса — это и есть замок


def _mon_dir():
    d = _D.get('data_dir')
    return os.path.join(d, 'sysmon') if d else ''


def _mon_write_atomic(path, obj):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, separators=(',', ':'))
    os.replace(tmp, path)


def _mon_read_jsonl(path):
    out, lines = [], 0
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                lines += 1
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass           # недописанная строка после обрыва питания
    except OSError:
        pass
    return out, lines


def _mon_default_iface():
    """Интерфейс маршрута по умолчанию: его трафик и есть трафик сервера.
    Туннели (awg, wg) и lo не считаем, иначе байты двоятся."""
    try:
        with open('/proc/net/route') as f:
            for line in f:
                fl = line.split()
                if len(fl) >= 2 and fl[1] == '00000000':
                    return fl[0]
    except OSError:
        pass
    return ''


def _mon_raw():
    """Накопительные счётчики /proc на момент замера; скорость — дельта двух замеров."""
    r = {'at': time.time(), 'cores': os.cpu_count() or 1}
    with open('/proc/stat') as f:
        for line in f:
            fl = line.split()
            if len(fl) >= 5 and fl[0] == 'cpu':
                # user nice system idle iowait irq softirq steal (guest уже внутри user)
                v = ([int(x) for x in fl[1:9]] + [0] * 8)[:8]
                r['cpu_total'] = sum(v)
                r['cpu_idle'], r['cpu_iow'], r['cpu_stl'] = v[3], v[4], v[7]
                break
        else:
            raise OSError('в /proc/stat нет строки cpu')
    try:
        with open('/proc/loadavg') as f:
            r['load'] = [float(x) for x in f.read().split()[:3]]
    except (OSError, ValueError):
        r['load'] = [0.0, 0.0, 0.0]
    mi = _health_read_meminfo()
    r['mem_total'] = mi.get('MemTotal', 0)
    r['mem_avail'] = mi.get('MemAvailable', mi.get('MemFree', 0))
    r['mem_cache'] = mi.get('Buffers', 0) + mi.get('Cached', 0) + mi.get('SReclaimable', 0)
    r['swap_total'] = mi.get('SwapTotal', 0)
    r['swap_free'] = mi.get('SwapFree', 0)

    iface = _mon_default_iface()
    r['iface'], r['rx'], r['tx'] = iface, 0, 0
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                name, sep, rest = line.partition(':')
                name = name.strip()
                if not sep or (iface and name != iface) or (not iface and name == 'lo'):
                    continue
                fl = rest.split()
                if len(fl) >= 9:
                    r['rx'] += int(fl[0])
                    r['tx'] += int(fl[8])
    except (OSError, ValueError):
        pass

    r['rd'] = r['wr'] = 0
    try:
        with open('/proc/diskstats') as f:
            for line in f:
                fl = line.split()
                if len(fl) < 10 or fl[2].startswith(_MON_SKIP_DISK):
                    continue
                if not os.path.exists('/sys/block/' + fl[2]):
                    continue       # раздел, а не целый диск
                r['rd'] += int(fl[5])
                r['wr'] += int(fl[9])
    except (OSError, ValueError):
        pass

    try:
        st = os.statvfs('/')
        r['disk_total'] = st.f_blocks * st.f_frsize
        r['disk_used'] = (st.f_blocks - st.f_bfree) * st.f_frsize
    except OSError:
        r['disk_total'] = r['disk_used'] = 0
    try:
        with open('/proc/uptime') as f:
            r['uptime'] = int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        r['uptime'] = 0
    return r


def _mon_sample(a, b):
    """Мгновенный замер из двух соседних наборов счётчиков."""
    def sub(x, y):             # сброс счётчика (x < y) считаем нулём
        return x - y if x >= y else 0

    def pct(v):
        return max(0.0, min(100.0, v))

    s = {
        't': int(b['at']), 'cpu': 0.0, 'iowait': 0.0, 'steal': 0.0,
        'load1': b['load'][0], 'load5': b['load'][1], 'load15': b['load'][2],
        'mem_total': b['mem_total'], 'mem_used': max(0, b['mem_total'] - b['mem_avail']),
        'mem_cache': b['mem_cache'],
        'swap_total': b['swap_total'], 'swap_used': max(0, b['swap_total'] - b['swap_free']),
        'rx': 0.0, 'tx': 0.0, 'rd': 0.0, 'wr': 0.0,
        'disk_used': b['disk_used'], 'disk_total': b['disk_total'],
    }
    dt = sub(b['cpu_total'], a['cpu_total'])
    if dt > 0:
        idle, iow = sub(b['cpu_idle'], a['cpu_idle']), sub(b['cpu_iow'], a['cpu_iow'])
        s['cpu'] = round(pct(100 * (dt - idle - iow) / dt), 2)
        s['iowait'] = round(pct(100 * iow / dt), 2)
        s['steal'] = round(pct(100 * sub(b['cpu_stl'], a['cpu_stl']) / dt), 2)
    sec = b['at'] - a['at']
    if sec > 0:
        if a['iface'] == b['iface']:   # сменился маршрут — счётчики несравнимы
            s['rx'] = round(sub(b['rx'], a['rx']) / sec, 1)
            s['tx'] = round(sub(b['tx'], a['tx']) / sec, 1)
        s['rd'] = round(sub(b['rd'], a['rd']) * 512 / sec, 1)
        s['wr'] = round(sub(b['wr'], a['wr']) * 512 / sec, 1)
    return s


# Поля точки: (поле точки, поле замера, поле пика или None).
_MON_FIELDS = (('c', 'cpu', 'cm'), ('l', 'load1', 'lm'), ('m', 'mem_used', 'mm'),
               ('s', 'swap_used', None), ('rx', 'rx', 'rxm'), ('tx', 'tx', 'txm'),
               ('rd', 'rd', 'rdm'), ('wr', 'wr', 'wrm'))


def _mon_fold_samples(ss):
    """Замеры минуты → точка: среднее и пик."""
    n = len(ss)
    p = {'t': 0, 'n': n, 'd': ss[-1]['disk_used']}
    for k, src, mx in _MON_FIELDS:
        vals = [x[src] for x in ss]
        p[k] = round(sum(vals) / n, 2)
        if mx:
            p[mx] = round(max(vals), 2)
    return p


def _mon_fold_points(ps):
    """Точки → одна точка: средние с весом n, пики — максимум."""
    n = sum(q.get('n', 0) for q in ps)
    p = {'t': 0, 'n': n, 'd': ps[-1].get('d', 0) if ps else 0}
    for k, _, mx in _MON_FIELDS:
        p[k] = round(sum(q.get(k, 0) * q.get('n', 0) for q in ps) / n, 2) if n else 0
        if mx:
            p[mx] = max((q.get(mx, 0) for q in ps), default=0)
    return p


class _MonCollector:
    """Фоновый сборщик. Живёт в одном процессе — том, что взял flock."""

    def __init__(self, d):
        self.dir = d
        self.prev = None
        self.cur = []                                      # замеры текущей минуты
        self.mins, mlines = _mon_read_jsonl(self._path('minute'))
        hours, hlines = _mon_read_jsonl(self._path('hour'))
        self.lines = {'minute': mlines, 'hour': hlines}
        self.last_hour = hours[-1]['t'] if hours else -1
        try:
            with open(os.path.join(d, 'records.json'), encoding='utf-8') as f:
                self.records = json.load(f)
        except (OSError, ValueError):
            self.records = {}
        _mon_import_sysstat(self)
        self.catch_up_hours()

    def _path(self, key):
        return os.path.join(self.dir, key + '.jsonl')

    def append(self, key, p):
        """Дописать точку; файл переписывается целиком, когда лишнего наберётся 10%."""
        keep = _MON_KEEP[key]
        if key == 'minute':
            self.mins.append(p)
            del self.mins[:-keep]
        if self.lines[key] + 1 <= keep + keep // 10:
            with open(self._path(key), 'a', encoding='utf-8') as f:
                f.write(json.dumps(p, separators=(',', ':')) + '\n')
            self.lines[key] += 1
            return
        pts = self.mins if key == 'minute' else \
            (_mon_read_jsonl(self._path(key))[0] + [p])[-keep:]
        tmp = self._path(key) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            for q in pts:
                f.write(json.dumps(q, separators=(',', ':')) + '\n')
        os.replace(tmp, self._path(key))
        self.lines[key] = len(pts)

    def catch_up_hours(self):
        """Часовые точки для всех закрытых часов после последней записанной —
        переживает рестарт панели посреди часа и простой."""
        cur_h = int(time.time()) // 3600 * 3600
        bucket, bucket_h = [], -1
        for p in self.mins:
            h = p['t'] // 3600 * 3600
            if h <= self.last_hour or h >= cur_h:
                continue
            if h != bucket_h and bucket:
                self._flush_hour(bucket, bucket_h)
                bucket = []
            bucket_h = h
            bucket.append(p)
        if bucket:
            self._flush_hour(bucket, bucket_h)

    def _flush_hour(self, pts, h):
        p = _mon_fold_points(pts)
        p['t'] = h
        self.append('hour', p)
        self.last_hour = h

    def tick(self):
        raw = _mon_raw()
        if self.prev is None:          # первый замер — только база для дельт
            self.prev = raw
            return
        s = _mon_sample(self.prev, raw)
        self.prev = raw

        flush = None
        if self.cur and self.cur[0]['t'] // 60 != s['t'] // 60:
            flush, self.cur = self.cur, []
        self.cur.append(s)

        changed = False
        for k, v in (('cpu', s['cpu']), ('load', s['load1']), ('mem', s['mem_used']),
                     ('rx', s['rx']), ('tx', s['tx']), ('rd', s['rd']), ('wr', s['wr'])):
            if v > (self.records.get(k) or {}).get('v', 0):
                self.records[k] = {'v': v, 't': s['t']}
                changed = True
        if changed:
            _mon_write_atomic(os.path.join(self.dir, 'records.json'), self.records)

        if flush:
            p = _mon_fold_samples(flush)
            p['t'] = flush[0]['t'] // 60 * 60
            self.append('minute', p)
            if p['t'] // 3600 != s['t'] // 3600:      # закрылся час
                self.catch_up_hours()

        _mon_write_atomic(os.path.join(self.dir, 'live.json'), {
            'now': s, 'minute': self.cur,
            'info': {'cores': raw['cores'], 'iface': raw['iface'], 'host_uptime_sec': raw['uptime']},
        })


# --- Разовый импорт истории sysstat ------------------------------------------
# На части серверов стоит sysstat и пишет средние за 10 минут в
# /var/log/sysstat/saNN (хранит ~9 дней). При первом старте сборщика забираем
# их через `sadf -j` — графики за 7/30 дней заполнены сразу, а не через неделю.
# Берём только то, что старше наших собственных замеров, поэтому повтор ничего
# не задвоит; отметка .sysstat-imported — чтобы не гонять sadf на каждом старте.
# Пиков у sysstat нет (только средние): пик точки = среднее, рекорды не трогаем,
# занятое место на диске неизвестно (d = 0, сводка такие точки пропускает).
_SYSSTAT_DIRS = ('/var/log/sysstat', '/var/log/sa')
_SYSSTAT_MARK = '.sysstat-imported'


def _sysstat_disk_name(dev):
    """Имя диска из sadf: «sda» как есть, «dev8-0» (без -p) — через /sys/dev/block."""
    if dev.startswith('dev') and '-' in dev:
        try:
            return os.path.basename(os.readlink('/sys/dev/block/' + dev[3:].replace('-', ':')))
        except OSError:
            return ''
    return dev


def _sysstat_points(stats, mem_total, iface):
    """Записи sadf -j → точки в формате minute.jsonl (t — начало интервала)."""
    import calendar
    out = []
    disk_names = {}
    for st in stats:
        ts = st.get('timestamp') or {}
        try:
            stamp = time.strptime(ts['date'] + ' ' + ts['time'], '%Y-%m-%d %H:%M:%S')
        except (KeyError, ValueError):
            continue
        end = calendar.timegm(stamp) if ts.get('utc', 1) else int(time.mktime(stamp))
        ival = int(ts.get('interval') or 600)
        if ival <= 0:
            continue
        cpu = next((c for c in st.get('cpu-load') or [] if str(c.get('cpu')) in ('all', '-1')), None)
        if not cpu:
            continue
        c = max(0.0, min(100.0, 100.0 - float(cpu.get('idle', 100)) - float(cpu.get('iowait', 0))))
        q = st.get('queue') or {}
        load = float(q.get('ldavg-1', 0) or 0)
        mem = st.get('memory') or {}
        if mem.get('avail') is not None and mem_total:
            m = max(0, mem_total - int(mem['avail']) * 1024)
        else:
            m = int(mem.get('memused', 0) or 0) * 1024
        swap = int(mem.get('swpused', 0) or 0) * 1024
        rx = tx = 0.0
        for n in ((st.get('network') or {}).get('net-dev') or []):
            if n.get('iface') == iface:
                rx, tx = float(n.get('rxkB', 0)) * 1024, float(n.get('txkB', 0)) * 1024
        rd = wr = 0.0
        for d in st.get('disk') or []:
            raw = str(d.get('disk-device', ''))
            if raw not in disk_names:
                disk_names[raw] = _sysstat_disk_name(raw)
            name = disk_names[raw]
            if not name or name.startswith(_MON_SKIP_DISK) or not os.path.exists('/sys/block/' + name):
                continue
            if 'rkB' in d:                       # sysstat 12+
                rd += float(d.get('rkB', 0)) * 1024
                wr += float(d.get('wkB', 0)) * 1024
            else:                                # 11.x — секторы по 512 байт
                rd += float(d.get('rd_sec', 0)) * 512
                wr += float(d.get('wr_sec', 0)) * 512
        out.append({'t': (end - ival) // 60 * 60, 'n': max(1, ival // _MON_EVERY), 'd': 0,
                    'c': round(c, 2), 'cm': round(c, 2), 'l': load, 'lm': load,
                    'm': m, 'mm': m, 's': swap,
                    'rx': round(rx, 1), 'rxm': round(rx, 1), 'tx': round(tx, 1), 'txm': round(tx, 1),
                    'rd': round(rd, 1), 'rdm': round(rd, 1), 'wr': round(wr, 1), 'wrm': round(wr, 1)})
    return out


def _sysstat_read():
    """Все точки из файлов sysstat, отсортированные по времени."""
    import glob
    import shutil
    import subprocess
    sadf = shutil.which('sadf')
    if not sadf:
        return None
    files = sorted({f for d in _SYSSTAT_DIRS for f in glob.glob(os.path.join(d, 'sa[0-9]*'))},
                   key=os.path.getmtime)
    mem_total = _health_read_meminfo().get('MemTotal', 0)
    iface = _mon_default_iface()
    env = dict(os.environ, LC_ALL='C')
    pts = {}
    for f in files:
        try:
            r = subprocess.run([sadf, '-j', f, '--', '-u', '-q', '-r', '-S', '-n', 'DEV', '-d'],
                               capture_output=True, text=True, timeout=120, env=env)
            hosts = json.loads(r.stdout)['sysstat']['hosts']
        except Exception:
            continue                             # битый или чужой версии файл — пропускаем
        for h in hosts:
            for p in _sysstat_points(h.get('statistics') or [], mem_total, iface):
                pts[p['t']] = p
    return [pts[t] for t in sorted(pts)]


def _mon_import_sysstat(c):
    """Дописать историю sysstat перед нашими замерами. Вызывается из сборщика один раз."""
    mark = os.path.join(c.dir, _SYSSTAT_MARK)
    if os.path.exists(mark):
        return
    try:
        pts = _sysstat_read()
    except Exception as e:
        print(f'[sysmon] импорт sysstat: {e}', flush=True)
        pts = []
    added = {'minute': 0, 'hour': 0}
    if pts:
        hours, _ = _mon_read_jsonl(c._path('hour'))
        own = [p['t'] for p in (c.mins[:1] + hours[:1])]
        first_own = min(own) if own else int(time.time()) // 60 * 60
        pts = [p for p in pts if p['t'] < first_own]
        cut_h = first_own // 3600 * 3600
        # Часовые точки — только за целиком прошедшие до нас часы.
        by_h = {}
        for p in pts:
            if p['t'] < cut_h:
                by_h.setdefault(p['t'] // 3600 * 3600, []).append(p)
        new_h = []
        for h in sorted(by_h):
            q = _mon_fold_points(by_h[h])
            q['t'] = h
            new_h.append(q)
        new_m = [p for p in pts if p['t'] >= time.time() - _MON_KEEP['minute'] * 60]
        for key, new, old in (('hour', new_h, hours), ('minute', new_m, c.mins)):
            if not new:
                continue
            allp = (new + old)[-_MON_KEEP[key]:]
            tmp = c._path(key) + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                for q in allp:
                    f.write(json.dumps(q, separators=(',', ':')) + '\n')
            os.replace(tmp, c._path(key))
            c.lines[key] = len(allp)
            added[key] = len(new)
            if key == 'minute':
                c.mins = allp
        if new_h and not hours:
            c.last_hour = new_h[-1]['t']
        if new_h or new_m:
            span = (pts[-1]['t'] - pts[0]['t']) / 86400
            print(f'[sysmon] импорт sysstat: {added["hour"]} часовых и {added["minute"]} минутных '
                  f'точек, {span:.1f} дн', flush=True)
    _mon_write_atomic(mark, {'at': int(time.time()), 'points': len(pts or []), **added})


def _mon_loop():
    global _MON_LOCK_FD
    d = _mon_dir()
    try:
        import fcntl
        os.makedirs(d, exist_ok=True)
    except Exception as e:
        print(f'[sysmon] история нагрузки отключена: {e}', flush=True)
        return
    # Воркеров gunicorn может быть несколько — пишет историю ровно один. Замок
    # снимается сам, когда процесс умирает, и его подхватывает следующий.
    while True:
        fd = None
        try:
            fd = open(os.path.join(d, '.collector.lock'), 'w')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _MON_LOCK_FD = fd
            break
        except OSError:
            if fd:
                fd.close()
            time.sleep(20)
    try:
        c = _MonCollector(d)
    except Exception as e:
        print(f'[sysmon] не удалось прочитать историю: {e}', flush=True)
        return
    last_err = ''
    nxt = time.time()
    while True:
        try:
            c.tick()
            last_err = ''
        except Exception as e:
            if str(e) != last_err:     # одна и та же ошибка раз в 10 с забила бы журнал
                last_err = str(e)
                print(f'[sysmon] замер: {e}', flush=True)
        nxt += _MON_EVERY
        delay = nxt - time.time()
        if delay < 1:                  # проспали (сервер стоял) — не догоняем пачкой
            nxt, delay = time.time() + _MON_EVERY, _MON_EVERY
        time.sleep(delay)


def _mon_start():
    global _MON_STARTED
    if _MON_STARTED or not _mon_dir() or not os.path.exists('/proc/stat'):
        return
    _MON_STARTED = True
    threading.Thread(target=_mon_loop, name='sysmon', daemon=True).start()


# Роут опрашивается раз в 10 с, а часовой файл — до мегабайта: держим разобранные
# точки, пока файл не поменялся.
_MON_CACHE = {}
_MON_CACHE_LOCK = threading.Lock()


def _mon_points(key, n):
    path = os.path.join(_mon_dir(), key + '.jsonl')
    try:
        st = os.stat(path)
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        return []
    with _MON_CACHE_LOCK:
        hit = _MON_CACHE.get(key)
        if not hit or hit[0] != sig:
            hit = (sig, _mon_read_jsonl(path)[0])
            _MON_CACHE[key] = hit
    pts = hit[1]
    return pts[-n:] if n > 0 else list(pts)


def _mon_summarize(pts, frm, to):
    """Сводка за окно: среднее и пик по метрикам, трафик, прирост диска."""
    per = {'from': frm, 'to': to, 'samples': 0, 'stats': {},
           'rx_bytes': 0.0, 'tx_bytes': 0.0, 'disk_delta': 0}
    acc = {}
    first_disk = last_disk = 0
    pairs = (('cpu', 'c', 'cm'), ('load', 'l', 'lm'), ('mem', 'm', 'mm'), ('swap', 's', 's'),
             ('rx', 'rx', 'rxm'), ('tx', 'tx', 'txm'), ('rd', 'rd', 'rdm'), ('wr', 'wr', 'wrm'))
    for p in pts:
        w = p.get('n', 0)
        if p['t'] < frm or p['t'] >= to or not w:
            continue
        per['samples'] += w
        for name, k, mx in pairs:
            a = acc.setdefault(name, [0.0, -1.0, 0])
            a[0] += p.get(k, 0) * w
            if p.get(mx, 0) > a[1]:
                a[1], a[2] = p.get(mx, 0), p['t']
        per['rx_bytes'] += p.get('rx', 0) * w * _MON_EVERY
        per['tx_bytes'] += p.get('tx', 0) * w * _MON_EVERY
        if p.get('d'):                 # у точек из sysstat места на диске нет
            first_disk = first_disk or p['d']
            last_disk = p['d']
    if per['samples']:
        for name, (sm, mx, mt) in acc.items():
            per['stats'][name] = {'avg': sm / per['samples'], 'max': max(mx, 0), 'max_t': mt}
    if first_disk:
        per['disk_delta'] = last_disk - first_disk
    return per


def _mon_bucket(pts, step):
    """Проредить точки до шага графика (если шаг крупнее исходного)."""
    out, cur, cur_t = [], [], -1

    def flush():
        q = _mon_fold_points(cur) if len(cur) > 1 else dict(cur[0])
        q['t'] = cur_t
        out.append(q)

    for p in pts:
        t = p['t'] // step * step
        if t != cur_t and cur:
            flush()
            cur = []
        cur_t = t
        cur.append(p)
    if cur:
        flush()
    return out


def _mon_report(rng):
    win, step, hourly = _MON_RANGES[rng]
    now = int(time.time())
    d = _mon_dir()
    try:
        with open(os.path.join(d, 'live.json'), encoding='utf-8') as f:
            live = json.load(f)
    except (OSError, ValueError):
        live = {}
    now_s, cur = live.get('now'), live.get('minute') or []
    if not now_s or now - now_s.get('t', 0) > 60:   # сборщик стоит — «сейчас» не врём
        now_s, cur = None, []
    try:
        with open(os.path.join(d, 'records.json'), encoding='utf-8') as f:
            records = json.load(f)
    except (OSError, ValueError):
        records = {}

    if hourly:
        pts = _mon_points('hour', 2 * win // 3600 + 2)
        # Незакрытый час — из минутных точек, чтобы график доходил до «сейчас».
        cur_h = now // 3600 * 3600
        tail = [p for p in _mon_points('minute', 70) if p['t'] >= cur_h]
        if cur:
            tail.append(_mon_fold_samples(cur))
        if tail:
            p = _mon_fold_points(tail)
            p['t'] = cur_h
            pts = [q for q in pts if q['t'] < cur_h] + [p]
    else:
        pts = _mon_points('minute', 2 * win // 60 + 2)
        if cur:                                         # незакрытая минута
            p = _mon_fold_samples(cur)
            p['t'] = cur[0]['t'] // 60 * 60
            pts = [q for q in pts if q['t'] < p['t']] + [p]

    frm = now - win
    return {
        'ok': True, 'range': rng, 'step': step, 'now': now_s,
        'info': live.get('info') or {}, 'records': records,
        'series': _mon_bucket([p for p in pts if p['t'] >= frm], step),
        'cur': _mon_summarize(pts, frm, now),
        'prev': _mon_summarize(pts, frm - win, frm),
    }


@bp.route('/api/system/monitor', methods=['GET'])
@_auth
def system_monitor_get():
    rng = request.args.get('range', '24h')
    if rng not in _MON_RANGES:
        rng = '24h'
    try:
        data = _mon_report(rng)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'no-store'
    return resp
