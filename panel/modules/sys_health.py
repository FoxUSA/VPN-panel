"""Здоровье сервера: CPU, память, диски, сеть, процессы — чтение /proc и /sys.

Вынесено из app.py третьим шагом разбиения. Модуль самодостаточен: из app.py ему
нужен ровно один login_required, всё остальное он читает у ядра сам. Роут отдаёт
те же поля и по тому же URL, что и раньше.

Паттерн тот же, что в awg_dest_log.py: Blueprint без url_prefix, login_required
приезжает в init() уже после объявления роутов и подставляется прокси _auth.
"""

import functools
import os
import time

from flask import Blueprint, jsonify

bp = Blueprint('sys_health', __name__)

_D = {}


def init(deps):
    """Принять зависимости от app.py. Нужен только login_required."""
    _D.clear()
    _D.update(deps or {})


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
