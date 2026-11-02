"""Обновление ядра XRay из панели — с проверкой ДО установки и откатом.

Раньше кнопка «Обновить» запускала install-release.sh: он сам останавливал
ядро, клал новый бинарь и поднимал его. Если новое ядро не принимало наш
конфиг (так было с 26.10.10: сменили формат XDNS — «xdns: empty domains»),
XRay не стартовал вовсе. Вместе с ним падали VLESS, Hysteria и фоллбек на
саму панель, а у того, кто сидел через этот же сервер, пропадал интернет —
то есть и возможность что-то починить.

Теперь порядок такой:
  1. скачать релиз во временную папку, живые файлы не трогаем;
  2. прогнать живой конфиг через `НОВЫЙ_БИНАРЬ run -test` и пробный запуск
     на свободных портах 127.0.0.1 (с гео-файлами из того же релиза — ровно
     то состояние, что будет после установки; см. _smoke — почему -test мало).
     Конфиг перед этим проходит через patchers — известные несовместимости
     формата чинятся сами. Не прошёл тест — обновление не ставим, сервер
     работает как работал;
  3. поставить бинарь атомарно (os.replace), прежний — в бэкап;
  4. перезапустить и убедиться, что ядро живо через несколько секунд
     (XRay с плохим конфигом успевает побыть «active» десятки миллисекунд);
     не поднялось — вернуть прежний бинарь и прежний конфиг.
"""

import copy
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile

_D = {}

RELEASE_URL = 'https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip'
ASSET_DIR = '/usr/local/share/xray'
GEO_FILES = ('geoip.dat', 'geosite.dat')

# uname -m → суффикс архива релиза
_ARCH = {
    'x86_64': '64', 'amd64': '64',
    'aarch64': 'arm64-v8a', 'arm64': 'arm64-v8a',
    'armv7l': 'arm32-v7a', 'armv6l': 'arm32-v6',
    'i386': '32', 'i686': '32',
    's390x': 's390x', 'riscv64': 'riscv64',
}


def init(deps):
    """deps: audit, run_cmd, xray_bin, xray_config, get_version,
    patchers — список fn(cfg) → число исправлений (на месте)."""
    _D.clear()
    _D.update(deps or {})
    return True


def _audit(level, msg):
    fn = _D.get('audit')
    if fn:
        try:
            fn(level, '[XRay update] %s' % msg)
        except Exception:
            pass


def _sh(cmd):
    return _D['run_cmd'](cmd)


def _tail(text, n=12):
    lines = [l for l in (text or '').splitlines() if l.strip()]
    return '\n'.join(lines[-n:])


def _test(xray_bin, cfg, work, asset_dir):
    """(ok, вывод) — `xray run -test` для словаря cfg."""
    path = os.path.join(work, 'candidate-%d.json' % int(time.time() * 1000))
    with open(path, 'w') as f:
        json.dump(cfg, f)
    env = dict(os.environ)
    if asset_dir:
        env['XRAY_LOCATION_ASSET'] = asset_dir
    try:
        p = subprocess.run([xray_bin, 'run', '-test', '-c', path],
                           capture_output=True, text=True, timeout=30, env=env)
    except Exception as e:
        return False, str(e)
    out = ((p.stdout or '') + '\n' + (p.stderr or '')).strip()
    return p.returncode == 0, out


def _free_port():
    """Порт, свободный и по TCP, и по UDP (mKCP/XDNS/Hysteria слушают UDP)."""
    for _ in range(50):
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            t.bind(('127.0.0.1', 0))
            port = t.getsockname()[1]
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
            finally:
                u.close()
        finally:
            t.close()
    raise RuntimeError('не нашлось свободного порта для пробного запуска')


def _smoke(xray_bin, cfg, work, asset_dir, secs=3):
    """(ok, вывод) — настоящий запуск ядра на копии конфига, где каждый вход
    переселён на свободный порт 127.0.0.1. `-test` только разбирает JSON, а
    часть ошибок ядро находит, лишь открывая порт: так 26.10.10 падал на старом
    XDNS («empty domains»), хотя `-test` писал Configuration OK."""
    cand = copy.deepcopy(cfg)
    cand['log'] = {'loglevel': 'warning'}       # чужие access.log не трогаем
    for i, ib in enumerate(cand.get('inbounds') or []):
        listen = str(ib.get('listen') or '')
        if listen.startswith('/') or listen.startswith('@'):
            ib['listen'] = os.path.join(work, 'smoke-%d.sock' % i)
        else:
            ib['listen'] = '127.0.0.1'
            ib['port'] = _free_port()
    if isinstance(cand.get('metrics'), dict) and cand['metrics'].get('listen'):
        cand['metrics']['listen'] = '127.0.0.1:%d' % _free_port()
    path = os.path.join(work, 'smoke-%d.json' % int(time.time() * 1000))
    with open(path, 'w') as f:
        json.dump(cand, f)
    logf = path + '.log'
    env = dict(os.environ)
    if asset_dir:
        env['XRAY_LOCATION_ASSET'] = asset_dir
    with open(logf, 'w') as out:
        p = subprocess.Popen([xray_bin, 'run', '-c', path], stdout=out, stderr=subprocess.STDOUT, env=env)
        try:
            p.wait(timeout=secs)
            alive = False
        except subprocess.TimeoutExpired:
            alive = True
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
    try:
        text = open(logf, errors='replace').read()
    except Exception:
        text = ''
    return alive, text


def _check(xray_bin, cfg, work, asset_dir):
    """`-test`, затем пробный запуск. (ok, вывод)."""
    ok, out = _test(xray_bin, cfg, work, asset_dir)
    if not ok:
        return ok, out
    return _smoke(xray_bin, cfg, work, asset_dir)


def _wait_alive(unit='xray'):
    """Живо ли ядро через несколько секунд после рестарта. Однократный
    is-active врёт: с невалидным конфигом процесс успевает побыть active."""
    time.sleep(3)
    for _ in range(4):
        if _sh('systemctl is-active %s' % unit)[0].strip() != 'active':
            return False
        time.sleep(0.5)
    return True


def _put(src, dst):
    """Атомарная замена файла (в т.ч. запущенного бинаря — os.replace меняет
    ссылку, работающий процесс доживает на старом inode)."""
    tmp = dst + '.new'
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


def _dat_tags(path):
    """Коды разделов .dat-файла в верхнем регистре: каждая запись — поле 1
    верхнего уровня protobuf, её код — первое поле записи."""
    with open(path, 'rb') as f:
        data = f.read()

    def varint(i):
        val = shift = 0
        while True:
            c = data[i]
            i += 1
            val |= (c & 127) << shift
            shift += 7
            if c < 128:
                return val, i

    tags = set()
    i = 0
    while i < len(data):
        _, i = varint(i)
        size, i = varint(i)
        _, j = varint(i)
        n, j = varint(j)
        tags.add(data[j:j + n].decode('ascii', 'replace').upper())
        i += size
    return tags


def _keep_installed_geoip(rel):
    """С v26.10.21 в релизе урезанный geoip.dat: из стран только RU, CN и IR.
    Правила по странам у XRay и Hysteria (geoip:tr и т.п.) с ним не запустятся,
    причём Hysteria — при следующем рестарте, проверка ниже её не видит. Если
    новая база теряет коды, кладём установленную поверх релизной: и проверка, и
    установка идут уже с ней. Возвращает число сохранённых кодов."""
    cur, new = os.path.join(ASSET_DIR, 'geoip.dat'), os.path.join(rel, 'geoip.dat')
    if not (os.path.isfile(cur) and os.path.isfile(new)):
        return 0
    try:
        lost = _dat_tags(cur) - _dat_tags(new)
    except Exception as e:
        _audit('warn', 'не удалось сравнить geoip.dat: %s' % e)
        return 0
    if lost:
        shutil.copy2(cur, new)
    return len(lost)


def safe_update(tag):
    """(ok, сообщение). tag — 'v26.10.10'."""
    xray_bin = _D.get('xray_bin') or '/usr/local/bin/xray'
    cfg_path = _D.get('xray_config') or '/usr/local/etc/xray/config.json'
    get_ver = _D.get('get_version') or (lambda: '')
    if not tag:
        return False, 'не удалось узнать последнюю версию XRay на GitHub'
    arch = _ARCH.get(platform.machine().lower())
    if not arch:
        return False, 'архитектура %s не поддерживается обновлением из панели' % platform.machine()

    was = get_ver() or '?'
    if was.lstrip('v') == tag.lstrip('v'):
        return True, '%s — уже последняя версия' % was
    stopped = _sh('systemctl is-active xray')[0].strip() == 'inactive'

    work = tempfile.mkdtemp(prefix='xray-update-')
    try:
        # 1. скачать и распаковать
        zpath = os.path.join(work, 'xray.zip')
        url = RELEASE_URL % (tag, arch)
        try:
            p = subprocess.run(['curl', '-fsSL', '--retry', '2', '--connect-timeout', '15',
                                '-o', zpath, url], capture_output=True, text=True, timeout=300)
        except Exception as e:
            return False, 'не удалось скачать %s: %s' % (url, e)
        if p.returncode != 0 or not os.path.isfile(zpath):
            return False, 'не удалось скачать %s: %s' % (url, _tail(p.stderr, 3))
        rel = os.path.join(work, 'release')
        try:
            with zipfile.ZipFile(zpath) as zf:
                zf.extractall(rel)
        except Exception as e:
            return False, 'архив релиза повреждён: %s' % e
        new_bin = os.path.join(rel, 'xray')
        if not os.path.isfile(new_bin):
            return False, 'в архиве релиза нет бинаря xray'
        os.chmod(new_bin, 0o755)
        p = subprocess.run([new_bin, 'version'], capture_output=True, text=True, timeout=15)
        if p.returncode != 0:
            return False, 'новый бинарь не запускается на этом сервере: %s' % _tail(p.stderr, 3)

        kept = _keep_installed_geoip(rel)
        if kept:
            _audit('info', 'geoip.dat оставлен прежний: в релизе %s нет %d кодов' % (tag, kept))

        # 2. проверить живой конфиг на новом ядре
        try:
            with open(cfg_path) as f:
                cfg_live = json.load(f)
        except Exception as e:
            return False, 'не удалось прочитать конфиг XRay: %s' % e
        cfg_new = copy.deepcopy(cfg_live)
        patched = 0
        for fn in _D.get('patchers') or []:
            try:
                patched += int(fn(cfg_new) or 0)
            except Exception as e:
                _audit('warn', 'patcher %s: %s' % (getattr(fn, '__name__', fn), e))
        ok, out = _check(new_bin, cfg_new, work, rel)
        if not ok:
            _audit('warn', 'XRay %s не принял текущий конфиг — обновление не ставим: %s'
                   % (tag, _tail(out, 3)))
            return False, ('XRay %s не принимает текущий конфиг — обновление НЕ установлено, '
                           'сервер работает на %s как прежде.\n%s' % (tag, was, _tail(out)))
        # Исправленный конфиг должен подходить и старому ядру — откат вернёт
        # старый бинарь, и с ним должен запускаться тот же файл.
        if patched and os.path.isfile(xray_bin):
            ok_old, out_old = _check(xray_bin, cfg_new, work, ASSET_DIR)
            if not ok_old:
                return False, ('исправленный под %s конфиг не принимает текущее ядро %s — '
                               'обновление НЕ установлено.\n%s' % (tag, was, _tail(out_old)))

        # 3. установить: бэкап → конфиг → гео → бинарь
        prev_bin = os.path.join(work, 'xray.prev')
        if os.path.isfile(xray_bin):
            shutil.copy2(xray_bin, prev_bin)
        if patched:
            with open(cfg_path + '.new', 'w') as f:
                json.dump(cfg_new, f, indent=2)
            os.replace(cfg_path + '.new', cfg_path)
            _audit('info', 'конфиг приведён к формату %s (исправлений: %d)' % (tag, patched))
        if os.path.isdir(ASSET_DIR):
            for g in GEO_FILES:
                src = os.path.join(rel, g)
                if os.path.isfile(src):
                    _put(src, os.path.join(ASSET_DIR, g))
        _put(new_bin, xray_bin)
        now = get_ver() or tag

        if stopped:
            _audit('info', 'бинарь обновлён %s → %s, сервис был остановлен — не запускали' % (was, now))
            return True, 'обновлён: %s → %s; сервис был остановлен — не запускали' % (was, now)

        # 4. перезапуск + откат
        _sh('systemctl reset-failed xray')
        _sh('systemctl restart xray')
        if _wait_alive():
            _audit('info', 'обновлён %s → %s' % (was, now))
            return True, 'обновлён: %s → %s' % (was, now)

        journal = _sh('journalctl -u xray -n 15 --no-pager')[0]
        if os.path.isfile(prev_bin):
            _put(prev_bin, xray_bin)
        if patched:
            with open(cfg_path + '.new', 'w') as f:
                json.dump(cfg_live, f, indent=2)
            os.replace(cfg_path + '.new', cfg_path)
        _sh('systemctl reset-failed xray')
        _sh('systemctl restart xray')
        back = _wait_alive()
        _audit('error', 'XRay %s не поднялся — возвращён %s (%s)'
               % (now, was, 'работает' if back else 'тоже не поднялся'))
        return False, ('XRay %s не поднялся после установки — возвращена версия %s%s.\n%s'
                       % (now, was, '' if back else ' (но и она не стартует — смотрите journalctl -u xray)',
                          _tail(journal)))
    finally:
        shutil.rmtree(work, ignore_errors=True)
