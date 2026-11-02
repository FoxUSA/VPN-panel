"""MTProto-прокси (mtg): конфиг, порт, секрет, логи и список получателей.

Протокол живёт своим движком — бинарь mtg, свой config.toml и systemd-юнит, —
поэтому в app.py от него не оставалось ничего, кроме путей. Здесь он целиком:
чтение и правка конфига (patch, а не перезапись — порт в bind-to это live source
of truth), выбор и смена порта, перегенерация секрета, разбор JSON-лога в
data/logs/mtg_access.log, расписание авто-выключения и перечень тех, кому прокси
выдан.

Контракт модуля — как у остальных (см. modules/__init__.py): зависимости от
app.py приезжают в init() одним словарём и ложатся в одноимённые глобалы, роуты
объявлены в Blueprint без url_prefix (URL те же, фронт не трогаем), побочных
эффектов на импорте нет.
"""

import json
import os
import re
import shutil
import subprocess
import time
import uuid as uuid_lib

from flask import Blueprint, jsonify, request

bp = Blueprint('mtg', __name__)

# === Зависимости от app.py ==================================================
# До init() модуль умеет только импортироваться. Имена совпадают с теми, что
# были в app.py, поэтому тела функций переехали байт в байт.
_client_ip = None
_proto_state = None
_run_capture = None
_save_server_config = None
_systemctl_cat = None
_tail_bytes = None
_validate_schedule_date = None
audit = None
ensure_firewall_port = None
geo_asn_full = None
get_server_ip = None
get_xray_inbound_params = None
pick_free_port = None
port_conflict = None
port_owner = None
run_cmd = None
login_required = None
SERVER_CFG = {}
_LOG_TTL_CACHE = {}
DATA_MTPROTO_DIR = ''
MTG_ACCESS_LOG = ''
MTG_BIN = ''
MTG_CONFIG = ''
MTG_FAKE_HOST = ''
MTG_RECIPIENTS_DB = ''
MTG_UNIT_FILE = ''
PANEL_LOGS_DIR = ''

REQUIRED_DEPS = [
    '_client_ip',
    '_proto_state',
    '_run_capture',
    '_save_server_config',
    '_systemctl_cat',
    '_tail_bytes',
    '_validate_schedule_date',
    'audit',
    'ensure_firewall_port',
    'geo_asn_full',
    'get_server_ip',
    'get_xray_inbound_params',
    'pick_free_port',
    'port_conflict',
    'port_owner',
    'run_cmd',
    'login_required',
    'DATA_MTPROTO_DIR',
    'MTG_ACCESS_LOG',
    'MTG_BIN',
    'MTG_CONFIG',
    'MTG_FAKE_HOST',
    'MTG_RECIPIENTS_DB',
    'MTG_UNIT_FILE',
    'PANEL_LOGS_DIR',
    'SERVER_CFG',
    '_LOG_TTL_CACHE',
]


def init(deps):
    """Принять зависимости из app.py (см. REQUIRED_DEPS) в одноимённые глобалы."""
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('mtg.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    for name in ('MTG_CONFIG', 'MTG_RECIPIENTS_DB', 'MTG_ACCESS_LOG', 'DATA_MTPROTO_DIR'):
        if not globals().get(name):
            raise RuntimeError(f'mtg.init: пустой {name} — путь не построить')
    # Разовый перенос списка получателей из server.json. Делаем на старте, а не
    # при первом открытии вкладки: так его видно в журнале и он проверяем рестартом.
    try:
        _mtg_recipients()
    except Exception as e:
        print(f'[mtg] перенос получателей не удался: {e}', flush=True)


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роуты объявлены раньше."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


def get_mtg_port():
    """Парсит bind-to из /etc/mtg/config.toml ('host:port' или '0.0.0.0:8443').
    Fallback на SERVER_CFG['mtg_port']."""
    try:
        with open(MTG_CONFIG, 'r') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('bind-to'):
                    m = re.search(r'"([^"]+)"', line)
                    if not m:
                        continue
                    val = m.group(1)
                    # формат "0.0.0.0:8443" — берём всё после последнего ':'
                    if ':' in val:
                        try:
                            return int(val.rsplit(':', 1)[1])
                        except (TypeError, ValueError):
                            break
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return SERVER_CFG.get('mtg_port', 8443)

def get_mtg_fake_host():
    """Извлекает реальный fake-host из секрета mtg. Секрет FakeTLS:
       ee<32 hex>...<hex(host)>. Берём secret после префикса, отрезаем 32 hex
       (ключ), остаток декодим из hex как UTF-8.
       Fallback — SERVER_CFG['mtg_fake_host']."""
    try:
        secret = mtg_read_secret() or ''
        # Префиксы: 'ee' (FakeTLS) — единственный, что у нас в ходу. На всякий —
        # также 'dd' (secure) и одиночные стартовые ee/dd до hex-хоста длиной >=2 bytes (4 hex).
        s = secret.strip().lower()
        if s.startswith('ee') or s.startswith('dd'):
            s = s[2:]
        elif s.startswith('7g') or s.startswith('1'):  # base64-ish — не наш случай
            return SERVER_CFG.get('mtg_fake_host', '')
        # Ключевая часть — 32 hex символа = 16 байт
        if len(s) < 32 + 4:
            return SERVER_CFG.get('mtg_fake_host', '')
        host_hex = s[32:]
        # Hex должен быть валидным и чётной длины
        if len(host_hex) % 2 != 0 or re.search(r'[^0-9a-f]', host_hex):
            return SERVER_CFG.get('mtg_fake_host', '')
        try:
            host = bytes.fromhex(host_hex).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return SERVER_CFG.get('mtg_fake_host', '')
        # Базовая проверка валидности доменного имени.
        if host and re.match(r'^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$', host):
            return host
    except Exception:
        pass
    return SERVER_CFG.get('mtg_fake_host', '')

def _find_mtg_paths():
    out = _run_capture(['systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager'])
    candidates = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        if name.startswith('mtg') and name.endswith('.service'):
            candidates.append(name)
    if not candidates and os.path.exists('/etc/systemd/system/mtg.service'):
        candidates.append('mtg.service')
    for unit in candidates:
        # Один `systemctl cat` на юнит вместо двух: и ExecStart, и StandardOutput
        # лежат в одном выводе, а каждый лишний вызов — это ещё один шанс поймать
        # таймаут и уехать не на тот юнит.
        full = _systemctl_cat(unit)
        es = ''
        for line in full.splitlines():
            line = line.strip()
            if line.startswith('ExecStart='):
                es = re.sub(r'^[\+\-@!:]+\s*', '', line[len('ExecStart='):].strip())
        # Пустой ExecStart при НЕПУСТОМ выводе — юнит действительно не наш, идём
        # дальше. А вот пустой вывод целиком означает, что systemd не ответил;
        # раньше здесь стоял безусловный continue, и панель молча переключалась
        # на следующий mtg-юнит (на серверах, где их два) — тот без drop-in.
        # Отсюда и брались NOT OK, которые сами исчезали на следующей проверке.
        if not es and full:
            continue
        if not es:
            # systemd не ответил — берём ExecStart прямо из файла юнита, иначе
            # следом «поедет» и путь к config.toml, а за ним проверка debug=true.
            for base in ('/etc/systemd/system', '/lib/systemd/system',
                         '/usr/lib/systemd/system'):
                try:
                    with open(os.path.join(base, unit), 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('ExecStart='):
                                es = re.sub(r'^[\+\-@!:]+\s*', '',
                                            line[len('ExecStart='):].strip())
                    if es:
                        break
                except Exception:
                    pass
        m = re.search(r'(\S+\.toml)', es)
        cfg = m.group(1) if m else ''
        unit_name = unit.replace('.service', '')
        access_log = ''
        for line in full.splitlines():
            m2 = re.match(r'\s*StandardOutput\s*=\s*append:(\S+)', line)
            if m2:
                access_log = m2.group(1)
                break
        # Ищем фактический drop-in файл — тот, где есть StandardOutput=
        drop_in = ''
        drop_in_log = ''
        drop_in_dir = f'/etc/systemd/system/{unit_name}.service.d'
        if os.path.isdir(drop_in_dir):
            try:
                for fn in sorted(os.listdir(drop_in_dir)):
                    fp = os.path.join(drop_in_dir, fn)
                    try:
                        with open(fp, 'r') as f:
                            content = f.read()
                        if 'StandardOutput' in content:
                            drop_in = fp
                            m3 = re.search(r'^\s*StandardOutput\s*=\s*append:(\S+)',
                                           content, re.M)
                            if m3:
                                drop_in_log = m3.group(1)
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        # Диск — источник истины на случай, когда systemd не ответил: файл
        # drop-in'а мы и так прочитали, и он говорит то же самое, что сказал бы
        # `systemctl cat`. Без этого единственный неудачный вызов превращался
        # в «Сейчас mtg пишет в: (не настроено)».
        if not access_log and drop_in_log:
            access_log = drop_in_log
        return {
            'unit': unit_name,
            'config': cfg,
            'access_log': access_log,
            'drop_in': drop_in,
            'drop_in_dir': drop_in_dir,
            'installed': True,
        }
    return {'unit': '', 'config': '', 'access_log': '', 'drop_in': '', 'drop_in_dir': '', 'installed': False}

def _install_mtg():
    """Ставит MTProto-прокси mtg. (ok, сообщение)."""
    if os.path.exists(MTG_CONFIG):
        # Конфиг с секретом уже есть — трогать его нельзя: клиенты подключаются
        # именно по этому секрету, и перегенерация оборвала бы всех разом.
        port = get_mtg_port()
    else:
        port, busy = pick_free_port(SERVER_CFG.get('mtg_port') or 8443, 'tcp', 'mtg')
        if not port:
            return False, f'не нашлось свободного порта под mtg ({busy})'
    if not os.path.exists(MTG_BIN):
        cmd = (
            'set -e\n'
            'cd /tmp\n'
            'LATEST=$(curl -sI https://github.com/9seconds/mtg/releases/latest '
            '| grep -i ^location | grep -oP "v[\\d.]+" | tr -d "\\r")\n'
            'test -n "$LATEST"\n'
            'ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64) A=arm64;; *) A=amd64;; esac\n'
            'curl -sL "https://github.com/9seconds/mtg/releases/download/${LATEST}/'
            'mtg-${LATEST#v}-linux-${A}.tar.gz" -o mtg.tar.gz\n'
            'tar xzf mtg.tar.gz\n'
            'install -m 0755 mtg-*-linux-*/mtg /usr/local/bin/mtg\n'
            'rm -rf mtg.tar.gz mtg-*-linux-*\n'
        )
        proc = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=300)
        if proc.returncode != 0 or not os.path.exists(MTG_BIN):
            return False, f'не удалось скачать бинарь: {(proc.stderr or proc.stdout)[-500:]}'
    if not os.path.exists(MTG_CONFIG):
        try:
            secret = mtg_generate_secret()
        except Exception as e:
            return False, f'не удалось сгенерировать секрет: {e}'
        os.makedirs(os.path.dirname(MTG_CONFIG), exist_ok=True)
        with open(MTG_CONFIG, 'w') as f:
            f.write(
                '# Файл создан панелью awg-panel при установке MTProto.\n'
                f'secret = "{secret}"\n'
                f'bind-to = "0.0.0.0:{port}"\n'
                # debug нужен панели для журнала подключений — без него лог пуст.
                'debug = true\n'
            )
        os.chmod(MTG_CONFIG, 0o600)
    # Юнит пишем всегда: логи должны идти в общий каталог панели, иначе журнал
    # MTProto окажется пустым, и об этом сразу заругаются «Зависимости».
    os.makedirs(PANEL_LOGS_DIR, exist_ok=True)
    with open(MTG_UNIT_FILE, 'w') as f:
        f.write(
            '[Unit]\n'
            'Description=MTProto proxy (awg-panel)\n'
            'After=network.target\n'
            '\n'
            '[Service]\n'
            'Type=simple\n'
            f'ExecStart={MTG_BIN} run {MTG_CONFIG}\n'
            'Restart=on-failure\n'
            'RestartSec=5\n'
            'LimitNOFILE=infinity\n'
            f'StandardOutput=append:{MTG_ACCESS_LOG}\n'
            f'StandardError=append:{MTG_ACCESS_LOG}\n'
            '\n'
            '[Install]\n'
            'WantedBy=multi-user.target\n'
        )
    run_cmd('systemctl daemon-reload')
    ensure_firewall_port(port, 'tcp', 'MTProto (awg-panel)')
    run_cmd('systemctl enable mtg')
    run_cmd('systemctl restart mtg')
    time.sleep(2)
    state, _, _ = run_cmd('systemctl is-active mtg')
    if state.strip() != 'active':
        out, _, _ = run_cmd('journalctl -u mtg -n 20 --no-pager')
        return False, f'сервис не поднялся: {out[-800:]}'
    SERVER_CFG['mtg_port'] = port
    _save_server_config(SERVER_CFG)
    audit('info', f'mtg установлен и запущен на TCP/{port}')
    return True, f'MTProto запущен на порту {port}'

# ============================================================
# MTProto Proxy (mtg) management
# ============================================================

def mtg_read_secret():
    if not os.path.exists(MTG_CONFIG):
        return ''
    try:
        with open(MTG_CONFIG, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('secret'):
                    # secret = "..."
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        return m.group(1)
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
        return ''
    except Exception:
        return ''

def mtg_write_config(secret):
    """Меняет только secret, сохраняя остальные строки (bind-to, debug, prefer-ip…).
    ВАЖНО: bind-to НЕ трогаем — порт в config.toml это live source of truth (его могли
    сменить вручную через ssh). server.json используем только если bind-to нет вовсе."""
    os.makedirs(os.path.dirname(MTG_CONFIG), exist_ok=True)
    existing = []
    if os.path.exists(MTG_CONFIG):
        try:
            with open(MTG_CONFIG, 'r') as f:
                existing = f.readlines()
        except Exception:
            existing = []
    out = []
    seen_secret = seen_bind = False
    for line in existing:
        if re.match(r'^\s*secret\s*=', line):
            if not seen_secret:
                out.append(f'secret = "{secret}"\n')
                seen_secret = True
            continue
        if re.match(r'^\s*bind-to\s*=', line):
            # сохраняем строку как есть — порт не перезаписываем
            seen_bind = True
            out.append(line if line.endswith('\n') else line + '\n')
            continue
        out.append(line if line.endswith('\n') else line + '\n')
    if not seen_secret:
        out.insert(0, f'secret = "{secret}"\n')
    if not seen_bind:
        # bind-to нет вовсе — синтезируем из live-порта (fallback на server.json)
        idx = next((i for i, l in enumerate(out) if l.startswith('secret')), -1) + 1
        out.insert(idx, f'bind-to = "0.0.0.0:{get_mtg_port()}"\n')
    with open(MTG_CONFIG, 'w') as f:
        f.writelines(out)

def mtg_read_prefer_ip():
    """Читает значение prefer-ip из config.toml ('' если строки нет)."""
    if not os.path.exists(MTG_CONFIG):
        return ''
    try:
        with open(MTG_CONFIG, 'r') as f:
            for line in f:
                if re.match(r'^\s*prefer-ip\s*=', line):
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        return m.group(1)
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        return parts[1].strip().strip('"').strip("'")
        return ''
    except Exception:
        return ''

def mtg_set_prefer_ip(value):
    """Добавляет/обновляет/удаляет строку prefer-ip, сохраняя остальной конфиг.
    value — строка ('prefer-ipv4' и т.п.) либо None/'' для удаления строки."""
    os.makedirs(os.path.dirname(MTG_CONFIG), exist_ok=True)
    existing = []
    if os.path.exists(MTG_CONFIG):
        try:
            with open(MTG_CONFIG, 'r') as f:
                existing = f.readlines()
        except Exception:
            existing = []
    out = []
    seen = False
    for line in existing:
        if re.match(r'^\s*prefer-ip\s*=', line):
            if value and not seen:
                out.append(f'prefer-ip = "{value}"\n')
                seen = True
            # value пустой → строку отбрасываем (удаление)
            continue
        out.append(line if line.endswith('\n') else line + '\n')
    if value and not seen:
        # вставить после bind-to (или после secret) для читаемости
        idx = next((i for i, l in enumerate(out) if re.match(r'^\s*bind-to\s*=', l)), -1)
        if idx < 0:
            idx = next((i for i, l in enumerate(out) if re.match(r'^\s*secret\s*=', l)), -1)
        out.insert(idx + 1, f'prefer-ip = "{value}"\n')
    with open(MTG_CONFIG, 'w') as f:
        f.writelines(out)

def mtg_generate_secret():
    stdout, _, rc = run_cmd(f'{MTG_BIN} generate-secret --hex {SERVER_CFG.get("mtg_fake_host", MTG_FAKE_HOST)}')
    if rc != 0 or not stdout:
        raise RuntimeError('mtg generate-secret failed')
    return stdout.strip()

def mtg_build_link(secret):
    if not secret:
        return ''
    return f'tg://proxy?server={get_server_ip()}&port={get_mtg_port()}&secret={secret}'

def mtg_restart_fast(unit='mtg'):
    """Быстрый перезапуск mtg. Обычный `systemctl restart` ждёт graceful-drain
    активных Telegram-стримов (до ~минуты) — сначала жёстко убиваем старый
    инстанс, затем стартуем новый. Соединения при смене секрета / IP всё равно
    рвутся, так что graceful-ожидание тут не нужно. --no-block: не висим в
    10-сек таймауте run_cmd, готовность подтверждает поллинг на фронте.

    Остановленный руками mtg (inactive) не поднимаем: правка конфига — не
    команда «запустить». Тогда out = 'skipped', и роут сообщает фронту, что
    ждать запуска не нужно. Упавший (failed) перезапускаем."""
    if mtg_unit_state(unit) == 'inactive':
        return 'skipped', '', 0
    run_cmd(f'systemctl kill --signal=SIGKILL {unit}')
    return run_cmd(f'systemctl --no-block restart {unit}')

def mtg_unit_state(unit='mtg'):
    """Сырое состояние юнита: active | activating | deactivating | reloading |
    inactive | failed. Нужно, чтобы отличать «перезапускается» от «остановлен»."""
    out, _, _ = run_cmd(f'systemctl is-active {unit}')
    return out.strip() or 'unknown'

def _run_mtg_scheduler():
    today = time.strftime('%Y-%m-%d')
    cfg = SERVER_CFG
    sa = cfg.get('mtg_scheduled_action')
    sd = cfg.get('mtg_scheduled_at')
    if not sa or not sd or sd > today:
        return
    if sa == 'disable':
        run_cmd('systemctl stop mtg')
        audit('info', f'Auto-disable (по расписанию) MTG')
    cfg['mtg_scheduled_action'] = None
    cfg['mtg_scheduled_at'] = None
    _save_server_config(cfg)

# === MTG logs ===
def _mtg_debug_enabled(cfg_path=None):
    """True if `debug = true` присутствует в указанном mtg-конфиге (по умолчанию MTG_CONFIG)."""
    path = cfg_path or MTG_CONFIG
    try:
        with open(path, 'r') as f:
            for line in f:
                if re.match(r'^\s*debug\s*=\s*true\s*$', line, re.IGNORECASE):
                    return True
    except Exception:
        pass
    return False

def _mtg_journal_records(limit=5000, since=None):
    """Парсит /opt/awg-panel/data/logs/mtg_access.log (JSON-line формат).
    Возвращает список с полями {ts, message, logger, client_ip, stream_id, dc, error, level}.
    Параметр `since` сейчас не используется (оставлен для совместимости)."""
    if not os.path.exists(MTG_ACCESS_LOG):
        return []
    # Читаем хвост файла на ~3MB — этого достаточно для нескольких тысяч строк.
    text = _tail_bytes(MTG_ACCESS_LOG, 3 * 1024 * 1024)
    if not text:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            mtg = json.loads(line)
        except Exception:
            continue
        if not isinstance(mtg, dict):
            continue
        ts_ms = mtg.get('timestamp')
        if isinstance(ts_ms, (int, float)) and ts_ms > 0:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_ms / 1000))
        else:
            ts = ''
        out.append({
            'ts': ts,
            'message': mtg.get('message') or '',
            'logger': mtg.get('logger') or '',
            'client_ip': mtg.get('client-ip') or '',
            'stream_id': mtg.get('stream-id') or '',
            'dc': mtg.get('dc'),
            'error': mtg.get('error') or '',
            'level': mtg.get('level') or '',
        })
    if len(out) > limit:
        out = out[-limit:]
    return out

@bp.route('/api/mtg/logs/debug-status', methods=['GET'])
@_auth
def mtg_logs_debug_status():
    return jsonify({'debug_enabled': _mtg_debug_enabled(), 'config_path': MTG_CONFIG})

@bp.route('/api/mtg/logs/enable-debug', methods=['POST'])
@_auth
def mtg_logs_enable_debug():
    if _mtg_debug_enabled():
        return jsonify({'ok': True, 'changed': False})
    try:
        with open(MTG_CONFIG, 'a') as f:
            f.write('\ndebug = true\n')
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Не удалось записать конфиг: {e}'}), 500
    # Остановленный руками mtg не поднимаем — debug включится при запуске.
    if mtg_unit_state('mtg') == 'inactive':
        audit('info', 'MTG: включён debug=true в config.toml (mtg остановлен, не запускали)')
        return jsonify({'ok': True, 'changed': True, 'restarted': False})
    out, err, rc = run_cmd('systemctl restart mtg')
    if rc != 0:
        return jsonify({'ok': False, 'error': f'Перезапуск mtg не удался: {err or out}'}), 500
    audit('info', 'MTG: включён debug=true в config.toml, mtg перезапущен')
    return jsonify({'ok': True, 'changed': True})

@bp.route('/api/mtg/logs/online', methods=['GET'])
@_auth
def mtg_logs_online_endpoint():
    """IP-адреса с открытыми сейчас стримами (started без finished)."""
    if not _mtg_debug_enabled():
        return jsonify({'debug_enabled': False, 'records': []})
    rows = _mtg_journal_records(limit=2000)
    active = {}
    for r in rows:
        if r['logger'] != 'proxy' or not r['stream_id']:
            continue
        if r['message'] == 'Stream has been started':
            active[r['stream_id']] = r
        elif r['message'] == 'Stream has been finished':
            active.pop(r['stream_id'], None)
    by_ip = {}
    geo_cache = {}
    for r in active.values():
        ip = r['client_ip']
        if not ip:
            continue
        slot = by_ip.setdefault(ip, {'ip': ip, 'streams': 0, 'last_ts': '', 'dcs': set()})
        slot['streams'] += 1
        if r['ts'] > slot['last_ts']:
            slot['last_ts'] = r['ts']
        if r['dc'] is not None:
            slot['dcs'].add(int(r['dc']))
    out = []
    for ip, slot in by_ip.items():
        if ip not in geo_cache:
            geo_cache[ip] = geo_asn_full(ip) or {}
        slot['dcs'] = sorted(slot.pop('dcs'))
        slot['geo'] = geo_cache[ip]
        out.append(slot)
    out.sort(key=lambda x: x['last_ts'], reverse=True)
    return jsonify({'debug_enabled': True, 'records': out})

def _cached_mtg_archive(ttl=2.0):
    """TTL-кеш для архива MTG (читает journald). Источник динамический → кеш по времени."""
    import time as _t
    now = _t.time()
    cached = _LOG_TTL_CACHE.get('mtg_archive')
    if cached and (now - cached[0]) < ttl:
        return cached[1]
    debug_on = _mtg_debug_enabled()
    rows = _mtg_journal_records(limit=5000)
    starts = [r for r in rows
              if r['logger'] == 'proxy' and r['message'] == 'Stream has been started' and r['client_ip']]
    starts.reverse()  # journald oldest-first → newest-first для дальнейшей дедупликации
    out = []
    seen_ips = set()
    geo_cache = {}
    for r in starts:
        ip = r['client_ip']
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        if ip not in geo_cache:
            geo_cache[ip] = geo_asn_full(ip) or {}
        out.append({
            'ts': r['ts'],
            'ip': ip,
            'dc': r['dc'],
            'geo': geo_cache[ip],
        })
    payload = {'debug_enabled': debug_on, 'records': out}
    _LOG_TTL_CACHE['mtg_archive'] = (now, payload)
    return payload

@bp.route('/api/mtg/logs/archive', methods=['GET'])
@_auth
def mtg_logs_archive_endpoint():
    """История уникальных IP — только последний коннект каждого IP, новые сверху."""
    try:
        limit = int(request.args.get('limit', 500))
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 100000))
    payload = _cached_mtg_archive()
    return jsonify({
        'debug_enabled': payload['debug_enabled'],
        'records': payload['records'][:limit],
    })

@bp.route('/api/mtg/status')
@_auth
def mtg_status():
    try:
        _run_mtg_scheduler()
    except Exception as _e:
        audit('warn', f'MTG scheduler error: {_e}')
    _, _, rc = run_cmd('systemctl is-active --quiet mtg')
    secret = mtg_read_secret()
    return jsonify({
        'running': rc == 0,
        'state': _proto_state('mtg'),
        'secret': secret,
        'link': mtg_build_link(secret),
        'server': get_server_ip(),
        'port': get_mtg_port(),
        'fake_host': get_mtg_fake_host(),
        'prefer_ip': mtg_read_prefer_ip(),
        'unit_state': mtg_unit_state(),
        'scheduled_action': SERVER_CFG.get('mtg_scheduled_action'),
        'scheduled_at': SERVER_CFG.get('mtg_scheduled_at'),
        'secret_created': SERVER_CFG.get('mtg_secret_created') or '',
    })

@bp.route('/api/mtg/schedule', methods=['POST'])
@_auth
def mtg_set_schedule():
    data = request.json or {}
    raw_action = data.get('action')
    raw_date = data.get('date')
    if raw_action in (None, '', 'none'):
        action, date = None, None
    elif raw_action == 'disable':
        date = _validate_schedule_date(raw_date)
        if not date:
            return jsonify({'error': 'date must be future YYYY-MM-DD'}), 400
        action = raw_action
    else:
        return jsonify({'error': 'action must be disable|none'}), 400
    cfg = SERVER_CFG
    cfg['mtg_scheduled_action'] = action
    cfg['mtg_scheduled_at'] = date
    _save_server_config(cfg)
    audit('info', f'MTG schedule: {action or "сброшено"} {date or ""}')
    return jsonify({'ok': True, 'scheduled_action': action, 'scheduled_at': date})

def _mtg_port_state():
    """Порт MTProto и кто на нём ещё сидит. TCP, поэтому сосед здесь — VLESS."""
    # Без конфига mtg не установлен: порта нет, конфликтовать не с кем.
    if not os.path.isfile(MTG_CONFIG):
        return {'port': 0, 'configured': False, 'conflict': '', 'xray_port': 0}
    try:
        port = int(get_mtg_port() or 0)
    except Exception:
        port = 0
    xray_port = 0
    try:
        xray_port = int((get_xray_inbound_params() or {}).get('port') or 0)
    except Exception:
        pass
    return {'port': port, 'configured': True,
            'conflict': port_conflict(port, 'tcp', ignore_kind='mtg', include_idle=True),
            'xray_port': xray_port}


@bp.route('/api/mtg/port', methods=['GET'])
@_auth
def mtg_port_get():
    return jsonify({'ok': True, **_mtg_port_state()})


@bp.route('/api/mtg/port', methods=['POST'])
@_auth
def mtg_port_set():
    """Сменить порт MTProto. POST {port}.

    Порт входит в каждую выданную ссылку t.me/proxy — после смены их нужно
    раздать заново. Панель строит ссылки на лету, так что новые будут верными.
    """
    data = request.get_json(silent=True) or {}
    try:
        new_port = int(data.get('port') or 0)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'порт должен быть числом'}), 400
    if not 1 <= new_port <= 65535:
        return jsonify({'ok': False, 'error': 'порт вне диапазона 1–65535'}), 400

    mtg = _find_mtg_paths()
    cfg_path = mtg.get('config') or MTG_CONFIG
    unit = mtg.get('unit') or 'mtg'
    if not os.path.exists(cfg_path):
        return jsonify({'ok': False, 'error': f'нет {cfg_path} — MTProto не настроен'}), 400

    old_port = 0
    try:
        old_port = int(get_mtg_port() or 0)
    except Exception:
        pass
    if new_port == old_port:
        return jsonify({'ok': True, 'unchanged': True, **_mtg_port_state()})

    idle_warn = port_conflict(new_port, 'tcp', ignore_kind='mtg', include_idle=True)
    clash = port_conflict(new_port, 'tcp', ignore_kind='mtg')
    if clash:
        # У VLESS особый вес: на нём же фоллбек в панель, заглушка и выпуск
        # сертификата, поэтому поясняем, чем именно рискуем.
        if 'XRay' in clash:
            clash += ' — на нём же работают панель и её заглушка'
        return jsonify({'ok': False, 'error': clash}), 400

    # Патчим только bind-to: в config.toml лежит секрет прокси и остальные
    # настройки, переписывать файл целиком нельзя.
    try:
        with open(cfg_path, 'r') as f:
            lines = f.read().splitlines()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'не прочитать {cfg_path}: {e}'}), 500

    patched, out = False, []
    for raw in lines:
        stripped = raw.strip()
        if not patched and stripped.startswith('bind-to') and '"' in stripped:
            m = re.search(r'"([^"]+)"', stripped)
            if m:
                val = m.group(1)
                host = val.rsplit(':', 1)[0] if ':' in val else '0.0.0.0'
                indent = raw[:len(raw) - len(raw.lstrip())]
                raw = f'{indent}bind-to = "{host}:{new_port}"'
                patched = True
        out.append(raw)
    if not patched:
        return jsonify({'ok': False, 'error': 'в конфиге нет строки bind-to'}), 500

    backup = cfg_path + '.portbak'
    try:
        shutil.copy2(cfg_path, backup)
        with open(cfg_path, 'w') as f:
            f.write('\n'.join(out) + '\n')
    except Exception as e:
        return jsonify({'ok': False, 'error': f'не записать {cfg_path}: {e}'}), 500

    ensure_firewall_port(new_port, 'tcp', 'MTProto (awg-panel)')
    # Остановленный руками mtg не поднимаем: порт в конфиге, применится при
    # запуске. Проверку «поднялся ли на новом порту» тогда делать не на чем.
    was_stopped = mtg_unit_state(unit) == 'inactive'
    if was_stopped:
        st, err = 'active', ''
    else:
        _, err, rc = run_cmd(f'systemctl restart {unit}')
        st, _, _ = run_cmd(f'systemctl is-active {unit}')
    if st.strip() != 'active':
        # Не поднялся — возвращаем прежний конфиг, иначе прокси остаётся лежать.
        try:
            shutil.copy2(backup, cfg_path)
            run_cmd(f'systemctl restart {unit}')
        except Exception:
            pass
        return jsonify({'ok': False, 'error': f'{unit} не поднялся на {new_port}: {err or "см. journalctl"} — порт возвращён'}), 500

    if old_port:
        try:
            if not port_owner(old_port, 'tcp'):
                run_cmd(f'ufw delete allow {old_port}/tcp')
        except Exception:
            pass
    try:
        os.remove(backup)
    except Exception:
        pass
    SERVER_CFG['mtg_port'] = new_port
    _save_server_config(SERVER_CFG)
    audit('warn', f'MTProto: порт {old_port or "?"} → {new_port}/tcp — ссылки клиентам надо раздать заново'
                  + (f' — внимание: {idle_warn}' if idle_warn else ''))
    return jsonify({'ok': True, 'old_port': old_port, 'warning': idle_warn, **_mtg_port_state()})


@bp.route('/api/mtg/prefer-ip', methods=['POST'])
@_auth
def mtg_set_prefer_ip_endpoint():
    """Тумблер «Приоритет IPv4 к Telegram». enabled=true → prefer-ip = "prefer-ipv4"
    (сначала IPv4, IPv6 как fallback) — лечит зависания при битом IPv6-маршруте сервера.
    enabled=false → строка удаляется (поведение mtg по умолчанию)."""
    data = request.get_json(force=True) or {}
    enabled = bool(data.get('enabled'))
    if enabled:
        # Уважаем настройку, выставленную до нашей опции: если админ уже
        # вручную задал only-ipv4 (или prefer-ipv4) — оставляем как есть,
        # не подменяем своим значением. Иначе ставим prefer-ipv4.
        existing = mtg_read_prefer_ip()
        value = existing if existing in ('prefer-ipv4', 'only-ipv4') else 'prefer-ipv4'
    else:
        value = None
    try:
        mtg_set_prefer_ip(value)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Не удалось записать конфиг: {e}'}), 500
    out, err, rc = mtg_restart_fast()
    if rc != 0:
        return jsonify({'ok': False, 'error': f'Не удалось перезапустить mtg: {err or out}'}), 500
    restarted = out != 'skipped'
    audit('info', f'MTG: prefer-ip = {value or "сброшено (mtg default)"}, '
                  + ('mtg перезапущен' if restarted else 'mtg остановлен — применится при запуске')
                  + f' (from {_client_ip()})')
    return jsonify({'ok': True, 'prefer_ip': value or '', 'restarted': restarted})

@bp.route('/api/mtg/regenerate', methods=['POST'])
@_auth
def mtg_regenerate():
    ip = _client_ip()
    try:
        new_secret = mtg_generate_secret()
    except Exception as e:
        audit('error', f'MTProto secret regenerate FAILED: {e} (from {ip})')
        return jsonify({'error': f'Generate failed: {e}'}), 500
    mtg_write_config(new_secret)
    # быстрый рестарт; готовность подтверждает поллинг на фронте
    restarted = mtg_restart_fast()[0] != 'skipped'
    created = time.strftime('%Y-%m-%d %H:%M')
    cfg = SERVER_CFG
    cfg['mtg_secret_created'] = created
    _save_server_config(cfg)
    audit('warn', f'MTProto secret перегенерирован (новый хвост …{new_secret[-8:]}, host={SERVER_CFG.get("mtg_fake_host", "")}) (from {ip})')
    return jsonify({
        'ok': True,
        'secret': new_secret,
        'link': mtg_build_link(new_secret),
        'secret_created': created,
        'restarted': restarted,
    })


# === MTProto recipients list (кому выдан прокси) ===
def _mtg_recipients():
    """Получатели MTProto из data/mtproto/recipients.json.

    Раньше список лежал внутри server.json. При первом обращении он оттуда
    переносится: server.json — это настройки сервера, а перечень выданных
    прокси — данные протокола, их место рядом с ним.
    """
    try:
        with open(MTG_RECIPIENTS_DB, 'r') as f:
            lst = json.load(f)
        if isinstance(lst, list):
            return lst
    except Exception:
        pass
    legacy = SERVER_CFG.get('mtg_recipients')
    lst = legacy if isinstance(legacy, list) else []
    if legacy is not None:
        _save_mtg_recipients(lst)
        SERVER_CFG.pop('mtg_recipients', None)
        _save_server_config(SERVER_CFG)
        print(f'[layout] mtg_recipients перенесены из server.json в {MTG_RECIPIENTS_DB}', flush=True)
    return lst

def _save_mtg_recipients(lst):
    os.makedirs(DATA_MTPROTO_DIR, exist_ok=True)
    tmp = MTG_RECIPIENTS_DB + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(lst, f, ensure_ascii=False, indent=2)
    os.replace(tmp, MTG_RECIPIENTS_DB)

# Перенос списка получателей из server.json запускает init(): на импорте
# модуля зависимостей ещё нет, да и побочных эффектов у импорта быть не должно.

def _norm_recipient_name(s):
    s = (s or '').strip()
    return s[:64]

@bp.route('/api/mtg/recipients', methods=['GET'])
@_auth
def mtg_recipients_list():
    return jsonify({'recipients': _mtg_recipients()})

@bp.route('/api/mtg/recipients', methods=['POST'])
@_auth
def mtg_recipients_add():
    data = request.get_json(force=True) or {}
    name = _norm_recipient_name(data.get('name'))
    if not name:
        return jsonify({'ok': False, 'error': 'имя пустое'}), 400
    lst = _mtg_recipients()
    rec = {'id': uuid_lib.uuid4().hex, 'name': name, 'created': int(time.time())}
    lst.append(rec)
    _save_mtg_recipients(lst)
    audit('info', f'MTG recipient added: {name}')
    return jsonify({'ok': True, 'recipient': rec})

@bp.route('/api/mtg/recipients/<rid>', methods=['PUT'])
@_auth
def mtg_recipients_rename(rid):
    data = request.get_json(force=True) or {}
    name = _norm_recipient_name(data.get('name'))
    if not name:
        return jsonify({'ok': False, 'error': 'имя пустое'}), 400
    lst = _mtg_recipients()
    for r in lst:
        if r.get('id') == rid:
            old = r.get('name', '')
            r['name'] = name
            _save_mtg_recipients(lst)
            audit('info', f'MTG recipient renamed: {old} -> {name}')
            return jsonify({'ok': True, 'recipient': r})
    return jsonify({'ok': False, 'error': 'не найдено'}), 404

@bp.route('/api/mtg/recipients/<rid>', methods=['DELETE'])
@_auth
def mtg_recipients_delete(rid):
    lst = _mtg_recipients()
    for i, r in enumerate(lst):
        if r.get('id') == rid:
            removed = lst.pop(i)
            _save_mtg_recipients(lst)
            audit('info', f'MTG recipient removed: {removed.get("name", "")}')
            return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'не найдено'}), 404

def _get_mtg_version():
    """`mtg --version` или `mtg version` → 'vX.Y.Z'."""
    bin_path = shutil.which('mtg') or '/usr/local/bin/mtg'
    for args in (['version'], ['--version'], ['-v']):
        try:
            proc = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=5)
            txt = (proc.stdout or proc.stderr or '')
            m = re.search(r'\bv?(\d+\.\d+\.\d+)\b', txt)
            if m:
                return 'v' + m.group(1)
        except Exception:
            continue
    return ''
