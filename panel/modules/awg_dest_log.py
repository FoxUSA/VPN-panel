"""AWG destination logging — куда ходят клиенты: IP из conntrack + домены из dnsmasq.

Первый модуль, вынесенный из app.py. Здесь обкатан паттерн, который дальше
повторяется для остальных доменов:

  * зависимости приезжают одним словарём в init() — модуль ничего не импортирует
    из app.py, поэтому циклического импорта нет и порядок определений не важен;
  * роуты объявлены на уровне модуля в Blueprint, без url_prefix — URL остаются
    ровно теми же, что были в app.py, фронт не трогаем. login_required приезжает
    в init() уже после того, как роуты объявлены, поэтому он подставляется
    прокси-декоратором _auth;
  * фоновый тред НЕ стартует на импорте: только из start_background(), которую
    зовёт app.py, когда всё готово. Импорт модуля не должен иметь побочных
    эффектов — иначе его нельзя ни проверить, ни импортировать дважды.

Что делает сама фича: раз в AWG_DEST_COLLECT_INTERVAL_SEC читает таблицу
соединений, отбирает flow из серверной сети AWG (live из awg0.conf) и дописывает
их в общий AWG-лог с kind='dest'. Если у клиента включён «Логи+» (per-client
dns_local), его DNS указывает на наш dnsmasq — тогда из его query-лога достаётся
имя хоста и подмешивается к dst_ip.
"""

import functools
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time

from flask import Blueprint, jsonify, request

bp = Blueprint('awg_dest_log', __name__)

# Пути, которыми фича владеет целиком. Читаются, только если включён
# глобальный свитч awg_dest_log_enabled.
AWG_DEST_DNSMASQ_CONFIG = '/etc/dnsmasq.d/awg-panel.conf'
AWG_DEST_DNSMASQ_LOG = '/var/log/dnsmasq-awg.log'
AWG_DEST_LOGROTATE = '/etc/logrotate.d/awg-panel-dnsmasq'
# На современных ядрах Debian/Ubuntu /proc/net/nf_conntrack отключён
# (CONFIG_NF_CONNTRACK_PROCFS=n), доступ только через netlink (userspace tool
# из пакета conntrack).
AWG_DEST_COLLECT_INTERVAL_SEC = 10
_AWG_DEST_SEEN_MAX = 50000

# Зависимости от app.py. Пустой словарь до init() — модуль в этом состоянии
# умеет только импортироваться.
_D = {}
_started = False


def init(deps):
    """Принять зависимости от app.py.

    Ожидаются ключи: cfg (SERVER_CFG), save_cfg, audit, login_required,
    load_clients, awg_network_str, awg_iface_ip, tail_bytes, logs_dir,
    access_log, awg_config.
    """
    _D.clear()
    _D.update(deps or {})


def _cfg():
    return _D.get('cfg') or {}


def _enabled():
    return bool(_cfg().get('awg_dest_log_enabled'))


def _auth(fn):
    """Прокси вместо login_required: настоящий декоратор приезжает только в init(),
    а роуты объявляются раньше — на уровне модуля."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        guard = _D.get('login_required')
        if not guard:
            return jsonify({'error': 'module not initialized'}), 503
        return guard(fn)(*a, **kw)
    return wrapper


# === Сбор ===================================================================

def _parse_nf_conntrack_for_awg(net):
    """Yield {src_ip, dst_ip, src_port, dst_port, proto} для соединений из сети net.
    Использует `conntrack -L` (netlink) — /proc/net/nf_conntrack отключён в современных ядрах."""
    text = ''
    bin_path = shutil.which('conntrack')
    if bin_path:
        try:
            proc = subprocess.run(
                [bin_path, '-L'],
                capture_output=True, text=True, timeout=10,
            )
            text = proc.stdout or ''
        except Exception:
            text = ''
    if not text:
        # Fallback на /proc (старые ядра / CONFIG_NF_CONNTRACK_PROCFS=y).
        try:
            with open('/proc/net/nf_conntrack', 'r') as f:
                text = f.read()
        except OSError:
            return
    iface_ip = (_D.get('awg_iface_ip') or (lambda: ''))()
    for line in text.splitlines():
        if 'src=' not in line:
            continue
        m = re.search(
            r'\b(tcp|udp|icmp)\b.*?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)'
            r'(?:\s+sport=(\d+)\s+dport=(\d+))?',
            line,
        )
        if not m:
            continue
        proto, src_ip, dst_ip, sport, dport = m.groups()
        try:
            if ipaddress.ip_address(src_ip) not in net:
                continue
        except ValueError:
            continue
        # Игнорим трафик к самому AWG-интерфейсу/нашему DNS — это служебное, не интересно.
        if dst_ip == iface_ip:
            continue
        yield {
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'src_port': sport or '', 'dst_port': dport or '', 'proto': proto,
        }


def _read_dnsmasq_dst_host_map():
    """{dst_ip: host} из последних 5MB dnsmasq лога (строки 'reply ... is X' / 'cached ... is X')."""
    if not os.path.exists(AWG_DEST_DNSMASQ_LOG):
        return {}
    try:
        text = _D['tail_bytes'](AWG_DEST_DNSMASQ_LOG, 5 * 1024 * 1024)
    except Exception:
        return {}
    cache = {}
    for line in (text or '').splitlines():
        m = re.search(r'\b(?:reply|cached)\s+(\S+)\s+is\s+(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cache[m.group(2)] = m.group(1)
    return cache


def _awg_dest_collector_loop():
    seen = {}
    dns_cache = {}
    last_dns_load = 0
    while True:
        try:
            time.sleep(AWG_DEST_COLLECT_INTERVAL_SEC)
            if not _enabled():
                if seen:
                    seen.clear()
                continue
            try:
                net = ipaddress.ip_network(_D['awg_network_str'](), strict=False)
            except ValueError:
                continue
            now = time.time()
            if now - last_dns_load > 30:
                dns_cache = _read_dnsmasq_dst_host_map()
                last_dns_load = now
            ip_to_pub = {}
            for pk, c in _D['load_clients']().items():
                ip = (c.get('address') or '').replace('/32', '')
                if ip:
                    ip_to_pub[ip] = pk
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            new_records = []
            for flow in _parse_nf_conntrack_for_awg(net):
                key = (flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'], flow['proto'])
                if key in seen:
                    continue
                seen[key] = now
                new_records.append({
                    'ts': ts,
                    'kind': 'dest',
                    'pubkey': ip_to_pub.get(flow['src_ip'], ''),
                    'ip': flow['src_ip'],
                    'src_port': flow['src_port'],
                    'dst_ip': flow['dst_ip'],
                    'dst_port': flow['dst_port'],
                    'proto': flow['proto'],
                    'host': dns_cache.get(flow['dst_ip'], ''),
                })
            if len(seen) > _AWG_DEST_SEEN_MAX:
                items = sorted(seen.items(), key=lambda kv: kv[1])
                seen = dict(items[len(items) // 2:])
            if new_records:
                try:
                    os.makedirs(_D['logs_dir'], exist_ok=True)
                    with open(_D['access_log'], 'a') as f:
                        for r in new_records:
                            f.write(json.dumps(r, ensure_ascii=False) + '\n')
                except Exception:
                    pass
        except Exception:
            pass


def start_background():
    """Поднять коллектор. Зовётся из app.py один раз, на импорте ничего не стартует."""
    global _started
    if _started or not _D:
        return
    _started = True
    threading.Thread(target=_awg_dest_collector_loop, daemon=True).start()


# === Пункт зависимостей =====================================================

def dependency_item():
    """Один пункт «Логирование destinations AWG» для списка зависимостей, или None.

    Виден ТОЛЬКО когда юзер включил глобальный свитч: пока он выключен, ⚠ в шапке
    не должна гореть на то, чего пользователь не просил.
    """
    if not _enabled():
        return None
    iface_ip = _D['awg_iface_ip']()
    awg_config = _D['awg_config']
    dnsmasq_conf_body = (
        f'# managed by awg-panel — DNS-резолвер для логирования доменов AWG-клиентов\n'
        f'listen-address={iface_ip}\n'
        f'bind-interfaces\n'
        f'no-resolv\n'
        f'server=1.1.1.1\n'
        f'server=8.8.8.8\n'
        f'cache-size=1000\n'
        f'log-queries\n'
        f'log-facility={AWG_DEST_DNSMASQ_LOG}\n'
    )
    lr_path = AWG_DEST_LOGROTATE
    lr_body = (
        f'{AWG_DEST_DNSMASQ_LOG} {{\n'
        f'    rotate 10\n'
        f'    size 100M\n'
        f'    compress\n'
        f'    missingok\n'
        f'    notifempty\n'
        f'    copytruncate\n'
        f'}}\n'
    )
    # Сводный статус — все 6 условий
    conntrack_ok = bool(shutil.which('conntrack'))
    dnsmasq_ok = bool(shutil.which('dnsmasq'))
    cfg_ok = False
    try:
        if os.path.exists(AWG_DEST_DNSMASQ_CONFIG):
            with open(AWG_DEST_DNSMASQ_CONFIG, 'r') as _f:
                existing = _f.read()
            cfg_ok = (f'listen-address={iface_ip}' in existing and
                      'log-queries' in existing and
                      AWG_DEST_DNSMASQ_LOG in existing)
    except Exception:
        cfg_ok = False
    try:
        rc = subprocess.run(['systemctl', 'is-active', '--quiet', 'dnsmasq'], timeout=3).returncode
        svc_ok = (rc == 0)
    except Exception:
        svc_ok = False
    lr_ok = os.path.exists(lr_path)
    # Firewall: правила должны быть и в живой iptables, и в PostUp awg0.conf (persist).
    fw_live_ok = False
    try:
        rc1 = subprocess.run(
            ['iptables', '-C', 'INPUT', '-i', 'awg0', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
            timeout=3, capture_output=True,
        ).returncode
        rc2 = subprocess.run(
            ['iptables', '-C', 'INPUT', '-i', 'awg0', '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'],
            timeout=3, capture_output=True,
        ).returncode
        fw_live_ok = (rc1 == 0 and rc2 == 0)
    except Exception:
        fw_live_ok = False
    fw_conf_ok = False
    try:
        with open(awg_config, 'r') as _f:
            awg_text = _f.read()
        fw_conf_ok = '-p udp --dport 53 -j ACCEPT' in awg_text and 'PostUp' in awg_text
    except Exception:
        fw_conf_ok = False
    fw_ok = fw_live_ok and fw_conf_ok
    all_ok = conntrack_ok and dnsmasq_ok and cfg_ok and svc_ok and lr_ok and fw_ok
    # Fix всё одним заходом, идемпотентно.
    # Open DNS на awg0 в живой iptables + дописать в PostUp/PostDown awg0.conf
    # для переживания ребута. Сначала пробуем -C (check), потом -I (insert).
    fix_script = (
        'set -e\n'
        'export DEBIAN_FRONTEND=noninteractive\n'
        f'IFACE_IP="{iface_ip or ""}"\n'
        'if [ -z "$IFACE_IP" ]; then echo "У awg0 нет IP — подними интерфейс и повтори"; exit 1; fi\n'
        'mkdir -p /etc/dnsmasq.d /etc/logrotate.d\n'
        '# Конфиг кладём ДО apt: postinst пакета сам стартует dnsmasq, и с дефолтным\n'
        '# конфигом (слушает все интерфейсы) он падает на :53, занятом systemd-resolved.\n'
        f"cat > {AWG_DEST_DNSMASQ_CONFIG} <<'AWGPANEL_EOF'\n{dnsmasq_conf_body}AWGPANEL_EOF\n"
        f"cat > {lr_path} <<'AWGPANEL_EOF'\n{lr_body}AWGPANEL_EOF\n"
        f'touch {AWG_DEST_DNSMASQ_LOG}\n'
        f'chown dnsmasq:dnsmasq {AWG_DEST_DNSMASQ_LOG} 2>/dev/null || chown root:root {AWG_DEST_DNSMASQ_LOG}\n'
        '# AppArmor: штатный профиль dnsmasq разрешает писать не в любой лог — добавляем наш.\n'
        'if [ -f /etc/apparmor.d/usr.sbin.dnsmasq ]; then\n'
        '  mkdir -p /etc/apparmor.d/local\n'
        f'  grep -qF "{AWG_DEST_DNSMASQ_LOG} w," /etc/apparmor.d/local/usr.sbin.dnsmasq 2>/dev/null || '
        f'echo "{AWG_DEST_DNSMASQ_LOG} w," >> /etc/apparmor.d/local/usr.sbin.dnsmasq\n'
        '  apparmor_parser -r /etc/apparmor.d/usr.sbin.dnsmasq >/dev/null 2>&1 || true\n'
        'fi\n'
        '# Пакеты. postinst может ругнуться на старте сервиса (deb-systemd-invoke) —\n'
        '# это не повод падать: результат проверяем сами ниже.\n'
        'apt-get update >/tmp/awg-dnsmasq-apt.log 2>&1 || true\n'
        'apt-get install -y conntrack dnsmasq >>/tmp/awg-dnsmasq-apt.log 2>&1 || true\n'
        'if ! command -v conntrack >/dev/null || ! command -v dnsmasq >/dev/null; then\n'
        '  echo "=== apt не поставил пакеты, хвост лога: ==="\n'
        '  tail -n 25 /tmp/awg-dnsmasq-apt.log\n'
        '  exit 1\n'
        'fi\n'
        'systemctl unmask dnsmasq >/dev/null 2>&1 || true\n'
        'systemctl enable dnsmasq >/dev/null 2>&1 || true\n'
        'systemctl restart dnsmasq >/dev/null 2>&1 || true\n'
        'if ! systemctl is-active --quiet dnsmasq; then\n'
        '  echo "=== dnsmasq не запустился. Проверка конфига: ==="\n'
        '  dnsmasq --test 2>&1 | tail -n 15\n'
        '  echo "=== Журнал сервиса: ==="\n'
        '  journalctl -u dnsmasq -n 25 --no-pager 2>&1 | tail -n 25\n'
        '  echo "=== Кто занял порт 53: ==="\n'
        '  ss -lunp "sport = :53" 2>/dev/null | head -n 8\n'
        '  exit 1\n'
        'fi\n'
        '# Firewall: открыть UDP/TCP 53 на awg0 (только для туннеля, наружу не торчит).\n'
        'iptables -C INPUT -i awg0 -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i awg0 -p udp --dport 53 -j ACCEPT\n'
        'iptables -C INPUT -i awg0 -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -i awg0 -p tcp --dport 53 -j ACCEPT\n'
        '# Persist в PostUp/PostDown awg0.conf — переживёт ребут.\n'
        f'AWG_CONF={awg_config}\n'
        'if ! grep -qF "i %i -p udp --dport 53 -j ACCEPT" "$AWG_CONF"; then\n'
        '  sed -i \'s|^PostUp = .*|&; iptables -I INPUT -i %i -p udp --dport 53 -j ACCEPT; iptables -I INPUT -i %i -p tcp --dport 53 -j ACCEPT|\' "$AWG_CONF"\n'
        '  sed -i \'s|^PostDown = .*|&; iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT; iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT|\' "$AWG_CONF"\n'
        'fi\n'
    )

    def _mark(cond):
        return '✓' if cond else '✗'

    status_lines = '\n'.join([
        f'{_mark(conntrack_ok)} Пакет conntrack (читать таблицу соединений через netlink)',
        f'{_mark(dnsmasq_ok)} Пакет dnsmasq (локальный DNS-резолвер для логов доменов)',
        f'{_mark(cfg_ok)} Конфиг {AWG_DEST_DNSMASQ_CONFIG}',
        f'{_mark(svc_ok)} Сервис dnsmasq запущен',
        f'{_mark(lr_ok)} logrotate {lr_path} (10×100MB)',
        f'{_mark(fw_ok)} Firewall: UDP/TCP 53 на awg0 в INPUT (live + PostUp awg0.conf)',
    ])
    return {
        'id': 'awg_dest_logging_setup',
        'name': 'Логирование destinations AWG',
        'description': (
            'Чтобы в логах AWG видеть куда ходят клиенты (IP + домены).\n\n'
            'Что нужно:\n' + status_lines + '\n\n'
            'Что сделает автофикс (одним заходом, в правильном порядке):\n'
            '1. apt update + установка conntrack и dnsmasq (если ещё нет)\n'
            f'2. Запишет конфиг {AWG_DEST_DNSMASQ_CONFIG}: listen-address={iface_ip}, log-queries → {AWG_DEST_DNSMASQ_LOG}\n'
            f'3. Запишет {lr_path} — ротация 10×100MB\n'
            '4. enable + restart dnsmasq, проверка что active\n'
            f'5. Откроет UDP/TCP 53 на awg0 в INPUT (iptables, в памяти + persist в PostUp/PostDown {awg_config})\n\n'
            '⏱ Время: 20–60 секунд (до 4 минут при первом apt update / медленном сервере).\n'
            'UI на это время блокируется оверлеем — это нормально, ждите.'
        ),
        'ok': all_ok,
        'fix_cmd': fix_script,
        'fixable': True,
        'long': True,
        'eta_hint': 'Обычно 20–60 сек, до 4 минут на медленном сервере',
    }


# === Роуты ==================================================================

@bp.route('/api/awg/dest-log/toggle', methods=['POST'])
@_auth
def awg_dest_log_toggle():
    """Глобальный свитч conntrack-логирования AWG. POST {enabled: bool}."""
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('enabled'))
    cfg = _D['cfg']
    cfg['awg_dest_log_enabled'] = enabled
    _D['save_cfg'](cfg)
    _D['audit']('info', 'AWG dest-log глобальный свитч → ' + ('ON' if enabled else 'OFF'))
    return jsonify({'ok': True, 'enabled': enabled})


@bp.route('/api/awg/dest-log/state', methods=['GET'])
@_auth
def awg_dest_log_state():
    return jsonify({'enabled': _enabled()})
