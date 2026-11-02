# -*- coding: utf-8 -*-
"""Живые проверки протоколов: то, без чего протокол «запущен», но не работает.

Пункты того же вида, что в «Зависимостях» ({id, name, description, ok,
fixable, fix_internal, …}), — их видит и ⚠ в шапке, и блок «Чтобы … заработал»
в окне ⚙ протокола. Сверх полей «Зависимостей» у пункта есть:

  level — 'block' (протокол у клиентов не работает), 'warn' (работает, но
          что-то отвалится или сломается позже), 'tip' (рекомендация);
  scope — вкладка окна XRay, к которой пункт относится: vless / hy / core / *.

Всё проверяется по живому состоянию сервера — сокеты, ufw, iptables, sysctl,
DNS, — а не по нашим конфигам: серверов тысячи, и что на каждом настроено
руками, панель не знает.
"""
import ipaddress
import os
import re

DEPS = {}


def init(**deps):
    DEPS.update(deps)


def _run(cmd):
    return DEPS['run_cmd'](cmd)


def _audit(level, msg):
    try:
        DEPS['audit'](level, msg)
    except Exception:
        pass


# Уровень для пунктов, которые собирает не этот модуль. Чего нет — 'warn'.
LEVELS = {
    # Не установлен — совет, а не авария: на новом сервере иначе красным горит всё
    # выбранное, хотя кнопка установки и так на экране. Как у Telegram WEB.
    'proto_awg_missing': 'tip', 'proto_xray_missing': 'tip', 'proto_mtg_missing': 'tip',
    'xray_hy_port_udp': 'block', 'xray_hy_port_clash': 'block', 'xray_hy_module': 'block',
    'xray_hy_autoenable': 'warn',
    'hy_firewall_port': 'block', 'hy_port_clash': 'block', 'hy_port_listener': 'block',
    'hy_config': 'block', 'hy_auth_path': 'block', 'hy_auth_script': 'block',
    'awg_subnet_match': 'block',
    'hy_cert_le_available': 'tip',
}


def level_of(item):
    return item.get('level') or LEVELS.get(item.get('id', ''), 'warn')


def scope_of(item):
    """Вкладка окна XRay: у ядра три входа, и пункт показываем там, где он чинится."""
    i = item.get('id', '')
    if item.get('scope'):
        return item['scope']
    if i.startswith('xray_hy_') and i != 'xray_hy_module':
        return 'hy'
    if i.startswith('xray_vless_') or i.startswith('xray_tls_'):
        return 'vless'
    if i == 'proto_xray_missing':
        return '*'
    return 'core'


# === ufw ======================================================================

_RE_TO = re.compile(r'^(\d+)(?::(\d+))?(?:/(tcp|udp))?$')


def _ufw_app_ports(name, cache):
    """Порты профиля ufw («Nginx Full» → [(80,80,'tcp'), (443,443,'tcp')])."""
    if name in cache:
        return cache[name]
    out, _, rc = _run("ufw app info '%s' 2>/dev/null" % name.replace("'", ''))
    res = []
    if rc == 0 and out:
        m = re.search(r'Ports?:\s*\n?(.+?)(?:\n\s*\n|\Z)', out, re.S)
        for chunk in re.split(r'[\s,]+', (m.group(1) if m else '').strip()):
            mm = re.match(r'^(\d+)(?::(\d+))?(?:/(tcp|udp))?$', chunk)
            if mm:
                a = int(mm.group(1))
                res.append((a, int(mm.group(2) or a), mm.group(3)))
        # «80,443/tcp» — протокол стоит только у последнего в списке.
        tail = next((p for _, _, p in reversed(res) if p), None)
        res = [(a, b, p or tail) for a, b, p in res]
    cache[name] = res
    return res


def ufw_allows(port, proto):
    """(ufw_включён, порт_пропускается). Разбор `ufw status verbose` целиком:
    правило «443» без протокола, диапазоны «10000:10100/udp», профили вроде
    «Nginx Full» и политика по умолчанию allow. Подстрока «443/udp» в выводе
    ловила бы и «1443/udp», и пропускала бы правило «443» на оба протокола."""
    out, _, rc = _run('ufw status verbose 2>/dev/null')
    if rc != 0 or 'Status: active' not in (out or ''):
        return False, True
    if re.search(r'Default:[^\n]*allow \(incoming\)', out):
        return True, True
    port = int(port)
    cache = {}
    for line in out.splitlines():
        cols = re.split(r'\s{2,}', line.strip())
        if len(cols) < 3 or not cols[1].startswith('ALLOW'):
            continue
        if 'Anywhere' not in cols[2]:
            continue     # правило только для своих адресов клиентам не помогает
        to = cols[0].replace('(v6)', '').strip()
        if ' on ' in ' %s ' % to:
            continue     # «53/udp on awg0» — только для этого интерфейса
        to = to.split()[-1] if ' ' in to and _RE_TO.match(to.split()[-1]) else to
        m = _RE_TO.match(to)
        ranges = ([(int(m.group(1)), int(m.group(2) or m.group(1)), m.group(3))] if m
                  else _ufw_app_ports(to, cache))
        for a, b, p in ranges:
            if a <= port <= b and (p is None or p == proto):
                return True, True
    return True, False


def ufw_allow(port, proto, comment):
    out, err, rc = _run("ufw allow %d/%s comment '%s'" % (int(port), proto, comment.replace("'", '')))
    if rc != 0:
        return False, (err or out or 'ufw вернул ошибку').strip()
    _audit('info', 'ufw: открыт %d/%s (%s)' % (int(port), proto, comment))
    return True, '%d/%s открыт в ufw' % (int(port), proto)


# === Слушатели портов ===========================================================

def listeners(port, proto):
    try:
        return [s for s in DEPS['listening_sockets']() if s['port'] == int(port) and s['proto'] == proto]
    except Exception:
        return []


def journal_tail(unit, n=3):
    """Последние строки журнала юнита, похожие на причину падения."""
    out, _, _ = _run('journalctl -u %s -n 40 --no-pager -o cat 2>/dev/null' % unit)
    lines = [l.strip() for l in (out or '').splitlines() if l.strip()]
    bad = [l for l in lines if re.search(r'fail|error|denied|in use|invalid|not found|panic|unable|cannot',
                                         l, re.I)]
    return (bad or lines)[-n:]


def service_item(proto, title, unit):
    """«Сервис остановлен / упал» — первым шагом: пока он лежит, остальные
    проверки протокола панель не делает, они бессмысленны."""
    out, _, _ = _run('systemctl is-failed %s 2>/dev/null' % unit)
    failed = (out or '').strip() == 'failed'
    tail = journal_tail(unit) if failed else []
    # Упал — поломка. Остановлен руками — решение пользователя: напоминаем
    # внутри ⚙, но на главной не сигналим (как и «Зависимости», которые
    # остановленный протокол не проверяют вовсе).
    return {
        'id': 'svc_stopped', 'scope': '*', 'level': 'block' if failed else 'tip',
        'name': ('%s упал и не запущен' % title) if failed else ('%s остановлен' % title),
        'description': (('Последнее из журнала %s:\n%s' % (unit, '\n'.join(tail))) if tail else
                        'Клиенты этого протокола сейчас не подключаются.'),
        'ok': False, 'fixable': False, 'ui': 'start', 'ui_label': 'Запустить',
    }


# === AmneziaWG ===================================================================

def _ipt(args):
    out, _, rc = _run('iptables %s 2>/dev/null' % args)
    return (out or '') if rc == 0 else ''


def _awg_net():
    try:
        return ipaddress.ip_interface(DEPS['awg_iface_addr']()).network
    except Exception:
        return None


def _awg_conf_lines():
    try:
        with open(DEPS['awg_config']) as f:
            return f.read().splitlines()
    except Exception:
        return []


def _awg_hook_has(key, needle):
    for line in _awg_conf_lines():
        k, _, v = line.partition('=')
        if k.strip() == key and needle in v:
            return True
    return False


def _awg_persist(up_cmd, down_cmd, marker):
    """Дописывает правило в PostUp/PostDown awg0.conf, чтобы оно пережило
    перезапуск интерфейса и сервера. Остальные строки не трогаем."""
    path = DEPS['awg_config']
    lines = _awg_conf_lines()
    if not lines:
        return False
    if any(l.partition('=')[0].strip() == 'PostUp' and marker in l for l in lines):
        return True
    out, has_up, has_down = [], False, False
    for l in lines:
        k = l.partition('=')[0].strip()
        if k == 'PostUp' and not has_up:
            l, has_up = l.rstrip() + '; ' + up_cmd, True
        elif k == 'PostDown' and not has_down:
            l, has_down = l.rstrip() + '; ' + down_cmd, True
        out.append(l)
    if not has_up or not has_down:
        # Своих хуков нет — вставляем в конец секции [Interface].
        idx = next((i for i, l in enumerate(out) if l.strip().lower() == '[interface]'), -1)
        end = next((i for i in range(idx + 1, len(out)) if out[i].strip().startswith('[')), len(out))
        while end > idx + 1 and not out[end - 1].strip():
            end -= 1
        add = ([] if has_up else ['PostUp = ' + up_cmd]) + ([] if has_down else ['PostDown = ' + down_cmd])
        out[end:end] = add
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write('\n'.join(out) + '\n')
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _audit('info', 'awg0.conf: правило «%s» добавлено в PostUp/PostDown' % marker)
    return True


def _default_iface():
    out, _, _ = _run('ip route show default')
    m = re.search(r'\bdev\s+(\S+)', out or '')
    return m.group(1) if m else ''


def awg_items():
    items = []
    try:
        port = int(DEPS['awg_port']() or 0)
    except Exception:
        port = 0
    if port:
        on, ok = ufw_allows(port, 'udp')
        items.append({
            'id': 'awg_port_ufw', 'level': 'block',
            'name': 'UDP-порт %d открыт в ufw' % port,
            'description': ('Порт AmneziaWG открыт.' if ok else
                            'ufw не пропускает %d/udp: пакеты клиентов до awg0 не доходят — в приложении '
                            '«подключено», но рукопожатия нет. Починка откроет порт.' % port),
            'ok': ok, 'fixable': True, 'fix_internal': 'ph_awg_ufw', 'fix_cmd': '',
        })

    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            fwd = f.read().strip() == '1'
    except Exception:
        fwd = True
    items.append({
        'id': 'awg_ip_forward', 'level': 'block',
        'name': 'Форвардинг IPv4 включён',
        'description': ('net.ipv4.ip_forward = 1.' if fwd else
                        'net.ipv4.ip_forward = 0: рукопожатие проходит, но трафик клиентов дальше сервера не '
                        'идёт — «подключено, интернета нет». Починка включит его сейчас и пропишет в '
                        '/etc/sysctl.d/99-awg-panel.conf, чтобы пережил перезагрузку.'),
        'ok': fwd, 'fixable': True, 'fix_internal': 'ph_awg_forward_sysctl', 'fix_cmd': '',
    })

    net = _awg_net()
    nat = _ipt('-t nat -S POSTROUTING')
    allrules = _ipt('-S')
    if not nat or not allrules:
        # iptables недоступен (чистый nftables и т.п.) — судить не по чему,
        # молчим, а не пугаем ложной тревогой.
        return items
    nat_ok = False
    for line in nat.splitlines():
        if '-j MASQUERADE' not in line and '-j SNAT' not in line:
            continue
        m = re.search(r'-s (\S+)', line)
        if not m:
            nat_ok = True
            break
        try:
            if net and ipaddress.ip_network(m.group(1), strict=False).overlaps(net):
                nat_ok = True
                break
        except ValueError:
            pass
    items.append({
        'id': 'awg_nat', 'level': 'block',
        'name': 'NAT для клиентов AWG',
        'description': ('Трафик клиентов выходит в интернет с адреса сервера.' if nat_ok else
                        'В iptables нет MASQUERADE для подсети %s: пакеты клиентов уходят в интернет с '
                        'внутренними адресами и ответы не возвращаются — «подключено, интернета нет». '
                        'Починка добавит правило сейчас и в PostUp/PostDown awg0.conf.' % (net or 'клиентов')),
        'ok': nat_ok, 'fixable': bool(net), 'fix_internal': 'ph_awg_nat', 'fix_cmd': '',
    })

    # Политику цепочки ufw выставляет сам (DEFAULT_FORWARD_POLICY / incoming),
    # поэтому смотрим на неё, а не на то, включён ли ufw.
    ufw_on = ufw_allows(1, 'tcp')[0]
    fw_lines = [l for l in allrules.splitlines() if re.match(r'-A (FORWARD|ufw[\w-]*forward)\b', l)]
    pol_fwd_accept = '-P FORWARD ACCEPT' in allrules
    in_ok = pol_fwd_accept or any('-i awg0' in l and '-j ACCEPT' in l for l in fw_lines)
    out_ok = pol_fwd_accept or any(('-o awg0' in l or 'ESTABLISHED' in l) and '-j ACCEPT' in l for l in fw_lines)
    items.append({
        'id': 'awg_forward', 'level': 'block',
        'name': 'Фаервол пропускает трафик клиентов AWG дальше сервера',
        'description': ('Цепочка FORWARD пропускает awg0.' if in_ok and out_ok else
                        'Цепочка FORWARD режет трафик awg0 (политика DROP%s): клиенты подключаются, но '
                        'интернета у них нет. Починка добавит ACCEPT для awg0 сейчас и в PostUp/PostDown.'
                        % (', ufw' if ufw_on else '')),
        'ok': in_ok and out_ok, 'fixable': True, 'fix_internal': 'ph_awg_forward', 'fix_cmd': '',
    })

    in_lines = [l for l in allrules.splitlines() if re.match(r'-A (INPUT|ufw[\w-]*input)\b', l)]
    pol_in_accept = '-P INPUT ACCEPT' in allrules
    inp_ok = pol_in_accept or any('-i awg0' in l and '-j ACCEPT' in l and '--dport' not in l for l in in_lines)
    items.append({
        'id': 'awg_input', 'level': 'tip',
        'name': 'Клиенты AWG видят закрытые снаружи сервисы сервера',
        'description': ('Входящие с awg0 разрешены целиком.' if inp_ok else
                        'Входящие с awg0 проходят через те же правила%s, что и из интернета: порты, открытые '
                        'для всех (VLESS, MTProto и т.п.), клиентам AWG через туннель доступны, а закрытые '
                        'снаружи — нет. Интернет у клиентов работает в любом случае. Если клиентам AWG нужен '
                        'доступ к внутренним сервисам сервера (например, к панели по закрытому порту), починка '
                        'разрешит весь вход с awg0 — сейчас и в PostUp/PostDown. Не нужно — можно не трогать.'
                        % (' ufw' if ufw_on else ' фаервола')),
        'ok': inp_ok, 'fixable': True, 'fix_internal': 'ph_awg_input', 'fix_cmd': '',
    })
    return items


def _fix_awg(kind):
    if kind == 'ph_awg_ufw':
        port = int(DEPS['awg_port']() or 0)
        if not port:
            return False, 'порт AWG не определён'
        return ufw_allow(port, 'udp', 'AmneziaWG (awg-panel)')
    if kind == 'ph_awg_forward_sysctl':
        _, err, rc = _run('sysctl -w net.ipv4.ip_forward=1')
        if rc != 0:
            return False, err or 'sysctl вернул ошибку'
        path = '/etc/sysctl.d/99-awg-panel.conf'
        try:
            cur = open(path).read() if os.path.exists(path) else ''
            if 'net.ipv4.ip_forward=1' not in cur.replace(' ', ''):
                with open(path, 'a') as f:
                    f.write('# awg-panel: форвардинг для туннеля AmneziaWG\nnet.ipv4.ip_forward=1\n')
        except Exception as e:
            return False, 'включён до перезагрузки, но %s не записан: %s' % (path, e)
        _audit('info', 'AWG: включён net.ipv4.ip_forward')
        return True, 'форвардинг включён и сохранён в %s' % path
    if kind == 'ph_awg_nat':
        net, dev = _awg_net(), _default_iface()
        if not net:
            return False, 'подсеть awg0 не определена'
        live = '-t nat -%s POSTROUTING -s %s%s -j MASQUERADE' % ('%s', net, (' -o ' + dev) if dev else '')
        if _run('iptables ' + (live % 'C'))[2] != 0:
            _, err, rc = _run('iptables ' + (live % 'A'))
            if rc != 0:
                return False, err or 'iptables вернул ошибку'
        _awg_persist('iptables -t nat -A POSTROUTING -s %s -j MASQUERADE' % net,
                     'iptables -t nat -D POSTROUTING -s %s -j MASQUERADE' % net, 'MASQUERADE')
        _audit('info', 'AWG: добавлен MASQUERADE для %s' % net)
        return True, 'NAT для %s добавлен' % net
    if kind == 'ph_awg_forward':
        for d in ('-i', '-o'):
            if _run('iptables -C FORWARD %s awg0 -j ACCEPT' % d)[2] != 0:
                _, err, rc = _run('iptables -I FORWARD %s awg0 -j ACCEPT' % d)
                if rc != 0:
                    return False, err or 'iptables вернул ошибку'
        _awg_persist('iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -j ACCEPT',
                     'iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT',
                     'FORWARD -i %i')
        _audit('info', 'AWG: FORWARD ACCEPT для awg0')
        return True, 'FORWARD для awg0 разрешён'
    if kind == 'ph_awg_input':
        if _run('iptables -C INPUT -i awg0 -j ACCEPT')[2] != 0:
            _, err, rc = _run('iptables -I INPUT -i awg0 -j ACCEPT')
            if rc != 0:
                return False, err or 'iptables вернул ошибку'
        _awg_persist('iptables -I INPUT -i %i -j ACCEPT', 'iptables -D INPUT -i %i -j ACCEPT', 'INPUT -i %i -j ACCEPT')
        _audit('info', 'AWG: INPUT ACCEPT для awg0')
        return True, 'вход с awg0 разрешён'
    return None


# === XRay: VLESS =================================================================

def _listener_item(iid, title, port, proto, want, unit):
    """Порт слушает именно наш сервис. Чужой слушатель = сервис не поднимется
    или клиенты попадут не туда; пустой порт = сервис жив, а инбаунд нет."""
    owners = sorted({s['process'] or '?' for s in listeners(port, proto)})
    mine = any(want in o for o in owners)
    if mine:
        desc, ok = '%d/%s слушает %s.' % (port, proto, want), True
    elif owners:
        desc, ok = ('%d/%s занят: %s. %s не может его занять — клиенты стучатся не в тот сервис. Освободите '
                    'порт: уберите его из настроек этой службы или остановите её, если она не нужна.'
                    % (port, proto, ', '.join(owners), title)), False
    else:
        tail = journal_tail(unit)
        desc, ok = ('%s запущен, но %d/%s никто не слушает — вход не поднялся.%s'
                    % (title, port, proto, ('\nИз журнала:\n' + '\n'.join(tail)) if tail else '')), False
    return {'id': iid, 'level': 'block', 'name': '%d/%s слушает %s' % (port, proto, title),
            'description': desc, 'ok': ok, 'fixable': False, 'fix_cmd': ''}


def _ufw_item(iid, title, port, proto, fix):
    on, ok = ufw_allows(port, proto)
    return {'id': iid, 'level': 'block', 'name': '%s/%s открыт в ufw' % (port, proto),
            'description': ('Порт открыт.' if ok else
                            'ufw не пропускает %d/%s — клиенты %s упираются в таймаут. Починка откроет порт.'
                            % (port, proto, title)),
            'ok': ok, 'fixable': True, 'fix_internal': fix, 'fix_cmd': ''}


def _hy():
    try:
        from modules.hysteria import service as hy
        return hy
    except Exception:
        return None


LE_HOOK_DIRS = ('/etc/letsencrypt/renewal-hooks/deploy', '/etc/letsencrypt/renewal-hooks/post')


def xray_renew_hook_ok(hy, domain):
    """Перезапустит ли что-нибудь XRay после продления сертификата.

    Смотреть только на хук отдельной Hysteria нельзя: XRay перезапускают и хук
    переноса Hysteria в XRay (awg-panel-xray.sh), и свои скрипты админа, и
    deploy_hook/renew_hook/post_hook прямо в renewal-конфиге сертификата.
    Годится любой из них, если в нём упомянут xray.
    """
    try:
        if hy.renew_hook_installed():
            return True
    except Exception:
        pass
    for d in LE_HOOK_DIRS:
        try:
            names = sorted(os.listdir(d))
        except Exception:
            continue
        for name in names:
            path = os.path.join(d, name)
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                continue
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    if 'xray' in f.read():
                        return True
            except Exception:
                pass
    try:
        conf, _ = hy.le_renewal_conf(domain)
        if conf:
            with open(conf, encoding='utf-8', errors='replace') as f:
                for line in f:
                    k = line.partition('=')[0].strip()
                    if k in ('deploy_hook', 'renew_hook', 'post_hook') and 'xray' in line:
                        return True
    except Exception:
        pass
    return False


def xray_items():
    items = []
    try:
        port = int(DEPS['xray_port']() or 443)
    except Exception:
        port = 443
    items.append(_listener_item('xray_vless_listen', 'XRay', port, 'tcp', 'xray', 'xray'))
    items.append(_ufw_item('xray_vless_ufw', 'VLESS', port, 'tcp', 'ph_xray_ufw'))

    try:
        sec = DEPS['xray_security']() or {}
    except Exception:
        sec = {}
    if sec.get('security') != 'tls':
        return items
    domain = sec.get('cert_domain') or ''
    days = sec.get('cert_days')
    if not domain or (days is None and sec.get('tls_blocked_reason')):
        items.append({'id': 'xray_tls_cert', 'level': 'block', 'name': 'Сертификат для TLS на %d' % port,
                      'description': 'Режим TLS, а сертификата домена нет: %s. Переключите 443 на Reality '
                                     'выше или выпустите сертификат.' % (sec.get('tls_blocked_reason') or '—'),
                      'ok': False, 'fixable': False, 'fix_cmd': ''})
        return items
    if days is not None:
        items.append({
            'id': 'xray_tls_cert', 'level': 'block' if days <= 0 else 'warn',
            'name': 'Срок сертификата %s' % domain,
            'description': ('Действителен ещё %d дн.' % days if days > 14 else
                            ('Сертификат истёк — клиенты VLESS не подключаются: приложение видит '
                             'просроченный TLS и рвёт соединение.' if days <= 0 else
                             'Осталось %d дн. Обычно certbot продлевает сам за 30 дней — раз дошло до '
                             'сюда, автопродление не работает.' % days) +
                            ' Починка перевыпустит сертификат и перезапустит XRay.'),
            'ok': days > 14, 'fixable': True, 'fix_internal': 'ph_xray_cert_renew', 'fix_cmd': '',
            'long': True, 'requires_restart': True,
            'eta_hint': 'Обычно 15–60 сек: certbot подтверждает домен, затем перезапускается XRay',
        })
    # Клиенты стучатся по домену: если A-запись ушла на другой IP (переезд,
    # оранжевое облако Cloudflare), VLESS «просто не работает».
    pub = DEPS['server_ip']() or ''
    try:
        ips, err = DEPS['resolve_a'](domain)
    except Exception:
        ips, err = [], 'resolver'
    if ips and pub:
        ok = pub in ips
        items.append({
            'id': 'xray_tls_domain_ip', 'level': 'block',
            'name': '%s указывает на этот сервер' % domain,
            'description': ('A → %s.' % ', '.join(ips) if ok else
                            'A-запись %s → %s, а IP сервера %s. Клиенты по ссылке идут не сюда. Исправьте '
                            'A-запись у регистратора; если домен на Cloudflare — облако у записи должно быть '
                            'серым (DNS only).' % (domain, ', '.join(ips), pub)),
            'ok': ok, 'fixable': False, 'fix_cmd': ''})
    elif not ips and err in ('имя не существует', 'у имени нет A-записи'):
        items.append({'id': 'xray_tls_domain_ip', 'level': 'block', 'name': '%s есть в DNS' % domain,
                      'description': 'Домен не резолвится (%s) — клиенты не найдут сервер.' % err,
                      'ok': False, 'fixable': False, 'fix_cmd': ''})
    hy = _hy()
    # Автопродление и перезапуск после него. Если отдельная Hysteria уже на
    # сертификате домена, эти же пункты показывает её вкладка — не дублируем.
    if hy and not (hy.bin_installed() and hy.cert_mode() == 'le'):
        try:
            items.append({'id': 'xray_tls_renew_timer', 'level': 'warn',
                          'name': 'Автопродление сертификата (certbot)',
                          'description': 'Сертификат Let’s Encrypt живёт 90 дней. Без таймера certbot он однажды '
                                         'истечёт, и VLESS перестанет подключаться.',
                          'ok': hy.renew_timer_active(), 'fixable': True,
                          'fix_cmd': 'systemctl enable --now certbot.timer'})
            items.append({'id': 'xray_tls_renew_hook', 'level': 'warn',
                          'name': 'XRay подхватывает продлённый сертификат',
                          'description': 'XRay читает сертификат при старте. Без deploy-hook certbot после '
                                         'продления он отдаёт старый, пока его не перезапустят.',
                          'ok': xray_renew_hook_ok(hy, domain), 'fixable': True,
                          'fix_internal': 'ph_xray_renew_hook', 'fix_cmd': '', 'requires_restart': True})
        except Exception:
            pass
    return items


# === MTProto =====================================================================

def mtg_items():
    try:
        port = int(DEPS['mtg_port']() or 0)
    except Exception:
        port = 0
    if not port:
        return []
    return [_listener_item('mtg_port_listen', 'MTProto', port, 'tcp', 'mtg', DEPS.get('mtg_unit') or 'mtg'),
            _ufw_item('mtg_port_ufw', 'MTProto', port, 'tcp', 'ph_mtg_ufw')]


# === Telegram WEB (telemt) =======================================================

def _tg():
    try:
        from modules.tgweb import nginx, service, xray_link
        return service, nginx, xray_link
    except Exception:
        return None


def _tg_front():
    try:
        from modules.tgweb import front
        return front
    except Exception:
        return None


def tgweb_items():
    """Цепочка 443 → (XRay → общий фоллбек →) nginx → telemt. Каждое звено своим
    пунктом: «WEB не работает» без указания звена чинить нечем.

    Кто принимает 443 — решает front.py: XRay в TLS (WEB за его фоллбеком) или
    сам nginx WEB-прокси, когда XRay на 443 нет. Первый пункт — этот выбор."""
    mods = _tg()
    fr = _tg_front()
    if not mods or not fr:
        return []
    svc, ng, xl = mods
    cfg = svc.load_settings()
    if not cfg.get('enabled'):
        return []
    items = []
    fwant, reason, why = fr.decide()
    have = fr.applied()
    xf = fr.xray_facts()
    front_item = {
        'id': 'tgweb_front', 'level': 'block', 'name': 'Вход на 443 для WEB-прокси',
        'ok': bool(fwant) and have == fwant, 'fixable': bool(fwant) and have != fwant,
        'fix_internal': 'ph_tgweb_heal', 'fix_cmd': '',
        'description': why if (fwant and have == fwant) else (
            why + (' Починка переключит вход.' if fwant else '')),
    }
    if reason == 'reality':
        # Переключение режима — решение админа (меняет и то, что видит обычный
        # посетитель), поэтому не починка, а кнопка в окно настроек XRay.
        front_item.update({'ui': 'xray_security', 'ui_label': 'Открыть настройки XRay'})
    items.append(front_item)
    if have == 'xray' and xf.get('installed') and not xf.get('active'):
        items.append({
            'id': 'tgweb_xray_running', 'level': 'block', 'name': 'XRay запущен',
            'ok': False, 'fixable': True, 'fix_internal': 'ph_tgweb_start_xray', 'fix_cmd': '',
            'description': ('XRay остановлен, но включён в автозапуск — 443 сейчас не слушает никто, и WEB-'
                            'прокси (он за фоллбеком XRay) недоступен вместе с VLESS. Починка запустит XRay. '
                            'Если XRay на этом сервере больше не нужен, выключите его вместе с автозапуском '
                            '(⚙ Telegram WEB → «Отдать 443 WEB-прокси») — тогда 443 займёт WEB.'),
        })
    host = svc.public_host()
    items.append({
        'id': 'tgweb_domain', 'level': 'block', 'name': 'Домен WEB-прокси',
        'ok': bool(host), 'fixable': False, 'fix_cmd': '',
        'description': ('Клиенты подключаются к %s.' % host if host else
                        'Не найден домен с сертификатом Let\'s Encrypt. WEB-прокси живёт только на домене с '
                        'настоящим сертификатом, по IP его не поднять.'),
    })
    tls = have == 'xray'
    standalone = have == 'nginx'
    st = xl.state()
    ng_inst = ng.installed()
    ng_act = ng_inst and ng.active()
    items.append({
        'id': 'tgweb_nginx', 'level': 'block', 'name': 'nginx установлен и работает',
        'ok': ng_act, 'fixable': not ng_act, 'fix_internal': 'ph_tgweb_nginx', 'fix_cmd': '',
        'long': not ng_inst, 'eta_hint': 'apt install nginx — обычно 20–60 сек',
        'description': ('nginx переводит реальный адрес клиента из XRay в telemt и разводит запросы: '
                        'префикс WEB-прокси — в telemt, остальное — сайту и панели.' if ng_act else
                        ('nginx не установлен — без него WEB-прокси не получает запросов. Починка поставит пакет.'
                         if not ng_inst else
                         'nginx остановлен. Пока он лежит, панель вернула общий фоллбек XRay напрямую '
                         '(сайт и вход работают), но WEB-прокси недоступен. Починка запустит nginx.')),
    })
    if ng_inst:
        sync = ng.in_sync()
        items.append({
            'id': 'tgweb_nginx_site', 'level': 'block', 'name': 'Блок nginx WEB-прокси на месте',
            'ok': sync, 'fixable': not sync, 'fix_internal': 'ph_tgweb_heal', 'fix_cmd': '',
            'description': ('Файл awg-panel-tgweb совпадает с тем, что генерирует панель.' if sync else
                            'Блок nginx WEB-прокси отсутствует или изменён руками — запросы к префиксу не '
                            'доходят до telemt. Починка перезапишет его (с проверкой nginx -t и откатом).'),
        })
    if standalone:
        cert = fr.tls_cert()
        days = cert.get('days_left')
        items.append({
            'id': 'tgweb_cert', 'level': 'block', 'name': 'Сертификат домена для 443',
            'ok': bool(cert.get('found')) and (days is None or days > 0), 'fixable': False, 'fix_cmd': '',
            'description': ('nginx WEB-прокси отдаёт на 443 сертификат %s%s.' % (
                cert.get('domain') or '?', '' if days is None else ', осталось %d дн.' % days))
            if cert.get('found') else 'Сертификат Let\'s Encrypt не найден — nginx не может слушать 443.',
        })
        items.append(_listener_item('tgweb_listen_443', 'nginx WEB-прокси', 443, 'tcp', 'nginx', 'nginx'))
        items.append(_ufw_item('tgweb_ufw_443', 'Telegram WEB', 443, 'tcp', 'ph_tgweb_ufw'))
        hy = _hy()
        if hy and cert.get('found'):
            try:
                hook_ok = hy.renew_hook_installed()
            except Exception:
                hook_ok = True
            items.append({
                'id': 'tgweb_renew_hook', 'level': 'warn', 'name': 'nginx подхватывает продлённый сертификат',
                'description': 'nginx читает сертификат при старте и reload. Без deploy-hook certbot после '
                               'продления он отдаёт старый, пока его не перезагрузят.',
                'ok': hook_ok, 'fixable': not hook_ok, 'fix_internal': 'ph_xray_renew_hook', 'fix_cmd': '',
            })
    if tls:
        ok = st['wired'] and st['in_sync']
        why = ('Общий фоллбек XRay ведёт в nginx WEB-прокси, сайт и панель — дальше на 127.0.0.1:%s.'
               % st.get('prev'))
        if not ok:
            why = ('Общий фоллбек XRay не ведёт в nginx WEB-прокси — так бывает после переключения режима 443 '
                   'или переустановки XRay. Клиенты WEB попадают на сайт вместо прокси. Починка вернёт запись '
                   '(с проверкой xray -test), XRay перезапустится.')
            if not ng_act:
                why = ('Фоллбек XRay временно возвращён напрямую, потому что nginx не работает — так панель '
                       'не теряет вход на 443. Поднимите nginx (пункт выше), запись вернётся сама.')
        items.append({
            'id': 'tgweb_xray_fallback', 'level': 'block', 'name': 'Фоллбек XRay ведёт в WEB-прокси',
            'ok': ok, 'fixable': (not ok) and ng_act, 'fix_internal': 'ph_tgweb_heal', 'fix_cmd': '',
            'description': why,
        })
    unit = 'telemt'
    for key, title, want in (('web_port', 'WEB-вход telemt', 'telemt'),
                             ('api_port', 'API telemt', 'telemt'),
                             ('nginx_port', 'nginx WEB-прокси', 'nginx')):
        port = int(cfg.get(key) or 0)
        # В режиме «сам на 443» nginx на внутреннем порту не слушает.
        if key == 'nginx_port' and standalone:
            continue
        if port and (want != 'nginx' or ng_act):
            it = _listener_item('tgweb_listen_' + key.split('_')[0], title, port, 'tcp', want,
                                unit if want == 'telemt' else 'nginx')
            # Порт внутренний: снаружи его быть не должно — проверяем адрес.
            exposed = [s for s in listeners(port, 'tcp')
                       if want in (s.get('process') or '') and not str(s.get('addr') or '').startswith(('127.', '[::1]', '::1'))]
            if it['ok'] and exposed:
                it['ok'] = False
                it['description'] = ('%d/tcp слушается не только на 127.0.0.1 — внутренний порт цепочки '
                                     'торчит наружу. Починка перепишет конфиг.' % port)
                it['fixable'], it['fix_internal'] = True, 'ph_tgweb_heal'
            items.append(it)
    # Сквозная проверка — только когда звенья целы, иначе она лишь повторит их.
    if all(i['ok'] for i in items):
        ok, msg = svc.self_test()
        items.append({
            'id': 'tgweb_chain', 'level': 'block', 'name': 'Мост WEB-прокси отвечает через 443',
            'ok': ok, 'fixable': not ok, 'fix_internal': 'ph_tgweb_heal', 'fix_cmd': '',
            'description': ('Панель запросила страницу моста служебным ключом так же, как это делает клиент '
                            'Telegram, — %s.' % msg) if ok else
                           ('Звенья на месте, но сквозной запрос не дошёл: %s. Починка перезапишет конфиг, '
                            'блок nginx и фоллбек и перезапустит telemt.' % msg),
        })
    if cfg.get('cascade') and not svc.cascade_live():
        items.append({
            'id': 'tgweb_cascade', 'level': 'warn', 'name': 'Каскад через ВПН2 применён',
            'ok': False, 'fixable': True, 'fix_internal': 'ph_tgweb_heal', 'fix_cmd': '',
            'description': 'Каскад для Telegram WEB включён в панели, но в конфиге telemt его нет. Починка '
                           'перезапишет конфиг и перезапустит telemt.',
        })
    try:
        upd = svc.update_available()
    except Exception:
        upd = False
    items.append({
        'id': 'tgweb_update', 'level': 'warn', 'name': 'Движок telemt последней версии',
        'ok': not upd, 'fixable': upd, 'fix_internal': 'ph_tgweb_update', 'fix_cmd': '',
        'long': True, 'eta_hint': 'Скачивание, пробный запуск рядом с рабочим, замена — 20–60 сек',
        'description': ('Установлена %s — последняя.' % (svc.installed_version() or '?')) if not upd else
                       ('Установлена %s, вышла %s. Обновление проверит новую версию пробным запуском рядом с '
                        'рабочей и откатится само, если она не заработает.'
                        % (svc.installed_version() or '?', svc.latest_version_nowait())),
        **({'ui': 'update', 'ui_label': 'Обновить до %s' % svc.latest_version_nowait()} if upd else {}),
    })
    items.append({
        'id': 'tgweb_clients_tip', 'level': 'tip', 'name': 'Какие клиенты Telegram это умеют',
        'ok': False, 'fixable': False, 'fix_cmd': '',
        'description': 'WEB-прокси есть в Telegram Desktop 7.1+, iOS 13.0+ (нужна iOS 15) и Android 13.0+. '
                       'На телефонах он работает, пока Telegram открыт на экране; звонки через него не идут. '
                       'Старый клиент на ссылку ответит «обновите приложение».',
    })
    # Починка цепочки перезапускает telemt и ждёт его API, пишет nginx с
    # проверкой — в таймаут gunicorn (30 с) это не всегда укладывается: в фон.
    for it in items:
        if it.get('fix_internal') == 'ph_tgweb_heal':
            it['long'] = True
            it.setdefault('eta_hint', 'Обычно 5–30 сек')
    return items


def _fix_tgweb(kind):
    if not kind.startswith('ph_tgweb_'):
        return None
    mods = _tg()
    if not mods:
        return False, 'пакет Telegram WEB не загружен'
    svc, ng, _ = mods
    if kind == 'ph_tgweb_heal':
        return svc.heal(force=True)
    if kind == 'ph_tgweb_nginx':
        if not ng.installed():
            ok, err = ng.install_package()
            if not ok:
                return False, err
        elif not ng.active():
            _run('systemctl enable --now nginx')
            if not ng.active():
                return False, 'nginx не запускается — см. journalctl -u nginx'
        svc.watch()
        return True, 'nginx работает'
    if kind == 'ph_tgweb_update':
        return svc.update_binary()
    if kind == 'ph_tgweb_start_xray':
        _run('systemctl start xray')
        import time as _t
        _t.sleep(2)
        out, _, _ = _run('systemctl is-active xray')
        if (out or '').strip() != 'active':
            return False, 'XRay не запустился — см. journalctl -u xray'
        svc.watch()
        return True, 'XRay запущен'
    if kind == 'ph_tgweb_ufw':
        return ufw_allow(443, 'tcp', 'Telegram WEB (awg-panel)')
    return None


# === Починка =====================================================================

def fix(kind):
    """(ok, сообщение) или None, если это не наш пункт."""
    r = _fix_awg(kind)
    if r is not None:
        return r
    r = _fix_tgweb(kind)
    if r is not None:
        return r
    if kind == 'ph_xray_ufw':
        return ufw_allow(int(DEPS['xray_port']() or 443), 'tcp', 'XRay VLESS (awg-panel)')
    if kind == 'ph_mtg_ufw':
        return ufw_allow(int(DEPS['mtg_port']() or 0), 'tcp', 'MTProto (awg-panel)')
    if kind == 'ph_xray_renew_hook':
        # Свой путь, а не hy.install_renew_hook(): тот сразу запускает хук, и
        # XRay перезапустился бы посреди этого же запроса — панель за его
        # фоллбеком оборвала бы ответ. Пишем тот же хук, а перезапуск — после.
        hy = _hy()
        if not hy:
            return False, 'модуль сертификатов (hysteria) не загружен'
        try:
            os.makedirs(os.path.dirname(hy.LE_DEPLOY_HOOK), exist_ok=True)
            with open(hy.LE_DEPLOY_HOOK, 'w', encoding='utf-8', newline='\n') as f:
                f.write(hy.RENEW_HOOK_BODY)
            os.chmod(hy.LE_DEPLOY_HOOK, 0o755)
        except Exception as e:
            return False, str(e)
        _audit('info', 'установлен deploy-hook certbot (XRay + nginx), XRay перечитает сертификат')
        DEPS['schedule_xray_restart']()
        return True, 'хук установлен; XRay перезапускается и перечитает сертификат'
    if kind == 'ph_xray_cert_renew':
        hy = _hy()
        if not hy:
            return False, 'модуль сертификатов (hysteria) не загружен'
        domain = (DEPS['xray_security']() or {}).get('cert_domain') or ''
        ok, msg = hy.renew_cert(domain)
        if ok:
            DEPS['schedule_xray_restart']()
            return True, msg + '; XRay перезапускается'
        return False, msg
    return None
