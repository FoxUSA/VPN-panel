"""Установка и обновление AmneziaWG из панели: детект состояния + пошаговый сценарий.

Раньше единственным ответом панели на «AWG не установлен» была ссылка на ручную
инструкцию. Здесь тот же подход, что у XRay и MTProto: панель сама выясняет, что
на сервере есть, а чего нет, и делает недостающее — с показом каждого шага.

AWG отличается от них одним: это **модуль ядра**. Поэтому детект смотрит не только
на бинарь и конфиг, но и на ядро, заголовки, репозиторий и состояние DKMS-сборки, а
сценарий установки идёт ровно в том порядке, в каком ломается на практике: без
заголовков текущего ядра DKMS не соберётся, без собранного модуля не поднимется
интерфейс, без конфига интерфейсу нечего поднимать.

Чего этот модуль намеренно НЕ делает — не собирает модуль из git с правкой версии в
Makefile (путь из ручной инструкции). Там ошибка тихая, а расплата — не поднявшийся
после перезагрузки туннель. Если пакета нет в apt, детект честно скажет, что нужен
репозиторий, и предложит его подключить отдельным шагом.
"""

import os
import re
import subprocess

_D = {}


def init(deps):
    """deps: audit, run_cmd, awg_config, awg_bin, pick_free_port, ensure_firewall_port,
    awg_params_fallback, awg_param_keys, port_fallback, server_ip."""
    _D.clear()
    _D.update(deps or {})


def _sh(cmd, timeout=60):
    """Короткая команда: (rc, output). Вывод склеен — его показываем пользователю."""
    try:
        p = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or '') + (p.stderr or '')).strip()
    except Exception as e:
        return 1, str(e)


def _norm_ver(raw):
    """Версия AmneziaWG как (major, minor, YYYYMMDD) — сравнимая между источниками.

    modinfo отдаёт '3.1.20260812', apt-кандидат — '1.0.0~20260906-0ubuntu1~...',
    где дата апстрим-релиза уезжает за тильду. Приводим оба вида к одному кортежу:
    сравнение только по дате игнорирует ветку, только по номеру — дату релиза.
    """
    if not raw:
        return None
    s = str(raw).strip().lstrip('v')
    m_date = re.search(r'(\d{8})', s)
    date = int(m_date.group(1)) if m_date else 0
    head = s.split('~', 1)[0]
    nums = [int(x) for x in re.findall(r'\d+', head) if len(x) < 8][:2]
    while len(nums) < 2:
        nums.append(0)
    return (nums[0], nums[1], date)


def norm_ver(raw):
    """Публичное имя _norm_ver: app.py нормализует им apt-кандидата для блока версий."""
    return _norm_ver(raw)


def version_info():
    """Что показать в блоке версий: {current, latest, has_update, module_version, source}.

    Показываем версию ПАКЕТА, а не модуля: ею управляет apt, её и имеет смысл
    сравнивать с кандидатом. Версия из modinfo уезжает в module_version — она
    полезна как справка («что реально загружено в ядро»), но несравнима с apt.
    Если модуль стоит мимо apt, показывать нечего кроме неё — тогда она и идёт
    в current, а обновление не предлагается.
    """
    st = detect()
    pkg_inst = _norm_ver(st['apt_installed'])
    pkg_cand = _norm_ver(st['apt_candidate'])
    fmt = lambda v: (f'v{v[0]}.{v[1]}.{v[2]}' if v else '')
    return {
        'current': fmt(pkg_inst) or (('v' + st['module_version']) if st['module_version'] else ''),
        'latest': fmt(pkg_cand),
        'has_update': bool(st['update_available']),
        'module_version': st['module_version'],
        'from_apt': bool(st['apt_installed']),
        'source': 'PPA',
    }


# === Детект ================================================================

def detect():
    """Полная картина состояния AWG на сервере. Ничего не меняет."""
    st = {}
    rc, out = _sh('uname -r')
    st['kernel'] = out if rc == 0 else ''
    rc, out = _sh('. /etc/os-release 2>/dev/null && echo "$ID $VERSION_CODENAME"')
    parts = (out or '').split()
    st['os_id'] = parts[0] if parts else ''
    st['os_codename'] = parts[1] if len(parts) > 1 else ''
    st['headers_ok'] = _sh(f'dpkg -s linux-headers-{st["kernel"]} >/dev/null 2>&1')[0] == 0 if st['kernel'] else False
    # Репозиторий: важен не сам файл в sources.list.d, а видит ли apt пакет.
    rc, out = _sh('apt-cache policy amneziawg-dkms 2>/dev/null')
    cand = ''
    inst = ''
    for line in (out or '').splitlines():
        line = line.strip()
        if line.startswith('Candidate:'):
            cand = line.split(':', 1)[1].strip()
        elif line.startswith('Installed:'):
            inst = line.split(':', 1)[1].strip()
    st['apt_candidate'] = '' if cand in ('', '(none)') else cand
    st['apt_installed'] = '' if inst in ('', '(none)') else inst
    st['repo_ok'] = bool(st['apt_candidate'])
    # Модуль: собран (modinfo видит) и загружен (в lsmod).
    rc, out = _sh('modinfo amneziawg 2>/dev/null')
    ver = ''
    for line in (out or '').splitlines():
        if line.startswith('version:'):
            ver = line.split(':', 1)[1].strip()
            break
    st['module_built'] = rc == 0
    st['module_version'] = ver
    st['module_loaded'] = _sh('lsmod | grep -q "^amneziawg"')[0] == 0
    st['dkms_status'] = _sh('dkms status amneziawg 2>/dev/null')[1]
    # Инструменты и конфиг.
    awg_bin = _D.get('awg_bin') or 'awg'
    st['bin_ok'] = _sh(f'command -v {awg_bin} >/dev/null 2>&1')[0] == 0
    st['quick_ok'] = _sh('command -v awg-quick >/dev/null 2>&1')[0] == 0
    st['config_ok'] = os.path.exists(_D.get('awg_config') or '')
    st['unit_active'] = _sh('systemctl is-active --quiet awg-quick@awg0')[0] == 0
    st['unit_enabled'] = _sh('systemctl is-enabled --quiet awg-quick@awg0')[0] == 0
    st['iface_up'] = _sh('ip link show awg0 >/dev/null 2>&1')[0] == 0
    # Доступна ли новая версия — ТОЛЬКО сравнением apt Installed против Candidate,
    # и сравнивает их сам dpkg, который умеет разбирать эпохи и тильды.
    #
    # Версию из modinfo сюда мешать нельзя: это внутренняя версия исходников
    # апстрима (WIREGUARD_VERSION), другая шкала. Пакет 1.0.0~20260906 собирает
    # модуль, который представляется как 3.1.20260812. Пока апстрим писал туда
    # 1.0.<дата>, шкалы случайно совпадали, и на этом совпадении держалось старое
    # сравнение — оно и звало «обновиться» на версию ниже установленной.
    st['update_available'] = False
    if st['apt_candidate'] and st['apt_installed']:
        rc, _ = _sh(f'dpkg --compare-versions "{st["apt_installed"]}" lt "{st["apt_candidate"]}"')
        st['update_available'] = (rc == 0)
    elif st['apt_candidate'] and not st['apt_installed'] and st['module_built']:
        # Модуль есть, но поставлен мимо apt (собран из исходников). Тогда пакет
        # из PPA — не «обновление», а замена на другую сборку: не навязываем.
        st['update_available'] = False
    st['candidate_ver'] = _norm_ver(st['apt_candidate'])
    st['installed_ver'] = _norm_ver(st['apt_installed'] or st['module_version'])
    st['installed'] = st['bin_ok'] and st['module_built']
    return st


# === Сценарий установки ====================================================

INSTALL_STEPS = [
    'Проверка системы (ядро, дистрибутив)',
    'Заголовки ядра для сборки модуля',
    'Репозиторий AmneziaWG',
    'Обновление списка пакетов',
    'Установка amneziawg (сборка модуля DKMS)',
    'Загрузка модуля в ядро',
    'Серверный конфиг awg0.conf',
    'Порт в фаерволе',
    'Запуск интерфейса awg0',
    'Итоговая проверка',
]


def install(progress, add_repo=True):
    """Полная установка AWG. progress(i, state, detail). Возвращает (ok, сообщение)."""
    st = detect()

    # 1. Система
    progress(0, 'run')
    if not st['kernel']:
        progress(0, 'fail', 'не удалось определить версию ядра')
        return False, 'не определяется ядро — установка невозможна'
    if st['os_id'] not in ('ubuntu', 'debian'):
        progress(0, 'fail', f'дистрибутив {st["os_id"] or "неизвестен"}')
        return False, (f'дистрибутив {st["os_id"] or "неизвестен"} не поддерживается автоустановкой: '
                       'пакеты AmneziaWG есть для Ubuntu/Debian')
    progress(0, 'ok', f'{st["os_id"]} {st["os_codename"]}, ядро {st["kernel"]}')

    # 2. Заголовки ядра — без них DKMS не соберётся, и это самая частая причина.
    progress(1, 'run')
    if st['headers_ok']:
        progress(1, 'ok', 'уже установлены')
    else:
        rc, out = _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y '
                      f'linux-headers-{st["kernel"]} 2>&1 | tail -n 5', timeout=600)
        if _sh(f'dpkg -s linux-headers-{st["kernel"]} >/dev/null 2>&1')[0] != 0:
            progress(1, 'fail', out[-400:])
            return False, (f'не ставятся заголовки linux-headers-{st["kernel"]}. '
                           'Обычно это значит, что ядро новее репозитория — попробуйте '
                           'обновить систему и перезагрузиться.')
        progress(1, 'ok', 'установлены')

    # 3. Репозиторий
    progress(2, 'run')
    if st['repo_ok']:
        progress(2, 'ok', f'пакет доступен: {st["apt_candidate"]}')
    elif not add_repo:
        progress(2, 'fail', 'пакета нет в apt')
        return False, 'репозиторий AmneziaWG не подключён, а подключать запрещено параметром'
    else:
        if st['os_id'] == 'ubuntu':
            rc, out = _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common '
                          '>/dev/null 2>&1; add-apt-repository -y ppa:amnezia/ppa 2>&1 | tail -n 5',
                          timeout=300)
        else:
            # У Debian отдельного репозитория нет: PPA Ubuntu на нём не работает.
            progress(2, 'fail', 'для Debian пакета нет')
            return False, ('на Debian пакета amneziawg в apt нет — модуль собирается из исходников, '
                           'см. инструкцию в блоке версий протокола')
        _sh('apt-get update >/dev/null 2>&1', timeout=300)
        if not detect()['repo_ok']:
            progress(2, 'fail', out[-400:])
            return False, 'репозиторий подключён, но пакет amneziawg-dkms всё равно не виден apt'
        progress(2, 'ok', 'ppa:amnezia/ppa подключён')

    # 4. apt update
    progress(3, 'run')
    rc, out = _sh('apt-get update 2>&1 | tail -n 3', timeout=300)
    progress(3, 'ok' if rc == 0 else 'skip', out[-200:])

    # 5. Сборка модуля — самый долгий шаг, минуты.
    progress(4, 'run', 'компиляция под текущее ядро, это занимает несколько минут')
    rc, out = _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y '
                  'amneziawg amneziawg-dkms amneziawg-tools 2>&1 | tail -n 20', timeout=1800)
    st = detect()
    if not st['module_built']:
        dkms = _sh('cat /var/lib/dkms/amneziawg/*/build/make.log 2>/dev/null | tail -n 20')[1]
        progress(4, 'fail', (dkms or out)[-400:])
        return False, ('модуль не собрался. Хвост лога сборки:\n' + (dkms or out)[-1200:])
    progress(4, 'ok', f'модуль собран, версия {st["module_version"]}')

    # 6. Загрузка модуля
    progress(5, 'run')
    if not st['module_loaded']:
        rc, out = _sh('modprobe amneziawg 2>&1')
        if _sh('lsmod | grep -q "^amneziawg"')[0] != 0:
            progress(5, 'fail', out[-300:])
            return False, f'модуль собран, но не загружается: {out[-300:]}'
    progress(5, 'ok', 'загружен в ядро')

    # 7. Конфиг
    progress(6, 'run')
    if st['config_ok']:
        progress(6, 'ok', 'уже есть, не трогаем')
        port = _D['get_awg_port']()
    else:
        ok, res = _write_server_config()
        if not ok:
            progress(6, 'fail', res)
            return False, f'не удалось создать конфиг: {res}'
        port = res
        progress(6, 'ok', f'создан, UDP-порт {port}, сеть 10.8.1.0/24')

    # 8. Фаервол
    progress(7, 'run')
    try:
        _D['ensure_firewall_port'](int(port), 'udp', 'AmneziaWG (awg-panel)')
        progress(7, 'ok', f'UDP {port} открыт')
    except Exception as e:
        progress(7, 'skip', str(e))

    # 9. Запуск
    progress(8, 'run')
    _sh('systemctl enable awg-quick@awg0 >/dev/null 2>&1')
    rc, out = _sh('systemctl start awg-quick@awg0 2>&1', timeout=90)
    if _sh('ip link show awg0 >/dev/null 2>&1')[0] != 0:
        jrn = _sh('journalctl -u awg-quick@awg0 -n 20 --no-pager 2>&1 | tail -n 20')[1]
        progress(8, 'fail', (out or jrn)[-400:])
        return False, 'интерфейс awg0 не поднялся:\n' + (jrn or out)[-1000:]
    progress(8, 'ok', 'awg0 поднят')

    # 10. Проверка
    progress(9, 'run')
    rc, out = _sh(f'{_D.get("awg_bin") or "awg"} show awg0 2>&1 | head -n 5')
    if rc != 0:
        progress(9, 'fail', out[-300:])
        return False, f'awg show не отвечает: {out[-300:]}'
    progress(9, 'ok', out[:200])
    final = detect()
    _D['audit']('info', f'AmneziaWG установлен из панели: модуль {final["module_version"]}, порт {port}')
    return True, (f'AmneziaWG установлен: модуль {final["module_version"]}, интерфейс awg0 поднят, '
                  f'UDP-порт {port}. Можно добавлять клиентов.')


def _write_server_config():
    """Создаёт awg0.conf с нуля: ключи, подсеть, порт, obf-параметры, PostUp/PostDown.

    Возвращает (True, port) или (False, причина). Существующий файл не трогает —
    в нём приватный ключ сервера, и перезапись оборвала бы всех клиентов разом.
    """
    cfg_path = _D['awg_config']
    if os.path.exists(cfg_path):
        return False, 'конфиг уже существует'
    awg_bin = _D.get('awg_bin') or 'awg'
    rc, priv = _sh(f'{awg_bin} genkey')
    if rc != 0 or not priv:
        return False, f'не сгенерировался приватный ключ: {priv}'
    port, busy = _D['pick_free_port'](_D.get('port_fallback') or 443, 'udp', 'awg')
    if not port:
        return False, f'не нашлось свободного UDP-порта ({busy})'
    # Подсеть берём свободную: 10.8.1.0/24 по умолчанию, но если такая уже есть
    # на машине (другой туннель, docker), сдвигаемся — иначе маршруты передерутся.
    rc, routes = _sh('ip -4 route show')
    subnet = ''
    for third in range(1, 60):
        cand = f'10.8.{third}.'
        if cand not in (routes or ''):
            subnet = cand
            break
    if not subnet:
        return False, 'не нашлось свободной подсети 10.8.x.0/24'
    params = _D.get('awg_params_fallback') or {}
    obf = '\n'.join(f'{k} = {v}' for k, v in params.items())
    # PostUp ставит и NAT, и INPUT ACCEPT: без второго клиенты проходят handshake,
    # но не достучатся до сервисов на сервере, если политика INPUT — DROP.
    body = (
        '# Создан панелью awg-panel при установке AmneziaWG.\n'
        '[Interface]\n'
        f'PrivateKey = {priv}\n'
        f'Address = {subnet}1/24\n'
        f'ListenPort = {port}\n'
        f'{obf}\n'
        'PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; '
        'iptables -t nat -A POSTROUTING -o $(ip route show default | awk \'{print $5; exit}\') -j MASQUERADE; '
        'iptables -I INPUT -i %i -j ACCEPT\n'
        'PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; '
        'iptables -t nat -D POSTROUTING -o $(ip route show default | awk \'{print $5; exit}\') -j MASQUERADE; '
        'iptables -D INPUT -i %i -j ACCEPT\n'
    )
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    with open(cfg_path, 'w') as f:
        f.write(body)
    os.chmod(cfg_path, 0o600)
    # Форвардинг: без него туннель поднимется, но трафик клиентов никуда не пойдёт.
    _sh('sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1')
    if not os.path.exists('/etc/sysctl.d/99-awg-panel.conf'):
        with open('/etc/sysctl.d/99-awg-panel.conf', 'w') as f:
            f.write('# awg-panel: форвардинг для туннеля AmneziaWG\nnet.ipv4.ip_forward=1\n')
    return True, port


# === Сценарий обновления ===================================================

UPDATE_STEPS = [
    'Проверка доступной версии',
    'Обновление пакета (пересборка модуля)',
    'Проверка новой версии модуля',
    'Перезагрузка модуля и интерфейса',
]


def update(progress):
    """Обновление модуля через apt. Туннель падает на несколько секунд на шаге 4."""
    st = detect()
    progress(0, 'run')
    if not st['module_built']:
        progress(0, 'fail', 'модуль не установлен')
        return False, 'AmneziaWG не установлен — обновлять нечего'
    _sh('apt-get update >/dev/null 2>&1', timeout=300)
    st = detect()
    if not st['repo_ok']:
        progress(0, 'fail', 'пакета нет в apt')
        return False, ('пакет amneziawg-dkms не виден apt — обновление возможно только из '
                       'исходников, см. инструкцию в блоке версий протокола')
    if not st['update_available']:
        progress(0, 'ok', f'уже актуальная версия {st["module_version"]}')
        return True, f'Обновление не требуется: установлена версия {st["module_version"]}'
    progress(0, 'ok', f'{st["module_version"]} → {st["apt_candidate"]}')

    progress(1, 'run', 'пересборка DKMS под текущее ядро, несколько минут')
    was = st['module_version']
    # Состояние интерфейса запоминаем ДО пересборки: к финальному шагу вернём его
    # как было, а не «как правильнее».
    was_up = st['iface_up']
    rc, out = _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y '
                  'amneziawg amneziawg-dkms amneziawg-tools 2>&1 | tail -n 20', timeout=1800)
    progress(1, 'ok' if rc == 0 else 'fail', out[-300:])
    if rc != 0:
        return False, 'apt не смог обновить пакет:\n' + out[-1000:]

    progress(2, 'run')
    st = detect()
    if st['module_version'] == was:
        # Частый и совершенно нормальный случай: установленный модуль новее того,
        # что лежит в репозитории (собран из исходников), и apt правомерно ничего
        # не менял. Это не ошибка, и перезагрузка тут ни при чём.
        if not st['update_available']:
            progress(2, 'ok', f'установленная версия {was} не ниже пакета в репозитории')
            return True, (f'Обновление не требуется: установлен модуль {was}, в репозитории — '
                          f'{st["apt_candidate"]}. Версия на сервере не ниже.')
        progress(2, 'fail', f'версия не изменилась: {was}')
        return False, (f'пакет обновлён, но modinfo показывает прежнюю версию {was}. '
                       'Собранный модуль не подхватился — помогает перезагрузка сервера.')
    progress(2, 'ok', f'собран {st["module_version"]}')

    # Перезагрузка модуля. Интерфейс возвращаем ровно в то состояние, в котором
    # застали: поднимать самим протокол, который пользователь остановил (например,
    # потому что его порт занят другим инбаундом), — значит чинить то, что не ломалось,
    # и ловить чужую ошибку «Address already in use».
    if was_up:
        progress(3, 'run', 'клиенты отключатся на несколько секунд')
        rc, out = _sh('awg-quick down awg0 2>&1; rmmod amneziawg 2>&1; modprobe amneziawg 2>&1; '
                      'awg-quick up awg0 2>&1', timeout=120)
        if _sh('ip link show awg0 >/dev/null 2>&1')[0] != 0:
            hint = ''
            if 'in use' in (out or '').lower():
                hint = ('\nПохоже, UDP-порт AWG занят другим сервисом — проверьте порт на плитке '
                        'AmneziaWG.')
            progress(3, 'fail', out[-400:])
            return False, ('модуль обновлён, но интерфейс не поднялся обратно:\n' + out[-800:]
                           + hint + '\nМожно поднять вручную: `systemctl start awg-quick@awg0`.')
        progress(3, 'ok', 'awg0 снова поднят')
    else:
        # Интерфейс был опущен — только меняем модуль в памяти, если он там висит.
        progress(3, 'run', 'интерфейс остановлен — поднимать не будем')
        rc, out = _sh('rmmod amneziawg 2>&1; modprobe amneziawg 2>&1', timeout=60)
        progress(3, 'ok', 'перезагружен только модуль, интерфейс оставлен остановленным')
    _D['audit']('info', f'AmneziaWG обновлён из панели: {was} → {st["module_version"]}'
                        + ('' if was_up else ' (интерфейс был остановлен, не поднимали)'))
    tail = ('интерфейс поднят.' if was_up
            else 'интерфейс оставлен остановленным — таким он и был до обновления.')
    return True, f'AmneziaWG обновлён: {was} → {st["module_version"]}, {tail}'


# === Пункт для списка зависимостей ==========================================

def dependency_items():
    """Пункты для «Проверки зависимостей»: установка и, отдельно, обновление."""
    st = detect()
    items = []

    def _mark(c):
        return '✓' if c else '✗'

    if not st['installed']:
        status = '\n'.join([
            f'{_mark(bool(st["kernel"]))} Ядро: {st["kernel"] or "не определено"}',
            f'{_mark(st["headers_ok"])} Заголовки ядра (нужны для сборки DKMS)',
            f'{_mark(st["repo_ok"])} Пакет в apt: {st["apt_candidate"] or "не виден"}',
            f'{_mark(st["module_built"])} Модуль amneziawg собран',
            f'{_mark(st["bin_ok"] and st["quick_ok"])} Утилиты awg / awg-quick',
            f'{_mark(st["config_ok"])} Конфиг {_D["awg_config"]}',
            f'{_mark(st["iface_up"])} Интерфейс awg0 поднят',
        ])
        items.append({
            'id': 'proto_awg_missing',
            'name': 'AmneziaWG включён в панели, но не установлен',
            'description': (
                'Панель поставит AmneziaWG целиком и покажет каждый шаг.\n\n'
                'Сейчас на сервере:\n' + status + '\n\n'
                'Что сделает установка:\n'
                '1. Поставит заголовки текущего ядра — без них модуль не соберётся\n'
                '2. Подключит репозиторий AmneziaWG (ppa:amnezia/ppa), если пакета нет\n'
                '3. Установит amneziawg + dkms + tools, это соберёт модуль под ваше ядро\n'
                '4. Загрузит модуль и проверит, что ядро его приняло\n'
                '5. Создаст awg0.conf: ключи сервера, свободная подсеть, свободный UDP-порт, '
                'параметры обфускации, NAT и разрешающее правило INPUT\n'
                '6. Откроет порт в ufw, включит форвардинг, поднимет интерфейс\n\n'
                '⏱ Время: 3–10 минут, основное — компиляция модуля.\n'
                'Существующий конфиг, если он вдруг есть, не перезаписывается.'
            ),
            'ok': False,
            'fix_cmd': '',
            'fix_internal': 'awg_install',
            'fixable': True,
            'long': True,
            'eta_hint': 'Обычно 3–10 минут: собирается модуль ядра',
        })
        return items

    if st['update_available']:
        items.append({
            'id': 'awg_module_update',
            'name': f'AmneziaWG: доступна новая версия модуля ({st.get("candidate_date", "")})',
            'description': (
                f'Пакет amneziawg-dkms: установлен {st["apt_installed"] or "—"}, '
                f'в репозитории {st["apt_candidate"]}.\n'
                f'Загруженный модуль сообщает версию {st["module_version"] or "—"} — это внутренняя '
                'метка исходников апстрима, с версией пакета она не сравнивается.\n\n'
                'Обновление пересоберёт модуль под текущее ядро и перезагрузит его.\n'
                '⚠ Если интерфейс поднят, туннель разорвётся на несколько секунд — клиенты '
                'переподключатся сами. Остановленный интерфейс поднимать не будем.\n\n'
                '⏱ Время: 2–8 минут.'
            ),
            'ok': False,
            'fix_cmd': '',
            'fix_internal': 'awg_update',
            'fixable': True,
            'ui': 'update', 'ui_label': 'Обновить модуль',
            'long': True,
            'eta_hint': 'Обычно 2–8 минут: пересборка модуля',
        })
    return items
