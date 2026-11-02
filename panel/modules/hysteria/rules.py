"""Глобальные серверные правила Hysteria и каскад через mihomo.

У hysteria список доступа (acl) один на весь сервер: в момент авторизации
пользователь известен, а в момент маршрутизации — уже нет. Поэтому здесь живут
ровно те правила, которые действуют сразу на всех: те же три режима, что у
Global rules XRay, плюс каскад — отправка всего трафика в socks5 движка ВПН2.

Состояние хранится как pending/applied (data/hysteria/global.json), как у XRay:
правки копятся, пока пользователь не нажмёт «Применить». Здесь это важнее, чем
у XRay: применение перезапускает сервис, а перезапуск рвёт все живые сессии.
"""
import os
import time

from . import (ACL_FILE, DATA_DIR, DEPS, GLOBAL_FILE, _read_json, _write_json,
               audit, load_settings, save_settings)

# Имена аутбаундов в config.yaml. Первый в списке — маршрут по умолчанию (так
# устроена hysteria), поэтому каскад включается перестановкой списка, а не
# отдельным правилом: иначе пришлось бы дублировать его в каждом режиме.
OUT_DIRECT = 'direct'
OUT_CASCADE = 'cascade'

DEFAULT_STATE = {'enabled': False, 'mode': 'lists', 'lists': [], 'countries': [],
                 # Ежемесячный сброс общего счётчика трафика Hysteria — ровно как
                 # у Global rules XRay: pending для него не имеет смысла, поле
                 # пишется сразу в оба состояния (см. save_field).
                 'traffic_reset_day': None, 'traffic_last_reset': None}

# Файлы geoip/geosite в формате v2ray. Свои не качаем: если рядом стоит XRay,
# берём его — они одинаковые, а лишняя копия базы это лишние 60 МБ и лишний
# источник расхождений. Если ничего не нашлось, hysteria скачает их сама
# в рабочий каталог (data/hysteria/), это её штатное поведение.
_GEO_DIRS = ('/usr/local/share/xray', '/usr/share/xray', '/usr/local/share/v2ray')


def norm_state(state):
    """Приводит состояние к известным полям: в файле мог остаться мусор от
    прошлых версий, а на вход приходит произвольный JSON от фронта."""
    s = dict(DEFAULT_STATE)
    if isinstance(state, dict):
        s['enabled'] = bool(state.get('enabled'))
        mode = state.get('mode') or 'lists'
        s['mode'] = mode if mode in ('lists', 'via', 'direct') else 'lists'
        s['lists'] = [str(x) for x in (state.get('lists') or [])]
        s['countries'] = sorted({str(c).upper()[:2] for c in (state.get('countries') or []) if c})
        rd = state.get('traffic_reset_day')
        try:
            rd = int(rd) if rd not in (None, '', 0, '0') else None
            if rd is not None and not 1 <= rd <= 31:
                rd = None
        except (TypeError, ValueError):
            rd = None
        s['traffic_reset_day'] = rd
        lr = state.get('traffic_last_reset')
        s['traffic_last_reset'] = lr if isinstance(lr, str) and lr else None
    return s


def load_global():
    blob = _read_json(GLOBAL_FILE, {})
    if not isinstance(blob, dict):
        blob = {}
    return {
        'pending': norm_state(blob.get('pending')),
        'applied': norm_state(blob.get('applied')),
        'last_update': blob.get('last_update') or '',
    }


def save_global(blob):
    _write_json(GLOBAL_FILE, blob)


def save_pending(state):
    """Запоминает намерение без применения — чтобы правки не потерялись при F5.

    Поля ежемесячного сброса приходить с фронта не должны: у них своя кнопка и
    свой роут, а тут они затёрлись бы дефолтом при каждом клике по свитчу.
    """
    blob = load_global()
    keep = blob['pending']
    state = norm_state(state)
    state['traffic_reset_day'] = keep.get('traffic_reset_day')
    state['traffic_last_reset'] = keep.get('traffic_last_reset')
    blob['pending'] = state
    save_global(blob)
    return blob


def save_field(field, value):
    """Пишет поле сразу в pending И applied: для расписания pending не имеет
    смысла — «Применить» перезапускает сервис, а день сброса этого не требует."""
    blob = load_global()
    blob['pending'][field] = value
    blob['applied'][field] = value
    save_global(blob)
    return blob


# --- каскад -----------------------------------------------------------------

def cascade_wanted():
    return bool(load_settings().get('cascade'))


def cascade_live():
    """Факт, а не намерение: реально ли в config.yaml прописан socks движка.

    config.yaml у нас производный от settings.json, но читаем именно его —
    настройка могла быть сохранена, а конфиг ещё не перезаписан (например,
    сервис не был установлен в тот момент)."""
    try:
        with open(os.path.join(DATA_DIR, 'config.yaml'), 'r', encoding='utf-8') as f:
            return ('name: %s' % OUT_CASCADE) in f.read()
    except Exception:
        return False


def set_cascade(on):
    """Включает/снимает каскад и перезапускает сервис. (ok, текст)."""
    from . import service
    cfg = load_settings()
    cfg['cascade'] = bool(on)
    save_settings(cfg)
    # acl адресует трафик по ИМЕНИ аутбаунда, а каскад это имя меняет. Без
    # пересборки файла правила ссылались бы на несуществующий «cascade», и
    # hysteria отказалась бы стартовать вовсе.
    applied = load_global()['applied']
    if applied.get('enabled'):
        text = build_acl(applied)
        if not text:
            # Пустой acl тут означает, что списки не собрались. Оставить старый
            # файл нельзя (он ссылается на прежний аутбаунд), затереть — значит
            # молча снять правила. Поэтому откатываем настройку и говорим прямо.
            cfg['cascade'] = not bool(on)
            save_settings(cfg)
            return False, 'не удалось пересобрать правила — каскад не переключён'
        write_acl(text)
    if not service.bin_installed():
        # Намерение сохранено, применится при установке — как у XRay/mtg,
        # где каскад ждёт запуска движка.
        return True, 'сохранено (сервис не установлен)'
    service.write_config(cfg)
    ok, err = service.apply_changes()
    if not ok:
        return False, err
    audit('info', 'каскад через ВПН2 %s' % ('включён' if on else 'снят'))
    return True, ('включён' if on else 'снят')


# --- ACL --------------------------------------------------------------------

def _geo_files():
    for d in _GEO_DIRS:
        ip, site = os.path.join(d, 'geoip.dat'), os.path.join(d, 'geosite.dat')
        if os.path.isfile(ip) and os.path.isfile(site):
            return ip, site
    return '', ''


def _acl_targets(domains, ips, outbound):
    """Строки acl вида `outbound(адрес)` для набора доменов и подсетей.

    Каталог хранит домены в нотации XRay (domain:/full:/keyword:), а hysteria
    понимает только точное имя и glob — поэтому суффикс разворачивается в две
    строки: сам домен и `*.домен` (иначе `example.com` не совпал бы с правилом
    для своих поддоменов, и наоборот).
    """
    lines = []
    for d in sorted(domains):
        d = d.strip().lower()
        if not d:
            continue
        if d.startswith('full:'):
            lines.append('%s(%s)' % (outbound, d[5:]))
        elif d.startswith('keyword:'):
            lines.append('%s(*%s*)' % (outbound, d[8:]))
        elif d.startswith('regexp:'):
            continue                      # regexp в acl нет — молча пропускаем
        else:
            bare = d[7:] if d.startswith('domain:') else d
            if not bare:
                continue
            lines.append('%s(%s)' % (outbound, bare))
            lines.append('%s(*.%s)' % (outbound, bare))
    for ip in sorted(ips):
        ip = ip.strip()
        if ip:
            lines.append('%s(%s)' % (outbound, ip))
    return lines


def build_acl(state, force_refresh=False):
    """Текст acl-файла для состояния. Пустая строка = правил нет."""
    state = norm_state(state)
    if not state.get('enabled'):
        return ''
    primary = OUT_CASCADE if cascade_wanted() else OUT_DIRECT
    mode = state['mode']
    lines = ['# Файл создан панелью awg-panel из data/hysteria/global.json.',
             '# Ручные правки будут перезаписаны при следующем «Применить».']
    if mode == 'lists':
        agg = {'domain': set(), 'ip': set()}
        fn = DEPS.get('aggregate_lists')
        if fn:
            try:
                agg = fn(state.get('lists') or [], force_refresh=force_refresh) or agg
            except Exception as e:
                audit('warn', 'списки правил не собрались: %s' % e)
                return ''
        if not (agg.get('domain') or agg.get('ip')):
            return ''
        # Порядок критичен: hysteria берёт ПЕРВОЕ совпадение сверху вниз.
        # DNS пропускаем всегда — иначе клиент не сможет даже отрезолвить
        # домены из белого списка и весь трафик упрётся в reject(all).
        lines.append('%s(all, udp/53)' % primary)
        lines += _acl_targets(agg.get('domain') or (), agg.get('ip') or (), primary)
        lines.append('reject(all)')
    elif mode == 'via':
        if not state['countries']:
            return ''
        lines.append('%s(all, udp/53)' % primary)
        for cc in state['countries']:
            lines.append('%s(geoip:%s)' % (primary, cc.lower()))
        lines.append('reject(all)')
    elif mode == 'direct':
        if not state['countries']:
            return ''
        # Чёрный список: перечисленные страны режем, остальное идёт маршрутом
        # по умолчанию (первый outbound) — своей строки для него не нужно.
        for cc in state['countries']:
            lines.append('reject(geoip:%s)' % cc.lower())
    return '\n'.join(lines) + '\n'


def write_acl(text):
    os.makedirs(DATA_DIR, exist_ok=True)
    if not text:
        try:
            os.remove(ACL_FILE)
        except OSError:
            pass
        return False
    tmp = '%s.tmp' % ACL_FILE
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, ACL_FILE)
    return True


def acl_active():
    return os.path.isfile(ACL_FILE) and os.path.getsize(ACL_FILE) > 0


def config_block():
    """Куски config.yaml: outbounds и acl. Зовётся из service.render_config().

    Аутбаунды объявляем всегда: без них у hysteria вообще один маршрут, и
    правилу некуда было бы адресовать трафик. Первым идёт тот, что должен быть
    маршрутом по умолчанию.
    """
    lines = ['', 'outbounds:']
    direct_block = ['  - name: %s' % OUT_DIRECT, '    type: direct']
    cascade_block = []
    if cascade_wanted():
        addr = DEPS.get('mihomo_socks') or '127.0.0.1:7890'
        if callable(addr):
            try:
                addr = addr() or '127.0.0.1:7890'
            except Exception:
                addr = '127.0.0.1:7890'
        cascade_block = ['  - name: %s' % OUT_CASCADE,
                         '    type: socks5',
                         '    socks5:',
                         '      addr: %s' % addr]
    # Каскад первым = маршрут по умолчанию для всего, что не поймал acl.
    lines += (cascade_block + direct_block) if cascade_block else direct_block
    if acl_active():
        lines += ['', 'acl:', '  file: %s' % ACL_FILE]
        geoip, geosite = _geo_files()
        if geoip:
            lines += ['  geoip: %s' % geoip, '  geosite: %s' % geosite]
    return lines


# --- применение -------------------------------------------------------------

def apply(state=None, force_refresh=False):
    """Собирает acl, переписывает конфиг, перезапускает сервис, фиксирует applied.

    Возвращает (blob, ошибка). Ошибка сборки не должна ронять зафиксированное
    состояние: если сервис не поднялся, применённым считается прежнее.
    """
    from . import service
    blob = load_global()
    state = norm_state(state if state is not None else blob['pending'])
    text = build_acl(state, force_refresh=force_refresh)
    if state.get('enabled') and not text:
        return blob, 'правила включены, но получился пустой список — выберите списки или страны'
    write_acl(text)
    if service.bin_installed():
        service.write_config()
        ok, err = service.apply_changes()
        if not ok:
            return blob, 'сервис не поднялся: %s' % err
    blob = {
        'pending': state,
        'applied': dict(state),
        'last_update': time.strftime('%Y-%m-%d %H:%M'),
    }
    save_global(blob)
    audit('info', 'глобальные правила применены (%s)' %
          (state['mode'] if state['enabled'] else 'выключены'))
    return blob, ''


def refresh_applied():
    """Пересобирает применённое состояние со свежими списками. Раз в сутки:
    списки в каталоге живут своей жизнью, и без этого правила протухают."""
    blob = load_global()
    applied = blob['applied']
    if not applied.get('enabled') or applied.get('mode') != 'lists':
        return False
    _, err = apply(applied, force_refresh=True)
    if err:
        audit('warn', 'автообновление глобальных правил не удалось: %s' % err)
        return False
    audit('info', 'глобальные правила: ежесуточное автообновление')
    return True


def status():
    blob = load_global()
    blob['cascade'] = cascade_wanted()
    blob['cascade_live'] = cascade_live()
    # Режимы по странам опираются на geoip.dat. Если рядом нет XRay, hysteria
    # полезет качать базу с GitHub сама — на сервере без доступа туда правила
    # молча не заработают, поэтому предупреждаем заранее.
    blob['geo_files'] = bool(_geo_files()[0])
    blob['acl_rules'] = 0
    if acl_active():
        try:
            with open(ACL_FILE, 'r', encoding='utf-8') as f:
                blob['acl_rules'] = sum(1 for ln in f if ln.strip() and not ln.startswith('#'))
        except Exception:
            pass
    return blob
