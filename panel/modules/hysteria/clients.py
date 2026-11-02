"""CRUD клиентов Hysteria.

Клиенты живут только в data/hysteria/clients.json — в config.yaml их нет.
Проверку выполняет auth.py при каждом подключении, поэтому любое изменение
списка действует сразу и не требует рестарта сервиса.
"""
import re
import secrets
import time

from . import DEPS, audit, load_clients, save_clients


def _clean_name(s):
    """(имя, ошибка). Имя приводится к правилам панели: латиница, цифры, _ и -,
    нижний регистр — оно попадает в имя файла профиля и в публичный URL.

    Недопустимые символы именно ОТКЛОНЯЕМ, а не вырезаем: «Андрей iPad» молча
    превратилось бы в «_ipad», и пользователь получил бы клиента, которого не
    заводил.
    """
    raw = str(s or '').strip()
    if not raw:
        return '', 'имя пустое'
    if re.search(r'[^A-Za-z0-9 _-]', raw):
        return '', 'Можно только латиницу, цифры, _ и -'
    fn = DEPS.get('safe_name')
    if fn:
        try:
            return (fn(raw) or ''), ''
        except Exception:
            pass
    return re.sub(r'[^A-Za-z0-9_-]', '', raw.replace(' ', '_'))[:32].lower(), ''


def list_clients():
    return ensure_tokens(load_clients())


def ensure_tokens(clients):
    """Досоздаёт токен публичного профиля клиентам, заведённым до его появления.

    Токен — ключ ссылок вида /hy/loon/<token8>/<имя>.conf: по нему профиль
    резолвится независимо от имени, поэтому переименование ссылку не рвёт
    (та же схема, что у XRay).
    """
    missing = [c for c in clients if not c.get('token')]
    if not missing:
        return clients
    for c in missing:
        c['token'] = secrets.token_hex(16)
    save_clients(clients)
    return clients


def by_token(token):
    """Клиент по токену: точное совпадение либо однозначный префикс.

    Неоднозначный префикс — это чужая или битая ссылка; молча отдать чей-то
    чужой профиль нельзя, поэтому возвращаем None.
    """
    token = str(token or '').strip().lower()
    if '.' in token:
        token = token.rsplit('.', 1)[0]
    if len(token) < 8:
        return None
    clients = list_clients()
    for c in clients:
        if (c.get('token') or '').lower() == token:
            return c
    hits = [c for c in clients if (c.get('token') or '').lower().startswith(token)]
    return hits[0] if len(hits) == 1 else None


def get(client_id):
    # list_clients, а не load_clients: у клиента должен быть токен профиля,
    # иначе модалка конфига не покажет ссылки старым клиентам.
    for c in list_clients():
        if c.get('id') == client_id:
            return c
    return None


def add(name, rule_lists=None, no_rules=False):
    """Новый клиент. Списки правил выбираются прямо в модалке создания — как у
    XRay: заводить клиента, а потом сразу лезть в его карточку за правилами,
    неудобно. Пустой выбор или no_rules = весь трафик в VPN (режим 'off').
    """
    name, err = _clean_name(name)
    if err:
        return None, err
    clients = load_clients()
    if any((c.get('name') or '').lower() == name.lower() for c in clients):
        return None, 'клиент с таким именем уже есть'
    ids = [] if no_rules else [str(x) for x in (rule_lists or []) if str(x or '').strip()]
    mode = 'lists' if ids else 'off'
    rec = {
        'id': secrets.token_hex(8),
        'name': name,
        # Пароль он же токен доступа: попадает в ссылку и сверяется auth.py.
        'password': secrets.token_urlsafe(16),
        # Токен публичного профиля — отдельно от пароля: профиль отдаётся по
        # ссылке без авторизации, и светить в ней пароль подключения нельзя.
        'token': secrets.token_hex(16),
        'created': int(time.time()),
        'disabled': False,
        'rule_lists': {'lists': ids},
        # Правила выбраны осознанно в модалке — применяем сразу, без «Применить».
        'geo_mode': mode,
        'geo_mode_pending': mode,
    }
    clients.append(rec)
    save_clients(clients)
    audit('info', 'добавлен клиент %s' % name)
    return rec, ''


def rename(client_id, name):
    name, err = _clean_name(name)
    if err:
        return None, err
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            old = c.get('name')
            c['name'] = name
            save_clients(clients)
            audit('info', 'клиент переименован: %s → %s' % (old, name))
            return c, ''
    return None, 'не найдено'


def set_disabled(client_id, disabled):
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['disabled'] = bool(disabled)
            # Ручное включение снимает и пометку «отключён по лимиту», иначе
            # следующая проверка лимитов тут же выключила бы клиента обратно.
            if not disabled:
                c['disabled_by_limit'] = False
            save_clients(clients)
            audit('info', 'клиент %s %s' % (c.get('name'), 'отключён' if disabled else 'включён'))
            if disabled:
                # auth.py спрашивают только при подключении, поэтому активную
                # сессию надо рвать явно — иначе отключённый продолжит работать.
                from . import stats
                stats.kick([client_id])
            return c, ''
    return None, 'не найдено'


def last_seen_map():
    """{id: {ip, ts}} — пишется скриптом auth.py при каждом подключении."""
    from . import LASTSEEN_FILE, _read_json
    data = _read_json(LASTSEEN_FILE, {})
    return data if isinstance(data, dict) else {}


def _clean_ip_list(items):
    """Оставляет валидные адреса и CIDR-маски. Возвращает (список, ошибка)."""
    import ipaddress
    out = []
    for raw in (items or []):
        s = str(raw or '').strip()
        if not s:
            continue
        try:
            if '/' in s:
                ipaddress.ip_network(s, strict=False)
            else:
                ipaddress.ip_address(s)
        except ValueError:
            return [], 'не похоже на адрес или маску: %s' % s
        if s not in out:
            out.append(s)
    return out, ''


def set_ip_filters(client_id, allow, block):
    """Белый и чёрный списки IP. Проверку выполняет auth.py — hysteria своими
    средствами фильтровать по адресу клиента не умеет."""
    allow, err = _clean_ip_list(allow)
    if err:
        return None, err
    block, err = _clean_ip_list(block)
    if err:
        return None, err
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['allow_ips'] = allow
            c['block_ips'] = block
            save_clients(clients)
            audit('info', 'фильтр IP для %s: белый %d, чёрный %d' % (c.get('name'), len(allow), len(block)))
            return c, ''
    return None, 'не найдено'


def set_rule_lists(client_id, lists, geo_mode=None):
    """Записи общего каталога правил, выбранные клиентом.

    Формат хранения совпадает с XRay ({'lists': [id, …]}) — профили собирает
    общий билдер панели, и своя структура ему была бы непонятна.
    """
    ids = [str(x) for x in (lists or []) if str(x or '').strip()]
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            # Членство в списках вступает в силу сразу — как у XRay: «Применить»
            # там сторожит только режим/страны/режим исключений.
            c['rule_lists'] = {'lists': ids}
            cur = c.get('geo_mode_pending', c.get('geo_mode') or 'off')
            if geo_mode in ('off', 'lists'):
                c['geo_mode_pending'] = geo_mode
            elif ids and cur == 'off':
                c['geo_mode_pending'] = 'lists'
            save_clients(clients)
            audit('info', 'правила клиента %s: %d записей' % (c.get('name'), len(ids)))
            return c, ''
    return None, 'не найдено'


def set_geo_mode(client_id, mode):
    """Стратегия маршрутизации клиента: off | lists | via | direct.

    Те же четыре режима, что у XRay, и те же имена полей: профили Loon/Clash
    собирает общий билдер панели, и он читает именно их. Пишем в PENDING —
    в силу изменение вступает по «Применить» (см. apply_geo).
    """
    if mode not in ('off', 'lists', 'via', 'direct'):
        return None, 'неизвестный режим'
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['geo_mode_pending'] = mode
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def set_geo_countries(client_id, countries):
    codes = sorted({str(x).upper()[:2] for x in (countries or []) if str(x or '').strip()})
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['geo_countries_pending'] = codes
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def set_lists_default(client_id, mode):
    """Режим исключений: куда идёт трафик, не попавший ни в один список.

    'direct' — списки описывают, что завернуть в VPN; 'vpn' — наоборот, всё
    через VPN, а списки становятся исключениями; 'block' — белый список:
    всё, что не перечислено, режется.
    """
    mode = mode if mode in ('direct', 'vpn', 'block') else 'direct'
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['lists_default_pending'] = mode
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def geo_view(c):
    """Значения, которые видит фронт: pending с откатом на applied.

    Ровно та же схема, что у XRay: свитчи и страны показывают pending (что
    правит пользователь), бейдж и профиль клиента — applied.
    """
    return {
        'geo_mode': c.get('geo_mode') or 'off',
        'geo_countries': c.get('geo_countries') or [],
        'lists_default': c.get('lists_default') or 'direct',
        'geo_mode_pending': c.get('geo_mode_pending', c.get('geo_mode') or 'off'),
        'geo_countries_pending': c.get('geo_countries_pending',
                                       c.get('geo_countries') or []),
        'lists_default_pending': c.get('lists_default_pending',
                                       c.get('lists_default') or 'direct'),
    }


def apply_geo(client_id):
    """«Применить»: фиксирует pending → applied.

    До этого момента профиль клиента (ссылка/Loon/Clash) собирается по applied —
    иначе клиент, перекачавший конфиг посреди правки, получил бы недоделанные
    правила. У XRay та же кнопка перезапускает маршрутизацию на сервере, у
    Hysteria серверный acl общий на всех, поэтому правила клиента живут только
    в его профиле — и «применить» означает «положить их в выдаваемый конфиг».
    """
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            v = geo_view(c)
            c['geo_mode'] = v['geo_mode_pending']
            c['geo_countries'] = list(v['geo_countries_pending'])
            c['lists_default'] = v['lists_default_pending']
            c['geo_mode_pending'] = c['geo_mode']
            c['geo_countries_pending'] = list(c['geo_countries'])
            c['lists_default_pending'] = c['lists_default']
            save_clients(clients)
            audit('info', 'правила клиента %s применены (%s)' % (c.get('name'), c['geo_mode']))
            return c, ''
    return None, 'не найдено'


def set_rule_policy(client_id, rule_id, policy):
    """Персональная политика одного правила: proxy | direct | reject.

    Пустая политика убирает переопределение — правило снова берётся из каталога.
    Каталог при этом не меняется: одно правило может быть у одного клиента Block,
    у другого Direct.
    """
    rule_id = str(rule_id or '').strip()
    if not rule_id:
        return None, 'не указано правило'
    policy = str(policy or '').strip().lower()
    # Общий поповер (RULE_POLICY_BTNS) и профили (RULE_POLICIES) зовут блок
    # 'reject'; 'block' принимаем как синоним от старых записей.
    if policy == 'block':
        policy = 'reject'
    if policy and policy not in ('proxy', 'direct', 'reject'):
        return None, 'неизвестная политика'
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            ov = c.get('rule_policy')
            ov = dict(ov) if isinstance(ov, dict) else {}
            if policy:
                ov[rule_id] = policy
            else:
                ov.pop(rule_id, None)
            c['rule_policy'] = ov
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def set_dns(client_id, dns):
    """DNS уходит в клиентские профили Loon/Clash. Сервер тут ни при чём:
    у hysteria свой резолвер общий на всех, а это персональная настройка."""
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            c['dns'] = dns if isinstance(dns, dict) else {}
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def schedule_date(at):
    """scheduled_at → 'YYYY-MM-DD'. Раньше хранили unix-время, теперь дату, как
    у XRay: общая модалка расписания шлёт и показывает ровно её."""
    if isinstance(at, (int, float)) and not isinstance(at, bool):
        return time.strftime('%Y-%m-%d', time.localtime(at)) if at > 0 else ''
    at = str(at or '').strip()
    return at if re.match(r'^\d{4}-\d{2}-\d{2}$', at) else ''


def set_schedule(client_id, action, date):
    """Отложенное действие: 'disable' | 'delete' | снять ('none'/пусто), date —
    'YYYY-MM-DD' в зоне сервера (формат XRay). Исполняет планировщик пакета в
    начале назначенного дня."""
    if action in (None, '', 'none'):
        action, date = None, None
    elif action in ('disable', 'delete'):
        date = schedule_date(date)
        if not date or date <= time.strftime('%Y-%m-%d'):
            return None, 'дата должна быть в будущем, YYYY-MM-DD'
    else:
        return None, 'неизвестное действие'
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            if not action:
                c.pop('scheduled_action', None)
                c.pop('scheduled_at', None)
            else:
                c['scheduled_action'] = action
                c['scheduled_at'] = date
            save_clients(clients)
            audit('info', 'расписание для %s: %s %s' % (c.get('name'), action or 'снято', date or ''))
            return c, ''
    return None, 'не найдено'


def heal_schedules():
    """Записи старого формата: unix-время → дата. Запись с нулём осталась от
    модалки, чью дату пакет не понимал: срабатывать ей не по чему — снимаем,
    иначе на карточке вечно горит значок расписания без даты."""
    clients = load_clients()
    changed = False
    for c in clients:
        if not c.get('scheduled_action'):
            continue
        at = c.get('scheduled_at')
        if isinstance(at, str) and schedule_date(at) == at:
            continue
        date = schedule_date(at)
        changed = True
        if date:
            c['scheduled_at'] = date
        else:
            c.pop('scheduled_action', None)
            c.pop('scheduled_at', None)
            audit('warn', 'расписание для %s снято: дата не сохранилась (старая ошибка)' % c.get('name'))
    if changed:
        save_clients(clients)
    return changed


def delete(client_id):
    clients = load_clients()
    for i, c in enumerate(clients):
        if c.get('id') == client_id:
            removed = clients.pop(i)
            save_clients(clients)
            from . import stats
            stats.kick([client_id])
            audit('warn', 'удалён клиент %s' % removed.get('name'))
            return removed, ''
    return None, 'не найдено'
