"""Клиенты WEB-прокси.

Источник правды — data/tgweb/clients.json. В конфиг telemt клиенты попадают
целиком при каждом изменении (service.apply_clients → рендер config.toml →
горячая перезагрузка): у каждого свой секрет, своя ссылка и свои ограничения,
поэтому отключение или удаление одного не задевает остальных.

Имя пользователя для telemt — неизменяемый id клиента, а не его имя:
переименование не должно сбрасывать счётчики и рвать сессии.
"""
import ipaddress
import re
import secrets
import time

from . import DEPS, audit, load_clients, save_clients


def _clean_name(s):
    """(имя, ошибка). Те же правила, что у остальных протоколов панели:
    латиница, цифры, _ и -. Недопустимое отклоняем, а не вырезаем — «Мама iPad»
    молча стало бы «_ipad»."""
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


def new_secret():
    return secrets.token_hex(16)


def list_clients():
    return load_clients()


def get(client_id):
    for c in load_clients():
        if c.get('id') == client_id:
            return c
    return None


def _apply():
    """Перенести изменения в telemt. Импорт внутри — service тянет clients."""
    from . import service
    return service.apply_clients()


def add(name):
    name, err = _clean_name(name)
    if err:
        return None, err
    clients = load_clients()
    if any((c.get('name') or '').lower() == name.lower() for c in clients):
        return None, 'клиент с таким именем уже есть'
    rec = {
        'id': secrets.token_hex(8),
        'name': name,
        # Секрет MTProxy (16 байт). Попадает в ссылку — это и есть ключ доступа.
        'secret': new_secret(),
        'created': int(time.time()),
        'disabled': False,
    }
    clients.append(rec)
    save_clients(clients)
    audit('info', 'добавлен клиент %s' % name)
    _apply()
    return rec, ''


def _mutate(client_id, fn):
    """Найти клиента, изменить fn(c), сохранить. (клиент, ошибка)."""
    clients = load_clients()
    for c in clients:
        if c.get('id') == client_id:
            err = fn(c)
            if err:
                return None, err
            save_clients(clients)
            return c, ''
    return None, 'не найдено'


def rename(client_id, name):
    name, err = _clean_name(name)
    if err:
        return None, err
    if any((c.get('name') or '').lower() == name.lower() and c.get('id') != client_id
           for c in load_clients()):
        return None, 'клиент с таким именем уже есть'
    old = {}

    def _f(c):
        old['name'] = c.get('name')
        c['name'] = name
    rec, err = _mutate(client_id, _f)
    if rec:
        # Имя в telemt не уходит (там id), применять нечего.
        audit('info', 'клиент переименован: %s → %s' % (old.get('name'), name))
    return rec, err


def set_disabled(client_id, disabled):
    def _f(c):
        c['disabled'] = bool(disabled)
        # Ручное включение снимает и пометку «отключён по лимиту», иначе
        # следующая проверка лимитов тут же выключила бы клиента обратно.
        if not disabled:
            c['disabled_by_limit'] = False
    rec, err = _mutate(client_id, _f)
    if rec:
        audit('info', 'клиент %s %s' % (rec.get('name'), 'отключён' if disabled else 'включён'))
        # telemt при отключении пользователя сам рвёт его активные сессии.
        _apply()
    return rec, err


def regenerate_secret(client_id):
    """Новый секрет = новая ссылка; старая перестаёт работать сразу."""
    def _f(c):
        c['secret'] = new_secret()
    rec, err = _mutate(client_id, _f)
    if rec:
        audit('warn', 'клиенту %s выдан новый секрет — старая ссылка больше не работает'
              % rec.get('name'))
        _apply()
    return rec, err


def _clean_ip_list(items):
    """Валидные адреса и CIDR-маски. (список, ошибка)."""
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
    """Белый и чёрный списки IP. У telemt есть только запрет (user_source_deny),
    поэтому белый список превращается в запрет всего остального — см.
    service.deny_list()."""
    allow, err = _clean_ip_list(allow)
    if err:
        return None, err
    block, err = _clean_ip_list(block)
    if err:
        return None, err

    def _f(c):
        c['allow_ips'] = allow
        c['block_ips'] = block
    rec, err = _mutate(client_id, _f)
    if rec:
        audit('info', 'фильтр IP для %s: белый %d, чёрный %d' % (rec.get('name'), len(allow), len(block)))
        _apply()
    return rec, err


def set_max_ips(client_id, n):
    """Сколько разных IP одновременно может держать клиент (0 — без ограничения).
    Против раздачи одной ссылки на десяток человек."""
    try:
        n = max(0, min(1000, int(n or 0)))
    except (TypeError, ValueError):
        return None, 'нужно целое число'

    def _f(c):
        c['max_ips'] = n
    rec, err = _mutate(client_id, _f)
    if rec:
        audit('info', 'лимит IP для %s: %s' % (rec.get('name'), n or 'без ограничения'))
        _apply()
    return rec, err


def set_schedule(client_id, action, date):
    """Отложенное действие: 'disable' | 'delete' | снять ('none'/пусто), date —
    'YYYY-MM-DD' в зоне сервера. Формат — как у XRay: общая модалка расписания
    шлёт ровно его.

    Исполняет планировщик пакета (run_schedules), а не telemt: его собственный
    user_expirations умеет только запрещать вход, и панель не знала бы, что
    клиент выключен."""
    if action in (None, '', 'none'):
        action, date = None, None
    elif action in ('disable', 'delete'):
        date = str(date or '').strip()
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', date) or date <= time.strftime('%Y-%m-%d'):
            return None, 'дата должна быть в будущем, YYYY-MM-DD'
    else:
        return None, 'неизвестное действие'

    def _f(c):
        if not action:
            c.pop('scheduled_action', None)
            c.pop('scheduled_at', None)
        else:
            c['scheduled_action'] = action
            c['scheduled_at'] = date
    rec, err = _mutate(client_id, _f)
    if rec:
        audit('info', 'расписание для %s: %s %s' % (rec.get('name'), action or 'снято', date or ''))
    return rec, err


def run_schedules():
    """Исполняет наступившие отложенные действия (в начале назначенного дня по
    часам сервера). True — что-то изменилось."""
    today = time.strftime('%Y-%m-%d')
    clients = load_clients()
    keep, changed = [], False
    for c in clients:
        action = c.get('scheduled_action')
        at = str(c.get('scheduled_at') or '')
        if action and at and at <= today:
            changed = True
            c.pop('scheduled_action', None)
            c.pop('scheduled_at', None)
            if action == 'delete':
                audit('warn', 'клиент %s удалён по расписанию' % c.get('name'))
                continue
            c['disabled'] = True
            audit('info', 'клиент %s отключён по расписанию' % c.get('name'))
        keep.append(c)
    if changed:
        save_clients(keep)
    return changed


def delete(client_id):
    clients = load_clients()
    for i, c in enumerate(clients):
        if c.get('id') == client_id:
            removed = clients.pop(i)
            save_clients(clients)
            audit('warn', 'удалён клиент %s' % removed.get('name'))
            _apply()
            from . import stats
            stats.forget(client_id)
            return removed, ''
    return None, 'не найдено'
