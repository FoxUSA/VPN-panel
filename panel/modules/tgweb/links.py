"""Ссылки на WEB-прокси для клиентов Telegram.

Формат (tproxy-server BASE_PATH.md, telemt docs/WEB):
  без префикса пути: tg://webproxy?server=<host>&secret=<32 hex>
  с префиксом:       tg://webproxy?server=<host>%2F<path>&secret=<base64url(0x70‖secret)>

Маркер 0x70 перед секретом нужен именно для ссылок с путём: старый клиент,
который пути не понимает, увидит «неизвестный тип секрета» вместо того, чтобы
молча стучаться в корень домена. Порта в ссылке нет — WEB-прокси всегда 443.

Секрет и путь вместе дают клиенту всё для подключения, поэтому пару
«сервер/секрет» в UI показываем только как запасной ручной ввод — в форму
классического MTProto её вводить нельзя: это был бы голый MTProxy на 443.
"""
import base64
import re
from urllib.parse import quote

SECRET_RE = re.compile(r'^[0-9a-f]{32}$')
PATH_MARK = b'\x70'


def path_secret(secret_hex):
    """base64url без паддинга от 0x70‖secret — секрет для ссылки с путём."""
    raw = bytes.fromhex(secret_hex)
    return base64.urlsafe_b64encode(PATH_MARK + raw).decode('ascii').rstrip('=')


def server_param(host, slug):
    host = (host or '').strip().lower()
    slug = (slug or '').strip().strip('/')
    return '%s/%s' % (host, slug) if slug else host


def query(host, slug, secret_hex):
    """server=…&secret=… — общая часть tg:// и t.me ссылок."""
    if not host or not SECRET_RE.match(secret_hex or ''):
        return ''
    slug = (slug or '').strip().strip('/')
    secret = path_secret(secret_hex) if slug else secret_hex
    # «/» внутри server обязан быть %2F: иначе t.me и клиент разберут путь
    # как часть своего URL, а не как параметр.
    return 'server=%s&secret=%s' % (quote(server_param(host, slug), safe=''), secret)


def tg_link(host, slug, secret_hex):
    q = query(host, slug, secret_hex)
    return ('tg://webproxy?' + q) if q else ''


def tme_link(host, slug, secret_hex):
    q = query(host, slug, secret_hex)
    return ('https://t.me/webproxy?' + q) if q else ''


def build(host, slug, secret_hex):
    """Всё, что карточка клиента показывает в окне «Ссылка»."""
    return {
        'tg': tg_link(host, slug, secret_hex),
        'tme': tme_link(host, slug, secret_hex),
        # Ручной ввод: Telegram → Прокси → Добавить → WEB. Сервер пишется с путём
        # через «/», секрет — обычным hex (маркер добавляет сам клиент).
        'manual_server': server_param(host, slug),
        'manual_secret': secret_hex or '',
    }
