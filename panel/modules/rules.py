"""Каталог правил: списки, шаблоны, страны, глобальные правила и белые IP.

Здесь всё, что отвечает на вопрос «какой трафик куда идёт»: единый каталог
'lists' (порядок в нём = приоритет правил в конфиге), библиотека шаблонов
blackmatrix7 и byfox, country rule-sets для клиентских профилей, глобальные
правила XRay с их pending/applied-циклом и фильтрация IP клиента
(белый список через дополнение, чёрный — напрямую).

Контракт модуля — как у остальных (см. modules/__init__.py): зависимости от
app.py приезжают в init() одним словарём и ложатся в одноимённые глобалы, роуты
объявлены в Blueprint без url_prefix (URL те же), побочных эффектов на импорте
нет. Пути и файлы (XRAY_RULE_LISTS_DB, BM7_*, BYFOX_*, COUNTRIES_*) остаются
константами app.py и тоже приезжают в init(): их читает и остающийся код —
реестр системных путей и апдейтер.
"""

import hashlib
import ipaddress
import json
import os
import re
import threading
import time

from flask import Blueprint, jsonify, request

bp = Blueprint('rules', __name__)

# === Зависимости от app.py ==================================================
# До init() модуль умеет только импортироваться. Имена совпадают с теми, что
# были в app.py, поэтому тела функций переехали байт в байт.
_detect_freedom_tag = None
_http_get_bytes = None
_http_get_text = None
_norm_allow_ips = None
_public_access_info = None
_save_server_config = None
_xray_unique_email = None
audit = None
find_xray_inbound_idx = None
load_xray_clients = None
load_xray_config = None
save_xray_clients = None
save_xray_config = None
schedule_xray_restart = None
login_required = None
SERVER_CFG = {}
BM7_SERVICES_URL = ''
BM7_TEMPLATES_FILE = ''
BYFOX_RULES_BASE = ''
BYFOX_RULES_FILE = ''
COUNTRIES_CACHE_DIR = ''
COUNTRIES_SRC_DIR = ''
COUNTRIES_ZIP_URL = ''
XRAY_CONFIG = ''
XRAY_GLOBAL_CACHE_DB = ''
XRAY_RULE_LISTS_DB = ''
_ALLOWIP_DENY_TAG = ''
_ALLOWIP_MARK = ''
_GLOBAL_MARK = ''
LISTS_DEFAULT_MODES = ()
CLIENT_RULE_PLATFORMS = ()
_xray_restart_lock = None

REQUIRED_DEPS = [
    'BM7_SERVICES_URL',
    'BM7_TEMPLATES_FILE',
    'BYFOX_RULES_BASE',
    'BYFOX_RULES_FILE',
    'CLIENT_RULE_PLATFORMS',
    'COUNTRIES_CACHE_DIR',
    'COUNTRIES_SRC_DIR',
    'COUNTRIES_ZIP_URL',
    'LISTS_DEFAULT_MODES',
    'SERVER_CFG',
    'XRAY_CONFIG',
    'XRAY_GLOBAL_CACHE_DB',
    'XRAY_RULE_LISTS_DB',
    '_ALLOWIP_DENY_TAG',
    '_ALLOWIP_MARK',
    '_GLOBAL_MARK',
    '_detect_freedom_tag',
    '_http_get_bytes',
    '_http_get_text',
    '_norm_allow_ips',
    '_public_access_info',
    '_save_server_config',
    '_xray_restart_lock',
    '_xray_unique_email',
    'audit',
    'find_xray_inbound_idx',
    'load_xray_clients',
    'load_xray_config',
    'login_required',
    'save_xray_clients',
    'save_xray_config',
    'schedule_xray_restart',
]


def init(deps):
    """Принять зависимости из app.py (см. REQUIRED_DEPS) в одноимённые глобалы."""
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('rules.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    for name in ('XRAY_RULE_LISTS_DB', 'COUNTRIES_CACHE_DIR', 'COUNTRIES_SRC_DIR',
                 'BM7_TEMPLATES_FILE', 'BYFOX_RULES_FILE'):
        if not globals().get(name):
            raise RuntimeError(f'rules.init: пустой {name} — путь не построить')
    # Стартовые действия, которые раньше стояли на верхнем уровне app.py:
    # распаковать country-наборы, если их ещё нет, и засеять каталог правил на
    # первом запуске. На импорте модуля этого делать нельзя — зависимостей нет.
    # Бутстрап стран качает архив — только фоном, как и раньше: старт панели
    # не должен ждать сеть.
    threading.Thread(target=_countries_bootstrap_if_missing, daemon=True).start()
    try:
        seed_rule_lists_if_empty()
    except Exception as e:
        print(f'[rules] засев каталога правил не удался: {e}', flush=True)


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роуты объявлены раньше."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


# ISO-2 → имя файла в countries.zip (имена там — короткие английские, как в NetGeoAudit).
# Покрывает страны, выбираемые в панели; чего нет — просто не раскладывается.
ISO_TO_COUNTRY_NAME = {
    'RU': 'Russia', 'BY': 'Belarus', 'KZ': 'Kazakhstan', 'UA': 'Ukraine',
    'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany', 'FR': 'France',
    'IT': 'Italy', 'ES': 'Spain', 'NL': 'The Netherlands', 'SE': 'Sweden',
    'NO': 'Norway', 'FI': 'Finland', 'DK': 'Denmark', 'PL': 'Poland',
    'CZ': 'Czechia', 'SK': 'Slovakia', 'AT': 'Austria', 'CH': 'Switzerland',
    'BE': 'Belgium', 'IE': 'Ireland', 'PT': 'Portugal', 'GR': 'Greece',
    'HU': 'Hungary', 'RO': 'Romania', 'BG': 'Bulgaria', 'HR': 'Croatia',
    'SI': 'Slovenia', 'EE': 'Estonia', 'LV': 'Latvia', 'LT': 'Lithuania',
    'CY': 'Cyprus', 'MT': 'Malta', 'LU': 'Luxembourg', 'IS': 'Iceland',
    'CA': 'Canada', 'MX': 'Mexico', 'BR': 'Brazil', 'AR': 'Argentina',
    'CL': 'Chile', 'CO': 'Colombia', 'PE': 'Peru', 'VE': 'Venezuela',
    'UY': 'Uruguay', 'EC': 'Ecuador', 'BO': 'Bolivia', 'PY': 'Paraguay',
    'CR': 'Costa Rica', 'PA': 'Panama', 'CU': 'Cuba', 'DO': 'Dominican Republic',
    'JP': 'Japan', 'CN': 'China', 'HK': 'Hong Kong', 'TW': 'Taiwan',
    'KR': 'South Korea', 'KP': 'North Korea', 'SG': 'Singapore', 'MY': 'Malaysia',
    'TH': 'Thailand', 'VN': 'Vietnam', 'ID': 'Indonesia', 'PH': 'Philippines',
    'IN': 'India', 'PK': 'Pakistan', 'BD': 'Bangladesh', 'LK': 'Sri Lanka',
    'NP': 'Nepal', 'MM': 'Myanmar', 'KH': 'Cambodia', 'LA': 'Laos',
    'MN': 'Mongolia', 'UZ': 'Uzbekistan', 'KG': 'Kyrgyzstan', 'TJ': 'Tajikistan',
    'TM': 'Turkmenistan', 'AF': 'Afghanistan', 'IR': 'Iran', 'IQ': 'Iraq',
    'SA': 'Saudi Arabia', 'AE': 'United Arab Emirates', 'QA': 'Qatar', 'KW': 'Kuwait',
    'BH': 'Bahrain', 'OM': 'Oman', 'JO': 'Jordan', 'LB': 'Lebanon',
    'SY': 'Syria', 'IL': 'Israel', 'PS': 'Palestine', 'TR': 'Türkiye',
    'EG': 'Egypt', 'LY': 'Libya', 'DZ': 'Algeria', 'MA': 'Morocco',
    'TN': 'Tunisia', 'SD': 'Sudan', 'ET': 'Ethiopia', 'KE': 'Kenya',
    'NG': 'Nigeria', 'GH': 'Ghana', 'ZA': 'South Africa', 'UG': 'Uganda',
    'TZ': 'Tanzania', 'ZW': 'Zimbabwe', 'ZM': 'Zambia', 'SN': 'Senegal',
    'CI': 'Ivory Coast', 'CM': 'Cameroon', 'AO': 'Angola', 'MZ': 'Mozambique',
    'MG': 'Madagascar', 'RW': 'Rwanda', 'MW': 'Malawi', 'BW': 'Botswana',
    'NA': 'Namibia', 'AU': 'Australia', 'NZ': 'New Zealand', 'FJ': 'Fiji',
    'PG': 'Papua New Guinea', 'MD': 'Moldova', 'GE': 'Georgia', 'AM': 'Armenia',
    'AZ': 'Azerbaijan', 'RS': 'Serbia', 'BA': 'Bosnia and Herzegovina',
    'MK': 'North Macedonia', 'ME': 'Montenegro', 'AL': 'Albania', 'XK': 'Kosovo',
}
COUNTRY_NAME_TO_ISO = {v: k for k, v in ISO_TO_COUNTRY_NAME.items()}


def _countries_download_and_store():
    """Скачать countries.zip, распаковать и разложить по ISO-кодам (сырые start-end).
    Вызывается из гео-апдейта. Возвращает число разложенных стран."""
    import zipfile, io
    data = _http_get_bytes(COUNTRIES_ZIP_URL, timeout=180)
    z = zipfile.ZipFile(io.BytesIO(data))
    os.makedirs(COUNTRIES_SRC_DIR, exist_ok=True)
    written = 0
    for info in z.infolist():
        if not info.filename.lower().endswith('.txt'):
            continue
        base = os.path.basename(info.filename)
        name = re.sub(r'_[0-9]+\.txt$', '', base)
        cc = COUNTRY_NAME_TO_ISO.get(name)
        if not cc:
            continue
        tmp = os.path.join(COUNTRIES_SRC_DIR, cc + '.txt.tmp')
        with open(tmp, 'wb') as f:
            f.write(z.read(info))
        os.replace(tmp, os.path.join(COUNTRIES_SRC_DIR, cc + '.txt'))
        written += 1
    # Сбрасываем кеш CIDR — пересоберётся при следующей отдаче.
    try:
        for fn in os.listdir(COUNTRIES_CACHE_DIR):
            os.remove(os.path.join(COUNTRIES_CACHE_DIR, fn))
    except Exception:
        pass
    return written


def _country_cidrs(cc):
    """CIDR-список страны (start-end → CIDR) с диск-кешем по mtime. None, если страны нет."""
    import ipaddress
    cc = (cc or '').upper()
    if not re.match(r'^[A-Z]{2}$', cc):
        return None
    src = os.path.join(COUNTRIES_SRC_DIR, cc + '.txt')
    if not os.path.isfile(src):
        return None
    cache = os.path.join(COUNTRIES_CACHE_DIR, cc + '.cidr')
    try:
        if os.path.isfile(cache) and os.path.getmtime(cache) >= os.path.getmtime(src):
            with open(cache) as f:
                return [ln.strip() for ln in f if ln.strip()]
    except Exception:
        pass
    cidrs = []
    try:
        with open(src) as f:
            for line in f:
                line = line.strip()
                if not line or '-' not in line:
                    continue
                a, _, b = line.partition('-')
                try:
                    for net in ipaddress.summarize_address_range(
                            ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())):
                        cidrs.append(str(net))
                except Exception:
                    continue
    except Exception:
        return None
    try:
        os.makedirs(COUNTRIES_CACHE_DIR, exist_ok=True)
        tmp = cache + '.tmp'
        with open(tmp, 'w') as f:
            f.write('\n'.join(cidrs))
        os.replace(tmp, cache)
    except Exception:
        pass
    return cidrs


def _country_ruleset_available(cc):
    """Есть ли распакованный справочник для страны (для подсветки/решений билдеров)."""
    return os.path.isfile(os.path.join(COUNTRIES_SRC_DIR, (cc or '').upper() + '.txt'))


def _country_ruleset_url(cc, fmt):
    """URL панели для отдачи rule-set страны клиенту. fmt: 'list' (SR/Loon) | 'clash'.

    Публичный адрес, а не адрес админки: ссылку открывает клиентское приложение.
    """
    base = (_public_access_info() or {}).get('base') or ''
    return f"{base}/country/{cc.upper()}.{fmt}"


def _countries_bootstrap_if_missing():
    """Разовый бутстрап: если справочник стран пуст (новый сервер / первый деплой фичи),
    качаем countries.zip один раз в фоне, не дожидаясь 180-дневного гео-цикла."""
    time.sleep(3)
    try:
        have = os.path.isdir(COUNTRIES_SRC_DIR) and any(
            n.endswith('.txt') for n in os.listdir(COUNTRIES_SRC_DIR))
        if have:
            return
        n = _countries_download_and_store()
        audit('info', f'countries.zip: первичная загрузка, {n} стран')
    except Exception as e:
        try: audit('warn', f'countries.zip bootstrap failed: {e}')
        except Exception: pass


# Default rule list catalog. Seeded into XRAY_RULE_LISTS_DB on first run.
# Each entry has separate URLs for Shadowrocket and Surge — the .list files
# differ in supported operators between the two clients.
def _bm7(client_dir, fname):
    return f'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/{client_dir}/{fname}'


# Блокирующие списки blackmatrix7, идут в каталоге сразу за нашим Block ads/trackers.
# Порядок каталога = приоритет правил в конфиге, поэтому блокировки стоят первыми.
# Advertising и Privacy разбиты у bm7 надвое: домены лежат в <Имя>_Domain, а в
# <Имя> остаётся огрызок из keyword/IP-CIDR (см. TPL_DOMAIN_SPLIT в app.js).
XRAY_DEFAULT_BLOCK_LISTS = [
    {'id': 'advertising', 'name': 'Advertising', 'policy': 'reject',
     'url': _bm7('Clash', 'Advertising/Advertising_Domain.yaml')},
    {'id': 'privacy',     'name': 'Privacy',     'policy': 'reject',
     'url': _bm7('Clash', 'Privacy/Privacy_Domain.yaml')},
    {'id': 'hijacking',   'name': 'Hijacking',   'policy': 'reject',
     'url': _bm7('Clash', 'Hijacking/Hijacking.yaml')},
]


# Сервисные шаблоны bm7. БОЛЬШЕ НЕ СИДЯТСЯ (см. seed_rule_lists_if_empty): у bm7
# папки переименовываются, и в свежем каталоге висели бы битые URL. Оставлено как
# справочник имён/URL — юзер добавляет сервисы через «Шаблоны» с живого индекса.
XRAY_DEFAULT_RULE_LISTS = [
    # (id, name, shadowrocket_url, loon_url, clash_url)
    ('telegram',  'Telegram',           _bm7('Shadowrocket','Telegram/Telegram.list'),     _bm7('Loon','Telegram/Telegram.list'),     _bm7('Clash','Telegram/Telegram.yaml')),
    ('instagram', 'Instagram',          _bm7('Shadowrocket','Instagram/Instagram.list'),   _bm7('Loon','Instagram/Instagram.list'),   _bm7('Clash','Instagram/Instagram.yaml')),
    ('whatsapp',  'WhatsApp',           _bm7('Shadowrocket','Whatsapp/Whatsapp.list'),     _bm7('Loon','Whatsapp/Whatsapp.list'),     _bm7('Clash','Whatsapp/Whatsapp.yaml')),
    ('youtube',   'YouTube',            _bm7('Shadowrocket','YouTube/YouTube.list'),       _bm7('Loon','YouTube/YouTube.list'),       _bm7('Clash','YouTube/YouTube.yaml')),
    ('gemini',    'Gemini',             _bm7('Shadowrocket','Gemini/Gemini.list'),         _bm7('Loon','Gemini/Gemini.list'),         _bm7('Clash','Gemini/Gemini.yaml')),
    ('anthropic', 'Claude / Anthropic', _bm7('Shadowrocket','Anthropic/Anthropic.list'),   _bm7('Loon','Anthropic/Anthropic.list'),   _bm7('Clash','Anthropic/Anthropic.yaml')),
    ('protonmail','ProtonMail',         _bm7('Shadowrocket','ProtonMail/ProtonMail.list'), _bm7('Loon','ProtonMail/ProtonMail.list'), _bm7('Clash','ProtonMail/ProtonMail.yaml')),
    ('speedtest', 'Speedtest',          _bm7('Shadowrocket','Speedtest/Speedtest.list'),   _bm7('Loon','Speedtest/Speedtest.list'),   _bm7('Clash','Speedtest/Speedtest.yaml')),
    ('tiktok',    'TikTok',             _bm7('Shadowrocket','TikTok/TikTok.list'),         _bm7('Loon','TikTok/TikTok.list'),         _bm7('Clash','TikTok/TikTok.yaml')),
    ('appleproxy','iMessage / FaceTime',_bm7('Shadowrocket','AppleProxy/AppleProxy.list'), _bm7('Loon','AppleProxy/AppleProxy.list'), _bm7('Clash','AppleProxy/AppleProxy.yaml')),
    ('netflix',   'Netflix',            _bm7('Shadowrocket','Netflix/Netflix.list'),       _bm7('Loon','Netflix/Netflix.list'),       _bm7('Clash','Netflix/Netflix.yaml')),
    ('discord',   'Discord',            _bm7('Shadowrocket','Discord/Discord.list'),       _bm7('Loon','Discord/Discord.list'),       _bm7('Clash','Discord/Discord.yaml')),
    ('openai',    'ChatGPT / OpenAI',   _bm7('Shadowrocket','OpenAI/OpenAI.list'),         _bm7('Loon','OpenAI/OpenAI.list'),         _bm7('Clash','OpenAI/OpenAI.yaml')),
]


def _fetch_remote_bm7_date():
    """Дата свежих шаблонов blackmatrix7 (DD.MM.YYYY) с CDN; '' при ошибке."""
    try:
        d, _ = _bm7_parse(_http_get_text(BM7_SERVICES_URL, timeout=12))
        return d or ''
    except Exception:
        return ''


def _slugify_rule_id(s):
    s = (s or '').strip().lower()
    s = re.sub(r'[^a-z0-9]+', '-', s).strip('-')
    return s or 'list'


# Хранилище правил: единый каталог 'lists' (для всех клиентских платформ сразу) +
# отдельный 'global' (серверная маршрутизация). Раньше каталог был разрезан на
# shadowrocket/loon/clash — теперь это лишь ФОРМАТЫ вывода при копировании конфига.
RULE_PLATFORMS = ('lists', 'global')
# Формы вывода при генерации клиентского конфига (URL для одной записи отличается
# только каталогом репозитория и расширением — см. _rule_url_for_platform).
RULE_OUTPUT_PLATFORMS = ('shadowrocket', 'loon', 'clash')


_RULE_TYPE_PREFIXES = (
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-SET',
    'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'URL-REGEX',
    'USER-AGENT', 'PROCESS-NAME', 'PROTOCOL', 'PORT', 'DST-PORT', 'SRC-PORT',
    'SRC-IP', 'IN-PORT', 'RULE-SET',
)


def _normalize_inline_rule_line(line):
    """
    Convert a free-form rule line into a Shadowrocket/Loon-compatible
    rule prefix (without policy). Returns None for empty/comment lines.

    Accepts very loose input — strips scheme, www., trailing path/port,
    leading wildcards/dots — and emits a clean DOMAIN-SUFFIX/IP-CIDR rule.

      "example.com"                  → "DOMAIN-SUFFIX,example.com"
      "www.example.com"              → "DOMAIN-SUFFIX,example.com"
      "https://www.example.com/x?y"  → "DOMAIN-SUFFIX,example.com"
      "http://example.com:8080"      → "DOMAIN-SUFFIX,example.com"
      "*.example.com"                → "DOMAIN-SUFFIX,example.com"
      ".example.com"                 → "DOMAIN-SUFFIX,example.com"
      "1.2.3.4"                      → "IP-CIDR,1.2.3.4/32"
      "1.2.3.0/24"                   → "IP-CIDR,1.2.3.0/24"
      "DOMAIN-SUFFIX,foo"            → unchanged
    """
    s = (line or '').strip()
    if not s or s.startswith('#') or s.startswith(';') or s.startswith('//'):
        return None
    upper = s.upper()
    for pfx in _RULE_TYPE_PREFIXES:
        if upper.startswith(pfx + ','):
            # Already typed rule. Strip trailing policy if user pasted one.
            parts = s.split(',')
            return ','.join(parts[:2]) + (',' + parts[2] if len(parts) > 2 and parts[2].lower() in ('no-resolve',) else '')
    # IP / CIDR detection (very loose; full validation isn't needed here)
    ipv4_cidr = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$', s)
    if ipv4_cidr:
        ip = ipv4_cidr.group(1)
        cidr = ipv4_cidr.group(2) or '32'
        return f'IP-CIDR,{ip}/{cidr}'
    if ':' in s and '/' in s and not s.lower().startswith(('http://', 'https://')):
        # rough IPv6/CIDR (skip if it's an http URL with a path)
        return f'IP-CIDR6,{s}'
    # Strip scheme http(s):// and any trailing path/query/port → leave bare host.
    m = re.match(r'^\s*(?:https?://)?([^/?#\s]+)', s, re.IGNORECASE)
    if m:
        s = m.group(1)
    # Drop port if present (example.com:8080 → example.com)
    if ':' in s and not s.startswith('['):
        s = s.split(':', 1)[0]
    # Strip wildcards / leading dots / www.
    if s.startswith('*.'):
        s = s[2:]
    if s.startswith('.'):
        s = s[1:]
    if s.lower().startswith('www.'):
        s = s[4:]
    s = s.strip().rstrip('.').lower()
    if not s:
        return None
    return f'DOMAIN-SUFFIX,{s}'


def _normalize_inline_rules(rules):
    """Accepts list[str] or newline-separated str; returns clean list[str] of original lines."""
    if rules is None:
        return None
    if isinstance(rules, str):
        rules = rules.splitlines()
    if not isinstance(rules, list):
        return None
    out = []
    for ln in rules:
        if not isinstance(ln, str):
            continue
        s = ln.strip()
        if s:
            out.append(s)
    return out


RULE_POLICIES = ('proxy', 'direct', 'reject')


def _normalize_simple_entry(r):
    """For split storage: {id, name, policy?, url?} or {id, name, policy?, rules: [str,...]}.

    Пересобирает запись из белого списка полей — что сюда не попало, теряется
    при первом же чтении каталога, даже если было записано на диск.
    """
    if not isinstance(r, dict) or not r.get('id'):
        return None
    out = {'id': r['id'], 'name': r.get('name') or r['id']}
    pol = r.get('policy')
    pol = pol.strip().lower() if isinstance(pol, str) else ''
    if pol in RULE_POLICIES:
        out['policy'] = pol            # 'proxy' — дефолт, поле можно и не хранить
    rules = _normalize_inline_rules(r.get('rules'))
    if rules:
        out['rules'] = rules
        return out
    if r.get('url'):
        out['url'] = r['url']
        return out
    return None


def load_rule_lists():
    """Returns {'lists': [{id,name,url|rules}], 'global': [...]}.

    Единый каталог 'lists' для всех клиентских платформ + отдельный 'global'.
    Платформенный URL одной записи выводится на лету при копировании конфига
    (_rule_url_for_platform), в каталоге храним один канонический URL.

    Мигрирует со старых схем (персистит миграцию при первом чтении):
      - по-платформенная {shadowrocket,loon,clash,global} → объединение по id
      - старый плоский список / surge-ключ
    """
    empty = {'lists': [], 'global': []}
    if not os.path.exists(XRAY_RULE_LISTS_DB):
        return empty
    try:
        with open(XRAY_RULE_LISTS_DB, 'r') as f:
            data = json.load(f)
    except Exception:
        return empty

    def _norm(arr):
        return [r for r in (_normalize_simple_entry(x) for x in (arr or [])) if r]

    if isinstance(data, dict):
        # Новая схема — уже единый каталог.
        if 'lists' in data:
            return {'lists': _norm(data.get('lists')), 'global': _norm(data.get('global'))}
        # Старая по-платформенная схема → сливаем sr/loon/clash(/surge) в один
        # каталог по id (id одинаков на всех платформах, дублей нет).
        merged, seen = [], set()
        for p in ('shadowrocket', 'loon', 'clash', 'surge'):
            for x in (data.get(p) or []):
                e = _normalize_simple_entry(x)
                if not e or e['id'] in seen:
                    continue
                seen.add(e['id'])
                merged.append(e)
        migrated = {'lists': merged, 'global': _norm(data.get('global'))}
        try: save_rule_lists(migrated)
        except Exception: pass
        return migrated

    if isinstance(data, list):
        merged, seen = [], set()
        for x in data:
            if not isinstance(x, dict) or not x.get('id') or x['id'] in seen:
                continue
            e = _normalize_simple_entry(x)
            if not e:
                # Legacy paired shape {id,name,shadowrocket_url|loon_url|surge_url}.
                url = (x.get('shadowrocket_url') or x.get('url')
                       or x.get('loon_url') or x.get('surge_url') or '')
                if not url:
                    continue
                e = {'id': x['id'], 'name': x.get('name') or x['id'], 'url': url}
            seen.add(e['id'])
            merged.append(e)
        migrated = {'lists': merged, 'global': []}
        try: save_rule_lists(migrated)
        except Exception: pass
        return migrated

    return empty


def save_rule_lists(data):
    with open(XRAY_RULE_LISTS_DB, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _byfox_rules_load():
    try:
        with open(BYFOX_RULES_FILE, 'r') as f:
            d = json.load(f)
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _byfox_rules_save(d):
    try:
        with open(BYFOX_RULES_FILE, 'w') as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _byfox_own_folders():
    """Имена наших шаблонов (папок) из кэша; пусто, если ещё не синкали."""
    fs = _byfox_rules_load().get('folders')
    return fs if isinstance(fs, list) else []


def _byfox_rules_sync_once():
    """Тянет folders.txt в локальный кэш — это перечень наших шаблонов для пикера.
    Период — общий с blackmatrix7 (вызывается из _bm7_sync_once).

    Сами правила панель НЕ качает: с тех пор как block_ads_trackers_quic стал
    обычным rule-set'ом, их забирает клиент по URL, как у blackmatrix7.
    """
    text = _http_get_text(BYFOX_RULES_BASE + '/folders.txt', timeout=12)
    folders, seen = [], set()
    for raw in (text or '').splitlines():
        s = raw.strip()
        if not s or s.startswith('#') or s in seen:
            continue
        seen.add(s)
        folders.append(s)
    if not folders:
        return
    _byfox_rules_save({'folders': folders, 'fetched': time.strftime('%Y-%m-%d %H:%M')})
    try:
        audit('info', f'Свои шаблоны правил обновлены ({len(folders)} шт)')
    except Exception:
        pass


def _bm7_parse(text):
    """('DD.MM.YYYY' | None, ['Telegram','OpenAI',...]); дедуп, порядок сохраняем."""
    lines = (text or '').splitlines()
    if not lines:
        return None, []
    m = re.search(r'(\d{2}\.\d{2}\.\d{4})', lines[0])
    date = m.group(1) if m else None
    services, seen = [], set()
    for raw in lines[1:]:
        s = raw.strip()
        if not s or s.startswith('<!--') or s.startswith('#') or s in seen:
            continue
        seen.add(s)
        services.append(s)
    return date, services


def _bm7_date_tuple(d):
    """'DD.MM.YYYY' → (Y,M,D) для сравнения; пусто/кривьё → (0,0,0)."""
    try:
        dd, mm, yy = str(d).split('.')
        return (int(yy), int(mm), int(dd))
    except Exception:
        return (0, 0, 0)


def _bm7_load_templates():
    """{date, services, last_check} из кэша; пусто, если кэша ещё нет."""
    try:
        with open(BM7_TEMPLATES_FILE, 'r') as f:
            d = json.load(f)
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _bm7_save_templates(d):
    try:
        with open(BM7_TEMPLATES_FILE, 'w') as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _bm7_local_version():
    return str(SERVER_CFG.get('bm7_version') or '').strip()


def _bm7_write_version(v):
    """Пишет дату шаблонов blackmatrix7 в server.json (как geo_version)."""
    try:
        SERVER_CFG['bm7_version'] = v
        _save_server_config(SERVER_CFG)
    except Exception:
        pass


def _bm7_interval_days():
    try:
        return max(1, int(SERVER_CFG.get('bm7_check_interval_days') or 7))
    except Exception:
        return 7


def _bm7_sync_once():
    """Тянет blackmatrix7.txt и, если дата свежее (или кэша ещё нет), перезаписывает
    кэш ШАБЛОНОВ. xray_rule_lists.json НЕ трогается — там выбор пользователя.
    Заодно (тот же период) синкает свои шаблоны с byfox.dev."""
    try:
        _byfox_rules_sync_once()   # свои шаблоны + QUIC-кэш; период общий с bm7
    except Exception as e:
        try: audit('warn', f'Свои шаблоны правил: {e}')
        except Exception: pass
    text = _http_get_text(BM7_SERVICES_URL, timeout=12)
    remote_date, services = _bm7_parse(text)
    if not services:
        return
    cached = _bm7_load_templates()
    have_cache = bool(cached.get('services'))
    newer = bool(remote_date) and _bm7_date_tuple(remote_date) > _bm7_date_tuple(_bm7_local_version())
    if not (newer or not have_cache):
        return
    _bm7_save_templates({'date': remote_date or '', 'services': services})
    if remote_date:
        _bm7_write_version(remote_date)
    try:
        audit('info', f'blackmatrix7: библиотека шаблонов обновлена ({len(services)} шт, дата {remote_date or "?"})')
    except Exception:
        pass


def _parse_clash_payload(text):
    """Парсит Clash YAML, выдаёт {'domain':[], 'ip':[]}.

    Поддерживает payload-блок: список 'DOMAIN-SUFFIX,foo.com', 'DOMAIN,bar.com',
    'DOMAIN-KEYWORD,baz', 'IP-CIDR,1.2.3.4/32', 'IP-CIDR6,::/0'.
    YAML парсится без зависимостей: ищем строки '- ITEM' внутри payload:.
    """
    domains, ips = [], []
    if not text:
        return {'domain': domains, 'ip': ips}
    in_payload = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not in_payload:
            if re.match(r'^payload\s*:\s*$', stripped):
                in_payload = True
            continue
        # Конец payload — строка без отступа и не начинается с '-' и не пустая.
        if line and not line.startswith((' ', '\t', '-')) and stripped and stripped != '...':
            in_payload = False
            continue
        if not stripped or stripped.startswith('#'):
            continue
        if not stripped.startswith('-'):
            continue
        item = stripped.lstrip('-').strip().strip("'\"")
        if not item:
            continue
        # Может содержать тип-префикс или быть просто доменом/IP.
        upper = item.upper()
        if upper.startswith('DOMAIN-SUFFIX,'):
            domains.append('domain:' + item.split(',', 1)[1].strip().lower())
        elif upper.startswith('DOMAIN,'):
            domains.append('full:' + item.split(',', 1)[1].strip().lower())
        elif upper.startswith('DOMAIN-KEYWORD,'):
            domains.append('keyword:' + item.split(',', 1)[1].strip().lower())
        elif upper.startswith('IP-CIDR,') or upper.startswith('IP-CIDR6,'):
            ips.append(item.split(',', 1)[1].strip().split(',')[0])
        elif '/' in item and re.match(r'^[0-9a-fA-F:.]+/\d+$', item):
            ips.append(item)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', item):
            ips.append(item + '/32')
        else:
            domains.append('domain:' + item.lower())
    return {'domain': domains, 'ip': ips}


def _parse_inline_rules(rules):
    """Парсит inline список (как в rule-lists rules)."""
    domains, ips = [], []
    for raw in (rules or []):
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        if not s or s.startswith('#') or s.startswith('//'):
            continue
        upper = s.upper()
        if upper.startswith('DOMAIN-SUFFIX,'):
            domains.append('domain:' + s.split(',', 1)[1].strip().lower())
        elif upper.startswith('DOMAIN,'):
            domains.append('full:' + s.split(',', 1)[1].strip().lower())
        elif upper.startswith('DOMAIN-KEYWORD,'):
            domains.append('keyword:' + s.split(',', 1)[1].strip().lower())
        elif upper.startswith('IP-CIDR,') or upper.startswith('IP-CIDR6,'):
            ips.append(s.split(',', 1)[1].strip().split(',')[0])
        elif re.match(r'^[0-9a-fA-F:.]+/\d+$', s):
            ips.append(s)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', s):
            ips.append(s + '/32')
        elif s.startswith('*.'):
            domains.append('domain:' + s[2:].lower())
        else:
            domains.append('domain:' + s.lower())
    return {'domain': domains, 'ip': ips}


def _load_global_cache():
    if not os.path.exists(XRAY_GLOBAL_CACHE_DB):
        return {}
    try:
        with open(XRAY_GLOBAL_CACHE_DB, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_global_cache(cache):
    try:
        tmp = XRAY_GLOBAL_CACHE_DB + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp, XRAY_GLOBAL_CACHE_DB)
    except Exception:
        pass


def _entry_cache_key(entry):
    """Стабильный ключ источника правил: URL или хеш inline-rules."""
    if entry.get('url'):
        return 'url:' + entry['url']
    if entry.get('rules'):
        h = hashlib.sha256(('\n'.join(entry['rules'])).encode('utf-8')).hexdigest()[:16]
        return 'inl:' + h
    return ''


def _aggregate_global_lists(selected_ids, force_refresh=False):
    """Скачивает + парсит выбранные записи из каталога 'global', возвращает {'domain':set,'ip':set}.

    Использует data/xray/global_cache.json: если ключ источника совпадает
    с кешем — берём готовый разбор, не качаем. force_refresh=True игнорирует кеш.
    """
    catalog = {r['id']: r for r in load_rule_lists().get('global', [])}
    cache = _load_global_cache()
    cache_changed = False
    all_domains = set()
    all_ips = set()
    for lid in selected_ids:
        entry = catalog.get(str(lid))
        if not entry:
            continue
        key = _entry_cache_key(entry)
        cached = cache.get(str(lid))
        if (not force_refresh and cached and cached.get('key') == key
                and isinstance(cached.get('domain'), list)
                and isinstance(cached.get('ip'), list)):
            all_domains.update(cached['domain'])
            all_ips.update(cached['ip'])
            continue
        if entry.get('rules'):
            parsed = _parse_inline_rules(entry['rules'])
        elif entry.get('url'):
            try:
                text = _http_get_text(entry['url'], timeout=15)
            except Exception as e:
                audit('warn', f'Global rules: не удалось скачать {entry["url"]}: {e}')
                if cached and isinstance(cached.get('domain'), list):
                    # При сетевой ошибке — fallback на старый кеш.
                    all_domains.update(cached['domain'])
                    all_ips.update(cached['ip'])
                continue
            parsed = _parse_clash_payload(text)
        else:
            continue
        cache[str(lid)] = {
            'key': key,
            'domain': sorted(parsed['domain']),
            'ip': sorted(parsed['ip']),
            'fetched': time.strftime('%Y-%m-%d %H:%M'),
        }
        cache_changed = True
        all_domains.update(parsed['domain'])
        all_ips.update(parsed['ip'])
    if cache_changed:
        _save_global_cache(cache)
    return {'domain': all_domains, 'ip': all_ips}


def _strip_global_rules(cfg):
    """Удаляет все ранее добавленные панелью global-правила и outbound."""
    routing = cfg.get('routing') or {}
    rules = routing.get('rules') or []
    new_rules = [r for r in rules if not (isinstance(r, dict) and r.get(_GLOBAL_MARK))]
    if 'routing' in cfg:
        cfg['routing']['rules'] = new_rules
    outbounds = cfg.get('outbounds') or []
    cfg['outbounds'] = [
        ob for ob in outbounds
        if not (isinstance(ob, dict) and ob.get(_GLOBAL_MARK) and ob.get('tag') == 'block')
    ]


def _build_global_rules(state, cfg, force_refresh=False):
    """Список dict-правил с маркером _panel_global для вставки в routing.rules."""
    mode = state.get('mode')
    rules = []
    if not state.get('enabled'):
        return rules
    freedom_tag = _detect_freedom_tag(cfg)
    if mode == 'lists':
        agg = _aggregate_global_lists(state.get('lists') or [], force_refresh=force_refresh)
        # Whitelist по доменам/IP. Порядок критичен — xray идёт сверху вниз,
        # первое совпадение выигрывает.
        # 1) DNS (53) пропускаем всегда — иначе клиент не сможет даже резолвить
        #    домены из whitelist, и весь трафик попадёт в catch-all block.
        # 2) Доменные правила → freedom (по SNI/Host).
        # 3) IP-CIDR правила → freedom (на случай прямого коннекта по IP).
        # 4) Catch-all → block.
        if agg['domain'] or agg['ip']:
            rules.append({
                'type': 'field',
                'port': '53',
                'outboundTag': freedom_tag,
                _GLOBAL_MARK: True,
            })
            if agg['domain']:
                rules.append({
                    'type': 'field',
                    'domain': sorted(agg['domain']),
                    'outboundTag': freedom_tag,
                    _GLOBAL_MARK: True,
                })
            if agg['ip']:
                rules.append({
                    'type': 'field',
                    'ip': sorted(agg['ip']),
                    'outboundTag': freedom_tag,
                    _GLOBAL_MARK: True,
                })
            rules.append({
                'type': 'field',
                'network': 'tcp,udp',
                'outboundTag': 'block',
                _GLOBAL_MARK: True,
            })
    elif mode == 'via':
        countries = [c.upper() for c in (state.get('countries') or [])]
        if countries:
            # Разрешить только страны из списка (geoip), остальное → block.
            rules.append({
                'type': 'field',
                'ip': [f'geoip:{cc.lower()}' for cc in countries],
                'outboundTag': freedom_tag,
                _GLOBAL_MARK: True,
            })
            rules.append({
                'type': 'field',
                'network': 'tcp,udp',
                'outboundTag': 'block',
                _GLOBAL_MARK: True,
            })
    elif mode == 'direct':
        countries = [c.upper() for c in (state.get('countries') or [])]
        if countries:
            rules.append({
                'type': 'field',
                'ip': [f'geoip:{cc.lower()}' for cc in countries],
                'outboundTag': 'block',
                _GLOBAL_MARK: True,
            })
    return rules


def seed_rule_lists_if_empty():
    if os.path.exists(XRAY_RULE_LISTS_DB):
        return
    # Единый каталог: храним один канонический (Clash) URL — формат под платформу
    # выводится на лету при копировании конфига (_rule_url_for_platform).
    # Сидим ТОЛЬКО блокирующие списки: сервисные шаблоны blackmatrix7 регулярно
    # переименовываются (папка уезжает → в каталоге висит битый URL), а блок-листы
    # стабильны. Сервисы юзер добавляет сам через «Шаблоны» — там имена живые.
    # Политику любого списка можно сменить на Direct/VPN кнопкой: список к REJECT
    # не привязан, в нём только условия.
    # Block ads/trackers (ADS_TEMPLATE_ID) больше не сидится ни в один каталог:
    # реклама у клиентов режется на уровне DNS, а доменные апексы, которых в
    # DNS-листах нет (doubleclick.net, googletagmanager.com), ломают YouTube и
    # сайты с consent-баннерами. Шаблон остаётся на CDN и доступен через кнопку
    # «Шаблоны» — кому нужен, добавляет руками.
    lists = [dict(e) for e in XRAY_DEFAULT_BLOCK_LISTS]
    glob = [dict(e) for e in XRAY_DEFAULT_BLOCK_LISTS]
    save_rule_lists({'lists': lists, 'global': glob})


def _ipv4_complement(cidrs):
    """0.0.0.0/0 минус переданные сети. Пустой/полный вход → пустой выход."""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    if not nets:
        return []
    remaining = [ipaddress.ip_network('0.0.0.0/0')]
    for a in ipaddress.collapse_addresses(nets):
        nxt = []
        for r in remaining:
            if a.subnet_of(r):
                nxt.extend(r.address_exclude(a))
            elif not r.subnet_of(a):
                nxt.append(r)
            # r целиком внутри a — вырезано, не переносим
        remaining = nxt
    return [str(n) for n in ipaddress.collapse_addresses(remaining)]


def _strip_allow_ip_rules(cfg):
    """Убирает всё, что панель добавила для белых списков (правила + outbound)."""
    if 'routing' in cfg:
        rules = (cfg.get('routing') or {}).get('rules') or []
        cfg['routing']['rules'] = [
            r for r in rules if not (isinstance(r, dict) and r.get(_ALLOWIP_MARK))
        ]
    cfg['outbounds'] = [
        ob for ob in (cfg.get('outbounds') or [])
        if not (isinstance(ob, dict) and ob.get(_ALLOWIP_MARK))
    ]


def _build_allow_ip_rules(cfg, clients):
    """deny-правила для клиентов с непустым белым и/или чёрным списком."""
    idx = find_xray_inbound_idx(cfg)
    emails = {}
    if idx >= 0:
        for c in ((cfg['inbounds'][idx].get('settings') or {}).get('clients') or []):
            if c.get('id') and c.get('email'):
                emails[c['id']] = c['email']
    rules = []
    for uid, c in (clients or {}).items():
        allow = _norm_allow_ips(c.get('allow_ips'))
        block = _norm_allow_ips(c.get('block_ips'))
        # Дополнение белого списка; пустое = разрешено 0.0.0.0/0, резать нечего.
        deny = _ipv4_complement(allow) if allow else []
        if not deny and not block:
            continue
        # Отключённого клиента в инбаунде нет; email считаем так же, как в статистике,
        # чтобы правило пережило выключение/включение без пересборки.
        email = emails.get(uid) or _xray_unique_email(c.get('name') or '', uid)
        if deny:
            rules.append({
                'type': 'field',
                'user': [email],
                # ::/0 — белый список только для IPv4, иначе доступ утечёт по v6.
                'source': deny + ['::/0'],
                'outboundTag': _ALLOWIP_DENY_TAG,
                _ALLOWIP_MARK: True,
            })
        if block:
            # Без ::/0: чёрный список режет ровно перечисленные адреса, не всёv6.
            rules.append({
                'type': 'field',
                'user': [email],
                'source': block,
                'outboundTag': _ALLOWIP_DENY_TAG,
                _ALLOWIP_MARK: True,
            })
    return rules


def apply_allow_ip_rules():
    """Пересобирает deny-правила (белый + чёрный списки) из xray_clients.json.

    True — конфиг менялся."""
    if not os.path.exists(XRAY_CONFIG):
        return False
    clients = load_xray_clients()
    changed = False
    with _xray_restart_lock:
        cfg = load_xray_config()
        before = json.dumps(cfg, sort_keys=True)
        _strip_allow_ip_rules(cfg)
        rules = _build_allow_ip_rules(cfg, clients)
        if rules:
            routing = cfg.setdefault('routing', {})
            rules_arr = routing.setdefault('rules', [])
            insert_at = 0
            for i, r in enumerate(rules_arr):
                if isinstance(r, dict) and 'api' in (r.get('inboundTag') or []):
                    insert_at = i + 1
            rules_arr[insert_at:insert_at] = rules
            # Свой blackhole, а не общий 'block': тот принадлежит global-правилам и
            # снимается вместе с ними (_strip_global_rules) — ссылка бы повисла.
            cfg.setdefault('outbounds', []).append({
                'protocol': 'blackhole',
                'tag': _ALLOWIP_DENY_TAG,
                _ALLOWIP_MARK: True,
            })
        if json.dumps(cfg, sort_keys=True) != before:
            save_xray_config(cfg)
            changed = True
    if changed:
        schedule_xray_restart()
    return changed


def _rule_url_for_platform(url, platform):
    """Канонический blackmatrix7-URL → URL под нужную платформу (отличаются только
    каталогом репо и расширением: SR/Loon → .list, Clash → .yaml). Не-bm7 URL
    (свой произвольный) отдаём как есть."""
    if not url:
        return url
    # Свои шаблоны byfox: /rules/<name>/{clash/rules.yaml|loon/rules.list|shadowrocket/rules.list}
    mb = re.search(r'^(https?://\S+/data/awg-panel/rules/[^/]+)/(?:clash|loon|shadowrocket)/rules\.(?:yaml|list)$', url)
    if mb:
        prefix = mb.group(1)
        if platform == 'clash':
            return f'{prefix}/clash/rules.yaml'
        p = 'shadowrocket' if platform == 'shadowrocket' else 'loon'
        return f'{prefix}/{p}/rules.list'
    m = re.search(r'/rule/(?:Shadowrocket|Loon|Clash)/(.+?)/([^/]+)\.(?:list|yaml)$', url)
    if not m:
        return url
    name_dir, fname = m.group(1), m.group(2)
    if platform == 'clash':
        return _bm7('Clash', f'{name_dir}/{fname}.yaml')
    return _bm7('Shadowrocket' if platform == 'shadowrocket' else 'Loon', f'{name_dir}/{fname}.list')


def _client_rule_policy_overrides(client):
    """{list_id: policy} — персональные политики правил этого клиента.

    Двойной клик по бейджу политики в карточке клиента пишет сюда, каталог при
    этом не меняется: одно и то же правило может быть у одного клиента Block,
    у другого Direct. Пустой словарь = все правила как в каталоге."""
    ov = client.get('rule_policy')
    if not isinstance(ov, dict):
        return {}
    out = {}
    for k, v in ov.items():
        if isinstance(v, str) and v.strip().lower() in RULE_POLICIES:
            out[str(k)] = v.strip().lower()
    return out


def _lists_final_policy(client, group_name):
    """Куда идёт трафик, не попавший ни в одно правило, в режиме 'lists'.

    По умолчанию 'direct' — списки перечисляют то, что гнать В VPN (историческое
    поведение). При lists_default='vpn' логика инвертируется: всё идёт через VPN,
    а списки становятся исключениями (реально работают только записи с политикой
    Direct/Block — VPN-правило при таком дефолте просто дублирует FINAL).
    При 'block' получается белый список: всё, что не перечислено, режется, а
    осмысленны записи с политикой VPN/Direct.

    Режимов по странам ('via'/'direct') не касается — там свой FINAL.

    Токены DIRECT/REJECT одинаковы у Shadowrocket, Loon и Clash (как в
    _entry_policy), поэтому хелпер один на все три билдера.
    """
    ld = (client.get('lists_default') or 'direct')
    if ld == 'vpn':
        return group_name
    if ld == 'block':
        return 'REJECT'
    return 'DIRECT'


@bp.route('/country/<cc>.<fmt>', methods=['GET'])
def public_country_ruleset(cc, fmt):
    """Публичная отдача rule-set страны для клиентов (без авторизации — их тянет
    сам Loon/Clash/Shadowrocket по URL). Конвертим start-end→CIDR на лету (кеш на диске).
      fmt='list'  → строки `IP-CIDR,<cidr>`  (Shadowrocket RULE-SET, Loon [Remote Rule])
      fmt='clash' → голые `<cidr>`           (Clash rule-provider behavior: ipcidr, format: text)"""
    if fmt not in ('list', 'clash'):
        return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    cidrs = _country_cidrs(cc)
    if cidrs is None:
        return ('Country ranges not available', 404, {'Content-Type': 'text/plain; charset=utf-8'})
    if fmt == 'clash':
        body = '\n'.join(cidrs) + '\n'
    else:
        body = '\n'.join('IP-CIDR,' + c for c in cidrs) + '\n'
    return (body, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=86400',
    })


@bp.route('/api/xray/clients/<client_uuid>/lists-default', methods=['POST'])
@_auth
def xray_set_lists_default(client_uuid):
    """Режим исключений для 'Списки правил': что делать с трафиком вне списков.
    Это часть стратегии маршрутизации, поэтому живёт по тем же правилам, что режим
    и страны: пишем в PENDING, в силу вступает по «Применить» (geo-apply)."""
    data = request.json or {}
    mode = (data.get('mode') or 'direct').strip()
    if mode not in LISTS_DEFAULT_MODES:
        return jsonify({'error': 'Invalid mode'}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['lists_default_pending'] = mode
    save_xray_clients(clients)
    return jsonify({'ok': True, 'lists_default_pending': mode})


@bp.route('/api/xray/clients/<client_uuid>/geo-countries', methods=['POST'])
@_auth
def xray_set_geo_countries(client_uuid):
    data = request.json or {}
    raw = data.get('countries') or []
    if not isinstance(raw, list):
        return jsonify({'error': 'countries must be array'}), 400
    countries = []
    for cc in raw:
        if isinstance(cc, str) and re.match(r'^[A-Za-z]{2}$', cc):
            countries.append(cc.upper())
    countries = list(dict.fromkeys(countries))  # dedup, preserve order
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Not found'}), 404
    clients[client_uuid]['geo_countries_pending'] = countries
    save_xray_clients(clients)
    return jsonify({'ok': True, 'geo_countries_pending': countries})


@bp.route('/api/xray/clients/<client_uuid>/rule', methods=['POST'])
@_auth
def xray_toggle_rule(client_uuid):
    data = request.json or {}
    bypass_ru = bool(data.get('bypass_ru', False))
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    was = bool(clients[client_uuid].get('bypass_ru', False))
    clients[client_uuid]['bypass_ru'] = bypass_ru
    save_xray_clients(clients)
    if was != bypass_ru:
        audit('info', f'XRay bypass_ru для {clients[client_uuid].get("name")}: ' + ('ON' if bypass_ru else 'OFF'))
    return jsonify({'ok': True, 'bypass_ru': bypass_ru})


@bp.route('/api/xray/rule-lists', methods=['GET'])
@_auth
def xray_rule_lists_get():
    return jsonify({'lists': load_rule_lists()})


@bp.route('/api/xray/rule-templates', methods=['GET'])
@_auth
def xray_rule_templates_get():
    """Библиотека шаблонов blackmatrix7 для пикера «Шаблоны». Авто-обновляется
    по интервалу bm7_* из server.json (_auto_update_loop). Пусто → фронт берёт вшитый TPL_SERVICES."""
    t = _bm7_load_templates()
    return jsonify({'date': t.get('date') or '', 'services': t.get('services') or [], 'own': _byfox_own_folders()})


@bp.route('/api/xray/rule-lists', methods=['POST'])
@_auth
def xray_rule_lists_add():
    data = request.json or {}
    platform = (data.get('platform') or '').strip()
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip()
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': f'platform must be one of {list(RULE_PLATFORMS)}'}), 400
    if not name:
        return jsonify({'error': 'name required'}), 400
    rules = _normalize_inline_rules(data.get('rules'))
    if rules:
        entry_body = {'rules': rules}
    elif url:
        if not (url.startswith('http://') or url.startswith('https://')):
            return jsonify({'error': 'url must be http(s)'}), 400
        entry_body = {'url': url}
    else:
        return jsonify({'error': 'either url or rules required'}), 400
    catalog = load_rule_lists()
    existing_ids = {r['id'] for r in catalog[platform]}
    base = _slugify_rule_id(name)
    new_id = base
    n = 2
    while new_id in existing_ids:
        new_id = f"{base}-{n}"
        n += 1
    entry = {'id': new_id, 'name': name, **entry_body}
    catalog[platform].append(entry)
    save_rule_lists(catalog)
    src = 'url' if 'url' in entry_body else f'inline:{len(rules)}'
    audit('info', f'Rule-list создан [{platform}] {name} (id={new_id}, {src})')
    return jsonify({'ok': True, 'platform': platform, 'list': entry})


@bp.route('/api/xray/rule-lists/<platform>/<list_id>', methods=['PUT'])
@_auth
def xray_rule_lists_update(platform, list_id):
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': 'unknown platform'}), 400
    data = request.json or {}
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip()
    if not name:
        return jsonify({'error': 'name required'}), 400
    rules = _normalize_inline_rules(data.get('rules'))
    if rules:
        new_body = {'rules': rules}
    elif url:
        if not (url.startswith('http://') or url.startswith('https://')):
            return jsonify({'error': 'url must be http(s)'}), 400
        new_body = {'url': url}
    else:
        return jsonify({'error': 'either url or rules required'}), 400
    catalog = load_rule_lists()
    found = False
    for r in catalog[platform]:
        if r['id'] == list_id:
            r['name'] = name
            # switch type cleanly: drop both fields, then set the new one
            r.pop('url', None)
            r.pop('rules', None)
            r.update(new_body)
            found = True
            break
    if not found:
        return jsonify({'error': 'not found'}), 404
    save_rule_lists(catalog)
    src = 'url' if 'url' in new_body else f'inline:{len(rules)}'
    audit('info', f'Rule-list изменён [{platform}] {name} (id={list_id}, {src})')
    return jsonify({'ok': True})


@bp.route('/api/xray/rule-lists/<platform>/<list_id>/policy', methods=['POST'])
@_auth
def xray_rule_lists_policy(platform, list_id):
    """Политика правила: VPN (группа прокси) | Direct | Block. Сохраняется сразу,
    как порядок — отдельной кнопки нет."""
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': 'unknown platform'}), 400
    policy = (request.json or {}).get('policy') or ''
    policy = policy.strip().lower()
    if policy not in RULE_POLICIES:
        return jsonify({'error': 'policy must be one of %s' % (', '.join(RULE_POLICIES))}), 400
    catalog = load_rule_lists()
    for r in catalog[platform]:
        if r['id'] == list_id:
            r['policy'] = policy
            save_rule_lists(catalog)
            audit('info', f'Rule-list политика [{platform}] {r.get("name")} → {policy} (id={list_id})')
            return jsonify({'ok': True})
    return jsonify({'error': 'not found'}), 404


@bp.route('/api/xray/rule-lists/<platform>/<list_id>', methods=['DELETE'])
@_auth
def xray_rule_lists_delete(platform, list_id):
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': 'unknown platform'}), 400
    catalog = load_rule_lists()
    before = len(catalog[platform])
    catalog[platform] = [r for r in catalog[platform] if r['id'] != list_id]
    if len(catalog[platform]) == before:
        return jsonify({'error': 'not found'}), 404
    save_rule_lists(catalog)
    # Drop this id from every client's per-platform selection.
    clients = load_xray_clients()
    changed = False
    for c in clients.values():
        rl = c.get('rule_lists') or {}
        if isinstance(rl, dict):
            sel = rl.get(platform) or []
            if list_id in sel:
                rl[platform] = [i for i in sel if i != list_id]
                changed = True
    if changed:
        save_xray_clients(clients)
    audit('info', f'Rule-list удалён [{platform}] id={list_id}' + (' (отвязан у клиентов)' if changed else ''))
    return jsonify({'ok': True})


@bp.route('/api/xray/rule-lists/<platform>/clear', methods=['POST'])
@_auth
def xray_rule_lists_clear(platform):
    """Очищает весь каталог одной вкладки. Выборки клиентов НЕ трогаем — id
    остаются в xray_clients.json, поэтому повторно добавленный шаблон с тем же
    id снова «загорится» у клиента."""
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': 'unknown platform'}), 400
    catalog = load_rule_lists()
    n = len(catalog.get(platform) or [])
    catalog[platform] = []
    save_rule_lists(catalog)
    audit('info', f'Rule-list: вкладка [{platform}] очищена ({n} записей), выборки клиентов сохранены')
    return jsonify({'ok': True, 'removed': n})


@bp.route('/api/xray/rule-lists/<platform>/reorder', methods=['POST'])
@_auth
def xray_rule_lists_reorder(platform):
    """Пересортировывает каталог вкладки по присланному порядку id. Порядок каталога
    = приоритет правил в конфиге (первое правило каталога = первое в конфиге). id, не
    попавшие в order, дописываются в конец в прежнем относительном порядке."""
    if platform not in RULE_PLATFORMS:
        return jsonify({'error': 'unknown platform'}), 400
    data = request.json or {}
    order = [str(i) for i in (data.get('order') or [])]
    catalog = load_rule_lists()
    entries = catalog.get(platform) or []
    by_id = {r['id']: r for r in entries}
    seen = set()
    ordered = []
    for i in order:
        r = by_id.get(i)
        if r and i not in seen:
            ordered.append(r)
            seen.add(i)
    # хвост: всё, что не перечислено (новые/пропущенные) — в прежнем порядке
    for r in entries:
        if r['id'] not in seen:
            ordered.append(r)
            seen.add(r['id'])
    catalog[platform] = ordered
    save_rule_lists(catalog)
    audit('info', f'Rule-list: порядок вкладки [{platform}] изменён ({len(ordered)} записей)')
    return jsonify({'ok': True})


@bp.route('/api/xray/clients/<client_uuid>/rule-lists', methods=['POST'])
@_auth
def xray_set_client_rule_lists(client_uuid):
    data = request.json or {}
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    catalog = load_rule_lists()
    new_sel = {}
    for p in CLIENT_RULE_PLATFORMS:
        ids_in_catalog = {r['id'] for r in catalog.get(p, [])}
        # Accept either {shadowrocket: [...], surge: [...]} or legacy {ids:[...]}
        if p in data and isinstance(data[p], list):
            arr = data[p]
        elif 'ids' in data and isinstance(data['ids'], list):
            arr = data['ids']
        else:
            # Preserve existing selection if not specified
            existing = clients[client_uuid].get('rule_lists') or {}
            arr = existing.get(p, []) if isinstance(existing, dict) else []
        new_sel[p] = [str(i) for i in arr if str(i) in ids_in_catalog]
    old_sel = clients[client_uuid].get('rule_lists') or {}
    clients[client_uuid]['rule_lists'] = new_sel
    save_xray_clients(clients)
    if old_sel != new_sel:
        summary = ', '.join(f'{p}={len(new_sel.get(p) or [])}' for p in CLIENT_RULE_PLATFORMS)
        audit('info', f'XRay rule-lists для {clients[client_uuid].get("name")}: {summary}')
    return jsonify({'ok': True, 'rule_lists': new_sel})


@bp.route('/api/xray/clients/<client_uuid>/rule-policy', methods=['POST'])
@_auth
def xray_set_client_rule_policy(client_uuid):
    """Персональная политика правила: перекрывает policy записи каталога только
    в профиле этого клиента. Пустая policy — снять переопределение и вернуться к
    каталогу. Сам каталог не меняется никогда, поэтому «Применить» тут не нужно:
    политика читается билдерами при выдаче профиля (_client_selected_for)."""
    data = request.json or {}
    list_id = str(data.get('id') or '').strip()
    policy = (data.get('policy') or '').strip().lower()
    if not list_id:
        return jsonify({'error': 'id required'}), 400
    if policy and policy not in RULE_POLICIES:
        return jsonify({'error': 'policy must be one of %s' % (', '.join(RULE_POLICIES))}), 400
    clients = load_xray_clients()
    if client_uuid not in clients:
        return jsonify({'error': 'Client not found'}), 404
    cur = clients[client_uuid].get('rule_policy')
    ov = {str(k): v for k, v in cur.items()} if isinstance(cur, dict) else {}
    if policy:
        ov[list_id] = policy
    else:
        ov.pop(list_id, None)
    clients[client_uuid]['rule_policy'] = ov
    save_xray_clients(clients)
    audit('info', f'Своя политика правила {list_id} у {clients[client_uuid].get("name")}: '
                  f'{policy or "как в каталоге"}')
    return jsonify({'ok': True, 'rule_policy': ov})
