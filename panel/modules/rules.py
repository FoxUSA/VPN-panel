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

import gzip
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

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
geo_asn_full = None
find_xray_inbound_idx = None
load_xray_clients = None
load_xray_config = None
save_xray_clients = None
save_xray_config = None
schedule_xray_restart = None
login_required = None
SERVER_CFG = {}
RULE_BASE_URL = ''
PANEL_VERSION = ''
BM7_TEMPLATES_FILE = ''
BYFOX_RULES_BASE = ''
BYFOX_RULES_FILE = ''
RULE_TPL_CACHE_DIR = ''
RULE_INDEX_DIR = ''
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
    'RULE_BASE_URL',
    'PANEL_VERSION',
    'BM7_TEMPLATES_FILE',
    'BYFOX_RULES_BASE',
    'BYFOX_RULES_FILE',
    'RULE_TPL_CACHE_DIR',
    'RULE_INDEX_DIR',
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
    'geo_asn_full',
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
                 'BM7_TEMPLATES_FILE', 'BYFOX_RULES_FILE', 'RULE_BASE_URL', 'RULE_INDEX_DIR'):
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
    # Индекс шаблонов для «Домен или IP» — через пару минут после старта, чтобы
    # не мешать запуску. Свежий (сверен за сутки) не трогается.
    _tpl_index_kick(delay=120)


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


# Файлы blackmatrix7 — с зеркала на api.byfox.dev: путь тот же, что в репо bm7
# (rule/<Платформа>/<Имя>/<файл>), меняется только начало адреса.
def _bm7(client_dir, fname):
    return f'{RULE_BASE_URL}bm7/{client_dir}/{fname}'


# Старые адреса шаблонов → api.byfox.dev. Хвост пути у всех трёх совпадает.
# Сохранённые в каталоге URL переписываются при чтении (load_rule_lists), а
# _rule_url_for_platform прогоняет через это всё, что приходит, на случай
# адреса, который ещё не прошёл через каталог.
_OLD_RULE_PREFIXES = (
    ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/', 'bm7/'),
    ('https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/', 'bm7/'),
    ('https://byfox.dev/data/awg-panel/rules/', 'byfox/'),
)


def _migrate_rule_url(url):
    for old, new in _OLD_RULE_PREFIXES:
        if url and url.startswith(old):
            return RULE_BASE_URL + new + url[len(old):]
    return url


def _default_block_lists():
    """Блокирующие списки blackmatrix7 для сида каталога. Порядок каталога =
    приоритет правил в конфиге, поэтому блокировки стоят первыми. У Advertising
    и Privacy домены лежат в <Имя>_Domain (domain-set), остальное — в «rest»
    (см. _tpl_rest_url). Функция, а не константа: RULE_BASE_URL приезжает в init()."""
    return [
        {'id': 'advertising', 'name': 'Advertising', 'policy': 'reject',
         'url': _bm7('Clash', 'Advertising/Advertising_Domain.yaml')},
        {'id': 'privacy',     'name': 'Privacy',     'policy': 'reject',
         'url': _bm7('Clash', 'Privacy/Privacy_Domain.yaml')},
        {'id': 'hijacking',   'name': 'Hijacking',   'policy': 'reject',
         'url': _bm7('Clash', 'Hijacking/Hijacking.yaml')},
    ]


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
            out = {'lists': _norm(data.get('lists')), 'global': _norm(data.get('global'))}
            # Шаблоны переехали на api.byfox.dev: старые адреса (GitHub, byfox.dev/data)
            # переписываем один раз и сохраняем — дальше каталог уже с новыми.
            moved = 0
            for e in out['lists'] + out['global']:
                if e.get('url'):
                    new = _migrate_rule_url(e['url'])
                    if new != e['url']:
                        e['url'] = new
                        moved += 1
            if moved:
                try:
                    save_rule_lists(out)
                    audit('info', f'Списки правил: {moved} адресов шаблонов переведены на api.byfox.dev')
                except Exception:
                    pass
            return out
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


def _byfox_own_folders():
    """Имена наших шаблонов: из каталога api.byfox.dev, а пока его нет — из
    старого кэша folders.txt. Скрытые не показываем."""
    items = _tpl_items()
    if items:
        return [i['id'] for i in items if i.get('src') == 'byfox' and not i.get('hidden')]
    fs = _byfox_rules_load().get('folders')
    return fs if isinstance(fs, list) else []


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
    """Кэш каталога {date, sha, base, items[]}; у старого кэша — {date, services[]}."""
    try:
        with open(BM7_TEMPLATES_FILE, 'r') as f:
            d = json.load(f)
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _bm7_save_templates(d):
    tmp = BM7_TEMPLATES_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, BM7_TEMPLATES_FILE)


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
        return max(1, int(SERVER_CFG.get('bm7_check_interval_days') or 1))
    except Exception:
        return 1


# --- Каталог шаблонов с api.byfox.dev --------------------------------------
# rule/templates.json(.gz) — все шаблоны bm7 и свои: подсказки RU/EN, теги,
# пути файлов под каждую платформу (files), у domain-set — ещё и rest (classical
# с keyword/IP, которые в domain-set не влезли). rule/manifest.json — sha
# каталога и индекса: по нему видно, что поменялось, не качая сам каталог.
# Из каталога в кэш берём только то, что читает панель.
_TPL_KEEP_FIELDS = ('id', 'src', 'name', 'title', 'desc', 'tags', 'category', 'check',
                    'domain_set', 'stats', 'sample', 'files', 'rest', 'hidden', 'updated')
_tpl_cache_mem = {'mtime': None, 'data': {}}


def _rule_manifest():
    return json.loads(_http_get_text(RULE_BASE_URL + 'manifest.json', timeout=12))


def _iso_to_ddmm(iso):
    """'2026-11-03' → '03.11.2026' (формат bm7_version, по нему сравнивает апдейтер)."""
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})', str(iso or ''))
    return f'{m.group(3)}.{m.group(2)}.{m.group(1)}' if m else ''


def _get_verified(rel, sha, timeout=60):
    """Файл с api.byfox.dev/rule/ с проверкой sha256 из манифеста."""
    data = _http_get_bytes(RULE_BASE_URL + rel, timeout=timeout)
    if sha and hashlib.sha256(data).hexdigest() != sha:
        raise ValueError(f'{rel}: sha256 не совпал с rule/manifest.json')
    return data


def _tpl_cached():
    """Кэш каталога из файла, перечитывается по mtime (его читают пикер, профили, поиск)."""
    try:
        mt = os.path.getmtime(BM7_TEMPLATES_FILE)
    except OSError:
        return {}
    if _tpl_cache_mem['mtime'] != mt:
        _tpl_cache_mem['data'] = _bm7_load_templates()
        _tpl_cache_mem.pop('urls', None)
        _tpl_cache_mem['mtime'] = mt
    return _tpl_cache_mem['data']


def _tpl_items():
    items = _tpl_cached().get('items')
    return items if isinstance(items, list) else []


def _tpl_base():
    return _tpl_cached().get('base') or RULE_BASE_URL


def _tpl_url_map():
    """URL файла шаблона (lower) → (item, 'files'|'rest', платформа)."""
    _tpl_cached()
    m = _tpl_cache_mem.get('urls')
    if m is None:
        m, base = {}, _tpl_base()
        for it in _tpl_items():
            for kind in ('files', 'rest'):
                for plat, rel in (it.get(kind) or {}).items():
                    m[(base + rel).lower()] = (it, kind, plat)
        _tpl_cache_mem['urls'] = m
    return m


def _tpl_rest_url(url):
    """Для domain-set шаблона — его classical-«rest» той же платформы, иначе ''.

    bm7 кладёт домены крупных списков в <Имя>_Domain, а ключевые слова, IP и ASN —
    в <Имя>.yaml/.list. Подключать надо оба, иначе половина правил теряется."""
    hit = _tpl_url_map().get(_migrate_rule_url(url or '').lower())
    if not hit:
        return ''
    it, kind, plat = hit
    rel = (it.get('rest') or {}).get(plat) if kind == 'files' and it.get('domain_set') else None
    return _tpl_base() + rel if rel else ''


def _fetch_remote_bm7_date():
    """Дата каталога шаблонов на api.byfox.dev (DD.MM.YYYY); '' при ошибке."""
    try:
        return _iso_to_ddmm(_rule_manifest().get('date'))
    except Exception:
        return ''


def _tpl_visible_ids(cached):
    items = cached.get('items')
    if isinstance(items, list):
        return ([i['id'] for i in items if i.get('src') == 'bm7' and not i.get('hidden')],
                [i['id'] for i in items if i.get('src') == 'byfox' and not i.get('hidden')])
    return list(cached.get('services') or []), list(_byfox_rules_load().get('folders') or [])


def _bm7_sync_once():
    """Синк каталога шаблонов + индекса для «Домен или IP» (индекс — фоном)."""
    man = None
    try:
        man = _rule_manifest()
    except Exception as e:
        try: audit('warn', f'api.byfox.dev/rule/manifest.json недоступен: {e}')
        except Exception: pass
    try:
        return _bm7_sync_core(man)
    finally:
        _tpl_index_kick(manifest=man)


def _bm7_sync_core(man):
    """Перекачивает каталог, если sha templates.json.gz в манифесте сменился (или
    кэша ещё нет). xray_rule_lists.json НЕ трогается — там выбор пользователя.

    Возвращает итог для кнопки «Обновить шаблоны»: сколько всего и что
    добавилось или ушло (blackmatrix7 и свои — вместе)."""
    cached = _bm7_load_templates()
    bm7_before, own_before = _tpl_visible_ids(cached)

    def _summary(changed, now):
        bm7_after, own_after = _tpl_visible_ids(now)
        before = set(bm7_before) | set(own_before)
        after = set(bm7_after) | set(own_after)
        return {'bm7': len(bm7_after), 'own': len(own_after), 'changed': changed,
                'added': sorted(after - before, key=str.lower),
                'removed': sorted(before - after, key=str.lower)}

    if not man:
        raise RuntimeError('api.byfox.dev не ответил — шаблоны остались прежние')
    f = (man.get('files') or {}).get('templates.json.gz') or {}
    if cached.get('items') and cached.get('sha') == f.get('sha256'):
        return _summary(False, cached)
    tpl = json.loads(gzip.decompress(_get_verified('templates.json.gz', f.get('sha256'))).decode('utf-8'))
    items = [{k: i[k] for k in _TPL_KEEP_FIELDS if k in i}
             for i in (tpl.get('items') or []) if isinstance(i, dict) and i.get('id') and i.get('files')]
    if len(items) < 100:
        raise RuntimeError(f'в каталоге api.byfox.dev подозрительно мало шаблонов ({len(items)})')
    date = _iso_to_ddmm(man.get('date') or tpl.get('date'))
    now = {'date': date, 'sha': f.get('sha256') or '', 'base': RULE_BASE_URL,
           'bm7_date': tpl.get('bm7_date') or '', 'items': items,
           'fetched': time.strftime('%Y-%m-%d %H:%M')}
    _bm7_save_templates(now)
    if date:
        _bm7_write_version(date)
    s = _summary(True, now)
    try:
        audit('info', f'Шаблоны правил обновлены с api.byfox.dev: {s["bm7"]} blackmatrix7 и {s["own"]} своих, дата {date or "?"}')
    except Exception:
        pass
    return s


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
        elif re.match(r'^[A-Z0-9-]+,', upper):
            # Тип, которого у XRay нет (IP-ASN, PROCESS-NAME, DOMAIN-REGEX, GEOIP…):
            # раньше он уезжал в домены мусором вида 'domain:ip-asn,62041'.
            continue
        else:
            # Голый домен. Списки с behavior: domain (bm7 *_Domain.yaml) пишут
            # суффикс как '+.example.com', Loon/SR-формат — как '.example.com'.
            # XRay '+.' не понимает: такая запись не совпадала ни с чем.
            d = item.lower()
            for pfx in ('+.', '*.', '.'):
                if d.startswith(pfx):
                    d = d[len(pfx):]
                    break
            if d:
                domains.append('domain:' + d)
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


# Версия разборщика в ключе кеша: при правке _parse_clash_payload старый разбор,
# закешированный в global_cache.json, пересобирается сам, без ручного сброса.
# 2 — '+.домен' из *_Domain.yaml и отбрасывание чужих типов (IP-ASN и т.п.).
# 3 — файлы с api.byfox.dev и rest к domain-set (keyword/IP, что в _Domain не влезли).
_GLOBAL_PARSER_VER = 3


def _entry_cache_key(entry):
    """Стабильный ключ источника правил: URL или хеш inline-rules."""
    if entry.get('url'):
        url = _migrate_rule_url(entry['url'])
        return f'url{_GLOBAL_PARSER_VER}:' + url + ('|' + _tpl_rest_url(url) if _tpl_rest_url(url) else '')
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
            url = _migrate_rule_url(entry['url'])
            rest = _tpl_rest_url(url)
            try:
                parsed = {'domain': [], 'ip': []}
                for u in ([url, rest] if rest else [url]):
                    part = _parse_clash_payload(_http_get_text(u, timeout=15))
                    parsed['domain'] += part['domain']
                    parsed['ip'] += part['ip']
            except Exception as e:
                audit('warn', f'Global rules: не удалось скачать {url}: {e}')
                if cached and isinstance(cached.get('domain'), list):
                    # При сетевой ошибке — fallback на старый кеш.
                    all_domains.update(cached['domain'])
                    all_ips.update(cached['ip'])
                continue
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
    lists = _default_block_lists()
    glob = _default_block_lists()
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
    """Канонический URL шаблона → URL под нужную платформу. Шаблон из каталога
    api.byfox.dev — путь берём из его files/rest (у платформы может быть свой файл
    или его нет вовсе); иначе — по шаблону пути bm7 (каталог репо + расширение:
    SR/Loon → .list, Clash → .yaml). Старые адреса (GitHub, byfox.dev/data) сначала
    переводятся на api.byfox.dev. Произвольный URL отдаём как есть."""
    if not url:
        return url
    url = _migrate_rule_url(url)
    plat = platform if platform in ('shadowrocket', 'loon') else 'clash'
    hit = _tpl_url_map().get(url.lower())
    if hit:
        it, kind, _ = hit
        rel = (it.get(kind) or {}).get(plat)
        if rel:
            return _tpl_base() + rel
    # Свои шаблоны byfox: /byfox/<name>/{clash/rules.yaml|loon/rules.list|shadowrocket/rules.list}
    mb = re.search(r'^(https?://\S+/rule/byfox/[^/]+)/(?:clash|loon|shadowrocket)/rules\.(?:yaml|list)$', url)
    if mb:
        prefix = mb.group(1)
        if platform == 'clash':
            return f'{prefix}/clash/rules.yaml'
        p = 'shadowrocket' if platform == 'shadowrocket' else 'loon'
        return f'{prefix}/{p}/rules.list'
    m = re.search(r'/rule/bm7/(?:Shadowrocket|Loon|Clash)/(.+?)/([^/]+)\.(?:list|yaml)$', url)
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
    """Каталог шаблонов для пикера «Шаблоны» (с api.byfox.dev, авто-обновляется по
    интервалу bm7_* из server.json). items — с подсказками и путями файлов, base —
    к чему эти пути приклеивать. Каталога ещё нет — старый кэш имён (services/own),
    а совсем пусто → фронт берёт вшитый TPL_SERVICES."""
    t = _tpl_cached()
    items = [i for i in _tpl_items() if not i.get('hidden')]
    if items:
        # Слова для поиска в пикере — из names индекса: id, теги, слова подсказки и
        # категории на RU/EN («imessage» → Apple, «нейросети» → OpenAI, Claude…).
        words = {}
        try:
            ids = (_idx_read('ids.json') or {}).get('ids') or []
            for w, nums in (_idx_read('names.json.gz', keep=False) or {}).items():
                for n in nums:
                    if 0 <= n < len(ids):
                        words.setdefault(ids[n], []).append(w)
        except Exception:
            pass
        items = [dict(i, words=' '.join(words.get(i['id'], ()))) for i in items]
        return jsonify({'date': t.get('date') or '', 'base': _tpl_base(), 'items': items})
    return jsonify({'date': t.get('date') or '', 'services': t.get('services') or [], 'own': _byfox_own_folders()})


# === Где домен: поиск по содержимому списков ================================
# Поле «Домен или IP» в модалке «Списки правил»: в какие записи каталога попадает
# адрес и какая из них сработает первой (порядок каталога = приоритет). Домен
# резолвится на сервере — так IP-CIDR / IP-ASN / GEOIP правила тоже проверяются.
# Файлы списков и шаблонов — копиями на диске (RULE_TPL_CACHE_DIR), общими для
# поиска и индекса шаблонов: один и тот же файл не качается дважды.
_LOOKUP_DEADLINE = 12          # gunicorn --timeout 30: не дольше, недокачанное — в фоне
_LOOKUP_MAX_HITS = 5           # строк-совпадений на запись, остальное — счётчиком
_RULES_FRESH = 86400           # копия младше суток — не перекачиваем
_DL_FILE_DEADLINE = 45         # потолок на файл целиком: GitHub с сервера бывает еле живой
_dl_inflight = {}              # url → Future: опрос раз в 4 с не плодит повторных загрузок
_dl_lock = threading.Lock()
_dl_pool = None
_gh_slow_until = 0             # GitHub подвёл — час качаем сначала с jsDelivr
_LOOKUP_DOMAIN_TYPES = ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX')
_LOOKUP_IP_TYPES = ('IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP')


def _lookup_parse_query(q):
    """'https://www.x.com:443/p' → ('www.x.com', []); '1.2.3.4' → ('', ['1.2.3.4'])."""
    s = (q or '').strip()
    m = re.match(r'^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/?#\s]*@)?(\[[^\]]+\]|[^/?#\s]+)', s, re.I)
    host = m.group(1) if m else ''
    if host.startswith('['):
        host = host[1:-1]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    host = host.strip().rstrip('.').lower()
    if host.startswith('*.'):
        host = host[2:]
    try:
        return '', [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        host = host.encode('idna').decode('ascii')   # .рф → xn--p1ai, как в списках
    except Exception:
        pass
    if not re.match(r'^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$', host):
        return None, None
    return host, []


def _lookup_resolve(host, timeout=4):
    """A/AAAA глазами сервера. getaddrinfo не умеет таймаут — ждём его в потоке."""
    res = {}

    def run():
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            res['ips'] = list(dict.fromkeys(i[4][0] for i in infos))
        except Exception as e:
            res['err'] = str(e)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return [], f'DNS timeout {timeout}s'
    return res.get('ips') or [], res.get('err')


def _rules_mirror(url):
    """raw.githubusercontent.com → то же через jsDelivr; для прочих URL — ''."""
    m = re.match(r'^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$', url)
    return f'https://cdn.jsdelivr.net/gh/{m.group(1)}/{m.group(2)}@{m.group(3)}/{m.group(4)}' if m else ''


def _read_url_capped(url, deadline):
    """Скачать целиком, но не дольше deadline: таймаут urlopen — на каждое чтение,
    и струйка в пару КБ/с тянула 8-мегабайтный файл бесконечно."""
    import urllib.request
    t0 = time.time()
    req = urllib.request.Request(url, headers={'User-Agent': f'awg-panel/{PANEL_VERSION}'})
    chunks = []
    with urllib.request.urlopen(req, timeout=15) as r:
        while True:
            b = r.read(65536)
            if not b:
                break
            chunks.append(b)
            if time.time() - t0 > deadline:
                raise TimeoutError(f'timeout {deadline}s')
    return b''.join(chunks).decode('utf-8', errors='replace')


def _rules_fetch(url):
    global _gh_slow_until
    alt = _rules_mirror(url)
    order = [url]
    if alt:
        order = [alt, url] if time.time() < _gh_slow_until else [url, alt]
    err = None
    for u in order:
        try:
            return _read_url_capped(u, _DL_FILE_DEADLINE)
        except Exception as e:
            err = e
            if u == url and alt:
                _gh_slow_until = time.time() + 3600
    raise err


def _rules_age(url):
    try:
        return time.time() - os.path.getmtime(_tpl_file(url))
    except OSError:
        return None


def _rules_cached(url):
    """Текст копии файла с диска или None."""
    try:
        with open(_tpl_file(url), 'r', encoding='utf-8') as f:
            return f.read()
    except OSError:
        return None


def _rules_download_job(url):
    text = _rules_fetch(url)
    path = _tpl_file(url)
    os.makedirs(RULE_TPL_CACHE_DIR, exist_ok=True)
    tmp = f'{path}.{threading.get_ident()}.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)       # поиск видит старую копию или новую, но не огрызок


def _rules_download(url, pool=None):
    """Future загрузки url в дисковый кеш. Уже идущая загрузка переиспользуется.
    Результат не возвращаем: Future живёт в _dl_inflight, текст держал бы память."""
    global _dl_pool
    with _dl_lock:
        f = _dl_inflight.get(url)
        if f and not f.done():
            return f
        if pool is None:
            if _dl_pool is None:
                _dl_pool = ThreadPoolExecutor(max_workers=6)
            pool = _dl_pool
        f = pool.submit(_rules_download_job, url)
        _dl_inflight[url] = f
        return f


def _lookup_scan(text, inline, host, ips, asns, ccs):
    """Строки списка, под которые попадает host или один из его IP.

    Понимает и Clash YAML (payload, '+.домен'), и .list. Голый домен в своём
    списке («Вручную») — суффикс, как его и собирает конфиг; в файле по URL
    (behavior: domain) — точное имя."""
    hits, total = [], 0
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in '#;' or s.startswith('//') or s.endswith(':'):
            continue
        if s.startswith('- '):
            s = s[2:].strip()
        s = s.strip('\'"')
        parts = [p.strip() for p in s.split(',')]
        typ = parts[0].upper()
        hit = None
        if len(parts) >= 2 and typ in _LOOKUP_DOMAIN_TYPES:
            if not host:
                continue
            v = parts[1].lower()
            if typ == 'DOMAIN':
                ok = host == v
            elif typ == 'DOMAIN-SUFFIX':
                ok = host == v or host.endswith('.' + v)
            elif typ == 'DOMAIN-KEYWORD':
                ok = v in host
            elif typ == 'DOMAIN-WILDCARD':
                ok = re.fullmatch(re.escape(v).replace(r'\*', '.*').replace(r'\?', '.'), host) is not None
            else:
                try:
                    ok = re.search(parts[1], host) is not None
                except re.error:
                    ok = False
            if ok:
                hit = {'rule': s, 'by': 'domain'}
        elif len(parts) >= 2 and typ in _LOOKUP_IP_TYPES:
            if not ips:
                continue
            nr = any(p.lower() == 'no-resolve' for p in parts[2:])
            if typ == 'IP-ASN':
                ok_ip = next((ip for ip in ips if asns.get(str(ip)) == parts[1]), None)
            elif typ == 'GEOIP':
                ok_ip = next((ip for ip in ips if ccs.get(str(ip)) == parts[1].upper()), None)
            else:
                try:
                    net = ipaddress.ip_network(parts[1], strict=False)
                except ValueError:
                    continue
                ok_ip = next((ip for ip in ips if ip.version == net.version and ip in net), None)
            if ok_ip is not None:
                hit = {'rule': s, 'by': 'ip', 'ip': str(ok_ip), 'no_resolve': nr}
        elif len(parts) == 1 and s:
            v = s.lower()
            if v[0].isdigit() or ':' in v:
                if not ips:
                    continue
                try:
                    net = ipaddress.ip_network(v, strict=False)
                except ValueError:
                    continue
                ok_ip = next((ip for ip in ips if ip.version == net.version and ip in net), None)
                if ok_ip is not None:
                    hit = {'rule': s, 'by': 'ip', 'ip': str(ok_ip), 'no_resolve': False}
            elif host:
                for pfx in ('+.', '.', '*.'):
                    if v.startswith(pfx):
                        d = v[len(pfx):]
                        ok = host.endswith('.' + d) or (pfx != '*.' and host == d)
                        break
                else:
                    ok = host == v or (inline and host.endswith('.' + v))
                if ok:
                    hit = {'rule': s, 'by': 'domain'}
        if hit:
            total += 1
            if len(hits) < _LOOKUP_MAX_HITS:
                hits.append(hit)
    return hits, total


# --- Индекс шаблонов: поиск по ещё не добавленным --------------------------
# Готовый индекс с api.byfox.dev/rule/index/ (собирается там раз в сутки по
# всем шаблонам): ids.json — номер → id шаблона; domain/<sha1(ключ)[:2]>.json.gz —
# {"suffix","exact"} по шардам; keyword/cidr/asn.json.gz. Домен ищется в шардах
# самого имени и каждого родителя, поэтому на запрос читается пара файлов по
# десятку КБ, а не весь индекс (целиком он ~100 МБ в памяти). Набор подменяется
# целиком: сначала собирается рядом по sha из rule/manifest.json, потом rename.
_TPL_INDEX_MAX_AGE = 86400
_tpl_index_state = {'running': False, 'done': 0, 'total': 0}
_tpl_index_lock = threading.Lock()
_idx_mem = {}                  # rel → (mtime, данные) для мелких файлов индекса


def _tpl_file(url):
    return os.path.join(RULE_TPL_CACHE_DIR, hashlib.sha256(url.encode('utf-8')).hexdigest()[:20] + '.txt')


def _tpl_meta():
    try:
        with open(os.path.join(RULE_INDEX_DIR, 'meta.json'), 'r') as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _tpl_index_sync(man):
    """Скачать изменившиеся файлы индекса (sha из манифеста) и подменить набор."""
    import shutil
    want = {k[len('index/'):]: v for k, v in (man.get('files') or {}).items()
            if k.startswith('index/') and isinstance(v, dict)}
    if 'ids.json' not in want:
        raise RuntimeError('в rule/manifest.json нет индекса')
    have = _tpl_meta().get('files') or {}
    if have == {k: v.get('sha256') for k, v in want.items()}:
        return False
    stage = RULE_INDEX_DIR + '.new'
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage)

    def one(rel):
        sha = want[rel].get('sha256')
        dst = os.path.join(stage, *rel.split('/'))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        cur = os.path.join(RULE_INDEX_DIR, *rel.split('/'))
        if have.get(rel) == sha and os.path.isfile(cur):
            shutil.copyfile(cur, dst)
        else:
            data = _get_verified('index/' + rel, sha)
            with open(dst, 'wb') as f:
                f.write(data)
        with _tpl_index_lock:
            _tpl_index_state['done'] += 1

    with _tpl_index_lock:
        _tpl_index_state.update(done=0, total=len(want))
    with ThreadPoolExecutor(max_workers=6) as pool:
        for f in [pool.submit(one, rel) for rel in want]:
            f.result()
    with open(os.path.join(stage, 'meta.json'), 'w') as f:
        json.dump({'date': man.get('date') or '', 'built': int(time.time()),
                   'files': {k: v.get('sha256') for k, v in want.items()}}, f)
    old = RULE_INDEX_DIR + '.old'
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isdir(RULE_INDEX_DIR):
        os.replace(RULE_INDEX_DIR, old)
    os.replace(stage, RULE_INDEX_DIR)
    shutil.rmtree(old, ignore_errors=True)
    _idx_mem.clear()
    return True


def _tpl_cache_prune():
    """Из tpl_cache — всё, что не файл списка каталога. Раньше там лежали копии
    всех ~680 шаблонов (35 МБ) для поиска; теперь поиск идёт по готовому индексу."""
    if not os.path.isdir(RULE_TPL_CACHE_DIR):
        return
    keep = {'meta.json'}
    catalog = load_rule_lists()
    for p in RULE_PLATFORMS:
        for e in (catalog.get(p) or []):
            if e.get('url'):
                keep.add(os.path.basename(_tpl_file(e['url'])))
                rest = _tpl_rest_url(e['url'])
                if rest:
                    keep.add(os.path.basename(_tpl_file(rest)))
    for fn in os.listdir(RULE_TPL_CACHE_DIR):
        if fn not in keep and not fn.endswith('.tmp'):
            try: os.remove(os.path.join(RULE_TPL_CACHE_DIR, fn))
            except Exception: pass


def _tpl_index_kick(delay=0, manifest=None):
    """Фоном сверить индекс с api.byfox.dev. Без манифеста — только если индекса
    нет или он сверялся больше суток назад (старт панели)."""
    def run():
        if delay:
            time.sleep(delay)
        with _tpl_index_lock:
            if _tpl_index_state['running']:
                return
            _tpl_index_state['running'] = True
        try:
            man = manifest
            if man is None:
                meta = _tpl_meta()
                if meta and time.time() - (meta.get('checked') or meta.get('built') or 0) < _TPL_INDEX_MAX_AGE:
                    return
                man = _rule_manifest()
            if not _tpl_items():
                _bm7_sync_core(man)    # каталог нужен поиску так же, как индекс
            _tpl_index_sync(man)
            meta = _tpl_meta()
            if meta:
                meta['checked'] = int(time.time())
                with open(os.path.join(RULE_INDEX_DIR, 'meta.json'), 'w') as f:
                    json.dump(meta, f)
            _tpl_cache_prune()
        except Exception as e:
            print(f'[rules] индекс шаблонов: {e}', flush=True)
        finally:
            with _tpl_index_lock:
                _tpl_index_state['running'] = False
    threading.Thread(target=run, daemon=True).start()


def _tpl_index_status():
    meta = _tpl_meta()
    with _tpl_index_lock:
        st = dict(_tpl_index_state)
    return {'building': st['running'] and not meta, 'done': st['done'], 'total': st['total'],
            'ready': bool(meta), 'built': meta.get('built') or 0, 'date': meta.get('date') or ''}


def _idx_read(rel, keep=True):
    """Файл индекса (json или json.gz). keep — держать в памяти до смены mtime."""
    path = os.path.join(RULE_INDEX_DIR, *rel.split('/'))
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return None
    hit = _idx_mem.get(rel)
    if hit and hit[0] == mt:
        return hit[1]
    opener = gzip.open if rel.endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    if keep:
        _idx_mem[rel] = (mt, data)
    return data


def _tpl_index_hits(host, ips, asns):
    """{номер шаблона: [hit, …]} по индексу. hit — как у _lookup_scan."""
    out = {}

    def add(nums, hit):
        for n in nums or ():
            out.setdefault(n, []).append(hit)

    if host:
        parts = host.split('.')
        for i in range(len(parts)):
            key = '.'.join(parts[i:])
            shard = _idx_read(f'domain/{hashlib.sha1(key.encode("utf-8")).hexdigest()[:2]}.json.gz',
                              keep=False) or {}
            if i == 0:
                add((shard.get('exact') or {}).get(key), {'rule': f'DOMAIN,{key}', 'by': 'domain'})
            add((shard.get('suffix') or {}).get(key), {'rule': f'DOMAIN-SUFFIX,{key}', 'by': 'domain'})
        for kw, nums in (_idx_read('keyword.json.gz') or {}).items():
            if kw and kw in host:
                add(nums, {'rule': f'DOMAIN-KEYWORD,{kw}', 'by': 'domain'})
    if ips:
        asn_idx = _idx_read('asn.json.gz') or {}
        for ip in ips:
            a = asns.get(str(ip))
            if a and a in asn_idx:
                add(asn_idx[a], {'rule': f'IP-ASN,{a}', 'by': 'ip', 'ip': str(ip), 'no_resolve': False})
        # CIDR — самый тяжёлый файл (~11 МБ в памяти): читаем на запрос и отпускаем.
        nets = _idx_read('cidr.json.gz', keep=False) or {}
        for key, typ in (('cidr', 'IP-CIDR'), ('cidr6', 'IP-CIDR6')):
            fam = [ip for ip in ips if ip.version == (4 if key == 'cidr' else 6)]
            if not fam:
                continue
            for net_s, nums in nets.get(key) or ():
                try:
                    net = ipaddress.ip_network(net_s, strict=False)
                except ValueError:
                    continue
                ok_ip = next((ip for ip in fam if ip in net), None)
                if ok_ip is not None:
                    add(nums, {'rule': f'{typ},{net_s}', 'by': 'ip', 'ip': str(ok_ip), 'no_resolve': False})
    return out


def _tpl_lookup_templates(host, ips, asns, catalog):
    """Шаблоны, которых нет в каталоге и которые покрывают адрес."""
    try:
        ids = (_idx_read('ids.json') or {}).get('ids') or []
        hits = _tpl_index_hits(host, ips, asns)
    except Exception as e:
        print(f'[rules] поиск по индексу шаблонов: {e}', flush=True)
        return []
    by_id = {i['id']: i for i in _tpl_items()}
    base = _tpl_base()
    added = {_rule_url_for_platform(e.get('url') or '', 'clash').lower()
             for p in RULE_PLATFORMS for e in (catalog.get(p) or []) if e.get('url')}
    out = []
    for n, hs in hits.items():
        tid = ids[n] if 0 <= n < len(ids) else None
        it = by_id.get(tid)
        if not it or it.get('hidden'):
            continue
        files = it.get('files') or {}
        rel = files.get('clash') or next(iter(files.values()), '')
        url = base + rel if rel else ''
        if not url or url.lower() in added:
            continue
        out.append({'name': it.get('name') or tid, 'id': tid, 'title': it.get('title') or {},
                    'own': it.get('src') == 'byfox', 'url': url,
                    'hits': hs[:_LOOKUP_MAX_HITS], 'total': len(hs)})
    out.sort(key=lambda t: (not t['own'], t['name'].lower()))
    return out


@bp.route('/api/xray/rule-templates/find', methods=['GET'])
@_auth
def xray_rule_templates_find():
    """Какие шаблоны покрывают домен или IP — для поиска в пикере «Шаблоны».
    Только по индексу, без DNS и без файлов каталога: ответ за миллисекунды.
    → {'ids': {id шаблона: первое совпавшее правило}, 'ready': индекс есть}."""
    host, ips = _lookup_parse_query(request.args.get('q'))
    st = _tpl_index_status()
    if host is None or not st['ready']:
        if not st['ready']:
            _tpl_index_kick()
        return jsonify({'ids': {}, 'ready': st['ready']})
    asns = {}
    for ip in ips:
        g = (geo_asn_full(ip) if geo_asn_full else None) or {}
        if g.get('asn'):
            asns[ip] = str(g['asn'])
    try:
        ids = (_idx_read('ids.json') or {}).get('ids') or []
        hits = _tpl_index_hits(host, [ipaddress.ip_address(i) for i in ips], asns)
    except Exception as e:
        return jsonify({'ids': {}, 'ready': True, 'error': str(e)[:200]})
    return jsonify({'ids': {ids[n]: hs[0]['rule'] for n, hs in hits.items() if 0 <= n < len(ids)},
                    'ready': True})


@bp.route('/api/xray/rule-lookup', methods=['GET'])
@_auth
def xray_rule_lookup():
    """В какие записи каталогов 'lists' и 'global' попадает домен или IP."""
    host, ips = _lookup_parse_query(request.args.get('q'))
    if host is None:
        return jsonify({'error': 'Нужен домен или IP, например youtube.com'}), 400
    dns_error = None
    if host:
        ips, dns_error = _lookup_resolve(host)
    ips = [str(ipaddress.ip_address(ip.split('%')[0])) for ip in ips[:16]]
    ip_info, asns, ccs = [], {}, {}
    for ip in ips:
        g = (geo_asn_full(ip) if geo_asn_full else None) or {}
        ip_info.append({'ip': ip, 'cc': g.get('cc') or '', 'country': g.get('country') or '',
                        'asn': g.get('asn'), 'org': g.get('org') or ''})
        if g.get('asn'):
            asns[ip] = str(g['asn'])
        if g.get('cc'):
            ccs[ip] = str(g['cc']).upper()
    ip_objs = [ipaddress.ip_address(ip) for ip in ips]

    catalog = load_rule_lists()
    jobs = [(p, i, e) for p in RULE_PLATFORMS for i, e in enumerate(catalog.get(p) or [])]

    # Файлы каталога: свежая копия — сразу; нет или старая — докачка (одна на URL,
    # сколько бы опросов ни пришло), ждём её не дольше дедлайна. Не успела — берём
    # старую копию, а без копии запись уходит в «ещё качаются». У domain-set
    # шаблона в профиль уходит и его rest — проверяем оба файла.
    def entry_urls(e):
        if not e.get('url'):
            return []
        rest = _tpl_rest_url(e['url'])
        return [e['url'], rest] if rest else [e['url']]

    texts, waits, errors = {}, {}, {}
    for _, _, e in jobs:
        for url in entry_urls(e):
            if url in texts or url in waits:
                continue
            age = _rules_age(url)
            if age is not None and age < _RULES_FRESH:
                texts[url] = _rules_cached(url)
                continue
            waits[url] = _rules_download(url)
    if waits:
        wait(list(waits.values()), timeout=_LOOKUP_DEADLINE)
    for url, f in waits.items():
        if f.done() and f.exception() is not None:
            errors[url] = str(f.exception())[:200]
        text = _rules_cached(url)
        if text is not None:
            texts[url] = text

    out = {p: [] for p in RULE_PLATFORMS}
    pending, pending_urls = [], set()
    for p, i, e in jobs:
        base = {'id': e['id'], 'name': e.get('name') or e['id'], 'prio': i + 1,
                'policy': e.get('policy') or 'proxy'}
        if e.get('rules'):
            hits, total = _lookup_scan('\n'.join(e['rules']), True, host, ip_objs, asns, ccs)
            if hits:
                out[p].append(dict(base, hits=hits, total=total))
            continue
        urls = entry_urls(e)
        if not urls:
            continue
        if urls[0] in errors:
            out[p].append(dict(base, error=errors[urls[0]]))
            continue
        if any(texts.get(u) is None for u in urls):
            if urls[0] not in pending_urls:   # Lists и Global делят файлы — имя один раз
                pending_urls.add(urls[0])
                pending.append(dict(base, platform=p))
            continue
        hits, total = [], 0
        for u in urls:
            h, t = _lookup_scan(texts[u], False, host, ip_objs, asns, ccs)
            hits += h
            total += t
        if hits:
            out[p].append(dict(base, hits=hits[:_LOOKUP_MAX_HITS], total=total))

    # Не добавленные шаблоны — по готовому индексу api.byfox.dev.
    tpl_state = _tpl_index_status()
    if not tpl_state['ready']:
        _tpl_index_kick()
    templates = _tpl_lookup_templates(host, ip_objs, asns, catalog) if tpl_state['ready'] else []
    return jsonify({'host': host, 'ips': ip_info, 'dns_error': dns_error,
                    'lists': out.get('lists', []), 'global': out.get('global', []),
                    'pending': pending, 'checked': len(jobs),
                    'templates': templates, 'tpl_index': tpl_state})


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
