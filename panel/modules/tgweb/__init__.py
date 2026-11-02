"""Telegram WEB-прокси для awg-panel (движок telemt).

Новый тип прокси Telegram (Desktop 7.1+, iOS/Android 13.0+): кадры MTProxy едут
внутри обычного HTTPS через встроенный WebView клиента. Снаружи это запросы
браузера к нашему домену на 443 — отличить их от посещения сайта по отпечатку
TLS нельзя, в отличие от самодельного FakeTLS.

Цепочка на сервере:
    клиент ─TLS 443─▶ XRay (VLESS+TLS) ─fallback по точному path, xver 1─▶
    nginx 127.0.0.1:<nginx_port> (PROXY protocol → X-Forwarded-For, без логов) ─▶
    telemt 127.0.0.1:<web_port> ─ посторонний запрос ─▶ Flask панели (заглушка)

Пакет изолирован так же, как modules/hysteria/: хелперы панели приходят через
register(app, deps), данные живут в <panel_root>/data/tgweb/. Если пакет сломан
или отсутствует, панель поднимается без него.
"""
import json
import os
import threading

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
# Пакет лежит на ДВА уровня ниже корня панели: <panel_root>/modules/tgweb/.
# Считать корень от dirname(PKG_DIR) нельзя — данные уехали бы в modules/data/.
PANEL_ROOT = os.path.dirname(os.path.dirname(PKG_DIR))
DATA_DIR = os.path.join(PANEL_ROOT, 'data', 'tgweb')
LOGS_DIR = os.path.join(PANEL_ROOT, 'data', 'logs')
STATIC_DIR = os.path.join(PKG_DIR, 'static')

SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
CLIENTS_FILE = os.path.join(DATA_DIR, 'clients.json')
# Накопленный трафик: telemt считает его в памяти процесса, после рестарта
# счётчики начинаются с нуля — копим дельты сами, как у Hysteria и XRay.
TOTALS_FILE = os.path.join(DATA_DIR, 'totals.json')
# История IP клиентов (последний вход, гео) — у telemt её нет, только «сейчас».
SEEN_FILE = os.path.join(DATA_DIR, 'seen.json')
NGINX_BACKUP_DIR = os.path.join(DATA_DIR, 'nginx-backup')
# Имя *_access.log — чтобы logrotate панели и исключения бэкапа подхватили его
# по общей маске, как логи остальных протоколов.
ACCESS_LOG = os.path.join(LOGS_DIR, 'tgweb_access.log')

BIN_PATH = '/usr/local/bin/telemt'
CONFIG_DIR = '/etc/telemt'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.toml')
UNIT_NAME = 'telemt'
UNIT_FILE = '/etc/systemd/system/%s.service' % UNIT_NAME
GITHUB_REPO = 'telemt/telemt'

NGINX_SITE = 'awg-panel-tgweb'
NGINX_AVAILABLE = '/etc/nginx/sites-available/%s' % NGINX_SITE
NGINX_ENABLED = '/etc/nginx/sites-enabled/%s' % NGINX_SITE

# Маркер наших записей в fallbacks XRay: по нему они находятся и снимаются, не
# задевая чужие. Лишний ключ xray игнорирует (тот же приём, что _panel_mihomo).
XRAY_MARK = '_panel_tgweb'

DEFAULT_SETTINGS = {
    # Префикс пути на домене. Меняется — все выданные ссылки перестают работать.
    'slug': '',
    # Внутренние порты цепочки, только 127.0.0.1. Клиент всегда приходит на
    # 443 — к XRay или, когда XRay там нет, к нашему nginx (см. front.py).
    'nginx_port': 0,
    'web_port': 0,
    'api_port': 0,
    'api_key': '',
    # Куда telemt отдаёт посторонние запросы — Flask панели: та же заглушка /
    # 404, что и на остальном сайте, поэтому префикс снаружи ничем не выделяется.
    'decoy_upstream': 'http://127.0.0.1:5000',
    # Пусто = домен берём из сертификата XRay (тот, на котором живёт TLS на 443).
    'host': '',
    # Цепочка подключена (установка прошла). Пока False, общий фоллбек XRay
    # не трогаем ни при каких правках.
    'enabled': False,
    # Куда общий фоллбек XRay вёл до нас — туда nginx отдаёт всё, кроме префикса.
    'prev_dest': 0,
    # Кто сейчас принимает 443 для WEB: 'xray' (за фоллбеком XRay в TLS),
    # 'nginx' (XRay на 443 нет — слушаем сами) или '' (порт не наш). Решает и
    # переключает front.py по живому состоянию сервера.
    'front': '',
    # До какого времени не забирать 443 себе: панель запускает, переключает или
    # ставит XRay и уже отдала ему порт (front.before_xray_claim).
    'hold_until': 0,
    # Секрет служебного пользователя самопроверки: им панель стучится в мост
    # через 443 и убеждается, что вся цепочка отвечает. В ссылки не попадает.
    'probe_secret': '',
    # Выход telemt в Telegram через socks движка каскада (mihomo).
    'cascade': False,
    # Отпечаток частей конфига, которые telemt подхватывает только рестартом
    # (listeners, api, upstreams, user_source_deny). Остальное — файловым
    # наблюдателем без рестарта и без обнуления счётчиков.
    'restart_sig': '',
}

_FILE_LOCK = threading.Lock()

# Хелперы панели, проброшенные через register().
DEPS = {}


def audit(level, msg):
    fn = DEPS.get('audit')
    if fn:
        try:
            return fn(level, '[Telegram WEB] %s' % msg)
        except Exception:
            pass
    print('[tgweb] %s: %s' % (level, msg), flush=True)
    return None


def run_cmd(cmd, timeout=120):
    """(stdout, stderr, rc). Своя реализация: у панельной таймаут 10 с, а
    скачиванию бинаря и nginx -t этого может не хватить."""
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'timeout', 1


def _read_json(path, fallback):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return fallback


def _write_json(path, data):
    """Атомарная запись: tmp рядом + os.replace — оборванная запись не оставит
    полуфайла вместо базы клиентов."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = '%s.tmp' % path
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def load_settings():
    cfg = dict(DEFAULT_SETTINGS)
    stored = _read_json(SETTINGS_FILE, {})
    if isinstance(stored, dict):
        cfg.update(stored)
    return cfg


def save_settings(cfg):
    with _FILE_LOCK:
        _write_json(SETTINGS_FILE, cfg)


def load_clients():
    data = _read_json(CLIENTS_FILE, [])
    return data if isinstance(data, list) else []


def save_clients(clients):
    with _FILE_LOCK:
        _write_json(CLIENTS_FILE, clients)


def _scheduler():
    """Раз в минуту: собрать трафик, исполнить расписания, проверить лимиты,
    раз в сутки — ежемесячный сброс. Лимит должен срабатывать быстро, иначе
    клиент успеет выкачать сверх него.

    Каждые 15 с — сторож цепочки (service.watch): упал nginx — общий фоллбек
    XRay возвращается напрямую, чтобы вместе с WEB-прокси не легли сайт и вход
    в панель на 443; вернулся nginx или фоллбек размыло переключением режима
    443 — подключаем обратно."""
    import time as _time
    last_day = ''
    tick = 0
    while True:
        try:
            from . import clients as cl
            from . import service, stats
            if service.bin_installed() and load_settings().get('enabled'):
                service.watch()
                if tick % 4 == 0:
                    stats.collect(force=True)
                    changed = cl.run_schedules()
                    changed = stats.enforce_limits() or changed
                    today = _time.strftime('%Y-%m-%d')
                    if today != last_day:
                        last_day = today
                        changed = stats.monthly_reset() or changed
                    if changed:
                        service.apply_clients()
        except Exception as e:
            print('[tgweb] scheduler: %s' % e, flush=True)
        tick += 1
        _time.sleep(15)


def _boot_heal():
    """Разовая починка того, что живёт вне папки панели и zip-обновление не
    трогает: наши fallbacks в XRay (их перезаписывает переключение режима 443 и
    переустановка XRay), блок nginx, юнит. В фоне и с задержкой — чтобы не
    держать подъём панели."""
    import time as _time
    _time.sleep(8)
    try:
        from . import service
        service.heal()
    except Exception as e:
        print('[tgweb] boot-heal: %s' % e, flush=True)


def register(app, deps=None):
    """Точка входа: app.py зовёт её после создания Flask-приложения."""
    DEPS.update(deps or {})
    os.makedirs(DATA_DIR, exist_ok=True)
    from . import routes
    routes.register(app)
    threading.Thread(target=_scheduler, daemon=True).start()
    threading.Thread(target=_boot_heal, daemon=True).start()
    return True
