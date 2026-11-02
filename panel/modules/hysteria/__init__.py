"""Протокол Hysteria 2 для awg-panel.

Изолированный пакет внутри modules/: весь код Hysteria живёт здесь, все
пользовательские данные — в <panel_root>/data/hysteria/. Панель подключает его
пятью защищёнными строками в app.py; если пакет отсутствует или сломан, панель
поднимается без Hysteria.

Хелперы панели (audit, run_cmd, login_required) приходят через register(app, deps),
а не импортом из app.py — иначе получился бы цикл: app.py импортирует нас.
"""
import json
import os
import threading

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
# Пакет лежит на ДВА уровня ниже корня панели: <panel_root>/modules/hysteria/.
# Считать корень от dirname(PKG_DIR) нельзя — данные уехали бы в modules/data/
# и панель молча завела бы вторую, пустую базу клиентов.
PANEL_ROOT = os.path.dirname(os.path.dirname(PKG_DIR))
DATA_DIR = os.path.join(PANEL_ROOT, 'data', 'hysteria')
LOGS_DIR = os.path.join(PANEL_ROOT, 'data', 'logs')
STATIC_DIR = os.path.join(PKG_DIR, 'static')

SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
CLIENTS_FILE = os.path.join(DATA_DIR, 'clients.json')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.yaml')
CERT_FILE = os.path.join(DATA_DIR, 'cert.pem')
KEY_FILE = os.path.join(DATA_DIR, 'key.pem')
TOTALS_FILE = os.path.join(DATA_DIR, 'totals.json')
# Последний IP и время входа пишет auth.py при каждом подключении — отдельным
# файлом, чтобы не трогать clients.json на каждый коннект.
LASTSEEN_FILE = os.path.join(DATA_DIR, 'lastseen.json')
AUTH_SCRIPT = os.path.join(PKG_DIR, 'auth.py')
ACCESS_LOG = os.path.join(LOGS_DIR, 'hysteria_access.log')
# Глобальные серверные правила: pending/applied + сгенерированный из них acl.
GLOBAL_FILE = os.path.join(DATA_DIR, 'global.json')
ACL_FILE = os.path.join(DATA_DIR, 'acl.txt')

BIN_PATH = '/usr/local/bin/hysteria'
UNIT_NAME = 'hysteria-server'
UNIT_FILE = '/etc/systemd/system/%s.service' % UNIT_NAME
GITHUB_REPO = 'HyNetworks/hysteria'

# Статистика сервера слушает только на localhost — наружу её отдавать незачем.
STATS_ADDR = '127.0.0.1:29513'

DEFAULT_SETTINGS = {
    'port': 443,                 # UDP; XRay сидит на TCP/443 и не конфликтует
    'obfs_password': '',         # salamander; пусто = обфускация выключена
    # Пусто = режим «голый 404»: hysteria отвечает посторонним 404 вместо того,
    # чтобы проксировать чужой сайт. Одно поле вместо двух — в config.yaml это
    # тоже одно решение (masquerade.type), а в UI выбор рисуется селектом.
    'masquerade_url': 'https://www.bing.com',
    'up_mbps': 0,                # 0 = не ограничивать
    'down_mbps': 0,
    'sni': '',                   # для клиентской ссылки; пусто = берём адрес сервера
    'stats_secret': '',          # токен Traffic Stats API, генерируется при установке
    'cascade': False,            # весь выход через socks движка ВПН2 (mihomo)
    'access_log': False,         # журнал назначений: hysteria пишет их только в debug
}

_FILE_LOCK = threading.Lock()

# Хелперы панели, проброшенные через register(). Обращаться только через audit()/run_cmd().
DEPS = {}


def audit(level, msg):
    fn = DEPS.get('audit')
    if fn:
        try:
            return fn(level, '[Hysteria] %s' % msg)
        except Exception:
            pass
    print('[hysteria] %s: %s' % (level, msg), flush=True)
    return None


def run_cmd(cmd):
    """(stdout, stderr, rc). Своя реализация, а не панельная: у той таймаут 10 с,
    а установке бинаря и systemctl restart этого может не хватить."""
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'timeout', 1


def _read_json(path, fallback):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception:
        return fallback


def _write_json(path, data):
    """Атомарная запись: tmp рядом + os.replace. Оборванная запись не оставит
    полуфайла — иначе потеря clients.json означала бы потерю всех клиентов."""
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


def _run_schedules(cl):
    """Исполняет отложенные действия клиентов (отключить / удалить)."""
    import time as _time
    today = _time.strftime('%Y-%m-%d')
    for c in list(cl.list_clients()):
        action = c.get('scheduled_action')
        at = cl.schedule_date(c.get('scheduled_at'))
        if not action or not at or at > today:
            continue
        cid = c.get('id')
        if action == 'delete':
            cl.delete(cid)
        elif action == 'disable':
            cl.set_disabled(cid, True)
            cl.set_schedule(cid, None, 0)


def _scheduler():
    """Фоновая проверка лимитов и месячного сброса.

    Раз в минуту: собрать трафик, отключить превысивших, включить тех, кому
    лимит сбросили. Раз в сутки хватило бы для сброса, но лимит должен срабатывать
    быстро — иначе клиент успеет выкачать сверх него.
    """
    import time as _time
    last_day = ''
    first = True
    while True:
        try:
            from . import clients as _cl
            from . import rules, service, stats
            _run_schedules(_cl)
            # +x у auth.py слетает при любом накате файлов (zip-апдейт, scp):
            # проверка — один os.access, чиним без рестарта и без участия юзера.
            service.heal_auth_exec()
            if service.is_active():
                stats.enforce_limits()
                today = _time.strftime('%Y-%m-%d')
                if today != last_day:
                    # На первом круге после старта панели правила не пересобираем:
                    # это перезапуск сервиса, и он оборвал бы сессии клиентов
                    # каждый раз, когда панель обновляется или падает.
                    if not first:
                        rules.refresh_applied()
                    last_day = today
                    first = False
                    stats.monthly_reset()
        except Exception as e:
            print('[hysteria] scheduler: %s' % e, flush=True)
        _time.sleep(60)


def _boot_heal():
    """Разовая починка на старте всего, что накат zip портит или не обновляет:
    бит +x у auth.py, deploy-hook certbot прошлой версии, путь auth.py в уже
    лежащем config.yaml.

    В фоне и с задержкой: heal_auth_path() может перезапустить сервис, а делать
    это синхронно в импорте app.py значит задержать подъём панели на секунды и
    повторить его в каждом воркере gunicorn.
    """
    import time as _time
    _time.sleep(6)
    try:
        from . import service
        service.heal_auth_exec()
        service.heal_renew_hook()
        service.heal_auth_path()
    except Exception as e:
        print('[hysteria] проверка пути auth.py не удалась: %s' % e, flush=True)
    try:
        from . import clients
        clients.heal_schedules()
    except Exception as e:
        print('[hysteria] починка расписаний не удалась: %s' % e, flush=True)


def register(app, deps=None):
    """Точка входа: app.py зовёт её после создания Flask-приложения."""
    DEPS.update(deps or {})
    os.makedirs(DATA_DIR, exist_ok=True)
    from . import routes
    routes.register(app)
    threading.Thread(target=_scheduler, daemon=True).start()
    threading.Thread(target=_boot_heal, daemon=True).start()
    return True
