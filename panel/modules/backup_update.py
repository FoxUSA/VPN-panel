"""Бэкапы панели и обновление кода: архивы, расписание, restore, накат awg-panel.zip.

Вынесено из app.py. Домен закрытый: снаружи его дёргали ровно дважды, и оба вызова
остались в app.py осознанно — `_local_manifest` читает версию из manifest.json ещё
на старте, до подключения модулей, поэтому живёт в ядре и приезжает сюда как
зависимость.

Зависимости раскладываются в одноимённые модульные переменные (тот же приём, что в
mihomo.py), поэтому тела функций перенесены без правок. Пути, растущие из PANEL_ROOT
и BACKUP_DIR, строятся ВНУТРИ init(): на импорте они ещё пусты, и os.path.join дал бы
относительный путь — на этом уже обожглись с профилями mihomo.

Фоновый цикл автообновления и синхронизация systemd-таймера стартуют только из
start_background().
"""

import io
import json
import os
import re
import shutil
import subprocess
import threading
import time
import zipfile

from flask import Blueprint, jsonify, request, send_file, send_from_directory

bp = Blueprint('backup_update', __name__)

# Зависимости из app.py — имена те же, что там.
audit = None
run_cmd = None
_save_server_config = None
_fmt_bytes = None
_restart_panel_soon = None
_vtuple = None
_http_get_text = None
_http_get_bytes = None
_local_manifest = None
_bm7_sync_once = None
_bm7_local_version = None
_bm7_date_tuple = None
_fetch_remote_bm7_date = None
_byfox_rules_sync_once = None
_fetch_remote_geo_version = None
_read_local_geo_version = None
_geo_newer = None
_do_geo_update = None
_do_geo_update_response = None
_find_awg_paths = None
_find_xray_paths = None
_find_mtg_paths = None
login_required = None
SERVER_CFG = {}
SERVER_CONFIG_FILE = ''
SECRET_KEY_FILE = ''
BACKUP_DIR = ''
UPDATE_BASE_URL = ''
UPDATE_ZIP_URL = ''
PANEL_ROOT = ''
PANEL_VERSION = ''
PANEL_RELEASED = ''

# Корень, который уходит в tar. Пустой до init() — строится там же, где остальные пути.
BACKUP_PANEL_ROOT = ''

REQUIRED_DEPS = [
    'audit',
    'run_cmd',
    '_save_server_config',
    '_fmt_bytes',
    '_restart_panel_soon',
    '_vtuple',
    '_http_get_text',
    '_http_get_bytes',
    '_local_manifest',
    '_bm7_sync_once',
    '_bm7_local_version',
    '_bm7_date_tuple',
    '_fetch_remote_bm7_date',
    '_byfox_rules_sync_once',
    '_fetch_remote_geo_version',
    '_read_local_geo_version',
    '_geo_newer',
    '_do_geo_update',
    '_do_geo_update_response',
    '_find_awg_paths',
    '_find_xray_paths',
    '_find_mtg_paths',
    'SERVER_CFG',
    'SERVER_CONFIG_FILE',
    'SECRET_KEY_FILE',
    'BACKUP_DIR',
    'UPDATE_BASE_URL',
    'UPDATE_ZIP_URL',
    'PANEL_ROOT',
    'PANEL_VERSION',
    'PANEL_RELEASED',
    'login_required',
]

_started = False


def init(deps):
    """Принять зависимости из app.py (см. REQUIRED_DEPS) в одноимённые глобалы."""
    missing = [k for k in REQUIRED_DEPS if k not in (deps or {})]
    if missing:
        raise RuntimeError('backup_update.init: не переданы зависимости: ' + ', '.join(missing))
    globals().update(deps)
    if not PANEL_ROOT or not BACKUP_DIR:
        raise RuntimeError('backup_update.init: пустой PANEL_ROOT/BACKUP_DIR — пути не построить')
    global BACKUP_PANEL_ROOT
    BACKUP_PANEL_ROOT = PANEL_ROOT


def start_background():
    """Автообновление и синхронизация systemd-таймера бэкапов."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_auto_update_loop, daemon=True).start()
    try:
        _backup_timer_resync_secret_path()
        cfg = _backup_cfg()
        if cfg.get('schedule_enabled'):
            _backup_systemd_write(cfg)
    except Exception as e:
        if audit:
            audit('warn', f'backup: стартовая синхронизация таймера не удалась: {e}')


def _auth(fn):
    """Прокси вместо login_required: он приезжает в init(), а роуты объявлены раньше."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not login_required:
            return jsonify({'error': 'module not initialized'}), 503
        return login_required(fn)(*a, **kw)
    return wrapper


def _fetch_manifest():
    """Returns dict or None on error."""
    try:
        text = _http_get_text(UPDATE_BASE_URL.rstrip('/') + '/manifest.json')
        return json.loads(text)
    except Exception as e:
        audit('warn', f'Manifest fetch failed: {e}')
        return None

@bp.route('/api/update/check')
@_auth
def update_check():
    """Богатый статус для раздела «Сервер и обновления»: для панели/гео/blackmatrix7 —
    текущая и удалённая версия, доступность, дата последней проверки, период и свитч
    авто-обновления (всё, кроме удалённых версий, берётся из server.json).
    «Доступно» = remote строго новее local; период/свитч управляют только авто-режимом,
    кнопкой обновить можно всегда.
    ?touch=1 — ручная проверка всего, ?touch=panel|geo|bm7 — одного блока: штампуем
    last_check (пассивная проверка при загрузке панели дату не трогает)."""
    # Панель
    m = _fetch_manifest() or {}
    remote_v = str(m.get('version') or '')
    panel_avail = bool(remote_v) and _vtuple(remote_v) > _vtuple(PANEL_VERSION)
    # Гео
    remote_geo = _fetch_remote_geo_version()
    local_geo = _read_local_geo_version()
    def _geo_int(s):
        try: return int(s)
        except Exception: return 0
    geo_avail = bool(remote_geo) and _geo_int(remote_geo) > _geo_int(local_geo)
    # blackmatrix7
    remote_bm7 = _fetch_remote_bm7_date()
    local_bm7 = _bm7_local_version()
    bm7_avail = bool(remote_bm7) and _bm7_date_tuple(remote_bm7) > _bm7_date_tuple(local_bm7)
    # Дата проверки — только если сервер обновлений ответил: иначе карточка говорила
    # бы «проверено только что», хотя узнать ничего не удалось.
    touch = request.args.get('touch') or ''
    if touch:
        now = int(time.time())
        for kind, remote in (('panel', remote_v), ('geo', remote_geo), ('bm7', remote_bm7)):
            if remote and touch in ('1', kind):
                SERVER_CFG[kind + '_last_check'] = now
        _save_server_config(SERVER_CFG)
        audit('info', 'Ручная проверка обновлений')

    def _i(key, default):
        try: return max(1, int(SERVER_CFG.get(key) or default))
        except Exception: return default
    panel = {
        'current': PANEL_VERSION, 'remote': remote_v, 'released': str(m.get('released') or PANEL_RELEASED),
        'update_available': panel_avail,
        'last_check': int(SERVER_CFG.get('panel_last_check') or 0),
        'interval_days': _i('panel_check_interval_days', 1),
        'auto': bool(SERVER_CFG.get('panel_auto_update', True)),
    }
    geo = {
        'local': local_geo, 'remote': remote_geo, 'update_available': geo_avail,
        'last_check': int(SERVER_CFG.get('geo_last_check') or 0),
        'interval_days': _i('geo_check_interval_days', 180),
        'auto': bool(SERVER_CFG.get('geo_auto_update', True)),
    }
    bm7 = {
        'local': local_bm7, 'remote': remote_bm7, 'update_available': bm7_avail,
        'last_check': int(SERVER_CFG.get('bm7_last_check') or 0),
        'interval_days': _i('bm7_check_interval_days', 7),
        'auto': bool(SERVER_CFG.get('bm7_auto_update', True)),
    }
    return jsonify({
        'panel': panel, 'geo': geo, 'bm7': bm7,
        'any_update': panel_avail or geo_avail or bm7_avail,
    })

# Что апдейт не трогает в корне панели:
#   data/   — рантайм-данные (гео/логи/бэкапы/конфиги клиентов);
#   public/ — фейк-лендинг пользователя (в архиве лежит только демо-заглушка,
#             заменять ею настроенную маскировку нельзя);
#   venv/   — питоновское окружение, в архиве его нет, но подстрахуемся.
_UPDATE_SKIP_TOP = {'data', 'public', 'venv'}

def _fetch_panel_zip_staging():
    """Скачать awg-panel.zip и распаковать в staging рядом с панелью (одна ФС →
    rename при накате атомарен). Живые файлы не трогаются вообще.
    Возвращает (staging, src_root, version); при любой ошибке бросает исключение —
    вызывающий решает, что делать (restore на этом месте обрывается ДО tar)."""
    staging = os.path.join(PANEL_ROOT, '.update_staging')
    raw = _http_get_bytes(UPDATE_ZIP_URL, timeout=180)
    if os.path.exists(staging):
        shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            zf.extractall(staging)
        # внутренний корень архива (обычно <staging>/awg-panel/)
        entries = os.listdir(staging)
        src_root = (os.path.join(staging, entries[0])
                    if len(entries) == 1 and os.path.isdir(os.path.join(staging, entries[0]))
                    else staging)
        if not os.path.isfile(os.path.join(src_root, 'app.py')):
            raise RuntimeError('в архиве нет app.py — отмена')
        # Битый .py (обрезанный при заливке на CDN, ошибка синтаксиса) после
        # наката = панель не поднимается, и починить её из браузера уже нельзя.
        # Компилируем всё ДО замены живых файлов; в память, без __pycache__.
        for dp, _dn, fns in os.walk(src_root):
            for fn in fns:
                if fn.endswith('.py'):
                    fp = os.path.join(dp, fn)
                    try:
                        with open(fp, 'rb') as f:
                            compile(f.read(), fp, 'exec')
                    except SyntaxError as e:
                        raise RuntimeError('в архиве битый %s (строка %s): %s — отмена, панель не тронута'
                                           % (os.path.relpath(fp, src_root), e.lineno, e.msg))
        remote_v = ''
        try:
            with open(os.path.join(src_root, 'manifest.json'), encoding='utf-8') as f:
                remote_v = (json.load(f) or {}).get('version') or ''
        except Exception:
            pass
        return staging, src_root, remote_v
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

def _apply_panel_staging(staging, src_root):
    """Разложить распакованный архив поверх панели:
      1) папки целиком заменяем (static/, modules/ и любые другие, кроме _UPDATE_SKIP_TOP)
         — atomic rename + .bak;
      2) файлы из корня архива копируем в корень панели с заменой (app.py, manifest.json,
         readme*, install_interactive.html, .gitignore, fox.ico — ВСЁ что есть в архиве);
      3) data/ и public/ не трогаем — там живёт пользовательское.
    Список файлов из manifest.files НЕ используется — берём ровно то, что в архиве,
    поэтому новые файлы (i18n.js, новые модули) подхватываются сами.
    Откат из .bak при любой ошибке, исключение уходит наружу.
    staging чистится в любом случае. Перезапуск сервиса — снаружи (вызывающим)."""
    panel_root = PANEL_ROOT
    moved_dirs = []    # (target, bak) — переименованные папки (для отката/чистки)
    file_baks = []     # (target, bak) — забэкапленные файлы
    try:
        for name in os.listdir(src_root):
            if name in _UPDATE_SKIP_TOP:
                continue
            sp = os.path.join(src_root, name)
            tp = os.path.join(panel_root, name)
            if os.path.isdir(sp):
                bak = tp + '.bak'
                if os.path.exists(bak):
                    shutil.rmtree(bak, ignore_errors=True)
                if os.path.exists(tp):
                    os.rename(tp, bak)
                    moved_dirs.append((tp, bak))
                os.rename(sp, tp)          # staging и panel_root на одной ФС → атомарно
                audit('info', f'Папка {name}/ заменена')
            else:
                if os.path.exists(tp):
                    bak = tp + '.bak'
                    shutil.copy2(tp, bak)
                    file_baks.append((tp, bak))
                shutil.copy2(sp, tp)

        # Модули переехали в modules/ (2026-09-21). На серверах со старой раскладкой
        # копии .py остаются лежать в корне: импортируются они уже из modules/, но
        # при отладке сбивают с толку — правишь один файл, работает другой. Сносим
        # ровно те корневые файлы, для которых в modules/ есть одноимённый.
        try:
            mod_dir = os.path.join(panel_root, 'modules')
            if os.path.isdir(mod_dir):
                for name in os.listdir(mod_dir):
                    if not name.endswith('.py') or name == '__init__.py':
                        continue
                    legacy = os.path.join(panel_root, name)
                    if os.path.isfile(legacy):
                        os.remove(legacy)
                        audit('info', f'Update: убран устаревший {name} из корня — модуль живёт в modules/')
        except Exception as _e:
            audit('warn', f'Update: не удалось убрать старые модули из корня: {_e}')

        # Пакет Hysteria переехал из корня в modules/ (2026-09-22). Старый
        # каталог панель больше не импортирует, но он остаётся лежать и сбивает
        # с толку при отладке: правишь hysteria/service.py, а работает
        # modules/hysteria/service.py. Сносим только когда новый на месте —
        # иначе неполный накат унёс бы протокол целиком.
        try:
            legacy_pkg = os.path.join(panel_root, 'hysteria')
            if os.path.isdir(os.path.join(panel_root, 'modules', 'hysteria'))                     and os.path.isdir(legacy_pkg):
                shutil.rmtree(legacy_pkg, ignore_errors=True)
                audit('info', 'Update: убран устаревший hysteria/ из корня — пакет живёт в modules/')
        except Exception as _e:
            audit('warn', f'Update: не удалось убрать старый hysteria/ из корня: {_e}')

        # успех — чистим staging и бэкапы
        shutil.rmtree(staging, ignore_errors=True)
        for _, bak in moved_dirs:
            shutil.rmtree(bak, ignore_errors=True)
        for _, bak in file_baks:
            try: os.remove(bak)
            except Exception: pass
    except Exception:
        for tp, bak in moved_dirs:        # вернуть папки
            try:
                if os.path.exists(tp):
                    shutil.rmtree(tp, ignore_errors=True)
                os.rename(bak, tp)
            except Exception:
                pass
        for tp, bak in file_baks:         # вернуть файлы
            try:
                shutil.copy2(bak, tp); os.remove(bak)
            except Exception:
                pass
        shutil.rmtree(staging, ignore_errors=True)
        raise

def _do_panel_update():
    """Полный накат awg-panel.zip: скачать → разложить. Возвращает (ok, version|error)."""
    try:
        staging, src_root, remote_v = _fetch_panel_zip_staging()
    except Exception as e:
        audit('error', f'Update failed: {e}')
        return False, str(e)
    audit('info', f'Update: накат awg-panel.zip (v{remote_v})')
    try:
        _apply_panel_staging(staging, src_root)
    except Exception as e:
        audit('error', f'Update failed: {e} — откат')
        return False, str(e)
    audit('info', f'Update: накат завершён, версия {remote_v}')
    return True, remote_v

_UPDATE_LOCK = threading.Lock()

_UPDATE_RUNNING = {'flag': False}

@bp.route('/api/update/apply-panel', methods=['POST'])
@_auth
def update_apply_panel():
    if not _UPDATE_LOCK.acquire(blocking=False):
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    if _UPDATE_RUNNING['flag']:
        _UPDATE_LOCK.release()
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    _UPDATE_RUNNING['flag'] = True
    try:
        SERVER_CFG['panel_last_check'] = int(time.time()); _save_server_config(SERVER_CFG)
        ok, info = _do_panel_update()
        if not ok:
            _UPDATE_RUNNING['flag'] = False   # рестарта не будет — снимаем флаг
            return jsonify({'ok': False, 'error': info}), 500
        audit('info', 'Restart after update')
        _restart_panel_soon()
        return jsonify({'ok': True, 'new_version': info})
    finally:
        # Keep flag=True until restart kicks; lock is released so a follow-up
        # poll doesn't deadlock if restart fails.
        _UPDATE_LOCK.release()

@bp.route('/api/update/apply-geo', methods=['POST'])
@_auth
def update_apply_geo():
    if not _UPDATE_LOCK.acquire(blocking=False):
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    if _UPDATE_RUNNING['flag']:
        _UPDATE_LOCK.release()
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    _UPDATE_RUNNING['flag'] = True
    try:
        res = _do_geo_update_response()
        # Успех → single jsonify (рестарт запланирован, флаг держим до перезапуска).
        # Ошибка → (jsonify, code) tuple, рестарта не будет → снимаем флаг.
        if isinstance(res, tuple):
            _UPDATE_RUNNING['flag'] = False
        return res
    finally:
        _UPDATE_LOCK.release()

@bp.route('/api/update/apply-bm7', methods=['POST'])
@_auth
def update_apply_bm7():
    """Принудительное обновление библиотеки шаблонов blackmatrix7 (без рестарта —
    шаблоны читаются по запросу)."""
    if not _UPDATE_LOCK.acquire(blocking=False):
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    try:
        SERVER_CFG['bm7_last_check'] = int(time.time()); _save_server_config(SERVER_CFG)
        try:
            summary = _bm7_sync_once()
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
        return jsonify({'ok': True, 'new_version': _bm7_local_version(),
                        'message': _bm7_summary_text(summary) if isinstance(summary, dict) else ''})
    finally:
        _UPDATE_LOCK.release()


def _bm7_summary_text(s):
    """Итог «Обновить шаблоны» одной фразой; имена новых — если их немного."""
    total = 'Всего %d blackmatrix7 и %d своих.' % (s['bm7'], s['own'])
    if not s['added'] and not s['removed']:
        return 'Шаблоны проверены, изменений нет. ' + total
    names = ''
    if s['added']:
        names = ' (%s%s)' % (', '.join(s['added'][:5]), ', …' if len(s['added']) > 5 else '')
    return 'Шаблоны обновлены: новых %d%s, убрано %d. %s' % (len(s['added']), names, len(s['removed']), total)

@bp.route('/api/update/apply-all', methods=['POST'])
@_auth
def update_apply_all():
    """Одной кнопкой: применяет ВСЁ свежее (blackmatrix7 + гео + панель). Доступность
    перепроверяется на сервере. Рестарт делается ОДИН раз в конце (его требуют и гео,
    и панель). last_check всем трём штампуется (это и есть проверка)."""
    if not _UPDATE_LOCK.acquire(blocking=False):
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    if _UPDATE_RUNNING['flag']:
        _UPDATE_LOCK.release()
        return jsonify({'ok': False, 'error': 'Обновление уже выполняется'}), 409
    _UPDATE_RUNNING['flag'] = True
    try:
        now = int(time.time())
        done, need_restart = [], False
        # 1) blackmatrix7 (без рестарта) + свои шаблоны (byfox)
        try:
            remote_bm7 = _fetch_remote_bm7_date()
            if remote_bm7 and _bm7_date_tuple(remote_bm7) > _bm7_date_tuple(_bm7_local_version()):
                _bm7_sync_once(); done.append('шаблоны blackmatrix7')
            else:
                _byfox_rules_sync_once()   # bm7 не свежее — свои шаблоны всё равно тянем
        except Exception as e:
            audit('warn', f'apply-all bm7: {e}')
        SERVER_CFG['bm7_last_check'] = now
        # 2) гео (рестарт нужен — отложим в конец)
        try:
            remote_geo = _fetch_remote_geo_version()
            if _geo_newer(remote_geo, _read_local_geo_version()):
                ok, err = _do_geo_update(remote_geo)
                if ok: done.append('гео-базы'); need_restart = True
                else: audit('warn', f'apply-all гео: {err}')
        except Exception as e:
            audit('warn', f'apply-all гео: {e}')
        SERVER_CFG['geo_last_check'] = now
        # 3) панель (рестарт нужен — отложим в конец)
        try:
            m = _fetch_manifest() or {}
            remote_v = str(m.get('version') or '')
            if remote_v and _vtuple(remote_v) > _vtuple(PANEL_VERSION):
                ok, info = _do_panel_update()
                if ok: done.append('панель'); need_restart = True
                else: audit('warn', f'apply-all панель: {info}')
        except Exception as e:
            audit('warn', f'apply-all панель: {e}')
        SERVER_CFG['panel_last_check'] = now
        _save_server_config(SERVER_CFG)

        if need_restart:
            audit('info', f'Обновлено: {", ".join(done)} — перезапуск')
            _restart_panel_soon()   # один рестарт на гео+панель
            return jsonify({'ok': True, 'restart': True, 'done': done})
        _UPDATE_RUNNING['flag'] = False   # рестарта нет
        if done:
            audit('info', f'Обновлено: {", ".join(done)}')
        return jsonify({'ok': True, 'restart': False, 'done': done})
    finally:
        _UPDATE_LOCK.release()

def _auto_due(last_key, interval_key, default_days, now):
    try:
        interval = max(1, int(SERVER_CFG.get(interval_key) or default_days)) * 86400
    except Exception:
        interval = default_days * 86400
    return (now - float(SERVER_CFG.get(last_key) or 0)) >= interval

def _auto_check_panel(now):
    SERVER_CFG['panel_last_check'] = int(now); _save_server_config(SERVER_CFG)
    m = _fetch_manifest() or {}
    remote_v = str(m.get('version') or '')
    if not (remote_v and _vtuple(remote_v) > _vtuple(PANEL_VERSION)):
        return
    if not _UPDATE_LOCK.acquire(blocking=False):
        return
    try:
        _UPDATE_RUNNING['flag'] = True
        audit('info', f'Авто-обновление панели: {PANEL_VERSION} → {remote_v}')
        ok, info = _do_panel_update()
        if ok:
            audit('info', f'Авто-обновление: панель обновлена до {info}, перезапуск')
            _restart_panel_soon()
        else:
            audit('error', f'Авто-обновление панели не удалось: {info}')
            _UPDATE_RUNNING['flag'] = False
    finally:
        _UPDATE_LOCK.release()

def _auto_check_geo(now):
    SERVER_CFG['geo_last_check'] = int(now); _save_server_config(SERVER_CFG)
    remote = _fetch_remote_geo_version()
    local = _read_local_geo_version()
    if not _geo_newer(remote, local):
        return
    if not _UPDATE_LOCK.acquire(blocking=False):
        return
    try:
        _UPDATE_RUNNING['flag'] = True
        audit('info', f'Авто-обновление гео: {local or "—"} → {remote}')
        ok, err = _do_geo_update(remote)
        if ok:
            audit('info', f'Авто-обновление: гео обновлена до {remote}, перезапуск')
            _restart_panel_soon()
        else:
            audit('error', f'Авто-обновление гео не удалось: {err}')
            _UPDATE_RUNNING['flag'] = False
    finally:
        _UPDATE_LOCK.release()

def _auto_check_bm7(now):
    SERVER_CFG['bm7_last_check'] = int(now); _save_server_config(SERVER_CFG)
    if not _UPDATE_LOCK.acquire(blocking=False):
        return
    try:
        _bm7_sync_once()   # сам сравнивает даты и обновляет только если свежее
    except Exception as e:
        try: audit('warn', f'Авто-обновление blackmatrix7: {e}')
        except Exception: pass
    finally:
        _UPDATE_LOCK.release()

def _auto_update_loop():
    time.sleep(20)   # дать панели подняться после старта
    while True:
        try:
            now = time.time()
            if SERVER_CFG.get('panel_auto_update', True) and _auto_due('panel_last_check', 'panel_check_interval_days', 1, now):
                _auto_check_panel(now)
            if SERVER_CFG.get('geo_auto_update', True) and _auto_due('geo_last_check', 'geo_check_interval_days', 180, now):
                _auto_check_geo(now)
            if SERVER_CFG.get('bm7_auto_update', True) and _auto_due('bm7_last_check', 'bm7_check_interval_days', 7, now):
                _auto_check_bm7(now)
        except Exception as e:
            try: audit('warn', f'Авто-обновление: ошибка цикла: {e}')
            except Exception: pass
        time.sleep(3600)   # тик раз в час; реальную проверку гейтят интервалы выше

BACKUP_TAR_EXCLUDES = [
    'venv',
    '__pycache__',
    '.update_staging',          # распакованный архив апдейта — живёт секунды, в бэкапе не нужен
    '*.bak',                    # .bak от наката (папки/файлы) — транзитные копии
    'data/backup',              # сами архивы
    # Логи доступа (гигабайты, ротируются отдельно) в архив не берём, а вот журнал
    # действий data/logs/audit.log — берём: он весит максимум мегабайт, а при
    # восстановлении сервера история «кто что менял» ценнее прочих логов.
    '*_access.log',
    'data/countries',           # кеш CIDR — пересобирается из countries_src
    'data/countries_src',       # сырые гео-исходники — качаются заново
    'data/geo_rules/countries',      # то же после переезда гео (фаза 5)
    'data/geo_rules/countries_src',
    '*.mmdb',                   # базы MaxMind (десятки МБ) — качаются заново
]

def _backup_external_files():
    """Список внешних конфигов сервисов, которые попадают в бэкап.
    Тянется из тех же _find_*_paths(), что и «Системные пути»/«Источники правды»,
    — единый источник правды. На сервере без какого-то протокола соответствующий
    файл не добавляется (пропуск отсутствующих случается всё равно в _backup_make)."""
    files = []
    try:
        awg = _find_awg_paths()
        if awg.get('config'):
            files.append(awg['config'])
    except Exception:
        pass
    try:
        xray = _find_xray_paths()
        if xray.get('config'):
            files.append(xray['config'])
    except Exception:
        pass
    try:
        mtg = _find_mtg_paths()
        if mtg.get('config'):
            files.append(mtg['config'])
        # mtg drop-in (StandardOutput=append:<path>) тоже бэкапим — на нём держится access-log
        if mtg.get('drop_in'):
            files.append(mtg['drop_in'])
    except Exception:
        pass
    # Юнит Hysteria: конфиг и клиенты лежат в data/ и едут в архив вместе с
    # панелью, а вот сам сервис описан снаружи. Без юнита восстановленная копия
    # поднимает всё, кроме Hysteria, и причина неочевидна: файлы на месте,
    # systemd о протоколе не знает. Бинарь не берём — он качается с GitHub.
    hy_unit = '/etc/systemd/system/hysteria-server.service'
    if os.path.exists(hy_unit):
        files.append(hy_unit)
    # Telegram WEB: юнит, конфиг telemt и наш блок nginx живут снаружи панели.
    # Клиенты и настройки — в data/tgweb и едут с архивом; config.toml панель
    # пересоберёт из них сама, но с ним восстановленная копия поднимается сразу.
    for tg_file in ('/etc/systemd/system/telemt.service', '/etc/telemt/config.toml',
                    '/etc/nginx/sites-available/awg-panel-tgweb',
                    '/etc/nginx/conf.d/awg-panel-tgweb.conf'):
        if os.path.exists(tg_file):
            files.append(tg_file)
    # Logrotate-конфиг панели — стандартное расположение
    lr = '/etc/logrotate.d/awg-panel'
    if os.path.exists(lr):
        files.append(lr)
    # Юнит самой панели: без него восстановленная копия не запустится как сервис.
    # Раньше страховкой служила копия awg-panel.service в корне панели — теперь
    # в архив едет оригинал, а копию в корне держать незачем.
    panel_unit = '/etc/systemd/system/awg-panel.service'
    if os.path.exists(panel_unit):
        files.append(panel_unit)
    return files

BACKUP_TIMER_SERVICE = '/etc/systemd/system/awg-panel-backup.service'

BACKUP_TIMER_UNIT = '/etc/systemd/system/awg-panel-backup.timer'

BACKUP_TIMER_NAME = 'awg-panel-backup.timer'

BACKUP_FILENAME_RE = re.compile(r'^awg-panel-\d{8}-\d{6}\.tar\.gz$')

DEFAULT_BACKUP_CFG = {
    'schedule_enabled': False,
    'interval_value': 1,
    'interval_unit': 'days',     # 'hours' | 'days'
    'retention_mode': 'count',   # 'count' | 'size'
    'retention_count': 10,
    'retention_size_mb': 100,
}

def _backup_cfg():
    cfg = SERVER_CFG.get('backup') or {}
    out = dict(DEFAULT_BACKUP_CFG)
    out.update({k: v for k, v in cfg.items() if k in DEFAULT_BACKUP_CFG})
    return out

def _save_backup_cfg(new_cfg):
    SERVER_CFG['backup'] = new_cfg
    _save_server_config(SERVER_CFG)

def _backup_list():
    """Return list of backup files sorted by mtime desc."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
    except Exception:
        pass
    items = []
    if not os.path.isdir(BACKUP_DIR):
        return items
    for fn in os.listdir(BACKUP_DIR):
        if not BACKUP_FILENAME_RE.match(fn):
            continue
        path = os.path.join(BACKUP_DIR, fn)
        try:
            st = os.stat(path)
        except Exception:
            continue
        items.append({'name': fn, 'size': st.st_size, 'ts': int(st.st_mtime)})
    items.sort(key=lambda x: x['ts'], reverse=True)
    return items

def _backup_dir_size():
    return sum(it['size'] for it in _backup_list())

def _backup_apply_retention():
    """Remove oldest backups according to retention policy."""
    cfg = _backup_cfg()
    items = _backup_list()  # newest first
    removed = []
    if cfg['retention_mode'] == 'count':
        keep = max(1, int(cfg.get('retention_count') or 1))
        for it in items[keep:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, it['name']))
                removed.append(it['name'])
            except Exception:
                pass
    else:  # size
        limit = max(1, int(cfg.get('retention_size_mb') or 1)) * 1024 * 1024
        # Keep newest first within limit; drop the rest.
        running = 0
        keep_idx = len(items)
        for i, it in enumerate(items):
            if running + it['size'] > limit and i > 0:
                keep_idx = i
                break
            running += it['size']
        for it in items[keep_idx:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, it['name']))
                removed.append(it['name'])
            except Exception:
                pass
    return removed

def _backup_make():
    """Create a new backup archive. Returns (filename, size_bytes)."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime('%Y%m%d-%H%M%S')
    fname = f'awg-panel-{ts}.tar.gz'
    path = os.path.join(BACKUP_DIR, fname)
    cmd = ['tar', '-czf', path]
    for ex in BACKUP_TAR_EXCLUDES:
        cmd.append(f'--exclude={ex}')
    # Папка с самими бэкапами уже исключена относительным паттерном data/backup —
    # абсолютный путь тут не сработал бы (в архиве имена идут без ведущего «/»).
    cmd.append(BACKUP_PANEL_ROOT)
    for ext in _backup_external_files():
        if os.path.exists(ext):
            cmd.append(ext)
    # ВАЖНО: gunicorn в awg-panel.service имеет --timeout 120 (с 2026-05-18).
    # Архив на пару МБ — сжатие <2с, проблем нет.
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        # tar code 1 = "some files changed during read" — non-fatal.
        if res.returncode != 1:
            try: os.remove(path)
            except Exception: pass
            raise RuntimeError(f'tar failed (rc={res.returncode}): {res.stderr.strip()[:300]}')
    size = os.path.getsize(path) if os.path.exists(path) else 0
    return fname, size

def _backup_systemd_write(cfg):
    """Write/update systemd service+timer. cfg: {schedule_enabled, interval_value, interval_unit}."""
    if not cfg.get('schedule_enabled'):
        _backup_systemd_disable()
        return
    val = max(1, int(cfg.get('interval_value') or 1))
    unit = cfg.get('interval_unit') or 'days'
    if unit == 'hours':
        on_active = f'{val}h'
        on_boot = '5min'
    else:
        on_active = f'{val}d'
        on_boot = '10min'
    secret_path = SECRET_KEY_FILE
    service_body = (
        '[Unit]\n'
        'Description=AWG Panel automatic backup\n'
        'After=network.target awg-panel.service\n'
        '\n'
        '[Service]\n'
        'Type=oneshot\n'
        f"ExecStart=/bin/bash -c '/usr/bin/curl -s -m 300 -X POST -H \"X-Backup-Token: $(cat {secret_path})\" http://127.0.0.1:5000/api/backup/timer-fire'\n"
    )
    timer_body = (
        '[Unit]\n'
        'Description=AWG Panel automatic backup timer\n'
        '\n'
        '[Timer]\n'
        f'OnBootSec={on_boot}\n'
        f'OnUnitActiveSec={on_active}\n'
        'Persistent=true\n'
        'Unit=awg-panel-backup.service\n'
        '\n'
        '[Install]\n'
        'WantedBy=timers.target\n'
    )
    with open(BACKUP_TIMER_SERVICE, 'w') as f: f.write(service_body)
    with open(BACKUP_TIMER_UNIT, 'w') as f: f.write(timer_body)
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)
    subprocess.run(['systemctl', 'enable', '--now', BACKUP_TIMER_NAME], check=False, capture_output=True, timeout=15)
    # Restart timer to pick up changed interval
    subprocess.run(['systemctl', 'restart', BACKUP_TIMER_NAME], check=False, capture_output=True, timeout=15)

def _backup_timer_resync_secret_path():
    """Перепрописывает юнит автобэкапа, если в нём остался прежний путь к secret.key.

    Юнит подставляет токен как $(cat <path>). После переезда secret.key в data/
    старый путь дал бы пустой токен — автобэкап отвалился бы молча, без ошибки в UI.
    Вызывается на старте; когда путь в юните уже верный, выходит сразу.
    """
    try:
        if not os.path.exists(BACKUP_TIMER_SERVICE):
            return False
        with open(BACKUP_TIMER_SERVICE, 'r') as f:
            body = f.read()
        if SECRET_KEY_FILE in body:
            return False
        cfg = _backup_cfg()
        if not cfg.get('schedule_enabled'):
            return False
        _backup_systemd_write(cfg)
        audit('info', f'Автобэкап: юнит перепрописан на новый путь secret.key ({SECRET_KEY_FILE})')
        return True
    except Exception as e:
        print(f'[layout] юнит автобэкапа обновить не удалось: {e}', flush=True)
        return False

def _backup_systemd_disable():
    subprocess.run(['systemctl', 'disable', '--now', BACKUP_TIMER_NAME], check=False, capture_output=True, timeout=15)
    for p in (BACKUP_TIMER_SERVICE, BACKUP_TIMER_UNIT):
        try:
            if os.path.exists(p): os.remove(p)
        except Exception:
            pass
    subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True, timeout=15)

def _backup_next_run():
    """Read systemctl output to get next NEXT timestamp (seconds since epoch)."""
    out, _, rc = run_cmd(f'systemctl show {BACKUP_TIMER_NAME} -p NextElapseUSecRealtime --value')
    if rc != 0 or not out:
        return None
    # Format like: "Sat 2026-05-11 03:14:00 UTC"
    out = out.strip()
    if not out or out == '0' or out == 'n/a':
        return None
    try:
        # Use `date -d` to parse — robust on minimal images.
        d_out, _, d_rc = run_cmd(f"date -d '{out}' +%s")
        if d_rc == 0 and d_out.strip().isdigit():
            return int(d_out.strip())
    except Exception:
        pass
    return None

def _safe_backup_name(name):
    if not BACKUP_FILENAME_RE.match(name or ''):
        return None
    return name

@bp.route('/api/backup/status')
@_auth
def backup_status():
    items = _backup_list()
    cfg = _backup_cfg()
    last = items[0] if items else None
    # Все внешние конфиги, которые сейчас попадут в архив — берём через _backup_external_files()
    # (тот же источник, что показывает «Системные пути» и «Источники правды»).
    ext_all = _backup_external_files()
    ext_present = [p for p in ext_all if os.path.exists(p)]
    ext_missing = [p for p in ext_all if not os.path.exists(p)]
    return jsonify({
        'config': cfg,
        'backup_dir': BACKUP_DIR,
        'panel_root': BACKUP_PANEL_ROOT,
        'excludes': BACKUP_TAR_EXCLUDES,
        'external_files': ext_present,
        'external_files_all': ext_all,
        'external_files_missing': ext_missing,
        'total_size': _backup_dir_size(),
        'total_size_h': _fmt_bytes(_backup_dir_size()),
        'count': len(items),
        'last': last and {**last, 'size_h': _fmt_bytes(last['size'])},
        'next_run': _backup_next_run() if cfg.get('schedule_enabled') else None,
        'items': [{**it, 'size_h': _fmt_bytes(it['size'])} for it in items],
    })

@bp.route('/api/backup/run', methods=['POST'])
@_auth
def backup_run():
    try:
        fname, size = _backup_make()
    except Exception as e:
        audit('error', f'Backup failed: {e}')
        return jsonify({'ok': False, 'error': str(e)}), 500
    removed = _backup_apply_retention()
    audit('info', f'Backup создан: {fname} ({_fmt_bytes(size)})' + (f', удалено старых: {len(removed)}' if removed else ''))
    return jsonify({'ok': True, 'name': fname, 'size': size, 'size_h': _fmt_bytes(size), 'removed': removed})

@bp.route('/api/backup/timer-fire', methods=['POST'])
def backup_timer_fire():
    """Triggered by systemd timer via curl with X-Backup-Token. No session auth."""
    token = request.headers.get('X-Backup-Token', '')
    try:
        with open(SECRET_KEY_FILE, 'r') as f:
            secret = f.read().strip()
    except Exception:
        return jsonify({'error': 'no secret'}), 500
    if not token or token != secret:
        return jsonify({'error': 'unauthorized'}), 401
    try:
        fname, size = _backup_make()
    except Exception as e:
        audit('error', f'Scheduled backup failed: {e}')
        return jsonify({'ok': False, 'error': str(e)}), 500
    removed = _backup_apply_retention()
    audit('info', f'Авто-бэкап: {fname} ({_fmt_bytes(size)})' + (f', удалено старых: {len(removed)}' if removed else ''))
    return jsonify({'ok': True, 'name': fname})

@bp.route('/api/backup/schedule', methods=['POST'])
@_auth
def backup_schedule():
    body = request.get_json(force=True) or {}
    cfg = _backup_cfg()
    if 'schedule_enabled' in body:
        cfg['schedule_enabled'] = bool(body['schedule_enabled'])
    if 'interval_value' in body:
        try:
            cfg['interval_value'] = max(1, int(body['interval_value']))
        except Exception:
            return jsonify({'ok': False, 'error': 'interval_value must be int >= 1'}), 400
    if 'interval_unit' in body:
        if body['interval_unit'] not in ('hours', 'days'):
            return jsonify({'ok': False, 'error': 'interval_unit must be hours|days'}), 400
        cfg['interval_unit'] = body['interval_unit']
    if 'retention_mode' in body:
        if body['retention_mode'] not in ('count', 'size'):
            return jsonify({'ok': False, 'error': 'retention_mode must be count|size'}), 400
        cfg['retention_mode'] = body['retention_mode']
    if 'retention_count' in body:
        try:
            cfg['retention_count'] = max(1, int(body['retention_count']))
        except Exception:
            return jsonify({'ok': False, 'error': 'retention_count must be int >= 1'}), 400
    if 'retention_size_mb' in body:
        try:
            cfg['retention_size_mb'] = max(1, int(body['retention_size_mb']))
        except Exception:
            return jsonify({'ok': False, 'error': 'retention_size_mb must be int >= 1'}), 400
    _save_backup_cfg(cfg)
    try:
        _backup_systemd_write(cfg)
    except Exception as e:
        audit('error', f'Backup timer write failed: {e}')
        return jsonify({'ok': False, 'error': f'systemd: {e}'}), 500
    # Apply new retention immediately
    removed = _backup_apply_retention()
    audit('info', f'Backup настройки: {cfg}')
    return jsonify({'ok': True, 'config': cfg, 'next_run': _backup_next_run() if cfg['schedule_enabled'] else None, 'removed': removed})

@bp.route('/api/backup/download/<name>')
@_auth
def backup_download(name):
    safe = _safe_backup_name(name)
    if not safe:
        return jsonify({'error': 'bad name'}), 400
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({'error': 'not found'}), 404
    return send_from_directory(BACKUP_DIR, safe, as_attachment=True)

@bp.route('/api/backup/<name>', methods=['DELETE'])
@_auth
def backup_delete(name):
    safe = _safe_backup_name(name)
    if not safe:
        return jsonify({'error': 'bad name'}), 400
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({'error': 'not found'}), 404
    try:
        os.remove(path)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    audit('info', f'Backup удалён: {safe}')
    return jsonify({'ok': True})

@bp.route('/api/backup/restore/<name>', methods=['POST'])
@_auth
def backup_restore(name):
    safe = _safe_backup_name(name)
    if not safe:
        return jsonify({'error': 'bad name'}), 400
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({'error': 'not found'}), 404
    audit('warn', f'Restore запущен из {safe}')

    # Шаг 1: до распаковки бэкапа тянем актуальный код панели с CDN — тем же
    # awg-panel.zip, что и апдейт (раньше тут парсился список файлов из README;
    # README на CDN не отдаётся, а поштучных .py там нет — restore просто падал,
    # да и modules/ в такой список не попал бы). Если CDN недоступен — прерываем
    # restore ДО tar: файлы на сервере ещё не тронуты.
    try:
        staging, src_root, remote_v = _fetch_panel_zip_staging()
    except Exception as e:
        audit('error', f'Restore прерван: не удалось скачать awg-panel.zip: {e}')
        return jsonify({'ok': False, 'error': f'Не удалось скачать код панели с CDN: {e}. Проверьте интернет и попробуйте позже.'}), 502
    audit('info', f'Restore: с CDN получен awg-panel.zip (v{remote_v})')

    # Шаг 2: распаковываем бэкап поверх. Внутри tar пути без ведущего «/»,
    # поэтому --exclude указываем относительно корня — иначе tar не отфильтрует
    # папку с самими бэкапами. Папка data/backup исключается чтобы не затереть
    # текущие архивы.
    backup_dir_rel = BACKUP_DIR.lstrip('/')
    cmd = [
        'tar', '-xzf', path,
        '-C', '/',
        f'--exclude={backup_dir_rel}',
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if res.returncode != 0:
        shutil.rmtree(staging, ignore_errors=True)
        audit('error', f'Restore tar failed: {res.stderr.strip()[:300]}')
        return jsonify({'ok': False, 'error': f'tar rc={res.returncode}: {res.stderr.strip()[:200]}'}), 500
    audit('info', f'Restore: бэкап развёрнут')

    # Шаг 3: поверх tar'a раскладываем свежий код панели из staging — тем же
    # кодом, что и обычный апдейт (папки целиком + файлы корня, data/ и public/
    # из бэкапа не трогаются). Это перезатирает app.py/static/*/modules/* из tar,
    # чтобы после восстановления данных панель работала на актуальной версии.
    try:
        _apply_panel_staging(staging, src_root)
    except Exception as e:
        audit('error', f'Restore: накат кода панели не удался: {e}')
        return jsonify({'ok': False, 'error': f'Бэкап развёрнут, но накатить свежий код панели не удалось: {e}'}), 500
    audit('info', f'Restore: накатан свежий код панели (v{remote_v}), перезапуск сервисов')

    # После restore конфиг расписания мог стать другим — синхронизируем timer
    # сразу, чтобы новые настройки применились до перезапуска панели.
    try:
        # Перечитываем server.json, потому что restore затёр SERVER_CFG в памяти
        # старыми значениями только в файле, но in-memory объект остался прежним.
        with open(SERVER_CONFIG_FILE, 'r') as _f:
            fresh = json.load(_f)
        SERVER_CFG.clear()
        SERVER_CFG.update(fresh)
        _backup_systemd_write(_backup_cfg())
    except Exception as e:
        audit('warn', f'Restore: timer resync failed: {e}')
    # Restart services asynchronously so this response is not killed.
    subprocess.Popen([
        'systemd-run', '--no-block', '--collect',
        '/bin/bash', '-c',
        'sleep 2 && '
        'systemctl restart xray.service 2>/dev/null; '
        'systemctl restart mtg.service 2>/dev/null; '
        'systemctl restart awg-quick@awg0.service 2>/dev/null; '
        'systemctl restart hysteria-server.service 2>/dev/null; '
        'systemctl restart telemt.service 2>/dev/null; '
        'nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null; '
        'systemctl restart awg-panel.service'
    ])
    return jsonify({'ok': True})
