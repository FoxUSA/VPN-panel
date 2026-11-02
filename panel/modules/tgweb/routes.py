"""Flask-роуты WEB-прокси: /api/tgweb/* и раздача своей статики.

Все роуты под login_required панели (приходит через DEPS) — своей авторизации
пакет не заводит.
"""
from flask import jsonify, request, send_from_directory

from . import DEPS, STATIC_DIR
from . import clients as cl
from . import links, service, stats


def _guard(f):
    dec = DEPS.get('login_required')
    if dec:
        return dec(f)

    def _closed(*a, **kw):
        return jsonify({'ok': False, 'error': 'auth unavailable'}), 503
    _closed.__name__ = f.__name__
    return _closed


# Ключи задач — те же, что у /api/system/install|update/tgweb в app.py: реестр
# фоновых задач общий, и кнопка в блоке версий не запустит вторую установку,
# пока идёт начатая с вкладки.
JOB_INSTALL = 'install:tgweb'
JOB_UPDATE = 'update:tgweb'
JOB_TAKE443 = 'take443:tgweb'


def _background(job_id, fn, steps=None):
    """Долгое — в фоне: gunicorn убивает воркер через 30 с, и вместо JSON
    браузер получил бы HTML-страницу 502, хотя установка продолжала бы идти."""
    starter = DEPS.get('job_start')
    if starter:
        try:
            return jsonify(starter(job_id, fn, steps) if steps else starter(job_id, fn))
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
    ok, msg = fn((lambda *a, **k: None)) if steps else fn()
    return jsonify({'ok': ok, 'note': msg if ok else '', 'error': '' if ok else msg}), (200 if ok else 500)


def _client_view(c, host, slug, totals, live, seen, geo_fn):
    rec = dict(c)
    cid = c.get('id')
    rec['links'] = links.build(host, slug, c.get('secret'))
    rec['total'] = stats.usage_bytes(cid, totals)
    lv = live.get(cid) or {}
    rec['conns'] = int(lv.get('conns') or 0)
    rec['ips_now'] = lv.get('ips') or []
    hist = seen.get(cid) or {}
    rec['last_ip'] = (rec['ips_now'][0] if rec['ips_now'] else hist.get('last_ip')) or ''
    rec['last_seen'] = int(hist.get('last_ts') or 0)
    if rec['last_ip'] and geo_fn:
        try:
            rec['geo'] = geo_fn(rec['last_ip']) or {}
        except Exception:
            rec['geo'] = {}
    # Секрет наружу отдаётся: он нужен окну «Ссылка» для ручного ввода, а
    # API закрыт входом в панель, как и ссылки остальных протоколов.
    return rec


def register(app):
    @app.route('/tgweb/static/<path:filename>')
    def tgweb_static(filename):
        return send_from_directory(STATIC_DIR, filename)

    @app.route('/api/tgweb/status')
    @_guard
    def tgweb_status():
        st = service.status()
        st['latest'] = service.latest_version_nowait()
        st['clients'] = len(cl.list_clients())
        return jsonify(st)

    @app.route('/api/tgweb/setup', methods=['POST'])
    @_guard
    def tgweb_setup():
        return _background(JOB_INSTALL, service.setup, service.SETUP_STEPS)

    @app.route('/api/tgweb/update', methods=['POST'])
    @_guard
    def tgweb_update():
        return _background(JOB_UPDATE, service.update_binary)

    @app.route('/api/tgweb/restart', methods=['POST'])
    @_guard
    def tgweb_restart():
        ok, err = service.restart(service.REQUEST_WAIT)
        return jsonify({'ok': ok, 'error': err}), (200 if ok else 500)

    @app.route('/api/tgweb/stop', methods=['POST'])
    @_guard
    def tgweb_stop():
        return jsonify({'ok': service.stop()})

    @app.route('/api/tgweb/autostart', methods=['POST'])
    @_guard
    def tgweb_autostart():
        on = bool((request.get_json(silent=True) or {}).get('enabled'))
        service.set_autostart(on)
        return jsonify({'ok': service.is_enabled() == on, 'autostart': service.is_enabled()})

    @app.route('/api/tgweb/uninstall', methods=['POST'])
    @_guard
    def tgweb_uninstall():
        data = request.get_json(silent=True) or {}
        service.uninstall(purge_data=bool(data.get('purge_data')))
        return jsonify({'ok': True})

    @app.route('/api/tgweb/slug', methods=['POST'])
    @_guard
    def tgweb_slug():
        """Новый префикс пути. Все выданные ссылки перестают работать — UI
        предупреждает об этом до вызова."""
        ok, res = service.regenerate_slug()
        if not ok:
            return jsonify({'ok': False, 'error': res}), 400
        return jsonify({'ok': True, 'slug': res})

    @app.route('/api/tgweb/take443', methods=['POST'])
    @_guard
    def tgweb_take443():
        """Явный выбор админа: отдать 443 WEB-прокси — XRay остановить и снять с
        автозапуска (VLESS на сервере перестаёт работать; UI предупреждает).
        В фоне: запрос мог прийти через этот же XRay, и его остановка оборвала
        бы ответ — результат UI заберёт опросом задачи новым соединением."""
        from . import front
        return _background(JOB_TAKE443, front.take_443)

    @app.route('/api/tgweb/heal', methods=['POST'])
    @_guard
    def tgweb_heal():
        """«Починить цепочку»: перезаписать nginx-блок, записи XRay, конфиг."""
        ok, msg = service.heal(force=True, wait=service.REQUEST_WAIT)
        return jsonify({'ok': ok, 'note': msg if ok else '', 'error': '' if ok else msg}), \
            (200 if ok else 500)

    # --- клиенты ---------------------------------------------------------------

    @app.route('/api/tgweb/clients', methods=['GET'])
    @_guard
    def tgweb_clients_list():
        host, slug = service.public_host(), service.load_slug()
        snap = stats.collect()
        seen = stats.load_seen()
        geo_fn = DEPS.get('geo_lookup')
        out = [_client_view(c, host, slug, snap['totals'], snap['live'], seen, geo_fn)
               for c in cl.list_clients()]
        return jsonify({'clients': out, 'host': host, 'slug': slug})

    @app.route('/api/tgweb/clients', methods=['POST'])
    @_guard
    def tgweb_clients_add():
        data = request.get_json(force=True) or {}
        rec, err = cl.add(data.get('name'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        rec = dict(rec)
        rec['links'] = links.build(service.public_host(), service.load_slug(), rec.get('secret'))
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>', methods=['PUT'])
    @_guard
    def tgweb_clients_rename(client_id):
        rec, err = cl.rename(client_id, (request.get_json(force=True) or {}).get('name'))
        if err:
            return jsonify({'ok': False, 'error': err}), (404 if err == 'не найдено' else 400)
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>', methods=['DELETE'])
    @_guard
    def tgweb_clients_delete(client_id):
        rec, err = cl.delete(client_id)
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        return jsonify({'ok': True})

    @app.route('/api/tgweb/clients/<client_id>/disable', methods=['POST'])
    @_guard
    def tgweb_clients_disable(client_id):
        rec, err = cl.set_disabled(client_id, (request.get_json(force=True) or {}).get('disabled'))
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>/secret', methods=['POST'])
    @_guard
    def tgweb_clients_secret(client_id):
        rec, err = cl.regenerate_secret(client_id)
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        rec = dict(rec)
        rec['links'] = links.build(service.public_host(), service.load_slug(), rec.get('secret'))
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>/allow-ips', methods=['POST'])
    @_guard
    def tgweb_allow_ips(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_ip_filters(client_id, data.get('allow_ips'), data.get('block_ips'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        # Списки и на верхнем уровне — общая модалка фильтра IP читает их оттуда.
        return jsonify({'ok': True, 'client': rec, 'allow_ips': rec.get('allow_ips') or [],
                        'block_ips': rec.get('block_ips') or []})

    @app.route('/api/tgweb/clients/<client_id>/max-ips', methods=['POST'])
    @_guard
    def tgweb_max_ips(client_id):
        rec, err = cl.set_max_ips(client_id, (request.get_json(force=True) or {}).get('max_ips'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>/schedule', methods=['POST'])
    @_guard
    def tgweb_schedule(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_schedule(client_id, data.get('action'), data.get('date'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>/traffic/reset', methods=['POST'])
    @_guard
    def tgweb_traffic_reset(client_id):
        stats.reset(client_id)
        if stats.enforce_limits():
            service.apply_clients()
        return jsonify({'ok': True})

    def _set_traffic_fields(client_id, data):
        """Лимит и день сброса. Имена полей — и свои (limit_gb/reset_day), и те,
        что шлёт общая модалка расписания панели (gb/day)."""
        def _f(c):
            try:
                if 'limit_gb' in data or 'gb' in data:
                    c['limit_gb'] = max(0.0, float(data.get('limit_gb', data.get('gb')) or 0))
                if 'reset_day' in data or 'day' in data:
                    c['traffic_reset_day'] = max(0, min(31, int(data.get('reset_day', data.get('day')) or 0)))
            except (TypeError, ValueError):
                return 'лимит и день должны быть числами'
            return ''
        rec, err = cl._mutate(client_id, _f)
        if rec and stats.enforce_limits():
            service.apply_clients()
        return rec, err

    @app.route('/api/tgweb/clients/<client_id>/traffic/limit', methods=['POST'])
    @_guard
    def tgweb_traffic_limit(client_id):
        rec, err = _set_traffic_fields(client_id, request.get_json(force=True) or {})
        if err:
            return jsonify({'ok': False, 'error': err}), (404 if err == 'не найдено' else 400)
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/tgweb/clients/<client_id>/traffic/reset-day', methods=['POST'])
    @_guard
    def tgweb_traffic_reset_day(client_id):
        rec, err = _set_traffic_fields(client_id, request.get_json(force=True) or {})
        if err:
            return jsonify({'ok': False, 'error': err}), (404 if err == 'не найдено' else 400)
        return jsonify({'ok': True, 'client': rec})

    # --- логи ------------------------------------------------------------------

    @app.route('/api/tgweb/logs')
    @_guard
    def tgweb_logs():
        """Онлайн — живые сессии из API, архив — наша история IP."""
        cid = request.args.get('client') or None
        geo_fn = DEPS.get('geo_lookup')
        names = {c.get('id'): c.get('name') for c in cl.list_clients()}
        live = stats.sessions(cid)
        for s in live.get('items') or []:
            s['name'] = names.get(s.get('user'), s.get('user'))
            if s.get('ip') and geo_fn:
                try:
                    s['geo'] = geo_fn(s['ip']) or {}
                except Exception:
                    s['geo'] = {}
        archive = []
        for uid, hist in stats.load_seen().items():
            if cid and uid != cid:
                continue
            for ip, ts in (hist.get('ips') or {}).items():
                row = {'user': uid, 'name': names.get(uid, uid), 'ip': ip, 'ts': ts}
                if geo_fn:
                    try:
                        row['geo'] = geo_fn(ip) or {}
                    except Exception:
                        row['geo'] = {}
                archive.append(row)
        archive.sort(key=lambda r: -int(r.get('ts') or 0))
        return jsonify({'online': live.get('items') or [], 'online_error': live.get('error') or '',
                        'archive': archive[:500], 'name': names.get(cid, '') if cid else ''})

    return app
