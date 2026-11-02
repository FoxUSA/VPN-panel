"""Flask-роуты Hysteria: /api/hysteria/* и раздача своей статики.

Все роуты защищены login_required, который приходит из панели через DEPS —
собственной авторизации пакет не заводит, чтобы правила входа оставались
в одном месте.
"""
import os

from flask import jsonify, request, send_from_directory

from . import DEPS, STATIC_DIR, load_settings, save_settings
from . import clients as cl
from . import logs as hylogs
from . import profiles, rules, service, stats


def _guard(f):
    """login_required панели; если его почему-то не передали — закрываем доступ,
    а не открываем."""
    dec = DEPS.get('login_required')
    if dec:
        return dec(f)

    def _closed(*a, **kw):
        return jsonify({'ok': False, 'error': 'auth unavailable'}), 503
    _closed.__name__ = f.__name__
    return _closed


# Идентификаторы фоновых задач. Те же, что использует сама панель в
# /api/system/install|update/hysteria: реестр задач у неё один, и одинаковый
# ключ означает, что кнопка в блоке версий и кнопка на вкладке не запустят две
# установки разом — вторая увидит уже запущенную и просто дождётся её.
JOB_INSTALL = 'install:hysteria'
JOB_UPDATE = 'update:hysteria'


def _background(job_id, fn):
    """Запускает долгую операцию через фоновый механизм панели.

    Синхронно такие вещи делать нельзя: установка тянет с GitHub бинарь на
    десятки мегабайт, а gunicorn убивает воркер по таймауту. Клиент получал бы
    HTML-страницу 502 вместо JSON — снаружи это выглядит как «панель зависла»,
    хотя установка на сервере продолжает идти и заканчивается успешно.

    Панель без этого механизма (старая версия) деградирует к синхронному
    вызову — там лучше рискнуть таймаутом, чем не уметь ставить вовсе.
    """
    starter = DEPS.get('job_start')
    if starter:
        try:
            return jsonify(starter(job_id, fn))
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
    ok, msg = fn()
    return jsonify({'ok': ok, 'note': msg if ok else '', 'error': '' if ok else msg}), \
        (200 if ok else 500)


def register(app):
    @app.route('/hysteria/static/<path:filename>')
    def hysteria_static(filename):
        # Своя раздача, чтобы не трогать static_folder панели.
        return send_from_directory(STATIC_DIR, filename)

    # --- публичные профили ---------------------------------------------------
    #
    # Без авторизации: по этим ссылкам клиент (Shadowrocket/Loon/Clash) сам
    # перекачивает профиль и подхватывает изменения правил. Ключ — токен
    # профиля, отдельный от пароля подключения. Имя клиента идёт ПОСЛЕДНИМ
    # сегментом: Loon берёт имя профиля из хвоста URL.

    def _profile_response(rest, kind):
        c = None
        for seg in [s for s in (rest or '').split('/') if s]:
            c = cl.by_token(seg)
            if c:
                break
        if not c:
            return ('Not found', 404, {'Content-Type': 'text/plain; charset=utf-8'})
        body = {
            'sub': lambda: profiles.build_link(c),
            'conf': lambda: profiles.build_shadowrocket(c),
            'loon': lambda: profiles.build_loon(c),
            'clash': lambda: profiles.build_clash(c),
        }[kind]()
        if not body:
            return ('Not ready', 503, {'Content-Type': 'text/plain; charset=utf-8'})
        ctype = 'application/x-yaml; charset=utf-8' if kind == 'clash' \
            else 'text/plain; charset=utf-8'
        headers = {'Content-Type': ctype, 'Cache-Control': 'no-store'}
        if kind == 'sub':
            # Подписка — base64 от списка ссылок, ровно как /sub/ у XRay
            # (profiles.public_subscription). Голую строку hysteria2://
            # Shadowrocket в «Type: Subscribe» не принимал: «не удалось
            # получить серверы для подписки».
            import base64
            body = base64.b64encode((body.strip() + '\n').encode('utf-8')).decode('ascii')
            headers['subscription-userinfo'] = 'upload=0; download=0; total=0; expire=0'
        if kind == 'clash':
            headers['Profile-Update-Interval'] = '24'
        # ?download=1 — кнопка «Скачать файл» в панели. Клиенты (Loon,
        # Shadowrocket, Clash) ходят по чистому URL и получают профиль как
        # раньше; заголовок добавляется только для ручного сохранения, иначе
        # телефон открыл бы профиль текстом в браузере вместо файла.
        if request.args.get('download'):
            ext = {'sub': 'txt', 'conf': 'conf', 'loon': 'conf', 'clash': 'yaml'}[kind]
            fname = '%s.%s' % ((rest or 'profile').rstrip('/').split('/')[-1].split('.')[0], ext)
            headers['Content-Disposition'] = 'attachment; filename="%s"' % fname
        return (body, 200, headers)

    @app.route('/hy/sub/<path:rest>')
    def hysteria_public_sub(rest):
        return _profile_response(rest, 'sub')

    @app.route('/hy/conf/<path:rest>')
    def hysteria_public_conf(rest):
        return _profile_response(rest, 'conf')

    @app.route('/hy/loon/<path:rest>')
    def hysteria_public_loon(rest):
        return _profile_response(rest, 'loon')

    @app.route('/hy/clash/<path:rest>')
    def hysteria_public_clash(rest):
        return _profile_response(rest, 'clash')

    @app.route('/api/hysteria/status')
    @_guard
    def hysteria_status():
        st = service.status()
        st['latest'] = service.latest_version_nowait()
        st['host'] = profiles.server_host()
        st['clients'] = len(cl.list_clients())
        st['global'] = rules.status()
        totals = stats.load_totals()
        st['totals'] = {
            'tx': sum(int((v or {}).get('tx') or 0) for v in totals.values()),
            'rx': sum(int((v or {}).get('rx') or 0) for v in totals.values()),
        }
        return jsonify(st)

    @app.route('/api/hysteria/update', methods=['POST'])
    @_guard
    def hysteria_update():
        return _background(JOB_UPDATE, service.update_binary)

    # --- глобальные серверные правила ---------------------------------------

    @app.route('/api/hysteria/global', methods=['GET'])
    @_guard
    def hysteria_global_get():
        return jsonify(rules.status())

    @app.route('/api/hysteria/global', methods=['POST'])
    @_guard
    def hysteria_global_set():
        """Сохраняет намерение БЕЗ применения: применение перезапускает сервис
        и рвёт сессии, поэтому оно всегда отдельной кнопкой."""
        rules.save_pending(request.get_json(force=True) or {})
        return jsonify(rules.status())

    @app.route('/api/hysteria/global/apply', methods=['POST'])
    @_guard
    def hysteria_global_apply():
        _, err = rules.apply()
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify(rules.status())

    @app.route('/api/hysteria/global/refresh', methods=['POST'])
    @_guard
    def hysteria_global_refresh():
        """Перекачать выбранные списки и применить заново."""
        blob = rules.load_global()
        _, err = rules.apply(blob['applied'], force_refresh=True)
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify(rules.status())

    @app.route('/api/hysteria/global/traffic/reset-day', methods=['POST'])
    @_guard
    def hysteria_global_reset_day():
        """Ежемесячный сброс ОБЩЕГО счётчика трафика Hysteria — как у Global
        rules XRay. Пишется сразу в pending и applied: «Применить» тут не нужен,
        перезапуска сервиса поле не требует."""
        data = request.get_json(force=True) or {}
        raw = data.get('day', None)
        if raw in (None, '', 0, '0'):
            day = None
        else:
            try:
                day = int(raw)
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'error': 'день должен быть числом'}), 400
            if not 1 <= day <= 31:
                return jsonify({'ok': False, 'error': 'день должен быть 1–31'}), 400
        rules.save_field('traffic_reset_day', day)
        return jsonify({'ok': True, 'traffic_reset_day': day})

    @app.route('/api/hysteria/global/traffic/reset', methods=['POST'])
    @_guard
    def hysteria_global_reset_now():
        """«Сбросить сейчас»: обнуляет накопленный трафик всех клиентов."""
        stats.reset_all()
        return jsonify({'ok': True})

    @app.route('/api/hysteria/cascade', methods=['POST'])
    @_guard
    def hysteria_cascade():
        data = request.get_json(force=True) or {}
        ok, msg = rules.set_cascade(bool(data.get('enabled')))
        if not ok:
            return jsonify({'ok': False, 'error': msg}), 500
        return jsonify({'ok': True, 'note': msg, 'global': rules.status()})

    # --- порт-хоппинг -------------------------------------------------------

    @app.route('/api/hysteria/hop', methods=['POST'])
    @_guard
    def hysteria_hop_toggle():
        """Порт-хоппинг: основной порт не меняется, диапазон добавляется — выданные
        ссылки продолжают работать. Сервис перезапускается."""
        data = request.get_json(force=True) or {}
        ok, res = service.set_hop(bool(data.get('enabled')))
        if not ok:
            return jsonify({'ok': False, 'error': res}), 400
        return jsonify({'ok': True, 'hop': res})

    # --- sniff ---------------------------------------------------------------

    @app.route('/api/hysteria/sniff', methods=['POST'])
    @_guard
    def hysteria_sniff_toggle():
        """Определение доменов по началу соединения — секция sniff в config.yaml.
        Ссылки клиентов не меняются; сервис перезапускается."""
        data = request.get_json(force=True) or {}
        cfg = load_settings()
        cfg['sniff'] = bool(data.get('enabled'))
        save_settings(cfg)
        if service.bin_installed():
            service.write_config(cfg)
            ok, err = service.apply_changes()
            if not ok:
                return jsonify({'ok': False, 'error': err}), 500
        return jsonify({'ok': True, 'enabled': cfg['sniff']})

    # --- журнал назначений ---------------------------------------------------

    @app.route('/api/hysteria/access-log', methods=['POST'])
    @_guard
    def hysteria_access_log_toggle():
        """Включает журнал назначений. Это смена уровня логирования в юните,
        поэтому сервис перезапускается — предупреждение висит в модалке."""
        data = request.get_json(force=True) or {}
        cfg = load_settings()
        cfg['access_log'] = bool(data.get('enabled'))
        save_settings(cfg)
        if service.bin_installed():
            service.write_unit(cfg)
            ok, err = service.apply_changes()
            if not ok:
                return jsonify({'ok': False, 'error': err}), 500
        return jsonify({'ok': True, 'enabled': cfg['access_log']})

    def _logs_payload(client_id=None):
        cfg = load_settings()
        try:
            limit = max(1, min(100000, int(request.args.get('limit', 500))))
        except (TypeError, ValueError):
            limit = 500
        name = ''
        if client_id:
            c = cl.get(client_id)
            name = (c or {}).get('name') or ''
        return jsonify({
            'access_log_enabled': bool(cfg.get('access_log')),
            'name': name,
            'records': hylogs.for_client(client_id, limit),
        })

    @app.route('/api/hysteria/logs')
    @_guard
    def hysteria_logs_all():
        return _logs_payload(None)

    @app.route('/api/hysteria/clients/<client_id>/logs')
    @_guard
    def hysteria_logs_client(client_id):
        return _logs_payload(client_id)

    @app.route('/api/hysteria/settings', methods=['GET'])
    @_guard
    def hysteria_settings_get():
        cfg = load_settings()
        # Секрет статистики наружу не отдаём — он нужен только серверной части.
        cfg.pop('stats_secret', None)
        return jsonify(cfg)

    @app.route('/api/hysteria/settings', methods=['POST'])
    @_guard
    def hysteria_settings_set():
        data = request.get_json(force=True) or {}
        cfg = load_settings()
        # Порт здесь не принимаем: он меняется только через /api/hysteria/port —
        # там проверка конфликтов, фаервол и откат. Раньше общий «Сохранить»
        # менял порт в обход всего этого.
        for key in ('up_mbps', 'down_mbps'):
            if key in data:
                try:
                    cfg[key] = max(0, int(data[key]))
                except (TypeError, ValueError):
                    return jsonify({'ok': False, 'error': 'поле %s должно быть числом' % key}), 400
        for key in ('obfs_password', 'masquerade_url', 'sni'):
            if key in data:
                cfg[key] = (data[key] or '').strip()
        if not 1 <= int(cfg.get('port') or 443) <= 65535:
            return jsonify({'ok': False, 'error': 'порт вне диапазона'}), 400
        save_settings(cfg)
        restarted = False
        if service.bin_installed():
            service.write_config(cfg)
            restarted = not service.stopped_by_hand()
            ok, err = service.apply_changes()
            if not ok:
                return jsonify({'ok': False, 'error': 'настройки сохранены, но сервис не поднялся: %s' % err}), 500
        return jsonify({'ok': True, 'restarted': restarted})

    # --- порт ----------------------------------------------------------------
    #
    # Отдельная пара роутов, а не поле в /settings: смена порта трогает конфиг,
    # фаервол и сервис, обесценивает выданные ссылки и умеет откатываться —
    # общей кнопке «Сохранить настройки» такая операция не по размеру. UI
    # открывает её из той же модалки смены порта, что у AmneziaWG и MTProto.

    @app.route('/api/hysteria/port', methods=['GET'])
    @_guard
    def hysteria_port_get():
        return jsonify({'ok': True, **service.port_state()})

    @app.route('/api/hysteria/port', methods=['POST'])
    @_guard
    def hysteria_port_set():
        data = request.get_json(silent=True) or {}
        ok, res = service.set_port(data.get('port'))
        if not ok:
            return jsonify({'ok': False, 'error': res}), 400
        return jsonify({'ok': True, **res})

    @app.route('/api/hysteria/setup', methods=['POST'])
    @_guard
    def hysteria_setup():
        def _run():
            ok, note = service.setup()
            if not ok:
                return False, note
            # note непустой, когда порт пришлось сменить — это важно показать.
            return True, (note or 'Hysteria 2 установлена и запущена')

        return _background(JOB_INSTALL, _run)

    @app.route('/api/hysteria/restart', methods=['POST'])
    @_guard
    def hysteria_restart():
        ok, err = service.restart()
        return jsonify({'ok': ok, 'error': err}), (200 if ok else 500)

    @app.route('/api/hysteria/stop', methods=['POST'])
    @_guard
    def hysteria_stop():
        return jsonify({'ok': service.stop()})

    @app.route('/api/hysteria/autostart', methods=['POST'])
    @_guard
    def hysteria_autostart():
        """Запуск юнита при перезагрузке сервера. Без него протокол молча не
        поднимется после ребута, и узнаёшь об этом от пользователей."""
        data = request.get_json(silent=True) or {}
        on = bool(data.get('enabled'))
        service.run_cmd('systemctl %s %s' % ('enable' if on else 'disable', service.UNIT_NAME))
        return jsonify({'ok': service.is_enabled() == on, 'autostart': service.is_enabled()})

    @app.route('/api/hysteria/uninstall', methods=['POST'])
    @_guard
    def hysteria_uninstall():
        data = request.get_json(silent=True) or {}
        service.uninstall(purge_data=bool(data.get('purge_data')))
        return jsonify({'ok': True})

    @app.route('/api/hysteria/clients', methods=['GET'])
    @_guard
    def hysteria_clients_list():
        host = profiles.server_host()
        totals = stats.collect()
        live = stats.online()
        seen = cl.last_seen_map()
        geo_fn = DEPS.get('geo_lookup')
        out = []
        for c in cl.list_clients():
            rec = dict(c)
            cid = c.get('id')
            t = totals.get(cid) or {}
            rec['link'] = profiles.build_link(c, host)
            rec['tx'] = int(t.get('tx') or 0)
            rec['rx'] = int(t.get('rx') or 0)
            rec['total'] = rec['tx'] + rec['rx']
            rec['devices'] = int(live.get(cid) or 0)
            ls = seen.get(cid) or {}
            rec['last_ip'] = ls.get('ip') or ''
            rec['last_seen'] = ls.get('ts') or 0
            # pending/applied правил — фронт рисует свитчи по pending, бейдж по applied.
            rec.update(cl.geo_view(c))
            # Гео по последнему IP — через панельные базы MaxMind, свои не заводим.
            if rec['last_ip'] and geo_fn:
                try:
                    rec['geo'] = geo_fn(rec['last_ip']) or {}
                except Exception:
                    rec['geo'] = {}
            out.append(rec)
        return jsonify({'clients': out, 'host': host})

    @app.route('/api/hysteria/clients/<client_id>/allow-ips', methods=['POST'])
    @_guard
    def hysteria_allow_ips(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_ip_filters(client_id, data.get('allow_ips'), data.get('block_ips'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/dns', methods=['POST'])
    @_guard
    def hysteria_set_dns(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_dns(client_id, data.get('dns'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/rule-lists', methods=['POST'])
    @_guard
    def hysteria_set_rule_lists(client_id):
        """Выбор правил из ОБЩЕГО каталога панели (тот же, что у XRay).

        Правила Hysteria действуют в клиентском профиле, а не на сервере: у
        hysteria ACL один на весь сервер, персональной маршрутизации нет.
        """
        data = request.get_json(force=True) or {}
        rec, err = cl.set_rule_lists(client_id, data.get('lists'), data.get('geo_mode'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/geo-mode', methods=['POST'])
    @_guard
    def hysteria_set_geo_mode(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_geo_mode(client_id, (data.get('mode') or 'off').strip())
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/geo-countries', methods=['POST'])
    @_guard
    def hysteria_set_geo_countries(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_geo_countries(client_id, data.get('countries'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/lists-default', methods=['POST'])
    @_guard
    def hysteria_set_lists_default(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_lists_default(client_id, data.get('mode'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/geo-apply', methods=['POST'])
    @_guard
    def hysteria_apply_geo(client_id):
        """«Применить»: pending → applied. Профили клиента собираются по applied,
        поэтому до нажатия выданный конфиг остаётся прежним."""
        rec, err = cl.apply_geo(client_id)
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        out = {'ok': True}
        out.update(cl.geo_view(rec))
        return jsonify(out)

    @app.route('/api/hysteria/clients/<client_id>/rule-policy', methods=['POST'])
    @_guard
    def hysteria_set_rule_policy(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_rule_policy(client_id, data.get('id'), data.get('policy'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'rule_policy': rec.get('rule_policy') or {}})

    @app.route('/api/hysteria/clients/<client_id>/schedule', methods=['POST'])
    @_guard
    def hysteria_set_schedule(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_schedule(client_id, data.get('action'),
                                   data.get('date') or data.get('at'))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/config')
    @_guard
    def hysteria_client_config(client_id):
        c = cl.get(client_id)
        if not c:
            return jsonify({'ok': False, 'error': 'не найдено'}), 404
        blob = profiles.build_all(c)
        blob['name'] = c.get('name')
        blob['host'] = profiles.server_host()
        return jsonify(blob)

    @app.route('/api/hysteria/clients/<client_id>/streams')
    @_guard
    def hysteria_client_streams(client_id):
        """Активные соединения клиента: куда он ходит прямо сейчас.

        У hysteria нет журнала назначений, как access.log у XRay, — API отдаёт
        только снимок открытых потоков. Это та же модель, что у логов AWG,
        где назначения снимаются из conntrack.
        """
        # '__all__' — потоки всех клиентов сразу (кнопка в карточке правил).
        return jsonify(stats.streams(None if client_id == '__all__' else client_id))

    @app.route('/api/hysteria/clients/<client_id>/traffic/reset', methods=['POST'])
    @_guard
    def hysteria_traffic_reset(client_id):
        stats.reset(client_id)
        return jsonify({'ok': True})

    def _set_traffic_fields(client_id, data):
        """Лимит и день сброса. Имена полей принимаем и свои (limit_gb/reset_day),
        и те, что шлёт общая модалка расписания панели (gb/day) — она одна на все
        протоколы, и подстраиваться должен протокол, а не она."""
        clients = cl.list_clients()
        for c in clients:
            if c.get('id') != client_id:
                continue
            try:
                if 'limit_gb' in data or 'gb' in data:
                    raw = data.get('limit_gb', data.get('gb'))
                    c['limit_gb'] = max(0.0, float(raw or 0))
                if 'reset_day' in data or 'day' in data:
                    raw = data.get('reset_day', data.get('day'))
                    c['traffic_reset_day'] = max(0, min(31, int(raw or 0)))
            except (TypeError, ValueError):
                return None, 'лимит и день должны быть числами'
            cl.save_clients(clients)
            stats.enforce_limits()
            return c, ''
        return None, 'не найдено'

    @app.route('/api/hysteria/clients/<client_id>/traffic/limit', methods=['POST'])
    @_guard
    def hysteria_traffic_limit(client_id):
        rec, err = _set_traffic_fields(client_id, request.get_json(force=True) or {})
        if err:
            return jsonify({'ok': False, 'error': err}), (404 if err == 'не найдено' else 400)
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/traffic/reset-day', methods=['POST'])
    @_guard
    def hysteria_traffic_reset_day(client_id):
        rec, err = _set_traffic_fields(client_id, request.get_json(force=True) or {})
        if err:
            return jsonify({'ok': False, 'error': err}), (404 if err == 'не найдено' else 400)
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients', methods=['POST'])
    @_guard
    def hysteria_clients_add():
        data = request.get_json(force=True) or {}
        # rule_lists приходит в том же виде, что у XRay: либо {'lists': [...]},
        # либо просто список — модалка создания у протоколов общая по смыслу.
        rl = data.get('rule_lists')
        if isinstance(rl, dict):
            rl = rl.get('lists')
        rec, err = cl.add(data.get('name'), rl, bool(data.get('no_rules')))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        rec = dict(rec)
        rec['link'] = profiles.build_link(rec)
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>', methods=['PUT'])
    @_guard
    def hysteria_clients_rename(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.rename(client_id, data.get('name'))
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>/disable', methods=['POST'])
    @_guard
    def hysteria_clients_disable(client_id):
        data = request.get_json(force=True) or {}
        rec, err = cl.set_disabled(client_id, data.get('disabled'))
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        return jsonify({'ok': True, 'client': rec})

    @app.route('/api/hysteria/clients/<client_id>', methods=['DELETE'])
    @_guard
    def hysteria_clients_delete(client_id):
        rec, err = cl.delete(client_id)
        if err:
            return jsonify({'ok': False, 'error': err}), 404
        return jsonify({'ok': True})

    return app
