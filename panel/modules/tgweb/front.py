"""Кто принимает клиентов WEB-прокси на 443/tcp — «фронт».

Ссылка WEB не содержит порта: клиент Telegram всегда идёт на 443. Отсюда два
режима, и панель выбирает между ними сама, по живому состоянию сервера:

- 'xray'  — XRay (VLESS) в режиме TLS на 443. Он терминирует TLS сертификатом
            домена, а всё не-VLESS отдаёт общим фоллбеком нашему nginx на
            127.0.0.1 (proxy_protocol) → префикс в telemt, остальное сайту и
            панели. Оба протокола живут на одном 443.
- 'nginx' — XRay на 443 нет: не установлен, ушёл на другой порт или выключен
            вместе с автозапуском. Тогда 443 слушает сам nginx с тем же
            сертификатом, а разводка запросов та же.

XRay «претендует» на 443, если стоит там в конфиге и запущен ИЛИ включён в
автозапуск: включённый, но остановленный XRay админ ждёт обратно, и отдать его
443 WEB-прокси значило бы, что после перезагрузки XRay не поднимется (порт
занят) — или наоборот, nginx не поднимется вместе со всеми сайтами. Поэтому:

- претендует XRay в TLS            → 'xray' (даже если он сейчас лежит);
- претендует XRay в Reality        → нельзя: Reality отдаёт чужой сертификат,
                                     WebView его не примет;
- не претендует, 443 свободен      → 'nginx';
- 443 держит кто-то чужой          → нельзя, называем кого.

Переход между режимами делает reconcile() — его зовут сторож (раз в 15 с),
починка, установка и хуки панели перед стартом XRay и сменой режима 443.
Главный инвариант: наш nginx никогда не слушает 443, если на него претендует
кто-то другой, — иначе упал бы nginx целиком вместе с чужими сайтами.
"""
import glob
import os
import re
import time

from . import DEPS, NGINX_AVAILABLE, audit, load_settings, run_cmd, save_settings

XRAY_UNIT = 'xray'


# --- факты о сервере ---------------------------------------------------------------

def _xray_config():
    from . import xray_link
    try:
        _, cfg = xray_link._load()
        return cfg
    except Exception:
        return None


def xray_facts():
    """{'installed', 'port', 'mode', 'active', 'enabled'} — по живому конфигу и systemd."""
    from . import xray_link
    bin_path = xray_link._xray_paths().get('bin') or '/usr/local/bin/xray'
    cfg = _xray_config()
    port, mode = 0, ''
    for ib in (cfg or {}).get('inbounds') or []:
        if ib.get('protocol') == 'vless':
            try:
                port = int(ib.get('port') or 0)
            except (TypeError, ValueError):
                port = 0
            mode = ((ib.get('streamSettings') or {}).get('security') or '')
            if port == 443:
                break
    installed = os.path.isfile(bin_path) and cfg is not None
    act, _, _ = run_cmd('systemctl is-active %s' % XRAY_UNIT)
    ena, _, _ = run_cmd('systemctl is-enabled %s' % XRAY_UNIT)
    return {
        'installed': installed,
        'port': port,
        'mode': mode,
        'active': act.strip() == 'active',
        'failed': act.strip() == 'failed',
        'enabled': ena.strip() in ('enabled', 'enabled-runtime'),
    }


def xray_claims_443(x=None):
    x = x or xray_facts()
    return bool(x['installed'] and x['port'] == 443 and (x['active'] or x['enabled']))


def _other_nginx_443():
    """Чужие конфиги nginx со `listen …443` — их сайты держат 443 сами, и
    поставить рядом свой блок на 443 значит перехватить их домены нашим
    сертификатом. Файлы панели (наш и блок доступа к панели) не считаются."""
    ours = os.path.realpath(NGINX_AVAILABLE)
    files = (glob.glob('/etc/nginx/sites-enabled/*') + glob.glob('/etc/nginx/conf.d/*.conf'))
    rx = re.compile(r'^\s*listen\s+(?:[^\s;]*:)?443(?:\s|;)', re.M)
    out = []
    for f in files:
        try:
            if os.path.realpath(f) == ours or os.path.basename(f).startswith(('awg-panel-tgweb', 'awg-panel-443')):
                continue
            with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                if rx.search(fh.read()):
                    out.append(os.path.basename(f))
        except Exception:
            continue
    return out


def _owner_443():
    fn = DEPS.get('port_owner')
    if fn:
        try:
            return fn(443, 'tcp') or ''
        except Exception:
            pass
    out, _, _ = run_cmd("ss -ltnpH 'sport = :443'")
    m = re.search(r'users:\(\("([^"]+)"', out or '')
    return m.group(1) if m else ('неизвестный процесс' if (out or '').strip() else '')


def tls_cert():
    """{'found', 'fullchain', 'privkey', 'domain', 'days_left'} — тот же
    сертификат, которым XRay терминировал бы 443 (выбор по домену панели)."""
    fn = DEPS.get('tls_cert')
    if fn:
        try:
            return fn() or {'found': False}
        except Exception:
            pass
    return {'found': False}


# --- решение ------------------------------------------------------------------------

def decide(ignore_xray=False):
    """(режим 'xray'|'nginx'|'', причина, пояснение).

    Причины: 'xray_tls' | 'standalone' | 'reality' | 'nginx_sites' | 'foreign' |
    'no_cert' | 'hold'. ignore_xray — «а если XRay с 443 убрать?»: проверка до
    того, как остановить XRay по кнопке «Отдать 443 WEB-прокси»."""
    x = xray_facts()
    if not ignore_xray and xray_claims_443(x):
        if x['mode'] == 'tls':
            return 'xray', 'xray_tls', 'XRay в режиме TLS на 443 — WEB-прокси за его фоллбеком'
        return '', 'reality', (
            'На 443 стоит XRay в режиме %s%s. WebView Telegram требует настоящий сертификат '
            'домена, а Reality отдаёт чужой — вместе они на 443 не живут. Переключите XRay в TLS '
            '(оба протокола будут на 443) или выключите XRay с автозапуском — тогда 443 займёт '
            'WEB-прокси.' % ((x['mode'] or '?').upper(),
                             '' if x['active'] else ' (сейчас остановлен, но включён в автозапуск)'))
    owner = _owner_443()
    sites = _other_nginx_443()
    if sites:
        return '', 'nginx_sites', (
            '443 слушают сайты nginx (%s) — у них свои домены и сертификаты, и WEB-прокси '
            'перехватил бы их. WEB можно поставить только за XRay в режиме TLS.' % ', '.join(sites[:4]))
    # nginx на 443 без чужих сайтов с `listen 443` — это наш блок (даже если
    # отметка front потерялась, например при восстановлении из бэкапа).
    mine = owner.startswith('nginx')
    if owner and not mine and not owner.startswith('xray'):
        return '', 'foreign', ('443/tcp занят процессом «%s» — WEB-прокси встать туда не может. '
                               'Освободите порт или уберите этот сервис с 443.' % owner)
    if owner.startswith('xray') and not ignore_xray:
        # XRay висит на 443, хотя по конфигу/автозапуску не претендует (запущен
        # руками с другим конфигом) — не трогаем, подождём следующего прохода.
        return '', 'foreign', '443/tcp держит процесс xray с другим конфигом — дождитесь его остановки.'
    if not ignore_xray and int(load_settings().get('hold_until') or 0) > time.time():
        return '', 'hold', ('443 придержан для XRay: идёт его запуск, смена режима или установка. '
                            'Если XRay не займёт порт, WEB-прокси вернёт его себе через пару минут.')
    if not tls_cert().get('found'):
        return '', 'no_cert', ('XRay на 443 нет, и WEB-прокси мог бы занять порт сам, но на сервере '
                               'нет сертификата Let\'s Encrypt: WebView Telegram без настоящего '
                               'сертификата домена не подключится. Выпустите сертификат для домена, '
                               'который смотрит на этот сервер (certbot certonly), — дальше панель '
                               'сама поставит WEB на 443.')
    return 'nginx', 'standalone', 'XRay на 443 нет — WEB-прокси слушает 443 сам (nginx с сертификатом домена)'


# --- переходы ----------------------------------------------------------------------

def applied():
    return load_settings().get('front') or ''


def _set_applied(front):
    cfg = load_settings()
    if (cfg.get('front') or '') != front:
        cfg['front'] = front
        save_settings(cfg)


def _open_443():
    fn = DEPS.get('ensure_fw')
    if fn:
        try:
            fn(443, 'tcp', 'Telegram WEB (awg-panel)')
        except Exception:
            pass


def reconcile(restart_xray=True):
    """Привести цепочку к решению decide(). (изменилось, ошибка).

    Порядок шагов важен: 443 сначала освобождаем и только потом занимаем —
    два слушателя на одном порту невозможны, и упал бы тот, кто пришёл вторым."""
    from . import nginx, xray_link
    cfg = load_settings()
    if not cfg.get('enabled'):
        return False, ''
    want, reason, why = decide()
    have = cfg.get('front') or ''
    if not nginx.installed():
        return False, 'nginx не установлен'

    if want == 'xray':
        changed = have != 'xray'
        if changed:
            _set_applied('xray')                       # блок nginx уходит с 443 на 127.0.0.1
        ok, err = nginx.apply()
        if not ok:
            return changed, err
        if nginx.active():
            sync_changed, err = xray_link.sync(restart=False)
            if err:
                return changed, err
            x = xray_facts()
            # XRay включён, но лежит: возможно, не смог занять 443, пока там был
            # наш nginx. Порт свободен — поднимаем. Остановленный руками
            # (inactive) не трогаем.
            if restart_xray and (sync_changed or (changed and x['failed'])):
                if x['active'] or x['failed']:
                    xray_link.restart_xray_later()
            changed = changed or sync_changed
        if changed:
            audit('info', 'вход на 443: через XRay (TLS) — WEB-прокси за его фоллбеком')
        return changed, ''

    if want == 'nginx':
        fn = DEPS.get('panel_443_release')
        if fn:
            fn()                                       # вход панели на 443 уступает порт WEB
        changed = have != 'nginx'
        if changed:
            # Наша запись в фоллбеках XRay больше не нужна (его нет на 443).
            # Конфиг XRay правим без рестарта: он не запущен.
            try:
                xray_link.sync(remove=True, restart=False)
            except Exception:
                pass
            _set_applied('nginx')
        ok, err = nginx.apply()
        if not ok:
            _set_applied(have)
            nginx.apply()
            return False, err
        _open_443()
        if changed:
            audit('info', 'вход на 443: WEB-прокси слушает сам (nginx с сертификатом %s)'
                  % (tls_cert().get('domain') or '?'))
        return changed, ''

    # Нельзя ни так, ни так: 443 не наш. Если мы его держали — отдаём.
    changed = have == 'nginx'
    if have:
        _set_applied('')
        nginx.apply()
    if changed:
        audit('warn', 'WEB-прокси освободил 443: %s' % why)
    return changed, ''


def before_xray_claim(mode=None):
    """Хук панели перед стартом XRay, включением его автозапуска, сменой режима
    443 и установкой XRay. (можно, сообщение).

    WEB-прокси держит 443 сам → XRay туда не встанет. Если XRay будет в TLS —
    уступаем порт заранее (после старта XRay WEB переедет за его фоллбек). Если
    в Reality — отказ с объяснением, иначе XRay упал бы на «address in use»,
    а админ не понял бы почему."""
    from . import nginx, xray_link
    cfg = load_settings()
    if not cfg.get('enabled') or (cfg.get('front') or '') != 'nginx':
        return True, ''
    x = xray_facts()
    target = mode or x['mode']
    if x['installed'] and x['port'] and x['port'] != 443:
        return True, ''                                # XRay на другом порту — не мешаем
    if target != 'tls':
        return False, ('443/tcp сейчас держит Telegram WEB-прокси. XRay в режиме Reality туда не '
                       'встанет: Reality отдаёт чужой сертификат, а WEB нужен настоящий, — вместе на '
                       '443 они не живут. Переключите XRay в TLS (оба будут работать на 443) или '
                       'удалите Telegram WEB.')
    # Придерживаем 443 на время старта/установки XRay: иначе сторож через 15 с
    # увидел бы «XRay ещё не поднялся» и забрал порт обратно.
    cfg['hold_until'] = int(time.time()) + 180
    cfg['front'] = 'xray' if x['installed'] else ''
    save_settings(cfg)
    ok, err = nginx.apply()
    if not ok:
        cfg = load_settings()
        cfg['front'], cfg['hold_until'] = 'nginx', 0
        save_settings(cfg)
        nginx.apply()
        return False, 'не удалось освободить 443 для XRay: %s' % err
    if x['installed']:
        # Фоллбек в nginx — в конфиг заранее: XRay стартует уже с ним, без
        # второго рестарта ради WEB.
        try:
            xray_link.sync(restart=False)
        except Exception:
            pass
    audit('info', '443 освобождён для XRay (TLS): WEB-прокси переедет за его фоллбек')
    return True, ''


def take_443():
    """Явный выбор админа: отдать 443 WEB-прокси — остановить XRay и выключить
    его автозапуск. VLESS на этом сервере перестанет работать. (ok, сообщение)."""
    # Сначала — встанет ли WEB на 443 без XRay (сертификат, чужие сайты). Иначе
    # кнопка оставила бы сервер и без VLESS, и без WEB.
    want, _, why = decide(ignore_xray=True)
    if want != 'nginx':
        return False, 'XRay не трогали: %s' % why
    x = xray_facts()
    if x['installed'] and x['port'] == 443:
        run_cmd('systemctl disable --now %s' % XRAY_UNIT, timeout=60)
        audit('warn', 'XRay остановлен и выключен из автозапуска: 443 отдан Telegram WEB')
    changed, err = reconcile()
    if err:
        return False, err
    want, _, why = decide()
    if want != 'nginx' or applied() != 'nginx':
        return False, why
    return True, 'WEB-прокси слушает 443 сам'


def xray_start_note():
    """Что будет с WEB, если запустить остановленный XRay, пока 443 держит WEB.
    (текст, запуск_не_пройдёт); ('', False) — WEB тут ни при чём.

    Пункт об этом живёт у XRay, а не у WEB: WEB работает, и красный «!» на нём
    из-за выключенного соседа читался бы как поломка. Важно это ровно тогда,
    когда XRay решат запустить, — там и подсказываем."""
    cfg = load_settings()
    if not cfg.get('enabled') or (cfg.get('front') or '') != 'nginx':
        return '', False
    x = xray_facts()
    if not x['installed'] or (x['port'] and x['port'] != 443):
        return '', False
    if x['mode'] == 'tls':
        return ('443 сейчас держит Telegram WEB-прокси. При запуске XRay он уступит порт и уйдёт за '
                'фоллбек XRay сам — ссылки клиентов WEB не меняются.'), False
    return ('443 сейчас держит Telegram WEB-прокси, а XRay в режиме Reality — запуск не пройдёт: Reality '
            'отдаёт чужой сертификат, а WEB нужен настоящий, вместе на 443 они не живут. Переключите '
            '«Режим на 443» на TLS — XRay запустится, и оба будут работать на 443.'), True


def describe():
    """Для статуса и UI: {'front', 'want', 'reason', 'why'}."""
    want, reason, why = decide()
    return {'front': applied(), 'want': want, 'reason': reason, 'why': why}
