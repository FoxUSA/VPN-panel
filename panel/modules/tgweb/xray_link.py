"""Общий фоллбек инбаунда XRay на 443 → наш nginx.

Почему не отдельные fallbacks по путям WEB-входа: XRay выбирает, куда отдать
соединение, по пути ПЕРВОГО запроса (точное совпадение, см.
proxy/vless/inbound/inbound.go), а дальше всё соединение идёт туда же. WebView
вправе открыть соединение запросом /favicon.ico (уйдёт сайту) и тем же
keep-alive отправить /<slug>/api/v1/up — сессия сломается. nginx разводит по
КАЖДОМУ запросу, поэтому общий фоллбек отдаём ему целиком: /<slug>/ → telemt,
остальное → туда, куда фоллбек вёл раньше (Flask :5000 или свой nginx :8444).

xver 1: XRay допишет PROXY-заголовок с реальным адресом клиента, nginx
переложит его в X-Forwarded-For для telemt и X-Real-IP для панели.

Прежний адрес сохраняется в самой записи (_panel_tgweb_prev) и в настройках —
снятие WEB-прокси и сторож при падении nginx возвращают его как был.
Переключение режима 443 и переустановка XRay переписывают fallbacks целиком;
app.py пропускает их через wrap_fallbacks(), а планировщик возвращает запись,
если её всё-таки размыло.
"""
import json
import os

from . import DEPS, XRAY_MARK, audit, load_settings, run_cmd, save_settings

PREV_KEY = XRAY_MARK + '_prev'


def _xray_paths():
    fn = DEPS.get('xray_paths')
    if fn:
        try:
            p = fn() or {}
            if p.get('config'):
                return p
        except Exception:
            pass
    return {'config': '/usr/local/etc/xray/config.json', 'bin': '/usr/local/bin/xray'}


def _load():
    path = _xray_paths()['config']
    with open(path, 'r', encoding='utf-8') as f:
        return path, json.load(f)


def _inbound(cfg):
    """Инбаунд VLESS с security=tls. None — режим не TLS или нет XRay."""
    for ib in cfg.get('inbounds') or []:
        ss = ib.get('streamSettings') or {}
        if ib.get('protocol') == 'vless' and ss.get('security') == 'tls':
            return ib
    return None


def _is_default(fb):
    """Общая запись: без path / name (SNI) / alpn — та, что ловит всё прочее."""
    return isinstance(fb, dict) and not fb.get('path') and not fb.get('name') and not fb.get('alpn')


def _dest_port(dest):
    """Порт из dest фоллбека (число, «8444», «127.0.0.1:8444»). 0 — не порт
    (unix-сокет и т.п.: такой адрес telemt и nginx не проксируют)."""
    s = str(dest or '').strip()
    if s.isdigit():
        return int(s)
    if ':' in s and s.rsplit(':', 1)[1].isdigit() and not s.startswith('/'):
        host = s.rsplit(':', 1)[0].strip('[]')
        if host in ('127.0.0.1', 'localhost', '::1'):
            return int(s.rsplit(':', 1)[1])
    return 0


def wrap_fallbacks(fallbacks, cfg=None):
    """Подменить общий фоллбек на наш nginx, запомнив прежний. Для app.py:
    переключение режима 443 и установка XRay пишут свой список fallbacks —
    пропуская его через эту функцию, они не теряют WEB-прокси."""
    cfg = cfg or load_settings()
    port = int(cfg.get('nginx_port') or 0)
    if not port or not cfg.get('enabled'):
        return fallbacks
    out, found = [], False
    for fb in (fallbacks or []):
        if _is_default(fb) and not found:
            found = True
            if fb.get(XRAY_MARK):
                prev = fb.get(PREV_KEY) or {}
            else:
                prev = {'dest': fb.get('dest'), 'xver': fb.get('xver', 0)}
            out.append({'dest': port, 'xver': 1, XRAY_MARK: True, PREV_KEY: prev})
        else:
            out.append(fb)
    if not found:
        out.append({'dest': port, 'xver': 1, XRAY_MARK: True,
                    PREV_KEY: {'dest': 5000, 'xver': 0}})
    return out


def unwrap_fallbacks(fallbacks):
    """Вернуть прежний общий фоллбек на место нашего."""
    out = []
    for fb in (fallbacks or []):
        if isinstance(fb, dict) and fb.get(XRAY_MARK):
            prev = fb.get(PREV_KEY) or {'dest': 5000, 'xver': 0}
            out.append({'dest': prev.get('dest') or 5000, 'xver': prev.get('xver', 0)})
        else:
            out.append(fb)
    return out


def prev_dest_port():
    """Куда вёл общий фоллбек до нас — туда nginx отдаёт всё, кроме префикса.
    Читаем из живого конфига XRay; если записи нет — из настроек; иначе 5000."""
    try:
        _, cfg = _load()
        ib = _inbound(cfg)
        for fb in ((ib or {}).get('settings') or {}).get('fallbacks') or []:
            if _is_default(fb):
                if fb.get(XRAY_MARK):
                    p = _dest_port((fb.get(PREV_KEY) or {}).get('dest'))
                else:
                    p = _dest_port(fb.get('dest'))
                if p:
                    return p
    except Exception:
        pass
    return int(load_settings().get('prev_dest') or 0) or 5000


def state():
    """{'mode': 'tls'|'reality'|'', 'wired': bool, 'in_sync': bool, 'prev': port}."""
    try:
        _, cfg = _load()
    except Exception:
        return {'mode': '', 'wired': False, 'in_sync': False, 'prev': 0}
    ib = _inbound(cfg)
    if not ib:
        sec = ''
        for x in cfg.get('inbounds') or []:
            if x.get('protocol') == 'vless':
                sec = ((x.get('streamSettings') or {}).get('security') or '') or sec
        return {'mode': sec, 'wired': False, 'in_sync': False, 'prev': 0}
    port = int(load_settings().get('nginx_port') or 0)
    ours = [fb for fb in ((ib.get('settings') or {}).get('fallbacks') or [])
            if isinstance(fb, dict) and fb.get(XRAY_MARK)]
    wired = bool(ours)
    return {'mode': 'tls', 'wired': wired,
            'in_sync': wired and _dest_port(ours[0].get('dest')) == port and ours[0].get('xver') == 1,
            'prev': prev_dest_port()}


def restart_xray_later():
    """Рестарт XRay с задержкой через systemd-run: запрос, пришедший к панели
    через этот же XRay (фоллбек 443), успевает получить ответ. Синхронный
    restart рвал бы его посреди ответа."""
    run_cmd("systemd-run --no-block --collect /bin/bash -c 'sleep 3 && systemctl restart xray'")


def sync(remove=False, restart=True):
    """Подключить общий фоллбек к nginx (или вернуть прежний). (изменилось, ошибка).

    Перед записью — xray -test на копии: битый конфиг XRay положил бы 443
    целиком, вместе с VLESS и доступом к панели."""
    try:
        path, cfg = _load()
    except Exception as e:
        return False, 'не читается конфиг XRay: %s' % e
    ib = _inbound(cfg)
    if not ib:
        return False, 'XRay не в режиме TLS на 443'
    settings = ib.setdefault('settings', {})
    before = settings.get('fallbacks') or []
    after = unwrap_fallbacks(before) if remove else wrap_fallbacks(unwrap_fallbacks(before))
    if json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True):
        return False, ''
    if not remove:
        # Запоминаем и в настройках: если запись в XRay потом размоет чужая
        # правка, nginx всё равно будет знать, куда отдавать сайт.
        prev = next((f.get(PREV_KEY) for f in after if isinstance(f, dict) and f.get(XRAY_MARK)), {})
        st = load_settings()
        p = _dest_port((prev or {}).get('dest'))
        if p and st.get('prev_dest') != p:
            st['prev_dest'] = p
            save_settings(st)
    settings['fallbacks'] = after
    # Расширение .json обязательно: формат конфига xray определяет по нему.
    tmp = '%s.tgweb-test.json' % path
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    out, err, rc = run_cmd('%s run -test -c %s' % (_xray_paths().get('bin') or '/usr/local/bin/xray', tmp),
                           timeout=30)
    if rc != 0:
        try:
            os.remove(tmp)
        except Exception:
            pass
        return False, 'xray -test отверг конфиг: %s' % ((err or out)[-500:])
    try:
        import shutil
        shutil.copy2(path, '%s.tgweb-bak' % path)
    except Exception:
        pass
    os.replace(tmp, path)
    audit('info', 'общий фоллбек XRay %s' % ('возвращён на прежний адрес' if remove
                                             else 'переведён на nginx WEB-прокси'))
    if restart:
        restart_xray_later()
    return True, ''
