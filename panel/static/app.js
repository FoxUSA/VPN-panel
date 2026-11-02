// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 byFox (https://byfox.dev). Full text: LICENSE.
// Additional term under AGPL section 7(b): keep the author attribution, see NOTICE.
const API = '';
let refreshTimer = null;

// ⚠ в шапке и значки протоколов сами опрашиваются раз в 5 минут. Любое действие,
// меняющее состояние сервера, перечитывает их здесь: вызовы по месту терялись, и
// «новая версия» висела после обновления. Новый эндпоинт по умолчанию влияет;
// в списке — только то, что проверки не затрагивает или шлётся опросом.
const _DEPS_NO_EFFECT = new RegExp('^/api/(login|logout|audit/|clients(/|$)|xray/clients|hysteria/clients|' +
  'tgweb/clients|mtg/recipients|xray/rule-lists|xray/global|hysteria/global|backup/|xray/xdns/check|' +
  'mihomo/(select|test|inspect|providers))');
let _depsBadgeTimers = [];
// Дважды: перезапуск сервисов часто отложен, и первая проверка застаёт его на середине.
function _depsBadgeSoon() {
  _depsBadgeTimers.forEach(clearTimeout);
  _depsBadgeTimers = [2000, 9000].map(ms => setTimeout(refreshDepsBadge, ms));
}
const _nativeFetch = window.fetch.bind(window);
window.fetch = function (url, opts) {
  const p = _nativeFetch(url, opts);
  const method = ((opts && opts.method) || 'GET').toUpperCase();
  const path = String(url).split('?')[0];
  if (method !== 'GET' && method !== 'HEAD' && path.startsWith('/api/') && !_DEPS_NO_EFFECT.test(path)) {
    p.then(r => { if (r.ok) _depsBadgeSoon(); }, () => {});
  }
  return p;
};

// Login
document.getElementById('passwordInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

async function enrichLoginAuditWithRealIp(auditId) {
  // Реальный IP+гео клиента — берём у api.ru.dog (видит источник напрямую,
  // в отличие от nginx за XRay-фоллбеком, где remote_addr=127.0.0.1).
  if (!auditId) return;
  try {
    const r = await fetch('https://api.ru.dog/v1/me');
    if (!r.ok) return;
    const d = await r.json();
    if (!d || !d.ip) return;
    await fetch(API + '/api/audit/client-ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({
        audit_id: auditId,
        ip: d.ip,
        country: d.country || '',
        city: d.city || '',
      })
    }).catch(() => {});
    // Audit-strip уже отрисовался с 127.0.0.1 — перечитываем после обновления.
    if (typeof refreshAuditStrip === 'function') refreshAuditStrip();
  } catch (e) {}
}

async function doLogin() {
  const pwd = document.getElementById('passwordInput').value;
  const res = await fetch(API + '/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pwd})
  });
  if (res.ok) {
    const loginData = await res.clone().json().catch(() => ({}));
    enrichLoginAuditWithRealIp(loginData.audit_id);
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    if (window.i18nApply) window.i18nApply();
    hydrateCardsFromCache();
    hydrateClientsFromCache();
    try { applyTabOrder(); } catch (_) {}
    loadServerConfig().then(async () => {
      applyVisibilityFromConfig();
      // Пароль, сгенерированный при установке, — временный: пока он не сменён,
      // панель открыта тому, у кого есть доступ к журналу сервиса. На свежей
      // установке пусто и имя сервера — спрашиваем его после смены пароля,
      // иначе обе модалки открывались одновременно.
      if (await checkTempPassword()) return;
      if (!_serverConfig.server_name) openServerNameModal(true);
    });
    // Фоновое (зависимости, версии с apt/GitHub, апдейт) — только после живых
    // списков клиентов: у gunicorn 4 потока, и тяжёлые проверки, стартуя
    // одновременно, держали /api/status и /api/xray/status в очереди.
    refreshAll().finally(() => {
      checkForUpdates();
      refreshAuditStrip();
      // Тихая проверка зависимостей — иконка ⚠ появится в шапке если что-то NOT OK.
      // Заодно прогреваем кеш для openDepsModal: при следующем открытии модалка
      // отрисуется мгновенно из кеша.
      refreshDepsBadge();
      refreshAwgDestLogToggle();
      loadSystemVersions();
      // Вкладка миграции появится, только если на сервере нашлись остатки
      // вырезанного протокола Hysteria.
      hymigProbe();
    });
    refreshTimer = setInterval(refreshAll, 15000);
    setInterval(refreshDepsBadge, 5 * 60 * 1000);
    setInterval(refreshAuditStrip, 8000);
  } else {
    document.getElementById('loginError').textContent = 'Неверный пароль';
    document.getElementById('passwordInput').value = '';
  }
}

async function doLogout() {
  const fakeOn = !!(_serverConfig && _serverConfig.fake_enabled);
  const keyOnly = !!(_serverConfig && _serverConfig.login_block_root);
  const loginPath = (_serverConfig && _serverConfig.login_path) || '/login.html';
  await fetch(API + '/api/logout', {method: 'POST'});
  clearInterval(refreshTimer);
  if (fakeOn || keyOnly) {
    // Корень отдаёт фейк-сайт (fake) или 404 (key-only) — уводим на адрес-ключ.
    window.location.href = loginPath;
    return;
  }
  document.getElementById('dashboard').classList.add('hidden');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('passwordInput').value = '';
  document.getElementById('loginError').textContent = '';
}

const _protoRunning = {awg: null, xray: null, mtg: null, hysteria: null, tgweb: null};
let _xraySecurity = '';  // 'tls' | 'reality' — live из статуса xray, для подсказок в UI

// ============================================================
// Card hydration cache. Цель: показать предыдущие значения мгновенно после
// логина, не дожидаясь свежего API-ответа. После каждого успешного refresh-а
// карточек значение записывается в localStorage; при следующем входе из него
// мгновенно красятся поля до того, как прилетит первый запрос.
// ============================================================
const CARD_CACHE_KEY = 'awgPanel:cardCache:v1';
function _readCardCache() {
  try { return JSON.parse(localStorage.getItem(CARD_CACHE_KEY) || '{}') || {}; }
  catch (_) { return {}; }
}
function _writeCardCache(patch) {
  try {
    const cur = _readCardCache();
    Object.assign(cur, patch);
    localStorage.setItem(CARD_CACHE_KEY, JSON.stringify(cur));
  } catch (_) {}
}
// Универсальный кеш произвольных API-ответов для модалок (системные пути,
// зависимости, источники правды). При открытии модалки сначала рисуем cached,
// в фоне обновляем. При нажатии «Перепроверить» / «Обновить» показываем shimmer
// и ждём свежий ответ.
const MODAL_CACHE_KEY = 'awgPanel:modalCache:v1';
function _readModalCache(name) {
  try {
    const all = JSON.parse(localStorage.getItem(MODAL_CACHE_KEY) || '{}') || {};
    return all[name] || null;
  } catch (_) { return null; }
}
function _writeModalCache(name, data) {
  try {
    const all = JSON.parse(localStorage.getItem(MODAL_CACHE_KEY) || '{}') || {};
    all[name] = data;
    localStorage.setItem(MODAL_CACHE_KEY, JSON.stringify(all));
  } catch (_) {}
}

// Включает/выключает спиннер на кнопке «Перепроверить»/«Обновить» в модалках.
// Контент модалки остаётся на экране, кнопка показывает что идёт фоновое обновление.
// Ставит в slot значение или pending-плейсхолдер, если значение пустое/'—'.
// Нужно для карточек stats-bar где данные приходят асинхронно и до их прихода
// должен висеть аккуратный спиннер, а не «—».
function _setStatOrPending(el, value) {
  if (!el) return;
  const v = (value == null) ? '' : String(value);
  if (v && v !== '—') {
    el.textContent = v;
  } else {
    el.innerHTML = '<span class="value-pending">ожидание результата</span>';
  }
}

function _spinBtn(btnId, on, busyText) {
  const b = document.getElementById(btnId);
  if (!b) return;
  if (on) {
    if (!b.dataset.origText) b.dataset.origText = b.textContent;
    b.classList.add('is-busy');
    b.innerHTML = '<span class="btn-spinner"></span>' + (busyText || b.dataset.origText);
  } else {
    b.classList.remove('is-busy');
    if (b.dataset.origText) b.textContent = b.dataset.origText;
  }
}

function hydrateCardsFromCache() {
  const c = _readCardCache();
  // AWG
  if (c.awg && c.awg.port != null) {
    const el = document.getElementById('awgPort');
    if (el) el.textContent = c.awg.port;
  }
  // XRay
  if (c.xray) {
    if (c.xray.sni) {
      const el = document.getElementById('xraySni');
      if (el) el.textContent = c.xray.sni;
    }
    if (c.xray.port) {
      const el = document.getElementById('xrayPortSuffix');
      if (el) el.textContent = `:${c.xray.port}/TCP`;
    }
    if (c.xray.security) {
      const el = document.getElementById('xraySecMode');
      if (el) {
        el.textContent = c.xray.security === 'reality'
          ? 'Reality (маск. под чужой)'
          : 'TLS (свой сертификат)';
      }
      const hdr = document.getElementById('xrayClientsHeader');
      // Кеш карточек: про инбаунд здесь ещё ничего не известно, поэтому без
      // Hysteria — refreshXray дорисует её через секунду.
      if (hdr) hdr.textContent = _xrayClientsHeaderText(c.xray.security === 'reality', false);
    }
  }
  // MTG
  if (c.mtg) {
    if (c.mtg.port != null) {
      const el = document.getElementById('mtgPort');
      if (el) el.textContent = c.mtg.port;
    }
    if (c.mtg.fake_host) {
      const el = document.getElementById('mtgFake');
      if (el) el.textContent = c.mtg.fake_host;
    }
  }
}
function _updateHeaderDot() {
  const dot = document.getElementById('statusDot');
  if (!dot) return;
  // Фолбэк до загрузки конфига — полный список известных протоколов: без
  // Точка в шапке гасла бы на сервере, где живёт только один протокол.
  const enabled = (_serverConfig && _serverConfig.enabled_protocols) || ['awg','xray','mtg','hysteria','tgweb'];
  let anyUp = false;
  let anyKnown = false;
  for (const p of enabled) {
    const v = _protoRunning[p];
    if (v === null || v === undefined) continue;
    anyKnown = true;
    if (v) { anyUp = true; break; }
  }
  if (!anyKnown) { dot.className = 'dot dot-green'; return; }
  dot.className = 'dot ' + (anyUp ? 'dot-green' : 'dot-red');
}

// Status
async function refreshStatus() {
  try {
    const res = await fetch(API + '/api/status');
    if (res.status === 401) { doLogout(); return; }
    const data = await res.json();
    _writeClientsCache('awg', data);
    _applyAwgStatus(data, false);
  } catch (e) {
    console.error('Refresh failed:', e);
  }
}

// fromCache — отрисовка из прошлой сессии до первого живого ответа: без
// побочных запросов и без онлайна (он к этому моменту уже неправда).
function _applyAwgStatus(data, fromCache) {
    if (!fromCache) {
      _protoRunning.awg = !!data.running;
      _updateHeaderDot();
    }

    if (data.server) {
      const portEl = document.getElementById('awgPort');
      const portVal = (data.server.port != null && data.server.port !== '') ? data.server.port : null;
      if (portEl) portEl.textContent = portVal != null ? portVal : '—';
      if (portVal != null && !fromCache) _writeCardCache({awg: {port: portVal}});
      // Столкновение с соседом по UDP (инбаунд Hysteria) видно только здесь:
      // иначе оно всплывает лишь тогда, когда сервис уже не поднялся.
      if (!fromCache) refreshPortConflict('awg');
    }

    let peers = data.peers || [];
    if (fromCache) peers = peers.map(p => Object.assign({}, p, {latest_handshake: '', endpoint: '', geo: null}));
    document.getElementById('totalClients').textContent = peers.length;

    let onlineCount = 0;
    let totalBytes = 0;

    peers.forEach(p => {
      if (isOnline(p.latest_handshake)) onlineCount++;
      totalBytes += parseTransfer(p.transfer || '');
    });

    document.getElementById('onlineClients').textContent = onlineCount;
    const sv = document.getElementById('awgService');
    if (sv && !fromCache) renderProtoState(sv, data.state, data.running);

    renderPeers(peers);
}

// Последние ответы /api/status и /api/xray/status — чтобы список клиентов
// появлялся сразу после входа, а не после всех systemctl/xray api на бэке.
const CLIENTS_CACHE_KEY = 'awgPanel:clientsCache:v1';
function _readClientsCache() {
  try { return JSON.parse(localStorage.getItem(CLIENTS_CACHE_KEY) || '{}') || {}; }
  catch (_) { return {}; }
}
function _writeClientsCache(kind, data) {
  try {
    const cur = _readClientsCache();
    cur[kind] = data;
    localStorage.setItem(CLIENTS_CACHE_KEY, JSON.stringify(cur));
  } catch (_) {}
}
function hydrateClientsFromCache() {
  const c = _readClientsCache();
  try { if (c.awg) _applyAwgStatus(c.awg, true); } catch (e) { console.error(e); }
  try { if (c.xray) _applyXrayStatus(c.xray, true); } catch (e) { console.error(e); }
}

function fmtXrayTs(ts) {
  // 'YYYY/MM/DD HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS' → 'DD.MM.YYYY HH:MM:SS'.
  if (!ts || typeof ts !== 'string') return '';
  const m = ts.match(/^(\d{4})[-\/](\d{2})[-\/](\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)/);
  return m ? `${m[3]}.${m[2]}.${m[1]} ${m[4]}` : ts;
}

// Смещение СИСТЕМНОЙ таймзоны сервера от UTC (сек). Заполняется из /api/server/config.
// Все epoch-метки показываем в этой зоне, чтобы время не зависело от браузера/компа.
let _serverTzOffsetSec = null;
function _fmtServerTs(ts, withSec) {
  // unix-seconds → 'DD.MM.YYYY HH:MM[:SS]' в системной TZ сервера.
  if (!ts) return '';
  // Сдвигаем epoch на смещение сервера и читаем UTC-поля → получаем «настенное»
  // время сервера независимо от зоны браузера. Fallback — зона браузера.
  const off = (_serverTzOffsetSec != null) ? _serverTzOffsetSec
            : -new Date().getTimezoneOffset() * 60;
  const d = new Date((ts + off) * 1000);
  const p = n => String(n).padStart(2, '0');
  let s = `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}.${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
  if (withSec) s += `:${p(d.getUTCSeconds())}`;
  return s;
}
function fmtAuditTs(ts) {
  // unix-seconds → 'DD.MM.YYYY HH:MM' (без секунд), в системной TZ сервера.
  return _fmtServerTs(ts, false);
}

function renderProtoState(el, state, runningFallback) {
  if (!el) return;
  // state: 'active' | 'stopped' | 'not_installed' | 'restarting'. Старые сборки бэка без поля → fallback.
  if (!state) state = runningFallback ? 'active' : 'stopped';
  if (state === 'active') {
    el.textContent = 'активен';
    el.style.color = 'var(--green)';
  } else if (state === 'restarting') {
    el.textContent = 'перезапускается…';
    el.style.color = 'var(--orange, #f59e0b)';
  } else if (state === 'not_installed') {
    el.textContent = 'не установлен';
    el.style.color = 'var(--text3)';
  } else {
    el.textContent = 'остановлен';
    el.style.color = 'var(--red)';
  }
}

// Баннер установки на странице протокола. Второй вход в ту же установку, что и
// в «Зависимостях»: пользователь, открывший вкладку пустого протокола, не должен
// искать её в другом окне.
const PROTO_INSTALL_TEXT = {
  xray: 'XRay на сервере не установлен. Панель поставит бинарь официальным установщиком XTLS, ' +
        'подберёт свободный порт, откроет его в фаерволе и создаст рабочий инбаунд: VLESS+TLS ' +
        'с фоллбеком на панель, если у сервера есть сертификат домена, иначе VLESS+Reality.',
  mtg: 'MTProto-прокси на сервере не установлен. Панель скачает бинарь mtg, сгенерирует секрет, ' +
       'создаст конфиг и юнит с записью логов в каталог панели, подберёт свободный порт и откроет ' +
       'его в фаерволе.',
};
const PROTO_INSTALL_DEP = {xray: 'proto_xray_missing', mtg: 'proto_mtg_missing'};

function _paintInstallBanner(kind, state) {
  const box = document.getElementById(kind + 'InstallBanner');
  if (!box) return;
  const show = state === 'not_installed';
  box.classList.toggle('hidden', !show);
  if (show) {
    const t = document.getElementById(kind + 'InstallText');
    if (t) t.textContent = PROTO_INSTALL_TEXT[kind] || '';
  }
}

async function installProto(kind) {
  // Тот же путь, что у кнопки в блоке версий: подтверждение, фоновая задача,
  // ожидание с шагами. Раньше баннер слал пункт «Зависимостей», для которого не
  // было обработчика, и установка с вкладки не работала.
  if (typeof applyProtoInstall === 'function') return applyProtoInstall(kind);
  const dep = PROTO_INSTALL_DEP[kind];
  if (!dep) return;
  showBusyOverlay('Устанавливаем ' + (kind === 'xray' ? 'XRay' : 'MTProto'),
                  'Скачиваем бинарь, готовим конфиг и поднимаем сервис');
  try {
    const r = await fetch(API + '/api/system/dependencies/fix', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: dep}),
    });
    const j = await r.json().catch(() => ({}));
    toast(j.ok ? (j.output || 'Установлено') : ('Не удалось: ' + (j.error || 'см. журнал')));
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
  refreshAll();
}

function isOnline(handshake) {
  if (!handshake || handshake === '-') return false;
  // Parse "X minutes, Y seconds ago" format
  const parts = handshake.toLowerCase();
  if (parts.includes('hour') || parts.includes('day') || parts.includes('year')) return false;
  const minMatch = parts.match(/(\d+)\s*minute/);
  if (minMatch && parseInt(minMatch[1]) > 3) return false;
  return true;
}

function parseTransfer(t) {
  if (!t || t === '-') return 0;
  let total = 0;
  const parts = t.split(',');
  parts.forEach(part => {
    const match = part.trim().match(/([\d.]+)\s*(KiB|MiB|GiB|B)/);
    if (match) {
      const val = parseFloat(match[1]);
      const unit = match[2];
      if (unit === 'B') total += val;
      else if (unit === 'KiB') total += val * 1024;
      else if (unit === 'MiB') total += val * 1024 * 1024;
      else if (unit === 'GiB') total += val * 1024 * 1024 * 1024;
    }
  });
  return total;
}

function _i18nEn() { return !!(window.i18nLang && window.i18nLang() === 'en'); }

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1024*1024*1024) return (bytes/(1024*1024)).toFixed(1) + ' MB';
  return (bytes/(1024*1024*1024)).toFixed(2) + ' GB';
}

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '';
  const A = 0x1F1E6;
  return String.fromCodePoint(A + cc.toUpperCase().charCodeAt(0) - 65) +
         String.fromCodePoint(A + cc.toUpperCase().charCodeAt(1) - 65);
}

function formatBytesShort(b) {
  if (!b || b <= 0) return '0';
  const u = _i18nEn() ? [' B', ' KB', ' MB', ' GB'] : [' Б', ' КБ', ' МБ', ' ГБ'];
  if (b < 1024) return b + u[0];
  if (b < 1024*1024) return (b/1024).toFixed(1) + u[1];
  if (b < 1024*1024*1024) return (b/(1024*1024)).toFixed(1) + u[2];
  return (b/(1024*1024*1024)).toFixed(2) + u[3];
}

function renderPeers(peers) {
  _lastPeers = peers;
  if (_clientDragDefer('awg', () => renderPeers(_lastPeers))) return;
  peers = _clientOrderSort('awg', peers, p => p.public_key);
  const list = document.getElementById('peersList');
  if (peers.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="icon">&#9881;</div><p>Клиентов пока нет. Создайте первого, чтобы начать.</p></div>';
    _refreshCollapseAllBtn('awg', 'awgCollapseAllBtn');
    return;
  }

  list.innerHTML = peers.map(p => {
    const on = isOnline(p.latest_handshake);
    const pkShort = p.public_key.substring(0, 12) + '...';
    const displayName = (p.name && p.name !== 'Unknown' && p.name !== 'Unnamed') ? p.name : 'Без имени';
    if (!_seenClientIds.has(p.public_key)) { _seenClientIds.add(p.public_key); _collapsedClients.add(p.public_key); }
    const collapsed = _collapsedClients.has(p.public_key);
    const disabled = !!p.disabled;
    const schedAction = p.scheduled_action || null;
    const pkAttr = escAttr(p.public_key);
    const nameAttr = escAttr(p.name || '');
    return `
    <div class="peer-card${collapsed ? ' collapsed' : ''}" data-ckey="${pkAttr}">
      <div class="peer-top">
        <div class="peer-name">
          <div class="peer-name-row">
            <span class="status-dot ${disabled ? 'disabled' : (on ? 'online' : 'offline')}" title="${disabled ? 'Отключён' : (on ? 'Online' : 'Offline')}"></span>
            ${escHtml(displayName)}
            <span class="traffic-total traffic-total--inline" title="Накопительный трафик (↓ + ↑)">total: ${escHtml(formatBytesShort((p.up || 0) + (p.down || 0)))}${p.traffic_limit_gb ? ` &middot; limit: ${escHtml(p.traffic_limit_gb)} GB` : ''}</span>
          </div>
        </div>
        <div class="peer-actions">
          <button class="btn btn-sm btn-ghost" onclick="showConfig('${pkAttr}','${nameAttr}')">Конфиг</button>
          <button class="btn btn-sm btn-ghost btn-logs-toggle" onclick="openAwgLogs('${pkAttr}')" title="Логи" aria-label="Логи"><span class="lbl-txt">Логи</span><span class="lbl-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/><line x1="8" y1="9" x2="11" y2="9"/></svg></span></button>
          ${dnsBtnHtml(`toggleDnsLocal('${pkAttr}','${nameAttr}',${p.dns_local ? 'true' : 'false'}, null)`, !!p.dns_local, nameAttr)}
          ${pencilBtnHtml(`showRename('${pkAttr}','${nameAttr}')`)}
          ${trashBtnHtml(`showDelete('${pkAttr}','${nameAttr}')`)}
          ${powerBtnHtml(`togglePeerDisabled('awg','${pkAttr}','${nameAttr}',${disabled})`, disabled)}
          ${scheduleBtnHtml(`openScheduleModal('awg','${pkAttr}','${nameAttr}',${schedAction ? `'${schedAction}'` : 'null'},${p.scheduled_at ? `'${p.scheduled_at}'` : 'null'},${p.traffic_reset_day != null ? p.traffic_reset_day : 'null'},${p.traffic_limit_gb != null ? p.traffic_limit_gb : 'null'})`, schedAction)}
          ${collapseBtnHtml(p.public_key, collapsed)}
        </div>
      </div>
      <div class="peer-meta">
        <div class="peer-meta-item">
          <span class="lbl">IP-адрес</span>
          <span class="val">${escHtml(p.address || p.allowed_ips || '-')}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Публичный ключ</span>
          <span class="val">${escHtml(pkShort)}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Подключение</span>
          <span class="val">${escHtml(p.endpoint || '-')}${
            p.geo && p.geo.cc ? ' &middot; ' + escHtml([p.geo.country, p.geo.city].filter(Boolean).join(', ')) : ''
          }</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Последний хендшейк</span>
          <span class="val">${escHtml(translateHandshake(p.latest_handshake))}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Трафик</span>
          <span class="val">${formatTransferHTML(p.transfer)}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Создан</span>
          <span class="val">${escHtml(_fmtYmd(p.created || '-'))}</span>
        </div>
      </div>
    </div>`;
  }).join('');
  _refreshCollapseAllBtn('awg', 'awgCollapseAllBtn');
}

// 'YYYY-MM-DD HH:MM[:SS]' (так сервер пишет created) → формат панели DD.MM.YYYY HH:MM[:SS].
function _fmtYmd(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?/.exec(s || '');
  return m ? `${m[3]}.${m[2]}.${m[1]}${m[4] ? ' ' + m[4] : ''}` : s;
}

function translateHandshake(h) {
  if (!h || h === '-') return '-';
  if (_i18nEn()) return h;   // source is already English (wg output)
  return h
    .replace(/(\d+)\s*years?/gi, '$1 г.')
    .replace(/(\d+)\s*months?/gi, '$1 мес.')
    .replace(/(\d+)\s*weeks?/gi, '$1 нед.')
    .replace(/(\d+)\s*days?/gi, '$1 дн.')
    .replace(/(\d+)\s*hours?/gi, '$1 ч.')
    .replace(/(\d+)\s*minutes?/gi, '$1 мин.')
    .replace(/(\d+)\s*seconds?/gi, '$1 сек.')
    .replace(/\bago\b/gi, 'назад');
}

function translateTransfer(t) {
  if (!t || t === '-') return '-';
  if (_i18nEn()) return t;   // source is already English (wg output)
  return t
    .replace(/received/gi, 'получено')
    .replace(/sent/gi, 'отправлено')
    .replace(/\bB\b/g, 'Б')
    .replace(/KiB/g, 'КиБ')
    .replace(/MiB/g, 'МиБ')
    .replace(/GiB/g, 'ГиБ');
}

// "186.29 KiB received, 2.31 MiB sent" → "получено 186.29 КиБ<br>отправлено 2.31 МиБ"
function formatTransferHTML(t) {
  if (!t || t === '-') return '-';
  const en = _i18nEn();
  const _unit = s => en ? s : s
    .replace(/\bB\b/g, 'Б')
    .replace(/KiB/g, 'КиБ')
    .replace(/MiB/g, 'МиБ')
    .replace(/GiB/g, 'ГиБ');
  let rx = /([\d.,]+\s*[KMG]?i?B)\s+received/i.exec(t);
  let tx = /([\d.,]+\s*[KMG]?i?B)\s+sent/i.exec(t);
  if (!rx && !tx) return escHtml(translateTransfer(t));
  const lines = [];
  if (rx) lines.push((en ? 'received ' : 'получено ') + escHtml(_unit(rx[1])));
  if (tx) lines.push((en ? 'sent ' : 'отправлено ') + escHtml(_unit(tx[1])));
  return lines.join('<br>');
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}
function escAttr(s) {
  return (s || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// Modals
function showAddModal() {
  document.getElementById('newClientName').value = '';
  document.getElementById('addModal').classList.remove('hidden');
  document.getElementById('newClientName').focus();
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

let _awgCreating = false;
async function createClient() {
  if (_awgCreating) return;
  const name = document.getElementById('newClientName').value.trim();
  if (!name) return;
  _awgCreating = true;
  try {
    const res = await fetch(API + '/api/clients', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name})
    });
    const data = await res.json();
    if (res.ok) {
      closeModal('addModal');
      // «Скачать .conf» в открывшемся окне — про нового клиента, а не прошлого.
      _currentAwgPk = data.public_key || '';
      _currentAwgName = name;
      showConfigData(name, data.config);
      refreshStatus();
      toast('Клиент «' + name + '» создан');
    } else {
      toast(translateError(data.error) || 'Ошибка создания клиента');
    }
  } finally {
    _awgCreating = false;
  }
}

document.getElementById('newClientName').addEventListener('keydown', e => {
  if (e.key === 'Enter') createClient();
});

let _currentAwgPk = '';
let _currentAwgName = '';
async function showConfig(pk, name) {
  const res = await fetch(API + '/api/clients/' + encodeURIComponent(pk) + '/config');
  if (!res.ok) { toast('Конфиг недоступен (клиент создан вне панели)'); return; }
  const data = await res.json();
  _currentAwgPk = pk;
  _currentAwgName = name;
  showConfigData(name, data.config);
}

function showConfigData(name, config) {
  document.getElementById('configModalTitle').textContent = name + ' — Конфиг';
  document.getElementById('configBlock').textContent = config;
  const qrBox = document.getElementById('awgQrBox');
  qrBox.innerHTML = '';
  qrBox.style.display = 'flex';
  try {
    new QRCode(qrBox, {
      text: config,
      width: 240,
      height: 240,
      correctLevel: QRCode.CorrectLevel.M
    });
  } catch (e) {
    qrBox.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">QR недоступен</div>';
  }
  document.getElementById('configModal').classList.remove('hidden');
}

function downloadAwgConfig() {
  if (!_currentAwgPk) return;
  // open in same window — server returns Content-Disposition: attachment so browser downloads
  window.location = API + '/api/clients/' + encodeURIComponent(_currentAwgPk) + '/config-file';
}

function copyConfig() {
  const text = document.getElementById('configBlock').textContent;
  navigator.clipboard.writeText(text).then(() => toast('Конфиг скопирован'));
}

function showDelete(pk, name) {
  document.getElementById('deleteClientName').textContent = name;
  document.getElementById('confirmDeleteBtn').onclick = async () => {
    const res = await fetch(API + '/api/clients/' + encodeURIComponent(pk), {method: 'DELETE'});
    if (res.ok) {
      closeModal('deleteModal');
      refreshStatus();
      toast('Клиент «' + name + '» удалён');
    } else {
      toast('Ошибка удаления клиента');
    }
  };
  document.getElementById('deleteModal').classList.remove('hidden');
}

function showRename(pk, name) {
  document.getElementById('renameInput').value = name;
  document.getElementById('confirmRenameBtn').onclick = async () => {
    const newName = document.getElementById('renameInput').value.trim();
    if (!newName) return;
    const res = await fetch(API + '/api/clients/' + encodeURIComponent(pk) + '/rename', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: newName})
    });
    if (res.ok) {
      closeModal('renameModal');
      refreshStatus();
      toast('Переименовано в «' + newName + '»');
    } else {
      toast('Ошибка переименования');
    }
  };
  document.getElementById('renameModal').classList.remove('hidden');
  document.getElementById('renameInput').focus();
}

document.getElementById('renameInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('confirmRenameBtn').click();
});

function translateError(err) {
  if (!err) return '';
  const map = {
    'Name required': 'Введите имя',
    'Name already exists': 'Клиент с таким именем уже существует',
    'No free IPs': 'Свободных IP-адресов нет',
    'Client not found': 'Клиент не найден',
    'Wrong password': 'Неверный пароль',
    'Unauthorized': 'Требуется авторизация'
  };
  return map[err] || err;
}

const TOAST_MAX = 5;   // больше пяти на экране — нижние всё равно не читают

// Куда писать, если ошибка непонятна или похожа на недоработку панели.
const PANEL_SUPPORT_URL = 'https://byfox.dev/awg-panel/';
const _ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;

// Ошибки бэкенда часто несут хвост лога или вывод команды. Целиком в уведомлении
// это выглядело как падение панели. Первая строка — что случилось, остальное —
// технические подробности, их показываем по кнопке.
function splitErrText(msg) {
  const clean = String(msg == null ? '' : msg)
    .replace(_ANSI_RE, '').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
  const lines = clean.split('\n');
  let head = (lines.shift() || '').trim();
  let tail = lines.join('\n').trim();
  // Лог, склеенный в одну строку: обрезаем на первом признаке лога —
  // пути модуля (telemt::maestro) или метке времени ISO.
  const logAt = head.search(/[A-Za-z_]\w*::[A-Za-z_]|\d{4}-\d\d-\d\dT\d\d:/);
  if (logAt > 15) {
    tail = (head.slice(logAt) + (tail ? '\n' + tail : '')).trim();
    head = head.slice(0, logAt).replace(/[\s:—]+$/, '');
  }
  const MAX = 180;
  if (head.length > MAX) {
    const cut = Math.max(head.lastIndexOf('. ', MAX), head.lastIndexOf(': ', MAX),
                         head.lastIndexOf(' — ', MAX));
    const at = cut > 60 ? cut + 1 : MAX;
    tail = (head.slice(at).trim() + (tail ? '\n' + tail : '')).trim();
    head = head.slice(0, at).replace(/[\s:—]+$/, '') + '…';
  }
  return {head, tail};
}

function openErrDetails(head, tail) {
  openAlert({
    title: 'Подробности ошибки',
    body: `<div style="margin-bottom:10px;">${escHtml(head)}</div>`
      + `<pre class="err-details">${escHtml(tail)}</pre>`
      + `<div style="margin-top:8px;"><button class="btn btn-ghost btn-sm" data-err-copy>Скопировать</button></div>`
      + `<div class="err-support">Если непонятно, что исправить, или это похоже на недоработку панели — напишите автору и приложите эти подробности:</div>`
      + `<a class="err-support-link" href="${PANEL_SUPPORT_URL}" target="_blank" rel="noopener">byfox.dev/awg-panel</a>`,
    okLabel: 'Закрыть',
  });
  const ovs = document.querySelectorAll('.modal-overlay');
  const btn = ovs.length && ovs[ovs.length - 1].querySelector('[data-err-copy]');
  if (btn) btn.addEventListener('click', async () => {
    const text = head + '\n\n' + tail;
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      // http без TLS (вход по SSH-туннелю) — clipboard API недоступен.
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e2) {}
      ta.remove();
    }
    btn.textContent = 'Скопировано';
  });
}

function toast(msg) {
  let stack = document.getElementById('toastStack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toastStack';
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  const {head, tail} = splitErrText(msg);
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = head;
  let gone = false;
  const hide = () => {
    if (gone) return;
    gone = true;
    t.classList.add('is-out');
    setTimeout(() => t.remove(), 220);
  };
  if (tail) {
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'toast-more';
    more.textContent = 'Подробности';
    more.addEventListener('click', (e) => { e.stopPropagation(); hide(); openErrDetails(head, tail); });
    t.appendChild(more);
  }
  t.addEventListener('click', hide);           // надоел — можно убрать сразу
  stack.appendChild(t);
  // Стопка растёт вверх (column-reverse), поэтому лишние срезаем с начала — самые старые.
  while (stack.children.length > TOAST_MAX) stack.firstChild.remove();
  // С подробностями — дольше: человек должен успеть нажать.
  setTimeout(hide, tail ? 10000 : 3000);
}

// ============================================================
// Tabs (AWG / XRay) and combined refresh
// ============================================================
let currentTab = 'awg';

const TAB_IDS = ['awg', 'xray', 'mtg', 'mihomo', 'hymig'];

function switchTab(tab) {
  currentTab = tab;
  TAB_IDS.forEach(id => {
    const cap = id.charAt(0).toUpperCase() + id.slice(1);
    const t = document.getElementById('tab' + cap);
    if (t) t.classList.toggle('active', tab === id);
    const sec = document.getElementById('section' + cap);
    if (sec) sec.classList.toggle('hidden', tab !== id);
  });
  renderVersionBox();
  if (tab === 'mihomo') mhRefresh();
  if (tab === 'hymig') hymigLoad();
}

// --- Миграция со старого протокола Hysteria ---------------------------------
// Вкладка-времянка: панель протокол больше не ведёт, но на серверах, где он
// работал, остались клиенты, файлы и живой демон на UDP-порту. Появляется
// только там, где эти остатки нашлись, и исчезает после уборки.
let _hymig = null;

async function hymigProbe() {
  try {
    const r = await fetch(API + '/api/hysteria-migration', {credentials: 'same-origin'});
    const j = await r.json();
    _hymig = j && j.ok ? j : null;
    const btn = document.getElementById('tabHymig');
    if (btn) btn.classList.toggle('hidden', !(_hymig && _hymig.present));
    return _hymig;
  } catch (e) {
    return null;
  }
}

async function hymigLoad() {
  const j = await hymigProbe();
  if (!j) return;
  hymigRender();
}

// Состояние инбаунда прямо на вкладке. Без этого перенос заканчивался фразой
// «клиентов не осталось» — и было непонятно, заработала Hysteria или нет.
function hymigRenderInbound(j) {
  const box = document.getElementById('hymigInbound');
  if (!box) return;
  const hy = j.inbound || {};
  const old = j.old_settings || {};
  const pending = (j.clients || []).length;
  const wrap = (color, html) =>
    '<div style="padding:12px 14px;background:var(--bg);border:1px solid ' + color +
    ';border-left:3px solid ' + color + ';border-radius:8px;font-size:13px;line-height:1.6;">' + html + '</div>';

  if (hy.enabled) {
    const bits = ['порт <b>' + escHtml(String(hy.port || '—')) + '/UDP</b>'];
    bits.push(hy.obfs ? 'обфускация salamander' : 'без обфускации');
    if (hy.masquerade_url) {
      let m = hy.masquerade_url;
      try { m = new URL(m).hostname; } catch (e) {}
      bits.push('маскировка под ' + escHtml(m));
    }
    if (hy.cert_mode === 'self') bits.push('самоподписанный сертификат (в ссылках pinSHA256)');
    box.innerHTML = wrap('var(--green)',
      '<b style="color:var(--green);">Инбаунд Hysteria 2 работает</b><br>' +
      bits.join(' · ') +
      (hy.xray_active ? '' : '<br><span style="color:var(--red);">Но сервис XRay сейчас не запущен — Hysteria не отвечает.</span>') +
      '<div style="color:var(--text3);margin-top:8px;">Ссылка и QR — кнопка «Конфиг» на карточке клиента, блок «Hysteria 2». ' +
      'В профилях Shadowrocket / Loon / Clash рядом с VLESS появился второй узел <code>имя_HY2</code>. ' +
      'Настройки инбаунда — ⚙ на плитке «Сервис XRay».</div>');
    return;
  }

  if (pending) {
    // Сертификат — единственное, что миграция не всегда может перенести сама,
    // а цена ошибки максимальная: в ссылках зашит pinSHA256, и чужой серт
    // ломает подключение всем разом. Поэтому показываем до нажатия кнопки.
    const cert = j.cert || {};
    let certLine = '';
    if (cert.action === 'copy') {
      certLine = '<div style="color:var(--text3);margin-top:8px;">Сертификат самоподписанный' +
        (cert.fingerprint ? ' (<code>' + escHtml(String(cert.fingerprint).slice(0, 17)) + '…</code>)' : '') +
        ' — переедет к инбаунду как есть, <code>pinSHA256</code> в выданных ссылках сойдётся.</div>';
    } else if (cert.action === 'le' && !cert.warning) {
      certLine = '<div style="color:var(--text3);margin-top:8px;">Сертификат Let’s Encrypt для <b>' +
        escHtml(cert.sni || '—') + '</b> — общий с панелью, менять нечего.</div>';
    }
    const certWarn = cert.warning
      ? '<div style="margin-top:8px;color:var(--orange);"><b>Сертификат:</b> ' + escHtml(cert.warning) + '</div>'
      : '';
    box.innerHTML = wrap(cert.warning ? 'var(--orange)' : 'var(--border)',
      'Инбаунд Hysteria 2 <b>ещё не поднят</b>. Кнопка ниже остановит старый сервис и поднимет его внутри XRay' +
      (old.port ? ' на порту <b>' + escHtml(String(old.port)) + '/UDP</b>' : '') +
      (old.obfs ? ' с тем же паролем обфускации' : '') + ' — выданные ссылки продолжат работать.' +
      certLine + certWarn);
    return;
  }

  // Переносить нечего, а инбаунда нет: либо перенос не поднял его, либо инбаунд
  // выключили позже. Молчать нельзя — Hysteria в этот момент не работает.
  box.innerHTML = wrap('var(--orange)',
    '<b style="color:var(--orange);">Инбаунд Hysteria 2 не поднят — Hysteria сейчас не работает.</b><br>' +
    'Клиенты перенесены в XRay, но подключиться по Hysteria не смогут, пока инбаунд выключен.' +
    '<div style="margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">' +
    '<button class="btn btn-sm btn-success" id="hymigRaiseBtn" onclick="hymigRaise()">Поднять инбаунд</button>' +
    '<span style="color:var(--text3);font-size:12px;">' +
    (old.port ? 'Порт ' + escHtml(String(old.port)) + '/UDP и обфускация взяты от старого сервиса — ссылки не сломаются.'
              : 'Порт и остальное — из настроек в ⚙ «Сервис XRay».') +
    ' Перезапустит XRay: VLESS оборвётся на пару секунд.</span></div>');
}

async function hymigRaise() {
  showBusyOverlay('Поднимаем инбаунд Hysteria',
                  'XRay перезапускается, соединения оборвутся на пару секунд');
  try {
    await _postXrayHysteria({enabled: true});
  } finally {
    await pingUntilAlive();
    hideBusyOverlay();
    await hymigLoad();
  }
}

function hymigRender() {
  const j = _hymig;
  if (!j) return;
  hymigRenderInbound(j);
  const box = document.getElementById('hymigClients');
  const list = j.clients || [];
  if (!list.length) {
    box.innerHTML = '<div class="empty-state"><p>Клиентов не осталось — все перенесены или список пуст.</p></div>';
    document.getElementById('hymigMigrateBox').classList.add('hidden');
  } else {
    box.innerHTML = '<div style="display:grid;gap:8px;">' + list.map(c =>
      '<div style="display:flex;gap:12px;align-items:center;padding:10px 12px;background:var(--bg);' +
      'border:1px solid var(--border);border-radius:8px;flex-wrap:wrap;">' +
        '<b style="min-width:140px;">' + escHtml(c.name || '—') + '</b>' +
        '<span style="color:var(--text3);font-size:12px;">' +
          (c.created ? escHtml(_fmtServerTs(c.created)) : '') + '</span>' +
        '<span style="color:var(--text3);font-size:12px;">правил: ' + c.rules + '</span>' +
        (c.disabled ? '<span style="color:var(--orange);font-size:12px;">отключён</span>' : '') +
        (c.has_password ? '' : '<span style="color:var(--red);font-size:12px;">нет ключа — не перенесётся</span>') +
      '</div>').join('') + '</div>';
    const mb = document.getElementById('hymigMigrateBox');
    mb.classList.remove('hidden');
    document.getElementById('hymigMigrateBtn').textContent =
      'Перенести в XRay (' + list.length + ')';
  }

  const inv = j.inventory || {};
  const rows = []
    .concat((inv.units || []).map(u => ['сервис', u.unit + (u.active ? ' — работает' : ' — остановлен')]))
    .concat((inv.dirs || []).map(d => [d.kind === 'manual' ? 'каталог (ручная установка)' : 'каталог', d.path]))
    .concat((inv.files || []).map(f => [
      f.kind === 'bin' ? 'бинарь' : (f.kind === 'le-hook' ? 'хук Let’s Encrypt' : 'лог'), f.path]));
  const invBox = document.getElementById('hymigInventory');
  invBox.innerHTML = rows.length
    ? '<div style="display:grid;gap:6px;font-size:12px;">' + rows.map(([k, v]) =>
        '<div style="display:flex;gap:10px;"><span style="color:var(--text3);min-width:170px;">' +
        escHtml(k) + '</span><span style="font-family:monospace;overflow-wrap:anywhere;">' +
        escHtml(v) + '</span></div>').join('') + '</div>'
    : '<div style="color:var(--text3);font-size:12px;">Ничего не найдено — можно скрывать вкладку.</div>';
}

async function hymigMigrate(ignoreCert) {
  const n = (_hymig && (_hymig.clients || []).length) || 0;
  if (!ignoreCert) {
    const ok = await openConfirm({
      title: 'Перенести клиентов в XRay?',
      body: 'Будет остановлен старый сервис Hysteria, инбаунд поднимется на том же порту, ' +
            'и ' + n + ' клиент(ов) переедут в XRay со своими ключами, токенами подписки и правилами. ' +
            'Выданные ссылки продолжат работать. Перенесённые удалятся из старого списка.',
      okLabel: 'Перенести',
    });
    if (!ok) return;
  }
  showBusyOverlay('Переносим клиентов', 'Гасим старый сервис и поднимаем инбаунд XRay');
  try {
    const r = await fetch(API + '/api/hysteria-migration/migrate', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify(ignoreCert ? {ignore_cert: true} : {}),
    });
    const j = await r.json().catch(() => ({}));
    // Сертификат не перенёсся — это ровно тот случай, когда «просто повторить»
    // означает сломать ссылки всем. Спрашиваем явно, с ценой в тексте.
    if (r.status === 409 && j.cert_blocked) {
      hideBusyOverlay();
      const go = await openConfirm({
        title: 'Сертификат не переносится',
        body: escHtml(j.error || '') + '\n\nЕсли продолжить, инбаунд поднимется на другом сертификате: ' +
              'у клиентов со ссылками с pinSHA256 подключение перестанет проходить, и им ' +
              'понадобятся новые ссылки. Остальное (порт, пароли, обфускация) переедет как есть.',
        okLabel: 'Всё равно перенести',
        danger: true,
      });
      if (go) return hymigMigrate(true);
      await hymigLoad();
      return;
    }
    if (!r.ok || !j.ok) { toast(j.error || 'Ошибка переноса'); return; }
    _hymig = j;
    hymigRender();
    const ren = (j.renamed || []).length;
    toast('Перенесено: ' + (j.moved || []).length + (ren ? (', переименовано: ' + ren) : ''));
    refreshXray();
  } catch (e) {
    toast(e.message);
  } finally {
    await pingUntilAlive();
    hideBusyOverlay();
  }
}

async function hymigPurge() {
  const keep = !!(document.getElementById('hymigKeepClients') || {}).checked;
  const ok = await openConfirm({
    title: 'Удалить Hysteria с сервера?',
    body: 'Сервисы будут остановлены и удалены вместе с каталогами, бинарями и хуком Let’s Encrypt. ' +
          (keep ? 'Список клиентов останется на диске.' : 'Список клиентов тоже будет удалён.') +
          ' Действие необратимо.',
    okLabel: 'Удалить',
    danger: true,
  });
  if (!ok) return;
  _spinBtn('hymigPurgeBtn', true, 'Удаляем…');
  try {
    const r = await fetch(API + '/api/hysteria-migration/purge', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify({keep_clients: keep}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) {
      toast((j.error || 'Ошибка') + ((j.failed || []).length ? (': ' + j.failed[0].path) : ''));
    } else {
      toast('Удалено объектов: ' + (j.removed || []).length);
    }
    _hymig = j.present !== undefined ? j : _hymig;
    hymigRender();
    hymigProbe();
  } catch (e) {
    toast(e.message);
  } finally {
    _spinBtn('hymigPurgeBtn', false);
  }
}

async function hymigDismiss() {
  const ok = await openConfirm({
    title: 'Скрыть вкладку?',
    body: 'Страница исчезнет и больше не появится. Файлы на сервере не изменятся.',
    okLabel: 'Скрыть',
  });
  if (!ok) return;
  const r = await fetch(API + '/api/hysteria-migration/dismiss', {
    method: 'POST', credentials: 'same-origin',
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) { toast(j.error || 'Ошибка'); return; }
  document.getElementById('tabHymig').classList.add('hidden');
  switchTab('xray');
  toast('Вкладка скрыта');
}

let _systemVersions = null;
let _systemVersionsLoading = false;

async function loadSystemVersions(force) {
  if (_systemVersionsLoading) return;
  if (_systemVersions && !force) { renderVersionBox(); return; }
  _systemVersionsLoading = true;
  const box = document.getElementById('versionBox');
  if (box) box.innerHTML = '<div class="version-spin"><span class="ring"></span> Проверка версии…</div>';
  try {
    const r = await fetch(API + '/api/system/versions', {credentials: 'same-origin'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    _systemVersions = await r.json();
  } catch (e) {
    _systemVersions = null;
    if (box) box.innerHTML = '<span class="v-label">Версия:</span> <span class="dim">не удалось проверить</span>';
    return;
  } finally {
    _systemVersionsLoading = false;
  }
  renderVersionBox();
}

// Чей блок версий показывать. Вкладка «Telegram» одна на два вида прокси —
// MTProto (mtg) и WEB (telemt); какой выбран, знает переключатель в tgweb.js.
function _versionKind() {
  if (currentTab === 'mtg' && typeof window.tgSegment === 'function' && window.tgSegment() === 'web') {
    return 'tgweb';
  }
  return currentTab;
}

// Новая версия вышла, но выше потолка из манифеста — короткая причина, почему её не ставим.
function _versionHoldNote(v) {
  if (!v || !v.hold) return '';
  return v.hold === 'panel' ? 'нужна панель ' + (v.need_panel || '') : 'новая версия ещё не проверена';
}

function renderVersionBox() {
  const box = document.getElementById('versionBox');
  if (!box) return;
  if (_systemVersionsLoading) return; // спиннер уже рендерится
  if (!_systemVersions) return;
  const vk = _versionKind();
  const v = _systemVersions[vk];
  if (!v) { box.innerHTML = ''; return; }
  if (!v.installed) {
    // Панель умеет поставить протокол сама — кнопка прямо здесь, а не только
    // в «Зависимостях»: увидел «не установлен» — нажал.
    let h = '<span class="v-label">Версия:</span> <span class="dim">не установлен</span>';
    if (v.installable) {
      h += `<button class="btn btn-sm btn-success btn-update" onclick="applyProtoInstall('${vk}')">Установить</button>`;
    }
    box.innerHTML = h;
    return;
  }
  const cur = v.current || '—';
  const lat = v.latest || '—';
  const labelMap = {awg: 'AmneziaWG', xray: 'XRay', mtg: 'mtg', mihomo: 'Mihomo', hysteria: 'Hysteria',
                    tgweb: 'telemt'};
  const stale = !!v.has_update;
  const curCls = stale ? 'v-stale' : 'v-up';
  const src = v.latest_source || 'GitHub';
  const latCls = (stale && !v.hold) ? 'v-up' : 'v-latest';
  const target = v.target || lat;
  // У AWG в строке стоит версия ПАКЕТА: ею управляет apt, её и сравниваем с кандидатом.
  // Версия загруженного модуля — внутренняя метка апстрима (бывает 3.1.x при пакете
  // 1.0.x), сравнивать их нельзя, поэтому она уходит в подсказку.
  const modTip = v.module_version ? ` title="модуль в ядре: ${escAttr(v.module_version)}"` : '';
  let html = `<span class="v-line"${modTip}>${escHtml(labelMap[vk])}: <span class="v-current ${curCls}">${escHtml(cur)}</span> / ${escHtml(src)}: <span class="${latCls}">${escHtml(lat)}</span></span>`;
  if (v.hold) {
    html += `<span class="dim" style="font-size:11.5px;margin-left:8px;" title="${escAttr(v.hold_text || '')}">${escHtml(_versionHoldNote(v))}</span>`;
  }
  if (stale && v.silent_update) {
    // Обновляется тихо и с откатом — кнопка не нужна, период настраивается в модалке.
    html += `<span class="dim" style="font-size:11.5px;margin-left:8px;">обновится само</span>`;
  } else if (stale && v.updatable) {
    // При потолке последняя версия и та, что поставится, разные: на кнопке — вторая.
    html += `<button class="btn btn-sm btn-success btn-update" onclick="applyProtoUpdate('${vk}','${escAttr(target)}')">${v.hold ? 'Обновить до ' + escHtml(target) : 'Обновить'}</button>`;
  } else if (stale && !v.updatable) {
    html += `<button class="btn btn-sm btn-ghost btn-update" title="DKMS-модуль ядра, апдейт вручную — инструкция внутри" onclick="openAwgUpdateInstructions()">Инструкция</button>`;
  } else if (v.hold) {
    // Ставить пока нечего, но кнопка на месте: по нажатию человек узнает, что делать.
    html += `<button class="btn btn-sm btn-ghost btn-update" onclick="applyProtoUpdate('${vk}','')">Обновить</button>`;
  }
  box.innerHTML = html;
}

async function openAwgUpdateInstructions() {
  const ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML = `
    <div class="modal modal-wide" style="max-width:760px;max-height:85vh;display:flex;flex-direction:column;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;">
        <h3 style="margin:0;">Обновление AmneziaWG (модуль ядра) вручную</h3>
        <button class="btn btn-sm btn-ghost" data-close>✕</button>
      </div>
      <div id="awgInstrBody" style="overflow-y:auto;line-height:1.55;font-size:13px;color:var(--text);flex:1 1 auto;min-height:80px;">
        <div class="version-spin"><span class="ring"></span> Загружаем…</div>
      </div>
    </div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.querySelector('[data-close]').addEventListener('click', close);
  try {
    const r = await fetch(API + '/api/system/awg-update-instructions', {credentials: 'same-origin'});
    const j = await r.json().catch(() => ({}));
    const body = ov.querySelector('#awgInstrBody');
    if (r.ok && j.ok) {
      body.innerHTML = renderMarkdownLite(j.markdown || '');
    } else {
      body.innerHTML = '<div style="color:var(--red);">Не удалось загрузить: ' + escHtml(j.error || ('HTTP ' + r.status)) + '</div>';
    }
  } catch (e) {
    ov.querySelector('#awgInstrBody').innerHTML = '<div style="color:var(--red);">Ошибка сети: ' + escHtml(e.message) + '</div>';
  }
}

function renderMarkdownLite(md) {
  // Минималистичный рендер: H1-H3, code fences, inline code, hr, bullets, blockquote, ссылки.
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  let out = '';
  let inCode = false;
  let codeBuf = [];
  let inList = false;
  const closeList = () => { if (inList) { out += '</ul>'; inList = false; } };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.startsWith('```')) {
      if (inCode) {
        out += renderCodeBlock(codeBuf);
        codeBuf = [];
        inCode = false;
      } else {
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) { codeBuf.push(raw); continue; }
    const line = raw.trim();
    if (!line) { closeList(); out += '<div style="height:6px;"></div>'; continue; }
    if (line === '---') { closeList(); out += '<hr style="border:none;border-top:1px solid var(--border);margin:10px 0;">'; continue; }
    let m = line.match(/^(#{1,3})\s+(.*)$/);
    if (m) {
      closeList();
      const lvl = m[1].length;
      const sizes = {1: '18px', 2: '16px', 3: '14px'};
      out += `<div style="font-weight:600;font-size:${sizes[lvl]};margin:14px 0 6px;color:var(--text);">${inlineMd(m[2])}</div>`;
      continue;
    }
    if (line.startsWith('> ')) {
      closeList();
      out += `<blockquote style="border-left:3px solid var(--border);padding:4px 10px;margin:6px 0;color:var(--text3);font-size:12px;">${inlineMd(line.slice(2))}</blockquote>`;
      continue;
    }
    if (/^[-*]\s+/.test(line)) {
      if (!inList) { out += '<ul style="margin:4px 0 4px 20px;padding:0;">'; inList = true; }
      out += `<li style="margin:2px 0;">${inlineMd(line.replace(/^[-*]\s+/, ''))}</li>`;
      continue;
    }
    closeList();
    out += `<div style="margin:4px 0;">${inlineMd(line)}</div>`;
  }
  closeList();
  return out;
}

function renderCodeBlock(lines) {
  // Один <pre>-блок с построчным рендером: у каждой исполняемой строки своя кнопка
  // «копировать», комментарии и пустые строки идут без кнопки.
  const rowBase = 'display:flex;align-items:flex-start;gap:8px;padding:1px 10px;';
  const cmdBase = 'flex:1 1 auto;white-space:pre-wrap;word-break:break-all;user-select:all;font-family:JetBrains Mono,monospace;font-size:12px;line-height:1.5;';
  const btnBase = 'flex:0 0 auto;background:var(--bg2,#1f2937);border:1px solid var(--border);color:var(--text2,#9ca3af);font-size:11px;padding:1px 8px;border-radius:4px;cursor:pointer;font-family:inherit;line-height:1.4;';
  const handler = "(function(b){const t=b.previousElementSibling.textContent;navigator.clipboard.writeText(t).then(()=>{const o=b.textContent;b.textContent='\\u2713 скопировано';b.style.color='var(--green,#22c55e)';setTimeout(()=>{b.textContent=o;b.style.color='';},1200);});})(this)";
  let html = '<div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 0;margin:8px 0;overflow-x:auto;">';
  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed) {
      html += '<div style="height:6px;"></div>';
      continue;
    }
    if (trimmed.startsWith('#')) {
      html += '<div style="' + rowBase + 'color:var(--text3,#6b7280);">' +
        '<span style="' + cmdBase + '">' + escHtml(raw) + '</span></div>';
      continue;
    }
    html += '<div style="' + rowBase + '">' +
      '<span style="' + cmdBase + 'color:var(--text);">' + escHtml(raw) + '</span>' +
      '<button type="button" class="md-copy-btn" style="' + btnBase + '" onclick="' + handler + '">копировать</button>' +
      '</div>';
  }
  html += '</div>';
  return html;
}

function inlineMd(s) {
  // escape HTML сначала, потом проставить inline-фишки через токены.
  let t = escHtml(s);
  t = t.replace(/`([^`]+)`/g, '<code style="background:var(--bg);padding:1px 5px;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:12px;user-select:all;">$1</code>');
  t = t.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" style="color:var(--accent,#60a5fa);">$1</a>');
  return t;
}

async function applyProtoInstall(proto) {
  const labels = {awg: 'AmneziaWG', xray: 'XRay', mtg: 'MTProto', hysteria: 'Hysteria 2', tgweb: 'Telegram WEB'};
  const bodies = {
    awg: `Панель поставит заголовки текущего ядра, подключит репозиторий AmneziaWG, соберёт модуль DKMS, создаст серверный конфиг (ключи, свободная подсеть и порт), откроет порт в фаерволе и поднимет интерфейс.

Каждый шаг виден на экране. ⏱ 3–10 минут: основное время — компиляция модуля ядра.`,
    xray: `Панель поставит XRay официальным установщиком XTLS, подберёт свободный порт, откроет его в фаерволе и создаст рабочий инбаунд. Существующий конфиг не перезаписывается.

⏱ Обычно 30–90 секунд.`,
    mtg: `Панель скачает бинарь mtg, сгенерирует секрет, создаст конфиг и юнит с логами в каталог панели, подберёт свободный порт и откроет его в фаерволе.

⏱ Обычно 20–60 секунд.`,
    hysteria: `Панель подберёт свободный UDP-порт, скачает бинарь Hysteria 2 с GitHub под архитектуру сервера, выпустит самоподписанный сертификат, создаст конфиг и юнит <code>hysteria-server</code> и откроет порт в фаерволе.

Трафик XRay на TCP/443 это не заденет: Hysteria слушает UDP — другой сокет.

⏱ Обычно 10–40 сек.`,
    tgweb: `Панель проверит, что XRay на 443 в режиме TLS с сертификатом домена, поставит nginx (если его нет), скачает движок telemt с GitHub, выберет внутренние порты на 127.0.0.1 и переведёт общий фоллбек XRay в nginx: префикс WEB-прокси уйдёт в telemt, сайт и вход в панель — туда же, куда раньше.

Наружу новых портов не открывается — клиенты приходят на 443. В конце панель сама запросит мост через 443 так, как это делает Telegram, и покажет результат.

Каждый шаг виден на экране. ⏱ Обычно 30–90 сек.`,
  };
  const ok = await openConfirm({
    title: `Установить ${labels[proto] || proto}?`,
    body: bodies[proto] || 'Панель установит протокол и настроит его.',
    okLabel: 'Установить',
  });
  if (!ok) return;
  showBusyOverlay('Установка ' + (labels[proto] || proto) + '…',
                  proto === 'awg' ? 'Собираем модуль ядра — это несколько минут'
                                  : 'Ставим и настраиваем');
  try {
    const r = await fetch(API + '/api/system/install/' + encodeURIComponent(proto), {method: 'POST'});
    let d = await r.json();
    let ok2 = r.ok && d.ok;
    if (ok2 && d.async) {
      // Сборка модуля ядра не укладывается в пятиминутный лимит опроса.
      const done = await _pollDepFix('install:' + proto, null, Date.now(),
                                     proto === 'awg' ? 'Сборка модуля ядра' : 'Установка',
                                     proto === 'awg' ? 20 * 60 * 1000 : 10 * 60 * 1000);
      ok2 = done.ok;
      d = done.ok ? {ok: true, output: done.msg} : {ok: false, error: done.msg};
    }
    if (ok2) {
      toast((labels[proto] || proto) + ': ' + (d.output || 'установлен'));
      _systemVersions = null;
      await loadSystemVersions(true);
      refreshAll();
    } else {
      toast('Ошибка установки: ' + (d.error || 'см. вывод'));
      console.error('proto install output:', d);
    }
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
}

// Манифест закрыл обновление: говорим, что делать. Нужна новая панель — ведём туда,
// иначе ждать проверки разработчика.
async function _protoHoldExplain(text, needPanel) {
  if (!needPanel) {
    await openAlert({title: 'Обновление пока закрыто', body: escHtml(text), okLabel: 'Понятно'});
    return;
  }
  const go = await openConfirm({title: 'Сначала обновите панель', body: escHtml(text), okLabel: 'К обновлению панели'});
  if (go) openServerUpdatesModal();
}

async function applyProtoUpdate(proto, latest) {
  const vinfo = _systemVersions && _systemVersions[proto];
  if (vinfo && vinfo.hold && !vinfo.has_update) {
    await _protoHoldExplain(vinfo.hold_text, vinfo.need_panel);
    return;
  }
  const labels = {xray: 'XRay', mtg: 'mtg', awg: 'AmneziaWG', hysteria: 'Hysteria', tgweb: 'telemt'};
  const bodies = {
    xray: `Скрипт с GitHub скачает свежий бинарь XRay и перезапустит сервис. <b>VLESS-соединения оборвутся на ~2 сек.</b>\n\nКоманда:\nbash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && systemctl restart xray\n\n⏱ Обычно 10–40 сек, до 3 мин на медленном сервере.`,
    awg: `Панель обновит пакет amneziawg через apt и <b>пересоберёт модуль ядра</b> под текущее ядро, затем перезагрузит модуль и поднимет интерфейс.

<b>Туннель оборвётся на 10–30 секунд</b> — клиенты переподключатся сами.

Каждый шаг виден на экране. ⏱ Обычно 2–8 минут: основное время — компиляция.`,
    mtg: `Скачается бинарь mtg ${latest}, заменит /usr/local/bin/mtg, перезапустит сервис. <b>Telegram-соединения оборвутся на пару секунд.</b> Конфиг и секрет не трогаются.\n\n⏱ Обычно 10–30 сек.`,
    hysteria: `Скачается бинарь Hysteria ${latest} и заменит /usr/local/bin/hysteria. <b>Живые сессии оборвутся.</b> Если новая версия не запустится, панель вернёт прежнюю сама. Конфиг, клиенты и сертификат не трогаются.\n\n⏱ Обычно 10–30 сек.`,
    tgweb: `Скачается telemt ${latest} (контрольная сумма сверяется). Сначала новая версия запускается пробно рядом с рабочей на запасных портах с вашим конфигом — рабочий сервис в это время не трогается. Только если она поднялась, бинарь заменяется и сервис перезапускается; затем панель проверяет мост через 443. Не заработало — панель вернёт прежнюю версию сама.\n\n<b>Клиенты WEB переподключатся сами за пару секунд.</b>\n\n⏱ Обычно 20–60 сек.`,
  };
  const ok = await openConfirm({
    title: `Обновить ${labels[proto] || proto} до ${latest}?`,
    body: ((vinfo && vinfo.hold) ? `<div style="margin-bottom:10px;">Последняя вышедшая ${escHtml(vinfo.latest || '')} ещё не проверена с этой панелью, поэтому поставится ${escHtml(latest)}.</div>` : '') +
      (bodies[proto] || `Будет скачан свежий бинарь ${labels[proto] || proto} и перезапущен сервис.`),
    okLabel: 'Обновить',
  });
  if (!ok) return;
  showBusyOverlay('Обновление ' + (labels[proto] || proto) + '…',
                  proto === 'awg' ? 'Пересобираем модуль ядра — это несколько минут'
                                  : 'Скачиваем бинарь и перезапускаем сервис');
  try {
    const r = await fetch(API + '/api/system/update/' + encodeURIComponent(proto), {method: 'POST'});
    let d = await r.json();
    let ok = r.ok && d.ok;
    // Манифест на CDN успел поменяться после загрузки страницы: это не ошибка, а отказ.
    if (d.hold) {
      hideBusyOverlay();
      await loadSystemVersions(true);
      const fresh = _systemVersions && _systemVersions[proto];
      await _protoHoldExplain(d.error, fresh && fresh.need_panel);
      return;
    }
    // Обновление идёт в фоне: скачивание релиза не укладывается в 30-секундный
    // таймаут gunicorn, и синхронный ответ приходил бы HTML-страницей 502.
    if (ok && d.async) {
      const done = await _pollDepFix('update:' + proto, null, Date.now(),
                                     proto === 'awg' ? 'Пересборка модуля ядра'
                                                     : 'Скачиваем бинарь и перезапускаем сервис',
                                     proto === 'awg' ? 20 * 60 * 1000 : 5 * 60 * 1000);
      ok = done.ok;
      d = done.ok ? {ok: true, output: done.msg} : {ok: false, error: done.msg};
    }
    if (ok) {
      toast((labels[proto] || proto) + ': ' + (d.output || 'обновлён'));
      _systemVersions = null;
      await loadSystemVersions(true);
    } else {
      toast('Ошибка обновления: ' + (d.error || 'см. вывод'));
      console.error('proto update output:', d.output);
    }
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
}

async function restartPanel() {
  const ok = await openConfirm({
    title: 'Перезапустить панель?',
    body: 'Сервис awg-panel перезапустится. Соединение прервётся на ~3 сек, страница перезагрузится автоматически.',
    okLabel: 'Перезапустить',
  });
  if (!ok) return;
  showRestartOverlay();
  try { await fetch(API + '/api/restart', {method: 'POST'}); } catch (e) {}
  pingUntilAlive();
}

function showBusyOverlay(title, subtitle) {
  let overlay = document.getElementById('panelRestartOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'panelRestartOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(15,17,22,0.92);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;color:var(--text);font-size:15px;';
    overlay.innerHTML = `
      <div id="panelRestartTitle" style="font-size:18px;font-weight:600;"></div>
      <div id="panelRestartStatus" style="color:var(--text3);font-size:13px;"></div>
      <div class="spinner" style="width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;"></div>
      <div id="panelBusySteps" style="display:none;max-width:560px;width:calc(100% - 32px);max-height:50vh;overflow:auto;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px 14px;font-size:13px;line-height:1.5;"></div>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>`;
    document.body.appendChild(overlay);
  }
  document.getElementById('panelRestartTitle').textContent = title || 'Загрузка…';
  document.getElementById('panelRestartStatus').textContent = subtitle || '';
  const steps = document.getElementById('panelBusySteps');
  if (steps) { steps.style.display = 'none'; steps.innerHTML = ''; }
  overlay.style.display = 'flex';
}

// Пошаговый прогресс длинной операции. Без него установка модуля ядра выглядит
// как зависшая панель: спиннер крутится молча минутами.
function _renderBusySteps(steps) {
  const box = document.getElementById('panelBusySteps');
  if (!box || !Array.isArray(steps) || !steps.length) return;
  const icon = {ok: '✓', fail: '✗', run: '•', skip: '–', pending: '·'};
  const color = {ok: 'var(--green, #3a3)', fail: 'var(--red, #e55)', run: 'var(--accent)',
                 skip: 'var(--text3)', pending: 'var(--text3)'};
  box.innerHTML = steps.map(s => {
    const st = s.state || 'pending';
    const weight = st === 'run' ? '600' : '400';
    // Хвост лога в шаге — под «Подробности», как и в уведомлениях.
    const parts = s.detail ? splitErrText(s.detail) : null;
    const detail = parts
      ? `<div style="color:var(--text3);font-size:12px;margin:2px 0 0 18px;white-space:pre-wrap;word-break:break-word;">${escHtml(parts.head)}`
        + (parts.tail ? `<details class="step-details"><summary>Подробности</summary><pre class="err-details">${escHtml(parts.tail)}</pre></details>` : '')
        + `</div>`
      : '';
    return `<div style="margin:3px 0;">
      <span style="display:inline-block;width:16px;color:${color[st]};">${icon[st] || '·'}</span>
      <span style="color:${st === 'pending' ? 'var(--text3)' : 'var(--text)'};font-weight:${weight};">${escHtml(s.title || '')}</span>
      ${detail}</div>`;
  }).join('');
  box.style.display = 'block';
}
function hideBusyOverlay() {
  const overlay = document.getElementById('panelRestartOverlay');
  if (overlay) overlay.style.display = 'none';
}
function showRestartOverlay() {
  showBusyOverlay('Панель перезапускается…', 'Ждём ответа от сервиса');
}

function pingUntilAlive() {
  const status = document.getElementById('panelRestartStatus');
  let tries = 0;
  const probe = async () => {
    tries++;
    try {
      const r = await fetch(API + '/api/system/dependencies', {credentials: 'same-origin', cache: 'no-store'});
      if (r.ok) {
        if (status) status.textContent = 'Готово, обновляю страницу…';
        setTimeout(() => window.location.reload(), 400);
        return;
      }
      if (r.status === 401 || r.status === 403) {
        window.location.reload();
        return;
      }
    } catch (e) {}
    if (tries > 60) {
      if (status) status.textContent = 'Слишком долго. Обнови страницу вручную.';
      return;
    }
    if (status) status.textContent = `Ждём ответа от сервиса (${tries})`;
    setTimeout(probe, 1000);
  };
  setTimeout(probe, 1500);
}

async function refreshAll() {
  const btn = document.getElementById('refreshBtn');
  if (btn) btn.classList.add('is-loading');
  const started = Date.now();
  try {
    await Promise.all([refreshStatus(), refreshXray(), refreshMtg(), mhRefreshStatus()]);
  } finally {
    _paintProtoAlerts();
    const elapsed = Date.now() - started;
    const minSpin = 350;
    if (elapsed < minSpin) await new Promise(r => setTimeout(r, minSpin - elapsed));
    if (btn) btn.classList.remove('is-loading');
  }
}

// ============================================================
// Settings menu
// ============================================================
function toggleSettingsMenu(ev) {
  ev && ev.stopPropagation();
  document.getElementById('settingsMenu').classList.toggle('hidden');
}
function closeSettingsMenu() {
  document.getElementById('settingsMenu').classList.add('hidden');
}

// ============================================================
// Settings hub (modal with descriptions + favorites)
// ============================================================
const SETTINGS_ITEMS = [
  {
    id: 'server_name',
    title: 'Сервер и обновления',
    desc: 'Имя сервера (в шапке и в именах конфигов), обновление панели, гео-баз и шаблонов blackmatrix7, смена пароля входа.',
    open: () => openServerUpdatesModal(),
  },
  {
    id: 'profile_naming',
    title: 'Имя конфига',
    desc: 'Формат имени файла профиля при импорте у клиента: понятное имя или токен.',
    open: () => openProfileNamingModal(),
  },
  {
    id: 'protocols',
    title: 'Скрыть протоколы / платформы',
    desc: 'Прячет лишние вкладки протоколов и клиентские платформы в UI. Вместе с вкладкой уходят и проверки ' +
          'протокола в «Зависимостях» — панель перестаёт следить за его состоянием. Сервисы на сервере не ' +
          'трогает: установка, перезапуск и удаление живут на плитке «Сервис» у самого протокола.',
    open: () => openProtocolsModal(),
  },
  {
    id: 'mihomo',
    title: 'Движок Mihomo (каскад)',
    desc: 'Подключение этого сервера ко второму VPN: установка движка, версия, автообновление, автозапуск, удаление.',
    open: () => openMihomoModal(),
  },
  {
    id: 'audit',
    title: 'Журнал действий',
    desc: 'История действий в панели: входы, изменения, перезапуски.',
    open: () => openAuditModal(),
  },
  {
    id: 'backup_settings',
    title: 'Настройка бэкапа',
    desc: 'Содержимое архива, расписание, список бэкапов, восстановление.',
    open: () => openBackupModal(),
  },
  {
    id: 'backup_quick',
    title: 'Сделать бэкап',
    desc: 'Разовый бэкап прямо сейчас по текущим настройкам.',
    open: () => backupQuickRun(),
  },
  {
    id: 'system_paths',
    title: 'Системные пути',
    desc: 'Авто-детект путей всех сервисов, по вкладке на протокол (AWG, XRay, mtg, Hysteria) ' +
          'плюс общие: код панели, данные, логи, бэкап, гео-базы.',
    open: () => openSystemPathsModal(),
  },
  {
    id: 'health',
    title: 'Здоровье сервера',
    desc: 'ОЗУ, ЦП, диски, сеть, аптайм. Плюс фаервол: какие порты открыты, кто их слушает, ' +
          'что банит fail2ban и кого он никогда не тронет. И внешний мониторинг.',
    open: () => openHealthModal(),
  },
  {
    id: 'truths',
    title: 'Источники правды',
    desc: 'Что именно панель сейчас читает: IP, порты, маскировки, режимы — по вкладке на протокол. ' +
          'Выбор IP-интерфейса по умолчанию.',
    open: () => openTruthsModal(),
  },
  {
    id: 'dependencies',
    title: 'Зависимости',
    desc: 'Все модули, бинари, конфиг-секции и логи. Кнопки автофикса для каждого пункта.',
    open: () => openDepsModal(),
  },
  {
    id: 'fake_landing',
    title: 'Страница входа (маскировка)',
    desc: 'Как открывается панель: вход по IP, маскировка фейк-сайтом или вход только по ключу (для Reality). Плюс отдельный порт для доступа, когда 443 занят VPN.',
    open: () => openFakeLandingModal(),
  },
];

function _getSettingsFavSet() {
  const list = (_serverConfig && _serverConfig.settings_favorites) || ['backup_quick', 'health'];
  return new Set(list);
}

function renderGearFavorites() {
  const box = document.getElementById('gearFavorites');
  if (!box) return;
  const favs = _getSettingsFavSet();
  const items = SETTINGS_ITEMS.filter(it => favs.has(it.id));
  if (items.length === 0) { box.innerHTML = ''; return; }
  box.innerHTML = items.map(it =>
    `<button class="sm-item" data-act="${it.id}">${it.title.replace(/<[^>]+>/g,'')}</button>`
  ).join('');
  box.querySelectorAll('button[data-act]').forEach(b => {
    b.addEventListener('click', () => {
      const it = SETTINGS_ITEMS.find(x => x.id === b.dataset.act);
      closeSettingsMenu();
      if (it) it.open();
    });
  });
}

function openSettingsModal() {
  renderSettingsModalList();
  document.getElementById('settingsModal').classList.remove('hidden');
}

function renderSettingsModalList() {
  const list = document.getElementById('settingsModalList');
  const favs = _getSettingsFavSet();
  list.innerHTML = SETTINGS_ITEMS.map(it => {
    const isFav = favs.has(it.id);
    return `
      <div class="settings-hub-item">
        <div class="shi-body">
          <div class="shi-title">${it.title}</div>
          <div class="shi-desc">${it.desc}</div>
        </div>
        <div class="shi-actions">
          <button class="shi-star ${isFav?'is-fav':''}" data-fav="${it.id}" title="${isFav?'Убрать из шестерёнки':'Добавить в шестерёнку'}">★</button>
          <button class="btn btn-sm btn-success" data-open="${it.id}">Открыть</button>
        </div>
      </div>`;
  }).join('');
  list.querySelectorAll('button[data-open]').forEach(b => {
    b.addEventListener('click', () => {
      const it = SETTINGS_ITEMS.find(x => x.id === b.dataset.open);
      if (it) it.open();
    });
  });
  list.querySelectorAll('button[data-fav]').forEach(b => {
    b.addEventListener('click', () => toggleSettingFav(b.dataset.fav));
  });
}

async function toggleSettingFav(id) {
  const favs = _getSettingsFavSet();
  if (favs.has(id)) favs.delete(id); else favs.add(id);
  const next = SETTINGS_ITEMS.filter(it => favs.has(it.id)).map(it => it.id);
  try {
    const r = await fetch(API + '/api/server/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings_favorites: next }),
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || 'Не сохранено'); return; }
    _serverConfig = j.config;
    renderSettingsModalList();
    renderGearFavorites();
  } catch (e) {
    toast('Сеть: не сохранено');
  }
}

document.addEventListener('click', e => {
  const m = document.getElementById('settingsMenu');
  if (!m || m.classList.contains('hidden')) return;
  if (!e.target.closest('.settings-menu') && !e.target.closest('button[onclick*="toggleSettingsMenu"]')) {
    m.classList.add('hidden');
  }
});

async function checkTempPassword() {
  try {
    const r = await fetch(API + '/api/admin/password-state', {credentials: 'same-origin'});
    const j = await r.json();
    if (!j.must_change) return false;
    toast('Пароль временный — смените его');
    openChangePasswordModal(true);
    return true;
  } catch (e) {}
  return false;
}

function openChangePasswordModal(isTemp) {
  document.getElementById('oldPasswordInput').value = '';
  document.getElementById('newPasswordInput').value = '';
  const note = document.getElementById('passwordTempNote');
  if (note) note.classList.toggle('hidden', !isTemp);
  document.getElementById('changePasswordModal').classList.remove('hidden');
  document.getElementById('oldPasswordInput').focus();
}
async function submitChangePassword() {
  const old = document.getElementById('oldPasswordInput').value;
  const nw = document.getElementById('newPasswordInput').value;
  if (!old || nw.length < 6) { toast('Введите старый пароль и новый минимум 6 символов'); return; }
  const r = await fetch(API + '/api/admin/change-password', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({old, new: nw})
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) {
    closeModal('changePasswordModal');
    toast('Пароль изменён');
    // Очередь первого входа: имя сервера спрашиваем следом за паролем.
    if (_serverConfig && !_serverConfig.server_name) openServerNameModal(true);
  } else {
    toast(j.error || 'Ошибка смены пароля');
  }
}

let _serverConfig = null;
let _serverPaths = null;
async function loadServerConfig() {
  const r = await fetch(API + '/api/server/config');
  if (!r.ok) return null;
  const j = await r.json();
  _serverConfig = j.config || {};
  _serverPaths = j.paths || null;
  if (j.server_tz && typeof j.server_tz.offset_sec === 'number') _serverTzOffsetSec = j.server_tz.offset_sec;
  if (j.panel_version) {
    document.getElementById('brandVersion').textContent = 'v' + j.panel_version;
    const hv = document.getElementById('headerVersion');
    if (hv) hv.textContent = 'v.' + j.panel_version;
  }
  // Show server name in header if set
  const nameEl = document.getElementById('serverNameLabel');
  const sepEl = document.getElementById('serverNameSep');
  if (_serverConfig.server_name) {
    nameEl.textContent = 'Server: ' + _serverConfig.server_name;
    nameEl.style.display = 'inline';
    sepEl.style.display = 'inline';
  } else {
    nameEl.style.display = 'none';
    sepEl.style.display = 'none';
  }
  if (_serverConfig.server_ip) {
    const ipEl = document.getElementById('serverIP');
    if (ipEl) ipEl.textContent = _serverConfig.server_ip;
  }
  try { renderGearFavorites(); } catch (_) {}
  try { applyTabOrder(); } catch (_) {}
  try { applyClientOrderDom(); } catch (_) {}
  return _serverConfig;
}

// ============================================================
// Порядок вкладок: перетаскивание мышью (и долгим нажатием на телефоне).
// Две группы — протоколы (.tabs) и «MTProto | WEB» (#tgSeg, её строит
// tgweb.js). Порядок живёт в server.json (tab_order) — один на все браузеры;
// копия в localStorage нужна, чтобы при входе вкладки сразу стояли на месте.
// ============================================================
const TAB_ORDER_KEY = 'awgPanel:tabOrder';
const TAB_GROUPS = {
  main: {box: () => document.querySelector('.tabs'), item: '.tab-btn', key: el => el.id},
  tg: {box: () => document.getElementById('tgSeg'), item: 'button[data-seg]', key: el => el.dataset.seg},
};

function _tabOrderSaved() {
  const cfg = _serverConfig && _serverConfig.tab_order;
  if (cfg && typeof cfg === 'object') return cfg;
  try { return JSON.parse(localStorage.getItem(TAB_ORDER_KEY) || '{}') || {}; } catch (_) { return {}; }
}

// Расставляет вкладки по сохранённому порядку. Незнакомые (новый протокол,
// которого не было при сохранении) остаются в конце в своём исходном порядке.
function applyTabOrder() {
  const saved = _tabOrderSaved();
  for (const g of Object.keys(TAB_GROUPS)) {
    const G = TAB_GROUPS[g], box = G.box(), order = saved[g];
    if (!box || !Array.isArray(order) || !order.length) continue;
    const items = [...box.children].filter(el => el.matches(G.item));
    const pos = k => { const i = order.indexOf(k); return i < 0 ? order.length : i; };
    items
      .map((el, i) => ({el, i, p: pos(G.key(el))}))
      .sort((a, b) => a.p - b.p || a.i - b.i)
      .forEach(x => box.appendChild(x.el));
  }
}

async function _saveTabOrder(group) {
  const G = TAB_GROUPS[group], box = G.box();
  if (!box) return;
  const next = Object.assign({}, _tabOrderSaved());
  next[group] = [...box.children].filter(el => el.matches(G.item)).map(G.key);
  try { localStorage.setItem(TAB_ORDER_KEY, JSON.stringify(next)); } catch (_) {}
  if (_serverConfig) _serverConfig.tab_order = next;
  try {
    const r = await fetch(API + '/api/server/config', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({tab_order: next}),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) toast(j.error || 'Порядок вкладок не сохранён');
  } catch (_) { toast('Сеть: порядок вкладок не сохранён'); }
}

(function initTabDrag() {
  let st = null;  // {group, box, el, x0, y0, dragging, ghost, timer, touch}

  function groupOf(el) {
    for (const g of Object.keys(TAB_GROUPS)) {
      const G = TAB_GROUPS[g], box = G.box();
      if (box && el.parentNode === box && el.matches(G.item)) return g;
    }
    return null;
  }

  function siblings() {
    return [...st.box.children].filter(el => el.matches(TAB_GROUPS[st.group].item) &&
      el !== st.el && el.offsetParent !== null);
  }

  // FLIP: соседи плавно переезжают на новые места, а не прыгают.
  function moveWithFlip(mutate) {
    const sibs = siblings();
    const before = new Map(sibs.map(el => [el, el.getBoundingClientRect()]));
    mutate();
    sibs.forEach(el => {
      const a = before.get(el), b = el.getBoundingClientRect();
      const dx = a.left - b.left, dy = a.top - b.top;
      if (!dx && !dy) return;
      el.style.transition = 'none';
      el.style.transform = `translate(${dx}px, ${dy}px)`;
      requestAnimationFrame(() => {
        el.style.transition = 'transform .18s ease';
        el.style.transform = '';
        setTimeout(() => { el.style.transition = ''; }, 200);
      });
    });
  }

  function begin() {
    const r = st.el.getBoundingClientRect();
    const g = st.el.cloneNode(true);
    g.removeAttribute('id');
    g.classList.add('tab-drag-ghost');
    g.style.cssText = `position:fixed;left:${r.left}px;top:${r.top}px;width:${r.width}px;height:${r.height}px;margin:0;`;
    // Кнопки «MTProto | WEB» стилизует их контейнер: вне его копия была бы
    // голой — переносим вид с оригинала. Прозрачный фон — подложка панели.
    const cs = getComputedStyle(st.el);
    ['font', 'padding', 'color', 'letterSpacing', 'textAlign', 'display', 'alignItems', 'justifyContent', 'gap']
      .forEach(k => { g.style[k] = cs[k]; });
    const bg = cs.backgroundColor;
    g.style.background = (!bg || bg === 'transparent' || bg === 'rgba(0, 0, 0, 0)') ? 'var(--bg2)' : bg;
    document.body.classList.add('tab-dragging');
    g.style.transition = 'none';  // у .tab-btn transition: all — копия отставала бы от курсора
    document.body.appendChild(g);
    st.ghost = g;
    st.ox = st.x0 - r.left;
    st.oy = st.y0 - r.top;
    st.el.classList.add('tab-drag-placeholder');
    st.box.classList.add('tab-dragging');
    st.dragging = true;
  }

  function follow(x, y) {
    st.ghost.style.left = (x - st.ox) + 'px';
    st.ghost.style.top = (y - st.oy) + 'px';
    // Куда встать: первая соседняя вкладка, чья середина правее курсора (в той
    // же строке, если вкладки перенеслись на две строки на узком экране).
    const sibs = siblings();
    let target = null;
    for (const el of sibs) {
      const b = el.getBoundingClientRect();
      if (y < b.top - 4 || y > b.bottom + 4) continue;
      if (x < b.left + b.width / 2) { target = el; break; }
    }
    const lastInRow = !target && sibs.filter(el => {
      const b = el.getBoundingClientRect();
      return y >= b.top - 4 && y <= b.bottom + 4;
    }).pop();
    if (target) {
      if (st.el.nextElementSibling !== target) moveWithFlip(() => st.box.insertBefore(st.el, target));
    } else if (lastInRow && lastInRow.nextElementSibling !== st.el) {
      moveWithFlip(() => st.box.insertBefore(st.el, lastInRow.nextElementSibling));
    }
  }

  function finish(save) {
    const s = st;
    st = null;
    document.removeEventListener('pointermove', onMove);
    document.removeEventListener('pointerup', onUp);
    document.removeEventListener('pointercancel', onCancel);
    document.removeEventListener('touchmove', blockScroll);
    clearTimeout(s.timer);
    if (!s.dragging) return;
    // Клик после перетаскивания не должен переключать вкладку.
    document.addEventListener('click', e => { e.stopPropagation(); e.preventDefault(); }, {capture: true, once: true});
    setTimeout(() => { s.box.classList.remove('tab-dragging'); document.body.classList.remove('tab-dragging'); }, 0);
    const r = s.el.getBoundingClientRect();
    const g = s.ghost;
    g.style.transition = 'left .15s ease, top .15s ease';
    g.style.left = r.left + 'px';
    g.style.top = r.top + 'px';
    setTimeout(() => {
      g.remove();
      s.el.classList.remove('tab-drag-placeholder');
    }, 160);
    if (save) _saveTabOrder(s.group);
  }

  function onMove(e) {
    if (!st) return;
    if (!st.dragging) {
      const far = Math.abs(e.clientX - st.x0) + Math.abs(e.clientY - st.y0) > 6;
      if (st.touch) { if (far) finish(false); return; }  // палец поехал до долгого нажатия — это прокрутка
      if (!far) return;
      begin();
    }
    e.preventDefault();
    follow(e.clientX, e.clientY);
  }
  function onUp() { if (st) finish(true); }
  function onCancel() { if (st) finish(!!st.dragging); }
  function blockScroll(e) { if (st && st.dragging) e.preventDefault(); }

  document.addEventListener('pointerdown', e => {
    if (st || e.button !== 0) return;
    const el = e.target.closest && e.target.closest('.tab-btn, #tgSeg > button[data-seg]');
    if (!el) return;
    const group = groupOf(el);
    if (!group) return;
    st = {group, box: el.parentNode, el, x0: e.clientX, y0: e.clientY, dragging: false,
          touch: e.pointerType === 'touch'};
    if (st.touch) {
      // На телефоне ряд вкладок прокручивается пальцем — тащим по долгому нажатию.
      st.timer = setTimeout(() => {
        if (!st || st.dragging) return;
        begin();
        if (navigator.vibrate) try { navigator.vibrate(15); } catch (_) {}
      }, 350);
      document.addEventListener('touchmove', blockScroll, {passive: false});
    }
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
    document.addEventListener('pointercancel', onCancel);
  });
})();

// ============================================================
// Порядок клиентов: карточки перетаскиваются за шапку мышью (на телефоне —
// долгим нажатием). Свёрнутая копия карточки едет за курсором, на её месте —
// пунктирное окно «сюда встанет», соседи расступаются FLIP-анимацией.
// Global rules (карточка без data-ckey) не тащится и всегда остаётся первой:
// вставка идёт только относительно клиентских карточек, а она стоит перед ними.
// Порядок — client_order в server.json (один на все браузеры) + копия в
// localStorage, чтобы при входе карточки сразу стояли на месте.
// ============================================================
// var, не const: рендер карточек из кеша может вызваться раньше этой строки.
var CLIENT_ORDER_KEY = 'awgPanel:clientOrder';
// группа → id контейнера списка. Ключ карточки — data-ckey.
var CLIENT_ORDER_GROUPS = {xray: 'xrayList', awg: 'peersList', hy: 'hyList'};
var _clientDrag = null;              // идёт перетаскивание: перерисовка этого списка ждёт
var _clientDragDeferred = {};      // группа → отложенная перерисовка

function _clientOrderSaved() {
  const cfg = _serverConfig && _serverConfig.client_order;
  if (cfg && typeof cfg === 'object') return cfg;
  try { return JSON.parse(localStorage.getItem(CLIENT_ORDER_KEY) || '{}') || {}; } catch (_) { return {}; }
}

// Копия массива клиентов в сохранённом порядке. Незнакомые (новый клиент)
// идут в конец в исходном порядке.
function _clientOrderSort(group, arr, keyFn) {
  const order = _clientOrderSaved()[group];
  if (!Array.isArray(arr) || !Array.isArray(order) || !order.length) return arr;
  const idx = new Map(order.map((k, i) => [String(k), i]));
  return arr
    .map((c, i) => { const k = String(keyFn(c)); return {c, p: idx.has(k) ? idx.get(k) : order.length + i}; })
    .sort((a, b) => a.p - b.p)
    .map(x => x.c);
}

// Перерисовка во время перетаскивания стёрла бы карточку из-под курсора —
// откладываем её до отпускания. true = отложено, рисовать сейчас не надо.
function _clientDragDefer(group, fn) {
  if (!_clientDrag || _clientDrag.group !== group) return false;
  _clientDragDeferred[group] = fn;
  return true;
}

function _clientCards(box) {
  return [...box.children].filter(el => el.matches('.peer-card[data-ckey]'));
}

// Карточки, уже нарисованные из кеша до прихода server.json, — расставить по
// сохранённому порядку без перерисовки.
function applyClientOrderDom() {
  if (_clientDrag) return;
  const saved = _clientOrderSaved();
  for (const g of Object.keys(CLIENT_ORDER_GROUPS)) {
    const box = document.getElementById(CLIENT_ORDER_GROUPS[g]);
    const order = saved[g];
    if (!box || !Array.isArray(order) || !order.length) continue;
    const cards = _clientCards(box);
    const sorted = _clientOrderSort(g, cards, el => el.dataset.ckey);
    if (sorted.some((el, i) => el !== cards[i])) sorted.forEach(el => box.appendChild(el));
  }
}

async function _saveClientOrder(group) {
  const box = document.getElementById(CLIENT_ORDER_GROUPS[group]);
  if (!box) return;
  const next = Object.assign({}, _clientOrderSaved());
  next[group] = _clientCards(box).map(el => el.dataset.ckey);
  try { localStorage.setItem(CLIENT_ORDER_KEY, JSON.stringify(next)); } catch (_) {}
  if (_serverConfig) _serverConfig.client_order = next;
  try {
    const r = await fetch(API + '/api/server/config', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({client_order: next}),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) toast(j.error || 'Порядок клиентов не сохранён');
  } catch (_) { toast('Сеть: порядок клиентов не сохранён'); }
}

(function initClientDrag() {
  // Шапка карточки — ручка, но не её кнопки, ссылки, поля и бейджи-кнопки.
  const NOT_HANDLE = 'button, a, input, select, textarea, label, [onclick], [contenteditable]';
  let st = null;  // {group, box, el, x0, y0, y, dragging, ghost, oy, timer, touch, raf, wasOpen}

  function siblings() {
    return _clientCards(st.box).filter(el => el !== st.el && el.offsetParent !== null);
  }

  // FLIP: соседи плавно переезжают на новые места, а не прыгают.
  function moveWithFlip(mutate) {
    const sibs = siblings();
    const before = new Map(sibs.map(el => [el, el.getBoundingClientRect().top]));
    mutate();
    sibs.forEach(el => {
      const dy = before.get(el) - el.getBoundingClientRect().top;
      if (!dy) return;
      el.style.transition = 'none';
      el.style.transform = `translateY(${dy}px)`;
      requestAnimationFrame(() => {
        el.style.transition = 'transform .18s ease';
        el.style.transform = '';
        setTimeout(() => { el.style.transition = ''; }, 200);
      });
    });
  }

  function begin() {
    if (!st.el.isConnected) { finish(false); return; }
    try { window.getSelection().removeAllRanges(); } catch (_) {}
    const r = st.el.getBoundingClientRect();
    // Копия всегда свёрнутая: раскрытая карточка заняла бы пол-экрана.
    const g = st.el.cloneNode(true);
    g.querySelectorAll('[id]').forEach(n => n.removeAttribute('id'));
    g.classList.add('collapsed', 'client-drag-ghost');
    g.style.cssText = `position:fixed;left:${r.left}px;top:${r.top}px;width:${r.width}px;margin:0;`;
    document.body.appendChild(g);
    const gh = g.getBoundingClientRect().height;
    st.ghost = g;
    st.oy = Math.max(8, Math.min(st.y0 - r.top, gh - 8));
    // Раскрытую карточку на время переноса сворачиваем: огромное окно на её
    // месте мешало бы целиться. После отпускания она раскроется обратно.
    st.wasOpen = !st.el.classList.contains('collapsed');
    if (st.wasOpen) st.el.classList.add('collapsed');
    st.el.classList.add('client-drag-placeholder');
    document.body.classList.add('client-dragging');
    st.dragging = true;
    _clientDrag = st;
    follow(st.y);
    st.raf = requestAnimationFrame(autoScroll);
  }

  function follow(y) {
    st.ghost.style.top = (y - st.oy) + 'px';
    // Встать перед первой карточкой, чья середина ниже курсора; таких нет —
    // в самый конец. Global rules в siblings нет, поэтому выше неё не встать.
    const sibs = siblings();
    let target = null;
    for (const el of sibs) {
      const b = el.getBoundingClientRect();
      if (y < b.top + b.height / 2) { target = el; break; }
    }
    if (target) {
      if (st.el.nextElementSibling !== target) moveWithFlip(() => st.box.insertBefore(st.el, target));
    } else {
      const last = sibs[sibs.length - 1];
      if (last && last.nextElementSibling !== st.el) moveWithFlip(() => st.box.insertBefore(st.el, last.nextElementSibling));
    }
  }

  // У края окна список сам прокручивается — иначе длинный список не перетащить.
  function autoScroll() {
    if (!st || !st.dragging) return;
    const edge = 70, y = st.y, h = window.innerHeight;
    let dy = 0;
    if (y < edge) dy = -Math.ceil((edge - y) / 5);
    else if (y > h - edge) dy = Math.ceil((y - (h - edge)) / 5);
    if (dy) {
      const was = window.scrollY;
      window.scrollBy(0, dy);
      if (window.scrollY !== was) follow(y);
    }
    st.raf = requestAnimationFrame(autoScroll);
  }

  function finish(save) {
    const s = st;
    st = null;
    document.removeEventListener('pointermove', onMove);
    document.removeEventListener('pointerup', onUp);
    document.removeEventListener('pointercancel', onCancel);
    document.removeEventListener('touchmove', blockScroll);
    clearTimeout(s.timer);
    cancelAnimationFrame(s.raf);
    if (!s.dragging) return;
    // Клик, который браузер шлёт сразу после отпускания, не должен нажать кнопку.
    const swallow = e => { e.stopPropagation(); e.preventDefault(); };
    document.addEventListener('click', swallow, true);
    setTimeout(() => document.removeEventListener('click', swallow, true), 0);
    document.body.classList.remove('client-dragging');
    const r = s.el.getBoundingClientRect();
    const g = s.ghost;
    g.style.transition = 'left .15s ease, top .15s ease';
    g.style.left = r.left + 'px';
    g.style.top = r.top + 'px';
    // Сохраняем до отложенной перерисовки: она отсортирует уже по новому порядку.
    if (save) _saveClientOrder(s.group);
    setTimeout(() => {
      g.remove();
      s.el.classList.remove('client-drag-placeholder');
      if (s.wasOpen) s.el.classList.remove('collapsed');
      _clientDrag = null;
      const fn = _clientDragDeferred[s.group];
      delete _clientDragDeferred[s.group];
      if (fn) try { fn(); } catch (_) {}
    }, 160);
  }

  function onMove(e) {
    if (!st) return;
    st.y = e.clientY;
    if (!st.dragging) {
      const far = Math.abs(e.clientX - st.x0) + Math.abs(e.clientY - st.y0) > 6;
      if (st.touch) { if (far) finish(false); return; }  // палец поехал до долгого нажатия — это прокрутка
      if (!far) return;
      begin();
      if (!st) return;
    }
    e.preventDefault();
    follow(e.clientY);
  }
  function onUp() { if (st) finish(true); }
  function onCancel() { if (st) finish(!!st.dragging); }
  function blockScroll(e) { if (st && st.dragging) e.preventDefault(); }

  document.addEventListener('pointerdown', e => {
    if (st || _clientDrag || e.button !== 0 || !e.target.closest) return;
    // Ручка — только левая часть шапки (имя и бейджи). Ряд кнопок справа не
    // ручка: там курсор мигал бы между стрелкой кнопок и «рукой» в зазорах.
    const handle = e.target.closest('.peer-top > .peer-name');
    if (!handle || e.target.closest(NOT_HANDLE)) return;
    const top = handle.parentNode;
    const el = top.parentNode;
    if (!el || !el.matches || !el.matches('.peer-card[data-ckey]')) return;
    const box = el.parentNode;
    const group = Object.keys(CLIENT_ORDER_GROUPS).find(g => box && box.id === CLIENT_ORDER_GROUPS[g]);
    if (!group) return;
    st = {group, box, el, x0: e.clientX, y0: e.clientY, y: e.clientY, dragging: false,
          touch: e.pointerType === 'touch'};
    if (st.touch) {
      // На телефоне список листается пальцем — тащим по долгому нажатию.
      st.timer = setTimeout(() => {
        if (!st || st.dragging) return;
        begin();
        if (st && navigator.vibrate) try { navigator.vibrate(15); } catch (_) {}
      }, 350);
      document.addEventListener('touchmove', blockScroll, {passive: false});
    }
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
    document.addEventListener('pointercancel', onCancel);
  });
})();

// Sanitize input live as user types
function _setHint(modal, msg, color) {
  if (!modal) return;
  let hint = modal.querySelector('.input-hint');
  if (!hint) {
    hint = document.createElement('div');
    hint.className = 'input-hint';
    hint.style.cssText = 'font-size:12px;margin-top:-10px;margin-bottom:10px;min-height:14px;';
    const input = modal.querySelector('input[type="text"]');
    if (input && input.nextSibling) input.parentNode.insertBefore(hint, input.nextSibling);
  }
  hint.textContent = msg || '';
  hint.style.color = color || 'var(--text3)';
}

function _sanitizeServerNameInput(el) {
  const before = el.value || '';
  const hadInvalid = /[^A-Za-z0-9_\- ]/.test(before);
  let v = before.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
  el.value = v;
  const btn = document.getElementById('serverNameSaveBtn');
  if (btn) btn.disabled = !v || !_firstRunProtosOk();
  const hint = document.getElementById('serverNameHint');
  if (hint) {
    if (!v) {
      hint.textContent = hadInvalid ? 'Можно только латиницу, цифры, _ и -' : 'Введите имя';
      hint.style.color = '#fa3';
    } else if (hadInvalid) {
      hint.textContent = 'Часть символов убрана. Разрешены только латиница, цифры, _ и -';
      hint.style.color = '#fa3';
    } else {
      hint.textContent = '';
    }
  }
}
function _sanitizeClientNameInput(el) {
  const before = el.value || '';
  const hadInvalid = /[^A-Za-z0-9_\- ]/.test(before);
  let v = before.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
  el.value = v;
  const modal = el.closest('.modal');
  const btn = modal && modal.querySelector('.btn-success, .btn-primary');
  if (btn) btn.disabled = !v;
  if (!v) {
    _setHint(modal, hadInvalid ? 'Можно только латиницу, цифры, _ и -' : 'Введите имя', '#fa3');
  } else if (hadInvalid) {
    _setHint(modal, 'Часть символов убрана. Разрешены только латиница, цифры, _ и -', '#fa3');
  } else {
    _setHint(modal, '');
  }
}

function _validateLoginToken(s) {
  // Без ведущего слэша — только тело пути.
  return /^[A-Za-z0-9._-]+$/.test(s);
}
function _panelEntryOrigin() {
  // Под SSH-туннелем window.location — это localhost:8080, что вводит в заблуждение.
  // Показываем реальный адрес сервера (IP из «Источников правды» = get_server_ip()).
  const host = window.location.hostname;
  const srvIp = _serverConfig && _serverConfig.server_ip;
  if ((host === 'localhost' || host === '127.0.0.1') && srvIp) {
    return window.location.protocol + '//' + srvIp;
  }
  return window.location.origin;
}
function _publicOrigin() {
  // Публичный адрес сервера для КЛИЕНТСКИХ ссылок: профили, подписки, rule-set'ы,
  // сайт-маскировка. Это не origin вкладки: панель может быть открыта на своём
  // порту (panel_port) или через SSH-туннель на localhost, и подставлять этот
  // адрес в конфиг клиента нельзя — он светит админку наружу и перестаёт
  // открываться при смене порта. Сервер считает базис в _public_access_info().
  const pa = (_serverConfig && _serverConfig.public_access) || {};
  return pa.base || window.location.origin;
}
function _loginUrlBase() {
  // Если задан порт панели — адрес входа идёт через него (scheme/host из panel_access).
  const portRaw = ((document.getElementById('panelPortInput') || {}).value || '').trim();
  if (portRaw) {
    const pa = (_serverConfig && _serverConfig.panel_access) || {};
    const scheme = pa.scheme || window.location.protocol.replace(':', '');
    const host = pa.host || (_serverConfig && _serverConfig.server_ip) || window.location.hostname;
    return scheme + '://' + host + ':' + portRaw;
  }
  return _panelEntryOrigin();
}
function _updateFakeLoginUrlPreview() {
  const inp = document.getElementById('fakeLoginPathInput');
  const before = inp.value || '';
  // Режем всё кроме [A-Za-z0-9._-] прямо в поле — кириллица и т.п. не пройдут.
  const cleaned = before.replace(/[^A-Za-z0-9._-]/g, '');
  if (cleaned !== before) {
    const pos = inp.selectionStart - (before.length - cleaned.length);
    inp.value = cleaned;
    try { inp.setSelectionRange(pos, pos); } catch (e) {}
  }
  const token = cleaned;
  const valid = _validateLoginToken(token);
  const urlEl = document.getElementById('fakeLoginUrl');
  const hint = document.getElementById('fakeLoginPathHint');
  const btn = document.getElementById('fakeLandingSaveBtn');
  if (valid) {
    urlEl.textContent = _loginUrlBase() + '/' + token;
    hint.style.color = 'var(--text3)';
    hint.innerHTML = 'Любое слово/число. Расширение <code>.html</code> в конце <b>не нужно</b> — это путь, а не файл. Разрешены: <code>A-Z a-z 0-9 . _ -</code>.';
    btn.disabled = false;
  } else {
    urlEl.textContent = '— введите адрес —';
    hint.style.color = '#fa3';
    hint.textContent = 'Введите минимум 1 символ. Разрешены только A-Z a-z 0-9 . _ -.';
    btn.disabled = true;
  }
  // Порт правится тем же полем, а на адрес сайта он влиять не должен —
  // обновляем и его превью, чтобы разница была видна сразу.
  _updateFakeSiteUrlPreview();
}
async function openFakeLandingModal() {
  // Перечитываем server config при каждом открытии — auto-detect public_dir/index
  // должен видеть свежее состояние ФС, а не закешированное с момента логина.
  try { await loadServerConfig(); } catch (e) {}
  if (!_serverConfig) { toast('Конфиг ещё не загружен'); return; }
  // Текущий режим: key-only > fake > ip
  const mode = _serverConfig.login_block_root ? 'key' : (_serverConfig.fake_enabled ? 'fake' : 'ip');
  const radio = document.querySelector(`input[name="fakeMode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  const realityHint = document.getElementById('fakeModeRealityHint');
  if (realityHint) realityHint.style.display = (_xraySecurity === 'reality') ? '' : 'none';
  // Доступ к панели по порту
  const ppInp = document.getElementById('panelPortInput');
  const curPort = (_serverConfig.panel_port && _serverConfig.panel_port > 0) ? _serverConfig.panel_port : 0;
  if (ppInp) ppInp.value = curPort || '';
  const ppHint = document.getElementById('panelPortHint');
  if (ppHint) {
    if (_xraySecurity === 'reality' && !curPort) {
      ppHint.innerHTML = '⚠ <b>Reality на 443</b> — снаружи панель недоступна (443 занят VPN). Без отдельного порта войти можно только через SSH-туннель. Укажи порт:';
      ppHint.style.color = 'var(--accent,#60a5fa)';
    } else {
      ppHint.innerHTML = 'Отдельный порт для входа в панель, не затрагивая XRay на 443.';
      ppHint.style.color = 'var(--text3)';
    }
  }
  const ppRes = document.getElementById('panelPortResult');
  if (ppRes) ppRes.textContent = curPort ? ('Сейчас открыт порт ' + curPort) : '';
  const path = _serverConfig.login_path || '/login.html';
  const inp = document.getElementById('fakeLoginPathInput');
  // В поле — без ведущего '/', он показан как префикс в UI.
  inp.value = path.replace(/^\/+/, '');
  inp.oninput = _updateFakeLoginUrlPreview;
  _updateFakeLoginUrlPreview();
  // Подставляем реальные пути с сервера (авто-детект через __file__).
  const paths = _serverPaths || {};
  const publicDir = paths.public_dir || '/opt/awg-panel/public';
  const dirEl = document.getElementById('fakePublicDir');
  if (dirEl) dirEl.textContent = publicDir + '/';
  const dirStatus = document.getElementById('fakePublicDirStatus');
  if (dirStatus) {
    dirStatus.textContent = paths.public_exists ? '✓ существует' : '⚠ не найдена';
    dirStatus.style.color = paths.public_exists ? '#3a3' : '#fa3';
  }
  const idxStatus = document.getElementById('fakeIndexStatus');
  if (idxStatus) {
    idxStatus.textContent = paths.public_index_exists ? '✓ есть' : '⚠ нет';
    idxStatus.style.color = paths.public_index_exists ? '#3a3' : '#fa3';
  }
  const scpEl = document.getElementById('fakeScpCmd');
  if (scpEl) scpEl.textContent = `scp -r ./mysite/* root@SERVER:${publicDir}/`;
  const mkEl = document.getElementById('fakeMkdirCmd');
  if (mkEl) mkEl.textContent = `mkdir -p ${publicDir} && chown -R root:root ${publicDir}`;
  const panelRoot = paths.panel_root || '/opt/awg-panel';
  const recEl = document.getElementById('fakeRecoveryCmd');
  // server.json живёт в data/ — в корне панели только код.
  if (recEl) recEl.textContent = `sed -i 's/"fake_enabled": true/"fake_enabled": false/;s/"login_block_root": true/"login_block_root": false/' ${panelRoot}/data/server.json && systemctl restart awg-panel`;
  _onFakeModeChange();
  document.getElementById('fakeLandingModal').classList.remove('hidden');
}
function _fakeSelectedMode() {
  const el = document.querySelector('input[name="fakeMode"]:checked');
  return el ? el.value : 'ip';
}
function _updateFakeSiteUrlPreview() {
  // Адрес сайта-маскировки и адрес входа — разные вещи: сайт обязан открываться
  // по обычному https://<домен>, а порт панели ведёт только в админку. Раньше
  // здесь показывался origin вкладки, и при panel_port сайт «превращался» в
  // https://<домен>:<порт панели>, чего снаружи никто не увидит.
  const box = document.getElementById('fakeSiteUrlBox');
  const urlEl = document.getElementById('fakeSiteUrl');
  const hintEl = document.getElementById('fakeSiteUrlHint');
  if (!box || !urlEl) return;
  const pa = (_serverConfig && _serverConfig.public_access) || {};
  const port = parseInt(((document.getElementById('panelPortInput') || {}).value || '').trim(), 10) || 0;
  if (pa.base && !pa.via_panel_port) {
    urlEl.textContent = pa.base + '/';
    if (hintEl) {
      hintEl.textContent = port
        ? `Это адрес для посетителей. Порт ${port} — только вход в панель, в маскировке он не участвует.`
        : 'Это адрес для посетителей — обычный сайт на 443, без порта.';
    }
  } else if (pa.base) {
    urlEl.textContent = pa.base + '/';
    if (hintEl) {
      hintEl.textContent = (pa.security === 'reality')
        ? 'На 443 работает Reality — обычный HTTPS до панели не доходит, поэтому сайт отдаётся '
          + 'только по адресу с портом панели. Переключить режим: настройки XRay → «Режим на 443».'
        : 'Обычный HTTPS на 443 до панели не доходит, поэтому сайт отдаётся по адресу с портом панели.';
    }
  } else {
    urlEl.textContent = '— снаружи не опубликован —';
    if (hintEl) {
      hintEl.textContent = 'Нет ни сертификата домена, ни порта панели: снаружи сайт открыть неоткуда. '
        + 'Проверьте «Доступ к профилям».';
    }
  }
}
function copyFakeSiteUrl() {
  const url = (document.getElementById('fakeSiteUrl').textContent || '').trim();
  if (!url || url.startsWith('—')) { toast('Адрес сайта недоступен'); return; }
  navigator.clipboard.writeText(url).then(() => toast('Адрес сайта скопирован'));
}
function _onFakeModeChange() {
  const mode = _fakeSelectedMode();
  const needsKey = (mode === 'fake' || mode === 'key');
  const pathWrap = document.getElementById('fakeLoginPathWrap');
  const urlBox = document.getElementById('fakeLoginUrlBox');
  const filesWrap = document.getElementById('fakeFilesWrap');
  const siteBox = document.getElementById('fakeSiteUrlBox');
  if (pathWrap) pathWrap.style.display = needsKey ? '' : 'none';
  if (urlBox) urlBox.style.display = needsKey ? '' : 'none';
  if (filesWrap) filesWrap.style.display = (mode === 'fake') ? '' : 'none';
  // Адрес сайта показываем только там, где сайт реально отдаётся.
  if (siteBox) siteBox.style.display = (mode === 'fake') ? '' : 'none';
  if (mode === 'fake') _updateFakeSiteUrlPreview();
  if (needsKey) {
    _updateFakeLoginUrlPreview();
  } else {
    const btn = document.getElementById('fakeLandingSaveBtn');
    if (btn) btn.disabled = false;  // в режиме «Вход по IP» ключ не нужен
  }
}
function copyFakeLoginUrl() {
  const url = (document.getElementById('fakeLoginUrl').textContent || '').trim();
  if (!url || url.startsWith('—')) { toast('Введите корректный адрес'); return; }
  navigator.clipboard.writeText(url).then(() => toast('URL входа скопирован'));
}
async function submitFakeLanding() {
  const mode = _fakeSelectedMode();
  const tokenRaw = document.getElementById('fakeLoginPathInput').value || '';
  const token = tokenRaw.trim().replace(/^\/+/, '');
  const payload = {fake_enabled: (mode === 'fake'), login_block_root: (mode === 'key')};
  if (mode === 'fake' || mode === 'key') {
    if (!_validateLoginToken(token)) { toast('Неверный формат адреса входа'); return; }
    payload.login_path = '/' + token;
  }
  // Порт доступа: пусто = без порта. Применяется здесь же, по «Сохранить».
  const portRaw = (document.getElementById('panelPortInput').value || '').trim();
  const newPort = portRaw ? parseInt(portRaw, 10) : 0;
  if (portRaw && (!newPort || newPort < 1 || newPort > 65535)) { toast('Порт должен быть 1–65535'); return; }
  const curPort = (_serverConfig && _serverConfig.panel_port) || 0;
  const portChanged = (newPort !== curPort);

  // 1) Сохраняем режим входа
  const r = await fetch(API + '/api/server/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  const j = await r.json().catch(() => ({}));
  if (!(r.ok && j.ok)) { toast(j.error || 'Ошибка сохранения'); return; }
  _serverConfig = j.config;

  // 2) Если порт изменился — закрываем старый, открываем новый (с затемнением)
  if (portChanged) {
    showBusyOverlay(newPort ? `Открываю порт ${newPort}…` : 'Закрываю порт…',
                    'Настраиваю nginx и фаервол');
    try {
      const pr = await fetch(API + '/api/panel/access-port', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({port: newPort})
      });
      const pj = await pr.json().catch(() => ({}));
      hideBusyOverlay();
      if (!pj.ok) { toast(translateError(pj.error) || 'Ошибка настройки порта'); return; }
      if (_serverConfig) _serverConfig.panel_port = newPort;
      closeModal('fakeLandingModal');
      toast(pj.published ? ('Готово. Вход: ' + pj.url) : 'Порт закрыт — вход через 443/SSH');
    } catch (e) {
      hideBusyOverlay();
      toast('Ошибка сети: ' + e.message);
    }
    return;
  }

  // Порт не менялся — просто сохранили режим
  closeModal('fakeLandingModal');
  const url = _loginUrlBase() + '/' + token;
  toast(mode === 'ip' ? 'Вход по IP (без маскировки)'
      : mode === 'fake' ? ('Маскировка фейк-сайтом. Вход: ' + url)
      : ('Только по ключу. Вход: ' + url));
}

function openProfileNamingModal() {
  const cur = (_serverConfig && _serverConfig.profile_naming) || 'friendly';
  document.querySelectorAll('input[name="profileNaming"]').forEach(el => {
    el.checked = (el.value === cur);
  });
  document.getElementById('profileNamingModal').classList.remove('hidden');
}
async function submitProfileNaming() {
  const sel = document.querySelector('input[name="profileNaming"]:checked');
  const v = sel ? sel.value : 'friendly';
  const r = await fetch(API + '/api/server/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({profile_naming: v})
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) {
    _serverConfig = j.config;
    closeModal('profileNamingModal');
    toast('Имя конфига: ' + (v === 'friendly' ? 'понятное имя' : 'токен'));
    // refresh open config modal so URLs/VLESS link update
    const cfgModal = document.getElementById('xrayConfigModal');
    if (cfgModal && !cfgModal.classList.contains('hidden') && _currentXrayConfigUuid) {
      showXrayConfig(_currentXrayConfigUuid);
    }
  } else toast(j.error || 'Ошибка');
}

function openServerNameModal(forceFirstRun) {
  const input = document.getElementById('serverNameInput');
  input.value = (_serverConfig && _serverConfig.server_name) || '';
  document.getElementById('serverNameModalTitle').textContent = forceFirstRun
    ? 'Задайте имя сервера'
    : 'Имя сервера';
  document.getElementById('serverNameCancelBtn').style.display = forceFirstRun ? 'none' : '';
  // Первый вход: выбор протоколов — иначе новый сервер встречает значками про всё,
  // что на нём и не планировалось. Галочек нет намеренно: выбор осознанный.
  document.getElementById('serverNameProtos').classList.toggle('hidden', !forceFirstRun);
  if (forceFirstRun) {
    const list = document.getElementById('serverNameProtosList');
    list.innerHTML = ALL_PROTOCOLS.map(id => `
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
        <input type="checkbox" data-proto="${id}">
        <span>${escHtml(PROTO_LABELS[id] || id)}</span>
      </label>`).join('');
    list.onchange = () => _sanitizeServerNameInput(input);
  }
  document.getElementById('serverNameModal').classList.remove('hidden');
  input.oninput = () => _sanitizeServerNameInput(input);
  _sanitizeServerNameInput(input);
  setTimeout(() => input.focus(), 50);
}
function _firstRunProtosOk() {
  const box = document.getElementById('serverNameProtos');
  return !box || box.classList.contains('hidden') || !!box.querySelector('input:checked');
}
async function submitServerName() {
  const v = (document.getElementById('serverNameInput').value || '').trim();
  if (!v) { toast('Имя сервера не может быть пустым'); return; }
  const body = {server_name: v};
  if (!document.getElementById('serverNameProtos').classList.contains('hidden')) {
    body.enabled_protocols = Array.from(document.querySelectorAll('#serverNameProtosList input:checked')).map(el => el.dataset.proto);
  }
  const r = await fetch(API + '/api/server/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) {
    closeModal('serverNameModal');
    _serverConfig = j.config;
    await loadServerConfig();
    applyVisibilityFromConfig();
    const su = document.getElementById('serverUpdatesModal');
    if (su && !su.classList.contains('hidden')) renderServerUpdates();
    toast('Имя сервера: ' + j.config.server_name);
  } else {
    toast(j.error || 'Ошибка');
  }
}


const ALL_PROTOCOLS = ['awg', 'xray', 'mtg'];
const ALL_PLATFORMS = ['shadowrocket', 'loon', 'clash'];
const PROTO_LABELS = {awg: 'AmneziaWG', xray: 'XRay', mtg: 'MTProto'};
const PLAT_LABELS = {shadowrocket: 'Shadowrocket', loon: 'Loon', clash: 'Clash'};

function openProtocolsModal() {
  if (!_serverConfig) { toast('Конфиг ещё не загружен'); return; }
  const enabledP = new Set(_serverConfig.enabled_protocols || ALL_PROTOCOLS);
  // Протокол, которого нет в ALL_PROTOCOLS, но который значится включённым в
  // server.json, всё равно показываем. Иначе не загрузившийся протокол
  // добавляет себя в ALL_PROTOCOLS сама) вычёркивался бы из конфига навсегда
  // первым же нажатием «Сохранить».
  const known = ALL_PROTOCOLS.slice();
  for (const id of enabledP) if (!known.includes(id)) known.push(id);
  document.getElementById('protocolsList').innerHTML = known.map(id => `
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
      <input type="checkbox" data-proto="${id}" ${enabledP.has(id) ? 'checked' : ''}>
      <span>${escHtml(PROTO_LABELS[id] || id)}</span>
    </label>`).join('');
  const enabledPl = new Set(_serverConfig.enabled_platforms || ALL_PLATFORMS);
  document.getElementById('platformsList').innerHTML = ALL_PLATFORMS.map(id => `
    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
      <input type="checkbox" data-plat="${id}" ${enabledPl.has(id) ? 'checked' : ''}>
      <span>${PLAT_LABELS[id]}</span>
    </label>`).join('');
  document.getElementById('protocolsModal').classList.remove('hidden');
}
async function submitProtocols() {
  const protos = Array.from(document.querySelectorAll('#protocolsList input:checked')).map(el => el.dataset.proto);
  const plats = Array.from(document.querySelectorAll('#platformsList input:checked')).map(el => el.dataset.plat);
  const r = await fetch(API + '/api/server/config', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled_protocols: protos, enabled_platforms: plats})
  });
  const j = await r.json().catch(() => ({}));
  if (r.ok && j.ok) {
    closeModal('protocolsModal');
    _serverConfig = j.config;
    applyVisibilityFromConfig();
    toast('Сохранено');
  } else {
    toast(j.error || 'Ошибка');
  }
}

function openMtgSchedule() {
  // Reuse generic schedule modal in 'mtg' mode.
  const cur = _mtgSchedule || {action: null, date: null};
  openScheduleModal('mtg', 'mtg', 'Telegram-прокси', cur.action, cur.date);
}
let _mtgSchedule = null;

// Прежняя ⏻-кнопка «переключить сервис» на плитке mtg убрана: старт, стоп и
// перезапуск у всех протоколов теперь живут в модалке настроек протокола
// (psvcAction → /api/service/action). Маршрут /api/service/toggle на бэкенде
// оставлен — им пользуются панели, которые ещё не обновились.

// ============================================================
// Настройки протокола — одна модалка на все протоколы
// ============================================================
//
// Открывается ⚙ в правом верхнем углу плитки «Сервис». Внутри: состояние,
// настройки самого протокола, управление сервисом и удаление. До этого каждый
// протокол разбрасывал свои кнопки по тулбару, и набор у всех был разный —
// теперь точка входа одна и вид одинаковый.
//
// Адаптеры протоколов лежат в PROTO_SVC: каждый дописывает туда свой
// при загрузке: править app.js ради него не нужно.
const PROTO_SVC = {};
window.PROTO_SVC = PROTO_SVC;

let _psvcKind = null;
let _psvcState = null;
// Последние флаги протоколов — их рисуют обычные refresh-функции вкладок,
// а модалке они нужны, чтобы показать тумблеры в правильном положении.
let _xrayFlags = {stats: false, logs: false};
let _mtgFlags = {preferIp4: false};

function openProtoSvcModal(kind) {
  if (!PROTO_SVC[kind]) { toast('Для этого протокола настроек нет'); return; }
  _psvcKind = kind;
  _psvcState = null;
  _psvcHealth = null;
  document.getElementById('protoSvcTitle').textContent = 'Настройки — ' + PROTO_SVC[kind].title;
  document.getElementById('protoSvcBody').innerHTML = '<div style="color:var(--text3);">…</div>';
  document.getElementById('protoSvcModal').classList.remove('hidden');
  loadProtoSvc();
}

async function loadProtoSvc() {
  const kind = _psvcKind;
  const a = PROTO_SVC[kind];
  if (!a) return;
  // Перечитывание затирает поля значениями с сервера. Молча терять введённый,
  // но не применённый порт нельзя — это выглядит как «кнопка не работает».
  if (_hyDirty || _xdnsDirty) {
    const ok = await openConfirm({
      title: 'Изменения не сохранены',
      body: 'В настройках ' + (_hyDirty ? 'Hysteria' : 'XDNS') + ' есть изменения, которые вы не применяли. ' +
            'Перечитывание состояния заменит их тем, что сейчас на сервере.',
      okLabel: 'Перечитать и потерять',
    });
    if (!ok) return;
    _hyDirty = false;
    _psvcSyncSave();
    _xdnsDirty = false;
    _psvcSyncSave();
  }
  _spinBtn('protoSvcReloadBtn', true, 'Читаем…');
  try {
    _psvcState = await a.load();
    _paintProtoSvc();
  } catch (e) {
    document.getElementById('protoSvcBody').innerHTML =
      '<div style="color:var(--red);">Не удалось получить состояние: ' + escHtml(e.message) + '</div>';
  } finally {
    _spinBtn('protoSvcReloadBtn', false);
  }
}

function _psvcStateCards(s) {
  const svc = !s.installed ? ['не установлен', 'orange']
            : (s.active ? ['работает', 'green'] : ['остановлен', 'red']);
  const ver = _systemVersions && _systemVersions[_psvcKind];
  let verHtml = '<span style="font-size:16px;color:var(--text3);">—</span>';
  if (ver && ver.installed) {
    const stale = !!ver.has_update;
    verHtml = `<span class="${stale ? 'v-stale' : 'v-up'}" style="font-size:18px;">${escHtml(ver.current || '—')}</span>` +
      (stale ? `<div style="font-size:11.5px;color:var(--orange);margin-top:3px;">доступна ${escHtml(ver.target || ver.latest || '')}</div>`
             : `<div style="font-size:11.5px;color:var(--text3);margin-top:3px;" title="${escAttr(ver.hold_text || '')}">${escHtml(_versionHoldNote(ver) || 'актуальная версия')}</div>`);
  }
  return `
    <div class="psvc-state">
      <div class="stat-card">
        <div class="label">Сервис</div>
        <div class="value ${svc[1]}" style="font-size:20px;">${svc[0]}</div>
        ${s.unit ? `<div style="font-size:11.5px;color:var(--text3);margin-top:4px;">${escHtml(s.unit)}</div>` : ''}
      </div>
      <div class="stat-card">
        <div class="label">Версия</div>
        <div class="value" style="font-size:20px;">${verHtml}</div>
      </div>
      <div class="stat-card">
        <div class="label">Автозапуск</div>
        <div class="value ${s.autostart ? 'green' : 'orange'}" style="font-size:20px;">${s.autostart ? 'включён' : 'выключен'}</div>
        <div style="font-size:11.5px;color:var(--text3);margin-top:4px;">после перезагрузки сервера</div>
      </div>
    </div>`;
}

function _paintProtoSvc() {
  const a = PROTO_SVC[_psvcKind];
  const s = _psvcState || {};
  const box = document.getElementById('protoSvcBody');
  const ver = _systemVersions && _systemVersions[_psvcKind];
  const canUpdate = !!(ver && ver.installed && ver.has_update);

  // Кнопка обновления: у AWG это DKMS-модуль ядра, ставить его из панели нельзя —
  // там открывается инструкция, а не запуск апдейта.
  let updBtn = '';
  if (canUpdate && ver.updatable) {
    updBtn = `<button class="btn btn-sm btn-success" onclick="psvcUpdate()">Обновить до ${escHtml(ver.target || ver.latest || '')}</button>`;
  } else if (canUpdate && !ver.updatable) {
    updBtn = `<button class="btn btn-sm btn-ghost" onclick="openAwgUpdateInstructions()" title="Модуль ядра DKMS — обновление вручную по инструкции">Инструкция по обновлению</button>`;
  } else if (ver && ver.installed && ver.hold) {
    updBtn = `<button class="btn btn-sm btn-ghost" onclick="psvcUpdate()">Обновить</button>`;
  }

  const opts = a.optionsHtml ? a.optionsHtml(s) : '';
  // Снос показываем только когда протокол реально стоит: у неустановленного
  // рядом висит кнопка «Установить», и красный блок сноса под ней сбивает с толку.
  const danger = (a.uninstall && s.installed) ? `
    <div class="psvc-sec">
      <div class="psvc-sec-h">Удаление</div>
      <div class="psvc-danger">
        <div style="font-size:13px;margin-bottom:6px;">${escHtml(a.uninstall.label)}</div>
        <div style="font-size:12px;color:var(--text2);line-height:1.55;margin-bottom:10px;">${a.uninstall.body}</div>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:10px;cursor:pointer;">
          <input type="checkbox" id="psvcPurge"> <span>Удалить и данные панели по этому протоколу (клиенты, настройки)</span>
        </label>
        <button class="btn btn-sm btn-danger" onclick="psvcUninstall()">Удалить ${escHtml(a.title)}</button>
      </div>
    </div>` : (a.uninstallNote ? `
    <div class="psvc-sec">
      <div class="psvc-sec-h">Удаление</div>
      <div class="psvc-note">${a.uninstallNote}</div>
    </div>` : '');

  const manage = `
    <div class="psvc-sec">
      <div class="psvc-sec-h">Управление сервисом</div>
      <div class="psvc-actions psvc-actions-eq">
        ${s.installed ? `<button class="btn btn-sm btn-primary" onclick="psvcAction('restart')">Перезапустить</button>` : ''}
        ${s.installed && s.active ? `<button class="btn btn-sm btn-ghost" onclick="psvcAction('stop')">Остановить</button>` : ''}
        ${s.installed && !s.active ? `<button class="btn btn-sm btn-success" onclick="psvcAction('start')">Запустить</button>` : ''}
        ${!s.installed && a.install ? `<button class="btn btn-sm btn-success" onclick="psvcInstall()">Установить и запустить</button>` : ''}
        ${s.installed ? `<button class="btn btn-sm btn-ghost" onclick="psvcAction('${s.autostart ? 'autostart_off' : 'autostart_on'}')">${s.autostart ? 'Выключить автозапуск' : 'Включить автозапуск'}</button>` : ''}
        ${updBtn}
      </div>
      <div class="psvc-note" style="margin-top:10px;">${a.restartNote ||
        'Перезапуск рвёт живые соединения клиентов на пару секунд. Панель проверяет исход реально ' +
        '(<code>systemctl is-active</code>), а не по коду возврата команды.'}</div>
    </div>`;

  // У XRay несколько входов одного ядра — для клиента это разные сервисы, и
  // каждый живёт своей вкладкой. Всё общее для ядра (состояние сервиса,
  // статистика, журнал, перезапуск, удаление) — отдельной вкладкой «Ядро»,
  // а не хвостом под настройками входа, где его путали с настройками входа.
  if (a.tabsHtml) {
    box.innerHTML = `
      ${a.tabsHtml(s)}
      <div class="psvc-sec">${opts}</div>
      <div id="psvcPaneCore" class="hidden">
        <div id="psvcNext_core" class="psvc-next-slot"></div>
        <div class="psvc-sec">${_psvcStateCards(s)}</div>
        ${a.coreHtml ? `<div class="psvc-sec">${a.coreHtml(s)}</div>` : ''}
        ${manage}
        ${danger}
      </div>`;
  } else {
    box.innerHTML = `
      <div id="psvcNext_main" class="psvc-next-slot"></div>
      <div class="psvc-sec">${_psvcStateCards(s)}</div>
      ${opts ? `<div class="psvc-sec"><div class="psvc-sec-h">Настройки протокола</div>${opts}</div>` : ''}
      ${manage}
      ${danger}`;
  }
  // Модалка перерисована: вкладка снова VLESS, значит применять нечего, а
  // прежний признак «не сохранено» относился к уже затёртым полям.
  _hyDirty = false;
  _psvcSyncSave();
  _xdnsDirty = false;
  _psvcSyncSave();
  _psvcActiveTab = 'vless';
  _psvcShowSave(false);
  if (a.onMount) a.onMount(box, s);
  loadProtoHealth();
}

// === «Чтобы … заработал»: что мешает протоколу, по порядку и с кнопками ======
// Пункты приходят с сервера (/api/proto/health) — те же живые проверки, что в
// «Зависимостях», но только этого протокола: кто слушает порт, ufw, iptables
// AWG, сертификат и A-запись домена, остановленный сервис с причиной из журнала.
// Человек не должен собирать картину по разным окнам и угадывать, что важно.
let _psvcHealth = null;
let _psvcHealthLoading = false;
let _psvcHealthBusy = '';

async function loadProtoHealth() {
  const kind = _psvcKind;
  if (!kind || !document.querySelector('.psvc-next-slot')) return;
  _psvcHealthLoading = true;
  _paintPsvcHealth();
  try {
    const r = await fetch(API + '/api/proto/health?proto=' + encodeURIComponent(kind), {credentials: 'same-origin'});
    const j = await r.json().catch(() => ({}));
    if (kind !== _psvcKind) return;
    _psvcHealth = (r.ok && j.ok) ? j : {items: [], error: j.error || ('HTTP ' + r.status)};
    _protoAlertFromHealth(kind, _psvcHealth);
  } catch (e) {
    _psvcHealth = {items: [], error: e.message};
  } finally {
    _psvcHealthLoading = false;
  }
  _paintPsvcHealth();
}

const _PSVC_SCOPE_NAME = {vless: 'VLESS', hy: 'Hysteria 2', core: 'Ядро XRay'};

function _psvcHealthItems(scope) {
  const h = _psvcHealth || {};
  return (h.items || []).filter(it => scope === 'main' || it.scope === scope || it.scope === '*');
}

function _psvcHealthBlock(scope) {
  const kind = _psvcKind;
  const name = kind === 'xray' ? (_PSVC_SCOPE_NAME[scope] || 'XRay') : ((PROTO_SVC[kind] || {}).title || kind);
  // Выключенный вход Hysteria — решение пользователя, а не поломка.
  if (scope === 'hy' && _xrayHy && !_xrayHy.enabled) return '';
  if (!_psvcHealth) {
    return _psvcHealthLoading
      ? '<div class="psvc-next-wait">Проверяю ' + escHtml(name) + ': сервис, порты, фаервол…</div>' : '';
  }
  const items = _psvcHealthItems(scope);
  const when = _psvcHealth.ts ? _fmtServerTs(_psvcHealth.ts, true) : '';
  const again = '<button class="btn btn-sm btn-ghost" data-ph-recheck="1"' + (_psvcHealthLoading ? ' disabled' : '') + '>' +
    (_psvcHealthLoading ? 'Проверяю…' : 'Проверить ещё раз') + '</button>';
  if (_psvcHealth.error && !items.length) {
    return '<div class="xdns-banner xdns-off"><b>Проверить ' + escHtml(name) + ' не удалось:</b> ' +
      escHtml(_psvcHealth.error) + '<div class="xdns-row-a">' + again + '</div></div>';
  }
  if (!items.length) {
    return '<div class="psvc-next-okline"><span>✓ <b>' + escHtml(name) + '</b> — проблем не найдено' +
      (when ? ' <span class="psvc-next-ts">· проверено ' + escHtml(when) + '</span>' : '') + '</span>' + again + '</div>';
  }
  const top = items[0].level;
  const cls = top === 'block' ? 'xdns-bad' : (top === 'warn' ? 'xdns-warn' : 'xdns-off');
  const tag = {block: 'не работает', warn: 'поправить', tip: 'совет'};
  // Три группы со своими заголовками: «чтобы заработал» — только то, без чего
  // протокол у клиентов не работает; остальное отдельно, чтобы совет обновиться
  // не выглядел обязательным шагом.
  const group = (lvl) => items.filter(x => x.level === lvl);
  const nb = group('block').length;
  const heads = {
    block: 'Чтобы ' + escHtml(name) + ' заработал, ' + (nb === 1 ? 'остался один шаг:'
      : 'осталось ' + nb + ' ' + (nb < 5 ? 'шага' : 'шагов') + ' — по порядку:'),
    warn: top === 'warn' ? escHtml(name) + ' работает, но есть что поправить:' : 'Кроме того, стоит поправить:',
    tip: top === 'tip' ? 'Рекомендации для ' + escHtml(name) + ':' : 'Рекомендации:',
  };
  const row = (it, i, first) => {
    const busy = _psvcHealthBusy === it.id;
    const btns = [];
    // Обновление идёт через кнопку с подтверждением: «Исправить» рядом — та же операция без него.
    if (it.fixable && it.ui !== 'update') {
      btns.push('<button class="btn btn-sm btn-success" data-ph-fix="' + escHtml(it.id) + '"' + (busy ? ' disabled' : '') + '>' +
        (busy ? 'Исправляю…' : 'Исправить') + '</button>');
    }
    if (it.ui) {
      btns.push('<button class="btn btn-sm btn-success" data-ph-ui="' + escHtml(it.ui) + '">' +
        escHtml(it.ui_label || 'Сделать') + '</button>');
    }
    return '<div class="xdns-next' + (first ? ' is-first' : '') + ' lvl-' + it.level + '">' +
      '<span class="xdns-next-n">' + (it.level === 'block' ? i + 1 : '•') + '</span>' +
      '<div class="xdns-next-b"><div class="xdns-next-t">' + escHtml(it.name) +
        '<span class="psvc-next-tag">' + (tag[it.level] || '') + '</span></div>' +
      (it.description ? '<div class="xdns-row-d" style="white-space:pre-line;">' + escHtml(it.description) + '</div>' : '') +
      (btns.length ? '<div class="xdns-row-a">' + btns.join(' ') + '</div>' : '') +
    '</div></div>';
  };
  let body = '';
  for (const lvl of ['block', 'warn', 'tip']) {
    const g = group(lvl);
    if (!g.length) continue;
    body += (body ? '<div class="psvc-next-sub">' + heads[lvl] + '</div>' : '<b>' + heads[lvl] + '</b>') +
      g.map((it, i) => row(it, i, lvl === top && i === 0)).join('');
  }
  return '<div class="xdns-banner ' + cls + '">' + body +
    '<div class="psvc-next-foot"><span>' + (when ? 'Проверено ' + escHtml(when) : '') + '</span>' + again + '</div></div>';
}

function _paintPsvcHealth() {
  for (const slot of document.querySelectorAll('.psvc-next-slot')) {
    const scope = slot.id.replace('psvcNext_', '');
    slot.innerHTML = _psvcHealthBlock(scope);
    // Обработчики кодом: escHtml кавычки не экранирует.
    for (const b of slot.querySelectorAll('[data-ph-fix]')) b.addEventListener('click', () => psvcHealthFix(b.dataset.phFix));
    for (const b of slot.querySelectorAll('[data-ph-ui]')) b.addEventListener('click', () => psvcHealthUi(b.dataset.phUi));
    for (const b of slot.querySelectorAll('[data-ph-recheck]')) b.addEventListener('click', () => loadProtoHealth());
  }
  // Точки на вкладках XRay: красная — вход не работает, оранжевая — есть что поправить.
  if (_psvcKind === 'xray' && _psvcHealth && !_psvcHealthLoading) {
    for (const [scope, id] of [['vless', 'psvcTabVlessDot'], ['core', 'psvcTabCoreDot']]) {
      if (scope === 'core' && !(_psvcState || {}).active) continue;
      const its = _psvcHealthItems(scope).filter(x => x.level !== 'tip');
      _psvcTabDot(id, its.some(x => x.level === 'block') ? 'bad' : (its.length ? 'warn' : 'on'),
                  its.length ? its[0].name : 'проблем не найдено');
    }
  }
}

async function psvcHealthUi(act) {
  if (act === 'start') return psvcAction('start');
  if (act === 'autostart_on') return psvcAction('autostart_on');
  if (act === 'update') return psvcUpdate();
  if (act === 'xray_security') return openProtoSvcModal('xray');
}

async function psvcHealthFix(id) {
  if (_psvcHealthBusy) return;
  const it = ((_psvcHealth || {}).items || []).find(x => x.id === id) || {};
  _psvcHealthBusy = id;
  _paintPsvcHealth();
  showBusyOverlay('Исправляем: ' + (it.name || id), it.eta_hint || (it.long ? 'Может занять до минуты' : 'Несколько секунд'));
  let ok = false, msg = '', lost = false;
  try {
    const r = await fetch(API + '/api/system/dependencies/fix', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'same-origin',
      body: JSON.stringify({id}),
    });
    let d = await r.json().catch(() => ({}));
    ok = r.ok && d.ok;
    if (ok && d.async) {
      const done = await _pollDepFix(id, null, Date.now(), it.eta_hint || '',
                                     it.long ? 20 * 60 * 1000 : 5 * 60 * 1000);
      ok = done.ok;
      d = done.ok ? {output: done.msg} : {error: done.msg};
    }
    msg = ok ? (d.output || 'Исправлено') : (d.error || d.output || 'не получилось');
  } catch (e) {
    msg = e.message;
    lost = true;
  } finally {
    hideBusyOverlay();
  }
  // Починка с перезапуском XRay рвёт соединение, если панель открыта через его
  // фоллбек: ответ «успешно» мог не долететь, хотя на сервере всё сделано.
  // Ошибку сети тогда не показываем — ждём панель и судим по перепроверке.
  if (lost && it.requires_restart) {
    showBusyOverlay((PROTO_SVC[_psvcKind] || {}).title + ' перезапускается', 'Связь оборвалась на перезапуске — ждём панель');
    try {
      await new Promise(res => setTimeout(res, 3000));
      await pingUntilAlive();
    } finally { hideBusyOverlay(); }
    _psvcHealthBusy = '';
    await loadProtoHealth();
    const still = ((_psvcHealth || {}).items || []).some(x => x.id === id);
    if (still) openAlert({title: 'Не получилось: ' + (it.name || id), body: 'Связь оборвалась, и после перепроверки пункт остался. ' + msg});
    else toast('Исправлено: ' + (it.name || id));
    return;
  }
  // Перевыпуск сертификата перезапускает XRay, а панель может жить за его
  // фоллбеком — ждём, пока она снова ответит, и только потом перепроверяем.
  if (ok && it.requires_restart) {
    showBusyOverlay((PROTO_SVC[_psvcKind] || {}).title + ' перезапускается', 'Соединения оборвутся на пару секунд');
    try {
      // Рестарт отложен на пару секунд, чтобы ответ успел дойти: пинг сразу
      // застал бы панель живой ещё до перезапуска.
      await new Promise(res => setTimeout(res, 4000));
      await pingUntilAlive();
    } finally { hideBusyOverlay(); }
  }
  _psvcHealthBusy = '';
  if (ok) toast(msg);
  else openAlert({title: 'Не получилось: ' + (it.name || id), body: msg});
  await loadProtoHealth();
}


async function psvcAction(action) {
  const a = PROTO_SVC[_psvcKind];
  const labels = {restart: 'Перезапускаем', stop: 'Останавливаем', start: 'Запускаем',
                  autostart_on: 'Включаем автозапуск', autostart_off: 'Выключаем автозапуск'};
  if (action === 'stop') {
    const ok = await openConfirm({
      title: `Остановить ${a.title}?`,
      body: 'Все клиенты этого протокола потеряют связь, пока сервис не будет запущен снова.',
      okLabel: 'Остановить', danger: true,
    });
    if (!ok) return;
  }
  showBusyOverlay(labels[action] + ' ' + a.title, 'Ждём ответа от сервиса');
  // Обрыв соединения при перезапуске XRay — не ошибка: на серверах, где панель
  // отдаётся фоллбеком самого XRay, рестарт ядра рвёт и её собственный запрос.
  // Команда при этом выполняется, а браузер видит «Failed to fetch». Сказать
  // «не удалось» значит соврать, поэтому такой обрыв ждём и смотрим реальное
  // состояние сервиса.
  let dropped = false;
  try {
    const j = a.svcAction ? await a.svcAction(action) : await _svcActionGeneric(_psvcKind, action);
    toast(j && j.ok ? `${a.title}: готово` : `${a.title}: не удалось — ${(j && j.error) || 'см. журнал'}`);
    if (j && !j.ok && j.error) console.error('service action output:', j.error);
  } catch (e) {
    dropped = (e instanceof TypeError)
      || /failed to fetch|networkerror|load failed|connection/i.test(e.message || '');
    if (!dropped) {
      // Сюда попадает и «сервис не поднялся»: адаптер может бросить 500,
      // и в message лежит хвост journalctl. Валить это на сеть было бы враньём.
      toast(`${a.title}: не удалось — ${e.message}`);
      console.error('service action error:', e);
    }
  } finally {
    if (dropped) await pingUntilAlive();
    hideBusyOverlay();
  }
  await loadProtoSvc();
  if (dropped) {
    const st = _psvcState || {};
    toast(st.active ? `${a.title}: готово — связь с панелью восстановлена`
                    : `${a.title}: связь оборвалась, сервис сейчас не запущен — см. журнал`);
  }
  if (a.afterAction) a.afterAction();
}

async function _svcActionGeneric(kind, action) {
  const r = await fetch(API + '/api/service/action', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({proto: kind, action}),
  });
  return await r.json().catch(() => ({ok: false, error: 'HTTP ' + r.status}));
}

async function psvcUpdate() {
  const ver = _systemVersions && _systemVersions[_psvcKind];
  await applyProtoUpdate(_psvcKind, (ver && (ver.target || ver.latest)) || '');
  await loadProtoSvc();
}

async function psvcInstall() {
  const a = PROTO_SVC[_psvcKind];
  await a.install();
  await loadSystemVersions(true);
  await loadProtoSvc();
  if (a.afterAction) a.afterAction();
}

async function psvcUninstall() {
  const a = PROTO_SVC[_psvcKind];
  const purge = !!(document.getElementById('psvcPurge') || {}).checked;
  const ok = await openConfirm({
    title: `Удалить ${a.title} с сервера?`,
    body: a.uninstall.body + (purge
      ? '<br><br><b>Данные панели по этому протоколу тоже будут удалены — клиенты и настройки не восстановить.</b>'
      : '<br><br>Данные панели (клиенты, настройки) останутся — при повторной установке всё вернётся.'),
    okLabel: 'Удалить', danger: true,
  });
  if (!ok) return;
  showBusyOverlay('Удаляем ' + a.title, 'Останавливаем сервис и убираем файлы');
  try {
    const j = await a.uninstall.run(purge);
    toast(j && j.ok ? `${a.title} удалён` : `Не удалось: ${(j && j.error) || 'см. журнал'}`);
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
  closeModal('protoSvcModal');
  await loadServerConfig();
  await loadSystemVersions(true);
  refreshAll();
}

// --- адаптеры протоколов ---------------------------------------------------

async function _svcStateGeneric(kind) {
  const r = await fetch(API + '/api/service/state?proto=' + encodeURIComponent(kind),
                        {credentials: 'same-origin'});
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.json();
}

// Строка «тумблер + описание» — единый вид для всех протокольных переключателей.
function _psvcSwitchRow(id, rowId, label, desc, on, handler) {
  return `
    <div class="psvc-row">
      <div class="psvc-row-body">
        <div class="psvc-row-t">${escHtml(label)}</div>
        <div class="psvc-row-d">${desc}</div>
      </div>
      <label class="switch-row ${on ? 'is-on' : ''}" id="${rowId}" style="margin:0;flex:0 0 auto;">
        <span class="switch switch-tinted">
          <input type="checkbox" id="${id}" ${on ? 'checked' : ''} onchange="${handler}">
          <span class="switch-slider"></span>
        </span>
      </label>
    </div>`;
}

// Заголовок входа: название, состояние словами и переключатель рядом. Раньше
// тумблер стоял строкой в середине формы с подписью «включена», даже когда
// вход выключен, — состояние читалось только по положению рычажка.
function _psvcToggleHead(id, title, on, handler, desc, disabled) {
  return `
    <div class="psvc-head">
      <div class="psvc-head-t">${escHtml(title)}
        <span class="psvc-head-st ${on ? 'is-on' : ''}">${on ? 'включён' : 'выключен'}</span></div>
      <label class="switch-row ${on ? 'is-on' : ''}" style="margin:0;flex:0 0 auto;">
        <span class="switch switch-tinted">
          <input type="checkbox" id="${id}" ${on ? 'checked' : ''} ${disabled ? 'disabled' : ''} onchange="${handler}">
          <span class="switch-slider"></span>
        </span>
      </label>
    </div>
    ${desc ? `<div class="psvc-head-d">${desc}</div>` : ''}`;
}

PROTO_SVC.awg = {
  title: 'AmneziaWG',
  load: async () => {
    const s = await _svcStateGeneric('awg');
    try {
      const r = await fetch(API + '/api/awg/dest-log/state', {credentials: 'same-origin'});
      s.dest_log = r.ok ? !!(await r.json()).enabled : false;
    } catch (e) { s.dest_log = false; }
    return s;
  },
  optionsHtml: (s) => _psvcSwitchRow(
    'awgDestLogToggle', 'rowAwgDestLog', 'Логи назначений',
    'Сборщик читает conntrack каждые 10 секунд и пишет IP назначения клиентов в общий лог AWG. ' +
    'Понадобятся пакеты conntrack и dnsmasq — после включения они появятся в «Зависимостях» с автофиксами. ' +
    'Конфиги клиентов не меняются, перевыдача не нужна.',
    s.dest_log, 'onAwgDestLogToggle(this.checked)') +
    '<div id="awgPortBox" style="margin-top:16px;"><div class="psvc-note">Читаю порт…</div></div>',
  onMount: () => loadProtoPort('awg'),
  restartNote: 'Перезапуск опускает и поднимает интерфейс awg0 — все туннели разорвутся на пару секунд. ' +
               'Если интерфейс завис, панель удалит его через <code>ip link delete</code> и поднимет заново.',
  uninstall: null,
  uninstallNote: 'AmneziaWG ставится модулем ядра через DKMS. Снос из панели легко оставляет сервер без сети, ' +
                 'поэтому кнопки удаления здесь нет — только вручную по ssh.',
  afterAction: () => refreshStatus(),
};

// === Режим на 443: Reality ⇄ TLS ===
// Это единственная настройка XRay, которая меняет не только VPN, но и то, что
// сервер показывает обычному посетителю: при Reality 443 отдаёт чужой сайт
// (dest), при TLS — фоллбек в панель, то есть заглушку и ссылки на профили без
// порта админки. Поэтому режим входа переключается той же операцией.
let _xraySec = null;

async function loadXraySecurity() {
  const box = document.getElementById('xraySecBox');
  if (!box) return;
  try {
    const r = await fetch(API + '/api/xray/security', {credentials: 'same-origin'});
    _xraySec = await r.json();
  } catch (e) {
    box.innerHTML = `<div class="psvc-note">Не удалось прочитать режим: ${escHtml(e.message)}</div>`;
    return;
  }
  _paintXraySecurity();
}

function _paintXraySecurity() {
  const box = document.getElementById('xraySecBox');
  const s = _xraySec || {};
  if (!box) return;
  if (s.installed === false) {
    box.innerHTML = `<div class="psvc-sec-h" style="margin-bottom:6px;">Режим на 443</div>
      <div class="psvc-note">XRay не установлен — переключать нечего.</div>`;
    return;
  }
  const isTls = (s.security === 'tls');
  const target = isTls ? 'reality' : 'tls';
  const days = (s.cert_days === null || s.cert_days === undefined) ? null : s.cert_days;
  const certLine = s.cert_domain
    ? `${escHtml(s.cert_domain)}${days !== null ? ` · сертификат ${days > 0 ? days + ' дн.' : 'просрочен'}` : ''}`
    : 'сертификата нет';
  const blocked = (!isTls && s.tls_blocked_reason) ? s.tls_blocked_reason : '';

  const now = isTls
    ? `<b>TLS</b> на <code>${escHtml(s.sni || s.cert_domain || '')}</code> — 443 терминирует XRay,
       всё, что не VLESS, уходит в панель. Сайт-заглушка и ссылки на профили работают по домену без порта.`
    : `<b>Reality</b>, маскировка под <code>${escHtml((s.dest || '').split(':')[0])}</code> — 443 отдаёт
       посетителю чужой сайт. Панель и профили доступны только через порт${s.panel_port ? ' ' + s.panel_port : ' панели'}.`;

  // Выбор того, что окажется на корне после перехода на TLS. При Reality этот
  // вопрос не стоит: до панели там всё равно ничего не доходит. Если переход
  // заблокирован, выбор тоже прячем — он ни на что не влияет.
  const loginChoice = (target === 'tls' && !blocked) ? `
    <div style="margin-top:10px;padding:10px;background:var(--bg);border:1px solid var(--border2);border-radius:8px;">
      <div style="font-size:12px;color:var(--text2);margin-bottom:8px;">Что показывать на <code>https://${escHtml(s.cert_domain || '')}/</code>:</div>
      <label style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;cursor:pointer;">
        <input type="radio" name="xraySecLogin" value="fake" checked style="margin-top:3px;">
        <span style="font-size:12.5px;">Сайт-заглушку из <code>public/</code>, вход в панель — по адресу-ключу
          <code>${escHtml(s.login_path || '/login.html')}</code>${
            (_serverPaths && _serverPaths.public_index_exists === false)
              ? ' <span style="color:#fa3;">— файлов сайта там сейчас нет, корень отдаст 404</span>' : ''}</span>
      </label>
      <label style="display:flex;gap:8px;align-items:flex-start;cursor:pointer;">
        <input type="radio" name="xraySecLogin" value="ip" style="margin-top:3px;">
        <span style="font-size:12.5px;">Саму панель (без маскировки)</span>
      </label>
    </div>` : '';

  box.innerHTML = `
    <div class="psvc-sec-h" style="margin-bottom:6px;">Режим на 443</div>
    <div class="psvc-note" style="margin-bottom:10px;">${now}</div>
    <div style="font-size:12px;color:var(--text3);margin-bottom:8px;">Домен: ${certLine}</div>
    ${loginChoice}
    ${blocked ? `<div class="psvc-note" style="margin-top:10px;color:#fa3;">Переключение на TLS недоступно: ${escHtml(blocked)}</div>` : ''}
    <div class="psvc-actions" style="margin-top:10px;">
      <button class="btn btn-sm ${blocked ? 'btn-ghost' : 'btn-primary'}" id="xraySecBtn" ${blocked ? 'disabled' : ''}>
        Переключить на ${target === 'tls' ? 'TLS (свой домен)' : 'Reality (маскировка)'}
      </button>
    </div>`;
  const btn = document.getElementById('xraySecBtn');
  if (btn && !blocked) btn.addEventListener('click', () => switchXraySecurity(target));
}

async function switchXraySecurity(mode) {
  const s = _xraySec || {};
  const toTls = (mode === 'tls');
  const body = toTls
    ? `XRay перестанет маскироваться под <code>${escHtml((s.dest || '').split(':')[0])}</code> и будет
       терминировать 443 сертификатом домена <code>${escHtml(s.cert_domain || '')}</code>.<br><br>
       <b>Всем клиентам VLESS придётся переполучить конфиг</b>: Reality и TLS — разные параметры
       подключения. Профили по ссылке (Loon, Clash, Shadowrocket) перекачаются сами, а вставленные
       вручную <code>vless://</code> перестанут работать. MTProto не затрагивается.<br><br>
       Побочный эффект: запросы к панели через 443 будут приходить от XRay локально, поэтому в
       журнале вместо адреса посетителя появится <code>127.0.0.1</code>. Вход по порту
       ${s.panel_port ? escHtml(String(s.panel_port)) : 'панели'} продолжит показывать реальный IP.`
    : `XRay снова начнёт маскироваться под чужой сайт, а 443 перестанет отдавать панель и заглушку —
       они останутся доступны только по порту${s.panel_port ? ' ' + s.panel_port : ' панели'}.<br><br>
       <b>Всем клиентам VLESS придётся переполучить конфиг.</b>`;
  // Telegram WEB живёт на 443 только с настоящим сертификатом домена: Reality
  // его выключит. Предупреждаем до переключения, а не жалобой клиентов после.
  const tgwebOn = (typeof _protoRunning !== 'undefined') && _protoRunning.tgweb != null;
  const tgNote = !tgwebOn ? '' : (toTls
    ? '<br><br>Telegram WEB уйдёт за фоллбек XRay сам — ссылки клиентов WEB не меняются.'
    : '<br><br><b>Telegram WEB перестанет работать</b>: WebView Telegram нужен настоящий сертификат ' +
      'домена, а Reality отдаёт чужой. Клиенты WEB не подключатся, пока XRay не вернут в TLS ' +
      '(или не выключат совсем — тогда 443 займёт сам WEB).');
  const ok = await openConfirm({
    title: toTls ? 'Переключить 443 на TLS?' : 'Вернуть Reality?',
    body: body + tgNote,
    okLabel: 'Переключить',
    danger: !toTls,
  });
  if (!ok) return;
  const picked = document.querySelector('input[name="xraySecLogin"]:checked');
  showBusyOverlay('Переключаю режим 443…', 'Правим конфиг XRay и перезапускаем сервис');
  try {
    const r = await fetch(API + '/api/xray/security', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mode, login_mode: (toTls && picked) ? picked.value : ''}),
    });
    const d = await r.json().catch(() => ({}));
    if (!(r.ok && d.ok)) { toast(d.error || 'Не удалось переключить'); return; }
    _xraySec = d;
    toast(d.message || 'Режим переключён');
    // Публичный адрес и ссылки на профили считаются от режима инбаунда —
    // перечитываем конфиг, иначе в карточках останется старый базис с портом.
    try { await loadServerConfig(); } catch (e) {}
    _paintXraySecurity();
    refreshXray();
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
}

// --- Инбаунд Hysteria внутри XRay -------------------------------------------
// Отдельного протокола в панели нет: Hysteria — второй вход того же ядра, с
// общими клиентами и правилами. Здесь только его собственные настройки: порт,
// маскировка, обфускация и потолки скорости.
let _xrayHy = null;
// Есть ли в полях Hysteria правки, которые ещё не применены. Объявлен здесь, а
// не рядом с обработчиком: loadProtoSvc читает флаг и лежит выше по файлу.
let _hyDirty = false;

async function loadXrayHysteria() {
  const box = document.getElementById('xrayHyBox');
  if (!box) return;
  try {
    const r = await fetch(API + '/api/xray/hysteria', {credentials: 'same-origin'});
    const j = await r.json();
    if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
    _xrayHy = j;
    renderXrayHysteria();
  } catch (e) {
    box.innerHTML = '<div class="psvc-note" style="color:var(--red);">Инбаунд Hysteria: ' +
      escHtml(e.message) + '</div>';
  }
}

function renderXrayHysteria() {
  const box = document.getElementById('xrayHyBox');
  if (!box || !_xrayHy) return;
  const s = _xrayHy;
  const f = (id, label, value, type, hint) =>
    '<label class="psvc-field"><span>' + escHtml(label) + '</span>' +
    '<input class="psvc-inp" id="' + id + '" type="' + type + '" value="' + escHtml(String(value)) + '"></label>' +
    (hint ? '<div class="psvc-row-d" style="margin:-8px 0 12px;">' + hint + '</div>' : '');

  // Сертификат: на TLS-сервере берётся тот же, что у VLESS; на Reality своего
  // нет, и панель выпускает самоподписанный — клиенту тогда нужен отпечаток.
  let certNote = '';
  if (s.enabled && s.cert_mode === 'self') {
    certNote = '<div class="psvc-note" style="margin-bottom:10px;">Сертификат самоподписанный: ' +
      'в ссылки клиентам добавляются <code>insecure=1</code> и <code>pinSHA256</code> — ' +
      'подмена невозможна, клиент сверяет конкретный сертификат.' +
      (s.fingerprint ? '<div style="font-family:monospace;font-size:11px;margin-top:6px;overflow-wrap:anywhere;">' +
        escHtml(s.fingerprint) + '</div>' : '') + '</div>';
  } else if (s.enabled && s.cert_mode === 'le') {
    certNote = '<div class="psvc-note" style="margin-bottom:10px;">Сертификат Let’s Encrypt — тот же, ' +
      'что у VLESS на 443/tcp. Клиентам ничего пиннить не нужно.</div>';
  }

  // Панель нашла серт домена, а инбаунд сидит на самоподписанном. Сама не
  // переключает — отпечаток зашит в выданные ссылки, — но и молчать нельзя:
  // иначе админ не узнает, что может уйти с insecure=1. Цена перехода
  // (сколько клиентов остаётся без связи) написана прямо на кнопке.
  const offer = s.cert_offer || {};
  if (offer.to === 'le') {
    certNote += '<div class="psvc-note" style="margin-bottom:10px;border-color:var(--orange);">' +
      '<b style="color:var(--orange);">Можно перейти на сертификат домена' +
      (offer.domain ? ' ' + escHtml(offer.domain) : '') + '</b><br>' +
      'Тогда из ссылок уйдут <code>insecure=1</code> и <code>pinSHA256</code>: клиент будет ' +
      'проверять цепочку сертификатов обычным образом. Это нужно, если у кого-то приложение ' +
      'не умеет пиннинг — такой клиент сейчас подключается вообще без проверки сертификата.' +
      '<div style="margin-top:8px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">' +
      '<button class="btn btn-sm btn-ghost" id="hyCertSwitchBtn" onclick="hyCertSwitch()">' +
      'Перейти на сертификат домена</button>' +
      '<span style="color:var(--text3);font-size:12px;">Ссылки перестанут работать у ' +
      escHtml(String(offer.clients || 0)) + ' клиент(ов) — им нужно будет раздать новые.</span>' +
      '</div></div>';
  }

  // Конфликт порта показывает общий блок порта ниже (тот же, что у AWG и
  // MTProto) — там же «Подобрать свободный» и «Сменить порт».
  let portWarn = '';
  if (s.autoenable_note && !s.enabled) {
    portWarn = '<div class="psvc-note" style="margin-bottom:10px;border-color:var(--orange);">' +
      'Панель пыталась включить Hysteria сама и не смогла: ' + escHtml(s.autoenable_note) + '</div>';
  }

  // Режим прикрытия: либо проксируем чужой сайт, либо ядро отдаёт голый 404.
  // В конфиге это одно поле (пустой url = 404), но в UI выбор нагляднее.
  const masqOn = !!(s.masquerade_url || '').trim();
  const hint = (t) => '<div class="psvc-row-d" style="margin:-8px 0 12px;">' + t + '</div>';

  box.innerHTML =
    _psvcToggleHead('swHyInbound', 'Hysteria 2', !!s.enabled, 'onToggleHyInbound(this)',
      'QUIC поверх UDP рядом с VLESS на TCP. Клиенты, правила, лимиты, статистика и логи общие — ' +
      'каждый клиент получает вторую ссылку в «Конфиге». Переключение перезапускает XRay: ' +
      'VLESS оборвётся на пару секунд. Выключение сохраняет порт, маскировку и пароли клиентов — ' +
      'при повторном включении ссылки останутся прежними.') +
    portWarn +

    // Порт — общим блоком, как у AWG/MTProto/Hysteria: отдельная операция с
    // подтверждением и откатом, а не поле формы «Сохранить».
    '<div id="xhyPortBox" style="margin-top:18px;"><div class="psvc-note">Читаю порт…</div></div>' +
    hint('VLESS слушает TCP, Hysteria — UDP: один и тот же номер им не мешает, это разные сокеты. ' +
      '<b>443/udp — лучший выбор:</b> снаружи это обычный HTTP/3, а UDP на других портах мобильные ' +
      'операторы часто режут как подозрительный QUIC.' +
      // Порт AWG мешает, только когда интерфейс поднят. Опущенный AWG порт не
      // держит, но если его потом поднимут — уже он не сможет занять номер.
      (s.awg_port && s.awg_up
        ? ' <b style="color:var(--orange);">AmneziaWG сейчас слушает ' + escHtml(String(s.awg_port)) +
          '/udp</b> — занимать этот номер нельзя, XRay не поднимется вообще.'
        : (s.awg_port
            ? ' В <code>awg0.conf</code> за AmneziaWG записан порт ' + escHtml(String(s.awg_port)) +
              '/udp, но интерфейс опущен — порт свободен. Если AWG потом поднимут, занятый номер ' +
              'достанется тому, кто стартует первым.'
            : ''))) +

    '<div class="psvc-sec-h" style="margin-top:18px;">Маскировка</div>' +
    '<label class="psvc-field"><span>Что видит посторонний</span>' +
    '<select class="psvc-inp" id="xhyMasqMode" onchange="hyMasqModeChanged()">' +
      '<option value="proxy"' + (masqOn ? ' selected' : '') + '>Проксировать чужой сайт</option>' +
      '<option value="404"' + (masqOn ? '' : ' selected') + '>Отдавать голый 404</option>' +
    '</select></label>' +
    '<div id="xhyMasqUrlWrap"' + (masqOn ? '' : ' class="hidden"') + '>' +
      '<label class="psvc-field"><span>Адрес сайта</span>' +
      '<input class="psvc-inp" id="xhyMasq" type="text" value="' + escHtml(s.masquerade_url || '') +
      '" placeholder="https://example.com"></label>' +
    '</div>' +
    hint('Прикрытие у Hysteria своё и с фоллбеком VLESS не связано: запрос постороннего по HTTP/3 ' +
      'проксируется на указанный сайт, и порт выглядит обычным веб-сервером. Голый 404 выглядит ' +
      'подозрительно пустым — так порт легче вычислить.') +

    '<div class="psvc-sec-h" style="margin-top:18px;">Обфускация</div>' +
    '<div class="psvc-pair">' +
      '<label class="psvc-field"><span>Пароль salamander</span>' +
      '<input class="psvc-inp" id="xhyObfs" type="text" value="' + escHtml(s.obfs_password || '') + '"></label>' +
      '<div class="psvc-field"><span>&nbsp;</span>' +
      '<button class="btn btn-sm btn-ghost" onclick="hyGenObfs()" style="height:34px;">Сгенерировать</button></div>' +
    '</div>' +
    hint('Маскирует сам QUIC: без него трафик опознаётся по сигнатуре протокола. Пароль общий для всех ' +
      'клиентов и входит в каждую ссылку — смена требует перевыдачи ссылок. Пусто — обфускация выключена.') +

    '<div class="psvc-sec-h" style="margin-top:18px;">Скорость</div>' +
    '<div class="psvc-pair">' +
      '<label class="psvc-field"><span>Вниз, Мбит/с</span>' +
      '<input class="psvc-inp" id="xhyDown" type="number" value="' + escHtml(String(s.down_mbps || 0)) + '"></label>' +
      '<label class="psvc-field"><span>Вверх, Мбит/с</span>' +
      '<input class="psvc-inp" id="xhyUp" type="number" value="' + escHtml(String(s.up_mbps || 0)) + '"></label>' +
    '</div>' +
    hint('Включает congestion control brutal: Hysteria перестаёт уступать канал и держит заданную полосу. ' +
      '0 в обоих полях — без ограничения, обычный QUIC. Это потолок инбаунда, а не лимит трафика клиента: ' +
      'месячные лимиты живут в карточке клиента и считаются вместе с VLESS.') +

    certNote;


  _psvcHyDot(s);
  // Правка полей ничего не применяет: без явного признака «не сохранено» ввод
  // молча терялся при перечитывании состояния.
  _hyDirty = false;
  _psvcSyncSave();
  for (const id of ['xhyMasq', 'xhyObfs', 'xhyDown', 'xhyUp', 'xhyMasqMode']) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', _hyMarkDirty);
    if (el && el.tagName === 'SELECT') el.addEventListener('change', _hyMarkDirty);
  }
  loadProtoPort('xray_hy');
}

function _hyMarkDirty() {
  _hyDirty = true;
  _psvcSyncSave();
}

// Кнопка применения нужна только там, где есть что применять: у вкладки VLESS
// своих полей нет, её тумблеры срабатывают сразу. И горит она, только когда
// в полях открытой вкладки есть несохранённые правки: зелёная кнопка при
// нетронутой форме читается как «что-то не сохранено».
function _psvcShowSave(on) {
  const btn = document.getElementById('psvcSaveBtn');
  if (btn) btn.classList.toggle('hidden', !on);
  _psvcSyncSave();
}

function _psvcSyncSave() {
  const btn = document.getElementById('psvcSaveBtn');
  const tab = _psvcActiveTab;
  const dirty = (tab === 'hy' && _hyDirty) || (tab === 'xdns' && _xdnsDirty);
  if (btn) {
    btn.disabled = !dirty;
    btn.classList.toggle('btn-success', dirty);
    btn.classList.toggle('btn-ghost', !dirty);
    btn.title = dirty ? '' : 'Изменений нет — сохранять нечего';
  }
  const note = document.getElementById('psvcDirtyNote');
  if (note) note.classList.toggle('hidden', !dirty || !btn || btn.classList.contains('hidden'));
}

function hyMasqModeChanged() {
  const mode = (document.getElementById('xhyMasqMode') || {}).value;
  const wrap = document.getElementById('xhyMasqUrlWrap');
  if (wrap) wrap.classList.toggle('hidden', mode !== 'proxy');
}

function hyGenObfs() {
  // 16 hex-символов: столько же, сколько панель генерирует при автовключении.
  const b = new Uint8Array(8);
  (window.crypto || {}).getRandomValues ? window.crypto.getRandomValues(b)
                                        : b.forEach((_, i) => b[i] = Math.floor(Math.random() * 256));
  const el = document.getElementById('xhyObfs');
  if (el) el.value = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  _hyMarkDirty();   // программная запись не шлёт input — пометку ставим сами
  toast('Новый пароль — не забудьте «Сохранить» и перевыдать ссылки');
}

async function hyRemoveInbound() {
  const ok = await openConfirm({
    title: 'Убрать инбаунд Hysteria?',
    body: 'Hysteria перестанет принимать подключения, инбаунд удалится из конфига XRay. ' +
          'Настройки и пароли клиентов сохранятся — при повторном включении ссылки останутся прежними. ' +
          'XRay перезапустится, VLESS оборвётся на пару секунд.',
    okLabel: 'Убрать',
  });
  if (!ok) return;
  showBusyOverlay('Убираем инбаунд Hysteria', 'XRay перезапускается, соединения оборвутся на пару секунд');
  try {
    await _postXrayHysteria({enabled: false});
  } finally {
    await pingUntilAlive();
    hideBusyOverlay();
    if (typeof refreshXray === 'function') refreshXray();
  }
}

async function _postXrayHysteria(payload, btnId) {
  if (btnId) _spinBtn(btnId, true, 'Применяем…');
  try {
    const r = await fetch(API + '/api/xray/hysteria', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify(payload),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { toast(j.error || 'Ошибка'); return null; }
    _xrayHy = j;
    _hyDirty = false;
    _psvcSyncSave();
    renderXrayHysteria();
    return j;
  } catch (e) {
    // Обрыв — не ошибка: настройка уже применена, а соединение рвёт рестарт
    // XRay, через фоллбек которого отдаётся сама панель. Ждём панель и
    // перечитываем реальное состояние, вместо «Failed to fetch».
    const dropped = (e instanceof TypeError)
      || /failed to fetch|networkerror|load failed|connection/i.test(e.message || '');
    if (!dropped) { toast(e.message); return null; }
    try {
      await pingUntilAlive();
      const r2 = await fetch(API + '/api/xray/hysteria', {credentials: 'same-origin'});
      const j2 = await r2.json().catch(() => ({}));
      if (r2.ok && j2.ok) {
        _xrayHy = j2;
        _hyDirty = false;
        _psvcSyncSave();
        renderXrayHysteria();
        toast('Настройки применены, XRay перезапущен');
        return j2;
      }
    } catch (e2) { /* ниже общий ответ */ }
    toast('Связь с панелью оборвалась — нажмите «Перечитать», чтобы увидеть состояние');
    return null;
  } finally {
    if (btnId) _spinBtn(btnId, false);
  }
}

async function hyCertSwitch() {
  const offer = (_xrayHy && _xrayHy.cert_offer) || {};
  const n = offer.clients || 0;
  const ok = await openConfirm({
    title: 'Перейти на сертификат домена?',
    body: 'Инбаунд Hysteria поднимется на сертификате ' + escHtml(offer.domain || 'домена') +
          '.\n\nУ ' + n + ' клиент(ов) в выданных ссылках зашит отпечаток текущего ' +
          'самоподписанного сертификата (pinSHA256). После перехода эти ссылки перестанут ' +
          'подключаться — каждому нужно будет раздать новую.\n\nВернуться обратно можно, ' +
          'сертификат никуда не денется, но ссылки снова сменятся.',
    okLabel: 'Перейти',
    danger: true,
  });
  if (!ok) return;
  const j = await _postXrayHysteria({cert_mode: 'auto'}, 'hyCertSwitchBtn');
  if (j) {
    toast(j.cert_mode === 'le' ? 'Перешли на сертификат домена — раздайте новые ссылки'
                               : 'Сертификат домена не подхватился, остались на самоподписанном');
    refreshXray();
  }
}

// Включение Hysteria прямо с плитки. Порт может быть занят (типовой случай —
// AmneziaWG на 443/udp), поэтому сначала показываем диагноз и предлагаем тот
// порт, который панель нашла свободным, а не молча упираемся в ошибку.
async function hyQuickEnable(hy) {
  hy = hy || {};
  const taken = hy.port_taken_by || '';
  const alt = parseInt(hy.suggested_port, 10) || 0;
  let body, payload = {enabled: true};
  if (taken && alt) {
    body = 'Порт ' + (hy.port || '') + '/UDP занят: ' + taken + '. Свободен ' + alt +
           '/UDP — поднимем инбаунд на нём. XRay перезапустится, VLESS оборвётся на пару секунд.';
    payload.port = alt;
  } else if (taken) {
    toast('Порт ' + (hy.port || '') + '/UDP занят (' + taken + '), свободного не нашлось');
    return;
  } else {
    body = 'Инбаунд Hysteria 2 поднимется на ' + (hy.port || 443) +
           '/UDP — рядом с VLESS, с теми же клиентами и правилами. Каждый клиент получит вторую ссылку. ' +
           'XRay перезапустится, VLESS оборвётся на пару секунд.';
  }
  const ok = await openConfirm({title: 'Включить Hysteria 2?', body, okLabel: 'Включить'});
  if (!ok) return;
  showBusyOverlay('Поднимаем инбаунд Hysteria',
                  'XRay перезапускается, соединения оборвутся на пару секунд');
  try {
    const j = await _postXrayHysteria(payload);
    if (j) toast('Hysteria 2 включена');
  } finally {
    await pingUntilAlive();
    hideBusyOverlay();
    if (typeof refreshXray === 'function') refreshXray();
  }
}

function onToggleHyInbound(el) {
  const on = !!el.checked;
  // Перезапуск ядра рвёт и VLESS-сессии — предупреждаем оверлеем, как везде.
  showBusyOverlay(on ? 'Поднимаем инбаунд Hysteria' : 'Выключаем инбаунд Hysteria',
                  'XRay перезапускается, соединения оборвутся на пару секунд');
  _postXrayHysteria({enabled: on}).finally(() => {
    pingUntilAlive().then(() => hideBusyOverlay());
  });
}

async function saveXrayHysteria() {
  const val = (id) => (document.getElementById(id) || {}).value;
  const j = await _postXrayHysteria({
    enabled: !!(_xrayHy && _xrayHy.enabled),
    // Режим «404» = пустой url: в конфиге это одно поле, выбор нужен только в UI.
    masquerade_url: (val('xhyMasqMode') === '404') ? '' : (val('xhyMasq') || ''),
    obfs_password: val('xhyObfs') || '',
    down_mbps: parseInt(val('xhyDown'), 10) || 0,
    up_mbps: parseInt(val('xhyUp'), 10) || 0,
  }, 'psvcSaveBtn');
  if (!j) return;                 // ошибку уже показал _postXrayHysteria
  // Порт был закреплён за остановленным соседом (типично — AmneziaWG в
  // awg0.conf): столкнутся они не сейчас, а когда тот сервис запустят.
  if (j.warning) toast(j.warning);
  _hyDirty = false;
  _psvcSyncSave();
  const dnote = document.getElementById('psvcDirtyNote');
  if (dnote) dnote.classList.add('hidden');
  // При выключенном инбаунде настройки только запоминаются — ядро не трогается.
  if (j.restart_scheduled === false) {
    toast('Настройки сохранены — применятся при включении Hysteria 2');
    return;
  }
  // Применение перезапускает XRay, а панель на 443 ходит через его фоллбек:
  // пара секунд, пока ядро поднимается, запросы не проходят. Без ожидания
  // обновление плитки падало с «Failed to fetch» сразу после «Применено».
  showBusyOverlay('Применяем настройки Hysteria',
                  'XRay перезапускается, соединения оборвутся на пару секунд');
  try {
    await pingUntilAlive();
  } finally {
    hideBusyOverlay();
  }
  toast('Настройки применены');
  if (typeof refreshXray === 'function') refreshXray();   // плитка «Маскировка»
}

// === XDNS — третий вход XRay, через DNS ======================================
// Аварийный канал под «белые списки»: трафик идёт DNS-запросами через резолвер
// оператора к поддомену, делегированному серверу. Вкладка — чек-лист готовности
// (ядро, порт 53, фаервол, DNS-записи, сквозной путь) с починкой на месте,
// записи для регистратора и настройки. Проверка DNS ходит в сеть, поэтому
// сервер помнит последний результат, а свежую панель запускает сама при
// открытии вкладки и по кнопке.
let _xrayXdns = null;
let _xdnsDirty = false;
let _xdnsCheck = null;
let _xdnsChecking = false;
let _xdnsSuggest = null;
const XDNS_AUTOCHECK_SEC = 300;

async function loadXrayXdns() {
  const box = document.getElementById('xrayXdnsBox');
  if (!box) return;
  try {
    const r = await fetch(API + '/api/xray/xdns', {credentials: 'same-origin'});
    const j = await r.json();
    if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
    _xrayXdns = j;
    if (j.last_check && j.last_check.steps) _xdnsCheck = j.last_check;
    renderXrayXdns();
    if (!j.domain && !_xdnsSuggest) xdnsLoadSuggest();
    if (_psvcActiveTab === 'xdns') xdnsMaybeAutoCheck();
  } catch (e) {
    box.innerHTML = '<div class="psvc-note" style="color:var(--red);">Вход XDNS: ' + escHtml(e.message) + '</div>';
  }
}

async function xdnsLoadSuggest() {
  try {
    const r = await fetch(API + '/api/xray/xdns/suggest', {credentials: 'same-origin'});
    const j = await r.json();
    // Подсказка есть — сразу проверяем, что из записей уже на месте: человеку
    // показываем план, а не догадки.
    if (j.ok && j.domain) { _xdnsSuggest = j; renderXrayXdns(); xdnsMaybeAutoCheck(); }
  } catch (e) { /* подсказка не обязательна */ }
}

// Проверка сама при открытии вкладки: человек открыл XDNS, чтобы понять,
// работает ли, — заставлять жать кнопку незачем. Не чаще раза в 5 минут.
function xdnsMaybeAutoCheck() {
  const s = _xrayXdns;
  if (!s || !(s.domain || (_xdnsSuggest && _xdnsSuggest.domain)) || _xdnsChecking || _xdnsDirty) return;
  const age = _xdnsCheck && _xdnsCheck.ts ? (Date.now() / 1000 - _xdnsCheck.ts) : 1e9;
  if (age > XDNS_AUTOCHECK_SEC) xdnsRunCheck(true);
}

function _xdnsFieldVal(id) {
  return ((document.getElementById(id) || {}).value || '').trim().toLowerCase().replace(/\.$/, '');
}

async function xdnsRunCheck(quiet) {
  if (_xdnsChecking) return;
  const sug = _xdnsSuggest || {};
  const domain = _xdnsFieldVal('xdnsDomain') || (_xrayXdns && _xrayXdns.domain) || sug.domain || '';
  const ns_host = _xdnsFieldVal('xdnsNsHost') || (_xrayXdns && _xrayXdns.ns_host) || sug.ns_host || '';
  if (!domain) { if (!quiet) toast('Сначала укажите поддомен туннеля'); return; }
  _xdnsChecking = true;
  renderXrayXdns();
  try {
    const r = await fetch(API + '/api/xray/xdns/check', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'same-origin',
      body: JSON.stringify({domain, ns_host}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
    _xdnsCheck = j.check;
    if (!quiet) toast(j.check.ok ? 'XDNS: всё на месте'
      : j.check.ready_to_enable ? 'XDNS: DNS настроен — осталось включить вход'
      : 'XDNS: есть что поправить — см. список');
  } catch (e) {
    if (!quiet) toast('Проверка не удалась: ' + e.message);
  } finally {
    _xdnsChecking = false;
    renderXrayXdns();
  }
}

// Строка чек-листа: значок, что проверено, подробности и кнопка-починка.
function _xdnsRow(state, title, detail, action) {
  const icon = {ok: '✓', bad: '✕', warn: '!', wait: '…', off: '•'}[state] || '•';
  return '<div class="xdns-row xdns-' + state + '">' +
    '<span class="xdns-ico">' + icon + '</span>' +
    '<div class="xdns-row-body"><div class="xdns-row-t">' + title + '</div>' +
    (detail ? '<div class="xdns-row-d">' + detail + '</div>' : '') +
    (action ? '<div class="xdns-row-a">' + action + '</div>' : '') +
    '</div></div>';
}

function _xdnsChecklist(s) {
  const rows = [];
  const ver = (_systemVersions && _systemVersions.xray) || {};
  // 1. Ядро: формат XDNS поменялся в 26.9.30, старое ядро конфиг не разберёт.
  if (s.core_ok) {
    rows.push(_xdnsRow('ok', 'Ядро XRay ' + escHtml(s.core_version) + ' умеет XDNS', ''));
  } else {
    // Кнопка есть всегда: список версий мог ещё не загрузиться — тогда он
    // подтянется по нажатию (xdnsUpdateCore).
    const upd = '<button class="btn btn-sm btn-success" data-xdns-act="core">Обновить XRay' +
      ((ver.target || ver.latest) ? ' до ' + escHtml(ver.target || ver.latest) : '') + '</button>';
    rows.push(_xdnsRow('bad', 'Ядро XRay ' + escHtml(s.core_version || '—') + ' — нужно ' + escHtml(s.core_min) + ' или новее',
      'Формат XDNS поменялся в ' + escHtml(s.core_min) + ', старое ядро его не разберёт. Обновление перезапустит XRay — ' +
      'клиенты переподключатся сами через пару секунд.', upd));
  }
  // 2. Порт 53 — на конкретном адресе: соседи на 127.0.0.53 и awg0 не мешают.
  const p = s.port53 || {};
  const neighbours = (p.holders || []).filter(h => !h.blocks && !h.ours)
    .map(h => escHtml(h.process) + ' на ' + escHtml(h.addr) + ' — ' + escHtml(h.note)).join('<br>');
  if (p.conflict) {
    const fix = p.fix === 'dnsmasq'
      ? '<button class="btn btn-sm btn-success" data-xdns-act="fix-dnsmasq">Отвязать dnsmasq от внешнего адреса</button>' +
        '<div class="xdns-row-d" style="margin-top:6px;">Панель допишет <code>bind-interfaces</code> и ' +
        '<code>except-interface</code> отдельным файлом в <code>/etc/dnsmasq.d/</code>: dnsmasq продолжит ' +
        'обслуживать локальные адреса и awg0, а внешний освободит.</div>'
      : '';
    const parts = [];
    if (!p.fix) {
      parts.push('Это не служба панели — освободите внешний адрес в её настройках (обычно <code>listen-address</code> ' +
        'или <code>interface</code>) либо остановите её, если она не нужна.');
    }
    if (neighbours) parts.push('Остальные на 53-м: ' + neighbours);
    rows.push(_xdnsRow('bad', escHtml(p.conflict), parts.join('<br>'), fix));
  } else {
    rows.push(_xdnsRow('ok', 'Порт 53/udp на ' + escHtml(p.listen || '—') + (s.enabled ? ' занят XDNS' : ' свободен'),
      neighbours ? 'На 53-м есть соседи, но они слушают другие адреса:<br>' + neighbours : ''));
  }
  // 3. ufw.
  const fw = s.ufw || {};
  if (fw.active && !fw.open) {
    rows.push(s.enabled
      ? _xdnsRow('bad', 'Фаервол ufw закрывает 53/udp', 'Резолверы не достучатся до сервера.',
          '<button class="btn btn-sm btn-success" data-xdns-act="fix-ufw">Открыть 53/udp</button>')
      : _xdnsRow('off', 'Фаервол ufw: 53/udp пока закрыт', 'Панель откроет его сама при включении.'));
  } else {
    rows.push(_xdnsRow('ok', fw.active ? 'Фаервол ufw пропускает 53/udp' : 'Фаервол ufw выключен — порт не закрыт', ''));
  }
  // 4–6. Проверка DNS: шаги приходят с сервера готовыми фразами.
  if (_xdnsChecking) {
    rows.push(_xdnsRow('wait', 'Проверяю DNS-записи и путь через Google, Cloudflare и Яндекс…', 'Обычно до 10 секунд.'));
  } else if (_xdnsCheck && (_xdnsCheck.steps || []).length) {
    for (const st of _xdnsCheck.steps) {
      const state = st.ok === true ? 'ok' : (st.ok === false ? 'bad' : 'off');
      rows.push(_xdnsRow(state, escHtml(st.title), escHtml(st.detail || '')));
    }
    rows.push('<div class="xdns-checked">Проверено ' + escHtml(_fmtServerTs(_xdnsCheck.ts, true)) +
      (_xdnsCheck.domain ? ' для ' + escHtml(_xdnsCheck.domain) : '') + '</div>');
  } else if (s.domain) {
    rows.push(_xdnsRow('off', 'DNS-записи ещё не проверялись', ''));
  } else {
    rows.push(_xdnsRow('off', 'Поддомен туннеля не задан', 'Заполните его ниже — панель покажет, какие записи добавить.'));
  }
  return rows.join('');
}

// «Что осталось сделать»: панель сама сводит всё, что мешает XDNS заработать, в
// один список по порядку — ядро, порт, записи у регистратора, включение, путь
// через резолверы — и у каждого шага своя кнопка. Человек не должен собирать
// картину из чек-листа и угадывать, что из красного важно, а что следствие.
function _xdnsNext(s, plan, effDomain) {
  const c = _xdnsCheck;
  const steps = c ? (c.steps || []) : [];
  const step = (id) => steps.find(x => x.id === id || (id === 'e2e' && String(x.id || '').startsWith('e2e_')));
  const todo = [];
  const btn = (act, label) => '<button class="btn btn-sm btn-success" data-xdns-act="' + act + '">' + label + '</button>';
  const ver = (_systemVersions && _systemVersions.xray) || {};

  if (s.xray_active === false) {
    todo.push({t: 'Запустите XRay — сейчас он остановлен.',
      d: 'Пока ядро лежит, не работает ни один вход: VLESS, Hysteria и XDNS. Причина — во вкладке «Ядро XRay».',
      b: btn('xray-start', 'Запустить XRay')});
  }
  if (!s.core_ok) {
    todo.push({t: 'Обновите ядро XRay: сейчас ' + escHtml(s.core_version || '—') + ', XDNS работает с ' +
      escHtml(s.core_min) + '.',
      d: 'Без этого вход не включится — старое ядро не разберёт его настройки. Обновление перезапустит XRay на пару секунд.',
      b: btn('core', 'Обновить XRay' + (ver.latest ? ' до ' + escHtml(ver.latest) : ''))});
  }
  const p = s.port53 || {};
  if (p.conflict) {
    todo.push({t: 'Освободите 53/udp: ' + escHtml(p.conflict) + '.',
      d: p.fix === 'dnsmasq' ? 'Панель отвяжет dnsmasq от внешнего адреса — локальный DNS и awg0 продолжат работать.'
                             : 'Это чужая служба — подробности в «Готовности» ниже.',
      b: p.fix === 'dnsmasq' ? btn('fix-dnsmasq', 'Освободить порт') : ''});
  }
  const fw = s.ufw || {};
  if (s.enabled && fw.active && !fw.open) {
    todo.push({t: 'Откройте 53/udp в ufw.', d: 'Иначе резолверы не достучатся до сервера.', b: btn('fix-ufw', 'Открыть порт')});
  }
  if (!effDomain) {
    todo.push({t: 'Задайте поддомен туннеля.', d: 'Ниже, в «DNS-записях у регистратора».', b: ''});
  } else if (_xdnsChecking) {
    todo.push({t: 'Проверяю DNS-записи…', d: '', b: '', wait: true});
  } else if (!plan) {
    todo.push({t: 'Проверьте DNS-записи.', d: '', b: btn('check', 'Проверить')});
  } else {
    const a = plan.a || {}, ns = plan.ns || {};
    const n = (a.state === 'ok' ? 0 : 1) + (ns.state === 'delegated' ? 0 : 1);
    if (n) {
      todo.push({t: 'Добавьте у регистратора ' + (n === 1 ? 'одну запись' : n + ' записи') + ' в зоне ' +
        escHtml(plan.apex || '') + '.',
        d: 'Что именно вписать — карточками в «DNS-записях у регистратора» ниже. После добавления подождите ' +
           'до часа и нажмите «Проверить».', b: btn('check', 'Проверить')});
    }
  }
  const blocked = todo.length > 0;
  if (!s.enabled) {
    todo.push({t: 'Включите XDNS.', d: 'XRay перезапустится, VLESS и Hysteria оборвутся на пару секунд.',
      b: blocked ? '' : btn('enable', 'Включить XDNS')});
  } else if (c && !_xdnsChecking && !blocked && !c.ok) {
    const local = step('local');
    if (local && local.ok === false) {
      todo.push({t: 'XRay не отвечает на 53/udp.', d: escHtml(local.detail || ''), b: btn('check', 'Проверить ещё раз')});
    } else {
      // Сервер сам себе отвечает, записи на месте, а резолверы не доходят —
      // остаётся только фаервол хостера: его панель изнутри сервера не видит.
      todo.push({t: 'Откройте входящий 53/udp в фаерволе хостера.',
        d: 'На сервере всё готово и записи на месте, но запросы снаружи не доходят. У многих хостеров есть свой ' +
           'фаервол в личном кабинете (Security Groups, Firewall) — разрешите там входящий UDP 53. Изнутри сервера ' +
           'панель его не видит.', b: btn('check', 'Проверить ещё раз')});
    }
  }

  if (!todo.length) {
    if (s.enabled && c && c.ok) {
      return '<div class="xdns-banner xdns-ok"><b>XDNS работает.</b> Запросы через публичные DNS доходят до сервера — ' +
        'клиентам можно выдавать конфиг со вкладки XDNS в «Конфиге».</div>';
    }
    return '<div class="xdns-banner xdns-warn"><b>XDNS включён.</b> Проверка ещё не выполнялась.</div>';
  }
  const items = todo.map((x, i) =>
    '<div class="xdns-next' + (i === 0 ? ' is-first' : '') + '">' +
      '<span class="xdns-next-n">' + (x.wait ? '…' : i + 1) + '</span>' +
      '<div class="xdns-next-b"><div class="xdns-next-t">' + x.t + '</div>' +
      (x.d ? '<div class="xdns-row-d">' + x.d + '</div>' : '') +
      (x.b && (i === 0 || !blocked) ? '<div class="xdns-row-a">' + x.b + '</div>' : '') +
    '</div></div>').join('');
  return '<div class="xdns-banner xdns-warn"><b>Чтобы XDNS заработал, ' +
    (todo.length === 1 ? 'остался один шаг:' : 'осталось ' + todo.length + ' ' +
      (todo.length < 5 ? 'шага' : 'шагов') + ' — по порядку:') + '</b>' + items + '</div>';
}

function renderXrayXdns() {
  const box = document.getElementById('xrayXdnsBox');
  if (!box || !_xrayXdns) return;
  const s = _xrayXdns;
  // Поля, которые человек уже правит, перерисовка не трогает.
  const keep = (id, fallback) => {
    const el = document.getElementById(id);
    return (el && _xdnsDirty) ? el.value : fallback;
  };
  const sug = _xdnsSuggest || {};
  const domain = keep('xdnsDomain', s.domain || '');
  const nsHost = keep('xdnsNsHost', s.ns_host || '');
  // Что реально подставлено: поле, а если оно пустое — подсказка панели.
  const effDomain = domain || sug.domain || '';
  const effNs = nsHost || sug.ns_host || '';
  // План записей берём только из проверки ИМЕННО этих значений: после правки
  // поля старый план врал бы про чужие имена.
  const plan = (_xdnsCheck && _xdnsCheck.plan && _xdnsCheck.plan.domain === effDomain &&
                _xdnsCheck.plan.ns_host === effNs) ? _xdnsCheck.plan : null;
  const hint = (t) => '<div class="psvc-row-d" style="margin:-8px 0 12px;">' + t + '</div>';
  const copyBtn = (v) => '<button class="btn btn-sm btn-ghost xdns-copy" data-copy="' + escHtml(v) + '">Копировать</button>';
  // Регистраторы просят имя записи БЕЗ домена зоны («t», а не «t.example.com»).
  const zone = (plan && plan.apex) || sug.apex || effDomain.split('.').slice(1).join('.');
  const rel = (host) => host === zone ? '@'
    : (host.endsWith('.' + zone) ? host.slice(0, -zone.length - 1) : host);
  const recField = (label, value, sub) =>
    '<div class="xdns-f"><span class="xdns-f-l">' + label + '</span>' +
    '<code class="xdns-f-v">' + escHtml(value) + '</code>' + copyBtn(value) +
    (sub ? '<div class="xdns-f-s">' + sub + '</div>' : '') + '</div>';
  const recCard = (n, action, type, name, value, title, note) =>
    '<div class="xdns-rec">' +
      '<div class="xdns-rec-h"><span class="xdns-rec-n">' + n + '</span><b>' + action + '</b> ' + title + '</div>' +
      (note ? '<div class="xdns-f-s" style="margin:-2px 0 8px;color:var(--orange);">' + note + '</div>' : '') +
      // Тип у регистраторов выбирают из списка — копировать его незачем.
      '<div class="xdns-f"><span class="xdns-f-l">Тип</span><code class="xdns-f-v">' + type + '</code>' +
        '<span class="xdns-f-t">' + (type === 'NS'
          ? 'в списке типов — <b>NS</b> (NS Record), не A: IP-адреса в этой записи нет'
          : 'выберите в списке типов') + '</span></div>' +
      recField('Имя <span>(Host / Name)</span>', rel(name),
        rel(name) !== name ? 'Если регистратор просит имя целиком — <code>' + escHtml(name) + '</code>' : '') +
      recField(type === 'NS' ? 'Значение <span>(Value / Nameserver)</span>' : 'Значение <span>(Value / IP)</span>', value) +
      '<div class="xdns-f"><span class="xdns-f-l">TTL</span><span class="xdns-f-t">любой, можно «Auto»</span></div>' +
    '</div>';
  const pub = (plan && plan.public_ip) || s.public_ip || 'IP сервера';

  // Записи: показываем ТОЛЬКО то, что надо сделать. Что уже есть в зоне —
  // одной зелёной строкой, без карточки «создайте».
  let recordsHtml = '';
  if (!effDomain) {
    recordsHtml = '';
  } else if (!plan) {
    recordsHtml = '<div class="psvc-note" style="margin-bottom:12px;">' +
      (_xdnsChecking ? 'Смотрю, какие записи уже есть в DNS зоны ' + escHtml(zone) + '…'
                     : 'Записи для этих имён ещё не проверены — нажмите «Проверить ещё раз».') + '</div>';
  } else {
    const done = [], cards = [];
    let n = 0;
    const a = plan.a || {}, ns = plan.ns || {};
    if (a.state === 'ok') {
      done.push('A-запись <code>' + escHtml(effNs) + '</code> → <code>' + escHtml((a.ips || []).join(', ')) +
        '</code> уже есть');
    } else if (a.state === 'missing') {
      cards.push(recCard(++n, 'Добавьте', 'A', effNs, pub, 'A-запись — «' + escHtml(effNs) + ' — это этот сервер»',
        plan.cloudflare ? 'Домен на Cloudflare: облако у записи — серое (DNS only), иначе отвечать будет Cloudflare.' : ''));
    } else if (a.state === 'wrong') {
      cards.push(recCard(++n, 'Исправьте', 'A', effNs, pub, 'существующую A-запись ' + escHtml(effNs),
        'Сейчас она указывает на ' + escHtml((a.ips || []).join(', ')) + ' — замените значение на ' + escHtml(pub) + '.' +
        (plan.cloudflare ? ' Домен на Cloudflare: если облако у записи оранжевое, переключите в серое (DNS only).' : '') +
        ' Либо впишите в «Имя этого сервера» другое имя, которое уже смотрит на этот сервер.'));
    }
    if (ns.state === 'delegated') {
      done.push('NS-запись <code>' + escHtml(effDomain) + '</code> → <code>' + escHtml(effNs) + '</code> уже есть');
    } else if (ns.state === 'elsewhere') {
      cards.push(recCard(++n, 'Исправьте', 'NS', effDomain, effNs, 'существующую NS-запись ' + escHtml(effDomain),
        'Сейчас она указывает на ' + escHtml((ns.to || []).join(', ')) + ' — замените значение.'));
    } else if (ns.state === 'taken') {
      cards.push(recCard(++n, 'Добавьте', 'NS', effDomain, effNs, 'NS-запись — «на вопросы про ' + escHtml(effDomain) +
        ' отвечает этот сервер»', 'Имя ' + escHtml(rel(effDomain)) + ' в зоне уже занято другой записью (A, CNAME или *). ' +
        'Удалите её или впишите в «Поддомен туннеля» другое имя.'));
    } else {
      cards.push(recCard(++n, 'Добавьте', 'NS', effDomain, effNs, 'NS-запись — «на вопросы про ' + escHtml(effDomain) +
        ' отвечает этот сервер»', ns.state === 'unknown' ? 'Серверы зоны не ответили — проверить, есть ли запись, не удалось.' : ''));
    }
    const doneHtml = done.map(t => '<div class="xdns-done">✓ ' + t + '</div>').join('');
    recordsHtml = cards.length
      ? '<div class="psvc-note" style="margin-bottom:10px;">У регистратора домена <b>' + escHtml(zone) + '</b>, в разделе ' +
          'DNS-записей, нужно ' + (cards.length === 1 ? '<b>одно действие</b>' : '<b>' + cards.length + ' действия</b>') +
          ' — ниже. Каждое поле копируется отдельно и вставляется в одноимённое поле формы.' + doneHtml + '</div>' +
        '<div class="xdns-recs">' + cards.join('') + '</div>' +
        hint('Изменения расходятся от нескольких минут до часа — затем «Проверить ещё раз» выше.')
      : '<div class="psvc-note" style="margin-bottom:12px;border-color:var(--green);">' +
          '<b style="color:var(--green);">Все нужные записи уже есть — у регистратора ничего делать не нужно.</b>' +
          doneHtml + '</div>';
  }

  const fail = s.last_failure && s.last_failure.ts
    ? '<div class="psvc-note" style="margin-bottom:12px;border-color:var(--red);"><b style="color:var(--red);">' +
      'Прошлое включение откатилось ' + escHtml(_fmtServerTs(s.last_failure.ts, true)) + '.</b> XRay не поднялся с новым ' +
      'входом, и панель сняла XDNS, чтобы не оставить без связи VLESS и Hysteria. Причина: ' +
      '<code style="overflow-wrap:anywhere;">' + escHtml(s.last_failure.error || 'см. журнал XRay') + '</code></div>'
    : '';

  const presets = s.resolver_presets || [];
  const chosen = s.resolvers || [];
  const custom = chosen.filter(r => !presets.some(p => p.addr === r));
  const resolverBoxes = presets.map(p =>
    '<label class="xdns-chk"><input type="checkbox" class="xdnsRes" value="' + escHtml(p.addr) + '"' +
    (chosen.includes(p.addr) ? ' checked' : '') + '> ' + escHtml(p.title) +
    ' <span style="color:var(--text3);">' + escHtml(p.addr.replace(/:53$/, '')) + '</span></label>').join('');

  const profiles = s.profiles || {};
  const profOpts = Object.entries(profiles).map(([k, v]) =>
    '<option value="' + k + '"' + (s.profile === k ? ' selected' : '') + '>' + escHtml(v.title) + ' — ' +
    escHtml(v.note) + '</option>').join('');

  box.innerHTML =
    _psvcToggleHead('swXdns', 'XDNS', !!s.enabled, 'onToggleXdns(this)',
      s.core_ok
        ? 'Третий вход ядра на ' + escHtml((s.port53 || {}).listen || '') + ':53/udp. Переключение перезапускает XRay — ' +
          'VLESS и Hysteria оборвутся на пару секунд. Если ядро не поднимется, панель сама снимет XDNS.'
        : '<span style="color:var(--orange);">Включить пока нельзя — сначала шаги ниже.</span>',
      !s.core_ok && !s.enabled) +
    _xdnsNext(s, plan, effDomain) + fail +
    '<div class="psvc-note" style="margin-bottom:14px;">Аварийный канал на случай <b>белых списков</b>, когда ' +
    'VLESS и Hysteria не проходят: телефон шлёт DNS-запросы обычному DNS-серверу (Яндекс, Google или оператора), ' +
    'а тот сам доносит их до этого сервера. Клиенты те же, лимиты и статистика общие. <b>Скорость низкая</b> — ' +
    'хватит на мессенджеры и текст, не на видео. Подключаются приложения на ядре Xray 26.9.30+ ' +
    '(v2rayNG, v2rayN, Happ и подобные) — JSON-конфигом со вкладки XDNS в «Конфиге» клиента.</div>' +

    '<div class="psvc-sec-h">Готовность</div>' +
    '<div class="xdns-list">' + _xdnsChecklist(s) + '</div>' +
    '<div style="margin:10px 0 18px;"><button class="btn btn-sm btn-ghost" data-xdns-act="check"' +
    (_xdnsChecking ? ' disabled' : '') + '>' + (_xdnsChecking ? 'Проверяю…' : 'Проверить ещё раз') + '</button></div>' +


    '<div class="psvc-sec-h" style="margin-top:18px;">DNS-записи у регистратора</div>' +
    '<div class="psvc-pair">' +
      '<label class="psvc-field"><span>Поддомен туннеля</span>' +
      '<input class="psvc-inp" id="xdnsDomain" type="text" value="' + escHtml(domain) + '" placeholder="' +
      escHtml(sug.domain || 't.example.com') + '"></label>' +
      '<label class="psvc-field"><span>Имя этого сервера в DNS</span>' +
      '<input class="psvc-inp" id="xdnsNsHost" type="text" value="' + escHtml(nsHost) + '" placeholder="' +
      escHtml(sug.ns_host || 'ns.example.com') + '"></label>' +
    '</div>' +
    ((!domain && sug.domain)
      ? '<div style="margin:-4px 0 12px;"><button class="btn btn-sm btn-ghost" data-xdns-act="suggest">Подставить ' +
        escHtml(sug.domain) + ' и ' + escHtml(sug.ns_host) + '</button></div>' : '') +
    hint('<b>Поддомен туннеля</b> — новое имя только для XDNS; сайт и почта домена не меняются. ' +
      '<b>Имя этого сервера</b> — любое уже существующее имя, A-запись которого смотрит на этот сервер ' +
      '(панель находит его сама). Оно станет значением NS-записи: «за поддомен отвечает вот этот сервер».') +
    recordsHtml +

    '<div class="psvc-sec-h" style="margin-top:18px;">Скорость</div>' +
    '<label class="psvc-field"><span>Размер пакета</span>' +
    '<select class="psvc-inp" id="xdnsProfile">' + profOpts + '</select></label>' +
    hint('Пакет крупнее — быстрее, но только через DNS, которые принимают большие ответы. Google, например, ' +
      'режет их до 512 байт, и в «Скорости» через него не пройдёт вообще ничего. Не уверены — оставьте «Совместимость».') +

    '<div class="psvc-sec-h" style="margin-top:18px;">Через какие DNS ходят клиенты</div>' +
    '<div class="xdns-chks">' + resolverBoxes + '</div>' +
    '<label class="psvc-field"><span>Свои адреса (через запятую)</span>' +
    '<input class="psvc-inp" id="xdnsResCustom" type="text" value="' + escHtml(custom.join(', ')) +
    '" placeholder="например, DNS вашего оператора"></label>' +
    hint('Клиент делит запросы между всеми выбранными DNS поровну. Если один из них заблокирован, теряется его доля ' +
      'пакетов и канал тормозит, — поэтому лучше один, заведомо доступный. При белых списках в РФ это обычно ' +
      'Яндекс. Попадает только в конфиг клиента: после смены его нужно выдать заново, ядро не перезапускается.');

  // Обработчики кодом: escHtml кавычки не экранирует, и аргументы в onclick
  // ломали бы разметку.
  for (const b of box.querySelectorAll('.xdns-copy')) {
    b.addEventListener('click', () => navigator.clipboard.writeText(b.dataset.copy || '')
      .then(() => toast('Скопировано')));
  }
  const acts = {
    'check': () => xdnsRunCheck(),
    'suggest': () => xdnsUseSuggest(),
    'core': () => xdnsUpdateCore(),
    'fix-ufw': () => xdnsFix('ufw'),
    'fix-dnsmasq': () => xdnsFix('dnsmasq'),
    'xray-start': () => psvcAction('start'),
    'enable': () => {
      const sw = document.getElementById('swXdns');
      if (sw) { sw.checked = true; onToggleXdns(sw); }
    },
  };
  for (const b of box.querySelectorAll('[data-xdns-act]')) {
    const fn = acts[b.dataset.xdnsAct];
    if (fn) b.addEventListener('click', fn);
  }
  for (const id of ['xdnsDomain', 'xdnsNsHost', 'xdnsResCustom', 'xdnsProfile']) {
    const el = document.getElementById(id);
    if (el) el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', _xdnsMarkDirty);
  }
  for (const el of box.querySelectorAll('.xdnsRes')) el.addEventListener('change', _xdnsMarkDirty);
  _xdnsDot();
}

function _xdnsDot() {
  const s = _xrayXdns || {};
  const c = _xdnsCheck;
  if (!s.enabled && s.core_ok === false) return _psvcTabDot('psvcTabXdnsDot', 'warn', 'нужно обновить ядро XRay');
  if (!s.enabled) return _psvcTabDot('psvcTabXdnsDot', 'off', 'выключен');
  if (c && c.ok) return _psvcTabDot('psvcTabXdnsDot', 'on', 'работает: ' + (s.domain || ''));
  _psvcTabDot('psvcTabXdnsDot', c ? 'warn' : 'on', c ? 'включён, но цепочка не сходится' : 'включён');
}

function _xdnsMarkDirty() {
  _xdnsDirty = true;
  _psvcSyncSave();
}

function xdnsUseSuggest() {
  const sug = _xdnsSuggest || {};
  const d = document.getElementById('xdnsDomain');
  const n = document.getElementById('xdnsNsHost');
  if (d) d.value = sug.domain || '';
  if (n) n.value = sug.ns_host || '';
  _xdnsMarkDirty();
  renderXrayXdns();
  xdnsRunCheck(true);
}

function _xdnsCollect() {
  const resolvers = [...document.querySelectorAll('.xdnsRes')].filter(e => e.checked).map(e => e.value);
  for (const r of _xdnsFieldVal('xdnsResCustom').split(/[\s,;]+/)) {
    if (r) resolvers.push(r);
  }
  return {
    domain: _xdnsFieldVal('xdnsDomain'),
    ns_host: _xdnsFieldVal('xdnsNsHost'),
    profile: (document.getElementById('xdnsProfile') || {}).value || 'compat',
    resolvers,
  };
}

async function _postXrayXdns(payload, btnId) {
  if (btnId) _spinBtn(btnId, true, 'Применяем…');
  try {
    const r = await fetch(API + '/api/xray/xdns', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify(payload),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) {
      // Ошибка бывает многострочной (вывод xray -test) — тосту она не по размеру.
      await openAlert({title: 'XDNS не применён',
        body: '<code style="white-space:pre-wrap;overflow-wrap:anywhere;">' + escHtml(j.error || ('HTTP ' + r.status)) + '</code>'});
      return null;
    }
    _xrayXdns = Object.assign({}, _xrayXdns, j);
    _xdnsDirty = false;
    _psvcSyncSave();
    return j;
  } catch (e) {
    // Обрыв — это рестарт XRay, через фоллбек которого может отдаваться панель.
    const dropped = (e instanceof TypeError)
      || /failed to fetch|networkerror|load failed|connection/i.test(e.message || '');
    if (!dropped) { toast(e.message); return null; }
    _xdnsDirty = false;
    _psvcSyncSave();
    return {ok: true, restart_scheduled: true, dropped: true};
  } finally {
    if (btnId) _spinBtn(btnId, false);
  }
}

// После перезапуска: дождаться панели, перечитать состояние (сторож мог
// откатить XDNS) и сразу проверить всю цепочку.
async function _xdnsAfterRestart(title) {
  showBusyOverlay(title, 'XRay перезапускается, соединения оборвутся на пару секунд');
  try {
    await pingUntilAlive();
    await new Promise(res => setTimeout(res, 4000));   // сторож отката успевает отработать
  } finally {
    hideBusyOverlay();
  }
  _xdnsCheck = null;
  await loadXrayXdns();
  const s = _xrayXdns || {};
  if (s.last_failure && s.last_failure.ts && !s.enabled) {
    toast('XRay не поднялся с XDNS — вход снят, остальное работает');
  } else if (s.enabled) {
    xdnsRunCheck(true);
  }
  if (typeof refreshXray === 'function') refreshXray();
}

async function onToggleXdns(el) {
  const on = !!el.checked;
  const f = _xdnsCollect();
  if (on && !f.domain) {
    el.checked = false;
    toast('Сначала укажите поддомен туннеля');
    return;
  }
  const ok = await openConfirm({
    title: on ? 'Включить XDNS?' : 'Выключить XDNS?',
    body: (on && _xdnsCheck && !_xdnsCheck.ok
            ? 'Проверка DNS-записей ещё не зелёная — клиенты не подключатся, пока записи не заработают. ' +
              'Включить можно заранее: панель перепроверит всё после включения.\n\n' : '') +
          (on ? '' : 'Клиенты перестанут подключаться через DNS; настройки сохранятся.\n\n') +
          'XRay перезапустится, VLESS и Hysteria оборвутся на пару секунд.',
    okLabel: on ? 'Включить' : 'Выключить',
  });
  if (!ok) { el.checked = !on; return; }
  const j = await _postXrayXdns(Object.assign(f, {enabled: on}));
  if (!j) { el.checked = !on; return; }
  if (j.restart_scheduled) await _xdnsAfterRestart(on ? 'Включаем XDNS' : 'Выключаем XDNS');
  else renderXrayXdns();
}

async function saveXrayXdns() {
  const f = _xdnsCollect();
  const j = await _postXrayXdns(Object.assign(f, {enabled: !!(_xrayXdns && _xrayXdns.enabled)}), 'psvcSaveBtn');
  if (!j) return;
  const dnote = document.getElementById('psvcDirtyNote');
  if (dnote) dnote.classList.add('hidden');
  if (j.restart_scheduled) {
    await _xdnsAfterRestart('Применяем настройки XDNS');
    toast('Настройки XDNS применены');
  } else {
    renderXrayXdns();
    toast(_xrayXdns && _xrayXdns.enabled
      ? 'Сохранено, ядро не трогали — выдайте клиентам конфиг заново'
      : 'Сохранено — применится при включении XDNS');
    if (f.domain) xdnsRunCheck(true);
  }
}

async function xdnsFix(what) {
  const labels = {ufw: 'Открываем 53/udp', dnsmasq: 'Отвязываем dnsmasq'};
  showBusyOverlay(labels[what] || 'Чиним', 'Пара секунд');
  try {
    const r = await fetch(API + '/api/xray/xdns/fix', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'same-origin',
      body: JSON.stringify({what}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { toast('Не получилось: ' + (j.error || 'HTTP ' + r.status)); return; }
    _xrayXdns = Object.assign({}, _xrayXdns, j);
    toast('Готово');
  } finally {
    hideBusyOverlay();
    renderXrayXdns();
  }
}

async function xdnsUpdateCore() {
  if (!(_systemVersions && _systemVersions.xray && _systemVersions.xray.latest)) {
    await loadSystemVersions(true);
  }
  const ver = (_systemVersions && _systemVersions.xray) || {};
  await applyProtoUpdate('xray', ver.target || ver.latest || '');
  await loadSystemVersions(true);
  await loadXrayXdns();
}

// Вкладки входов ядра XRay. Выбор не запоминаем: модалка открывается ради
// конкретной задачи, и прошлая вкладка чаще мешает.
let _psvcActiveTab = 'vless';
const _PSVC_PANES = {vless: 'psvcPaneVless', hy: 'psvcPaneHy', xdns: 'psvcPaneXdns', core: 'psvcPaneCore'};

function psvcTab(which) {
  _psvcActiveTab = which;
  for (const btn of document.querySelectorAll('.psvc-tab')) {
    btn.classList.toggle('active', btn.dataset.psvctab === which);
  }
  for (const [key, id] of Object.entries(_PSVC_PANES)) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', key !== which);
  }
  // «Сохранить» — только там, где есть поля: тумблеры VLESS срабатывают сразу.
  _psvcShowSave(which === 'hy' || which === 'xdns');
  if (which === 'xdns') xdnsMaybeAutoCheck();
}

// Кнопка внизу модалки одна — сохраняет то, что открыто.
function psvcSaveActive() {
  if (_psvcActiveTab === 'xdns') return saveXrayXdns();
  return saveXrayHysteria();
}

// Индикатор на вкладке: состояние входа видно, не открывая её.
function _psvcTabDot(id, state, title) {
  const el = document.getElementById(id);
  if (!el) return;
  const colors = {on: 'var(--green)', warn: 'var(--orange)', bad: 'var(--red)', off: 'var(--text3)'};
  el.textContent = state === 'off' ? '○' : '●';
  el.style.color = colors[state] || colors.off;
  el.title = title || '';
}

function _psvcHyDot(st) {
  if (!st) return;
  _psvcTabDot('psvcTabHyDot', st.enabled ? 'on' : 'off',
              st.enabled ? ('включена, порт ' + (st.port || '') + '/udp') : 'выключена');
}

PROTO_SVC.xray = {
  title: 'XRay',
  load: () => _svcStateGeneric('xray'),
  // Три входа одного ядра — для клиента это три разных способа подключиться,
  // у каждого свой транспорт, прикрытие и набор полей. Вкладки стоят первыми.
  tabsHtml: (s) =>
    `<div class="psvc-tabs-cap">Три входа ядра XRay — у каждого свои настройки; общее — во вкладке «Ядро»</div>
     <div class="psvc-tabs">
       <button class="psvc-tab active" data-psvctab="vless" onclick="psvcTab('vless')">
         <span class="psvc-tab-t">VLESS<span class="psvc-tab-dot" id="psvcTabVlessDot" style="color:var(--green);">●</span></span>
         <span class="psvc-tab-s">TCP · основной</span></button>
       <button class="psvc-tab" data-psvctab="hy" onclick="psvcTab('hy')">
         <span class="psvc-tab-t">Hysteria 2<span class="psvc-tab-dot" id="psvcTabHyDot"></span></span>
         <span class="psvc-tab-s">UDP · QUIC</span></button>
       <button class="psvc-tab" data-psvctab="xdns" onclick="psvcTab('xdns')">
         <span class="psvc-tab-t">XDNS<span class="psvc-tab-dot" id="psvcTabXdnsDot"></span></span>
         <span class="psvc-tab-s">DNS · аварийный</span></button>
       <button class="psvc-tab psvc-tab-core" data-psvctab="core" onclick="psvcTab('core')">
         <span class="psvc-tab-t">Ядро XRay<span class="psvc-tab-dot" id="psvcTabCoreDot" style="color:${s.active ? 'var(--green)' : 'var(--red)'};">●</span></span>
         <span class="psvc-tab-s">общее для всех</span></button>
     </div>`,
  optionsHtml: (s) =>
    `<div id="psvcPaneVless">` +
      `<div id="psvcNext_vless" class="psvc-next-slot"></div>` +
      `<div id="xraySecBox"><div class="psvc-note">Читаю режим 443…</div></div>` +
      `<div class="psvc-note" style="margin-top:10px;">Порт, SNI и отпечаток VLESS панель меняет не здесь: ` +
      `что сейчас в конфиге — видно в «Настройки → Источники правды».</div>` +
    `</div>` +
    `<div id="psvcPaneHy" class="hidden">` +
      `<div id="psvcNext_hy" class="psvc-next-slot"></div>` +
      `<div id="xrayHyBox"><div class="psvc-note">Читаю инбаунд Hysteria…</div></div>` +
    `</div>` +
    `<div id="psvcPaneXdns" class="hidden">` +
      `<div id="xrayXdnsBox"><div class="psvc-note">Читаю вход XDNS…</div></div>` +
    `</div>`,
  // Статистика и журнал включаются на всё ядро, а не на один вход, — их место
  // в общем блоке под вкладками.
  coreHtml: (s) =>
    _psvcSwitchRow('swEnableStats', 'rowEnableStats', 'Статистика трафика',
      'Однократная настройка XRay: в конфиг добавляется блок stats и policy, после чего в карточках клиентов ' +
      'появляются цифры трафика. Считается по всем входам сразу — у клиента один счётчик на VLESS, Hysteria и XDNS.',
      _xrayFlags.stats, 'onSwitchEnableStats(this)') +
    _psvcSwitchRow('swEnableLogs', 'rowEnableLogs', 'Журнал подключений',
      'Однократная настройка access.log: в карточках клиентов появятся последний IP, страна и кнопка «Логи». ' +
      'Пишет все входы в один журнал.',
      _xrayFlags.logs, 'onSwitchEnableLogs(this)'),
  onMount: () => { loadXraySecurity(); loadXrayHysteria(); loadXrayXdns(); },
  restartNote: 'Перезапуск рвёт соединения всех входов ядра — VLESS, Hysteria и XDNS — ' +
               'примерно на две секунды; клиенты переподключаются сами. Если панель открыта по 443 через ' +
               'фоллбек XRay, на это время она тоже станет недоступна — страница восстановится сама.',
  install: async () => installProto('xray'),
  uninstall: {
    label: 'Удалить XRay с сервера',
    body: 'Сервис будет остановлен и выключен из автозапуска, затем удалены бинарь <code>/usr/local/bin/xray</code>, ' +
          'каталог <code>/usr/local/etc/xray</code> и systemd-юнит. Вкладка XRay скроется. ' +
          '<b>Вместе с ядром пропадут Hysteria и XDNS</b> — это его входы, отдельного сервиса у них нет. ' +
          '<b>Если панель открыта по 443 через фоллбек XRay, доступ к ней пропадёт</b> — сначала включите ' +
          'отдельный порт панели.',
    run: async (purge) => {
      const r = await fetch(API + '/api/service/uninstall', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({proto: 'xray', purge_data: purge}),
      });
      return await r.json().catch(() => ({ok: false, error: 'HTTP ' + r.status}));
    },
  },
  afterAction: () => refreshXray(),
};


// --- Порт протокола в ⚙ ------------------------------------------------------
// Один блок на AWG и MTProto: у обоих порт лежит в своём конфиге, зашит в уже
// выданные клиентам ссылки и делит пространство портов с соседями — у AWG это
// инбаунд Hysteria на UDP, у MTProto — VLESS на TCP.
const _PORT_PROTO = {
  awg: {
    box: 'awgPortBox', proto: 'udp', title: 'UDP-порт AmneziaWG',
    note: 'Порт зашит в <code>Endpoint</code> каждого клиентского конфига: после смены всем клиентам ' +
          'нужно выдать конфиги заново — уже установленные продолжат стучаться на старый порт. ' +
          'Панель поправит <code>awg0.conf</code>, откроет порт в ufw и закроет прежний. ' +
          'Поднятому интерфейсу порт меняется на лету, туннели не рвутся.',
  },
  mtg: {
    box: 'mtgPortBox', proto: 'tcp', title: 'TCP-порт MTProto',
    note: 'Порт входит в каждую ссылку <code>t.me/proxy</code>: после смены ссылки надо раздать заново. ' +
          'Панель поправит <code>bind-to</code> в конфиге, откроет порт в ufw и перезапустит сервис. ' +
          'Если прокси не поднимется на новом порту, прежний вернётся автоматически.',
  },
  xray_hy: {
    box: 'xhyPortBox', proto: 'udp', title: 'UDP-порт Hysteria 2 (инбаунд XRay)',
    modalTitle: 'Порт Hysteria 2 в XRay', unit: 'ссылки',
    note: 'Порт зашит во вторую ссылку каждого клиента (<code>hysteria2://</code>) и в профили ' +
          'Loon/Clash/Shadowrocket: после смены их нужно раздать заново. Панель перепишет инбаунд в ' +
          'конфиге XRay, откроет новый порт в ufw и перезапустит XRay (VLESS оборвётся на пару секунд). ' +
          'Если XRay не поднимется на новом номере, прежний вернётся сам. Пока инбаунд выключен, порт ' +
          'только запоминается и применится при включении.',
    steps: ['Перепишет инбаунд Hysteria в конфиге XRay — клиенты, маскировка и обфускация не тронутся',
            'Откроет новый порт в ufw и закроет прежний, если на нём никого не осталось',
            'Перезапустит XRay; VLESS и Hysteria оборвутся на пару секунд',
            'Если XRay не поднимется — вернёт прежний порт сам'],
    // XRay перезапускается после ответа, а панель может отдаваться его же
    // фоллбеком: ждём, пока она снова ответит, и только потом перечитываем.
    after: async (j) => {
      if (j && j.restart_scheduled) {
        showBusyOverlay('Применяем порт Hysteria', 'XRay перезапускается, соединения оборвутся на пару секунд');
        try { await pingUntilAlive(); } finally { hideBusyOverlay(); }
      } else if (j && j.restart_scheduled === false) {
        toast('Инбаунд выключен — порт сохранён и применится при включении Hysteria 2');
      }
      // Несохранённые правки маскировки/обфускации не затираем перерисовкой.
      if (_hyDirty) loadProtoPort('xray_hy'); else loadXrayHysteria();
    },
  },
  hysteria: {
    box: 'hysteriaPortBox', proto: 'udp', title: 'UDP-порт Hysteria',
    modalTitle: 'Порт Hysteria', unit: 'ссылки',
    note: 'Порт зашит в каждую выданную ссылку <code>hysteria2://</code> и в профили Loon/Clash/Shadowrocket: ' +
          'после смены их нужно раздать заново. Панель перепишет <code>config.yaml</code>, откроет новый порт ' +
          'в ufw, закроет прежний и перезапустит сервис. Если он не поднимется на новом номере, ' +
          'прежний вернётся автоматически.',
    steps: ['Перепишет <code>config.yaml</code> — клиенты, сертификат и правила не тронутся',
            'Откроет новый порт в ufw и закроет прежний, если на нём никого не осталось',
            'Перезапустит сервис; живые QUIC-сессии оборвутся, клиенты переподключатся сами',
            'Если сервис не поднимется — вернёт прежний порт и скажет почему'],
    after: () => { try { if (typeof hyRerender === 'function') hyRerender(true); } catch (e) {} },
  },
};
let _protoPort = {};

async function loadProtoPort(kind) {
  const spec = _PORT_PROTO[kind];
  const box = spec && document.getElementById(spec.box);
  if (!box) return;
  try {
    const r = await fetch(API + '/api/' + kind + '/port', {credentials: 'same-origin'});
    const j = await r.json();
    if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
    _protoPort[kind] = j;
    renderProtoPort(kind);
  } catch (e) {
    box.innerHTML = '<div class="psvc-note" style="color:var(--red);">Порт: ' + escHtml(e.message) + '</div>';
  }
}

function renderProtoPort(kind) {
  const spec = _PORT_PROTO[kind];
  const box = document.getElementById(spec.box);
  const j = _protoPort[kind];
  if (!box || !j) return;
  // Протокол не настроен (у AWG нет awg0.conf) — порта нет, менять нечего и
  // конфликтовать не с кем. Не рисуем ни поле, ни кнопки.
  if (j.configured === false) {
    box.innerHTML = '<div class="psvc-sec-h">' + escHtml(spec.title) + '</div>' +
      '<div class="psvc-note">Протокол не настроен — порта пока нет. Он появится после установки.</div>';
    return;
  }
  // Конфликт показываем всегда, даже когда сервис лежит: именно в таком виде
  // он и всплывает — при старте, когда порт уже занял сосед.
  const warn = j.conflict
    ? '<div class="psvc-note" style="margin-bottom:10px;border-color:var(--orange);">' +
      '<b style="color:var(--orange);">Конфликт портов:</b> ' + escHtml(j.conflict) + '</div>'
    : '';
  box.innerHTML =
    '<div class="psvc-sec-h">' + escHtml(spec.title) + '</div>' + warn +
    '<div class="psvc-pair">' +
      '<label class="psvc-field"><span>Порт</span>' +
      '<input class="psvc-inp" id="' + kind + 'PortInp" type="number" value="' + escHtml(String(j.port || '')) + '"></label>' +
      '<div class="psvc-field psvc-btns">' +
      '<div class="psvc-btns-row">' +
      '<button class="btn btn-sm btn-ghost" id="' + kind + 'PortPickBtn">Подобрать свободный</button>' +
      '<button class="btn btn-sm btn-ghost" id="' + kind + 'PortBtn">Сменить порт</button>' +
      '</div></div>' +
    '</div>' +
    '<div class="psvc-row-d" style="margin:-4px 0 12px;">' + spec.note + '</div>';
  // Обработчик вешаем кодом: kind внутри onclick пришлось бы экранировать, а
  // escHtml кавычки не трогает — типовой источник сломанной разметки.
  const btn = document.getElementById(kind + 'PortBtn');
  if (btn) btn.addEventListener('click', () => saveProtoPort(kind));
  const pick = document.getElementById(kind + 'PortPickBtn');
  if (pick) pick.addEventListener('click',
    () => pickFreePortInto(kind, kind + 'PortInp', kind + 'PortPickBtn', '«Сменить порт»'));
}

// «Подобрать свободный» — общий для всех протоколов с изменяемым портом.
// Сервер проверяет кандидата и по живым слушателям, и по реестру портов:
// порт, закреплённый за остановленным соседом, не предлагается. Значение
// только вписывается в поле — применяет его кнопка сохранения.
async function pickFreePortInto(kind, inputId, btnId, saveLabel) {
  const el = document.getElementById(inputId);
  if (!el) return;
  if (btnId) _spinBtn(btnId, true, 'Ищем…');
  try {
    const cur = parseInt(el.value, 10) || 0;
    const r = await fetch(API + '/api/port/suggest?kind=' + encodeURIComponent(kind) +
                          '&current=' + cur, {credentials: 'same-origin'});
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { toast(j.error || 'Свободного порта не нашлось'); return; }
    el.value = j.port;
    // Программная запись не шлёт input — без этого не сработают пометки
    // «не сохранено» и предупреждения при закрытии формы.
    el.dispatchEvent(new Event('input', {bubbles: true}));
    toast('Свободен ' + j.port + '/' + String(j.proto || '').toUpperCase() + ' — нажмите ' + saveLabel);
  } catch (e) {
    toast('Сеть: не удалось');
  } finally {
    if (btnId) _spinBtn(btnId, false);
  }
}

// Модалка смены порта с плитки. Операция трогает конфиг, фаервол и сервис,
// поэтому сначала показываем, что именно произойдёт, а потом — что произошло.
let _portModalKind = '';

async function openPortModal(kind) {
  const spec = _PORT_PROTO[kind];
  if (!spec) return;
  _portModalKind = kind;
  document.getElementById('portModalTitle').textContent =
    spec.modalTitle || (kind === 'awg' ? 'Порт AmneziaWG' : 'Порт MTProto');
  const body = document.getElementById('portModalBody');
  body.innerHTML = '<div class="psvc-note">Читаю текущий порт…</div>';
  document.getElementById('portModal').classList.remove('hidden');
  try {
    const r = await fetch(API + '/api/' + kind + '/port', {credentials: 'same-origin'});
    const j = await r.json();
    if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
    _protoPort[kind] = j;
  } catch (e) {
    body.innerHTML = '<div class="psvc-note" style="color:var(--red);">' + escHtml(e.message) + '</div>';
    return;
  }
  const j = _protoPort[kind];
  const submit = document.getElementById('portModalBtn');
  if (submit) submit.classList.toggle('hidden', j.configured === false);
  if (j.configured === false) {
    body.innerHTML = '<div class="psvc-note">Протокол не настроен — порта пока нет. Он появится после установки.</div>';
    return;
  }
  const steps = spec.steps || (kind === 'awg'
    ? ['Поправит <code>ListenPort</code> в awg0.conf — ключи, обфускация и пиры не тронутся',
       'Откроет новый порт в ufw и закроет прежний, если на нём никого не осталось',
       'Поднятому интерфейсу сменит порт на лету — туннели не оборвутся']
    : ['Поправит <code>bind-to</code> в config.toml — секрет прокси не тронется',
       'Откроет новый порт в ufw и закроет прежний, если на нём никого не осталось',
       'Перезапустит сервис; если он не поднимется — вернёт прежний порт сам']);
  body.innerHTML =
    (j.conflict ? '<div class="psvc-note" style="margin-bottom:12px;border-color:var(--orange);">' +
       '<b style="color:var(--orange);">Конфликт:</b> ' + escHtml(j.conflict) + '</div>' : '') +
    '<div style="font-size:13px;color:var(--text2);margin-bottom:12px;">Сейчас: <b>' +
      escHtml(String(j.port || '—')) + '/' + spec.proto.toUpperCase() + '</b></div>' +
    '<div class="psvc-pair">' +
    '<label class="psvc-field"><span>Новый порт</span>' +
    '<input class="psvc-inp" id="portModalInp" type="number" value="' + escHtml(String(j.port || '')) + '"></label>' +
    '<div class="psvc-field"><span>&nbsp;</span>' +
    '<button class="btn btn-sm btn-ghost" id="portModalPickBtn" style="height:34px;">Подобрать свободный</button></div>' +
    '</div>' +
    '<div class="psvc-note" style="margin-top:6px;">Что сделает панель:<ul style="margin:6px 0 0;padding-left:18px;">' +
      steps.map(t => '<li style="margin-bottom:4px;">' + t + '</li>').join('') +
    '</ul></div>' +
    '<div class="psvc-note" style="margin-top:10px;border-color:var(--orange);">' +
      '<b style="color:var(--orange);">После смены клиентам нужно выдать ' +
      (spec.unit || (kind === 'awg' ? 'конфиги' : 'ссылки')) + ' заново:</b> старый порт зашит в то, что ' +
      'уже стоит на устройствах, и сам он там не обновится.</div>';
  const pick = document.getElementById('portModalPickBtn');
  if (pick) pick.addEventListener('click',
    () => pickFreePortInto(kind, 'portModalInp', 'portModalPickBtn', '«Сменить порт»'));
}

async function submitPortModal() {
  const kind = _portModalKind;
  const spec = _PORT_PROTO[kind];
  if (!spec) return;
  const cur = (_protoPort[kind] || {}).port || 0;
  const val = parseInt((document.getElementById('portModalInp') || {}).value, 10) || 0;
  if (!val || val < 1 || val > 65535) { toast('Порт вне диапазона 1–65535'); return; }
  if (val === cur) { toast('Это текущий порт'); return; }
  _spinBtn('portModalBtn', true, 'Меняем…');
  showBusyOverlay('Меняем порт на ' + val,
                  kind === 'awg' ? 'Правим awg0.conf, фаервол и интерфейс'
                                 : 'Правим конфиг, фаервол и перезапускаем сервис');
  try {
    const r = await fetch(API + '/api/' + kind + '/port', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify({port: val}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { toast(j.error || 'Не удалось сменить порт'); return; }
    _protoPort[kind] = j;
    closeModal('portModal');
    toast('Порт ' + (j.old_port || '?') + ' → ' + j.port + '. Выдайте клиентам новые ' +
          (spec.unit || (kind === 'awg' ? 'конфиги' : 'ссылки')));
    // Порт был закреплён за остановленным соседом: столкнутся они не сейчас,
    // а когда тот сервис запустят — сказать об этом надо сразу.
    if (j.warning) toast(j.warning);
    renderProtoPort(kind);                       // если открыта ⚙ — обновим и там
    if (kind === 'awg' && typeof refreshStatus === 'function') refreshStatus();
    if (kind === 'mtg' && typeof refreshMtg === 'function') refreshMtg();
    if (spec.after) await spec.after(j);
  } catch (e) {
    toast(e.message);
  } finally {
    hideBusyOverlay();
    _spinBtn('portModalBtn', false);
  }
}

// Подпись о конфликте прямо под портом на плитке: без неё столкновение видно
// только в момент, когда сервис уже не поднялся.
function paintPortConflict(kind, conflict) {
  const el = document.getElementById(kind + 'PortConflict');
  if (!el) return;
  if (conflict) {
    el.textContent = conflict;
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
}

async function refreshPortConflict(kind) {
  try {
    const r = await fetch(API + '/api/' + kind + '/port', {credentials: 'same-origin'});
    const j = await r.json();
    if (r.ok && j.ok) {
      _protoPort[kind] = j;
      paintPortConflict(kind, j.conflict || '');
    }
  } catch (e) { /* плитка обойдётся без подписи */ }
}

async function saveProtoPort(kind) {
  const spec = _PORT_PROTO[kind];
  const cur = (_protoPort[kind] || {}).port || 0;
  const val = parseInt((document.getElementById(kind + 'PortInp') || {}).value, 10) || 0;
  if (!val || val < 1 || val > 65535) { toast('Порт вне диапазона 1–65535'); return; }
  if (val === cur) { toast('Это текущий порт'); return; }
  const ok = await openConfirm({
    title: 'Сменить порт на ' + val + '?',
    body: spec.note + '<br><br><b>Клиентам придётся выдать конфиги и ссылки заново.</b>',
    okLabel: 'Сменить',
  });
  if (!ok) return;
  _spinBtn(kind + 'PortBtn', true, 'Меняем…');
  try {
    const r = await fetch(API + '/api/' + kind + '/port', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin', body: JSON.stringify({port: val}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) { toast(j.error || 'Не удалось сменить порт'); return; }
    _protoPort[kind] = j;
    renderProtoPort(kind);
    toast('Порт: ' + (j.old_port || '?') + ' → ' + j.port + '. Выдайте клиентам новые ' +
          (spec.unit || (kind === 'awg' ? 'конфиги' : 'ссылки')));
    if (j.warning) toast(j.warning);
    if (kind === 'awg' && typeof refreshStatus === 'function') refreshStatus();
    if (kind === 'mtg' && typeof refreshMtg === 'function') refreshMtg();
    if (spec.after) await spec.after(j);
  } catch (e) {
    toast(e.message);
  } finally {
    _spinBtn(kind + 'PortBtn', false);
  }
}

PROTO_SVC.mtg = {
  title: 'MTProto',
  load: () => _svcStateGeneric('mtg'),
  optionsHtml: (s) =>
    _psvcSwitchRow('mtgPreferIpToggle', 'rowMtgPreferIp', 'Приоритет IPv4 к Telegram',
      'mtg сначала пробует IPv4, IPv6 остаётся запасным. Лечит зависания, когда у сервера есть IPv6-адрес, ' +
      'но нет рабочего маршрута наружу. Сервис перезапустится.',
      _mtgFlags.preferIp4, 'onMtgPreferIpToggle(this.checked)') +
    `<div class="psvc-row">
      <div class="psvc-row-body">
        <div class="psvc-row-t">Секрет прокси</div>
        <div class="psvc-row-d">Один общий секрет на весь сервер. При пересоздании старая ссылка перестанет
          работать у всех, кому была выдана.</div>
      </div>
      <button class="btn btn-sm btn-ghost" onclick="regenerateMtg()">Пересоздать</button>
    </div>
    <div class="psvc-row">
      <div class="psvc-row-body">
        <div class="psvc-row-t">Расписание</div>
        <div class="psvc-row-d">Автоматическая остановка или запуск сервиса в заданную дату.</div>
      </div>
      <button class="btn btn-sm btn-ghost" onclick="openMtgSchedule()">Настроить</button>
    </div>
    <div id="mtgPortBox" style="margin-top:16px;"><div class="psvc-note">Читаю порт…</div></div>`,
  onMount: () => loadProtoPort('mtg'),
  restartNote: 'Перезапуск рвёт Telegram-соединения на пару секунд; клиенты переподключаются сами.',
  install: async () => installProto('mtg'),
  uninstall: {
    label: 'Удалить MTProto-прокси с сервера',
    body: 'Сервис будет остановлен и выключен из автозапуска, затем удалены бинарь <code>/usr/local/bin/mtg</code>, ' +
          'каталог <code>/etc/mtg</code> и systemd-юнит. Вкладка MTProto скроется.',
    run: async (purge) => {
      const r = await fetch(API + '/api/service/uninstall', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({proto: 'mtg', purge_data: purge}),
      });
      return await r.json().catch(() => ({ok: false, error: 'HTTP ' + r.status}));
    },
  },
  afterAction: () => refreshMtg(),
};

function applyVisibilityFromConfig() {
  if (!_serverConfig) return;
  const enabledP = new Set(_serverConfig.enabled_protocols || ALL_PROTOCOLS);
  ['awg', 'xray', 'mtg'].forEach(id => {
    const cap = id.charAt(0).toUpperCase() + id.slice(1);
    const t = document.getElementById('tab' + cap);
    if (t) t.classList.toggle('hidden', !enabledP.has(id));
    const sec = document.getElementById('section' + cap);
    if (sec && !enabledP.has(id)) sec.classList.add('hidden');
  });
  const visible = ALL_PROTOCOLS.find(p => enabledP.has(p));
  // Вкладка Mihomo не протокол и в enabled_protocols не значится — её видимость
  // определяется тем, установлен ли движок. Без этой проверки загрузка конфига
  // выкидывала бы пользователя с открытой вкладки Mihomo обратно на AWG.
  if (visible && currentTab && currentTab !== 'mihomo' && !enabledP.has(currentTab)) switchTab(visible);
  applyPlatformVisibility();
}

function isPlatformEnabled(platform) {
  if (!_serverConfig) return true;
  const en = _serverConfig.enabled_platforms || ALL_PLATFORMS;
  return en.includes(platform);
}

function applyPlatformVisibility() {
  // Config modal tabs
  const map = {
    shadowrocket: ['cfgTabShadow'],
    loon:         ['cfgTabLoon'],
    clash:        ['cfgTabClash'],
  };
  for (const [plat, ids] of Object.entries(map)) {
    const enabled = isPlatformEnabled(plat);
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('hidden', !enabled);
    });
  }
  // Repaint XRay client cards (their per-platform sub-blocks depend on visibility)
  if (typeof renderXrayClients === 'function' && _lastXrayData) renderXrayClients(_lastXrayData);
  // Re-render new-client modal blocks if it's open
  if (typeof _renderNewClientPlatforms === 'function' && !document.getElementById('xrayAddModal').classList.contains('hidden')) {
    _renderNewClientPlatforms();
  }
}

// ============================================================
// Сервер и обновления (имя сервера + панель / гео / blackmatrix7)
// ============================================================
let _updateInfo = null;
async function checkForUpdates() {
  try {
    const r = await fetch(API + '/api/update/check');
    if (!r.ok) return;
    _updateInfo = await r.json();
    if (_updateInfo.geo && _updateInfo.geo.remote) {
      document.getElementById('brandGeoVersion').textContent = 'geo ' + _updateInfo.geo.remote;
    }
    // Уведомляем в подвале только если есть обновление с ВЫКЛЮЧЕННЫМ авто-свитчем.
    // Включённый свитч = тихое авто-обновление, дёргать юзера не нужно.
    const needsAttention = ['panel', 'geo', 'bm7'].some(k =>
      _updateInfo[k] && _updateInfo[k].update_available && !_updateInfo[k].auto);
    document.getElementById('updateBtn').classList.toggle('hidden', !needsAttention);
    const modal = document.getElementById('serverUpdatesModal');
    if (modal && !modal.classList.contains('hidden')) renderServerUpdates();
  } catch (e) {}
}

function openServerUpdatesModal() {
  const nameEl = document.getElementById('suServerNameInput');
  if (nameEl) nameEl.value = (_serverConfig && _serverConfig.server_name) || '';
  renderServerUpdates();
  _suBaseline = _suSnapshot();   // эталон для «Сохранить» (неактивна пока нет изменений)
  _suCheckDirty();
  const prog = document.getElementById('suProgress');
  prog.style.display = 'none'; prog.innerHTML = '';
  document.getElementById('serverUpdatesModal').classList.remove('hidden');
  if (!_updateInfo) checkForUpdates();  // подтянет версии и перерисует
}

// Снимок текущих значений контролов модалки (имя + периоды + свитчи).
function _suSnapshot() {
  const v = id => { const e = document.getElementById(id); return e ? e.value : ''; };
  const c = id => { const e = document.getElementById(id); return e ? e.checked : false; };
  return JSON.stringify({
    name: (v('suServerNameInput') || '').trim(),
    pi: v('suPanelInterval'), pa: c('suPanelAuto'),
    gi: v('suGeoInterval'),   ga: c('suGeoAuto'),
    bi: v('suBm7Interval'),   ba: c('suBm7Auto'),
  });
}
let _suBaseline = '';
function _suCheckDirty() {
  const btn = document.getElementById('suSaveBtn');
  if (!btn) return;
  btn.disabled = (_suSnapshot() === _suBaseline);
}

function _suFmtCheck(ts) {
  return ts ? fmtAuditTs(ts) : 'ещё не проверялось';
}

function _suGeoDate(s) {
  // 'YYYYMMDD' → 'DD.MM.YYYY'; остальное возвращаем как есть
  if (!s) return '';
  const m = String(s).match(/^(\d{4})(\d{2})(\d{2})$/);
  return m ? `${m[3]}.${m[2]}.${m[1]}` : String(s);
}

// Ручная проверка не должна затирать несохранённые период и свитч.
let _suKeepInputs = false;

function _suBlock(prefix, cur, avail, remote, lastCheck, interval, auto) {
  document.getElementById(prefix + 'Ver').textContent = cur || '—';
  // Пустой remote — сервер обновлений не ответил. «Актуально» тут было бы неправдой.
  const state = !_updateInfo ? 'Проверяем…' : (remote ? 'актуально' : 'нет связи с сервером обновлений');
  document.getElementById(prefix + 'Meta').innerHTML =
    (avail
      ? `<span style="color:#9f9">Доступно обновление${remote ? ' → ' + remote : ''}</span>`
      : `<span style="color:var(--text3)">${state}</span>`)
    + `<br><span style="color:var(--text3)">Последняя проверка: ${_suFmtCheck(lastCheck)}</span>`;
  const upd = document.getElementById(prefix + 'UpdBtn');
  upd.classList.toggle('hidden', !avail);
  upd.textContent = remote ? 'Обновить до ' + remote : 'Обновить';
  if (_suKeepInputs) return;
  const intEl = document.getElementById(prefix + 'Interval');
  if (document.activeElement !== intEl) intEl.value = interval;
  const sw = document.getElementById(prefix + 'Auto');
  sw.checked = !!auto;
  const row = sw.closest('.switch-row');
  if (row) row.classList.toggle('is-on', !!auto);
}

function renderServerUpdates() {
  const u = _updateInfo || {};
  const cfg = _serverConfig || {};
  const P = u.panel || {}, G = u.geo || {}, B = u.bm7 || {};
  _suBlock('suPanel', P.current ? 'v' + P.current : (cfg.panel_version ? 'v' + cfg.panel_version : ''),
    P.update_available, P.remote ? 'v' + P.remote : '',
    P.last_check, P.interval_days || cfg.panel_check_interval_days || 1,
    P.auto !== undefined ? P.auto : cfg.panel_auto_update !== false);
  _suBlock('suGeo', _suGeoDate(G.local), G.update_available, _suGeoDate(G.remote),
    G.last_check, G.interval_days || cfg.geo_check_interval_days || 180,
    G.auto !== undefined ? G.auto : cfg.geo_auto_update !== false);
  _suBlock('suBm7', B.local || '', B.update_available, B.remote || '',
    B.last_check, B.interval_days || cfg.bm7_check_interval_days || 7,
    B.auto !== undefined ? B.auto : cfg.bm7_auto_update !== false);
  // Единая нижняя кнопка: «Обновить» (как «Сохранить») если есть хоть одно обновление,
  // иначе «Проверить» (как «Закрыть»).
  const anyAvail = [P, G, B].some(x => x && x.update_available);
  const mb = document.getElementById('suMainBtn');
  if (mb) {
    mb.textContent = anyAvail ? 'Обновить' : 'Проверить';
    mb.classList.toggle('btn-success', anyAvail);
    mb.classList.toggle('btn-ghost', !anyAvail);
  }
  _suCheckDirty();
}

// Единая кнопка: есть обновления → применить всё; иначе — перепроверить.
function _suAnyAvail() {
  return !!(_updateInfo && ['panel', 'geo', 'bm7'].some(k => _updateInfo[k] && _updateInfo[k].update_available));
}
async function suMainAction() {
  if (_suAnyAvail()) return applyAllUpdates();
  await suRecheck();
  const offline = ['panel', 'geo', 'bm7'].every(k => !_suVersions(k).remote);
  toast(offline ? 'Нет связи с сервером обновлений'
                : (_suAnyAvail() ? 'Доступно обновление — нажмите «Обновить»' : 'Обновлений нет'));
}

// Проверка одного блока кнопкой на его карточке.
async function suCheckOne(kind) {
  if (_updateBusy) return;
  const btnId = _SU_ONE[kind].prefix + 'CheckBtn';
  _spinBtn(btnId, true);
  const ok = await suRecheck(kind);
  _spinBtn(btnId, false);
  const v = _suVersions(kind);
  if (!ok || !v.remote) toast('Нет связи с сервером обновлений');
  else toast(_updateInfo[kind].update_available ? 'Есть обновление: ' + v.remote : 'Установлена актуальная версия');
}

// touch — что считать проверенным вручную: '1' всё, имя блока — его, '' ничего
// (просто свежие версии перед диалогом). Возвращает, ответил ли бэкенд.
async function suRecheck(touch = '1') {
  _suSetBusy(true);
  let answered = false;
  try {
    const r = await fetch(API + '/api/update/check' + (touch ? '?touch=' + touch : ''));
    if (r.ok) {
      answered = true;
      _updateInfo = await r.json();
      if (_updateInfo.geo && _updateInfo.geo.remote)
        document.getElementById('brandGeoVersion').textContent = 'geo ' + _updateInfo.geo.remote;
      const needsAttention = ['panel', 'geo', 'bm7'].some(k =>
        _updateInfo[k] && _updateInfo[k].update_available && !_updateInfo[k].auto);
      document.getElementById('updateBtn').classList.toggle('hidden', !needsAttention);
    }
  } catch (e) {}
  _suKeepInputs = true;
  renderServerUpdates();
  _suKeepInputs = false;
  _suSetBusy(false);
  return answered;
}

function _suSanitizeName(el) {
  el.value = (el.value || '').replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
}

// Общая кнопка «Сохранить»: имя сервера + периоды + свитчи одним запросом.
async function suSaveAll() {
  const nameEl = document.getElementById('suServerNameInput');
  const name = (nameEl.value || '').trim();
  if (!name) { toast('Имя сервера не может быть пустым'); nameEl.focus(); return; }
  const intv = id => Math.max(1, parseInt(document.getElementById(id).value) || 1);
  const body = {
    server_name: name,
    panel_check_interval_days: intv('suPanelInterval'),
    panel_auto_update: document.getElementById('suPanelAuto').checked,
    geo_check_interval_days: intv('suGeoInterval'),
    geo_auto_update: document.getElementById('suGeoAuto').checked,
    bm7_check_interval_days: intv('suBm7Interval'),
    bm7_auto_update: document.getElementById('suBm7Auto').checked,
  };
  const btn = document.getElementById('suSaveBtn');
  const orig = btn.textContent; btn.disabled = true; btn.textContent = 'Сохраняю…';
  try {
    const r = await fetch(API + '/api/server/config', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.ok) {
      _serverConfig = j.config;
      // Период и свитч лежат в ДВУХ клиентских кэшах: _serverConfig и _updateInfo
      // (оба читают один server.json). Перезапрашивается тут только первый, поэтому
      // второй синхронизируем руками — иначе renderServerUpdates(), который берёт
      // interval_days/auto из _updateInfo, покажет старые значения до «Проверить».
      if (_updateInfo) {
        const sync = (k, iv, au) => {
          if (_updateInfo[k]) { _updateInfo[k].interval_days = iv; _updateInfo[k].auto = au; }
        };
        sync('panel', body.panel_check_interval_days, body.panel_auto_update);
        sync('geo',   body.geo_check_interval_days,   body.geo_auto_update);
        sync('bm7',   body.bm7_check_interval_days,   body.bm7_auto_update);
      }
      await loadServerConfig();
      toast('Сохранено');
      closeModal('serverUpdatesModal');
    } else { toast(j.error || 'Ошибка сохранения'); }
  } catch (e) { toast('Ошибка: ' + e.message); }
  finally { btn.disabled = false; btn.textContent = orig; }
}

let _updateBusy = false;
function _suSetBusy(on) {
  _updateBusy = on;
  const mb = document.getElementById('suMainBtn');
  if (mb) { mb.disabled = !!on; mb.style.opacity = on ? '0.55' : ''; }
  const sb = document.getElementById('suSaveBtn');
  if (sb) { sb.style.opacity = on ? '0.55' : ''; if (on) sb.disabled = true; else _suCheckDirty(); }
  // Per-блочные «Обновить»: бэкенд держит один _UPDATE_LOCK на всех, поэтому
  // на время операции гасим все три, а не только нажатую.
  document.querySelectorAll('.su-upd-btn').forEach(b => {
    b.disabled = !!on; b.style.opacity = on ? '0.55' : '';
  });
}

// Одна кнопка «Обновить»: применяет всё свежее (панель + гео + blackmatrix7) одним
// запросом; рестарт (если нужен) один в конце.
async function applyAllUpdates() {
  if (_updateBusy) return;
  const LBL = {panel: 'панель', geo: 'гео-базы', bm7: 'шаблоны blackmatrix7'};
  const items = ['panel', 'geo', 'bm7']
    .filter(k => _updateInfo[k] && _updateInfo[k].update_available).map(k => LBL[k]);
  const ok = await openConfirm({
    title: 'Обновить?',
    body: 'Будет обновлено: ' + items.join(', ') + '.\nОбновление панели или гео-баз перезапустит панель.',
    okLabel: 'Обновить',
  });
  if (!ok) return;
  _suSetBusy(true);
  const prog = document.getElementById('suProgress');
  prog.style.display = 'block'; prog.innerHTML = 'Запуск обновления…\n';
  pollAuditDuringUpdate();
  try {
    const r = await fetch(API + '/api/update/apply-all', {method: 'POST'});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.ok) {
      if (j.restart) {
        toast('Обновление применено. Перезапуск…');
        setTimeout(() => location.reload(), 6000);
        return;  // не снимаем busy — идёт перезапуск
      }
      toast('Обновлено: ' + (j.done && j.done.length ? j.done.join(', ') : 'нет изменений'));
      if (_updatePollTimer) clearInterval(_updatePollTimer);
      _updateInfo = null; await checkForUpdates(); renderServerUpdates();
    } else {
      toast(j.error || 'Ошибка обновления');
      if (_updatePollTimer) clearInterval(_updatePollTimer);
    }
  } catch (e) { toast('Ошибка: ' + e.message); if (_updatePollTimer) clearInterval(_updatePollTimer); }
  _suSetBusy(false);
}
// Обновление или переустановка ОДНОГО блока (панель / гео / шаблоны). Эндпоинты
// форсированные: панель и гео перекачиваются без сверки версий и требуют рестарта,
// шаблоны — без рестарта (заодно тянут свои шаблоны с byfox).
const _SU_ONE = {
  panel: {url: '/api/update/apply-panel', label: 'панель',   prefix: 'suPanel', restart: true,
          reinstall: 'Панель скачается заново и ляжет поверх текущей: код заменится целиком. Клиенты, настройки и логи не затрагиваются. Панель перезапустится на несколько секунд.'},
  geo:   {url: '/api/update/apply-geo',   label: 'гео-базы', prefix: 'suGeo',   restart: true,
          reinstall: 'Гео-базы скачаются заново и заменят текущие. Панель перезапустится на несколько секунд.'},
  bm7:   {url: '/api/update/apply-bm7',   label: 'шаблоны',  prefix: 'suBm7',   restart: false,
          reinstall: 'Библиотека шаблонов скачается заново. Списки, уже выбранные у клиентов, не изменятся. Перезапуск не требуется.'},
};

// Версии блока для диалогов. older — на сервере обновлений версия старше установленной:
// форсированная установка вернула бы панель назад, так бывает, пока CDN не догнал сервер.
function _suVersions(kind) {
  const u = (_updateInfo && _updateInfo[kind]) || {};
  if (kind === 'panel') {
    const nums = s => String(s || '').split('.').map(x => parseInt(x) || 0);
    const [a, b] = [nums(u.remote), nums(u.current)];
    let older = false;
    for (let i = 0; i < 3; i++) {
      if ((a[i] || 0) !== (b[i] || 0)) { older = (a[i] || 0) < (b[i] || 0); break; }
    }
    return {cur: u.current ? 'v' + u.current : '—', remote: u.remote ? 'v' + u.remote : '', older: !!u.remote && older};
  }
  if (kind === 'geo') {
    return {cur: _suGeoDate(u.local) || '—', remote: _suGeoDate(u.remote),
            older: !!u.remote && !!u.local && u.remote < u.local};
  }
  return {cur: u.local || '—', remote: u.remote || '', older: false};
}

async function _suConfirmReinstall(kind) {
  const c = _SU_ONE[kind];
  await suRecheck('');   // решение принимается по свежим версиям, а не по открытию окна
  const v = _suVersions(kind);
  if (!v.remote) {
    await openAlert({title: 'Нет связи с сервером обновлений',
                     body: 'Переустановка скачивает файлы оттуда. Попробуйте позже.', okLabel: 'Понятно'});
    return false;
  }
  const line = `<div style="margin-top:10px;">Установлена ${escHtml(v.cur)}, на сервере обновлений ${escHtml(v.remote)}.</div>`;
  if (v.older) {
    return openConfirm({
      title: 'Переустановка вернёт старую версию',
      body: `<div>${c.reinstall}</div>${line}<div style="margin-top:10px;">На сервере обновлений версия старше установленной: будет установлена ${escHtml(v.remote)}, и более новые исправления пропадут.</div>`,
      okLabel: 'Вернуть старую версию', danger: true,
    });
  }
  return openConfirm({title: 'Переустановить: ' + c.label + '?', body: `<div>${c.reinstall}</div>${line}`, okLabel: 'Переустановить'});
}

// opts.noConfirm — запуск без диалога (кнопка «Обновить шаблоны» в каталоге правил:
// операция без перезапуска и без побочных эффектов, спрашивать не о чем).
// opts.reinstall — та же установка, но со своим диалогом и сверкой версий.
async function suApplyOne(kind, opts) {
  if (_updateBusy) return false;
  const c = _SU_ONE[kind];
  if (!c) return false;
  if (opts && opts.reinstall) {
    if (!await _suConfirmReinstall(kind)) return false;
  } else if (!(opts && opts.noConfirm)) {
    const v = _suVersions(kind);
    const ok = await openConfirm({
      title: 'Обновить: ' + c.label + '?',
      body: `<div>Установлена ${escHtml(v.cur)}, будет установлена ${escHtml(v.remote || '—')}.</div>`
          + `<div style="margin-top:10px;">${c.restart ? 'Панель перезапустится.' : 'Перезапуск не требуется.'}</div>`,
      okLabel: 'Обновить',
    });
    if (!ok) return false;
  }
  _suSetBusy(true);
  let done = false;
  const prog = document.getElementById('suProgress');
  if (prog) { prog.style.display = 'block'; prog.innerHTML = 'Запуск обновления…\n'; }
  pollAuditDuringUpdate();
  try {
    const r = await fetch(API + c.url, {method: 'POST'});
    const j = await r.json().catch(() => ({}));
    if (r.ok && j.ok) {
      if (c.restart) {
        toast(c.label + ': обновлено. Перезапуск…');
        setTimeout(() => location.reload(), 6000);
        return;   // busy не снимаем — идёт перезапуск
      }
      if (_updatePollTimer) clearInterval(_updatePollTimer);
      toast(j.message || (c.label + ': обновлено'));   // у шаблонов бэкенд пишет, что изменилось
      done = true;
      _updateInfo = null; await checkForUpdates(); renderServerUpdates();
    } else {
      toast(j.error || 'Ошибка обновления');
      if (_updatePollTimer) clearInterval(_updatePollTimer);
    }
  } catch (e) { toast('Ошибка: ' + e.message); if (_updatePollTimer) clearInterval(_updatePollTimer); }
  _suSetBusy(false);
  return done;
}

// «Обновить шаблоны» в каталоге правил. Та же принудительная синхронизация
// библиотеки blackmatrix7, что и кнопка «Обновить» в «Сервер и обновления»,
// только без диалога. После неё перечитываем библиотеку, иначе пикер шаблонов
// до конца сессии показывал бы прежний кэш.
async function rmRefreshTemplates(btnId) {
  if (_updateBusy) return;
  _spinBtn(btnId, true, 'Обновляем…');
  try {
    const ok = await suApplyOne('bm7', {noConfirm: true});
    if (ok) {
      _tplServicesLoaded = false;
      await loadRuleTemplates();
      if (!document.getElementById('templatePickerModal').classList.contains('hidden')) _renderTemplates();
    }
  } finally {
    _spinBtn(btnId, false);
  }
}

let _updatePollTimer = null;
function pollAuditDuringUpdate() {
  if (_updatePollTimer) clearInterval(_updatePollTimer);
  _updatePollTimer = setInterval(async () => {
    try {
      const r = await fetch(API + '/api/audit?n=20');
      const j = await r.json();
      const target = document.getElementById('suProgress');
      if (target) target.innerHTML = (j.items || []).map(it =>
        `<div class="audit-line ${it.level}"><span class="ts">${fmtAuditTs(it.ts)}</span>${escHtml(it.msg)}</div>`).join('');
      if (target) target.scrollTop = target.scrollHeight;
    } catch (e) {}
  }, 1500);
}

// ============================================================
// Audit log strip + modal
// ============================================================
async function refreshAuditStrip() {
  try {
    const r = await fetch(API + '/api/audit?n=1');
    const j = await r.json();
    if (j.items && j.items.length) {
      const last = j.items[j.items.length - 1];
      document.getElementById('auditLatest').textContent = `${fmtAuditTs(last.ts)} · ${last.msg}`;
      document.getElementById('auditStrip').classList.remove('hidden');
    }
  } catch (e) {}
}
function toggleAuditStrip() {
  const body = document.getElementById('auditBody');
  const strip = document.getElementById('auditStrip');
  body.classList.toggle('hidden');
  const open = !body.classList.contains('hidden');
  if (strip) strip.classList.toggle('is-open', open);
  if (open) loadAuditStripBody();
}
async function loadAuditStripBody() {
  const r = await fetch(API + '/api/audit?n=50');
  const j = await r.json();
  document.getElementById('auditBody').innerHTML = (j.items || []).slice().reverse().map(it =>
    `<div class="audit-line ${it.level}"><span class="ts">${fmtAuditTs(it.ts)}</span>${escHtml(it.msg)}</div>`).join('');
}
function openAuditModal() {
  document.getElementById('auditModal').classList.remove('hidden');
  loadAuditFull();
}
async function loadAuditFull() {
  const r = await fetch(API + '/api/audit?n=400');
  const j = await r.json();
  document.getElementById('auditLogBlock').innerHTML = (j.items || []).slice().reverse().map(it =>
    `<div class="audit-line ${it.level}"><span class="ts">${fmtAuditTs(it.ts)}</span>${escHtml(it.msg)}</div>`).join('');
}

// ============================================================
// Backup
// ============================================================
function openBackupModal() {
  document.getElementById('backupModal').classList.remove('hidden');
  loadBackupStatus();
}
async function loadBackupStatus() {
  try {
    const r = await fetch(API + '/api/backup/status');
    const j = await r.json();
    const cfg = j.config || {};
    // Что попадает в архив: корень панели (все файлы и подпапки), без указанных папок,
    // плюс внешние конфиги сервисов с реального сервера (читаются через _backup_external_files()
    // — единый источник правды с «Системными путями» и «Источниками правды»).
    const ext = j.external_files || [];
    const extMissing = j.external_files_missing || [];
    const excludes = j.excludes || [];

    const extListHtml = ext.length
      ? ext.map(p => `<div class="bk-info-line"><span class="bk-info-bullet">✓</span><code>${escHtml(p)}</code></div>`).join('')
      : '<div class="bk-info-line" style="color:var(--text3);">— нет (ни одного сервиса не найдено)</div>';
    const extMissingHtml = extMissing.length
      ? extMissing.map(p => `<div class="bk-info-line"><span class="bk-info-bullet" style="color:var(--text3);">○</span><code style="color:var(--text3);">${escHtml(p)}</code> <span style="color:var(--text3);font-size:11px;">— файла нет, в архив не попадёт</span></div>`).join('')
      : '';
    const excludesHtml = excludes.length
      ? excludes.map(x => `<code>${escHtml(x)}</code>`).join(' ')
      : '<span style="color:var(--text3);">—</span>';

    document.getElementById('backupPathsInfo').innerHTML = `
      <div class="bk-info-block">
        <div class="bk-info-row"><span class="bk-info-key">Корень панели:</span><code>${escHtml(j.panel_root || '')}/</code></div>
        <div class="bk-info-row"><span class="bk-info-key">Исключения:</span>${excludesHtml}</div>
        <div class="bk-info-row"><span class="bk-info-key">Папка архивов:</span><code>${escHtml(j.backup_dir || '')}</code></div>
      </div>
      <div class="bk-info-block">
        <div class="bk-info-row"><span class="bk-info-key">Внешние конфиги сервисов:</span></div>
        ${extListHtml}
        ${extMissingHtml}
      </div>
    `;
    document.getElementById('bkLastSize').textContent = j.last ? j.last.size_h : '—';
    document.getElementById('bkLastDate').textContent = j.last ? _fmtServerTs(j.last.ts, true) : 'нет';
    document.getElementById('bkTotalSize').textContent = j.total_size_h || '0 B';
    document.getElementById('bkCount').textContent = j.count || 0;
    document.getElementById('bkNextRun').textContent = j.next_run
      ? _fmtServerTs(j.next_run, true)
      : (cfg.schedule_enabled ? 'скоро' : 'выкл.');
    document.getElementById('bkEnabled').checked = !!cfg.schedule_enabled;
    document.getElementById('bkIntervalValue').value = cfg.interval_value || 1;
    document.getElementById('bkIntervalUnit').value = cfg.interval_unit || 'days';
    const rm = cfg.retention_mode || 'count';
    document.querySelectorAll('input[name="bkRetMode"]').forEach(el => { el.checked = (el.value === rm); });
    document.getElementById('bkRetCount').value = cfg.retention_count || 10;
    document.getElementById('bkRetSize').value = cfg.retention_size_mb || 100;
    renderBackupList(j.items || []);
  } catch (e) {
    toast('Не удалось загрузить статус бэкапа');
  }
}
function renderBackupList(items) {
  const el = document.getElementById('bkList');
  if (!items.length) {
    el.innerHTML = '<div style="padding:14px;color:var(--text3);font-size:13px;text-align:center;">Бэкапов пока нет</div>';
    return;
  }
  el.innerHTML = items.map(it => `
    <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid var(--border);">
      <div style="flex:1;min-width:0;">
        <div style="color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;">${escHtml(it.name)}</div>
        <div style="color:var(--text3);font-size:11px;">${_fmtServerTs(it.ts, true)} · ${it.size_h}</div>
      </div>
      <a class="btn btn-sm btn-ghost" href="${API}/api/backup/download/${encodeURIComponent(it.name)}" download>↓</a>
      <button class="btn btn-sm btn-ghost" onclick="backupAskRestore('${escHtml(it.name)}')">Восстановить</button>
      <button class="btn btn-sm btn-ghost" onclick="backupAskDelete('${escHtml(it.name)}')" style="color:var(--red);">×</button>
    </div>`).join('');
}
async function backupQuickRun() {
  toast('Создаю бэкап…');
  try {
    const r = await fetch(API + '/api/backup/run', {method: 'POST'});
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'fail');
    toast(`Бэкап создан: ${j.size_h}`);
  } catch (e) {
    toast('Ошибка: ' + e.message);
  }
  try { refreshAuditStrip(); } catch(_) {}
  try { if (!document.getElementById('auditBody').classList.contains('hidden')) loadAuditStripBody(); } catch(_) {}
}
async function backupRunNow() {
  const btn = document.getElementById('bkRunBtn');
  const status = document.getElementById('bkRunStatus');
  btn.disabled = true; status.textContent = 'Создаю архив…';
  try {
    const r = await fetch(API + '/api/backup/run', {method: 'POST'});
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'fail');
    status.textContent = `Готово: ${j.size_h}`;
    toast(`Бэкап создан: ${j.size_h}`);
    loadBackupStatus();
  } catch (e) {
    status.textContent = '';
    toast('Ошибка: ' + e.message);
  } finally {
    btn.disabled = false;
    setTimeout(() => { status.textContent = ''; }, 4000);
  }
  try { refreshAuditStrip(); } catch(_) {}
  try { if (!document.getElementById('auditBody').classList.contains('hidden')) loadAuditStripBody(); } catch(_) {}
}
async function backupSaveSchedule() {
  const body = {
    schedule_enabled: document.getElementById('bkEnabled').checked,
    interval_value: parseInt(document.getElementById('bkIntervalValue').value, 10) || 1,
    interval_unit: document.getElementById('bkIntervalUnit').value,
    retention_mode: document.querySelector('input[name="bkRetMode"]:checked')?.value || 'count',
    retention_count: parseInt(document.getElementById('bkRetCount').value, 10) || 10,
    retention_size_mb: parseInt(document.getElementById('bkRetSize').value, 10) || 100,
  };
  try {
    const r = await fetch(API + '/api/backup/schedule', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'fail');
    toast('Настройки сохранены');
    loadBackupStatus();
  } catch (e) {
    toast('Ошибка: ' + e.message);
  }
  try { refreshAuditStrip(); } catch(_) {}
  try { if (!document.getElementById('auditBody').classList.contains('hidden')) loadAuditStripBody(); } catch(_) {}
}
function backupAskDelete(name) {
  document.getElementById('bkDeleteName').textContent = name;
  document.getElementById('backupDeleteModal').classList.remove('hidden');
  document.getElementById('bkDeleteConfirmBtn').onclick = async () => {
    try {
      const r = await fetch(API + '/api/backup/' + encodeURIComponent(name), {method: 'DELETE'});
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'fail');
      toast('Удалено');
      closeModal('backupDeleteModal');
      loadBackupStatus();
    } catch (e) {
      toast('Ошибка: ' + e.message);
    }
    try { refreshAuditStrip(); } catch(_) {}
    try { if (!document.getElementById('auditBody').classList.contains('hidden')) loadAuditStripBody(); } catch(_) {}
  };
}
function backupAskRestore(name) {
  document.getElementById('bkRestoreName').textContent = name;
  document.getElementById('backupRestoreModal').classList.remove('hidden');
  document.getElementById('bkRestoreConfirmBtn').onclick = async () => {
    const btn = document.getElementById('bkRestoreConfirmBtn');
    btn.disabled = true; btn.textContent = 'Восстанавливаю…';
    try {
      const r = await fetch(API + '/api/backup/restore/' + encodeURIComponent(name), {method: 'POST'});
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'fail');
      closeModal('backupRestoreModal');
      closeModal('backupModal');
      toast('Восстановление запущено. Сервисы перезапускаются…');
    } catch (e) {
      toast('Ошибка: ' + e.message);
      btn.disabled = false; btn.textContent = 'Восстановить';
    }
  };
}

// ============================================================
// XRay
// ============================================================
let _ruleListCatalog = {lists: [], global: []};
let _rmCurrentTab = 'shadowrocket';
const _expandedRuleSections = new Set();        // keyed by uuid (legacy outer toggle, kept for compat)
const _collapsedClients = new Set();             // keyed by public_key (AWG) / uuid (XRay)
const _seenClientIds = new Set();                // ids we've rendered at least once (to apply default-collapsed)

function _chevronSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>';
}
function _pencilSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>';
}
function pencilBtnHtml(onclick) {
  return `<button class="btn-act" onclick="${onclick}" title="Переименовать" aria-label="Переименовать">${_pencilSvg()}</button>`;
}
function _extLinkSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';
}
function _trashSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>';
}
function _powerSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>';
}
function _calendarSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/></svg>';
}
function _dnsSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/></svg>';
}
function dnsBtnHtml(onclick, enabled, name) {
  const cls = enabled ? 'btn-act is-active-dns' : 'btn-act';
  const title = enabled
    ? `Локальный DNS включён — домены пишутся в лог. Клик: выключить (нужно перевыдать конфиг «${name}»).`
    : `Включить локальный DNS-сервер для «${name}». В лог попадут запрошенные домены. После включения нужно перевыдать конфиг клиенту.`;
  return `<button class="${cls}" onclick="${onclick}" title="${title}" aria-label="DNS-сервер">${_dnsSvg()}</button>`;
}
function _dnsCfgSvg() {
  // Стойка серверов — «настройка DNS-серверов». Отличается от глобуса _dnsSvg («Логи+»).
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><line x1="7" y1="7" x2="7.01" y2="7"/><line x1="7" y1="17" x2="7.01" y2="17"/></svg>';
}
// active: 'green'/true — как в Global rules; 'cyan' — свои настройки; false/'' — DNS не передаётся.
function dnsCfgBtnHtml(onclick, active, title) {
  const cls = 'btn-act' + (active === 'cyan' ? ' is-active-cyan' : (active ? ' is-active-dns' : ''));
  return `<button class="${cls}" onclick="${onclick}" title="${title || 'Настройка DNS'}" aria-label="Настройка DNS">${_dnsCfgSvg()}</button>`;
}
function _allowIpSvg() {
  // Щит — «доступ только с разрешённых адресов».
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.4-3 7.9-7 9-4-1.1-7-4.6-7-9V6l7-3z"/><path d="M9.5 12l2 2 3.5-3.5"/></svg>';
}
function allowIpBtnHtml(onclick, active, title) {
  const cls = active ? 'btn-act is-active-dns' : 'btn-act';
  return `<button class="${cls}" onclick="${onclick}" title="${title || 'Фильтрация по IP'}" aria-label="Фильтрация по IP">${_allowIpSvg()}</button>`;
}
// Сравнение двух DNS-настроек по факту (mode + резолверы + фолбэк), template игнорим.
// fallback значим только для h3:// — при других схемах он всегда сохраняется как
// false, поэтому нормализуем его к false, чтобы старые записи не считались чужими.
function _dnsSameCfg(a, b) {
  const n = d => {
    d = d || {};
    const mode = d.mode === 'set' ? 'set' : 'off';
    const doh = (d.doh || '').trim();
    return {mode, doh, plain: (d.plain || []).slice().sort().join(','),
            fallback: doh.indexOf('h3://') === 0 ? (d.fallback !== false) : false};
  };
  const x = n(a), y = n(b);
  if (x.mode !== y.mode) return false;
  if (x.mode === 'off') return true;         // оба off = одинаково
  return x.doh === y.doh && x.plain === y.plain && x.fallback === y.fallback;
}
// Режим «Списки правил» + исключения в сторону VPN. На цвет иконки НЕ влияет
// (см. ниже) — нужен только для поясняющей строки в модалке: при нём в VPN
// уходит почти всё, и персональному DNS остаются лишь правила Direct.
// Берём ПРИМЕНЁННЫЕ значения, а не pending: до «Применить» конфиг ещё старый.
function _clientListsVpnMode(c) {
  return !!c && (c.geo_mode || 'off') === 'lists' && (c.lists_default || 'direct') === 'vpn';
}
// Цвет иконки DNS отвечает ровно на один вопрос: ЧТО панель пишет клиенту в
// конфиг. Про то, кто какой домен резолвит, он не говорит — резолвят и клиент
// (для правил по IP/странам), и сервер (для всего, что ушло в VPN), и режим
// исключений на это не влияет.
//   ''      — DNS не передаётся, у клиента системный;
//   'green' — передаётся дефолтный (тот же, что достаётся новым клиентам);
//   'cyan'  — передаётся свой, отличный от дефолта.
// Если дефолт выключен (иконка Global серая), сравнивать не с чем: любой
// заданный DNS клиента считается своим.
function _dnsIconState(c) {
  const g = _globalDnsDefault;
  const dns = c && c.dns;
  if (!dns || dns.mode !== 'set') return '';
  return (g && g.mode === 'set' && _dnsSameCfg(dns, g)) ? 'green' : 'cyan';
}
function _dnsIconTitle(state) {
  if (state === 'green') return 'Настройка DNS (как в Global rules)';
  if (state === 'cyan') return 'Настройка DNS (свои настройки)';
  return 'Настройка DNS (не передаётся клиенту)';
}
function trashBtnHtml(onclick) {
  return `<button class="btn-act danger" onclick="${onclick}" title="Удалить" aria-label="Удалить">${_trashSvg()}</button>`;
}
function powerBtnHtml(onclick, disabled) {
  const cls = disabled ? 'btn-act is-active' : 'btn-act';
  const title = disabled ? 'Включить' : 'Отключить';
  return `<button class="${cls}" onclick="${onclick}" title="${title}" aria-label="${title}">${_powerSvg()}</button>`;
}
function scheduleBtnHtml(onclick, scheduledAction) {
  const cls = scheduledAction ? 'btn-act is-active' : 'btn-act';
  const title = scheduledAction ? 'Расписание установлено' : 'Расписание';
  return `<button class="${cls}" onclick="${onclick}" title="${title}" aria-label="${title}">${_calendarSvg()}</button>`;
}

// === DNS modal =============================================================
// Настройка DNS, который панель кладёт в клиентские XRay-конфиги (Loon/Clash/SR).
// kind='xray' — один клиент; kind='global' — дефолт для новых юзеров (server.json).
// «Применить ко всем» (как у расписания) раскатывает выбранный DNS на всех клиентов.
let _dnsTarget = null;      // {kind:'xray'|'global', id, name, bulk}
let _dnsTemplates = null;   // каталог из /api/dns/templates
let _globalDnsDefault = {mode: 'off', template: '', plain: [], doh: ''};

async function _ensureDnsTemplates() {
  if (_dnsTemplates) return _dnsTemplates;
  try {
    const r = await fetch(API + '/api/dns/templates');
    const j = await r.json();
    _dnsTemplates = j.templates || [];
  } catch (e) { _dnsTemplates = []; }
  return _dnsTemplates;
}

async function openDnsModal(kind, id, name) {
  _dnsTarget = {kind, id, name, bulk: false};
  await _ensureDnsTemplates();
  let dns = {mode: 'off', template: '', plain: [], doh: ''};
  let listsVpn = false;
  if (kind === 'global') {
    dns = _globalDnsDefault || dns;
    try {
      const r = await fetch(API + '/api/dns/default');
      const j = await r.json();
      if (j.dns) { dns = j.dns; _globalDnsDefault = j.dns; }
    } catch (e) {}
  } else {
    const c = _protoFindClient(kind, id);
    if (c && c.dns) dns = c.dns;
    listsVpn = _clientListsVpnMode(c);
  }
  document.getElementById('dnsClientName').textContent = name || '';
  document.getElementById('dnsGlobalInfo').style.display = (kind === 'global') ? '' : 'none';
  // Пояснение про клиентский DNS — постоянное, у Global своя врезка выше.
  document.getElementById('dnsClientInfo').style.display = (kind === 'global') ? 'none' : '';
  document.getElementById('dnsListsVpnNote').style.display = listsVpn ? '' : 'none';
  const bulkSw = document.getElementById('dnsBulkSwitch');
  if (bulkSw) bulkSw.checked = false;
  document.getElementById('dnsBulkRow').classList.remove('hidden');
  _dnsFillForm(dns);
  document.getElementById('dnsModal').classList.remove('hidden');
}

function _dnsTemplateOptionsHtml(selId) {
  const opts = ['<option value="">— Свой / вручную —</option>'];
  for (const tpl of (_dnsTemplates || [])) {
    const s = tpl.id === selId ? ' selected' : '';
    opts.push(`<option value="${escAttr(tpl.id)}"${s}>${escHtml(tpl.name)}</option>`);
  }
  return opts.join('');
}

// Хост зашифрованного URL (без схемы/пути/ID): h3://dns.nextdns.io/xxx → dns.nextdns.io.
function _dnsHost(u) {
  const m = (u || '').trim().match(/^[a-z0-9]+:\/\/([^\/]+)/i);
  return m ? m[1].toLowerCase() : '';
}
// id шаблона, чей хост совпадает с хостом doh (схему и ID/путь игнорим). Иначе ''.
function _dnsMatchTemplateId(doh) {
  const h = _dnsHost(doh);
  if (!h) return '';
  const tpl = (_dnsTemplates || []).find(t => _dnsHost(t.doh) === h);
  return tpl ? tpl.id : '';
}

function _dnsFillForm(dns) {
  const off = (dns.mode !== 'set');
  document.getElementById('dnsOffSwitch').checked = off;
  // Селект — по совпадению хоста (h3://dns.nextdns.io/ID покажет «NextDNS»),
  // иначе по сохранённому template, иначе «Свой».
  const selId = _dnsMatchTemplateId(dns.doh) || dns.template || '';
  document.getElementById('dnsTemplateSel').innerHTML = _dnsTemplateOptionsHtml(selId);
  document.getElementById('dnsPlainInput').value = (dns.plain || []).join(', ');
  document.getElementById('dnsDohInput').value = dns.doh || '';
  // Загрузка сохранённого: уважаем сохранённый fallback, показываем тумблер по факту h3.
  document.getElementById('dnsFallbackSwitch').checked = (dns.fallback !== false);
  const isH3 = (dns.doh || '').indexOf('h3://') === 0;
  document.getElementById('dnsFallbackRow').style.display = isH3 ? '' : 'none';
  _dnsSyncDisabled();
}

// Тумблер фолбэка показываем только когда введён h3:// (для https/quic не нужен).
// При ПОЯВЛЕНии h3 (ввод/выбор шаблона) включаем фолбэк по умолчанию — рекомендуется.
function _dnsSyncFallback() {
  const row = document.getElementById('dnsFallbackRow');
  const isH3 = document.getElementById('dnsDohInput').value.trim().indexOf('h3://') === 0;
  const wasHidden = row.style.display === 'none';
  row.style.display = isH3 ? '' : 'none';
  if (isH3 && wasHidden) document.getElementById('dnsFallbackSwitch').checked = true;
}

function _dnsSyncDisabled() {
  const off = document.getElementById('dnsOffSwitch').checked;
  const fields = document.getElementById('dnsFields');
  if (fields) fields.style.opacity = off ? '0.4' : '1';
  ['dnsTemplateSel', 'dnsPlainInput', 'dnsDohInput', 'dnsFallbackSwitch'].forEach(idv => {
    const el = document.getElementById(idv);
    if (el) el.disabled = off;
  });
  const row = document.getElementById('dnsOffSwitch').closest('.switch-row');
  if (row) row.classList.toggle('is-on', off);
}

function _onDnsOffToggle() { _dnsSyncDisabled(); }

function _onDnsTemplatePick() {
  const id = document.getElementById('dnsTemplateSel').value;
  const tpl = (_dnsTemplates || []).find(x => x.id === id);
  if (!tpl) return; // «Свой» — поля не трогаем
  // Если в поле уже URL того же провайдера (напр. твой NextDNS с ID) — не затираем,
  // только вернём селект на этот шаблон.
  if (_dnsHost(document.getElementById('dnsDohInput').value) === _dnsHost(tpl.doh)) return;
  document.getElementById('dnsPlainInput').value = (tpl.plain || []).join(', ');
  document.getElementById('dnsDohInput').value = tpl.doh || '';
  _dnsSyncFallback();
}

function _onDnsFieldEdit() {
  // Ручная правка → селект следует за хостом: dns.nextdns.io остаётся «NextDNS»
  // при любом ID/схеме; чужой хост → «Свой».
  document.getElementById('dnsTemplateSel').value = _dnsMatchTemplateId(document.getElementById('dnsDohInput').value);
  _dnsSyncFallback();
}

function _dnsCollect() {
  if (document.getElementById('dnsOffSwitch').checked) return {mode: 'off', template: '', plain: [], doh: '', fallback: false};
  const template = document.getElementById('dnsTemplateSel').value;
  const plain = document.getElementById('dnsPlainInput').value.split(',').map(s => s.trim()).filter(Boolean);
  const doh = document.getElementById('dnsDohInput').value.trim();
  // Фолбэк осмыслен только для h3:// — иначе всегда false.
  const fallback = doh.indexOf('h3://') === 0 && document.getElementById('dnsFallbackSwitch').checked;
  return {mode: 'set', template, plain, doh, fallback};
}

function _onDnsBulkToggle(el) { if (_dnsTarget) _dnsTarget.bulk = !!el.checked; }

// Общие модалки (DNS, фильтр IP, расписание) обслуживают несколько протоколов.
// Различий всего два: где лежат клиенты и по какому URL их править — поэтому
// вместо копий модалок под каждый протокол здесь два маленьких резолвера.
// Протоколы-пакеты (modules/<proto>/): свои клиенты, свой API, своя
// перерисовка. Общие модалки ходят к ним через эти три точки.
const _PKG_PROTO = {
  hysteria: {api: '/api/hysteria', clients: () => (typeof hyClients === 'function' ? hyClients() : []),
             rerender: () => { if (typeof hyRerender === 'function') hyRerender(); }},
  tgweb: {api: '/api/tgweb', clients: () => (typeof tgwebClients === 'function' ? tgwebClients() : []),
          rerender: () => { if (typeof tgwebRerender === 'function') tgwebRerender(); }},
};

function _protoClientsData(kind) {
  // У пакетов свои клиенты и своё состояние — пакет отдаёт их хуком
  // (hyClients/tgwebClients). Так общим модалкам не нужно знать, где они лежат.
  if (_PKG_PROTO[kind]) {
    try { return _PKG_PROTO[kind].clients() || []; } catch (e) { return []; }
  }
  return _lastXrayData || [];
}
function _protoFindClient(kind, id) {
  return _protoClientsData(kind).find(x => x && (x.uuid === id || x.id === id));
}
// Перерисовка списка карточек нужного протокола. Общие модалки и поповеры
// правят состояние клиента оптимистично и должны показать это сразу.
function _protoRerender(kind) {
  if (_PKG_PROTO[kind]) {
    try { _PKG_PROTO[kind].rerender(); } catch (e) {}
    return;
  }
  // DNS-дефолт общий на панель: он красит иконки в карточках всех протоколов,
  // поэтому после его правки перерисовываем и Hysteria.
  if (kind === 'global') { try { if (typeof hyRerender === 'function') hyRerender(); } catch (e) {} }
  renderXrayClients(_lastXrayData);
}
function _protoClientUrl(kind, id, suffix) {
  const base = _PKG_PROTO[kind] ? _PKG_PROTO[kind].api + '/clients/' : '/api/xray/clients/';
  return API + base + encodeURIComponent(id) + suffix;
}

async function _dnsPost(uid, dns) {
  const kind = (_dnsTarget && _dnsTarget.kind) || 'xray';
  const r = await fetch(_protoClientUrl(kind, uid, '/dns'), {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({dns}),
  });
  if (r.ok) { const c = _protoFindClient(kind, uid); if (c) c.dns = dns; }
  return r.ok;
}

async function applyDnsModal() {
  if (!_dnsTarget) return;
  const dns = _dnsCollect();
  const {kind, id, bulk} = _dnsTarget;
  const btn = document.getElementById('dnsApplyBtn');
  const old = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    let ok, xrayRestarted = false;
    if (kind === 'global') {
      const r = await fetch(API + '/api/dns/default', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({dns}),
      });
      ok = r.ok;
      if (ok) {
        _globalDnsDefault = dns;
        const j = await r.json().catch(() => ({}));
        xrayRestarted = !!j.xray_restarted;   // серверный резолвер xray поменялся
        if (j.warning) toast(j.warning);
      }
    } else {
      ok = await _dnsPost(id, dns);
    }
    if (!ok) { toast('Ошибка сохранения DNS (сервер отклонил запрос)'); return; }
    let bulkN = 0;
    if (bulk) {
      // «Ко всем» — внутри своего протокола: у каждого свои клиенты и свои URL.
      const ids = _protoClientsData(kind).map(c => c && (c.uuid || c.id)).filter(Boolean);
      for (const uid of ids) { if (await _dnsPost(uid, dns)) bulkN++; }
    }
    closeModal('dnsModal');
    toast(bulk ? `DNS применён ко всем (${bulkN})`
               : (kind === 'global'
                    ? (xrayRestarted ? 'DNS сохранён, XRay перезапускается' : 'DNS-дефолт сохранён')
                    : 'DNS сохранён'));
    _protoRerender(kind);
    if (xrayRestarted) confirmXrayRestart('XRay перезапущен — DNS применён');
  } catch (e) {
    toast('Ошибка сохранения DNS');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = old; }
  }
}

// Рестарт xray делает фоновый воркер на сервере, ответ на запрос уходит раньше —
// поэтому после «перезапускается» дожидаемся факта и показываем, чем кончилось.
// Молча выходим только по таймауту: тогда о судьбе рестарта скажет карточка XRay.
async function confirmXrayRestart(okMsg) {
  for (let i = 0; i < 40; i++) {                       // ~20 c потолок
    await new Promise(r => setTimeout(r, 500));
    let j = null;
    try {
      const r = await fetch(API + '/api/xray/restart-status');
      if (!r.ok) return false;
      j = await r.json();
    } catch (e) { continue; }
    if (j && !j.busy) {
      if (j.ok === false) toast('XRay не поднялся после перезапуска — проверьте сервис');
      else toast(okMsg || 'XRay перезапущен');
      if (typeof refreshXray === 'function') refreshXray();
      return j.ok !== false;
    }
  }
  return false;
}

// === Фильтрация IP клиента: белый и чёрный списки ===========================
// Белый: пустой = доступ с любого адреса; как только адрес добавлен, XRay режет
// трафик всех остальных адресов. Чёрный: режет ровно перечисленные адреса.
// Соединение при этом устанавливается — UUID проверяется до роутинга.
// Правила серверные, сохранение перезапускает xray. Обе вкладки уходят на сервер
// одним запросом по «Сохранить».
let _allowIpTarget = null;   // {id, name, lastIp}
let _allowIpList = [];       // рабочая копия белого списка
let _blockIpList = [];       // рабочая копия чёрного списка
let _allowIpTab = 'allow';   // активная вкладка: 'allow' | 'block'

// Элементы обеих вкладок различаются только суффиксом — белый список сохранил
// исходные id, чёрный получил тот же id + 'Block'.
function _allowIpEl(base, kind) {
  return document.getElementById(base + (kind === 'block' ? 'Block' : ''));
}
function _allowIpArr(kind) { return kind === 'block' ? _blockIpList : _allowIpList; }

function openAllowIpModal(id, name, kind) {
  kind = kind || 'xray';
  const c = _protoFindClient(kind, id);
  _allowIpTarget = {id, name, kind, lastIp: (c && c.last_ip) || ''};
  _allowIpList = ((c && c.allow_ips) || []).slice();
  _blockIpList = ((c && c.block_ips) || []).slice();
  document.getElementById('allowIpClientName').textContent = name || '';
  ['allow', 'block'].forEach(k => {
    _allowIpEl('allowIpInput', k).value = '';
    _allowIpSetErr('', k);
    _allowIpRender(k);
  });
  switchAllowIpTab('allow');
  document.getElementById('allowIpModal').classList.remove('hidden');
  setTimeout(() => _allowIpEl('allowIpInput', 'allow').focus(), 30);
}

function switchAllowIpTab(kind) {
  _allowIpTab = kind === 'block' ? 'block' : 'allow';
  document.getElementById('allowIpTabAllow').classList.toggle('active', _allowIpTab === 'allow');
  document.getElementById('allowIpTabBlock').classList.toggle('active', _allowIpTab === 'block');
  document.getElementById('allowIpPaneAllow').classList.toggle('hidden', _allowIpTab !== 'allow');
  document.getElementById('allowIpPaneBlock').classList.toggle('hidden', _allowIpTab !== 'block');
  const inp = _allowIpEl('allowIpInput', _allowIpTab);
  if (inp) setTimeout(() => inp.focus(), 20);
}

// srcEl — поле, к которому относится ошибка: оно и подсвечивается. По умолчанию
// это поле добавления; при правке строки списка подсвечивается сама строка.
function _allowIpSetErr(msg, kind, srcEl) {
  kind = kind || _allowIpTab;
  const el = _allowIpEl('allowIpErr', kind);
  el.textContent = msg || '';
  el.style.display = msg ? '' : 'none';
  const pane = document.getElementById(kind === 'block' ? 'allowIpPaneBlock' : 'allowIpPaneAllow');
  const hot = srcEl || _allowIpEl('allowIpInput', kind);
  (pane || document).querySelectorAll('.is-bad').forEach(n => n.classList.remove('is-bad'));
  if (msg && hot) hot.classList.add('is-bad');
}

// Маска поля адреса. Запятая = точка (её удобнее нажимать на цифровой клавиатуре),
// всё кроме цифр/точки/слэша срезается, точка ставится сама после третьего разряда
// октета. Так «192,168,1,1» и «1921681001» набираются одинаково успешно.
// growTail=true — добавить точку в хвост (юзер печатает, а не стирает): иначе
// backspace по автоточке тут же вернул бы её обратно.
function _ipMaskFormat(raw, growTail) {
  const s = String(raw == null ? '' : raw).replace(/,/g, '.').replace(/[^0-9./]/g, '');
  const si = s.indexOf('/');
  const host = si >= 0 ? s.slice(0, si) : s;
  let pref = si >= 0 ? s.slice(si + 1).replace(/[^0-9]/g, '').slice(0, 2) : null;
  const octs = [];
  let cur = '';
  for (const ch of host) {
    if (ch === '.') {
      if (cur === '' || octs.length >= 3) continue;   // ведущие и лишние точки
      octs.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
    if (cur.length === 3 && octs.length < 3) {
      // Три цифры в октет влезают не всегда: «300» — это 30 и начало следующего.
      if (+cur <= 255) { octs.push(cur); cur = ''; }
      else { octs.push(cur.slice(0, 2)); cur = cur.slice(2); }
    } else if (cur.length > 3) {
      cur = cur.slice(0, 3);                          // последний октет — не длиннее 3
    }
  }
  let out = octs.concat(cur === '' ? [] : [cur]).join('.');
  if (cur === '' && octs.length && octs.length < 4 && growTail) out += '.';
  if (pref !== null && !out) pref = null;             // «/24» без адреса смысла не имеет
  if (pref !== null) out += '/' + pref;
  return out;
}

// Прогоняет значение поля через маску, сохраняя позицию курсора.
function _ipMaskApply(el) {
  const raw = el.value;
  const prev = el.dataset.prev || '';
  const caret = el.selectionStart == null ? raw.length : el.selectionStart;
  // Точку в хвост дописываем только когда строка растёт и курсор в конце.
  const v = _ipMaskFormat(raw, raw.length > prev.length && caret >= raw.length);
  if (v !== raw) {
    // Курсор держим по числу значащих символов слева от него — точки маска ставит сама.
    const want = raw.slice(0, caret).replace(/[^0-9/]/g, '').length;
    let pos = v.length, seen = 0;
    for (let i = 0; i < v.length; i++) {
      if (seen >= want) { pos = i; break; }
      if (/[0-9/]/.test(v[i])) seen++;
    }
    el.value = v;
    try { el.setSelectionRange(pos, pos); } catch (e) {}
  }
  el.dataset.prev = el.value;
  return el.value;
}

// Живая проверка: ругаемся только на дописанный адрес, чтобы «10.» не краснело.
function _ipLiveCheck(v, kind) {
  return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v) ? _allowIpValidate(v, kind) : {};
}

function _allowIpFilterInput(el, kind) {
  const v = _ipMaskApply(el);
  _allowIpSetErr(_ipLiveCheck(v, kind).err || '', kind, el);
}

// '10.0.0.5' → {val:'10.0.0.5/32'}; '10.0.0.5/24' → {val:'10.0.0.0/24'} (как нормализует
// сервер); мусор → {err}. Хостовые биты гасим здесь же, чтобы в списке было ровно то,
// что реально сохранится.
function _allowIpValidate(s, kind) {
  s = (s || '').trim();
  if (!s) return {err: 'Введите адрес'};
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return {err: 'Формат: 255.255.255.255 или 255.255.255.0/24'};
  for (let i = 1; i <= 4; i++) if (+m[i] > 255) return {err: 'Октет не может быть больше 255'};
  const bits = m[5] === undefined ? 32 : +m[5];
  if (bits > 32) return {err: 'Маска — от 1 до 32'};
  // /0 = «все адреса»: в белом списке ограничение выродится в его отсутствие (сервер
  // такое правило не построит — дополнение пустое), в чёрном — отрежет клиента целиком,
  // для чего есть кнопка выключения. В обоих случаях честнее не дать ввести.
  if (bits === 0) {
    return {err: kind === 'block'
      ? 'Маска /0 — это все адреса, для полной блокировки выключите клиента'
      : 'Маска /0 — это все адреса, ограничение не имеет смысла'};
  }
  const num = (((+m[1]) * 256 + (+m[2])) * 256 + (+m[3])) * 256 + (+m[4]);
  const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
  const net = (num & mask) >>> 0;
  const val = [net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + bits;
  return {val};
}

function _allowIpAdd(kind) {
  kind = kind === 'block' ? 'block' : 'allow';
  const list = _allowIpArr(kind);
  const inp = _allowIpEl('allowIpInput', kind);
  const res = _allowIpValidate(inp.value, kind);
  if (res.err) { _allowIpSetErr(res.err, kind, inp); return; }
  if (list.indexOf(res.val) >= 0) { _allowIpSetErr('Этот адрес уже в списке', kind, inp); return; }
  if (list.length >= 32) { _allowIpSetErr('Максимум 32 адреса', kind, inp); return; }
  list.push(res.val);
  inp.value = '';
  inp.dataset.prev = '';
  _allowIpSetErr('', kind);
  _allowIpRender(kind);
  inp.focus();
}

function _allowIpOnKey(e, kind) { if (e.key === 'Enter') { e.preventDefault(); _allowIpAdd(kind); } }

// Правка строки списка. Значение уходит в список только когда оно валидно;
// мусор и дубли откатываются к прежнему адресу, чтобы список всегда был чистым.
function _allowIpEditCommit(el, kind, idx) {
  const list = _allowIpArr(kind);
  const orig = list[idx];
  if (orig === undefined) return;
  const revert = msg => {
    _allowIpSetErr(msg, kind, el);
    el.value = orig;
    el.dataset.prev = orig;
  };
  const res = _allowIpValidate(el.value, kind);
  if (res.err) { revert(res.err); return; }
  if (res.val === orig) { el.value = orig; el.dataset.prev = orig; _allowIpSetErr('', kind); return; }
  if (list.indexOf(res.val) >= 0) { revert('Этот адрес уже в списке'); return; }
  list[idx] = res.val;
  el.value = res.val;                 // показываем нормализованное: 10.0.0.5/24 → 10.0.0.0/24
  el.dataset.prev = res.val;
  _allowIpSetErr('', kind);
}

function _allowIpRender(kind) {
  kind = kind === 'block' ? 'block' : 'allow';
  const list = _allowIpArr(kind);
  const box = _allowIpEl('allowIpList', kind);
  const state = _allowIpEl('allowIpState', kind);
  if (!list.length) {
    box.innerHTML = `<div class="allowip-empty">${kind === 'block'
      ? 'Список пуст — блокировок нет.'
      : 'Список пуст — клиент работает с любого адреса.'}</div>`;
  } else {
    // Строка — редактируемое поле с той же маской, что и поле добавления.
    box.innerHTML = list.map((ip, i) => `
      <div class="allowip-item">
        <input class="allowip-cidr" data-idx="${i}" inputmode="numeric" autocomplete="off"
               spellcheck="false" aria-label="Адрес">
        <button class="allowip-del" data-idx="${i}" title="Удалить" aria-label="Удалить">&times;</button>
      </div>`).join('');
    // escHtml не экранирует кавычки — значения и обработчики вешаем из JS, не в разметке.
    box.querySelectorAll('input.allowip-cidr').forEach(inp => {
      const idx = +inp.dataset.idx;
      inp.value = list[idx];
      inp.dataset.prev = inp.value;
      inp.addEventListener('input', () => {
        const v = _ipMaskApply(inp);
        _allowIpSetErr(_ipLiveCheck(v, kind).err || '', kind, inp);
      });
      inp.addEventListener('blur', () => _allowIpEditCommit(inp, kind, idx));
      inp.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); inp.blur(); }
        else if (e.key === 'Escape') {
          e.preventDefault();
          inp.value = list[idx];
          inp.dataset.prev = inp.value;
          _allowIpSetErr('', kind);
          inp.blur();
        }
      });
    });
    box.querySelectorAll('.allowip-del').forEach(b => b.addEventListener('click', () => {
      list.splice(+b.dataset.idx, 1);
      _allowIpSetErr('', kind);
      _allowIpRender(kind);
    }));
  }
  state.textContent = list.length
    ? (kind === 'block' ? 'Трафик с адресов из списка блокируется.'
                        : 'Трафик отдаётся только с адресов из списка. С остальных — нет.')
    : (kind === 'block' ? 'Блокировок нет.' : 'Ограничений нет.');
  state.classList.toggle('is-on', list.length > 0);
  state.classList.toggle('is-block', kind === 'block');
  // Быстрое добавление последнего адреса, с которого клиент реально заходил.
  const cur = _allowIpEl('allowIpCurrent', kind);
  const last = _allowIpTarget && _allowIpTarget.lastIp;
  const already = last && list.indexOf(last + '/32') >= 0;
  if (last && !already && /^\d{1,3}(\.\d{1,3}){3}$/.test(last)) {
    cur.style.display = '';
    cur.innerHTML = `<span>Последний IP клиента: <b>${escHtml(last)}</b></span>`;
    const b = document.createElement('button');
    b.className = 'btn btn-sm btn-ghost';
    b.textContent = 'Добавить';
    b.addEventListener('click', () => {
      _allowIpEl('allowIpInput', kind).value = last;
      _allowIpAdd(kind);
    });
    cur.appendChild(b);
  } else {
    cur.style.display = 'none';
    cur.innerHTML = '';
  }
}

async function saveAllowIpModal() {
  if (!_allowIpTarget) return;
  const {id} = _allowIpTarget;
  const kind = _allowIpTarget.kind || 'xray';
  const btn = document.getElementById('allowIpSaveBtn');
  const old = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    // Обе вкладки — одним запросом: правила серверные, рестарт xray должен быть один.
    const r = await fetch(_protoClientUrl(kind, id, '/allow-ips'), {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({allow_ips: _allowIpList, block_ips: _blockIpList}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { _allowIpSetErr(j.error || 'Сервер отклонил запрос'); return; }
    const c = _protoFindClient(kind, id);
    if (c) { c.allow_ips = j.allow_ips || []; c.block_ips = j.block_ips || []; }
    const anyRule = (j.allow_ips || []).length || (j.block_ips || []).length;
    closeModal('allowIpModal');
    toast(j.xray_restarted
      ? (anyRule ? 'Списки сохранены, XRay перезапускается — фильтр включается'
                 : 'Ограничения сняты, XRay перезапускается')
      : 'Списки сохранены');
    _protoRerender(kind);
    if (j.xray_restarted) confirmXrayRestart('XRay перезапущен — фильтр применён');
  } catch (e) {
    _allowIpSetErr('Ошибка сохранения');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = old; }
  }
}

// === Schedule modal state ===
let _schedTarget = null; // {kind:'awg'|'xray', id, name, action, date}
// Включает/выключает «Применить» в зависимости от того, отличается ли значение от сохранённого
function _syncSection1() {
  const t = _schedTarget; if (!t) return;
  const btn = document.getElementById('schedConfirmBtn'); if (!btn) return;
  const action = (document.querySelector('input[name="schedAction"]:checked') || {}).value || null;
  const date = document.getElementById('schedDateInput').value || null;
  const changed = (action !== (t.currentAction || null)) || (date !== (t.currentDate || null));
  const valid = action && date;
  btn.disabled = !(changed && valid);
}
function _syncSection2() {
  const t = _schedTarget; if (!t) return;
  const btn = document.getElementById('schedResetApplyBtn'); if (!btn) return;
  const raw = document.getElementById('schedResetDay').value.trim();
  const day = raw === '' ? null : parseInt(raw, 10);
  const cur = t.currentResetDay == null ? null : parseInt(t.currentResetDay, 10);
  btn.disabled = (day === cur);
}
function _syncSection3() {
  const t = _schedTarget; if (!t) return;
  const btn = document.getElementById('schedLimitApplyBtn'); if (!btn) return;
  const raw = document.getElementById('schedLimitGb').value.trim();
  const gb = raw === '' ? null : parseInt(raw, 10);
  const cur = t.currentLimitGb == null ? null : parseInt(t.currentLimitGb, 10);
  btn.disabled = (gb === cur);
}

function _onSchedBulkToggle(el) {
  if (!_schedTarget) return;
  _schedTarget.bulk = !!el.checked;
  const ttl = document.getElementById('scheduleClientName');
  if (!ttl) return;
  if (_schedTarget.bulk) ttl.textContent = 'всех';
  else ttl.textContent = _schedTarget.name || '';
}

function openScheduleModal(kind, id, name, currentAction, currentDate, currentResetDay, currentLimitGb) {
  _schedTarget = {kind, id, name, currentAction, currentDate, currentResetDay, currentLimitGb, bulk: false};
  document.getElementById('scheduleClientName').textContent = name || '';
  // Свитч «Применить ко всем» — только для per-user (xray). Для global/awg/mtg скрыт.
  const bulkRow = document.getElementById('schedBulkRow');
  if (bulkRow) bulkRow.classList.toggle('hidden', kind !== 'xray');
  const bulkSw = document.getElementById('schedBulkSwitch');
  if (bulkSw) bulkSw.checked = false;
  // Для MTG и Global — пункт «Удалить» не имеет смысла, скрываем
  const isGlobal = (kind === 'global' || kind === 'hysteria_global');
  const noDelete = (kind === 'mtg' || isGlobal);
  const deleteOpt = document.querySelector('input[name="schedAction"][value="delete"]');
  if (deleteOpt && deleteOpt.parentElement) deleteOpt.parentElement.style.display = noDelete ? 'none' : '';
  // Видимость секций:
  //   kind='global'/'hysteria_global' → только Раздел 2 (сброс трафика — общий на всех)
  //   kind='xray'/'hysteria'          → все три
  //   kind='awg'/'mtg'                → только Раздел 1
  const actionSec = document.getElementById('schedActionSection');
  if (actionSec) actionSec.style.display = isGlobal ? 'none' : '';
  const trafficSec = document.getElementById('schedTrafficSection');
  if (trafficSec) trafficSec.style.display = (kind === 'xray' || isGlobal || kind === 'awg' || _PKG_PROTO[kind]) ? '' : 'none';
  const limitSec = document.getElementById('schedLimitSection');
  if (limitSec) limitSec.style.display = (kind === 'xray' || kind === 'awg' || _PKG_PROTO[kind]) ? '' : 'none';
  // Раздел 2: день сброса
  const dayInp = document.getElementById('schedResetDay');
  if (dayInp) dayInp.value = (currentResetDay != null && currentResetDay !== '') ? String(currentResetDay) : '';
  const resetHint = document.getElementById('schedResetHint');
  if (resetHint) { resetHint.textContent = ''; resetHint.style.color = ''; }
  const resetClear = document.getElementById('schedResetClearBtn');
  if (resetClear) resetClear.classList.toggle('hidden', !currentResetDay);
  // Раздел 3: лимит
  const limitInp = document.getElementById('schedLimitGb');
  if (limitInp) limitInp.value = (currentLimitGb != null && currentLimitGb !== '') ? String(currentLimitGb) : '';
  const limitHint = document.getElementById('schedLimitHint');
  if (limitHint) { limitHint.textContent = ''; limitHint.style.color = ''; }
  const limitClear = document.getElementById('schedLimitClearBtn');
  if (limitClear) limitClear.classList.toggle('hidden', !currentLimitGb);
  // Раздел 1: одноразовое действие
  const clearBtn = document.getElementById('schedClearBtn');
  if (clearBtn) clearBtn.classList.toggle('hidden', !currentAction);
  const t = new Date();
  t.setDate(t.getDate() + 1);
  const yyyy = t.getFullYear();
  const mm = String(t.getMonth() + 1).padStart(2, '0');
  const dd = String(t.getDate()).padStart(2, '0');
  const min = `${yyyy}-${mm}-${dd}`;
  const inp = document.getElementById('schedDateInput');
  inp.dataset.min = min;
  _setSchedDate(currentDate && currentDate >= min ? currentDate : '');
  const radios = document.querySelectorAll('input[name="schedAction"]');
  radios.forEach(r => r.checked = (r.value === (currentAction || 'disable')));
  document.getElementById('schedHint').textContent = '';
  _closeSchedPicker();
  document.getElementById('scheduleModal').classList.remove('hidden');
  // Изначально все «Применить» disabled — значения совпадают с сохранёнными
  _syncSection1();
  _syncSection2();
  _syncSection3();
}

function _schedBulkIds() {
  // Когда включён свитч «Применить ко всем» (только для kind='xray') — возвращает все UUID.
  // Иначе null (одиночный режим).
  if (_schedTarget && _schedTarget.bulk && _schedTarget.kind === 'xray') {
    return ((_lastXrayData || []).map(c => c && c.uuid).filter(Boolean));
  }
  return null;
}

async function _schedBulkPost(buildUrl, body) {
  // Возвращает {ok, failed:[{id,error}], total}
  const ids = _schedBulkIds() || [_schedTarget.id];
  let okN = 0;
  const failed = [];
  for (const id of ids) {
    try {
      const r = await fetch(API + buildUrl(id), {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: body == null ? undefined : JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) okN++;
      else failed.push({id, error: j.error || `HTTP ${r.status}`});
    } catch (e) {
      failed.push({id, error: e.message});
    }
  }
  return {ok: okN, failed, total: ids.length};
}

// Протоколы, у которых есть Раздел 2 (ежемесячный сброс трафика).
const _SCHED_TRAFFIC_KINDS = new Set(['xray', 'global', 'awg', 'hysteria', 'hysteria_global', 'tgweb']);

// === Раздел 2: ежемесячный сброс трафика ===
async function applyResetDay() {
  if (!_schedTarget || !_SCHED_TRAFFIC_KINDS.has(_schedTarget.kind)) return;
  const hint = document.getElementById('schedResetHint');
  hint.style.color = ''; hint.textContent = '';
  const raw = (document.getElementById('schedResetDay') || {}).value;
  let day = null;
  if (raw && raw.trim() !== '') {
    const n = parseInt(raw, 10);
    if (isNaN(n) || n < 1 || n > 31) { hint.textContent = 'День должен быть 1–31'; return; }
    day = n;
  }
  try {
    if (_schedTarget.kind === 'global') {
      const r = await fetch(API + `/api/xray/global/traffic/reset-day`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({day})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else if (_schedTarget.kind === 'hysteria_global') {
      const r = await fetch(API + `/api/hysteria/global/traffic/reset-day`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({day})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else if (_PKG_PROTO[_schedTarget.kind]) {
      const r = await fetch(_protoClientUrl(_schedTarget.kind, _schedTarget.id, '/traffic/reset-day'), {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({day})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else if (_schedTarget.kind === 'awg') {
      const r = await fetch(API + `/api/clients/${encodeURIComponent(_schedTarget.id)}/traffic/reset-day`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({day})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else {
      const res = await _schedBulkPost(
        (id) => `/api/xray/clients/${encodeURIComponent(id)}/traffic/reset-day`,
        {day}
      );
      if (res.failed.length) { hint.textContent = `Ошибка: ${res.ok}/${res.total} ОК`; return; }
    }
    _schedTarget.currentResetDay = day;
    document.getElementById('schedResetClearBtn').classList.toggle('hidden', !day);
    hint.style.color = 'var(--green, #4ade80)';
    const bulkMark = _schedBulkIds() ? ` (всем: ${_schedBulkIds().length})` : '';
    hint.textContent = (day ? `День сброса сохранён: ${day}` : 'Авто-сброс отключён') + bulkMark;
    _syncSection2();
    refreshAll();
  } catch (e) {
    hint.textContent = 'Ошибка: ' + e.message;
  }
}
async function clearResetDay() {
  document.getElementById('schedResetDay').value = '';
  await applyResetDay();
}
async function resetTrafficNow() {
  if (!_schedTarget || !_SCHED_TRAFFIC_KINDS.has(_schedTarget.kind)) return;
  const bulk = !!_schedBulkIds();
  const isHyGlobal = _schedTarget.kind === 'hysteria_global';
  const what = isHyGlobal
    ? 'весь трафик Hysteria (все клиенты)'
    : ((_schedTarget.kind === 'global' || bulk)
        ? 'весь XRay-трафик (все клиенты)'
        : ('трафик ' + (_schedTarget.name || 'клиента')));
  const ok = await openConfirm({
    title: 'Обнулить трафик?',
    body: 'Будет обнулён ' + escHtml(what) + '. Логи посещений останутся.',
    okLabel: 'Обнулить',
    danger: true,
  });
  if (!ok) return;
  const hint = document.getElementById('schedResetHint');
  hint.style.color = ''; hint.textContent = '';
  try {
    let resetAt = '';
    // Для global и bulk-режима — глобальный сброс одной операцией (он чистит всех).
    if (isHyGlobal) {
      const r = await fetch(API + `/api/hysteria/global/traffic/reset`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
      resetAt = j.reset_at || '';
    } else if (_PKG_PROTO[_schedTarget.kind]) {
      const r = await fetch(_protoClientUrl(_schedTarget.kind, _schedTarget.id, '/traffic/reset'), {
        method: 'POST', headers: {'Content-Type': 'application/json'}
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
      resetAt = j.reset_at || '';
    } else if (_schedTarget.kind === 'global' || bulk) {
      const r = await fetch(API + `/api/xray/global/traffic/reset`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
      resetAt = j.reset_at || '';
    } else if (_schedTarget.kind === 'awg') {
      const r = await fetch(API + `/api/clients/${encodeURIComponent(_schedTarget.id)}/traffic/reset`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
      resetAt = j.reset_at || '';
    } else {
      const r = await fetch(API + `/api/xray/clients/${encodeURIComponent(_schedTarget.id)}/traffic/reset`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
      resetAt = j.reset_at || '';
    }
    hint.style.color = 'var(--green, #4ade80)';
    hint.textContent = 'Трафик обнулён ' + resetAt;
    toast('Трафик обнулён');
    refreshAll();
  } catch (e) {
    hint.textContent = 'Ошибка: ' + e.message;
  }
}

// === Раздел 3: лимит трафика ===
async function applyLimit() {
  if (!_schedTarget || !(_schedTarget.kind === 'xray' || _schedTarget.kind === 'awg'
                         || _PKG_PROTO[_schedTarget.kind])) return;
  const hint = document.getElementById('schedLimitHint');
  hint.style.color = ''; hint.textContent = '';
  const raw = (document.getElementById('schedLimitGb') || {}).value;
  let gb = null;
  if (raw && raw.trim() !== '') {
    const n = parseInt(raw, 10);
    if (isNaN(n) || n < 1) { hint.textContent = 'Лимит — целое число GB (>=1)'; return; }
    gb = n;
  }
  try {
    if (_PKG_PROTO[_schedTarget.kind]) {
      const r = await fetch(_protoClientUrl(_schedTarget.kind, _schedTarget.id, '/traffic/limit'), {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({gb})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else if (_schedTarget.kind === 'awg') {
      const r = await fetch(API + `/api/clients/${encodeURIComponent(_schedTarget.id)}/traffic/limit`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({gb})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    } else {
      const res = await _schedBulkPost(
        (id) => `/api/xray/clients/${encodeURIComponent(id)}/traffic/limit`,
        {gb}
      );
      if (res.failed.length) { hint.textContent = `Ошибка: ${res.ok}/${res.total} ОК`; return; }
    }
    _schedTarget.currentLimitGb = gb;
    document.getElementById('schedLimitClearBtn').classList.toggle('hidden', !gb);
    hint.style.color = 'var(--green, #4ade80)';
    const bulkMark = _schedBulkIds() ? ` (всем: ${_schedBulkIds().length})` : '';
    hint.textContent = (gb ? `Лимит сохранён: ${gb} GB` : 'Лимит снят') + bulkMark;
    _syncSection3();
    refreshAll();
  } catch (e) {
    hint.textContent = 'Ошибка: ' + e.message;
  }
}
async function clearLimit() {
  document.getElementById('schedLimitGb').value = '';
  await applyLimit();
}
// === Custom calendar (replaces native <input type="date"> for cross-platform UX) ===
let _schedCal = null; // {year, month} of currently displayed page
const _SCHED_MONTHS = ['Январь','Февраль','Март','Апрель','Май','Июнь','Июль','Август','Сентябрь','Октябрь','Ноябрь','Декабрь'];

function _setSchedDate(iso) {
  const inp = document.getElementById('schedDateInput');
  const disp = document.getElementById('schedDateDisplay');
  if (!inp || !disp) return;
  inp.value = iso || '';
  if (iso) {
    const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (m) {
      disp.textContent = `${m[3]}.${m[2]}.${m[1]}`;
      disp.classList.remove('is-placeholder');
      return;
    }
  }
  disp.textContent = '—';
  disp.classList.add('is-placeholder');
}

function _openSchedPicker() {
  const pop = document.getElementById('schedCalPop');
  if (!pop) return;
  if (!pop.classList.contains('hidden')) { _closeSchedPicker(); return; }
  const inp = document.getElementById('schedDateInput');
  const minIso = inp && inp.dataset.min;
  let base;
  if (inp && inp.value) base = inp.value;
  else if (minIso) base = minIso;
  else { const t = new Date(); t.setDate(t.getDate()+1); base = _isoFromDate(t); }
  const m = base.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  _schedCal = { year: +m[1], month: +m[2] - 1 };
  _renderSchedCal();
  pop.classList.remove('hidden');
  _clampSchedPickerToModal(pop);
  setTimeout(() => document.addEventListener('click', _schedCalOutsideClick, true), 0);
}

function _clampSchedPickerToModal(pop) {
  // Используем position:fixed, чтобы не упираться в overflow:auto у модалки.
  // Якорь — кнопка «иконка календаря» (родитель попапа). Если справа/снизу
  // не помещается — флипаем по соответствующей оси.
  const anchor = pop.parentElement && pop.parentElement.querySelector('.sched-date-btn, button');
  const triggerRect = (anchor || pop.parentElement || pop).getBoundingClientRect();
  pop.style.position = 'fixed';
  pop.style.left = '';
  pop.style.right = '';
  pop.style.top = '';
  pop.style.bottom = '';
  // Сначала пробуем «вниз от триггера, выровнено по левому краю».
  pop.style.top = (triggerRect.bottom + 6) + 'px';
  pop.style.left = triggerRect.left + 'px';
  const margin = 8;
  const vw = window.innerWidth, vh = window.innerHeight;
  let r = pop.getBoundingClientRect();
  // Горизонталь: если вылез вправо — прижимаем правый край к правому краю триггера.
  if (r.right > vw - margin) {
    const newLeft = Math.max(margin, triggerRect.right - r.width);
    pop.style.left = newLeft + 'px';
    r = pop.getBoundingClientRect();
  }
  if (r.left < margin) {
    pop.style.left = margin + 'px';
    r = pop.getBoundingClientRect();
  }
  // Вертикаль: если вниз не помещается — открываем вверх от триггера.
  if (r.bottom > vh - margin) {
    const aboveTop = triggerRect.top - r.height - 6;
    if (aboveTop >= margin) {
      pop.style.top = aboveTop + 'px';
    } else {
      // И вверху не влезает — прижимаем к низу вьюпорта.
      pop.style.top = Math.max(margin, vh - r.height - margin) + 'px';
    }
  }
}
function _closeSchedPicker() {
  const pop = document.getElementById('schedCalPop');
  if (pop) pop.classList.add('hidden');
  document.removeEventListener('click', _schedCalOutsideClick, true);
}
function _schedCalOutsideClick(e) {
  const pop = document.getElementById('schedCalPop');
  if (!pop || pop.classList.contains('hidden')) return;
  const wrap = pop.parentElement;
  if (wrap && !wrap.contains(e.target)) _closeSchedPicker();
}
function _isoFromDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function _renderSchedCal() {
  if (!_schedCal) return;
  const title = document.getElementById('schedCalTitle');
  const grid = document.getElementById('schedCalGrid');
  if (!title || !grid) return;
  const {year, month} = _schedCal;
  title.textContent = `${_SCHED_MONTHS[month]} ${year}`;
  const inp = document.getElementById('schedDateInput');
  const minIso = (inp && inp.dataset.min) || '';
  const selIso = (inp && inp.value) || '';
  const todayIso = _isoFromDate(new Date());
  const first = new Date(year, month, 1);
  // Monday-first: shift so Mon=0..Sun=6
  const jsDow = first.getDay(); // 0=Sun..6=Sat
  const leading = (jsDow + 6) % 7;
  const startDate = new Date(year, month, 1 - leading);
  let html = '';
  for (let i = 0; i < 42; i++) {
    const d = new Date(startDate); d.setDate(startDate.getDate() + i);
    const iso = _isoFromDate(d);
    const isOther = d.getMonth() !== month;
    const disabled = minIso && iso < minIso;
    const cls = ['sched-cal-day'];
    if (isOther) cls.push('is-other');
    if (iso === todayIso) cls.push('is-today');
    if (iso === selIso) cls.push('is-selected');
    html += `<button type="button" class="${cls.join(' ')}" data-iso="${iso}"${disabled ? ' disabled' : ''}>${d.getDate()}</button>`;
  }
  grid.innerHTML = html;
  grid.querySelectorAll('.sched-cal-day').forEach(btn => {
    btn.addEventListener('click', _onSchedCalDayClick);
  });
  // Wire nav buttons (idempotent re-binds OK since innerHTML didn't touch them)
  const pop = document.getElementById('schedCalPop');
  pop.querySelectorAll('.sched-cal-nav').forEach(btn => {
    btn.onclick = (e) => {
      const dir = +btn.dataset.dir;
      let m2 = _schedCal.month + dir, y2 = _schedCal.year;
      if (m2 < 0) { m2 = 11; y2--; }
      if (m2 > 11) { m2 = 0; y2++; }
      _schedCal = { year: y2, month: m2 };
      _renderSchedCal();
    };
  });
}
function _onSchedCalDayClick(e) {
  const iso = e.currentTarget.dataset.iso;
  if (!iso) return;
  _setSchedDate(iso);
  _closeSchedPicker();
  _validateSchedDate();
  _syncSection1();
}

function _validateSchedDate() {
  const inp = document.getElementById('schedDateInput');
  const hint = document.getElementById('schedHint');
  const v = inp.value;
  if (!v) { hint.textContent = ''; return false; }
  const m = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) { hint.textContent = 'Формат даты: ДД.ММ.ГГГГ'; return false; }
  const [_, y, mo, d] = m;
  const dt = new Date(`${v}T00:00:00`);
  if (isNaN(dt.getTime()) || dt.getFullYear() != +y || (dt.getMonth() + 1) != +mo || dt.getDate() != +d) {
    hint.textContent = 'Такой даты не существует';
    return false;
  }
  const today = new Date(); today.setHours(0,0,0,0);
  if (dt <= today) { hint.textContent = 'Дата должна быть позже сегодняшней (минимум — завтра)'; return false; }
  hint.textContent = '';
  return true;
}

async function clearSchedule() {
  if (!_schedTarget) return;
  const t = _schedTarget;
  const hint = document.getElementById('schedHint');
  try {
    if (t.kind === 'xray') {
      const res = await _schedBulkPost(
        (id) => `/api/xray/clients/${encodeURIComponent(id)}/schedule`,
        {action: 'none'}
      );
      if (res.failed.length) { hint.textContent = `Ошибка: ${res.ok}/${res.total} ОК`; return; }
    } else {
      let url;
      if (t.kind === 'awg') url = `/api/clients/${encodeURIComponent(t.id)}/schedule`;
      else if (t.kind === 'mtg') url = `/api/mtg/schedule`;
      else if (_PKG_PROTO[t.kind]) url = `${_PKG_PROTO[t.kind].api}/clients/${encodeURIComponent(t.id)}/schedule`;
      else return;
      const r = await fetch(API + url, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: 'none'})
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
    }
    _schedTarget.currentAction = null;
    _schedTarget.currentDate = null;
    document.getElementById('schedClearBtn').classList.add('hidden');
    _setSchedDate('');
    hint.style.color = 'var(--green, #4ade80)';
    const bulkMark = _schedBulkIds() ? ` (всем: ${_schedBulkIds().length})` : '';
    hint.textContent = 'Расписание удалено' + bulkMark;
    _syncSection1();
    refreshAll();
  } catch (e) { hint.textContent = 'Ошибка: ' + e.message; }
}

async function applySchedule() {
  if (!_schedTarget) return;
  const action = (document.querySelector('input[name="schedAction"]:checked') || {}).value;
  const date = document.getElementById('schedDateInput').value;
  const hint = document.getElementById('schedHint');
  hint.style.color = ''; hint.textContent = '';
  if (!date) { hint.textContent = 'Выбери или введи дату'; return; }
  if (!_validateSchedDate()) return;
  const t = _schedTarget;
  let url;
  if (t.kind === 'xray') {
    const res = await _schedBulkPost(
      (id) => `/api/xray/clients/${encodeURIComponent(id)}/schedule`,
      {action, date}
    );
    if (res.failed.length) { hint.textContent = `Ошибка: ${res.ok}/${res.total} ОК`; return; }
  } else {
    let url;
    if (t.kind === 'awg') url = `/api/clients/${encodeURIComponent(t.id)}/schedule`;
    else if (t.kind === 'mtg') url = `/api/mtg/schedule`;
    else if (_PKG_PROTO[t.kind]) url = `${_PKG_PROTO[t.kind].api}/clients/${encodeURIComponent(t.id)}/schedule`;
    else { hint.textContent = 'Неподдерживаемый режим'; return; }
    const r = await fetch(API + url, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action, date})
    });
    const j = await r.json();
    if (!r.ok || !j.ok) { hint.textContent = j.error || 'Ошибка'; return; }
  }
  _schedTarget.currentAction = action;
  _schedTarget.currentDate = date;
  document.getElementById('schedClearBtn').classList.remove('hidden');
  hint.style.color = 'var(--green, #4ade80)';
  const bulkMark = _schedBulkIds() ? ` (всем: ${_schedBulkIds().length})` : '';
  hint.textContent = `Запланировано: ${action === 'delete' ? 'удаление' : 'отключение'} ${date}` + bulkMark;
  _syncSection1();
  refreshAll();
}

async function togglePeerDisabled(kind, id, name, currentlyDisabled) {
  const url = kind === 'xray'
    ? `/api/xray/clients/${encodeURIComponent(id)}/disable`
    : `/api/clients/${encodeURIComponent(id)}/disable`;
  const r = await fetch(API + url, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({disabled: !currentlyDisabled})
  });
  const j = await r.json();
  if (!r.ok || !j.ok) { toast(j.error || 'Ошибка'); return; }
  toast(j.disabled ? `${name}: отключён` : `${name}: включён`);
  refreshAll();
}
function collapseBtnHtml(id, collapsed) {
  const cls = collapsed ? 'btn-collapse is-collapsed' : 'btn-collapse';
  const title = collapsed ? 'Развернуть' : 'Свернуть';
  return `<button class="${cls}" onclick="toggleClientCollapse('${escAttr(id)}')" title="${title}" aria-label="${title}">${_chevronSvg()}</button>`;
}
function toggleClientCollapse(id) {
  if (_collapsedClients.has(id)) _collapsedClients.delete(id);
  else _collapsedClients.add(id);
  if (_lastXrayData) renderXrayClients(_lastXrayData);
  if (_lastPeers) renderPeers(_lastPeers);
}
function toggleAllCollapse(scope) {
  let ids = [];
  if (scope === 'awg' && _lastPeers) ids = _lastPeers.map(p => p.public_key);
  else if (scope === 'xray' && _lastXrayData) ids = _lastXrayData.map(c => c.uuid);
  if (!ids.length) return;
  const anyExpanded = ids.some(id => !_collapsedClients.has(id));
  if (anyExpanded) ids.forEach(id => _collapsedClients.add(id));
  else ids.forEach(id => _collapsedClients.delete(id));
  if (scope === 'awg' && _lastPeers) renderPeers(_lastPeers);
  if (scope === 'xray' && _lastXrayData) renderXrayClients(_lastXrayData);
}
function _scopeAllCollapsed(scope) {
  let ids = [];
  if (scope === 'awg' && _lastPeers) ids = _lastPeers.map(p => p.public_key);
  else if (scope === 'xray' && _lastXrayData) ids = _lastXrayData.map(c => c.uuid);
  if (!ids.length) return false;
  return ids.every(id => _collapsedClients.has(id));
}
function _refreshCollapseAllBtn(scope, btnId) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  const allCol = _scopeAllCollapsed(scope);
  btn.classList.toggle('is-collapsed', allCol);
  btn.title = allCol ? 'Развернуть всех' : 'Свернуть всех';
  btn.setAttribute('aria-label', btn.title);
}
let _lastPeers = null;
const _expandedRulePlatforms = new Set();       // keyed by `${uuid}:${platform}`

// Единый каталог: {lists:[{id,name,url|rules}], global:[...]}. Платформенный URL
// записи выводит сервер при копировании конфига — тут платформа не важна.
function normalizeCatalog(raw) {
  if (Array.isArray(raw)) {
    const lists = [];
    for (const r of raw) {
      const id = r.id, name = r.name || id;
      if (r.rules && r.rules.length) { lists.push({id, name, rules: r.rules}); continue; }
      const url = r.url || r.clash_url || r.shadowrocket_url || r.loon_url || r.surge_url || '';
      if (url) lists.push({id, name, url});
    }
    return {lists, global: lists.slice()};
  }
  if (raw && raw.lists) return {lists: raw.lists || [], global: raw.global || []};
  // Легаси по-платформенная схема → объединяем по id.
  const merged = [], seen = new Set();
  for (const p of ['shadowrocket', 'loon', 'clash', 'surge']) {
    for (const r of ((raw && raw[p]) || [])) {
      if (!r || !r.id || seen.has(r.id)) continue;
      seen.add(r.id); merged.push(r);
    }
  }
  return {lists: merged, global: (raw && raw.global) || []};
}

function clientRuleLists(c) {
  const rl = c && c.rule_lists;
  if (Array.isArray(rl)) return {lists: rl.slice()};
  if (rl && Array.isArray(rl.lists)) return {lists: rl.lists.slice()};
  // Легаси per-platform → объединяем в один набор по id.
  const seen = new Set(), lists = [];
  for (const p of ['shadowrocket', 'loon', 'clash', 'surge']) {
    for (const id of ((rl && rl[p]) || [])) { if (!seen.has(id)) { seen.add(id); lists.push(id); } }
  }
  return {lists};
}

// Правая половина плитки «Маскировка под» и подпись под статусом сервиса.
// Половина заполнена в любом состоянии: пустая или спрятанная означала бы,
// что о втором входе — и о том, почему он не поднялся — узнать неоткуда.
function renderXrayMaskHysteria(hy) {
  const half = document.getElementById('xrayHyHalf');
  const tag = document.getElementById('xrayHyTag');
  const host = document.getElementById('xrayHyHost');
  const meta = document.getElementById('xrayHyMeta');
  const what = document.getElementById('xrayServiceWhat');
  if (!half || !host || !meta) return;

  const setWhat = (txt, color) => {
    if (!what) return;
    what.textContent = txt;
    what.style.color = color || 'var(--text3)';
  };

  if (hy.enabled) {
    let masq = hy.masquerade_url || '';
    try { if (masq) masq = new URL(masq).hostname; } catch (e) {}
    half.classList.remove('off');
    if (tag) tag.textContent = 'Hysteria 2 · UDP';
    host.textContent = masq || 'голый 404';
    meta.innerHTML =
      '<span>:' + escHtml(String(hy.port || '—')) + '</span>' +
      '<span>' + (hy.obfs ? 'salamander' : 'без обфускации') + '</span>' +
      (hy.cert_mode === 'self' ? '<span>самоподписанный серт</span>' : '');
    setWhat('VLESS + Hysteria 2', 'var(--green)');
    return;
  }

  half.classList.add('off');
  setWhat('только VLESS');

  if (hy.module === false) {
    // Модуль не загрузился — обычно файл не долетел при обновлении. Прятать
    // нельзя: снаружи это выглядит как «Hysteria просто нет».
    if (tag) tag.textContent = 'Hysteria 2';
    host.textContent = 'модуль не загружен';
    host.style.color = 'var(--orange)';
    meta.textContent = 'обновление доехало не полностью — см. «Зависимости»';
    return;
  }

  host.style.color = '';
  if (tag) tag.textContent = 'Hysteria 2 · UDP';
  host.textContent = 'выключена';
  // Почему выключена: занятый порт называем прямо, иначе непонятно, это
  // решение пользователя или сбой.
  const why = hy.port_taken_by
    ? ('порт ' + (hy.port || '') + ' занят: ' + hy.port_taken_by)
    : (hy.autoenable_note || '');
  meta.innerHTML =
    (why ? '<span style="color:var(--orange);">' + escHtml(why) + '</span>' : '') +
    '<a href="#" id="xrayHyEnableLink">включить</a>';
  const lnk = meta.querySelector('#xrayHyEnableLink');
  if (lnk) lnk.addEventListener('click', (e) => { e.preventDefault(); hyQuickEnable(hy); });
}

// Заголовок списка клиентов описывает, чем они вообще подключаются. Входов у
// ядра два, поэтому Hysteria дописывается, когда её инбаунд поднят: иначе
// заголовок утверждает, что клиент ходит только по VLESS, а в «Конфиге» у него
// лежит вторая ссылка.
function _xrayClientsHeaderText(isReality, hyOn) {
  const base = isReality ? 'Клиенты VLESS + Reality' : 'Клиенты VLESS + TLS + Vision';
  return hyOn ? base + ' + Hysteria 2' : base;
}

let _lastXrayData = null;
async function refreshXray() {
  try {
    const res = await fetch(API + '/api/xray/status');
    if (res.status === 401) { doLogout(); return; }
    const data = await res.json();
    _writeClientsCache('xray', data);
    _applyXrayStatus(data, false);
  } catch (e) {
    console.error('XRay refresh failed:', e);
  }
}

function _applyXrayStatus(data, fromCache) {
    let clients = data.clients || [];
    if (fromCache) {
      clients = clients.map(c => Object.assign({}, c, {online: false, devices: 0, via_active: []}));
    } else {
      _protoRunning.xray = !!data.running;
      _updateHeaderDot();
    }
    _lastXrayData = clients;
    _ruleListCatalog = normalizeCatalog(data.rule_lists);
    // Глобальные правила из кеша не берём: модалка Global сохранила бы устаревшее.
    if (data.global_rules && !fromCache) _globalIngest(data.global_rules);
    if (data.dns_default && !fromCache) _globalDnsDefault = data.dns_default;
    _globalTotals = data.global_totals || {up: 0, down: 0};
    document.getElementById('xrayTotal').textContent = clients.length;
    document.getElementById('xrayOnline').textContent = clients.filter(c => c.online).length;
    const sniEl = document.getElementById('xraySni');
    _xraySecurity = data.xray_security || '';
    const isReality = data.xray_security === 'reality';
    const xrayDomain = isReality ? (data.xray_dest || '—') : ((_serverConfig && _serverConfig.sni) || '—');
    // Из кеша при TLS домена ещё нет (он в конфиге сервера) — не затираем
    // то, что уже нарисовал hydrateCardsFromCache.
    if (!(fromCache && xrayDomain === '—')) _setStatOrPending(sniEl, xrayDomain);
    const xrayHdr = document.getElementById('xrayClientsHeader');
    if (xrayHdr) xrayHdr.textContent =
      _xrayClientsHeaderText(isReality, !!(data.hysteria && data.hysteria.enabled));
    // Port suffix next to domain + security mode line below
    const portTxt = (data.port != null && data.port !== '') ? data.port : '—';
    const portSuffixEl = document.getElementById('xrayPortSuffix');
    if (portSuffixEl) portSuffixEl.textContent = `:${portTxt}`;
    const secModeEl = document.getElementById('xraySecMode');
    if (secModeEl) {
      secModeEl.textContent = isReality
        ? 'Reality (чужой сайт)'
        : 'TLS (свой сертификат)';
    }
    renderXrayClients(clients);
    if (fromCache) return;
    renderXrayMaskHysteria(data.hysteria || {});
    renderProtoState(document.getElementById('xrayService'), data.state, data.running);
    _paintInstallBanner('xray', data.state);
    _updXrayToolbarBtnState(data);
    // Кешируем для мгновенной отрисовки при следующем логине.
    _writeCardCache({xray: {
      sni: (xrayDomain && xrayDomain !== '—') ? xrayDomain : undefined,
      port: (data.port != null && data.port !== '') ? data.port : undefined,
      security: isReality ? 'reality' : 'tls',
    }});
}

// === Country list (ISO 3166-1 alpha-2) ===
const COUNTRY_LIST = [
  ['RU','🇷🇺','Россия'],['BY','🇧🇾','Беларусь'],['KZ','🇰🇿','Казахстан'],['UA','🇺🇦','Украина'],
  ['US','🇺🇸','США'],['GB','🇬🇧','Великобритания'],['DE','🇩🇪','Германия'],['FR','🇫🇷','Франция'],
  ['IT','🇮🇹','Италия'],['ES','🇪🇸','Испания'],['NL','🇳🇱','Нидерланды'],['SE','🇸🇪','Швеция'],
  ['NO','🇳🇴','Норвегия'],['FI','🇫🇮','Финляндия'],['DK','🇩🇰','Дания'],['PL','🇵🇱','Польша'],
  ['CZ','🇨🇿','Чехия'],['SK','🇸🇰','Словакия'],['AT','🇦🇹','Австрия'],['CH','🇨🇭','Швейцария'],
  ['BE','🇧🇪','Бельгия'],['IE','🇮🇪','Ирландия'],['PT','🇵🇹','Португалия'],['GR','🇬🇷','Греция'],
  ['HU','🇭🇺','Венгрия'],['RO','🇷🇴','Румыния'],['BG','🇧🇬','Болгария'],['HR','🇭🇷','Хорватия'],
  ['SI','🇸🇮','Словения'],['EE','🇪🇪','Эстония'],['LV','🇱🇻','Латвия'],['LT','🇱🇹','Литва'],
  ['CY','🇨🇾','Кипр'],['MT','🇲🇹','Мальта'],['LU','🇱🇺','Люксембург'],['IS','🇮🇸','Исландия'],
  ['CA','🇨🇦','Канада'],['MX','🇲🇽','Мексика'],['BR','🇧🇷','Бразилия'],['AR','🇦🇷','Аргентина'],
  ['CL','🇨🇱','Чили'],['CO','🇨🇴','Колумбия'],['PE','🇵🇪','Перу'],['VE','🇻🇪','Венесуэла'],
  ['UY','🇺🇾','Уругвай'],['EC','🇪🇨','Эквадор'],['BO','🇧🇴','Боливия'],['PY','🇵🇾','Парагвай'],
  ['CR','🇨🇷','Коста-Рика'],['PA','🇵🇦','Панама'],['CU','🇨🇺','Куба'],['DO','🇩🇴','Доминикана'],
  ['JP','🇯🇵','Япония'],['CN','🇨🇳','Китай'],['HK','🇭🇰','Гонконг'],['TW','🇹🇼','Тайвань'],
  ['KR','🇰🇷','Южная Корея'],['KP','🇰🇵','КНДР'],['SG','🇸🇬','Сингапур'],['MY','🇲🇾','Малайзия'],
  ['TH','🇹🇭','Таиланд'],['VN','🇻🇳','Вьетнам'],['ID','🇮🇩','Индонезия'],['PH','🇵🇭','Филиппины'],
  ['IN','🇮🇳','Индия'],['PK','🇵🇰','Пакистан'],['BD','🇧🇩','Бангладеш'],['LK','🇱🇰','Шри-Ланка'],
  ['NP','🇳🇵','Непал'],['MM','🇲🇲','Мьянма'],['KH','🇰🇭','Камбоджа'],['LA','🇱🇦','Лаос'],
  ['MN','🇲🇳','Монголия'],['UZ','🇺🇿','Узбекистан'],['KG','🇰🇬','Киргизия'],['TJ','🇹🇯','Таджикистан'],
  ['TM','🇹🇲','Туркменистан'],['AF','🇦🇫','Афганистан'],['IR','🇮🇷','Иран'],['IQ','🇮🇶','Ирак'],
  ['SA','🇸🇦','Саудовская Аравия'],['AE','🇦🇪','ОАЭ'],['QA','🇶🇦','Катар'],['KW','🇰🇼','Кувейт'],
  ['BH','🇧🇭','Бахрейн'],['OM','🇴🇲','Оман'],['JO','🇯🇴','Иордания'],['LB','🇱🇧','Ливан'],
  ['SY','🇸🇾','Сирия'],['IL','🇮🇱','Израиль'],['PS','🇵🇸','Палестина'],['TR','🇹🇷','Турция'],
  ['EG','🇪🇬','Египет'],['LY','🇱🇾','Ливия'],['DZ','🇩🇿','Алжир'],['MA','🇲🇦','Марокко'],
  ['TN','🇹🇳','Тунис'],['SD','🇸🇩','Судан'],['ET','🇪🇹','Эфиопия'],['KE','🇰🇪','Кения'],
  ['NG','🇳🇬','Нигерия'],['GH','🇬🇭','Гана'],['ZA','🇿🇦','ЮАР'],['UG','🇺🇬','Уганда'],
  ['TZ','🇹🇿','Танзания'],['ZW','🇿🇼','Зимбабве'],['ZM','🇿🇲','Замбия'],['SN','🇸🇳','Сенегал'],
  ['CI','🇨🇮','Кот-д\'Ивуар'],['CM','🇨🇲','Камерун'],['AO','🇦🇴','Ангола'],['MZ','🇲🇿','Мозамбик'],
  ['MG','🇲🇬','Мадагаскар'],['RW','🇷🇼','Руанда'],['MW','🇲🇼','Малави'],['BW','🇧🇼','Ботсвана'],
  ['NA','🇳🇦','Намибия'],['AU','🇦🇺','Австралия'],['NZ','🇳🇿','Новая Зеландия'],['FJ','🇫🇯','Фиджи'],
  ['PG','🇵🇬','Папуа — Новая Гвинея'],['MD','🇲🇩','Молдова'],['GE','🇬🇪','Грузия'],['AM','🇦🇲','Армения'],
  ['AZ','🇦🇿','Азербайджан'],['RS','🇷🇸','Сербия'],['BA','🇧🇦','Босния и Герцеговина'],['MK','🇲🇰','Северная Македония'],
  ['ME','🇲🇪','Черногория'],['AL','🇦🇱','Албания'],['XK','🇽🇰','Косово'],['BY','🇧🇾','Беларусь'],
];
// Dedup (in case any duplicates)
const _COUNTRY_SEEN = new Set();
const COUNTRIES = COUNTRY_LIST.filter(c => {
  if (_COUNTRY_SEEN.has(c[0])) return false;
  _COUNTRY_SEEN.add(c[0]); return true;
});

const _countrySearchByUuid = {};

function renderGeoModeBlock(c, geoMode, geoCountries, selLists) {
  const uuid = c.uuid;
  const u = escAttr(uuid);
  const sw = (mode, label) => {
    const isOn = geoMode === mode;
    return `
      <label class="geo-switch ${isOn ? 'on' : ''}" title="${label}">
        <input type="checkbox" ${isOn ? 'checked' : ''}
          onchange="setClientGeoMode('${u}', this.checked ? '${mode}' : 'off')">
        <span class="switch-slider"></span>
        <span class="geo-switch-label">${label}</span>
      </label>`;
  };
  const switches = `
    <div class="geo-mode-switches">
      ${sw('lists', 'Списки правил')}
      ${sw('via', 'Страны с VPN')}
      ${sw('direct', 'Страны без VPN')}
    </div>`;

  let body = '';
  if (geoMode === 'lists') {
    body = platformBlockHtml(c, 'lists', 'Списки правил', selLists);
  } else if (geoMode === 'via' || geoMode === 'direct') {
    body = renderCountrySelector(uuid, geoCountries, geoMode);
  } else {
    body = '<div style="color:var(--text3);font-size:12px;text-align:center;padding:60px 0;">Все режимы выключены — весь трафик идёт через VPN.</div>';
  }
  return switches + `<div class="geo-body">${body}</div>`;
}

// Сравнение правил по имени. Локаль зафиксирована 'en' сознательно: (1) без неё
// порядок зависел бы от языка браузера, (2) ru-коллация ICU ставит кириллицу ПЕРЕД
// латиницей («Мои сайты» выше «Advertising»), а каталог почти весь латиницей —
// привычнее латиница, потом кириллица (как в проводнике). Кириллица между собой
// сортируется верно и с 'en'. numeric — чтобы «Rule 10» шло после «Rule 2».
function _byRuleName(a, b) {
  return (a.name || '').localeCompare(b.name || '', 'en', {sensitivity: 'base', numeric: true});
}
// Каталог по алфавиту для пользовательских списков (карточка клиента, Global,
// модалка создания). ОБЯЗАТЕЛЬНО копия: порядок самого _ruleListCatalog — это
// приоритет правил в конфиге, сортировать его на месте нельзя.
function _catalogByName(platform) {
  return [...(_ruleListCatalog[platform] || [])].sort(_byRuleName);
}

function platformBlockHtml(c, platform, label, selSet) {
  const cat = _catalogByName(platform);
  const ovMap = _clientRulePolicyMap(c);
  const platKey = c.uuid + ':' + platform;
  // Единый набор 'lists' раскрыт по умолчанию (членство в set = «свёрнут»);
  // у прочих платформ старая семантика (членство = «раскрыт»).
  const isPlatExpanded = platform === 'lists'
    ? !_expandedRulePlatforms.has(platKey)
    : _expandedRulePlatforms.has(platKey);
  const rows = (cat.length === 0)
    ? '<div class="rule-list-empty">Каталог пуст. Откройте «Списки правил» сверху и добавьте нужные через «Шаблоны».</div>'
    : cat.map(r => {
        const viewBtn = r.url
          ? `<button class="rule-view" title="Открыть .list" onclick="window.open('${escAttr(r.url)}','_blank','noopener')">&#128065;</button>`
          : `<span class="rule-view" title="Свой список (${(r.rules || []).length} правил)" style="cursor:default;color:var(--text3);">&#9776;</span>`;
        // Политика правила показывается и тут, рядом с именем: без неё непонятно,
        // заворачивает включённый список в VPN или наоборот исключает/блокирует.
        // Клик открывает выбор политики ТОЛЬКО для этого клиента (пунктир на
        // бейдже); каталог при этом не меняется — он правится в «Списках правил».
        const own = ovMap[r.id] || '';
        const pol = own || _rulePolicyOf(r);
        const polBtn = RULE_POLICY_BTNS.find(([v]) => v === pol) || RULE_POLICY_BTNS[2];
        const polHint = polBtn[2] + ' · ' + (own
          ? 'Своя политика этого клиента, клик — сменить'
          : 'Клик — своя политика для этого клиента');
        return `<div class="rule-list-row">
          <label class="switch">
            <input type="checkbox" ${selSet.has(r.id) ? 'checked' : ''}
              onchange="toggleClientRuleList('${escAttr(c.uuid)}','${platform}','${escAttr(r.id)}', this.checked)">
            <span class="switch-slider"></span>
          </label>
          <span class="rule-name" title="${escAttr(r.name)}">${escHtml(r.name)}</span>
          <span class="rule-pol${own ? ' own' : ''}" data-pol="${pol}"
            data-uuid="${escAttr(c.uuid)}" data-plat="${platform}" data-rid="${escAttr(r.id)}"
            title="${escAttr(polHint)}">${polBtn[1]}</span>
          ${viewBtn}
        </div>`;
      }).join('');
  const allOn = cat.length > 0 && cat.every(r => selSet.has(r.id));
  return `
    <div style="margin-top:10px;">
      <div class="plat-block-head"
           onclick="togglePlatBlock('${escAttr(c.uuid)}','${platform}', event)">
        <span class="pbh-title">
          <span class="pbh-caret">${isPlatExpanded ? '▾' : '▸'}</span>
          ${label}
          <span class="pbh-count">[${cat.filter(r => selSet.has(r.id)).length}/${cat.length}]</span>
        </span>
        <span class="pbh-mode" onclick="event.stopPropagation()">${listsDefaultToggleHtml(c)}</span>
        <button class="btn btn-sm btn-ghost pbh-all"
          onclick="event.stopPropagation();setAllClientRuleLists('${escAttr(c.uuid)}','${platform}', ${allOn ? 'false' : 'true'})"
          ${cat.length === 0 ? 'disabled' : ''}>
          ${allOn ? 'Выключить все' : 'Включить все'}
        </button>
      </div>
      <div class="rule-list-grid" style="margin-top:6px;${isPlatExpanded ? '' : 'display:none;'}">${rows}</div>
    </div>`;
}

// Режим исключений (Direct / VPN / Block) в шапке блока «Списки правил».
// Управляет только FINAL/MATCH в режиме 'lists': что делать с трафиком, не попавшим
// ни в одно правило. Режимов по странам не касается.
// Три варианта — свитча мало, поэтому радиогруппа.
const LISTS_DEFAULT_OPTS = [
  ['direct', 'Direct', 'Остальной трафик — в обход VPN, напрямую с IP клиента'],
  ['vpn',    'VPN',    'Остальной трафик — через VPN'],
  ['block',  'Block',  'Остальной трафик — блокируется'],
];
function listsDefaultToggleHtml(c) {
  // Показываем PENDING (что юзер редактирует) — в силу вступает по «Применить».
  const cur = _clientListsDefault(c);
  const hint = 'Режим исключений определяет, куда идёт весь остальной трафик — тот, что не попал ни в один включённый список. Direct — в обход VPN, напрямую с IP клиента. VPN — через VPN. Block — блокируется.';
  const u = escAttr(c.uuid);
  const opts = LISTS_DEFAULT_OPTS.map(([v, label, tip]) => `
      <label class="ld-opt${cur === v ? ' on' : ''}" title="${escAttr(tip)}">
        <input type="radio" name="ld_${u}" ${cur === v ? 'checked' : ''}
          onchange="setClientListsDefault('${u}', '${v}')">
        <span>${label}</span>
      </label>`).join('');
  return `
    <span class="lists-default" title="${escAttr(hint)}">
      <span class="lists-default-cap">Режим исключений:</span>
      <span class="lists-default-radios">${opts}</span>
    </span>`;
}

// pending-значение радиогруппы (что редактирует юзер), с откатом на applied.
function _clientListsDefault(c) {
  const v = (c && c.lists_default_pending != null) ? c.lists_default_pending
                                                   : ((c && c.lists_default) || 'direct');
  return (v === 'vpn' || v === 'block') ? v : 'direct';
}

// Как режим/страны: меняем ТОЛЬКО pending, в силу вступает по «Применить».
async function setClientListsDefault(uuid, mode) {
  const c = (_lastXrayData || []).find(x => x.uuid === uuid);
  if (c) c.lists_default_pending = mode;  // оптимистично, чтобы «Применить» сразу загорелся/погас
  renderXrayClients(_lastXrayData);
  const r = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/lists-default', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode})
  });
  if (!r.ok) { toast('Ошибка смены режима'); refreshXray(); }
}

function renderCountrySelector(uuid, selectedCodes, mode) {
  const u = escAttr(uuid);
  const sel = new Set(selectedCodes);
  const q = (_countrySearchByUuid[uuid] || '').toLowerCase();
  const filtered = q
    ? COUNTRIES.filter(([code, flag, name]) =>
        code.toLowerCase().includes(q) || name.toLowerCase().includes(q))
    : COUNTRIES;
  // Render selected first, then rest
  const selFirst = filtered.slice().sort((a, b) => {
    const aSel = sel.has(a[0]) ? 0 : 1;
    const bSel = sel.has(b[0]) ? 0 : 1;
    if (aSel !== bSel) return aSel - bSel;
    return a[2].localeCompare(b[2], 'ru');
  });
  const rows = selFirst.map(([code, flag, name]) => `
    <label class="country-row${sel.has(code) ? ' selected' : ''}">
      <input type="checkbox" ${sel.has(code) ? 'checked' : ''}
        onchange="toggleClientCountry('${u}', '${code}', this.checked)">
      <span class="country-flag">${flag}</span>
      <span class="country-name">${escHtml(name)}</span>
    </label>`).join('');
  return `
    <div class="country-search-row">
      <input type="text" placeholder="Поиск страны…" value="${escAttr(q)}"
        oninput="updateCountrySearch('${u}', this.value)" autocomplete="off">
      <span style="color:var(--text3);font-size:12px;">Выбрано: ${sel.size}</span>
    </div>
    <div class="country-grid">${rows}</div>`;
}

// Нормализованный отпечаток режима+стран+режима исключений; страны учитываются
// только в via/direct, режим исключений — только в lists (в других режимах он не влияет
// на конфиг, и «Применить» из-за него гореть не должен).
function _geoNorm(mode, countries, listsDefault) {
  mode = mode || 'off';
  const cs = (mode === 'via' || mode === 'direct')
    ? (countries || []).map(s => String(s).toUpperCase()).slice().sort()
    : [];
  const ld = (mode === 'lists')
    ? ((listsDefault === 'vpn' || listsDefault === 'block') ? listsDefault : 'direct')
    : '';
  return mode + '|' + cs.join(',') + '|' + ld;
}
// «Применить» горит только при реальном отличии pending от applied (как глобал-рул).
function _clientGeoDirty(c) {
  const pMode = (c.geo_mode_pending != null) ? c.geo_mode_pending : (c.geo_mode || 'off');
  const pC = c.geo_countries_pending || c.geo_countries || [];
  return _geoNorm(pMode, pC, _clientListsDefault(c))
      !== _geoNorm(c.geo_mode || 'off', c.geo_countries || [], c.lists_default || 'direct');
}

// Режим/страны меняем ТОЛЬКО в pending — на сервере ничего не пересобирается до «Применить».
async function setClientGeoMode(uuid, mode) {
  const c = (_lastXrayData || []).find(x => x.uuid === uuid);
  if (c) c.geo_mode_pending = mode;       // оптимистично, чтобы «Применить» сразу загорелся/погас
  renderXrayClients(_lastXrayData);
  const r = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/geo-mode', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode})
  });
  if (!r.ok) { toast('Ошибка смены режима'); refreshXray(); }
}

async function toggleClientCountry(uuid, code, on) {
  if (uuid === GLOBAL_ID) {
    const cur = new Set(((_globalRulesState || {}).countries || []).map(s => String(s).toUpperCase()));
    if (on) cur.add(code.toUpperCase()); else cur.delete(code.toUpperCase());
    return setGlobalCountries(Array.from(cur));
  }
  const c = (_lastXrayData || []).find(x => x.uuid === uuid);
  if (!c) return;
  const set = new Set((c.geo_countries_pending || c.geo_countries || []).map(s => String(s).toUpperCase()));
  if (on) set.add(code.toUpperCase()); else set.delete(code.toUpperCase());
  const arr = Array.from(set);
  c.geo_countries_pending = arr;          // оптимистично
  renderXrayClients(_lastXrayData);
  const r = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/geo-countries', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({countries: arr})
  });
  if (!r.ok) { toast('Ошибка'); refreshXray(); }
}

// «Применить» — фиксируем pending → applied (тут правила реально вступают в силу).
async function applyClientGeo(uuid) {
  const r = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/geo-apply', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'
  });
  if (r.ok) {
    const j = await r.json().catch(() => ({}));
    const c = (_lastXrayData || []).find(x => x.uuid === uuid);
    if (c && j.ok) {
      c.geo_mode = j.geo_mode; c.geo_countries = j.geo_countries;
      c.geo_mode_pending = j.geo_mode; c.geo_countries_pending = (j.geo_countries || []).slice();
      c.lists_default = j.lists_default || 'direct';
      c.lists_default_pending = c.lists_default;
    }
    renderXrayClients(_lastXrayData);
    toast('Правила применены');
  } else toast('Ошибка применения');
}

function updateCountrySearch(uuid, q) {
  _countrySearchByUuid[uuid] = q;
  // re-render only this client's body to keep input focused
  if (uuid !== GLOBAL_ID) {
    const c = (_lastXrayData || []).find(x => x.uuid === uuid);
    if (!c) return;
  }
  const card = document.querySelector(`.peer-card .peer-actions button[onclick*="${uuid}"]`);
  // Easier: re-render whole list
  renderXrayClients(_lastXrayData);
  // Restore focus on country search input
  const cards = document.querySelectorAll('.country-search-row input');
  cards.forEach(inp => {
    if (inp.parentElement && inp.parentElement.parentElement &&
        inp.parentElement.parentElement.parentElement) {
      // find the card containing this and check if it's our uuid — simpler: focus the last one with that value
    }
  });
  // Cheap fallback: focus first matching by value
  const target = Array.from(document.querySelectorAll('.country-search-row input'))
    .find(i => i.value === q);
  if (target) { target.focus(); target.setSelectionRange(q.length, q.length); }
}

// === Global rules (server-side routing pseudo-client) ===
let _globalPending = null;
let _globalApplied = null;
let _globalLastUpdate = null;
let _globalTotals = {up: 0, down: 0};
const GLOBAL_ID = '__global__';

function _globalDirty() {
  // pending != applied → есть несохранённые изменения, кнопка «Применить» видна.
  if (!_globalPending || !_globalApplied) return false;
  // Когда правила выключены — режим/списки/страны не важны (правило не действует),
  // иначе «включил режим X → выключил» оставляет mode=X и кнопка «Применить» висит.
  const norm = s => !s.enabled ? '{"enabled":false}' : JSON.stringify({
    enabled: true,
    mode: s.mode || 'lists',
    lists: (s.lists || []).slice().map(String).sort(),
    countries: (s.countries || []).slice().map(c => String(c).toUpperCase()).sort(),
  });
  return norm(_globalPending) !== norm(_globalApplied);
}

function renderGlobalRulesCard() {
  const pending = _globalPending || {enabled: false, mode: 'lists', lists: [], countries: []};
  const applied = _globalApplied || {enabled: false, mode: 'lists', lists: [], countries: []};
  // Карточка отражает PENDING — то, что юзер видит/редактирует. Бейдж/точка статуса
  // показывают APPLIED — реально активное состояние.
  const enabled = !!pending.enabled;
  const mode = pending.mode || 'lists';
  if (!_seenClientIds.has(GLOBAL_ID)) { _seenClientIds.add(GLOBAL_ID); _collapsedClients.add(GLOBAL_ID); }
  const collapsed = _collapsedClients.has(GLOBAL_ID);

  const badge = (() => {
    if (!applied.enabled) return '<span class="badge badge-rule" style="opacity:0.6;">Global rules выключены</span>';
    if (applied.mode === 'lists')  return `<span class="badge badge-rule">Списки правил [${(applied.lists || []).length}]</span>`;
    if (applied.mode === 'via')    return `<span class="badge badge-rule">Страны ✔ — не блокируем [${(applied.countries || []).length}]</span>`;
    if (applied.mode === 'direct') return `<span class="badge badge-rule">Страны ✔ — блокируем [${(applied.countries || []).length}]</span>`;
    return '';
  })();
  const dot = applied.enabled
    ? '<span class="status-dot online"></span>'
    : '<span class="status-dot disabled" title="Global rules выключены"></span>';

  const sw = (m, label) => {
    const isOn = enabled && mode === m;
    return `
      <label class="geo-switch ${isOn ? 'on' : ''}" title="${label}">
        <input type="checkbox" ${isOn ? 'checked' : ''}
          onchange="setGlobalMode('${m}', this.checked)">
        <span class="switch-slider"></span>
        <span class="geo-switch-label">${label}</span>
      </label>`;
  };
  const switchesHtml = `
    <div class="geo-mode-switches">
      ${sw('lists', 'Списки правил')}
      ${sw('via', 'Страны ✔ — не блокируем')}
      ${sw('direct', 'Страны ✔ — блокируем')}
    </div>`;

  let bodyHtml = '';
  if (!enabled) {
    bodyHtml = '<div style="color:var(--text3);font-size:12px;text-align:center;padding:40px 0;">Global rules выключены. Правила в карточках клиентов работают как обычно.</div>';
  } else if (mode === 'lists') {
    bodyHtml = renderGlobalListsBlock(pending);
  } else {
    bodyHtml = renderCountrySelector(GLOBAL_ID, pending.countries || [], mode);
  }
  const dirty = _globalDirty();
  const applyBtn = dirty
    ? `<button class="btn btn-sm btn-success" onclick="applyGlobalRules()" title="Применить изменения">Применить</button>`
    : '';

  // Глобальное расписание: используется только секция 2 (ежемесячный сброс трафика).
  const gResetDay = applied.traffic_reset_day != null ? applied.traffic_reset_day : null;
  const gSchedActive = !!gResetDay;
  const gTotalBytes = (_globalTotals.up || 0) + (_globalTotals.down || 0);
  const trafficInlineHtml = `<span class="traffic-total traffic-total--inline" title="Суммарный трафик XRay (↓ + ↑)">total: ${escHtml(formatBytesShort(gTotalBytes))}</span>`;
  return `
    <div class="peer-card${collapsed ? ' collapsed' : ''}" data-global-card="1">
      <div class="peer-top">
        <div class="peer-name">
          <div class="peer-name-row">
            ${dot}
            Global rules
            ${trafficInlineHtml}
          </div>
          <div class="peer-name-badge">${badge}</div>
        </div>
        <div class="peer-actions">
          ${applyBtn}
          <button class="btn btn-sm btn-ghost" onclick="openGlobalLogs()">Логи</button>
          <button class="btn-act" onclick="refreshGlobalRules()" title="Перекачать списки правил с источников и применить заново. Это не перезапуск сервиса — меняется только содержимое правил." aria-label="Перекачать списки правил">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/></svg>
          </button>
          ${dnsCfgBtnHtml(`openDnsModal('global','${GLOBAL_ID}','Global rules')`, (_globalDnsDefault && _globalDnsDefault.mode === 'set'), 'DNS-дефолт для новых юзеров')}
          ${powerBtnHtml(`toggleGlobalRules()`, !enabled)}
          ${scheduleBtnHtml(`openScheduleModal('global','${GLOBAL_ID}','Global rules',null,null,${gResetDay != null ? gResetDay : 'null'},null)`, gSchedActive ? 'active' : null)}
          ${collapseBtnHtml(GLOBAL_ID, collapsed)}
        </div>
      </div>
      <div class="peer-meta">
        <div class="peer-meta-item">
          <span class="lbl">Обновлено</span>
          <span class="val">${escHtml(_globalLastUpdate || '—')}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Трафик XRay (всего)</span>
          <span class="val">↓ ${escHtml(formatBytesShort(_globalTotals.down || 0))} &middot; ↑ ${escHtml(formatBytesShort(_globalTotals.up || 0))}</span>
        </div>
      </div>
      <div class="rule-list-section">
        ${switchesHtml}
        <div class="geo-body">${bodyHtml}</div>
      </div>
    </div>`;
}

function renderGlobalListsBlock(state) {
  const cat = (_ruleListCatalog && _ruleListCatalog.global) ? _catalogByName('global') : [];
  if (!cat.length) {
    return '<div class="rule-list-empty">Каталог Global пуст. Откройте «Списки правил» сверху → вкладка Global.</div>';
  }
  const sel = new Set((state.lists || []).map(String));
  const rows = cat.map(r => {
    const viewBtn = r.url
      ? `<button class="rule-view" title="Открыть .yaml" onclick="window.open('${escAttr(r.url)}','_blank','noopener')">&#128065;</button>`
      : `<span class="rule-view" title="Свой список (${(r.rules || []).length} правил)" style="cursor:default;color:var(--text3);">&#9776;</span>`;
    return `<div class="rule-list-row">
      <label class="switch">
        <input type="checkbox" ${sel.has(String(r.id)) ? 'checked' : ''}
          onchange="toggleGlobalList('${escAttr(r.id)}', this.checked)">
        <span class="switch-slider"></span>
      </label>
      <span class="rule-name" title="${escAttr(r.name)}">${escHtml(r.name)}</span>
      ${viewBtn}
    </div>`;
  }).join('');
  const allOn = cat.length > 0 && cat.every(r => sel.has(String(r.id)));
  return `
    <div style="margin-top:10px;">
      <div class="plat-block-head pbh-static">
        <span class="pbh-title">
          Списки
          <span class="pbh-count">[${sel.size}/${cat.length}]</span>
        </span>
        <button class="btn btn-sm btn-ghost pbh-all"
          onclick="setAllGlobalLists(${allOn ? 'false' : 'true'})"
          ${cat.length === 0 ? 'disabled' : ''}>
          ${allOn ? 'Выключить все' : 'Включить все'}
        </button>
      </div>
      <div class="rule-list-grid" style="margin-top:6px;">${rows}</div>
    </div>`;
}

function _globalIngest(blob) {
  if (!blob) return;
  _globalPending = blob.pending || _globalPending;
  _globalApplied = blob.applied || _globalApplied;
  _globalLastUpdate = blob.last_update || _globalLastUpdate;
}

async function _globalSavePending() {
  // Сохраняет _globalPending на сервер БЕЗ apply — просто чтобы не потерять при F5.
  if (!_globalPending) return;
  try {
    const r = await fetch(API + '/api/xray/global', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        enabled: !!_globalPending.enabled,
        mode: _globalPending.mode || 'lists',
        lists: _globalPending.lists || [],
        countries: _globalPending.countries || [],
      })
    });
    if (r.ok) {
      const data = await r.json();
      _globalIngest(data);
    }
  } catch (e) { /* не критично */ }
}

async function applyGlobalRules() {
  toast('Применяю правила…');
  const r = await fetch(API + '/api/xray/global/apply', {method: 'POST'});
  const data = await r.json();
  if (r.ok) {
    _globalIngest(data);
    renderXrayClients(_lastXrayData || []);
    toast('Правила применены');
  } else {
    toast(data.error || 'Ошибка применения');
  }
}

async function refreshGlobalRules() {
  toast('Полное обновление…');
  const r = await fetch(API + '/api/xray/global/refresh', {method: 'POST'});
  const data = await r.json();
  if (r.ok) {
    _globalIngest(data);
    renderXrayClients(_lastXrayData || []);
    toast('Списки переcкачаны и применены');
  } else {
    toast(data.error || 'Ошибка обновления');
  }
}

async function toggleGlobalRules() {
  if (!_globalPending) _globalPending = {enabled: false, mode: 'lists', lists: [], countries: []};
  _globalPending.enabled = !_globalPending.enabled;
  renderXrayClients(_lastXrayData || []);
  _globalSavePending();
}

async function setGlobalMode(mode, on) {
  if (!_globalPending) _globalPending = {enabled: false, mode: 'lists', lists: [], countries: []};
  if (on) {
    _globalPending.enabled = true;
    _globalPending.mode = mode;
  } else {
    _globalPending.enabled = false;
  }
  renderXrayClients(_lastXrayData || []);
  _globalSavePending();
}

async function toggleGlobalList(id, on) {
  if (!_globalPending) _globalPending = {enabled: true, mode: 'lists', lists: [], countries: []};
  const cur = new Set((_globalPending.lists || []).map(String));
  if (on) cur.add(String(id)); else cur.delete(String(id));
  _globalPending.lists = Array.from(cur);
  renderXrayClients(_lastXrayData || []);
  _globalSavePending();
}

async function setAllGlobalLists(on) {
  if (!_globalPending) _globalPending = {enabled: true, mode: 'lists', lists: [], countries: []};
  const cat = (_ruleListCatalog && _ruleListCatalog.global) || [];
  _globalPending.lists = on ? cat.map(r => String(r.id)) : [];
  renderXrayClients(_lastXrayData || []);
  _globalSavePending();
}

async function setGlobalCountries(arr) {
  if (!_globalPending) _globalPending = {enabled: true, mode: 'via', lists: [], countries: []};
  _globalPending.countries = arr;
  renderXrayClients(_lastXrayData || []);
  _globalSavePending();
}

// «Через что сидит» клиент XRay: вход (по журналу XRay — у каждого
// соединения записан инбаунд) и приложение (по User-Agent последней загрузки
// профиля или подписки — сам VPN-трафик приложение не называет).
const _VIA_NAMES = {vless: 'VLESS', hy: 'Hysteria 2', xdns: 'XDNS'};

function _fmtLogTs(ts) {
  // «2026/10/06 20:31:05» или «2026-10-06 20:31:05» → «06.10.2026 20:31:05»
  const m = String(ts || '').match(/^(\d{4})[\/-](\d{2})[\/-](\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  return m ? `${m[3]}.${m[2]}.${m[1]} ${m[4]}` : String(ts || '');
}

function _xrayViaBadge(c) {
  const via = c.via || {};
  const kinds = Object.keys(_VIA_NAMES).filter(k => via[k]);
  if (!kinds.length) return '';
  // Все входы, активные сейчас: клиент может сидеть на VLESS с ноутбука и на
  // Hysteria с телефона одновременно. Нет активных в окне — самый свежий.
  const active = Object.keys(_VIA_NAMES).filter(k => (c.via_active || []).includes(k));
  const nowKinds = active.length ? active : [kinds.reduce((a, k) => (via[k] > via[a] ? k : a), kinds[0])];
  const nowText = nowKinds.map(k => _VIA_NAMES[k]).join(' + ');
  const app = (c.app && c.app.name && c.app.name !== 'браузер') ? c.app.name : '';
  const lines = ['Сейчас: ' + nowText + (app ? ' · ' + app : '')];
  for (const k of Object.keys(_VIA_NAMES)) {
    lines.push(_VIA_NAMES[k] + ' — ' + (via[k] ? 'последний раз ' + _fmtLogTs(via[k]) : 'не подключался'));
  }
  if (app) lines.push('Приложение — по последней загрузке профиля/подписки: ' + app + ', ' + _fmtLogTs(c.app.ts));
  if (nowKinds.includes('xdns')) lines.push('Через XDNS сервер видит адрес DNS-резолвера, а не клиента — IP взят из VLESS/Hysteria.');
  // Только пока онлайн: у офлайн-клиента «сейчас» нет, а история — в подсказке
  // онлайн-бейджа и в «Логах».
  if (!c.online) return '';
  return `<span class="badge badge-rule badge-via" title="${escAttr(lines.join('\n'))}">` +
    `${escHtml(nowText)}${app ? ' · ' + escHtml(app) : ''}</span>`;
}

function renderXrayClients(clients) {
  if (_clientDragDefer('xray', () => renderXrayClients(_lastXrayData || clients))) return;
  clients = _clientOrderSort('xray', clients, c => c.uuid);
  const list = document.getElementById('xrayList');
  // Always render Global rules card first.
  const globalCard = renderGlobalRulesCard();
  if (clients.length === 0) {
    list.innerHTML = globalCard + '<div class="empty-state"><div class="icon">&#9881;</div><p>Клиентов пока нет. Создайте первого, чтобы начать.</p></div>';
    _refreshCollapseAllBtn('xray', 'xrayCollapseAllBtn');
    return;
  }
  list.innerHTML = globalCard + clients.map(c => {
    const uuidShort = c.uuid.substring(0, 8) + '…' + c.uuid.substring(c.uuid.length - 4);
    const sel = clientRuleLists(c);
    const selLists = new Set(sel.lists);
    // Свитчи/страны показывают PENDING (что юзер редактирует), бейдж — APPLIED (что в силе).
    const appliedMode = c.geo_mode || 'off';
    const appliedCountries = (c.geo_countries || []).map(s => String(s).toUpperCase());
    const geoMode = (c.geo_mode_pending != null ? c.geo_mode_pending : appliedMode) || 'off';
    const geoCountries = (c.geo_countries_pending || c.geo_countries || []).map(s => String(s).toUpperCase());
    const geoDirty = _clientGeoDirty(c);
    const modeBadge = (() => {
      if (appliedMode === 'lists')  return '<span class="badge badge-rule">Списки правил</span>';
      if (appliedMode === 'via')    return `<span class="badge badge-rule">Страны с VPN [${appliedCountries.length}]</span>`;
      if (appliedMode === 'direct') return `<span class="badge badge-rule">Страны без VPN [${appliedCountries.length}]</span>`;
      return '<span class="badge badge-rule" style="opacity:0.6;">Правила не применяются</span>';
    })();
    // «Устройств» — активные сессии клиента по данным ядра (VLESS + Hysteria
    // вместе: у обоих инбаундов общий email). Ноль не показываем: у офлайн-
    // клиента бейдж «Устройств: 0» — шум, точка статуса и так серая.
    const devicesBadge = (c.devices || 0) > 0
      ? `<span class="badge badge-rule" title="Сколько устройств сейчас онлайн. Ядро XRay считает адреса — телефон и ноутбук за одним роутером для него одно устройство; если они сидят на разных входах (VLESS и Hysteria), панель засчитывает два.">Устройств: ${c.devices}</span>`
      : '';
    const onlineDot = c.online
      ? '<span class="status-dot online"></span>'
      : '<span class="status-dot offline"></span>';
    const isExpanded = _expandedRuleSections.has(c.uuid);
    if (!_seenClientIds.has(c.uuid)) { _seenClientIds.add(c.uuid); _collapsedClients.add(c.uuid); }
    const collapsed = _collapsedClients.has(c.uuid);
    const disabled = !!c.disabled;
    const schedAction = c.scheduled_action || null;
    const uuidAttr = escAttr(c.uuid);
    const nameAttr = escAttr(c.name || '');
    return `
    <div class="peer-card${collapsed ? ' collapsed' : ''}" data-ckey="${uuidAttr}">
      <div class="peer-top">
        <div class="peer-name">
          <div class="peer-name-row">
            ${disabled
              ? '<span class="status-dot disabled" title="Отключён"></span>'
              : onlineDot}
            ${escHtml(c.name || 'Без имени')}
            <span class="traffic-total traffic-total--inline" title="Суммарный трафик (↓ + ↑)">total: ${escHtml(formatBytesShort((c.up || 0) + (c.down || 0)))}${c.traffic_limit_gb ? ` &middot; limit: ${escHtml(c.traffic_limit_gb)} GB` : ''}</span>
          </div>
          <div class="peer-name-badge">${modeBadge}${devicesBadge}${_xrayViaBadge(c)}</div>
        </div>
        <div class="peer-actions">
          ${geoDirty ? `<button class="btn btn-sm btn-success" onclick="applyClientGeo('${uuidAttr}')" title="Применить изменения правил">Применить</button>` : ''}
          <button class="btn btn-sm btn-ghost" onclick="showXrayConfig('${uuidAttr}')">Конфиг</button>
          <button class="btn btn-sm btn-ghost" onclick="openXrayLogs('${uuidAttr}')">Логи</button>
          ${dnsCfgBtnHtml(`openDnsModal('xray','${uuidAttr}','${nameAttr}')`, _dnsIconState(c), _dnsIconTitle(_dnsIconState(c)))}
          ${allowIpBtnHtml(`openAllowIpModal('${uuidAttr}','${nameAttr}')`, ((c.allow_ips || []).length + (c.block_ips || []).length) > 0, 'Фильтрация по IP (зелёный = список задан)')}
          ${pencilBtnHtml(`showXrayRename('${uuidAttr}','${nameAttr}')`)}
          ${trashBtnHtml(`showXrayDelete('${uuidAttr}','${nameAttr}')`)}
          ${powerBtnHtml(`togglePeerDisabled('xray','${uuidAttr}','${nameAttr}',${disabled})`, disabled)}
          ${scheduleBtnHtml(`openScheduleModal('xray','${uuidAttr}','${nameAttr}',${schedAction ? `'${schedAction}'` : 'null'},${c.scheduled_at ? `'${c.scheduled_at}'` : 'null'},${c.traffic_reset_day != null ? c.traffic_reset_day : 'null'},${c.traffic_limit_gb != null ? c.traffic_limit_gb : 'null'})`, schedAction)}
          ${collapseBtnHtml(c.uuid, collapsed)}
        </div>
      </div>
      <div class="peer-meta">
        <div class="peer-meta-item">
          <span class="lbl">UUID</span>
          <span class="val">${escHtml(uuidShort)}</span>
        </div>
        <div class="peer-meta-item">
          <span class="lbl">Создан</span>
          <span class="val">${escHtml(_fmtYmd(c.created || '-'))}</span>
        </div>
        ${c.last_ip ? `
        <div class="peer-meta-item">
          <span class="lbl" style="color:var(--text2);">on-line:${c.last_seen ? ' <span style="font-weight:normal;">' + escHtml(fmtXrayTs(c.last_seen)) + '</span>' : ''}</span>
          <span class="val" title="${escAttr(c.last_seen || '')}">${escHtml(c.last_ip)}${c.geo && (c.geo.country || c.geo.city) ? ' · ' + escHtml([c.geo.country, c.geo.city].filter(Boolean).join(', ')) : ''}${c.geo && c.geo.org ? ' · ' + escHtml(c.geo.org) : ''}</span>
        </div>` : ''}
        <div class="peer-meta-item">
          <span class="lbl">Трафик</span>
          <span class="val">↓ ${escHtml(formatBytesShort(c.down || 0))} &middot; ↑ ${escHtml(formatBytesShort(c.up || 0))}</span>
        </div>
      </div>
      <div class="rule-list-section">
        ${renderGeoModeBlock(c, geoMode, geoCountries, selLists)}
      </div>
    </div>`;
  }).join('');
  _refreshCollapseAllBtn('xray', 'xrayCollapseAllBtn');
}

function _updXrayToolbarBtnState(data) {
  // Тумблеры отражают «намерение» (что юзер хочет), а не факт наличия секций в
  // конфиге: иначе при слетевшем stats тумблер показывал бы OFF, а ⚠ срабатывало —
  // рассинхрон. *_wanted приходят с бэка (stats по умолчанию ON, логи — опт-ин).
  // Фолбэк на старое поведение, если бэк ещё не отдаёт *_wanted.
  const statsOn = (data.stats_wanted !== undefined)
    ? data.stats_wanted === true
    : ((data.clients || []).some(c => c.up || c.down) || data.stats_enabled === true);
  const logsOn  = (data.logs_wanted !== undefined)
    ? data.logs_wanted === true
    : data.access_log_enabled === true;
  // Тумблеры переехали в модалку «Настройки протокола» и существуют только пока
  // она открыта — состояние держим здесь, чтобы модалка открывалась уже готовой.
  _xrayFlags = {stats: !!statsOn, logs: !!logsOn};
  const swStats = document.getElementById('swEnableStats');
  const swLogs  = document.getElementById('swEnableLogs');
  const rowStats = document.getElementById('rowEnableStats');
  const rowLogs  = document.getElementById('rowEnableLogs');
  if (swStats) swStats.checked = !!statsOn;
  if (swLogs)  swLogs.checked  = !!logsOn;
  if (rowStats) rowStats.classList.toggle('is-on', !!statsOn);
  if (rowLogs)  rowLogs.classList.toggle('is-on', !!logsOn);
}

async function onSwitchEnableStats(el) {
  if (!el.checked) {
    // Disabling stats requires manual edit of xray config — keep panel safe.
    el.checked = true;
    toast('Отключение статистики делается вручную в конфиге XRay');
    return;
  }
  await enableXrayStats();
}

async function onSwitchEnableLogs(el) {
  if (!el.checked) {
    el.checked = true;
    toast('Отключение логов делается вручную в конфиге XRay');
    return;
  }
  await enableXrayAccessLog();
}

async function enableXrayAccessLog() {
  const ok = await openConfirm({
    title: 'Включить логи XRay?',
    body: 'Однократно: в /usr/local/etc/xray/config.json добавится блок log (access=/var/log/xray/access.log, loglevel=info), создастся каталог, xray перезапустится. После этого в карточках клиентов появятся последний IP и кнопка «Логи».',
    okLabel: 'Включить',
  });
  if (!ok) return;
  const res = await fetch(API + '/api/xray/enable-access-log', {method: 'POST'});
  const data = await res.json();
  if (res.ok) {
    if (data.changed) {
      toast('Логи включены, xray перезапущен. Подождите ~3 сек, затем обновите.');
      setTimeout(refreshXray, 3000);
    } else {
      toast('Логи уже были настроены');
    }
  } else {
    toast(data.error || 'Не удалось включить логи');
  }
}

async function enableXrayStats() {
  const ok = await openConfirm({
    title: 'Включить статистику XRay?',
    body: 'Однократно: в /usr/local/etc/xray/config.json добавится блок stats/api/policy и инбаунд на 127.0.0.1:10085, xray перезапустится.',
    okLabel: 'Включить',
  });
  if (!ok) return;
  const res = await fetch(API + '/api/xray/enable-stats', {method: 'POST'});
  const data = await res.json();
  if (res.ok) {
    if (data.changed) {
      toast('Статистика включена, xray перезапущен. Подождите ~3 сек и обновите.');
      setTimeout(refreshXray, 3000);
    } else {
      toast('Статистика уже была настроена');
    }
  } else {
    toast(data.error || 'Не удалось включить статистику');
  }
}

const _expandedNewClientPlats = new Set();

// Списки, которые НЕ включаются новому клиенту по умолчанию (тумблер есть, но
// выключен). Block ads/trackers: у клиентов блокировка рекламы уже стоит на
// уровне DNS, а доменные апексы вроде doubleclick.net/googletagmanager.com,
// которых нет в DNS-листах, ломают YouTube и сайты с consent-баннерами.
const NEW_CLIENT_OFF_BY_DEFAULT = new Set(['block_ads_trackers_quic']);

function _newClientGridId(platform) { return 'xrayNewRuleListGrid_' + platform; }

function _renderNewClientPlatforms() {
  const wrap = document.getElementById('xrayNewPlatBlocks');
  const platforms = [{id: 'lists', label: 'Списки правил'}];
  wrap.innerHTML = platforms.map(p => {
    const cat = _catalogByName(p.id);
    const onCount = cat.filter(r => !NEW_CLIENT_OFF_BY_DEFAULT.has(r.id)).length;
    const expanded = _expandedNewClientPlats.has(p.id);
    const gridId = _newClientGridId(p.id);
    const rows = (cat.length === 0)
      ? '<div class="rule-list-empty">Каталог пуст. Сначала добавьте списки.</div>'
      : cat.map(r => {
          const viewBtn = r.url
            ? `<button class="rule-view" title="Открыть .list в новом окне" onclick="window.open('${escAttr(r.url)}','_blank','noopener')">&#128065;</button>`
            : `<span class="rule-view" title="Свой список (${(r.rules || []).length} правил)" style="cursor:default;color:var(--text3);">&#9776;</span>`;
          return `
          <div class="rule-list-row">
            <label class="switch">
              <input type="checkbox" data-rule-id="${escAttr(r.id)}" data-platform="${p.id}"${NEW_CLIENT_OFF_BY_DEFAULT.has(r.id) ? '' : ' checked'}>
              <span class="switch-slider"></span>
            </label>
            <span class="rule-name" title="${escAttr(r.name)}">${escHtml(r.name)}</span>
            ${viewBtn}
          </div>`;
        }).join('');
    return `
      <div style="margin-top:10px;">
        <div class="plat-block-head" style="cursor:pointer;display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-radius:6px;background:var(--surface2);"
             onclick="toggleNewClientPlat('${p.id}', event)">
          <span style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--text2);font-weight:500;">
            <span style="display:inline-block;width:14px;color:var(--accent);">${expanded ? '▾' : '▸'}</span>
            ${p.label}
            <span class="newPlatCount" data-platform="${p.id}" style="color:var(--text3);font-weight:normal;">[${onCount}/${cat.length}]</span>
          </span>
          <span onclick="event.stopPropagation()">
            <button type="button" class="btn btn-sm btn-ghost" style="padding:2px 10px;"
              onclick="_setAllNewClientPlat('${p.id}')"
              ${cat.length === 0 ? 'disabled' : ''}>
              <span class="newPlatToggleLabel" data-platform="${p.id}">${(onCount === cat.length && cat.length > 0) ? 'Выключить все' : 'Включить все'}</span>
            </button>
          </span>
        </div>
        <div id="${gridId}" class="rule-list-grid" style="margin-top:6px;${expanded ? '' : 'display:none;'}">${rows}</div>
      </div>`;
  }).join('');
  // hook checkbox change → update counts + RU switch state
  document.querySelectorAll('#xrayNewPlatBlocks input[type=checkbox]')
    .forEach(el => el.addEventListener('change', () => {
      _updNewClientPlatHeader(el.dataset.platform);
      _updNewClientBypassRuState();
    }));
}

function _updNewClientPlatHeader(platform) {
  const cat = _ruleListCatalog[platform] || [];
  const grid = document.getElementById(_newClientGridId(platform));
  if (!grid) return;
  const checked = grid.querySelectorAll('input[type=checkbox]:checked').length;
  const countEl = document.querySelector(`.newPlatCount[data-platform="${platform}"]`);
  if (countEl) countEl.textContent = `[${checked}/${cat.length}]`;
  const lblEl = document.querySelector(`.newPlatToggleLabel[data-platform="${platform}"]`);
  if (lblEl) lblEl.textContent = (checked === cat.length && cat.length > 0) ? 'Выключить все' : 'Включить все';
}

function toggleNewClientPlat(platform, ev) {
  if (ev) ev.stopPropagation();
  if (_expandedNewClientPlats.has(platform)) _expandedNewClientPlats.delete(platform);
  else _expandedNewClientPlats.add(platform);
  const grid = document.getElementById(_newClientGridId(platform));
  if (grid) grid.style.display = _expandedNewClientPlats.has(platform) ? '' : 'none';
  // toggle the arrow
  const head = grid && grid.previousElementSibling;
  if (head) {
    const arrow = head.querySelector('span > span');
    if (arrow) arrow.textContent = _expandedNewClientPlats.has(platform) ? '▾' : '▸';
  }
}

function _setAllNewClientPlat(platform) {
  const grid = document.getElementById(_newClientGridId(platform));
  if (!grid) return;
  const cat = _ruleListCatalog[platform] || [];
  const checked = grid.querySelectorAll('input[type=checkbox]:checked').length;
  const turnOn = !(checked === cat.length && cat.length > 0);
  grid.querySelectorAll('input[type=checkbox]').forEach(el => el.checked = turnOn);
  _updNewClientPlatHeader(platform);
  _updNewClientBypassRuState();
}

function showXrayAddModal() {
  document.getElementById('xrayNewName').value = '';
  const noRulesEl = document.getElementById('xrayNewNoRules');
  if (noRulesEl) { noRulesEl.checked = false; _onNoRulesToggle(noRulesEl); }
  _expandedNewClientPlats.clear();
  _expandedNewClientPlats.add('lists');  // единый блок раскрыт сразу
  _renderNewClientPlatforms();
  document.getElementById('xrayAddModal').classList.remove('hidden');
  document.getElementById('xrayNewName').focus();
}

function _updNewClientBypassRuState() { /* legacy noop — replaced by _onNoRulesToggle */ }

function _onNoRulesToggle(cb) {
  const block = document.getElementById('xrayNewRulesBlock');
  if (!block) return;
  block.style.opacity = cb.checked ? '0.4' : '';
  block.style.pointerEvents = cb.checked ? 'none' : '';
}

let _xrayCreating = false;
async function createXrayClient(ev) {
  if (_xrayCreating) return;
  const name = document.getElementById('xrayNewName').value.trim();
  const noRulesEl = document.getElementById('xrayNewNoRules');
  const no_rules = noRulesEl ? noRulesEl.checked : false;
  const rule_lists = {lists: []};
  if (!no_rules) {
    document.querySelectorAll('#xrayNewPlatBlocks input[type=checkbox]:checked').forEach(el => {
      const plat = el.getAttribute('data-platform');
      const id = el.getAttribute('data-rule-id');
      if (rule_lists[plat]) rule_lists[plat].push(id);
    });
  }
  if (!name) return;
  // Ключ идемпотентности на одно нажатие: браузер сам переотправляет POST, если
  // соединение оборвалось до ответа, а рестарт XRay его как раз и рвёт — панель
  // на таких серверах отдаётся его же фоллбеком. С этим ключом повтор вернёт
  // уже созданного клиента вместо второго такого же.
  const reqId = (window.crypto && crypto.randomUUID)
    ? crypto.randomUUID()
    : (Date.now().toString(36) + Math.random().toString(36).slice(2));
  _xrayCreating = true;
  const btn = ev && ev.target ? ev.target : document.querySelector('#xrayAddModal .btn-success');
  const prevText = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Создаём…'; }
  try {
    const res = await fetch(API + '/api/xray/clients', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name, no_rules, rule_lists, request_id: reqId})
    });
    const data = await res.json();
    if (res.ok) {
      closeModal('xrayAddModal');
      refreshXray();
      showXrayConfigData(data);
      toast('Клиент «' + name + '» создан');
    } else {
      toast(translateError(data.error) || 'Ошибка создания клиента');
    }
  } catch (e) {
    // Соединение оборвал рестарт XRay. Клиент при этом создан, и повтор с тем
    // же request_id вернёт именно его — поэтому не гадаем, а переспрашиваем.
    console.error('createXrayClient failed:', e);
    try {
      await pingUntilAlive();
      const again = await fetch(API + '/api/xray/clients', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name, no_rules, rule_lists, request_id: reqId})
      });
      const data2 = await again.json();
      if (again.ok) {
        closeModal('xrayAddModal');
        refreshXray();
        showXrayConfigData(data2);
        toast('Клиент «' + name + '» создан');
      } else {
        closeModal('xrayAddModal');
        refreshXray();
        toast(translateError(data2.error) || 'Ошибка создания клиента');
      }
    } catch (e2) {
      closeModal('xrayAddModal');
      refreshXray();
      toast('Соединение прервано — проверьте список (клиент мог создаться)');
    }
  } finally {
    _xrayCreating = false;
    if (btn) { btn.disabled = false; btn.textContent = prevText; }
  }
}

document.getElementById('xrayNewName').addEventListener('keydown', e => {
  if (e.key === 'Enter') createXrayClient();
});

function openXrayLogs(uuid) {
  window.open('/static/logs.html?uuid=' + encodeURIComponent(uuid), '_blank', 'noopener');
}

function openGlobalLogs() {
  window.open('/static/logs.html?global=1', '_blank', 'noopener');
}

function openMtgLogs() {
  window.open('/static/mtg_logs.html', '_blank', 'noopener');
}

// === Dependencies window ===
let _depsNeedRestart = false;
let _depsTab = '';

function switchDepsTab(key) {
  _depsTab = key;
  if (_depsLastData) _paintDeps(_depsLastData);
}

function _paintDepsTabs(data) {
  const box = document.getElementById('depsTabs');
  if (!box) return;
  const groups = data.groups || [];
  if (!groups.length) { box.innerHTML = ''; return; }
  // Первой открываем вкладку с проблемами: если что-то сломано, показывать
  // сперва «всё хорошо» на другой вкладке — только сбивать с толку.
  if (!_depsTab || !groups.some(g => g.key === _depsTab)) {
    const bad = groups.find(g => g.failing > 0);
    _depsTab = (bad || groups[0]).key;
  }
  box.innerHTML = groups.map(g => {
    const mark = g.failing
      ? ` <span class="deps-tab-badge">${g.failing}</span>`
      : '';
    return `<button class="cfg-tab${g.key === _depsTab ? ' active' : ''}${g.failing ? ' has-problem' : ''}"
      onclick="switchDepsTab('${escAttr(g.key)}')">${escHtml(g.title)}${mark}</button>`;
  }).join('');
  _revealActiveTab(box);
}

function _paintDeps(data) {
  const list = document.getElementById('depsList');
  if (!list) return;
  _paintDepsAlertBtn(data);
  _depsNeedRestart = false;
  document.getElementById('depsRestartBlock').classList.add('hidden');
  _paintDepsTabs(data);
  const shown = (data.groups || []).length
    ? (data.items || []).filter(i => (i.group || 'panel') === _depsTab)
    : (data.items || []);
  list.innerHTML = shown.map(it => {
    const idAttr = escAttr(it.id);
    const statusBadge = it.ok
      ? '<span class="dep-status ok">● OK</span>'
      : (it.level === 'tip' ? '<span class="dep-status tip">● совет</span>'
                            : '<span class="dep-status bad">● NOT OK</span>');
    const desc = it.description ? `<div class="dep-desc">${escHtml(it.description)}</div>` : '';
    let cmdBlock = '';
    if (!it.ok && it.fix_cmd) {
      cmdBlock = `
        <div class="dep-section-label">Команда для терминала (можно скопировать)</div>
        <pre class="dep-cmd">${escHtml(it.fix_cmd)}</pre>`;
    }
    let actions = '';
    if (!it.ok && it.fixable) {
      actions = `
        <div class="dep-section-label">Или применить из панели</div>
        <div class="dep-actions">
          <button class="btn btn-sm btn-success" onclick="applyDepFix('${idAttr}')">Применить через панель</button>
          <div class="dep-result pending" id="depRes_${idAttr}">Готово к запуску</div>
        </div>`;
    } else if (!it.ok && !it.fixable && it.fix_cmd) {
      actions = `<div class="dep-section-label" style="color:var(--orange);">Только ручное исправление — выполни команду выше в терминале сервера</div>`;
    }
    return `<div class="dep-card ${it.ok ? 'is-ok' : ''}">
      <div class="dep-head">
        <div class="dep-title">${escHtml(it.name)}</div>
        ${statusBadge}
      </div>
      ${desc}
      ${cmdBlock}
      ${actions}
    </div>`;
  }).join('');
}

let _depsLastData = null;
async function loadDeps(opts) {
  opts = opts || {};
  const list = document.getElementById('depsList');
  if (!opts.silent && !list.hasChildNodes()) {
    list.innerHTML = '<div style="color:var(--text3);">…</div>';
  }
  if (!opts.silent) _spinBtn('depsReloadBtn', true, 'Проверяем…');
  try {
    const r = await fetch(API + '/api/system/dependencies', {credentials: 'same-origin'});
    if (!r.ok) {
      if (!opts.silent) list.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>';
      return;
    }
    const data = await r.json();
    _depsLastData = data;
    _writeModalCache('deps', data);
    _paintDeps(data);
    return data;
  } catch (e) {
    if (!opts.silent && !list.hasChildNodes()) {
      list.innerHTML = '<div style="color:var(--red);">Ошибка: ' + escHtml(e.message) + '</div>';
    }
  } finally {
    _spinBtn('depsReloadBtn', false);
  }
}

// Долгий фикс ушёл в фон — ждём его, показывая, сколько уже прошло.
// Возвращает {ok, msg}. Ограничение сверху — чтобы не крутить опрос вечно,
// если операция умерла вместе с процессом.
async function _pollDepFix(id, res, startedAt, hint, limitMs) {
  // Сборка модуля ядра идёт минутами — для таких операций лимит задаёт вызывающий.
  const LIMIT_MS = limitMs || 5 * 60 * 1000;
  while (Date.now() - startedAt < LIMIT_MS) {
    await new Promise(r => setTimeout(r, 2000));
    let job = null;
    try {
      const r = await fetch(API + '/api/system/dependencies/fix-status?id=' + encodeURIComponent(id),
                            {credentials: 'same-origin'});
      job = await r.json();
    } catch (e) {
      continue;  // панель могла на секунду перезапуститься — не считаем это провалом
    }
    if (job.steps && job.steps.length) _renderBusySteps(job.steps);
    if (job.state === 'done' || job.state === 'error') _depsBadgeSoon();
    if (job.state === 'done') return {ok: true, msg: job.msg || ''};
    if (job.state === 'error') return {ok: false, msg: job.msg || 'не удалось'};
    // Запись создаётся до ответа на запуск, поэтому 'idle' здесь означает, что
    // панель перезапустилась и потеряла задачу вместе с процессом.
    if (job.state === 'idle') {
      return {ok: false, msg: 'панель перезапустилась во время операции — нажмите «Перепроверить»'};
    }
    const sec = Math.round((Date.now() - startedAt) / 1000);
    if (res) res.textContent = `Выполняется… ${sec} с`;
    // Счётчик дублируем в затемнение: строка под кнопкой им же и закрыта.
    const ovl = document.getElementById('panelRestartStatus');
    if (ovl && hint) ovl.textContent = `${hint} · идёт ${sec} с`;
    else if (ovl) ovl.textContent = `Идёт ${sec} с`;
  }
  return {ok: false, msg: 'операция идёт дольше 5 минут — проверьте журнал сервиса'};
}
async function applyDepFix(id) {
  const res = document.getElementById('depRes_' + id);
  // Защита от двойного клика
  const btn = document.querySelector(`button[onclick="applyDepFix('${id}')"]`);
  if (btn && btn.disabled) return;
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; btn.style.cursor = 'wait'; }
  if (res) {
    res.className = 'dep-result pending';
    res.textContent = 'Выполняется…';
  }
  const dep = (_depsLastData && _depsLastData.items || []).find(x => x.id === id) || {};
  const isLong = !!dep.long;
  // Перепроверка после фикса сама управляет затемнением — тогда finally его не гасит.
  let keepOverlay = false;
  if (isLong) {
    showBusyOverlay('Настройка: ' + (dep.name || id), dep.eta_hint || 'Может занять несколько минут');
  }
  try {
    const r = await fetch(API + '/api/system/dependencies/fix', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id})
    });
    let d = await r.json();
    let ok = r.ok && d.ok;
    // Фоновая операция: HTTP-ответ приходит сразу, результат — опросом.
    // Иначе gunicorn (--timeout 30) рвёт запрос и вместо JSON прилетает
    // HTML-страница ошибки от nginx.
    if (ok && d.async) {
      // Установка AWG собирает модуль ядра — это дольше пяти минут, ждём до двадцати.
      const done = await _pollDepFix(id, res, Date.now(), dep.eta_hint || '',
                                     dep.long ? 20 * 60 * 1000 : 5 * 60 * 1000);
      d = done.ok ? {ok: true, output: done.msg} : {ok: false, error: done.msg};
      ok = done.ok;
    }
    if (ok) {
      // Обновили движок отсюда — блок версий и кнопка в ⚙ не должны показывать старую.
      if (id.endsWith('_update')) loadSystemVersions(true);
      if (d.requires_restart) {
        _depsNeedRestart = true;
        document.getElementById('depsRestartBlock').classList.remove('hidden');
      }
      if (res) {
        res.className = 'dep-result success';
        // Показываем, ЧТО именно сделал обработчик (например «сертификат
        // обновлён, срок — 89 дн.»): «Успешно применено» не даёт понять,
        // сработало ли по делу.
        const detail = (d.output || '').trim();
        res.textContent = (detail || 'Успешно применено')
          + (d.requires_restart ? ' — требуется перезапуск панели (см. блок ниже)' : '');
      }
      // Авто-перепроверку делаем только для фиксов, не требующих рестарта самой панели.
      // Иначе пункт мгновенно перерисуется как NOT OK (т.к. модуль/состояние не подгрузилось в текущий процесс).
      if (!d.requires_restart) {
        // Затемнение не гасим между операцией и перепроверкой: иначе экран на
        // мгновение «отпускает», хотя список ещё перерисовывается.
        keepOverlay = true;
        showBusyOverlay('Перепроверяем зависимости…', 'Сканируем сервисы и пути');
        setTimeout(async () => {
          try { await loadDeps(); } finally { hideBusyOverlay(); }
        }, 600);
      }
    } else {
      if (res) {
        res.className = 'dep-result error';
        res.textContent = 'Ошибка: ' + (d.error || 'см. вывод') + (d.output ? '\n' + d.output : '');
      }
    }
  } catch (e) {
    if (res) {
      res.className = 'dep-result error';
      res.textContent = 'Ошибка сети: ' + e.message;
    }
  } finally {
    if (btn) { btn.disabled = false; btn.style.opacity = ''; btn.style.cursor = ''; }
    if (isLong && !keepOverlay) hideBusyOverlay();
  }
}

async function restartPanelFromDeps() {
  const ok = await openConfirm({
    title: 'Перезапустить панель?',
    body: 'Панель перезапустится сейчас. Страница обновится автоматически.',
    okLabel: 'Перезапустить',
  });
  if (!ok) return;
  closeModal('depsModal');
  showRestartOverlay();
  try { await fetch(API + '/api/restart', {method: 'POST'}); } catch (e) {}
  pingUntilAlive();
}

// === Здоровье сервера — live RAM/ЦП/диск/сеть ===
let _healthTimer = null;

function openHealthModal() {
  document.getElementById('healthModal').classList.remove('hidden');
  switchHealthTab('load');
  const cached = _readModalCache('health');
  if (cached && typeof cached === 'object') {
    _paintHealth(cached);
    loadHealth({silent: true});
  } else {
    loadHealth();
  }
  // Авто-обновление пока окно открыто
  if (_healthTimer) clearInterval(_healthTimer);
  _healthTimer = setInterval(() => {
    const m = document.getElementById('healthModal');
    if (!m || m.classList.contains('hidden')) { clearInterval(_healthTimer); _healthTimer = null; return; }
    // Автообновление — только у live-нагрузки. Фаервол и мониторинг перечитывать
    // каждые 4 секунды незачем: там ss, ufw и fail2ban-client, а данные статичны.
    if (_healthTab !== 'load') return;
    loadHealth({silent: true});
  }, 4000);
}

let _healthTab = 'load';

function switchHealthTab(kind) {
  if (!['load', 'fw', 'mon'].includes(kind)) kind = 'load';
  _healthTab = kind;
  const map = {load: ['healthTabLoad', 'healthPaneLoad'],
               fw:   ['healthTabFw',   'healthPaneFw'],
               mon:  ['healthTabMon',  'healthPaneMon']};
  for (const [k, [tabId, paneId]] of Object.entries(map)) {
    const tab = document.getElementById(tabId), pane = document.getElementById(paneId);
    if (tab) tab.classList.toggle('active', k === kind);
    if (pane) pane.classList.toggle('hidden', k !== kind);
  }
  // Кнопка «Обновить» перезагружает только live-нагрузку; у фаервола своя.
  const btn = document.getElementById('healthReloadBtn');
  if (btn) btn.classList.toggle('hidden', kind !== 'load');
  if (kind === 'mon') loadProbeInfo();
  if (kind === 'fw') loadFirewall();
}

// ============================================================
// Фаервол и fail2ban
// ============================================================
let _fwData = null;
// Какие jail'ы раскрыты по забаненным адресам. Список бывает на сотни строк и
// закрывает собой всё остальное, поэтому по умолчанию свёрнут; состояние живёт
// вне разметки, чтобы перерисовка после разбана не захлопывала список обратно.
const _fwOpenBans = new Set();

function fwToggleBans(jail) {
  const box = document.getElementById('fwBans_' + jail);
  if (!box) return;
  if (box.classList.toggle('is-open')) _fwOpenBans.add(jail);
  else _fwOpenBans.delete(jail);
}

async function loadFirewall(opts) {
  opts = opts || {};
  const box = document.getElementById('firewallBody');
  if (!box) return;
  if (!opts.silent && !box.hasChildNodes()) box.innerHTML = '<div style="color:var(--text3);">…</div>';
  try {
    const r = await fetch(API + '/api/system/firewall', {credentials: 'same-origin'});
    if (!r.ok) { box.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>'; return; }
    _fwData = await r.json();
    _paintFirewall();
  } catch (e) {
    if (!box.hasChildNodes()) box.innerHTML = '<div style="color:var(--red);">Сеть: ' + escHtml(e.message) + '</div>';
  }
}

// Ввод портов: только цифры, диапазон через «-». Запятая — частая опечатка
// вместо дефиса на цифровой клавиатуре телефона, молча её исправляем.
function _fwSanitizePort(inp) {
  let v = (inp.value || '').replace(/[,;.]/g, '-').replace(/[^\d-]/g, '');
  v = v.replace(/-{2,}/g, '-');
  const parts = v.split('-');
  if (parts.length > 2) v = parts[0] + '-' + parts[1];
  inp.value = v.slice(0, 11);
}

// Счётчик попыток — только цифры: диапазон здесь бессмыслен, а маска порта
// пропускала дефис, и «5-3» доезжало до бэкенда только чтобы там отлупиться.
function _fwDigitsOnly(inp, max) {
  inp.value = (inp.value || '').replace(/\D/g, '').slice(0, max || 6);
}

// Ввод IP: цифры, точки и «/» для маски. Точка ставится сама после третьей
// цифры октета — набирать 203.0.113.10 на телефоне иначе мучительно.
function _fwSanitizeIp(inp) {
  const raw = inp.value || '';
  const atEnd = inp.selectionStart === raw.length;
  let v = raw.replace(/,/g, '.').replace(/[^0-9a-fA-F:./]/g, '');
  // IPv6 разбирать нечем: там и hex, и двойные двоеточия — только чистим мусор.
  if (v.includes(':')) { inp.value = v.slice(0, 45); return; }
  // Точки подряд схлопываем: после авто-точки поле уже «203.», и привычно
  // набранная своя точка давала «203..» — дальше пустой октет съедал слот в
  // slice(0,4), и последний октет молча терялся.
  v = v.replace(/[^0-9./]/g, '').replace(/\.{2,}/g, '.');
  // «/» имеет смысл, только если в ИСХОДНОЙ строке перед ним стояла цифра.
  // Иначе вставка мусора («203.0.113.10; rm -rf /») оставляла бы висящий слэш:
  // выброшенные символы склеили бы далёкие куски строки в подобие маски.
  const slashAt = raw.indexOf('/');
  const keepSlash = slashAt > 0 && /\d/.test(raw.charAt(slashAt - 1));
  const [addr, mask] = v.split('/');
  const parts = addr.split('.');
  // Хвостовая точка — это состояние «октет закончен, следующий ещё не начат»,
  // её надо сохранить; пустые октеты в середине слот занимать не должны.
  const trailingDot = parts.length > 1 && parts[parts.length - 1] === '';
  const octets = parts.filter(o => o !== '').slice(0, 4).map(o => o.slice(0, 3));
  let out = octets.join('.');
  if (trailingDot && octets.length < 4) out += '.';
  // Авто-точка: последний октет добит до трёх цифр и он ещё не четвёртый.
  if (atEnd && !out.endsWith('.') && octets.length < 4 &&
      /^\d{3}$/.test(octets[octets.length - 1] || '')) out += '.';
  if (keepSlash && mask !== undefined) out += '/' + mask.replace(/\D/g, '').slice(0, 2);
  inp.value = out.slice(0, 43);
}

function _fwValidIp(v) {
  v = (v || '').trim();
  if (!v) return false;
  if (v.includes(':')) return /^[0-9A-Fa-f:]{2,45}(\/\d{1,3})?$/.test(v);
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(v);
  if (!m) return false;
  if (m.slice(1, 5).some(o => +o > 255)) return false;
  return !(m[5] !== undefined && +m[5] > 32);
}

function _fwValidPort(v) {
  v = (v || '').trim().replace('-', ':');
  if (/^\d+$/.test(v)) return +v >= 1 && +v <= 65535;
  const m = /^(\d+):(\d+)$/.exec(v);
  return !!m && +m[1] >= 1 && +m[1] <= +m[2] && +m[2] <= 65535;
}

function _fwErr(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg || '';
}

function _paintFirewall() {
  const box = document.getElementById('firewallBody');
  const d = _fwData || {};
  const ufw = d.ufw || {};
  const known = d.known_ports || {};
  const f2b = d.fail2ban || {};

  // --- ufw ---
  let ufwHtml;
  if (!ufw.installed) {
    ufwHtml = '<div class="psvc-note">ufw на сервере не установлен — панель не может ни показать, ни изменить ' +
      'правила фаервола. Если фаервол ведётся через iptables/nftables напрямую, правьте его по ssh.</div>';
  } else if (!ufw.active) {
    ufwHtml = '<div class="psvc-note" style="border-color:var(--orange);"><b>ufw выключен.</b> Все порты сервера ' +
      'открыты наружу, включая те, что слушают только для себя. Включается командой <code>ufw enable</code> — ' +
      'из панели намеренно не делаем: без правила на SSH это отрежет доступ к серверу.</div>';
  } else {
    const rules = (ufw.rules || []).map(r => {
      const portNum = (r.to.match(/^(\d+)/) || [])[1];
      const own = portNum && known[portNum];
      const deny = /DENY|REJECT/i.test(r.action);
      return `<div class="fw-item">
        <span class="fw-port">${escHtml(r.to)}</span>
        <span class="fw-meta">${escHtml(r.action)} · от ${escHtml(r.from)}${r.comment ? ' · ' + escHtml(r.comment) : ''}</span>
        ${own ? `<span class="fw-tag own">${escHtml(own)}</span>` : ''}
        ${deny ? '<span class="fw-tag deny">блокировка</span>' : ''}
        <span class="fw-spacer"></span>
        <button class="btn btn-sm btn-ghost" onclick="fwDeleteRule(${r.num})"
          title="${own ? 'Порт занят протоколом «' + escAttr(own) + '» — после удаления правила клиенты потеряют связь' : 'Удалить правило'}">Удалить</button>
      </div>`;
    }).join('') || '<div class="psvc-note">Правил нет — ufw активен с политикой по умолчанию.</div>';
    ufwHtml = `
      <div class="psvc-note" style="margin-bottom:10px;">Политика входящих: <b>${escHtml(ufw.default_incoming || '—')}</b>.
        Правила пронумерованы так же, как их печатает <code>ufw status numbered</code>.</div>
      <div class="fw-list">${rules}</div>
      <div class="fw-form">
        <input class="fw-inp fw-inp-port" id="fwPort" placeholder="порт или 20000-20100" inputmode="numeric"
               oninput="_fwSanitizePort(this)" autocomplete="off" spellcheck="false">
        <select class="fw-sel" id="fwProto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">TCP+UDP</option></select>
        <select class="fw-sel" id="fwAction"><option value="allow">Разрешить</option><option value="deny">Запретить</option></select>
        <input class="fw-inp fw-inp-ip" id="fwFrom" placeholder="источник (пусто = откуда угодно)"
               inputmode="numeric" oninput="_fwSanitizeIp(this)" autocomplete="off" spellcheck="false">
        <input class="fw-inp fw-inp-note" id="fwComment" placeholder="комментарий" maxlength="60" autocomplete="off">
        <button class="btn btn-sm btn-success" onclick="fwAddRule()">Добавить правило</button>
        <div class="fw-err" id="fwRuleErr"></div>
      </div>`;
  }

  // --- слушающие порты ---
  const listen = (d.listening || []).reduce((acc, p) => {
    const key = p.proto + ':' + p.port + ':' + (p.process || '');
    if (!acc.seen.has(key)) { acc.seen.add(key); acc.rows.push(p); }
    return acc;
  }, {seen: new Set(), rows: []}).rows;
  const listenHtml = listen.length ? listen.map(p => `
    <div class="fw-item">
      <span class="fw-port">${escHtml(p.proto.toUpperCase())} ${escHtml(String(p.port))}</span>
      <span class="fw-meta">${escHtml(p.process || 'процесс не определён')}</span>
      ${known[String(p.port)] ? `<span class="fw-tag own">${escHtml(known[String(p.port)])}</span>` : ''}
    </div>`).join('') : '<div class="psvc-note">Не удалось прочитать список — нет утилиты ss?</div>';

  // --- fail2ban ---
  let f2bHtml;
  if (!f2b.installed) {
    f2bHtml = '<div class="psvc-note">fail2ban не установлен. Он банит IP за перебор паролей (в первую очередь по ' +
      'SSH). Ставится командой <code>apt install fail2ban</code> — из панели не ставим, чтобы не подсунуть серверу ' +
      'чужую политику блокировок.</div>';
  } else if (!f2b.active) {
    f2bHtml = `<div class="psvc-note" style="border-color:var(--orange);"><b>fail2ban установлен, но не запущен</b> —
      подборы паролей никто не блокирует.</div>
      <div class="fw-form"><button class="btn btn-sm btn-success" onclick="fwF2b('restart')">Запустить fail2ban</button></div>`;
  } else {
    const jails = (f2b.jails || []).map(j => `
      <div class="fw-jail">
        <div class="fw-jail-h">
          <span class="fw-jail-n">${escHtml(j.name)}</span>
          <span class="fw-jail-s">забанено сейчас: ${j.currently_banned} · всего: ${j.total_banned} ·
            неудачных попыток: ${j.currently_failed}/${j.total_failed}</span>
        </div>
        <div class="fw-jail-s">порог ${escHtml(j.maxretry || '—')} попыток за ${escHtml(j.findtime || '—')} с,
          бан на ${escHtml(j.bantime || '—')} с${j.files ? ' · лог: ' + escHtml(j.files) : ''}</div>
        <div class="fw-form">
          <input class="fw-inp fw-inp-port" id="fwRetry_${escAttr(j.name)}" value="${escAttr(j.maxretry || '')}"
                 placeholder="попыток" inputmode="numeric" oninput="_fwDigitsOnly(this, 4)">
          <input class="fw-inp fw-inp-port" id="fwFind_${escAttr(j.name)}" value="${escAttr(j.findtime || '')}"
                 placeholder="окно, сек">
          <input class="fw-inp fw-inp-port" id="fwBan_${escAttr(j.name)}" value="${escAttr(j.bantime || '')}"
                 placeholder="бан, сек">
          <button class="btn btn-sm btn-ghost" onclick="fwSaveJail('${escAttr(j.name)}')">Сохранить</button>
          <div class="fw-err" id="fwJailErr_${escAttr(j.name)}"></div>
        </div>
        ${j.banned.length ? `<div class="fw-bans${_fwOpenBans.has(j.name) ? ' is-open' : ''}" id="fwBans_${escAttr(j.name)}">
          <button class="fw-bans-t" onclick="fwToggleBans('${escAttr(j.name)}')">
            <svg class="fw-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"
                 stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"/></svg>
            Забаненные адреса: ${j.banned.length}</button>
          <div class="fw-bans-b">
            <div class="fw-jail-s">Клик по ✕ разбанит.</div>
            <div class="fw-ips">${j.banned.map(ip =>
              `<span class="fw-ip">${escHtml(ip)}<button title="Разбанить"
                 onclick="fwF2b('unban','${escAttr(j.name)}','${escAttr(ip)}')">✕</button></span>`).join('')}</div>
          </div>
        </div>`
          : '<div class="fw-jail-s" style="margin-top:8px;">Забаненных адресов нет.</div>'}
        <div class="fw-form">
          <input class="fw-inp fw-inp-ip" id="fwBanIp_${escAttr(j.name)}" placeholder="забанить IP вручную"
                 inputmode="numeric" oninput="_fwSanitizeIp(this)" autocomplete="off" spellcheck="false">
          <button class="btn btn-sm btn-ghost" onclick="fwBanManual('${escAttr(j.name)}')">Забанить</button>
        </div>
      </div>`).join('') || '<div class="psvc-note">Ни один jail не включён — fail2ban запущен, но ничего не сторожит.</div>';

    const ign = ((f2b.jails || [])[0] || {}).ignoreip || [];
    f2bHtml = `${jails}
      <div class="fw-sec" style="margin-top:14px;">
        <div class="fw-sec-h"><span>Исключения (никогда не банить)</span></div>
        <div class="psvc-note" style="margin-bottom:8px;">Действуют на все jail'ы. Впишите сюда свой домашний адрес,
          прежде чем экспериментировать с настройками бана — иначе fail2ban отрежет вас от собственного сервера.</div>
        <div class="fw-ips">${ign.length ? ign.map(ip =>
          `<span class="fw-ip">${escHtml(ip)}<button title="Убрать из исключений"
             onclick="fwF2b('ignore_remove',null,'${escAttr(ip)}')">✕</button></span>`).join('')
          : '<span class="fw-jail-s">пусто</span>'}</div>
        <div class="fw-form">
          <input class="fw-inp fw-inp-ip" id="fwIgnIp" placeholder="203.0.113.10 или 203.0.113.0/24"
                 inputmode="numeric" oninput="_fwSanitizeIp(this)" autocomplete="off" spellcheck="false">
          <button class="btn btn-sm btn-success" onclick="fwAddIgnore()">Добавить исключение</button>
          <div class="fw-err" id="fwIgnErr"></div>
        </div>
      </div>`;
  }

  box.innerHTML = `
    <div class="fw-sec">
      <div class="fw-sec-h"><span>Открытые порты (ufw)</span>
        <button class="btn btn-sm btn-ghost" onclick="loadFirewall()">Перепроверить</button></div>
      ${ufwHtml}
    </div>
    <div class="fw-sec">
      <div class="fw-sec-h"><span>Кто слушает порты на сервере</span></div>
      <div class="psvc-note" style="margin-bottom:8px;">Выше — что разрешено фаерволом, здесь — что реально
        слушает сокеты. Порт, открытый в ufw, но никем не занятый, снаружи всё равно молчит.</div>
      <div class="fw-list">${listenHtml}</div>
    </div>
    <div class="fw-sec">
      <div class="fw-sec-h"><span>Блокировки (fail2ban)</span></div>
      ${f2bHtml}
    </div>`;
}

async function _fwPost(url, body) {
  const r = await fetch(API + url, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
  });
  return await r.json().catch(() => ({ok: false, error: 'HTTP ' + r.status}));
}

async function fwAddRule() {
  const port = (document.getElementById('fwPort').value || '').trim();
  const from = (document.getElementById('fwFrom').value || '').trim();
  if (!_fwValidPort(port)) { _fwErr('fwRuleErr', 'Порт: число 1–65535 или диапазон, например 20000-20100'); return; }
  if (from && !_fwValidIp(from)) { _fwErr('fwRuleErr', 'Источник: IP или подсеть, например 203.0.113.10 или 203.0.113.0/24'); return; }
  _fwErr('fwRuleErr', '');
  const j = await _fwPost('/api/system/firewall/rule', {
    action: document.getElementById('fwAction').value,
    port, proto: document.getElementById('fwProto').value, from,
    comment: (document.getElementById('fwComment').value || '').trim() || 'awg-panel',
  });
  if (!j.ok) { _fwErr('fwRuleErr', j.error || 'Не удалось'); return; }
  toast('Правило добавлено');
  loadFirewall();
}

async function fwDeleteRule(num) {
  const ok = await openConfirm({
    title: 'Удалить правило фаервола?',
    body: 'Если этот порт нужен работающему протоколу, его клиенты потеряют связь сразу же. ' +
          'Проверьте отметку протокола рядом с правилом.',
    okLabel: 'Удалить', danger: true,
  });
  if (!ok) return;
  const j = await _fwPost('/api/system/firewall/rule', {action: 'delete', num});
  toast(j.ok ? 'Правило удалено' : (j.error || 'Не удалось'));
  loadFirewall();
}

async function fwF2b(action, jail, ip) {
  const j = await _fwPost('/api/system/fail2ban/action', {action, jail, ip});
  if (!j.ok) { toast(j.error || 'Не удалось'); return; }
  const words = {unban: 'Разбанен', ban: 'Забанен', ignore_remove: 'Исключение убрано',
                 ignore_add: 'Исключение добавлено', restart: 'fail2ban перезапущен'};
  toast(words[action] || 'Готово');
  loadFirewall();
}

async function fwAddIgnore() {
  const ip = (document.getElementById('fwIgnIp').value || '').trim();
  if (!_fwValidIp(ip)) { _fwErr('fwIgnErr', 'Нужен IP или подсеть, например 203.0.113.10 или 203.0.113.0/24'); return; }
  _fwErr('fwIgnErr', '');
  await fwF2b('ignore_add', null, ip);
}

async function fwBanManual(jail) {
  const el = document.getElementById('fwBanIp_' + jail);
  const ip = (el && el.value || '').trim();
  if (!_fwValidIp(ip)) { toast('Нужен корректный IP или подсеть'); return; }
  await fwF2b('ban', jail, ip);
}

async function fwSaveJail(jail) {
  const val = id => ((document.getElementById(id + '_' + jail) || {}).value || '').trim();
  const maxretry = val('fwRetry'), findtime = val('fwFind'), bantime = val('fwBan');
  // Время принимает суффикс (10m), счётчик попыток — только целое: ровно так
  // же это проверяет бэкенд, чтобы ошибка не всплывала уже после отправки.
  const okTime = v => v === '' || /^\d+[smhdw]?$/.test(v);
  if (!okTime(findtime) || !okTime(bantime)) {
    _fwErr('fwJailErr_' + jail, 'Время: число секунд или с суффиксом m/h/d, например 600 или 10m');
    return;
  }
  if (!(maxretry === '' || /^\d{1,4}$/.test(maxretry))) {
    _fwErr('fwJailErr_' + jail, 'Попыток: целое число от 1 до 9999');
    return;
  }
  _fwErr('fwJailErr_' + jail, '');
  const j = await _fwPost('/api/system/fail2ban/action', {action: 'set_params', jail, maxretry, findtime, bantime});
  if (!j.ok) { _fwErr('fwJailErr_' + jail, j.error || 'Не удалось'); return; }
  toast('Настройки jail ' + jail + ' сохранены');
  loadFirewall();
}

function _paintHealth(h) {
  const box = document.getElementById('healthBody');
  if (box) box.innerHTML = renderHealth(h);
}

async function loadHealth(opts) {
  opts = opts || {};
  const box = document.getElementById('healthBody');
  if (!opts.silent && box && !box.hasChildNodes()) {
    box.innerHTML = '<div style="color:var(--text3);">…</div>';
  }
  if (!opts.silent) _spinBtn('healthReloadBtn', true, 'Обновляем…');
  try {
    const r = await fetch(API + '/api/system/health', {credentials: 'same-origin'});
    if (!r.ok) {
      if (!opts.silent && box) box.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>';
      return;
    }
    const h = await r.json();
    _writeModalCache('health', h);
    _paintHealth(h);
  } catch (e) {
    if (!opts.silent && box && !box.hasChildNodes()) {
      box.innerHTML = '<div style="color:var(--red);">Сеть: ' + escHtml(e.message) + '</div>';
    }
  } finally {
    _spinBtn('healthReloadBtn', false);
  }
}

// === Вкладка «Мониторинг» ===================================================
// Показывает реквизиты, которые надо перенести в утилиту мониторинга на другом
// сервере, и краткую инструкцию по её установке. Подробности — в УСТАНОВКА.md
// внутри архива.

let _probeInfo = null;
let _probeRotateArmed = false;

async function loadProbeInfo() {
  const box = document.getElementById('monitorBody');
  if (!box) return;
  if (!box.hasChildNodes()) box.innerHTML = '<div style="color:var(--text3);">…</div>';
  try {
    const r = await fetch(API + '/api/probe/info', {credentials: 'same-origin'});
    if (!r.ok) {
      box.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>';
      return;
    }
    _probeInfo = await r.json();
    _paintProbeInfo();
  } catch (e) {
    box.innerHTML = '<div style="color:var(--red);">Сеть: ' + escHtml(e.message) + '</div>';
  }
}

function _probeRow(label, value, hint, copyIdx) {
  const btn = copyIdx == null ? '' :
    '<button class="btn btn-sm btn-ghost" data-copy="' + copyIdx + '" style="flex:0 0 auto;">Копировать</button>';
  return '<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-top:1px solid var(--border);">' +
    '<div style="flex:0 0 150px;color:var(--text3);font-size:12px;">' + escHtml(label) + '</div>' +
    '<div style="flex:1 1 auto;min-width:0;font-family:JetBrains Mono,monospace;font-size:13px;' +
      'word-break:break-all;user-select:all;">' + escHtml(value) +
      (hint ? '<div style="font-family:inherit;font-size:11px;color:var(--text3);margin-top:2px;">' +
              escHtml(hint) + '</div>' : '') +
    '</div>' + btn + '</div>';
}

function _paintProbeInfo() {
  const box = document.getElementById('monitorBody');
  const i = _probeInfo || {};
  if (!box) return;

  const port = i.port || 0;
  const portTxt = port ? String(port) : 'не опубликован';
  const scheme = i.use_https ? 'https' : 'http';
  // то, что копируется по кнопкам — держим в массиве, а не в атрибутах:
  // escHtml не экранирует кавычки, inline-строка в data-* сломала бы разметку
  const copy = [
    i.host || '',
    String(port || ''),
    i.token || '',
    'Название: ' + (i.name || '—') +
      '\nАдрес панели: ' + (i.host || '') +
      '\nПорт панели: ' + portTxt +
      '\nТокен мониторинга: ' + (i.token || '') +
      '\nHTTPS: ' + (i.use_https ? 'да' : 'нет'),
  ];

  const warn = i.warning
    ? '<div style="background:var(--bg);border:1px solid var(--red);border-radius:8px;' +
      'padding:11px 13px;margin-bottom:14px;font-size:12px;color:var(--red);line-height:1.5;">' +
      escHtml(i.warning) + '</div>'
    : '';

  const creds =
    '<div style="font-size:13px;font-weight:600;margin-bottom:2px;">Реквизиты этого сервера</div>' +
    '<div style="color:var(--text3);font-size:12px;margin-bottom:6px;">' +
      'Эти четыре значения вводятся в админке мониторинга при добавлении сервера. ' +
      'Порты XRay и MTProto вводить не нужно — мониторинг забирает их сам.</div>' +
    _probeRow('Название', i.name || '—', '', null) +
    _probeRow('Адрес панели', i.host || '—', 'домен надёжнее IP: адрес улетает в блок первым', 0) +
    _probeRow('Порт панели', portTxt, port ? scheme.toUpperCase() : 'включите доступ по отдельному порту', 1) +
    _probeRow('Токен мониторинга', i.token || '—', 'общий секрет, даёт только чтение портов и скачивание нулей', 2) +
    '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">' +
      '<button class="btn btn-sm" data-copy="3">Скопировать реквизиты</button>' +
      '<button class="btn btn-sm btn-ghost" id="monRotateBtn">Перевыпустить токен</button>' +
    '</div>';

  const seen =
    '<div style="font-size:13px;font-weight:600;margin:22px 0 2px;">Что увидит мониторинг</div>' +
    '<div style="color:var(--text3);font-size:12px;margin-bottom:6px;">' +
      'Живые значения с этого сервера — они отдаются по запросу и обновляются сами.</div>' +
    _probeRow('Порт XRay', i.xray_port ? String(i.xray_port) : '—', '', null) +
    _probeRow('Порт MTProto', i.mtg_port ? String(i.mtg_port) : '—', '', null) +
    _probeRow('Порт Hysteria', i.hysteria_port ? String(i.hysteria_port) : '—', i.hysteria_port ? 'UDP' : '', null) +
    _probeRow('Telegram WEB', i.tgweb_port ? 'страница моста на ' + i.tgweb_port : '—',
      i.tgweb_port ? 'проверяется ответ telemt, а не открытый порт' : '', null) +
    _probeRow('Режим инбаунда', i.security || '—', '', null);

  const zip = i.zip_url || 'https://byfox.dev/data/awg-panel/monitoring.zip';
  const how =
    '<div style="font-size:13px;font-weight:600;margin:22px 0 2px;">Как поднять мониторинг</div>' +
    '<div style="color:var(--text3);font-size:12px;line-height:1.55;margin-bottom:8px;">' +
      'Утилита ставится один раз на отдельный сервер — тот, откуда надо видеть эти серверы, ' +
      'обычно в России. Все серверы добавляются в неё одной установкой, подробная инструкция ' +
      'лежит внутри архива.</div>' +
    '<div style="margin-bottom:10px;"><button class="btn btn-sm" id="monZipBtn">' +
      'Скачать monitoring.zip</button></div>' +
    renderCodeBlock([
      '# 1. поставить на сервер мониторинга',
      'apt update && apt install -y python3-venv unzip curl',
      'mkdir -p /opt/monitoring && cd /opt/monitoring',
      'curl -fL ' + zip + ' -o monitoring.zip',
      'unzip -o monitoring.zip && rm monitoring.zip',
      'python3 -m venv venv && ./venv/bin/pip install flask gunicorn',
      '',
      '# 2. запустить',
      'cp /opt/monitoring/monitoring.service /etc/systemd/system/',
      'systemctl daemon-reload && systemctl enable --now monitoring',
    ]) +
    '<div style="color:var(--text3);font-size:12px;line-height:1.55;margin-top:8px;">' +
      'Сервис слушает только локальный адрес, наружу его отдаёт nginx — готовый блок ' +
      'location есть в инструкции внутри архива. Пароль админки нигде не прописывается: ' +
      'он задаётся в браузере при первом открытии админки и хранится отдельно от кода, ' +
      'поэтому обновление его не сбрасывает. Дальше добавьте там сервер с реквизитами ' +
      'выше и нажмите «Связь»: утилита прогонит полную проверку и покажет, на каком шаге ' +
      'что не так.</div>' +
    _probeRow('Админка мониторинга', '/status/admin.html', '', null) +
    _probeRow('Публичная страница', '/status/', '', null);

  box.innerHTML = warn + creds + seen + how;

  box.querySelectorAll('button[data-copy]').forEach(b => {
    b.addEventListener('click', () => {
      const txt = copy[+b.dataset.copy] || '';
      if (!txt) { toast('Нечего копировать'); return; }
      navigator.clipboard.writeText(txt).then(() => toast('Скопировано'));
    });
  });

  const zipBtn = document.getElementById('monZipBtn');
  if (zipBtn) zipBtn.addEventListener('click', () => window.open(zip, '_blank', 'noopener'));

  const rot = document.getElementById('monRotateBtn');
  if (rot) {
    _probeRotateArmed = false;
    rot.addEventListener('click', async () => {
      // два шага вместо confirm(): первый клик взводит, второй выполняет
      if (!_probeRotateArmed) {
        _probeRotateArmed = true;
        rot.textContent = 'Точно? Старый токен перестанет работать';
        rot.style.color = 'var(--red)';
        setTimeout(() => {
          if (!_probeRotateArmed) return;
          _probeRotateArmed = false;
          rot.textContent = 'Перевыпустить токен';
          rot.style.color = '';
        }, 5000);
        return;
      }
      _probeRotateArmed = false;
      _spinBtn('monRotateBtn', true, 'Меняем…');
      try {
        const r = await fetch(API + '/api/probe/rotate', {method: 'POST', credentials: 'same-origin'});
        if (!r.ok) { toast('Не удалось сменить токен'); return; }
        toast('Токен перевыпущен — пропишите новый в мониторинге');
        await loadProbeInfo();
      } finally {
        _spinBtn('monRotateBtn', false);
      }
    });
  }
}

function _hBarColor(pct) {
  if (pct == null) return 'var(--text3)';
  if (pct >= 90) return 'var(--red)';
  if (pct >= 75) return '#e0a800';
  return 'var(--accent)';
}

function _hBar(pct) {
  const p = (pct == null) ? 0 : Math.max(0, Math.min(100, pct));
  const label = (pct == null) ? '—' : pct + '%';
  return `<div class="health-bar"><div class="health-bar-fill" style="width:${p}%;background:${_hBarColor(pct)};"></div><span class="health-bar-label">${label}</span></div>`;
}

function _hUptime(sec) {
  if (sec == null) return '—';
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400);
  const hh = Math.floor((sec % 86400) / 3600);
  const mm = Math.floor((sec % 3600) / 60);
  const en = _i18nEn();
  const parts = [];
  if (d) parts.push(d + (en ? 'd' : 'д'));
  if (hh || d) parts.push(hh + (en ? 'h' : 'ч'));
  parts.push(mm + (en ? 'm' : 'м'));
  return parts.join(' ');
}

function _hRate(bps) {
  return formatBytesShort(bps) + '/с';
}

function renderHealth(h) {
  if (!h || h.ok === false) {
    return '<div style="color:var(--red);">' + escHtml((h && h.error) || 'нет данных') + '</div>';
  }
  const mem = h.mem || {};
  const swap = h.swap || {};
  const cpu = h.cpu || {};
  const net = h.net || {};
  const disks = h.disks || [];

  // CPU
  const cpuMeta = [];
  const _en = _i18nEn();
  if (cpu.cores) cpuMeta.push(cpu.cores + (_en ? ' cores' : ' ядер'));
  if (cpu.freq_mhz) cpuMeta.push((cpu.freq_mhz >= 1000 ? (cpu.freq_mhz/1000).toFixed(2) + (_en ? ' GHz' : ' ГГц') : cpu.freq_mhz + (_en ? ' MHz' : ' МГц')));
  if (cpu.temp_c != null) cpuMeta.push(cpu.temp_c + ' °C');
  if (cpu.load) cpuMeta.push('load ' + cpu.load.join(' / '));
  const perCore = (cpu.per_core && cpu.per_core.length)
    ? `<div class="health-cores">${cpu.per_core.map((p,i) =>
        `<div class="health-core" title="ядро ${i}: ${p}%"><div class="health-core-fill" style="height:${Math.max(2,p)}%;background:${_hBarColor(p)};"></div></div>`
      ).join('')}</div>`
    : '';
  const cpuModel = cpu.model ? `<div class="health-sub">${escHtml(cpu.model)}</div>` : '';

  // Сеть
  const netRows = (net.interfaces || []).map(i => {
    const _gb = _i18nEn() ? ' Gbit/s' : ' Гбит/с', _mb = _i18nEn() ? ' Mbit/s' : ' Мбит/с';
    const spd = i.speed_mbps ? `<span class="health-pill">${i.speed_mbps >= 1000 ? (i.speed_mbps/1000)+_gb : i.speed_mbps+_mb}</span>` : '';
    return `<div class="health-net-row">
      <div class="health-net-name">${escHtml(i.iface)} ${spd}</div>
      <div class="health-net-rates">
        <span title="входящий поток">↓ ${escHtml(_hRate(i.rx_rate))}</span>
        <span title="исходящий поток">↑ ${escHtml(_hRate(i.tx_rate))}</span>
      </div>
      <div class="health-sub">всего: ↓ ${escHtml(formatBytesShort(i.rx_bytes))} &middot; ↑ ${escHtml(formatBytesShort(i.tx_bytes))}</div>
    </div>`;
  }).join('') || '<div class="health-sub">нет интерфейсов</div>';

  // Диски
  const diskRows = disks.map(d => `
    <div class="health-disk">
      <div class="health-disk-head">
        <span class="health-disk-mount">${escHtml(d.mount)}</span>
        <span class="health-sub">${escHtml(d.fstype)} &middot; ${escHtml(formatBytesShort(d.used))} / ${escHtml(formatBytesShort(d.total))} &middot; свободно ${escHtml(formatBytesShort(d.free))}</span>
      </div>
      ${_hBar(d.percent)}
    </div>`).join('') || '<div class="health-sub">диски не найдены</div>';

  return `
    <div class="health-grid">
      <div class="health-card">
        <div class="health-card-title">ОЗУ</div>
        ${_hBar(mem.percent)}
        <div class="health-sub">занято ${escHtml(formatBytesShort(mem.used))} из ${escHtml(formatBytesShort(mem.total))}</div>
        <div class="health-sub">доступно ${escHtml(formatBytesShort(mem.available))}${mem.cached ? ' &middot; кеш ' + escHtml(formatBytesShort(mem.cached)) : ''}</div>
        ${swap.total ? `<div class="health-sub" style="margin-top:8px;">Swap: ${escHtml(formatBytesShort(swap.used))} / ${escHtml(formatBytesShort(swap.total))} (${swap.percent}%)</div>` : ''}
      </div>

      <div class="health-card">
        <div class="health-card-title">Процессор</div>
        ${_hBar(cpu.usage_pct)}
        ${cpu.load_pct != null ? `<div class="health-sub">нагрузка по load: ${cpu.load_pct}%</div>` : ''}
        ${cpuMeta.length ? `<div class="health-sub">${cpuMeta.map(escHtml).join(' &middot; ')}</div>` : ''}
        ${perCore}
        ${cpuModel}
      </div>

      <div class="health-card">
        <div class="health-card-title">Сеть</div>
        <div class="health-net-total">
          <span>↓ ${escHtml(_hRate(net.total_rx_rate || 0))}</span>
          <span>↑ ${escHtml(_hRate(net.total_tx_rate || 0))}</span>
        </div>
        ${netRows}
      </div>

      <div class="health-card">
        <div class="health-card-title">Диски</div>
        ${diskRows}
      </div>
    </div>
    <div class="health-footer">
      Аптайм: ${escHtml(_hUptime(h.uptime_sec))}${h.proc_count != null ? ' &middot; процессов: ' + h.proc_count : ''}
    </div>`;
}

function openDepsModal() {
  document.getElementById('depsModal').classList.remove('hidden');
  const cached = _readModalCache('deps');
  if (cached && Array.isArray(cached.items)) {
    _paintDeps(cached);
    loadDeps({silent: true});
  } else {
    loadDeps();
  }
}

// === Truths window — single source of truth for everything panel reads ===
function openTruthsModal() {
  document.getElementById('truthsModal').classList.remove('hidden');
  const cached = _readModalCache('truths');
  if (cached && typeof cached === 'object') {
    _paintTruths(cached);
    loadTruths({silent: true});
  } else {
    loadTruths();
  }
}

let _truthsTab = 'panel';
let _truthsData = null;

function switchTruthsTab(key) {
  _truthsTab = key;
  if (_truthsData) _paintTruths(_truthsData);
}

function _paintTruths(t) {
  const list = document.getElementById('truthsList');
  if (!list) return;
  _truthsData = t;
  // Вкладка протокола показывается, только если он на сервере вообще есть:
  const present = new Set(['panel']);
  if ((t.awg || {}).port != null) present.add('awg');
  if ((t.xray || {}).port != null) present.add('xray');
  if ((t.mtg || {}).port != null) present.add('mtg');
  // Hysteria отдаёт блок, только когда её пакет подключён к панели — иначе
  // пустой раздел «Hysteria» на сервере без неё был бы лишним шумом.
  if ((t.hysteria || {}).port != null) present.add('hysteria');
  if ((t.tgweb || {}).installed) present.add('tgweb');
  if (!present.has(_truthsTab)) _truthsTab = 'panel';
  _paintProtoTabs('truthsTabs', present, _truthsTab, 'switchTruthsTab');
  list.innerHTML = renderTruths(t);
  list.querySelectorAll('button[data-pick-ip]').forEach(b => {
    b.addEventListener('click', () => setIpOverride(b.dataset.pickIp));
  });
  const clearBtn = document.getElementById('truthIpClearBtn');
  if (clearBtn) clearBtn.addEventListener('click', () => setIpOverride(''));

  const manualInput = document.getElementById('truthIpManualInput');
  const manualBtn = document.getElementById('truthIpManualBtn');
  const detectBtn = document.getElementById('truthIpDetectBtn');
  const applyManual = () => {
    const ip = (manualInput.value || '').trim();
    if (!isIPv4(ip)) { toast('Нужен корректный IPv4, например 203.0.113.10'); return; }
    setIpOverride(ip);
  };
  if (manualBtn) manualBtn.addEventListener('click', applyManual);
  if (manualInput) manualInput.addEventListener('keydown', e => { if (e.key === 'Enter') applyManual(); });
  if (detectBtn) detectBtn.addEventListener('click', () => detectExternalIp(detectBtn, manualInput));
}

function isIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((s || '').trim());
  return !!m && m.slice(1).every(o => o.length <= 3 && +o <= 255 && String(+o) === String(+o));
}

// Спрашивает внешний IP у api.ru.dog ЗАПРОСОМ С СЕРВЕРА (не из браузера — иначе
// вернулся бы IP админа). Ничего не сохраняет: только подставляет в поле.
async function detectExternalIp(btn, input) {
  const hint = document.getElementById('truthIpManualHint');
  btn.disabled = true;
  _spinBtn('truthIpDetectBtn', true, 'Определяем…');
  try {
    const r = await fetch(API + '/api/system/external-ip');
    const j = await r.json();
    if (!j.ok) { toast(j.error || 'Не удалось определить внешний IP'); return; }
    if (input) { input.value = j.ip; input.focus(); }
    const where = [j.city, j.country].filter(Boolean).join(', ');
    if (hint) {
      // IP и гео — отдельными нодами, чтобы предложения переводились целиком.
      const tail = j.matches_local
        ? '— он же на интерфейсе, NAT нет. Кнопка «Закрепить» зафиксирует его как override.'
        : '— на интерфейсах его нет, значит сервер за NAT. Нажмите «Закрепить», чтобы клиентские ссылки шли с ним.';
      hint.innerHTML = `<span>Внешний IP</span> <span class="tiw-ip">${escHtml(j.ip)}</span>` +
        (where ? ` <span class="tiw-ip">(${escHtml(where)})</span>` : '') +
        ` <span>${escHtml(tail)}</span>`;
    }
    toast('Внешний IP: ' + j.ip);
  } catch (e) {
    toast('Сеть: не удалось определить внешний IP');
  } finally {
    _spinBtn('truthIpDetectBtn', false);
    btn.disabled = false;
  }
}

async function loadTruths(opts) {
  opts = opts || {};
  const list = document.getElementById('truthsList');
  if (!opts.silent && !list.hasChildNodes()) {
    list.innerHTML = '<div style="color:var(--text3);">…</div>';
  }
  if (!opts.silent) _spinBtn('truthsReloadBtn', true, 'Обновляем…');
  try {
    const r = await fetch(API + '/api/system/truths', {credentials: 'same-origin'});
    if (!r.ok) {
      if (!opts.silent) list.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>';
      return;
    }
    const t = await r.json();
    _writeModalCache('truths', t);
    _paintTruths(t);
  } catch (e) {
    if (!opts.silent && !list.hasChildNodes()) {
      list.innerHTML = '<div style="color:var(--red);">Сеть: ' + escHtml(e.message) + '</div>';
    }
  } finally {
    _spinBtn('truthsReloadBtn', false);
  }
}

function renderTruthPorts(ports) {
  if (!Array.isArray(ports) || !ports.length) {
    return `<div class="truth-row"><div class="tk">—</div><div class="ts">не удалось прочитать (нет ss?)</div></div>`;
  }
  // Один порт может слушаться и по IPv4, и по IPv6 — показываем одной строкой,
  // иначе список удваивается и читать его невозможно.
  const seen = new Map();
  ports.forEach(p => {
    const key = p.proto + ':' + p.port + ':' + (p.process || '');
    if (!seen.has(key)) seen.set(key, p);
  });
  return Array.from(seen.values()).map(p => `
    <div class="truth-row">
      <div class="tk">${escHtml(p.proto.toUpperCase())} ${escHtml(String(p.port))}</div>
      <div>
        <div class="tv">${escHtml(p.process || 'процесс не определён')}</div>
        <div class="ts">${escHtml(p.addr || '')}</div>
      </div>
    </div>`).join('');
}

function renderTruths(t) {
  const s = t.server || {};
  const a = t.awg || {};
  // XRay и MTProto рисуют renderTruthsXray / renderTruthsMtg — свои разделы
  // они читают из t сами, здесь их локальные копии не нужны.
  const ifaces = (s.interfaces || []).map(iface => {
    const isCur = iface.ip === s.effective_ip;
    const badges = [];
    if (iface.is_outbound) badges.push('<span class="tir-badge live">outbound</span>');
    if (isCur) badges.push('<span class="tir-badge">текущий</span>');
    const pickBtn = isCur ? '' :
      `<button class="btn btn-sm btn-success tir-pick" data-pick-ip="${escAttr(iface.ip)}">Выбрать</button>`;
    return `<div class="truth-iface-row ${isCur?'is-current':''}">
      <span class="tir-ip">${escHtml(iface.ip)}</span>
      <span class="tir-meta">${escHtml(iface.iface)}</span>
      ${badges.join(' ')}
      ${pickBtn}
    </div>`;
  }).join('');
  const overrideRow = s.ip_override
    ? `<div class="truth-row">
        <div class="tk">Override</div>
        <div>
          <div class="tv">${escHtml(s.ip_override)}</div>
          <div class="ts">явный выбор в этом окне; переопределяет live-detect</div>
          <button id="truthIpClearBtn" class="btn btn-sm btn-ghost" style="margin-top:6px;">Сбросить (вернуться к live)</button>
        </div>
      </div>`
    : '';

  // Серый эффективный IP = клиентские ссылки не работают снаружи. Самый частый
  // случай — облако с NAT (Yandex Cloud, GCP, AWS): белый адрес висит на NAT
  // провайдера и внутри ВМ не виден, поэтому в списке интерфейсов его нет.
  // Динамический IP вынесен в отдельный <span>, чтобы соседние предложения
  // остались цельными текст-нодами и переводились по словарю (см. i18n.js).
  const privateWarn = s.effective_is_private
    ? `<div class="truth-ip-warn">
        <strong>Серый IP в клиентских ссылках.</strong>
        <span class="tiw-ip">${escHtml(s.effective_ip || '')}</span>
        <span>— адрес из приватного диапазона, снаружи по нему не подключиться. Если сервер в облаке с NAT (Yandex Cloud, GCP, AWS), белый IP не виден внутри ВМ — впишите его вручную ниже.</span>
      </div>`
    : '';

  // Легаси-поле server_ip из server.json — читается ТОЛЬКО если live-detect не дал
  // ничего. Показываем строку, когда оно есть и расходится с фактическим: иначе
  // непонятно, почему прописанный в файле IP не попадает в ссылки.
  const legacyRow = (s.legacy_server_ip && s.legacy_server_ip !== s.effective_ip)
    ? `<div class="truth-row">
        <div class="tk">server.json → server_ip</div>
        <div>
          <div class="tv">${escHtml(s.legacy_server_ip)}</div>
          <div class="ts">устаревшее поле, читается только если live-detect ничего не вернул. В ссылки оно НЕ идёт — чтобы закрепить этот адрес, впишите его в «Свой IP» ниже.</div>
        </div>
      </div>`
    : '';

  const obfPairs = Object.entries(a.obf || {})
    .map(([k, v]) => `<span style="color:var(--text2);">${escHtml(k)}=</span>${escHtml(String(v))}`)
    .join(' &nbsp; ');

  // Разделы разложены по вкладкам протоколов (как в «Зависимостях»): в одном
  // свитке эти четыре набора значений читать невозможно, а ищут в них всегда
  // что-то одно.
  const SECTIONS = {
    awg: `
    <div class="truth-section">
      <h3>AmneziaWG</h3>
      <div class="truth-row">
        <div class="tk">UDP-порт</div>
        <div>
          <div class="tv">${escHtml(String(a.port ?? '—'))}</div>
          <div class="ts">${escHtml(a.port_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Сеть клиентов</div>
        <div>
          <div class="tv">${escHtml(a.address || '—')}</div>
          <div class="ts">${escHtml(a.address_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Обф-параметры</div>
        <div>
          <div class="tv" style="font-size:12px;">${obfPairs || '—'}</div>
          <div class="ts">${escHtml(a.obf_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Файл интерфейса</div>
        <div class="tv">${escHtml(a.iface_config || '—')}</div>
      </div>
    </div>`,

  };

  if (_truthsTab === 'awg') return SECTIONS.awg;
  if (_truthsTab === 'xray') return renderTruthsXray(t);
  if (_truthsTab === 'mtg') return renderTruthsMtg(t);
  if (_truthsTab === 'hysteria') return renderTruthsHysteria(t);
  if (_truthsTab === 'tgweb') return renderTruthsTgweb(t);

  return `
    <div class="truth-section">
      <h3>Сервер — IP</h3>
      ${privateWarn}
      <div class="truth-row">
        <div class="tk">Эффективный IP</div>
        <div>
          <div class="tv">${escHtml(s.effective_ip || '—')}</div>
          <div class="ts">источник: ${escHtml(s.source || '—')}; именно этот IP попадает в vless://, Endpoint AWG и tg://-ссылки</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Live outbound</div>
        <div>
          <div class="tv">${escHtml(s.live_outbound || '—')}</div>
          <div class="ts">ip route get 1.1.1.1 → src</div>
        </div>
      </div>
      ${legacyRow}
      ${overrideRow}
      <div class="truth-row">
        <div class="tk">Интерфейсы</div>
        <div>
          ${ifaces || '<div class="ts">нет IPv4-адресов кроме loopback</div>'}
          <div class="ts" style="margin-top:8px;">Кнопка «Выбрать» закрепляет IP как override — все клиентские конфиги пойдут с ним, даже если outbound сменится.</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Свой IP</div>
        <div>
          <div class="truth-ip-manual">
            <input type="text" id="truthIpManualInput" class="tir-manual-ip" placeholder="203.0.113.10"
                   value="${escAttr(s.ip_override || '')}" spellcheck="false" autocomplete="off">
            <button id="truthIpManualBtn" class="btn btn-sm btn-success">Закрепить</button>
            <button id="truthIpDetectBtn" class="btn btn-sm btn-ghost">Определить внешний</button>
          </div>
          <div class="ts" id="truthIpManualHint" style="margin-top:8px;">Для облаков с NAT (Yandex Cloud, GCP, AWS), где белого IP нет ни на одном интерфейсе. «Определить внешний» спрашивает api.ru.dog с сервера и только подставляет значение в поле — закрепляется оно кнопкой.</div>
        </div>
      </div>
    </div>

    <div class="truth-section">
      <h3>Занятые порты — что реально слушает сервер</h3>
      <div class="truth-row">
        <div class="tk">Источник</div>
        <div class="ts">ss -tulnp. Выше показаны порты из конфигов — здесь то, что занято на самом деле.
        Расхождение объясняет, почему сервис может не подняться на «своём» порту.</div>
      </div>
      ${renderTruthPorts(t.ports)}
    </div>

    <div class="truth-section">
      <h3>Файлы — каноничные источники</h3>
      <div class="truth-row">
        <div class="tk">Описание</div>
        <div class="ts">Из этих файлов панель сейчас читает значения выше. Полный реестр всех файлов и папок панели — в окне «Системные пути».</div>
      </div>
      ${renderTruthFile('server.json', (t.files||{}).panel_server_json, 'настройки сервера (имя, SNI, override IP, расписания)')}
      ${renderTruthFile('admin.json', (t.files||{}).panel_admin_json, 'хеш пароля админа панели')}
      ${renderTruthFile('secret.key', (t.files||{}).panel_secret_key, 'Flask session key — без него сессии слетают при рестарте')}
      ${renderTruthFile('AWG конфиг', (t.files||{}).awg_config, 'порт + обф-параметры + список peers')}
      ${renderTruthFile('XRay конфиг', (t.files||{}).xray_config, 'порт vless-tls inbound, режим (TLS/Reality), SNI/dest')}
      ${renderTruthFile('mtg конфиг', (t.files||{}).mtg_config, 'bind-to (порт) + secret (с зашитым fake-host)')}
      ${(t.files||{}).hysteria_config ? renderTruthFile('Hysteria конфиг', t.files.hysteria_config, 'порт, маскировка, обфускация, сертификат и acl глобальных правил') : ''}
    </div>
  `;
}


// XRay и MTProto — отдельные вкладки «Источников правды». Вынесены функциями,
// чтобы renderTruths не превращался в один нечитаемый шаблон на 300 строк.
function renderTruthsXray(t) {
  const x = t.xray || {};
  return `
    <div class="truth-section">
      <h3>XRay</h3>
      <div class="truth-row">
        <div class="tk">TCP-порт</div>
        <div>
          <div class="tv">${escHtml(String(x.port ?? '—'))}</div>
          <div class="ts">${escHtml(x.port_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Режим</div>
        <div>
          <div class="tv">${escHtml(x.security || '—')}</div>
          <div class="ts">${escHtml(x.security_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">SNI</div>
        <div>
          <div class="tv">${escHtml(x.sni || '—')}</div>
          <div class="ts">${escHtml(x.sni_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Flow</div>
        <div>
          <div class="tv">${escHtml(x.flow || '—')}</div>
          <div class="ts">${escHtml(x.flow_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Fingerprint</div>
        <div class="tv">${escHtml(x.fingerprint || '—')}</div>
      </div>
      ${x.security === 'reality' ? `
      <div class="truth-row">
        <div class="tk">Reality dest</div>
        <div class="tv">${escHtml(x.reality_dest || '—')}</div>
      </div>
      <div class="truth-row">
        <div class="tk">Reality publicKey</div>
        <div>
          <div class="tv" style="overflow-wrap:anywhere;">${escHtml(x.reality_public_key || '—')}</div>
          <div class="ts">${escHtml(x.reality_public_key_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Reality shortId</div>
        <div>
          <div class="tv">${escHtml(x.reality_short_id || '—')}</div>
          <div class="ts">${escHtml(x.reality_short_id_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Reality spiderX</div>
        <div class="tv">${escHtml(x.reality_spider_x || '—')}</div>
      </div>` : ``}
      <div class="truth-row">
        <div class="tk">Файл inbound</div>
        <div class="tv">${escHtml(x.inbound_config || '—')}</div>
      </div>
    </div>` + renderTruthsHyInbound(t);
}

// Инбаунд Hysteria — часть того же ядра, поэтому и в «Источниках правды» он
// идёт внутри вкладки XRay, а не отдельным разделом. Выключен — блока нет.
function renderTruthsHyInbound(t) {
  const h = t.hysteria_inbound || {};
  if (!h.enabled) return '';
  const row = (k, v, src) =>
    `<div class="truth-row"><div class="tk">${escHtml(k)}</div><div>` +
    `<div class="tv">${escHtml(String(v))}</div>` +
    (src ? `<div class="ts">${escHtml(src)}</div>` : '') + `</div></div>`;
  const cfg = 'config.json → inbounds[hysteria-in]';
  return `
    <div class="truth-section">
      <h3>Hysteria 2 (инбаунд XRay)</h3>
      ${row('UDP-порт', h.port ?? '—', cfg + '.port')}
      ${row('Маскировка под', h.masquerade_url || '404 (заглушка не задана)',
            cfg + '.streamSettings.hysteriaSettings.masquerade')}
      ${row('Обфускация', h.obfs ? 'salamander' : 'выключена',
            cfg + '.streamSettings.finalmask.udp[salamander]')}
      ${row('Лимиты', (h.up_mbps || h.down_mbps)
              ? `${h.up_mbps || 0} / ${h.down_mbps || 0} Мбит/с (вверх/вниз)`
              : 'без ограничений',
            cfg + '.streamSettings.finalmask.quicParams (brutal)')}
      ${row('Сертификат', h.cert_mode === 'le' ? "Let’s Encrypt (общий с VLESS)"
              : (h.cert_mode === 'self' ? 'самоподписанный, клиенты пиннят отпечаток' : '—'),
            h.cert_mode === 'self' ? 'data/xray/hysteria-self-cert.pem' : 'общий с VLESS')}
      ${h.fingerprint ? row('Отпечаток (pinSHA256)', h.fingerprint, 'уходит клиентам в ссылке') : ''}
    </div>`;
}

function renderTruthsMtg(t) {
  const m = t.mtg || {};
  return `
    <div class="truth-section">
      <h3>MTProto (mtg)</h3>
      <div class="truth-row">
        <div class="tk">TCP-порт</div>
        <div>
          <div class="tv">${escHtml(String(m.port ?? '—'))}</div>
          <div class="ts">${escHtml(m.port_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Маскировка под</div>
        <div>
          <div class="tv">${escHtml(m.fake_host || '—')}</div>
          <div class="ts">${escHtml(m.fake_host_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Файл конфига</div>
        <div class="tv">${escHtml(m.config || '—')}</div>
      </div>
    </div>`;
}

// Telegram WEB: публичного порта нет (клиенты приходят на 443 к XRay), зато
// есть три внутренних на 127.0.0.1 и общий фоллбек XRay — их и показываем,
// вместе с тем, кто сейчас держит каждый порт.
// Кто принимает 443 для Telegram WEB (modules/tgweb/front.py).
const _TG_FRONT_LABEL = {xray: 'через XRay (TLS)', nginx: 'сам (nginx на 443)'};

function renderTruthsTgweb(t) {
  const g = (t.tgweb || {});
  const row = (k, v, src, warn) => `
      <div class="truth-row">
        <div class="tk"${warn ? ' style="color:var(--orange);"' : ''}>${escHtml(k)}</div>
        <div><div class="tv"${warn ? ' style="color:var(--orange);"' : ''}>${escHtml(String(v ?? '—'))}</div>
        ${src ? `<div class="ts">${escHtml(src)}</div>` : ''}</div>
      </div>`;
  const ports = (g.ports || []).map(p => row(
    p.who, p.port,
    p.conflict ? p.conflict : ('слушает: ' + (p.listener || 'никто')), !!p.conflict)).join('');
  return `
    <div class="truth-section">
      <h3>Telegram WEB (telemt ${escHtml(g.version || '')})</h3>
      ${row('Домен', g.host, g.host_source)}
      ${row('Префикс пути', g.slug, g.slug_source)}
      ${row('Вход на 443', _TG_FRONT_LABEL[g.front] || 'не наш', g.front_why, !g.front)}
      ${row('Режим XRay на 443', (g.xray_mode || '—').toUpperCase(), 'с WEB совместим только TLS; без XRay WEB слушает 443 сам')}
      ${row('Фоллбек XRay', g.fallback, g.fallback_source)}
      ${row('Блок nginx', g.nginx_site, g.front === 'nginx' ? '443 с сертификатом домена, без журнала запросов' : 'только 127.0.0.1, без журнала запросов')}
      ${row('Выход к Telegram', g.cascade, 'каскад включается на вкладке Mihomo')}
      ${ports}
    </div>`;
}

function renderTruthsHysteria(t) {
  const h = (t.hysteria || {});
  // Конфликт по UDP отдельной строкой сверху: соседей у Hysteria двое (AWG и
  // инбаунд внутри XRay), и совпадение номеров иначе видно только в момент,
  // когда сервис уже не поднялся.
  const clash = h.conflict
    ? `<div class="truth-row">
        <div class="tk" style="color:var(--orange);">Конфликт порта</div>
        <div><div class="tv" style="color:var(--orange);">${escHtml(h.conflict)}</div>
        <div class="ts">Реестр портов панели: кто ещё претендует на этот UDP-номер.</div></div>
      </div>`
    : '';
  return `
    <div class="truth-section">
      <h3>Hysteria 2</h3>
      ${clash}
      <div class="truth-row">
        <div class="tk">UDP-порт</div>
        <div>
          <div class="tv">${escHtml(String(h.port ?? '—'))}</div>
          <div class="ts">${escHtml(h.port_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Адрес подключения</div>
        <div>
          <div class="tv">${escHtml(h.connect_host || '—')}</div>
          <div class="ts">${escHtml(h.connect_host_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Маскировка под</div>
        <div>
          <div class="tv">${escHtml(h.masquerade || '—')}</div>
          <div class="ts">${escHtml(h.masquerade_source || '')}</div>
          <div class="ts">Это НЕ адрес подключения: сюда hysteria проксирует чужой HTTP/3-запрос, пришедший на тот же порт.</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Обфускация</div>
        <div>
          <div class="tv">${escHtml(h.obfs || '—')}</div>
          <div class="ts">${escHtml(h.obfs_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Сертификат</div>
        <div>
          <div class="tv">${escHtml(h.cert_mode || '—')}</div>
          <div class="ts">${escHtml(h.cert_source || '')}</div>
          <div class="ts" style="overflow-wrap:anywhere;">Отпечаток: ${escHtml(h.fingerprint || '—')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Лимит полосы</div>
        <div>
          <div class="tv">${escHtml(h.bandwidth || '—')}</div>
          <div class="ts">${escHtml(h.bandwidth_source || '')}</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Кто слушает порт</div>
        <div>
          <div class="tv">${escHtml(h.listener || 'никто')}</div>
          <div class="ts">ss -ulnp. Чужой слушатель объясняет, почему сервис не поднимается.</div>
        </div>
      </div>
      <div class="truth-row">
        <div class="tk">Файл конфига</div>
        <div class="tv">${escHtml(h.config || '—')}</div>
      </div>
    </div>`;
}

function renderTruthFile(label, path, note) {
  return `
    <div class="truth-row">
      <div class="tk">${escHtml(label)}</div>
      <div>
        <div class="tv">${escHtml(path || '—')}</div>
        <div class="ts">${escHtml(note || '')}</div>
      </div>
    </div>`;
}

const XRAY_CONFIG_LABEL = '/usr/local/etc/xray/config.json';

async function setIpOverride(ip) {
  showBusyOverlay('Сохраняем выбор IP…', ip ? ('Новый override: ' + ip) : 'Сбрасываем override');
  try {
    const r = await fetch(API + '/api/server/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({server_ip_override: ip || ''}),
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || 'Не удалось сохранить'); return; }
    _serverConfig = j.config;
    // Шапка / карточки обновятся при следующем refreshAll, но IP в шапке — сразу.
    const ipEl = document.getElementById('serverIP');
    if (ipEl && _serverConfig.server_ip_override) ipEl.textContent = _serverConfig.server_ip_override;
    toast(ip ? 'IP закреплён: ' + ip : 'Override сброшен');
    await loadTruths();
    await loadServerConfig();
    refreshAll();
  } catch (e) {
    toast('Сеть: не сохранено');
  } finally {
    hideBusyOverlay();
  }
}

// === System paths window ===
function openSystemPathsModal() {
  document.getElementById('systemPathsModal').classList.remove('hidden');
  const cached = _readModalCache('sysPaths');
  if (cached && Array.isArray(cached.items)) {
    _renderSysPathsItems(cached.items);
    loadSystemPaths({silent: true});  // фоновое обновление
  } else {
    loadSystemPaths();  // первый раз — shimmer
  }
}

// Порядок групп в окне «Системные пути» — соответствует порядку, в котором их
// возвращает бэкенд (_discover_paths_detailed). Если бэк отдал группу не из этого
// списка — она встанет в конец.
const SYS_PATH_GROUP_ORDER = [
  'Код панели',
  'Данные панели',
  'Логи доступа',
  'Бэкапы',
  'Geo-базы',
  'Внешние конфиги сервисов',
  'Бинари и юниты',
  'Другое',
];

// Вкладки протоколов — те же и в том же порядке, что в «Зависимостях»: реестр
// путей длинный, сплошным списком в нём ничего не найти.
const PROTO_TAB_ORDER = [
  ['panel', 'Общие'],
  ['awg', 'AmneziaWG'],
  ['xray', 'XRay'],
  ['mtg', 'MTProto'],
  ['hysteria', 'Hysteria'],
  ['tgweb', 'Telegram WEB'],
];

let _sysPathsTab = 'panel';
let _sysPathsItems = [];

function switchSysPathsTab(key) {
  _sysPathsTab = key;
  _renderSysPathsItems(_sysPathsItems);
}

function _paintProtoTabs(boxId, present, current, onclickFn) {
  const box = document.getElementById(boxId);
  if (!box) return;
  const tabs = PROTO_TAB_ORDER.filter(([k]) => present.has(k));
  if (tabs.length < 2) { box.innerHTML = ''; return; }
  box.innerHTML = tabs.map(([k, title]) =>
    `<button class="cfg-tab${k === current ? ' active' : ''}" onclick="${onclickFn}('${k}')">${escHtml(title)}</button>`
  ).join('');
  _revealActiveTab(box);
}

// На узком экране ряд вкладок листается — активную докручиваем в видимую
// область. Только scrollLeft: scrollIntoView дёрнул бы и саму модалку.
function _revealActiveTab(box) {
  const a = box && box.querySelector('.cfg-tab.active');
  if (!a || box.scrollWidth <= box.clientWidth) return;
  const l = a.getBoundingClientRect().left - box.getBoundingClientRect().left + box.scrollLeft;
  const r = l + a.offsetWidth;
  if (l < box.scrollLeft) box.scrollLeft = l - 12;
  else if (r > box.scrollLeft + box.clientWidth) box.scrollLeft = r - box.clientWidth + 12;
}

function _renderSysPathsItems(items) {
  const list = document.getElementById('sysPathsList');
  if (!list) return;
  _sysPathsItems = items || [];
  const present = new Set(_sysPathsItems.map(i => i.proto || 'panel'));
  if (!present.has(_sysPathsTab)) _sysPathsTab = 'panel';
  _paintProtoTabs('sysPathsTabs', present, _sysPathsTab, 'switchSysPathsTab');
  items = _sysPathsItems.filter(i => (i.proto || 'panel') === _sysPathsTab);
  const grouped = new Map();
  for (const it of (items || [])) {
    const g = it.group || 'Другое';
    if (!grouped.has(g)) grouped.set(g, []);
    grouped.get(g).push(it);
  }
  for (const arr of grouped.values()) {
    arr.sort((a, b) => (a.not_installed ? 1 : 0) - (b.not_installed ? 1 : 0));
  }
  const orderedGroups = SYS_PATH_GROUP_ORDER.filter(g => grouped.has(g))
    .concat([...grouped.keys()].filter(g => !SYS_PATH_GROUP_ORDER.includes(g)));
  list.innerHTML = orderedGroups.map(g => {
    const cards = grouped.get(g).map(renderSysPathCard).join('');
    return `
      <div class="sys-path-group">
        <div class="sys-path-group-head">${escHtml(g)}</div>
        ${cards}
      </div>`;
  }).join('');
}

async function loadSystemPaths(opts) {
  opts = opts || {};
  const list = document.getElementById('sysPathsList');
  // Если контейнер пуст (нет ни кеша, ни предыдущей отрисовки) — короткий
  // плейсхолдер строкой; если уже что-то нарисовано (cached / прошлый ответ) —
  // контент остаётся, индикатор обновления только на кнопке.
  if (!opts.silent && !list.hasChildNodes()) {
    list.innerHTML = '<div style="color:var(--text3);">…</div>';
  }
  if (!opts.silent) _spinBtn('sysPathsReloadBtn', true, 'Сканируем…');
  try {
    const r = await fetch(API + '/api/system/paths', {credentials: 'same-origin'});
    if (!r.ok) { list.innerHTML = '<div style="color:var(--red);">Ошибка ' + r.status + '</div>'; return; }
    const data = await r.json();
    _writeModalCache('sysPaths', data);
    _renderSysPathsItems(data.items || []);
  } catch (e) {
    if (!opts.silent && !list.hasChildNodes()) {
      list.innerHTML = '<div style="color:var(--red);">Ошибка: ' + escHtml(e.message) + '</div>';
    }
  } finally {
    _spinBtn('sysPathsReloadBtn', false);
  }
}

function renderSysPathCard(it) {
  let status;
  if (it.not_installed) {
    status = '<span class="dep-status" style="background:var(--bg);color:var(--text3);border:1px solid var(--border);">○ протокол не установлен</span>';
  } else if (it.exists) {
    status = '<span class="dep-status ok">● найдено</span>';
  } else {
    status = '<span class="dep-status bad">● не найдено</span>';
  }
  const isDefault = (it.is_default === true)
    ? '<span style="font-size:11px;color:var(--text3);">= дефолт</span>'
    : (it.is_default === false ? `<span style="font-size:11px;color:var(--orange);">≠ дефолт (${escHtml(it.default)})</span>` : '');
  const value = it.value
    ? `<pre class="dep-cmd" style="margin:6px 0 0;user-select:all;">${escHtml(it.value)}</pre>`
    : '<div style="font-size:12px;color:var(--text3);font-style:italic;margin-top:6px;">— пусто (не удалось определить)</div>';
  const source = it.source
    ? `<div style="font-size:10.5px;color:var(--text3);margin-top:4px;">Откуда: ${escHtml(it.source)}</div>`
    : '';
  return `<div class="dep-card${it.not_installed ? ' is-ok' : ''}">
    <div class="dep-head">
      <div class="dep-title">${escHtml(it.label)}</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">${isDefault} ${status}</div>
    </div>
    <div class="dep-desc">${escHtml(it.description)}</div>
    ${value}
    ${source}
  </div>`;
}

function openAwgLogs(pubkey) {
  window.open('/static/logs.html?awg=' + encodeURIComponent(pubkey), '_blank', 'noopener');
}

let _depsBadgeSeq = 0;
function refreshDepsBadge() {
  const seq = ++_depsBadgeSeq;
  return fetch(API + '/api/system/dependencies', {credentials: 'same-origin', cache: 'no-store'})
    .then(r => r.json())
    .then(d => {
      if (seq !== _depsBadgeSeq) return;  // поздний ответ старой проверки не затирает свежий
      _paintDepsAlertBtn(d);
      _writeModalCache('deps', d);
    })
    .catch(() => {});
}

// ⚠ в шапке горит только на то, что надо чинить: красным — что-то не работает,
// оранжевым — работает, но есть что поправить. Советы его не зажигают.
function _paintDepsAlertBtn(d) {
  const btn = document.getElementById('depsAlertBtn');
  if (btn) {
    btn.classList.toggle('hidden', (d.failing || 0) === 0);
    btn.classList.toggle('is-warn', d.level === 'warn');
  }
  if (d.protos) {
    _protoAlerts = d.protos;
    _paintProtoAlerts();
  }
}

// === Значки протоколов на главной ===========================================
// Красный «!» — протокол у клиентов не работает (сервис упал, порт закрыт,
// сертификат истёк…), оранжевый — работает, но есть что поправить. Советы и
// остановленный руками сервис на главной не сигналят — они видны внутри ⚙.
// Значок стоит на вкладке протокола и рядом с ⚙ на плитке сервиса; клик
// открывает ⚙, где блок «Чтобы … заработал» говорит, что делать.
let _protoAlerts = {};
// WEB-прокси живёт на вкладке «Telegram» вместе с MTProto: значок вкладки
// показывает худшее из двух, а у ⚙ на плитке каждого вида — своё.
const _PROTO_TAB_IDS = {awg: 'tabAwg', xray: 'tabXray', mtg: 'tabMtg', hysteria: 'tabHysteria',
                        tgweb: 'tabMtg'};

function _protoCogEl(kind) {
  if (kind === 'hysteria') return document.querySelector('.stat-icon[data-hy="settings"]');
  if (kind === 'tgweb') return document.querySelector('.stat-icon[data-tg="settings"]');
  return document.querySelector('.stat-icon[onclick="openProtoSvcModal(\'' + kind + '\')"]');
}

function _alertTitle(a) {
  const lvl = a.level || '';
  return lvl ? ((lvl === 'block' ? 'Не работает: ' : 'Есть что поправить: ') + (a.top || '') +
    (a.count > 1 ? ' (и ещё ' + (a.count - 1) + ')' : '') + ' — откройте ⚙') : '';
}

function _paintProtoAlerts() {
  // Худший уровень на вкладку: у «Telegram» два протокола, и второй не должен
  // гасить значок, зажжённый первым.
  const rank = {block: 2, warn: 1};
  const lvlOf = (k) => ((_protoAlerts[k] || {}).level || '');
  const perTab = {};
  for (const kind of Object.keys(_PROTO_TAB_IDS)) {
    const id = _PROTO_TAB_IDS[kind];
    if (!perTab[id] || (rank[lvlOf(kind)] || 0) > (rank[lvlOf(perTab[id])] || 0)) perTab[id] = kind;
  }
  for (const kind of Object.keys(_PROTO_TAB_IDS)) {
    const a = _protoAlerts[kind] || {};
    const lvl = a.level || '';
    const title = _alertTitle(a);
    const tab = document.getElementById(_PROTO_TAB_IDS[kind]);
    // Значок вкладки рисует только «худший» из её протоколов.
    if (tab && perTab[_PROTO_TAB_IDS[kind]] === kind) {
      let dot = tab.querySelector('.proto-alert');
      if (lvl && !dot) {
        dot = document.createElement('span');
        dot.className = 'proto-alert';
        dot.textContent = '!';
        tab.appendChild(dot);
      }
      if (dot) {
        dot.classList.toggle('hidden', !lvl);
        dot.classList.toggle('lvl-warn', lvl === 'warn');
        dot.title = title;
      }
    }
    const cog = _protoCogEl(kind);
    if (cog && cog.parentNode) {
      let b = cog.parentNode.querySelector('.proto-alert-btn');
      if (lvl && !b) {
        b = document.createElement('button');
        b.className = 'proto-alert-btn';
        b.textContent = '!';
        b.addEventListener('click', (e) => { e.stopPropagation(); openProtoSvcModal(kind); });
        cog.parentNode.insertBefore(b, cog);
      }
      if (b) {
        b.classList.toggle('hidden', !lvl);
        b.classList.toggle('lvl-warn', lvl === 'warn');
        b.title = title;
      }
    }
  }
}

// Свежий результат из окна ⚙ сразу правит значок этого протокола: человек
// нажал «Исправить» — значок на главной должен погаснуть, а не ждать опроса.
function _protoAlertFromHealth(kind, h) {
  if (!kind || !h || h.error) return;
  const items = (h.items || []).filter(x => x.level !== 'tip');
  const block = items.find(x => x.level === 'block');
  const top = block || items[0];
  _protoAlerts[kind] = {level: block ? 'block' : (items.length ? 'warn' : ''),
                        count: items.length, top: top ? top.name : ''};
  _paintProtoAlerts();
}

async function refreshAwgDestLogToggle() {
  try {
    const r = await fetch('/api/awg/dest-log/state');
    if (!r.ok) return;
    const d = await r.json();
    const el = document.getElementById('awgDestLogToggle');
    if (el) el.checked = !!d.enabled;
  } catch (_) {}
}

async function onAwgDestLogToggle(checked) {
  // Тумблер живёт в модалке «Настройки протокола» — при отказе возвращаем его на
  // место только если модалка ещё открыта.
  const _revert = () => {
    const el = document.getElementById('awgDestLogToggle');
    if (el) {
      el.checked = !checked;
      const row = el.closest('.switch-row');
      if (row) row.classList.toggle('is-on', !checked);
    }
  };
  const ok = await openConfirm({
    title: checked ? 'Включить логи назначения AWG?' : 'Выключить логи назначения AWG?',
    body: checked
      ? 'Сборщик начнёт читать /proc/net/nf_conntrack каждые 10 сек и писать IP назначения клиентов в общий лог AWG.\n\nПонадобятся пакеты <b>conntrack</b> и <b>dnsmasq</b> (для доменов через «Логи+» у клиентов) — после включения они появятся в разделе «Зависимости» с автофиксами.\n\nКонфиги клиентов не меняются, перевыдача не нужна.'
      : 'Сборщик остановится. Уже записанные строки лога останутся. Установленные пакеты НЕ удаляются — можно включить обратно без переустановки.',
    okLabel: checked ? 'Включить' : 'Выключить',
  });
  if (!ok) { _revert(); return; }
  const r = await fetch('/api/awg/dest-log/toggle', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled: checked}),
  });
  if (!r.ok) {
    toast('Не удалось переключить');
    _revert();
    return;
  }
  const row = (document.getElementById('awgDestLogToggle') || {closest: () => null}).closest('.switch-row');
  if (row) row.classList.toggle('is-on', checked);
  toast(checked ? 'Логи AWG включены' : 'Логи AWG выключены');
}

async function toggleDnsLocal(pk, name, current, inputEl) {
  const enabling = !current;
  const ok = await openConfirm({
    title: enabling ? `«Логи+» для «${name}»: включить?` : `«Логи+» для «${name}»: выключить?`,
    body: enabling
      ? 'В клиентском конфиге <b>DNS поменяется с 1.1.1.1 на адрес AWG-интерфейса сервера</b> (наш локальный dnsmasq). После этого его DNS-запросы пишутся в лог, и в общем AWG-логе появится колонка <b>Хост назначения</b> с реальными доменами.\n\n⚠ Если конфиг уже выдан клиенту — ему нужно <b>перевыдать новый .conf</b>, иначе он продолжит ходить через 1.1.1.1 и доменов мы не увидим.'
      : 'DNS вернётся к 1.1.1.1. Конфиг тоже придётся перевыдать клиенту, иначе он продолжит спрашивать наш локальный DNS.',
    okLabel: enabling ? 'Включить и обновить конфиг' : 'Выключить и обновить конфиг',
  });
  if (!ok) {
    if (inputEl) inputEl.checked = !!current;
    return;
  }
  const r = await fetch('/api/clients/' + encodeURIComponent(pk) + '/dns-local', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled: enabling}),
  });
  if (!r.ok) {
    toast('Не удалось');
    if (inputEl) inputEl.checked = !!current;
    return;
  }
  toast(enabling ? 'DNS заменён на локальный — перевыдай конфиг' : 'DNS возвращён на 1.1.1.1 — перевыдай конфиг');
  if (_lastPeers) {
    for (const p of _lastPeers) if (p.public_key === pk) p.dns_local = enabling;
    renderPeers(_lastPeers);
  }
}

function openConfirm({title, body, okLabel, danger}) {
  return new Promise(resolve => {
    const ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = `
      <div class="modal" style="max-width:520px;">
        <h3 style="margin-top:0;">${escHtml(title)}</h3>
        <div style="white-space:pre-line;line-height:1.5;font-size:14px;">${body}</div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px;">
          <button class="btn btn-ghost" data-cancel>Отмена</button>
          <button class="btn ${danger ? 'btn-danger' : 'btn-success'}" data-ok>${escHtml(okLabel || 'OK')}</button>
        </div>
      </div>`;
    document.body.appendChild(ov);
    const close = (val) => { ov.remove(); resolve(val); };
    ov.querySelector('[data-cancel]').addEventListener('click', () => close(false));
    ov.querySelector('[data-ok]').addEventListener('click', () => close(true));
  });
}

// Модальное окно-уведомление с одной кнопкой (для ошибок валидации и т.п.).
function openAlert({title, body, okLabel}) {
  return new Promise(resolve => {
    const ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = `
      <div class="modal" style="max-width:520px;">
        <h3 style="margin-top:0;">${escHtml(title)}</h3>
        <div style="white-space:pre-line;line-height:1.5;font-size:14px;">${body}</div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px;">
          <button class="btn btn-success" data-ok>${escHtml(okLabel || 'OK')}</button>
        </div>
      </div>`;
    document.body.appendChild(ov);
    const close = () => { ov.remove(); resolve(true); };
    ov.querySelector('[data-ok]').addEventListener('click', close);
  });
}

let _currentXrayConfigUuid = '';
async function showXrayConfig(uuid) {
  _currentXrayConfigUuid = uuid;
  const res = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/config');
  if (!res.ok) { toast('Клиент не найден'); return; }
  const data = await res.json();
  showXrayConfigData(data);
}

let _currentVless = '';
let _currentHy2 = '';
let _currentShadow = '';
let _currentLoon = '';
let _currentClash = '';
let _currentSubUrl = '';
let _currentShadowConfUrl = '';
let _currentLoonConfUrl = '';
let _currentClashConfUrl = '';

// Зеркало _safe_filename в app.py, включая нижний регистр: имя уходит в
// публичный URL профиля, а он lowercase.
function _safeName(name) {
  let s = (name || 'profile').trim().replace(/[^A-Za-z0-9._-]+/g, '_');
  return (s || 'profile').slice(0, 64).toLowerCase();
}
// Человеческое имя профиля: `<server>-<client>` (сервер первым — профили разных
// серверов группируются в списке подписок). Зеркалит _profile_filename в app.py.
function _profileName(name, token) {
  const mode = (_serverConfig && _serverConfig.profile_naming) || 'friendly';
  if (mode === 'token' && token) return token.slice(0, 96);
  const sn = (_serverConfig && _serverConfig.server_name)
    ? _safeName(_serverConfig.server_name).slice(0, 32) : '';
  const cn = _safeName(name);
  return (sn ? `${sn}-${cn}` : cn).slice(0, 96);
}
// Путь профиля: `<token8>/<имя>`. Имя ПОСЛЕДНИМ — Loon показывает профиль под
// именем последнего сегмента URL, Content-Disposition он игнорирует. Резолвит
// сервер по токену, поэтому переименование ссылку не рвёт. Зеркалит
// _profile_url_seg в app.py, длина токена должна совпадать.
const PROFILE_TOKEN_URL_LEN = 8;
function _profilePath(name, token) {
  const mode = (_serverConfig && _serverConfig.profile_naming) || 'friendly';
  if (mode === 'token') return token.slice(0, 96);
  return token.slice(0, PROFILE_TOKEN_URL_LEN) + '/' + _profileName(name, null);
}
function buildSubUrl(token, name) {
  if (!token) return '';
  return _publicOrigin() + '/sub/' + _profilePath(name, token) + '.txt';
}
function buildShadowConfUrl(token, name) {
  if (!token) return '';
  return _publicOrigin() + '/conf/' + _profilePath(name, token) + '.conf';
}
function buildLoonConfUrl(token, name) {
  if (!token) return '';
  return _publicOrigin() + '/loon/' + _profilePath(name, token) + '.conf';
}
function buildClashConfUrl(token, name) {
  if (!token) return '';
  return _publicOrigin() + '/clash/' + _profilePath(name, token) + '.yaml';
}

function copyVless() {
  if (!_currentVless) return;
  navigator.clipboard.writeText(_currentVless).then(() => toast('VLESS-ссылка скопирована'));
}

let _currentXdns = '';
let _currentXdnsLink = '';
let _currentXdnsName = 'xdns.json';
function copyXdnsLink() {
  if (!_currentXdnsLink) return;
  navigator.clipboard.writeText(_currentXdnsLink).then(() => toast('Ссылка XDNS скопирована'));
}
function copyXdnsConfig() {
  if (!_currentXdns) return;
  navigator.clipboard.writeText(_currentXdns).then(() => toast('Конфиг XDNS скопирован'));
}
function downloadXdnsConfig() {
  if (!_currentXdns) return;
  const url = URL.createObjectURL(new Blob([_currentXdns], {type: 'application/json'}));
  const a = document.createElement('a');
  a.href = url;
  a.download = _currentXdnsName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function copyHy2() {
  if (!_currentHy2) return;
  navigator.clipboard.writeText(_currentHy2).then(() => toast('Ссылка Hysteria скопирована'));
}

function copySubUrl() {
  if (!_currentSubUrl) { toast('Subscription URL пусто'); return; }
  navigator.clipboard.writeText(_currentSubUrl).then(() => toast('Subscription URL скопирован'));
}
function copyShadowConfUrl() {
  if (!_currentShadowConfUrl) { toast('Config URL пусто'); return; }
  navigator.clipboard.writeText(_currentShadowConfUrl).then(() => toast('Shadowrocket Config URL скопирован'));
}
function copyLoonConfUrl() {
  if (!_currentLoonConfUrl) { toast('Config URL пусто'); return; }
  navigator.clipboard.writeText(_currentLoonConfUrl).then(() => toast('Loon Config URL скопирован'));
}
function copyClashConfUrl() {
  if (!_currentClashConfUrl) { toast('Config URL пусто'); return; }
  navigator.clipboard.writeText(_currentClashConfUrl).then(() => toast('Clash Config URL скопирован'));
}
function openInLoon() {
  if (!_currentLoonConfUrl) { toast('Config URL пусто'); return; }
  // Loon URL Scheme: loon://import?url=<encoded config URL>
  const scheme = 'loon://import?url=' + encodeURIComponent(_currentLoonConfUrl);
  window.location.href = scheme;
}

// Живой опрос блоков «Последний запрос», пока открыто окно конфига (без кнопки «Обновить»).
let _fetchInfoPoll = null;
function _startFetchInfoPolling(uuid) {
  if (_fetchInfoPoll) { clearInterval(_fetchInfoPoll); _fetchInfoPoll = null; }
  if (!uuid) return;
  _fetchInfoPoll = setInterval(async () => {
    const modal = document.getElementById('xrayConfigModal');
    if (!modal || modal.classList.contains('hidden')) {
      clearInterval(_fetchInfoPoll); _fetchInfoPoll = null; return;
    }
    try {
      const res = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/profile-fetch');
      if (!res.ok) return;
      const pf = (await res.json()).profile_fetch || {};
      _fillFetchInfo('shadowFetchInfo', pf.shadowrocket);
      _fillFetchInfo('loonFetchInfo', pf.loon);
      _fillFetchInfo('clashFetchInfo', pf.clash);
    } catch (e) { /* тихо: сеть моргнула — попробуем на следующем тике */ }
  }, 5000);
}

// Блок «Последний запрос на обновление» над содержимым каждого Config URL.
function _fillFetchInfo(elId, info) {
  const el = document.getElementById(elId);
  if (!el) return;
  const label = '<div class="lbl" style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;">Последний запрос на обновление</div>';
  if (!info || !info.ts) {
    el.innerHTML = label + '<span style="color:var(--text3);font-size:12px;">Запросов с клиента ещё не было.</span>';
    return;
  }
  // Приватный/loopback IP не показываем (его реально не удалось определить).
  const isPriv = ip => !ip || /^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1)/.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
  const showIp = !isPriv(info.ip);
  const geo = showIp ? [info.country, info.city].filter(Boolean).join(', ') : '';
  el.innerHTML = label +
    '<span style="font-size:12px;color:var(--text2);">' + escHtml(fmtXrayTs(info.ts)) +
    (showIp ? ' &middot; <span style="font-family:\'JetBrains Mono\',monospace;">' + escHtml(info.ip) + '</span>' : '') +
    (geo ? ' &middot; ' + escHtml(geo) : '') +
    '</span>';
}

function showXrayConfigData(data) {
  const name = data.name, vless = data.vless, token = data.token || '';
  document.getElementById('xrayConfigTitle').textContent = name + ' — Конфиг';
  _currentVless = vless;
  _currentShadow = data.shadowrocket || '';
  _currentLoon = data.loon || '';
  _currentClash = data.clash || '';
  _currentSubUrl = buildSubUrl(token, name);
  _currentShadowConfUrl = buildShadowConfUrl(token, name);
  _currentLoonConfUrl = buildLoonConfUrl(token, name);
  _currentClashConfUrl = buildClashConfUrl(token, name);
  document.getElementById('vlessBlock').textContent = vless;
  // Ссылка Hysteria — если инбаунд поднят. Пароль у клиента свой, остальное
  // (адрес, порт, обфускация, отпечаток) панель подставляет из инбаунда.
  _currentHy2 = data.hy2 || '';
  const hy2Wrap = document.getElementById('hy2Wrap');
  if (hy2Wrap) {
    if (_currentHy2) {
      document.getElementById('hy2Block').textContent = _currentHy2;
      hy2Wrap.classList.remove('hidden');
      const hqr = document.getElementById('hy2QrBox');
      hqr.innerHTML = '';
      try {
        if (typeof QRCode !== 'undefined') {
          new QRCode(hqr, {text: _currentHy2, width: 180, height: 180, correctLevel: QRCode.CorrectLevel.M});
        }
      } catch (e) {}
    } else {
      hy2Wrap.classList.add('hidden');
    }
  }
  // Профиль один на платформу, а узлов внутри два. Без пояснения вкладки
  // Shadowrocket / Loon / Clash выглядят так, будто Hysteria в них не попала.
  const hyNode = (_currentShadow || '').includes('_HY2') || (_currentLoon || '').includes('_HY2')
                 || (_currentClash || '').includes('_HY2');
  for (const el of document.querySelectorAll('[data-hynote]')) {
    if (hyNode) {
      // Где именно переключать — пишем по шагам. «В группе выбора» звучало
      // понятно только тому, кто и так знает: в списке узлов переключателя
      // нет, выбор живёт в политике/группе, и человек упирается в это первым.
      el.innerHTML = 'В профиле <b>два узла</b>: <b>' + escHtml(name) + '</b> (VLESS по TCP) и <b>' +
        escHtml(name) + '_HY2</b> (Hysteria 2 по UDP). Ссылка на профиль одна, правила, DNS и ' +
        'списки у обоих общие.' +
        '<div style="margin-top:8px;">Где переключить — в списке узлов переключателя нет, выбор ' +
        'делается в группе:<br>' +
        '• <b>Loon</b> — вкладка «Политика» → группа <code>' + escHtml(name) + '_group</code> → ' +
        'узел <code>' + escHtml(name) + '_HY2</code>;<br>' +
        '• <b>Shadowrocket</b> — «Настройки» → «Группа» <code>' + escHtml(name) + '_group</code>;<br>' +
        '• <b>Clash / mihomo</b> — экран «Прокси» → группа <code>' + escHtml(name) + '_group</code>;<br>' +
        '• <b>v2RayTun, Streisand, NekoBox</b> — узлы приходят подпиской отдельными строками, ' +
        'там узел <code>' + escHtml(name) + '_HY2</code> выбирается прямо в списке.</div>';
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
  }
  // XDNS: ссылка vless:// с параметром fm (стандарт ссылок Xray) + QR, и тот
  // же профиль JSON-ом — для приложений, которые fm ещё не понимают.
  // Вкладки нет, когда вход выключен.
  _currentXdnsLink = data.xdns_link || '';
  const xl = document.getElementById('xdnsLinkBlock');
  if (xl) xl.textContent = _currentXdnsLink;
  const xq = document.getElementById('xdnsQrBox');
  if (xq) {
    xq.innerHTML = '';
    try {
      if (_currentXdnsLink && typeof QRCode !== 'undefined') {
        new QRCode(xq, {text: _currentXdnsLink, width: 260, height: 260, correctLevel: QRCode.CorrectLevel.L});
      }
    } catch (e) {}
  }
  _currentXdns = data.xdns ? JSON.stringify(data.xdns, null, 2) : '';
  _currentXdnsName = _profileName(name, token) + '-xdns.json';
  const xdnsTab = document.getElementById('cfgTabXdns');
  if (xdnsTab) xdnsTab.classList.toggle('hidden', !_currentXdns);
  const xdnsBlock = document.getElementById('xdnsCfgBlock');
  if (xdnsBlock) xdnsBlock.textContent = _currentXdns;
  document.getElementById('shadowBlock').textContent = _currentShadow;
  document.getElementById('loonBlock').textContent = _currentLoon;
  document.getElementById('clashBlock').textContent = _currentClash;
  const pf = data.profile_fetch || {};
  _fillFetchInfo('shadowFetchInfo', pf.shadowrocket);
  _fillFetchInfo('loonFetchInfo', pf.loon);
  _fillFetchInfo('clashFetchInfo', pf.clash);
  _startFetchInfoPolling(data.uuid || _currentXrayConfigUuid);
  const noToken = '(токен не назначен — обновите страницу)';
  document.getElementById('subUrlBlock').textContent = _currentSubUrl || noToken;
  document.getElementById('shadowConfUrlBlock').textContent = _currentShadowConfUrl || noToken;
  document.getElementById('loonConfUrlBlock').textContent = _currentLoonConfUrl || noToken;
  document.getElementById('clashConfUrlBlock').textContent = _currentClashConfUrl || noToken;
  const qrBox = document.getElementById('qrBox');
  qrBox.innerHTML = '';
  try {
    if (typeof QRCode !== 'undefined') {
      new QRCode(qrBox, {
        text: vless,
        width: 220,
        height: 220,
        correctLevel: QRCode.CorrectLevel.M
      });
    } else {
      qrBox.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">QR-код недоступен (библиотека не загрузилась). Скопируйте ссылку.</div>';
    }
  } catch (e) {
    console.error('QR generation failed:', e);
    qrBox.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">Не удалось построить QR-код. Скопируйте ссылку.</div>';
  }
  // Вкладка Clash в этот момент скрыта — QRCode рисует в canvas фиксированного
  // размера, так что это не мешает. Кодируем Config URL, а не YAML: профиль
  // целиком в QR не помещается.
  const clashQr = document.getElementById('clashQrBox');
  if (clashQr) {
    clashQr.innerHTML = '';
    if (!_currentClashConfUrl) {
      clashQr.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">' + noToken + '</div>';
    } else if (typeof QRCode === 'undefined') {
      clashQr.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">QR-код недоступен (библиотека не загрузилась). Скопируйте ссылку.</div>';
    } else {
      try {
        new QRCode(clashQr, {
          text: _currentClashConfUrl,
          width: 220,
          height: 220,
          correctLevel: QRCode.CorrectLevel.M
        });
      } catch (e) {
        console.error('Clash QR generation failed:', e);
        clashQr.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">Не удалось построить QR-код. Скопируйте ссылку.</div>';
      }
    }
  }
  // Shadowrocket: QR со схемами из его мануала (URL-Schemes) — подписка
  // shadowrocket://add/{url}, конфиг shadowrocket://config/add/{url}. Камера
  // iPhone открывает приложение, длинную ссылку набирать не нужно.
  _renderUrlQr('srSubQrBox', _currentSubUrl ? 'shadowrocket://add/' + _currentSubUrl : '', noToken);
  _renderUrlQr('srConfQrBox', _currentShadowConfUrl ? 'shadowrocket://config/add/' + _currentShadowConfUrl : '', noToken);
  switchCfgTab('vless');
  document.getElementById('xrayConfigModal').classList.remove('hidden');
}

function _renderUrlQr(boxId, text, emptyMsg) {
  const box = document.getElementById(boxId);
  if (!box) return;
  box.innerHTML = '';
  const msg = (t) => { box.innerHTML = '<div style="color:#666;padding:20px;font-size:13px;">' + t + '</div>'; };
  if (!text) return msg(emptyMsg || 'Ссылки нет');
  if (typeof QRCode === 'undefined') return msg('QR-код недоступен (библиотека не загрузилась). Скопируйте ссылку.');
  try {
    new QRCode(box, {text: text, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M});
  } catch (e) {
    console.error('QR generation failed:', e);
    msg('Не удалось построить QR-код. Скопируйте ссылку.');
  }
}

function switchCfgTab(which) {
  const tabs = ['vless', 'shadow', 'loon', 'clash', 'xdns'];
  tabs.forEach(t => {
    const tabBtn = {
      vless: 'cfgTabVless', shadow: 'cfgTabShadow', loon: 'cfgTabLoon', clash: 'cfgTabClash', xdns: 'cfgTabXdns'
    }[t];
    const pane = {
      vless: 'cfgPaneVless', shadow: 'cfgPaneShadow', loon: 'cfgPaneLoon', clash: 'cfgPaneClash', xdns: 'cfgPaneXdns'
    }[t];
    document.getElementById(tabBtn).classList.toggle('active', t === which);
    document.getElementById(pane).classList.toggle('hidden', t !== which);
  });
  // На телефоне полоса вкладок прокручивается — активная не должна оставаться за краем.
  const act = document.querySelector('#xrayConfigModal .cfg-tab.active');
  if (act && act.scrollIntoView) act.scrollIntoView({block: 'nearest', inline: 'nearest'});
}

function showXrayDelete(uuid, name) {
  document.getElementById('xrayDeleteName').textContent = name;
  document.getElementById('xrayConfirmDeleteBtn').onclick = async () => {
    const res = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid), {method: 'DELETE'});
    if (res.ok) {
      closeModal('xrayDeleteModal');
      refreshXray();
      toast('Клиент «' + name + '» удалён');
    } else {
      toast('Ошибка удаления клиента');
    }
  };
  document.getElementById('xrayDeleteModal').classList.remove('hidden');
}

function showXrayRename(uuid, name) {
  document.getElementById('xrayRenameInput').value = name;
  document.getElementById('xrayConfirmRenameBtn').onclick = async () => {
    const newName = document.getElementById('xrayRenameInput').value.trim();
    if (!newName) return;
    const res = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/rename', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: newName})
    });
    if (res.ok) {
      closeModal('xrayRenameModal');
      refreshXray();
      toast('Переименовано в «' + newName + '»');
    } else {
      toast('Ошибка переименования');
    }
  };
  document.getElementById('xrayRenameModal').classList.remove('hidden');
  document.getElementById('xrayRenameInput').focus();
}

document.getElementById('xrayRenameInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('xrayConfirmRenameBtn').click();
});

// ============================================================
// MTProto (mtg)
// ============================================================
let _mtgLink = '';

async function refreshMtgRecipients() {
  const box = document.getElementById('mtgRecipientsList');
  if (!box) return;
  try {
    const res = await fetch(API + '/api/mtg/recipients');
    if (!res.ok) return;
    const data = await res.json();
    const items = (data.recipients || []);
    const rows = items.map(r => {
      const id = escAttr(r.id);
      const name = escHtml(r.name || '');
      const nameAttr = escAttr(r.name || '');
      return `<div style="display:flex;align-items:center;gap:4px;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg2,#1a1a1a);min-width:0;">
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;" title="${name}">${name}</span>
        <button class="mtg-rec-icon" data-act="rename" data-id="${id}" data-name="${nameAttr}" title="Переименовать" aria-label="Переименовать">${_pencilSvg()}</button>
        <button class="mtg-rec-icon danger" data-act="delete" data-id="${id}" data-name="${nameAttr}" title="Удалить" aria-label="Удалить">${_trashSvg()}</button>
      </div>`;
    }).join('');
    const addCell = `<button data-act="add" class="mtg-rec-add" title="Добавить запись" aria-label="Добавить запись" style="display:flex;align-items:center;justify-content:center;gap:4px;padding:4px 8px;border:1px dashed var(--border);border-radius:6px;background:transparent;color:var(--text3);min-width:0;cursor:pointer;font-size:13px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></button>`;
    box.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px;">${rows}${addCell}</div>`;
    box.querySelectorAll('button[data-act]').forEach(b => {
      b.addEventListener('click', () => {
        const act = b.getAttribute('data-act');
        if (act === 'add') { addMtgRecipient(); return; }
        const id = b.getAttribute('data-id');
        const name = b.getAttribute('data-name') || '';
        if (act === 'rename') renameMtgRecipient(id, name);
        else deleteMtgRecipient(id, name);
      });
    });
  } catch (e) {
    console.error('MTG recipients refresh failed:', e);
  }
}

let _mtgRecipientEdit = null; // {id, name} при редактировании, null при добавлении

function _openMtgRecipientModal(mode, id, currentName) {
  _mtgRecipientEdit = (mode === 'edit') ? {id, name: currentName || ''} : null;
  document.getElementById('mtgRecipientModalTitle').textContent =
    (mode === 'edit') ? 'Переименовать запись' : 'Добавить получателя';
  const input = document.getElementById('mtgRecipientInput');
  input.value = currentName || '';
  document.getElementById('mtgRecipientModal').classList.remove('hidden');
  setTimeout(() => { input.focus(); input.select(); }, 30);
}

function addMtgRecipient() {
  _openMtgRecipientModal('add', null, '');
}

function renameMtgRecipient(id, currentName) {
  _openMtgRecipientModal('edit', id, currentName);
}

async function submitMtgRecipient() {
  const input = document.getElementById('mtgRecipientInput');
  const trimmed = (input.value || '').trim();
  if (!trimmed) { toast('Имя пустое'); input.focus(); return; }
  const btn = document.getElementById('mtgRecipientSaveBtn');
  btn.disabled = true;
  try {
    let res;
    if (_mtgRecipientEdit) {
      if (trimmed === _mtgRecipientEdit.name) { closeModal('mtgRecipientModal'); return; }
      res = await fetch(API + '/api/mtg/recipients/' + encodeURIComponent(_mtgRecipientEdit.id), {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: trimmed})
      });
    } else {
      res = await fetch(API + '/api/mtg/recipients', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: trimmed})
      });
    }
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      closeModal('mtgRecipientModal');
      refreshMtgRecipients();
      toast(_mtgRecipientEdit ? 'Переименовано' : 'Добавлено');
    } else {
      toast((data && data.error) || ('HTTP ' + res.status));
    }
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById('mtgRecipientInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); submitMtgRecipient(); }
});

let _mtgRecipientDelete = null; // {id, name}

function deleteMtgRecipient(id, name) {
  _mtgRecipientDelete = {id, name: name || ''};
  document.getElementById('mtgRecipientDeleteName').textContent = name || '';
  document.getElementById('mtgRecipientDeleteModal').classList.remove('hidden');
}

async function confirmDeleteMtgRecipient() {
  if (!_mtgRecipientDelete) return;
  const btn = document.getElementById('mtgRecipientDeleteBtn');
  btn.disabled = true;
  try {
    const res = await fetch(API + '/api/mtg/recipients/' + encodeURIComponent(_mtgRecipientDelete.id), {method: 'DELETE'});
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      closeModal('mtgRecipientDeleteModal');
      _mtgRecipientDelete = null;
      refreshMtgRecipients();
      toast('Удалено');
    } else {
      toast((data && data.error) || ('HTTP ' + res.status));
    }
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function refreshMtg() {
  try {
    const res = await fetch(API + '/api/mtg/status');
    if (res.status === 401) { doLogout(); return; }
    const data = await res.json();
    const transitional = ['activating', 'deactivating', 'reloading'].includes(data.unit_state);
    renderProtoState(document.getElementById('mtgService'), transitional ? 'restarting' : data.state, data.running);
    _paintInstallBanner('mtg', data.state);
    _protoRunning.mtg = !!data.running;
    _updateHeaderDot();
    _mtgSchedule = {action: data.scheduled_action || null, date: data.scheduled_at || null};
    const mtgSched = document.getElementById('mtgScheduleBtn');
    if (mtgSched) mtgSched.classList.toggle('is-active', !!data.scheduled_action);
    const preferIp4 = (data.prefer_ip === 'prefer-ipv4' || data.prefer_ip === 'only-ipv4');
    _mtgFlags = {preferIp4};
    const piToggle = document.getElementById('mtgPreferIpToggle');
    if (piToggle) piToggle.checked = preferIp4;
    const piRow = document.getElementById('rowMtgPreferIp');
    if (piRow) piRow.classList.toggle('is-on', preferIp4);
    document.getElementById('mtgPort').textContent = (data.port != null && data.port !== '') ? data.port : '—';
    refreshPortConflict('mtg');
    _setStatOrPending(document.getElementById('mtgFake'), data.fake_host || '—');
    if (data.port != null || data.fake_host) {
      _writeCardCache({mtg: {
        port: (data.port != null && data.port !== '') ? data.port : undefined,
        fake_host: data.fake_host || undefined,
      }});
    }
    document.getElementById('mtgLink').textContent = data.link || '(не настроен)';
    document.getElementById('mtgSecret').textContent = data.secret || '(нет секрета)';
    const sc = document.getElementById('mtgSecretCreated');
    if (data.secret_created) {
      const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2})/.exec(data.secret_created);
      sc.textContent = (_i18nEn() ? 'Secret from ' : 'Секрет от ') + (m ?(m[3] + '.' + m[2] + '.' + m[1] + ' ' + m[4]) : data.secret_created);
      sc.style.display = '';
    } else {
      sc.style.display = 'none';
    }
    _mtgLink = data.link || '';
    const qr = document.getElementById('mtgQrBox');
    qr.innerHTML = '';
    if (_mtgLink) {
      try {
        if (typeof QRCode !== 'undefined') {
          new QRCode(qr, {
            text: _mtgLink,
            width: 200,
            height: 200,
            correctLevel: QRCode.CorrectLevel.M
          });
        } else {
          qr.innerHTML = '<div style="color:#666;padding:30px;font-size:13px;">QR недоступен</div>';
        }
      } catch (e) {
        console.error('QR generation failed:', e);
      }
    }
  } catch (e) {
    console.error('MTG refresh failed:', e);
  }
  refreshMtgRecipients();
}

function copyMtgLink() {
  if (!_mtgLink) { toast('Ссылка пуста'); return; }
  navigator.clipboard.writeText(_mtgLink).then(() => toast('Ссылка скопирована'));
}

function openMtgLink() {
  if (!_mtgLink) { toast('Ссылка пуста'); return; }
  window.open(_mtgLink, '_blank', 'noopener');
}

// Ждёт, пока mtg снова станет active после рестарта. Держит busy-overlay с
// понятным текстом, различая «перезапускается» и «ждём». Возвращает true при успехе.
async function _waitMtgRunning() {
  const statusEl = document.getElementById('panelRestartStatus');
  // Пауза перед первым опросом: рестарт ставится в очередь (--no-block),
  // даём старому инстансу уйти, чтобы не «поймать» его ещё как active.
  await new Promise(r => setTimeout(r, 600));
  for (let tries = 1; tries <= 40; tries++) {
    let state = '';
    try {
      const sr = await fetch(API + '/api/mtg/status', {cache: 'no-store'});
      if (sr.ok) {
        const sd = await sr.json();
        if (sd.running) return true;
        state = sd.unit_state || '';
      }
    } catch (e) {}
    if (statusEl) {
      statusEl.textContent = ['activating', 'deactivating', 'reloading'].includes(state)
        ? `mtg перезапускается… (${tries})`
        : `Ждём запуска mtg… (${tries})`;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

async function onMtgPreferIpToggle(checked) {
  const ok = await openConfirm({
    title: checked ? 'Приоритет IPv4 к Telegram?' : 'Вернуть авто-выбор IP?',
    body: checked
      ? 'mtg будет подключаться к серверам Telegram сначала по IPv4 (prefer-ipv4), IPv6 останется как fallback. Помогает, когда у сервера есть IPv6-адрес, но нет рабочего маршрута наружу — соединение перестаёт зависать.\nСервис mtg перезапустится — Telegram-соединения оборвутся на пару секунд.'
      : 'Строка prefer-ip будет удалена из конфига, mtg вернётся к выбору IP по умолчанию.\nСервис mtg перезапустится — Telegram-соединения оборвутся на пару секунд.',
    okLabel: checked ? 'Включить' : 'Выключить',
  });
  if (!ok) {
    const t = document.getElementById('mtgPreferIpToggle');
    if (t) t.checked = !checked;
    return;
  }
  showBusyOverlay(checked ? 'Включаем приоритет IPv4…' : 'Возвращаем авто-выбор IP…', 'Перезапускаем mtg — обычно пара секунд');
  try {
    const res = await fetch(API + '/api/mtg/prefer-ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled: checked}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      hideBusyOverlay();
      toast(translateError(data.error) || 'Не удалось переключить');
      const t = document.getElementById('mtgPreferIpToggle');
      if (t) t.checked = !checked;
      return;
    }
    if (data.restarted === false) {
      await refreshMtg();
      toast('Настройка сохранена — mtg остановлен, применится при запуске');
      return;
    }
    const running = await _waitMtgRunning();
    await refreshMtg();
    if (running) toast(checked ? 'Приоритет IPv4 включён' : 'Авто-выбор IP возвращён');
    else toast('Настройка применена, но mtg ещё запускается — проверьте статус');
  } catch (e) {
    hideBusyOverlay();
    toast('Ошибка сети: ' + e.message);
    const t = document.getElementById('mtgPreferIpToggle');
    if (t) t.checked = !checked;
    return;
  } finally {
    hideBusyOverlay();
  }
}

async function regenerateMtg() {
  const ok = await openConfirm({
    title: 'Пересоздать секрет MTProto?',
    body: 'Текущая ссылка перестанет работать у всех, кому была выдана.\nСервис mtg будет перезапущен — Telegram-соединения оборвутся на пару секунд.',
    okLabel: 'Пересоздать',
    danger: true,
  });
  if (!ok) return;
  showBusyOverlay('Пересоздаём секрет…', 'Перезапускаем mtg — обычно пара секунд');
  try {
    const res = await fetch(API + '/api/mtg/regenerate', {method: 'POST'});
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      hideBusyOverlay();
      toast(translateError(data.error) || 'Ошибка пересоздания секрета');
      return;
    }
    if (data.restarted === false) {
      await refreshMtg();
      toast('Секрет пересоздан — mtg остановлен, новый секрет заработает при запуске');
      return;
    }
    const running = await _waitMtgRunning();
    await refreshMtg();
    toast(running ? 'Секрет пересоздан, mtg перезапущен'
                  : 'Секрет пересоздан, но mtg ещё запускается — проверьте статус');
  } catch (e) {
    toast('Ошибка сети: ' + e.message);
  } finally {
    hideBusyOverlay();
  }
}

async function toggleXrayRule(uuid, enabled) {
  const res = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/rule', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({bypass_ru: enabled})
  });
  if (res.ok) {
    refreshXray();
    toast(enabled ? 'RU-исключение включено' : 'RU-исключение выключено');
  } else {
    toast('Ошибка обновления правила');
    refreshXray();
  }
}

function toggleRuleSection(uuid, ev) {
  if (ev) ev.stopPropagation();
  if (_expandedRuleSections.has(uuid)) _expandedRuleSections.delete(uuid);
  else _expandedRuleSections.add(uuid);
  // Re-render via cached last status — cheap to just refetch.
  refreshXray();
}

function togglePlatBlock(uuid, platform, ev) {
  if (ev) ev.stopPropagation();
  const key = uuid + ':' + platform;
  if (_expandedRulePlatforms.has(key)) _expandedRulePlatforms.delete(key);
  else _expandedRulePlatforms.add(key);
  refreshXray();
}

async function setAllClientRuleLists(uuid, platform, enableAll) {
  if (_clientRuleListBusy[uuid]) return;
  _clientRuleListBusy[uuid] = true;
  try {
    const cat = _ruleListCatalog[platform] || [];
    const payload = {};
    payload[platform] = enableAll ? cat.map(r => r.id) : [];
    const r2 = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/rule-lists', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    if (r2.ok) {
      toast(enableAll ? 'Все ' + platform + ' включены' : 'Все ' + platform + ' выключены');
      refreshXray();
    } else {
      toast('Ошибка обновления списков');
      refreshXray();
    }
  } finally {
    _clientRuleListBusy[uuid] = false;
  }
}

// --- Per-client rule list selection ---
const _clientRuleListBusy = {};
async function toggleClientRuleList(uuid, platform, ruleId, enabled) {
  if (_clientRuleListBusy[uuid]) return;
  _clientRuleListBusy[uuid] = true;
  try {
    const res = await fetch(API + '/api/xray/status');
    if (!res.ok) { toast('Ошибка'); return; }
    const data = await res.json();
    const client = (data.clients || []).find(c => c.uuid === uuid);
    if (!client) { toast('Клиент не найден'); return; }
    const sel = clientRuleLists(client);
    const set = new Set(sel[platform]);
    if (enabled) set.add(ruleId); else set.delete(ruleId);
    const payload = {};
    payload[platform] = Array.from(set);
    const r2 = await fetch(API + '/api/xray/clients/' + encodeURIComponent(uuid) + '/rule-lists', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    if (r2.ok) {
      refreshXray();
    } else {
      toast('Ошибка обновления списка');
      refreshXray();
    }
  } finally {
    _clientRuleListBusy[uuid] = false;
  }
}

// --- Rule list catalog manager ---
async function showRuleListManager() {
  await loadRuleListCatalogInto();
  let initial = _rmCurrentTab || 'lists';
  if (initial !== 'lists' && initial !== 'global') initial = 'lists';
  switchRmTab(initial);
  _applyRmUi();
  document.getElementById('ruleListManagerModal').classList.remove('hidden');
}

function switchRmTab(platform) {
  _rmCurrentTab = platform;
  document.getElementById('rmTabLists').classList.toggle('active', platform === 'lists');
  document.getElementById('rmTabGlobal').classList.toggle('active', platform === 'global');
  document.getElementById('rmPaneLists').classList.toggle('hidden', platform !== 'lists');
  document.getElementById('rmPaneGlobal').classList.toggle('hidden', platform !== 'global');
}

async function loadRuleListCatalogInto() {
  try {
    const res = await fetch(API + '/api/xray/rule-lists');
    if (!res.ok) { toast('Не удалось загрузить каталог'); return; }
    const data = await res.json();
    // Backend may return {lists: <new>} or older shape
    _ruleListCatalog = normalizeCatalog(data.lists || data);
    renderRuleListManager();
  } catch (e) {
    console.error('rule-list load failed:', e);
  }
}

// Какие пути показывать в каталоге 'lists'. Панель хранит один канонический URL
// (Clash), а под платформу выводит его на лету — это зеркало серверного
// _rule_url_for_platform(), чтобы в UI были ровно те пути, что уедут в конфиг.
let _rmUrlPlatform = 'clash';

function _ruleUrlForPlatform(url, platform) {
  if (!url) return url;
  // Свои шаблоны byfox: /rules/<name>/{clash/rules.yaml | loon|shadowrocket/rules.list}
  let m = url.match(/^(https?:\/\/\S+\/data\/awg-panel\/rules\/[^/]+)\/(?:clash|loon|shadowrocket)\/rules\.(?:yaml|list)$/);
  if (m) {
    if (platform === 'clash') return `${m[1]}/clash/rules.yaml`;
    return `${m[1]}/${platform === 'shadowrocket' ? 'shadowrocket' : 'loon'}/rules.list`;
  }
  // blackmatrix7: /rule/{Shadowrocket|Loon|Clash}/<Name>/<Name>.{list|yaml}
  m = url.match(/^(https?:\/\/\S+\/rule)\/(?:Shadowrocket|Loon|Clash)\/(.+?)\/([^/]+)\.(?:list|yaml)$/);
  if (m) {
    if (platform === 'clash') return `${m[1]}/Clash/${m[2]}/${m[3]}.yaml`;
    return `${m[1]}/${platform === 'shadowrocket' ? 'Shadowrocket' : 'Loon'}/${m[2]}/${m[3]}.list`;
  }
  return url;   // произвольный URL юзера — как есть
}

// Поле правки показывает путь для платформы, выбранной в «Показать пути для», а
// каталог 'lists' хранит ОДИН канонический URL (clash) — платформенные выводятся
// на лету при сборке конфига. Поэтому то, что ввели, приводим обратно к clash.
// Произвольную ссылку конвертер не трогает, у 'global' переключателя платформ нет.
function _canonRuleUrl(platform, url) {
  return platform === 'lists' ? _ruleUrlForPlatform(url, 'clash') : url;
}

function setRmUrlPlatform(p) {
  _rmUrlPlatform = p;
  document.querySelectorAll('#rmPlatSwitch .rml-plat-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.plat === p);
  });
  renderRuleListManager();
}

// Свёртка справки и краткий вид каталога в модалке «Списки правил».
// Выбор запоминается в localStorage и переживает перезагрузку панели.
const RM_UI_KEY = 'awgPanel:rmUi:v1';
function _readRmUi() {
  try { return JSON.parse(localStorage.getItem(RM_UI_KEY) || '{}') || {}; }
  catch (_) { return {}; }
}
function _writeRmUi(patch) {
  try {
    const cur = _readRmUi();
    Object.assign(cur, patch);
    localStorage.setItem(RM_UI_KEY, JSON.stringify(cur));
  } catch (_) {}
}
// Свёртка каталога и справки — своя на каждой вкладке: у Lists и Global разный
// объём содержимого, общий флаг сворачивал бы обе разом.
let _rmCompact = !!_readRmUi().compact;
let _rmHelpCollapsed = !!_readRmUi().helpCollapsed;
let _rmCompactGlobal = !!_readRmUi().compactGlobal;
let _rmHelpCollapsedGlobal = !!_readRmUi().helpCollapsedGlobal;
// Сортировка каталога в модалке — ТОЛЬКО вид, данные не трогает: порядок записей
// = приоритет в конфиге. Режима «по дате добавления» нет — записи такого поля не
// хранят (id — slug от имени, не таймстемп), придумывать дату не из чего.
let _rmSort = _readRmUi().sort === 'name' ? 'name' : 'prio';
let _rmQuery = '';                       // не запоминаем: запрос живёт до закрытия

function _sortNumSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="10" y1="6" x2="21" y2="6"/><line x1="10" y1="12" x2="21" y2="12"/><line x1="10" y1="18" x2="21" y2="18"/><path d="M4 6h1v4"/><path d="M4 10h2"/><path d="M6 18H4c0-1 2-1.5 2-2.5S5 14 4 14.5"/></svg>';
}
function _sortAzSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 16l4 4 4-4"/><path d="M7 20V4"/><path d="M20 8h-5"/><path d="M15 10V6.5a2.5 2.5 0 0 1 5 0V10"/><path d="M15 14h5l-5 6h5"/></svg>';
}

function _setCollapseBtnState(btn, collapsed) {
  if (!btn) return;
  btn.classList.toggle('is-collapsed', collapsed);
  const t = collapsed ? 'Развернуть' : 'Свернуть';
  btn.title = t;
  btn.setAttribute('aria-label', t);
}

function _applyRmUi() {
  const body = document.getElementById('ruleListBodyLists');
  // На пустом каталоге сетку не включаем — там одна строка «Каталог пуст».
  const gridOn = _rmCompact && (_ruleListCatalog.lists || []).length > 0;
  if (body) body.classList.toggle('rml-compact', gridOn);
  const sortBtn = document.getElementById('rmSortBtn');
  if (sortBtn) {
    const byName = _rmSort === 'name';
    sortBtn.innerHTML = byName ? _sortAzSvg() : _sortNumSvg();
    const t = byName ? 'Сортировка: по имени' : 'Сортировка: по приоритету';
    sortBtn.title = t;
    sortBtn.setAttribute('aria-label', t);
  }
  _setCollapseBtnState(document.getElementById('rmCompactBtn'), _rmCompact);
  const help = document.getElementById('rmHelpLists');
  if (help) help.classList.toggle('collapsed', _rmHelpCollapsed);
  _setCollapseBtnState(document.getElementById('rmHelpToggle'), _rmHelpCollapsed);

  // Вкладка Global — та же пара «свернуть каталог / свернуть справку».
  const gBody = document.getElementById('ruleListBodyGlobal');
  const gGridOn = _rmCompactGlobal && (_ruleListCatalog.global || []).length > 0;
  if (gBody) gBody.classList.toggle('rml-compact', gGridOn);
  _setCollapseBtnState(document.getElementById('rmCompactBtnGlobal'), _rmCompactGlobal);
  const gHelp = document.getElementById('rmHelpGlobal');
  if (gHelp) gHelp.classList.toggle('collapsed', _rmHelpCollapsedGlobal);
  _setCollapseBtnState(document.getElementById('rmHelpToggleGlobal'), _rmHelpCollapsedGlobal);
}

function toggleRmCompact(tab) {
  cancelEditRuleList();   // в кратком виде формы редактирования не видно
  if (tab === 'global') {
    _rmCompactGlobal = !_rmCompactGlobal;
    _writeRmUi({compactGlobal: _rmCompactGlobal});
  } else {
    _rmCompact = !_rmCompact;
    _writeRmUi({compact: _rmCompact});
  }
  _applyRmUi();
}

function toggleRmHelp(tab) {
  if (tab === 'global') {
    _rmHelpCollapsedGlobal = !_rmHelpCollapsedGlobal;
    _writeRmUi({helpCollapsedGlobal: _rmHelpCollapsedGlobal});
  } else {
    _rmHelpCollapsed = !_rmHelpCollapsed;
    _writeRmUi({helpCollapsed: _rmHelpCollapsed});
  }
  _applyRmUi();
}

function toggleRmSort() {
  cancelEditRuleList();          // строки перерисуются — открытая форма потеряется
  _rmSort = _rmSort === 'name' ? 'prio' : 'name';
  _writeRmUi({sort: _rmSort});
  renderRuleListManager();
}

function onRmSearch(v) {
  _rmQuery = v || '';
  renderRuleListManager();
}

// Адрес для «открыть в новом окне» из ОДНОЙ строки правила. Вручную-списки хранятся
// как есть, поэтому строка бывает и голым доменом, и «DOMAIN-SUFFIX,example.com», и
// «IP-CIDR,1.2.3.4/32» (хвост вроде ,PROXY / ,no-resolve игнорируем). Открыть нечего у
// DOMAIN-KEYWORD и у подсетей шире /32 — там null, иконка гаснет.
function _ruleOpenUrl(line) {
  const s = (line || '').trim();
  // В «Вручную» строкой нередко пишут готовый URL — открываем его как есть. Проверка
  // идёт до разбора на тип: в URL есть слэши, а их дальше отбрасывают (иначе подсеть
  // «10.0.0.0/8» выдала бы себя за хост).
  if (/^https?:\/\/\S+$/i.test(s)) return s;
  const parts = s.split(',').map(p => p.trim());
  if (!parts[0]) return null;
  let host = null;
  if (parts.length === 1) {
    host = parts[0];                                   // голый домен или IP
  } else {
    const type = parts[0].toUpperCase();
    if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') host = parts[1];
    else if (type === 'IP-CIDR') {
      const m = (parts[1] || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/32)?$/);
      if (m) host = m[1];                              // /32 = один хост; шире — нет
    }
  }
  if (!host) return null;
  host = host.replace(/^\*\./, '').replace(/^\./, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 'https://' + host;
  // Домен = есть точка и нет служебных символов. Юникод (.рф) пропускаем осознанно.
  return /^[^\s,/*]+\.[^\s,/*]{2,}$/.test(host) ? 'https://' + host : null;
}

function _renderManagerPane(platform, bodyId) {
  const cat = _ruleListCatalog[platform] || [];
  const body = document.getElementById(bodyId);
  if (!cat.length) {
    body.innerHTML = '<div class="rule-list-empty" style="padding:14px 0;">Каталог пуст. Добавьте первый список ниже.</div>';
    return;
  }
  // Вид = каталог + фильтр по имени + сортировка. Позицию в КАТАЛОГЕ тащим с собой
  // (idx): это номер приоритета и он же решает, упёрлась ли запись в край списка.
  // Поиск и сортировка — только у 'lists': в 'global' своей строки-панели нет.
  const isMain = platform === 'lists';
  const q = isMain ? _rmQuery.trim().toLowerCase() : '';
  let view = cat.map((r, idx) => ({r, idx}));
  if (q) view = view.filter(x => (x.r.name || '').toLowerCase().includes(q));
  const byName = isMain && _rmSort === 'name';
  if (byName) view.sort((a, b) => _byRuleName(a.r, b.r));
  if (!view.length) {
    body.innerHTML = '<div class="rule-list-empty" style="padding:14px 0;">Ничего не найдено.</div>';
    return;
  }
  body.innerHTML = view.map(({r, idx}) => {
    const isUrl = !!r.url;
    const isRules = !!(r.rules && r.rules.length);
    const editKind = isRules ? 'rules' : 'url';
    const rulesText = (r.rules || []).join('\n');
    // В 'lists' показываем путь под выбранную платформу (как уедет в конфиг);
    // в 'global' платформы нет — там всегда канонический Clash-URL.
    const shownUrl = isUrl
      ? (platform === 'lists' ? _ruleUrlForPlatform(r.url, _rmUrlPlatform) : r.url)
      : '';
    let bodyHtml;
    if (isUrl) {
      bodyHtml = `<a href="${escAttr(shownUrl)}" target="_blank" rel="noopener">${escHtml(shownUrl)}</a>`;
    } else if (isRules) {
      bodyHtml = escHtml(r.rules.join('\n'));
    } else {
      bodyHtml = '—';
    }
    // Иконка «открыть» есть всегда, но гаснет когда открывать нечего: у списка на
    // несколько адресов открывать нечего конкретно, а одиночный адрес видно — его и
    // открываем (для URL-списков это сам файл правил).
    const openUrl = isUrl
      ? shownUrl
      : (isRules && r.rules.length === 1 ? _ruleOpenUrl(r.rules[0]) : null);
    const openBtn = openUrl
      ? `<button class="btn-act rml-open-icon" onclick="window.open('${escAttr(openUrl)}','_blank','noopener')" title="Открыть ссылку в новом окне" aria-label="Открыть ссылку в новом окне">${_extLinkSvg()}</button>`
      : `<button class="btn-act rml-open-icon" disabled title="${escAttr(isRules && r.rules.length > 1 ? 'В списке несколько адресов — открывать нечего' : 'В правиле нет адреса, который можно открыть')}" aria-label="Открыть ссылку в новом окне">${_extLinkSvg()}</button>`;

    const urlExt = (shownUrl.match(/\.(list|yaml)$/i) || ['', 'list'])[1].toLowerCase();
    const kindBadge = isRules
      ? '<span class="rule-mgr-card-kind">Свой список · ' + r.rules.length + '</span>'
      : '<span class="rule-mgr-card-kind">URL .' + urlExt + '</span>';

    // Политика: что клиент делает с попавшим под правило трафиком. Задаётся тут,
    // на сервере, и уезжает в конфиг как policy=/RULE-SET-политика. Дефолт 'proxy'
    // = прежнее поведение, поэтому у старых записей поля нет и всё работает как было.
    const pol = _rulePolicyOf(r);
    const polHtml = `<span class="rml-pol" role="group" aria-label="Политика правила">` +
      RULE_POLICY_BTNS.map(([val, label, hint]) =>
        `<button type="button" class="rml-pol-btn${pol === val ? ' active' : ''}" data-pol="${val}"` +
        ` title="${escAttr(hint)}"` +
        ` onclick="setRuleListPolicy('${platform}','${escAttr(r.id)}','${val}')">${label}</button>`
      ).join('') + `</span>`;

    // При сортировке по имени стрелки гасим: они меняют приоритет, но строка
    // осталась бы на месте (её позицию задаёт имя) — жать вслепую бессмысленно.
    // Тултип в этом режиме общий на все три — одной строкой в словаре дешевле,
    // чем тремя склейками «В самый верх — доступно…».
    const noMove = byName ? 'disabled' : '';
    const offTitle = 'Порядок меняется в сортировке по приоритету';
    return `
    <div class="rule-mgr-card" data-platform="${platform}" data-id="${escAttr(r.id)}">
      <div class="rml-view">
        <div class="rule-mgr-card-head">
          <div class="rml-head-main">
            <span class="rml-order" title="Порядок = приоритет в конфиге. Сохраняется сразу.">
              <span class="rml-num">${idx + 1}</span>
              <button type="button" class="rml-arrow rml-top" title="${byName ? offTitle : 'В самый верх'}" onclick="ruleListMoveTop('${platform}','${escAttr(r.id)}')" ${idx === 0 ? 'disabled' : noMove}>&#8657;</button>
              <button type="button" class="rml-arrow" title="${byName ? offTitle : 'Выше на один'}" onclick="ruleListMoveUp('${platform}','${escAttr(r.id)}')" ${idx === 0 ? 'disabled' : noMove}>&#8593;</button>
              <button type="button" class="rml-arrow" title="${byName ? offTitle : 'Ниже на один'}" onclick="ruleListMoveDown('${platform}','${escAttr(r.id)}')" ${idx === cat.length - 1 ? 'disabled' : noMove}>&#8595;</button>
            </span>
            <span class="rule-mgr-card-name">${escHtml(r.name)}</span>
            ${kindBadge}
          </div>
          <div class="rule-mgr-card-actions">
            ${polHtml}
            ${openBtn}
            <button class="btn-act rml-edit-icon" onclick="startEditRuleList('${platform}','${escAttr(r.id)}')" title="Редактировать" aria-label="Редактировать">${_pencilSvg()}</button>
            <button class="btn-act danger rml-del-icon" onclick="deleteRuleList('${platform}','${escAttr(r.id)}','${escAttr(r.name)}')" title="Удалить" aria-label="Удалить">${_trashSvg()}</button>
          </div>
        </div>
        <div class="rule-mgr-card-body">${bodyHtml}</div>
      </div>

      <div class="rml-edit hidden" style="display:flex;flex-direction:column;gap:10px;">
        <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;">Редактирование списка</div>
        <input type="text" data-edit-name placeholder="Название" value="${escAttr(r.name)}" style="margin:0;">
        <div style="display:flex;gap:14px;align-items:center;font-size:13px;color:var(--text2);">
          <label style="cursor:pointer;"><input type="radio" name="editKind_${escAttr(r.id)}" value="url" ${editKind === 'url' ? 'checked' : ''} onchange="_updEditKind('${platform}','${escAttr(r.id)}')"> URL .list файла</label>
          <label style="cursor:pointer;"><input type="radio" name="editKind_${escAttr(r.id)}" value="rules" ${editKind === 'rules' ? 'checked' : ''} onchange="_updEditKind('${platform}','${escAttr(r.id)}')"> Вручную</label>
          <label style="cursor:pointer;"><input type="radio" name="editKind_${escAttr(r.id)}" value="auto" onchange="_updEditKind('${platform}','${escAttr(r.id)}')"> Автоматический</label>
        </div>
        <div class="edit-auto-hint" style="display:none;font-size:12px;color:var(--text3);line-height:1.5;">Впишите сайты по одному на строку — каждый будет преобразован в правило, закрывающее все поддомены. Напр.: <code>xe.com → DOMAIN-SUFFIX,xe.com,PROXY</code>. Схему (https://, www., путь) можно не убирать.</div>
        <input class="edit-url" type="text" data-edit-url placeholder="https://.../Service.list" value="${escAttr(shownUrl || r.url || '')}" style="margin:0;font-family:'JetBrains Mono',monospace;font-size:13px;${editKind === 'url' ? '' : 'display:none;'}">
        <textarea class="edit-rules" data-edit-rules rows="7" placeholder="example.com&#10;1.2.3.4&#10;10.0.0.0/8" style="font-family:'JetBrains Mono',monospace;font-size:13px;width:100%;resize:vertical;min-height:140px;${editKind === 'rules' ? '' : 'display:none;'}">${escHtml(rulesText)}</textarea>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button class="btn btn-sm btn-ghost" onclick="cancelEditRuleList()">Отмена</button>
          <button class="btn btn-sm btn-success" onclick="saveEditRuleList('${platform}','${escAttr(r.id)}')">Сохранить</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

function _updNewKind(suffix) {
  const kind = document.querySelector(`input[name="new${suffix}Kind"]:checked`).value;
  const isUrl = kind === 'url';
  document.getElementById('new' + suffix + 'Url').classList.toggle('hidden', !isUrl);
  document.getElementById('new' + suffix + 'Rules').classList.toggle('hidden', isUrl);
  const hint = document.getElementById('new' + suffix + 'AutoHint');
  if (hint) hint.classList.toggle('hidden', kind !== 'auto');
  _updNewBtns(suffix);
}

// Преобразует строку-сайт в правило DOMAIN-SUFFIX, закрывающее все поддомены
// («xe.com» → «DOMAIN-SUFFIX,xe.com»; политика ,PROXY добавляется на этапе
// сборки конфига под платформу). IP → IP-CIDR. Комментарии/пустое — отбрасываются.
function _autoRuleLine(line) {
  let s = (line || '').trim();
  if (!s || s.startsWith('#') || s.startsWith('//') || s.startsWith(';')) return null;
  const m = s.match(/^\s*(?:https?:\/\/)?([^/?#\s]+)/i);
  if (m) s = m[1];
  if (s.includes(':') && !s.startsWith('[')) s = s.split(':')[0];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'IP-CIDR,' + s + '/32';
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s)) return 'IP-CIDR,' + s;
  s = s.replace(/^\*\./, '').replace(/^\./, '').replace(/^www\./i, '').replace(/\.+$/, '').toLowerCase();
  if (!s) return null;
  return 'DOMAIN-SUFFIX,' + s;
}
function _autoConvertRules(lines) {
  const out = [], seen = new Set();
  for (const ln of lines) {
    const r = _autoRuleLine(ln);
    if (r && !seen.has(r)) { seen.add(r); out.push(r); }
  }
  return out;
}

const _PLATFORM_OF_SFX = {Lists: 'lists', Global: 'global', Shadow: 'shadowrocket', Loon: 'loon', Clash: 'clash'};

function _ruleExt(platform) {
  return (platform === 'clash' || platform === 'global') ? '.yaml' : '.list';
}

function _updNewBtns(suffix) {
  const platform = _PLATFORM_OF_SFX[suffix];
  if (!platform) return;
  const kind = document.querySelector(`input[name="new${suffix}Kind"]:checked`).value;
  const name = document.getElementById('new' + suffix + 'Name').value.trim();
  const url = document.getElementById('new' + suffix + 'Url').value.trim();
  const rules = document.getElementById('new' + suffix + 'Rules').value.trim();
  const isRules = (kind === 'rules' || kind === 'auto');
  // Единый 'lists' принимает .list или .yaml; остальные — свой фикс. формат.
  const urlOk = /^https?:\/\//i.test(url) && (platform === 'lists'
    ? /\.(list|yaml)$/i.test(url)
    : url.toLowerCase().endsWith(_ruleExt(platform)));
  // «Добавить» активна только когда реально есть что добавить (имя + валидный ввод).
  const canAdd = !!name && (isRules ? !!rules : urlOk);
  const addBtn = document.getElementById('addBtn' + suffix);
  if (addBtn) addBtn.disabled = !canAdd;
  const tplBtn = document.getElementById('tplBtn' + suffix);
  if (tplBtn) tplBtn.disabled = (kind !== 'url');
}

// Полный список папок в blackmatrix7/ios_rule_script (rule/<platform>/<Name>/).
// Не все имена есть на всех трёх платформах — при добавлении URL 404 → юзер
// увидит ошибку загрузки и сможет убрать шаблон.
const TPL_SERVICES = [
  "115","12306","1337x","17173","178","17zuoye","2KGames","360","36kr","3Type",
  "3dm","4399","4Paradigm","4chan","51Job","51nod","56","58TongCheng","6JianFang","6park",
  "8btc","9News","9to5","ABC","AFP","ALJazeera","AMD","AMP","AOL","APKCombo",
  "ATTWatchTV","Abema","AbemaTV","AcFun","Accuweather","Acer","Acplay","Actalis","AdColony","AdGuardSDNSFilter",
  "AddToAny","Addthis","Adidas","Adobe","AdobeActivation","Advertising","AdvertisingLite","AdvertisingMiTV","AdvertisingTest","Aerogard",
  "Afdian","Agora","AiQiCha","AirChina","AirWick","Akamai","Ali213","AliPay","Alibaba","All4",
  "Amazon","AmazonCN","AmazonIP","AmazonPrimeVideo","AmazonTrust","Americasvoice","AnTianKeJi","Anaconda","AnandTech","Android",
  "Anime","Anjuke","Anonv","Anthropic","Antutu","Apifox","Apkpure","AppLovin","AppStore","Apple",
  "AppleDaily","AppleDev","AppleFirmware","AppleHardware","AppleID","AppleMail","AppleMedia","AppleMusic","AppleNews","AppleProxy",
  "AppleTV","Arphic","Asahi","AsianMedia","Assassin'sCreed","Atlassian","Atomdata","BBC","BMW","BOC",
  "BOCOM","Bahamut","BaiDuTieBa","BaiFenDian","BaiShanYunKeJi","Baidu","BaoFengYingYin","BardAI","Battle","BeStore",
  "Beats","BesTV","Bestbuy","BianFeng","BiliBili","BiliBiliIntl","Binance","Bing","Blizzard","BlockHttpDNS",
  "Bloomberg","Blued","BoXun","Bootcss","BrightCove","BritboxUK","Buypass","ByteDance","CAS","CBS",
  "CCB","CCTV","CEB","CETV","CGB","CHT","CIBN","CKJR","CMB","CNKI",
  "CNN","CNNIC","CSDN","CWSeed","CableTV","CaiNiao","CaiXinChuanMei","Cake","Camera360","Canon",
  "ChengTongWangPan","China","ChinaDNS","ChinaIPs","ChinaIPsBGP","ChinaMax","ChinaMaxNoIP","ChinaMaxNoMedia","ChinaMedia","ChinaMobile",
  "ChinaNews","ChinaNoMedia","ChinaTelecom","ChinaTest","ChinaUnicom","Chromecast","ChuangKeTie","ChunYou","Cisco","Civitai",
  "Classic","Claude","Cloud","Cloudflare","Cloudflarecn","Clubhouse","ClubhouseIP","Cnet","Collabora","Comodo",
  "Contentful","Coolapk","Copilot","Crypto","Cryptocurrency","CyberTrust","DAZN","DMM","DNS","DaMai",
  "Dailymail","Dailymotion","DanDanZan","Dandanplay","DangDang","Dedao","Deepin","Deezer","Dell","Developer",
  "DiDi","DiLianWangLuo","DiSiFanShi","DiabloIII","DianCeWangKe","DigiCert","DigitalOcean","DingTalk","DingXiangYuan","Direct",
  "Discord","DiscoveryPlus","Disney","Disqus","Docker","Domob","Dood","DouBan","DouYin","Douyu",
  "Download","Dropbox","DtDNS","Dubox","Duckduckgo","DuoWan","Duolingo","DynDNS","Dynu","EA",
  "EHGallery","EastMoney","EasyPrivacy","Electron","Eleme","Embl","Emby","Emojipedia","EncoreTVB","Entrust",
  "Epic","Espn","FOXNOW","FOXPlus","Facebook","FanFou","FangZhengDianZi","Faronics","FeiZhu","FengHuangWang",
  "FengXiaWangLuo","Figma","Fiio","FindMy","FitnessPlus","FlipBoard","Flurry","Fox","FreeCodeCamp","FuboTV",
  "Funshion","Game","GaoDe","Garena","Geely","Gettyimages","Gigabyte","GitBook","GitHub","GitLab",
  "Gitee","Global","GlobalMedia","GlobalScholar","GlobalSign","Gog","Google","GoogleDrive","GoogleEarth","GoogleFCM",
  "GoogleSearch","GoogleVoice","GovCN","Gucci","GuiGuDongLi","HBO","HBOAsia","HBOHK","HBOUSA","HKBN",
  "HKOpenTV","HKedcity","HP","HWTV","HaiNanHangKong","HamiVideo","HanYi","HashiCorp","Haveibeenpwned","HeMa",
  "Hearthstone","HeroesoftheStorm","Heroku","HibyMusic","Hijacking","Himalaya","Hkgolden","HoYoverse","Hpplay","HuYa",
  "HuaShuTV","HuanJu","Huawei","Huffpost","Hulu","HuluJP","HuluUSA","HunanTV","Hupu","IBM",
  "ICBC","IKEA","IMDB","IPTVMainland","IPTVOther","ITV","Identrust","Imgur","Instagram","Intel",
  "Intercom","JOOX","Japonx","Jetbrains","Jfrog","JiGuangTuiSong","JianGuoYun","JianShu","JinJiangWenXue","JingDong",
  "Jquery","Jsdelivr","JueJin","Jwplayer","KKBOX","KKTV","KakaoTalk","Kantv","Keep","KingSmith",
  "Kingsoft","KouDaiShiShang","Ku6","KuKeMusic","KuaiDi100","KuaiShou","KuangShi","KugouKuwo","LG","Lan",
  "LanZouYun","LastFM","LastPass","LeJu","LeTV","Lenovo","LiTV","LianMeng","Limelight","Line",
  "LineTV","Linguee","LinkedIn","Linux","LivePerson","Logitech","LondonReal","LuDaShi","LvMiLianChuang","MEGA",
  "MIUIPrivacy","MOMOShop","MOOV","Mail","Mailru","Majsoul","Manorama","Maocloud","Marketing","McDonalds",
  "MeWatch","MeiTu","MeiTuan","MeiZu","MiWu","Microsoft","MicrosoftEdge","Migu","MingLueZhaoHui","Mogujie",
  "Mojitianqi","Movefree","Mozilla","My5","NBC","NGA","NGAA","NTPService","NYPost","NYTimes",
  "NaSDDNS","Naver","NaverTV","NetEase","NetEaseMusic","Netflix","Niconico","Nike","Nikkei","Nintendo",
  "NivodTV","Notion","NowE","Npmjs","Nvidia","OKX","OP","OPPO","Olevod","OneDrive",
  "OnePlus","OpenAI","Opera","Oracle","Oreilly","Origin","OuPeng","Overcast","Overwatch","PBS",
  "PCCW","PChome","PChomeTW","PPTV","PSBC","Pandora","PandoraTV","ParamountPlus","Patreon","PayPal",
  "Peacock","Picacg","Picsee","PikPak","Pinduoduo","PingAn","Pinterest","Pixiv","Pixnet","PlayStation",
  "PotatoChat","PrimeVideo","Privacy","PrivateTracker","Protonmail","Proxy","ProxyLite","Pubmatic","Purikonejp","Python",
  "QiNiuYun","QingCloud","Qobuz","Qualcomm","QuickConnect","Qyyjt","RTHK","Rakuten","Rarbg","Razer",
  "Reabble","Reddit","RemoteDesktop","Riot","Rockstar","RuanMei","SFExpress","SMG","SMZDM","STUN",
  "Salesforce","Samsung","Scaleflex","Scholar","Sectigo","ShangHaiJuXiao","Shanling","Sharethis","ShenMa","ShiJiChaoXing",
  "ShiNongZhiKe","Shopee","Shopify","Sina","Siri","SkyGO","Slack","SlideShare","Sling","SmarTone",
  "Snap","Sohu","Sony","SouFang","SoundCloud","SourceForge","Spark","Speedtest","Spotify","Stackexchange",
  "StarCraftII","Starbucks","Steam","SteamCN","Stripe","SuNing","SublimeText","SuiShiChuanMei","Supercell","Synology",
  "SystemOTA","TCL","TIDAL","TVB","TVer","TaiKang","TaiWanGood","TaiheMusic","TapTap","TeamViewer",
  "Teambition","Teams","Telegram","TelegramNL","TelegramSG","TelegramUS","Tencent","TencentVideo","TeraBox","Tesla",
  "TestFlight","ThomsonReuters","Threads","TianTianKanKan","TianWeiChengXin","TianYaForum","TigerFintech","TikTok","Tmdb","TongCheng",
  "TrustWave","TruthSocial","Tumblr","Twitch","Twitter","U17","UBI","UC","UCloud","UKMedia",
  "UPYun","USMedia","Ubisoft","Ubuntu","Udacity","UnionPay","Unity","VISA","VK","VOA",
  "Vancl","Vercel","Verisign","Verizon","VidolTV","VikACG","Viki","Vimeo","VipShop","ViuTV",
  "Vivo","Voxmedia","W3schools","WIX","WanKaHuanJu","WanMeiShiJie","Wanfang","WangSuKeJi","WangXinKeJi","WeChat",
  "WeTV","WeType","WeiZhiYunDong","Weibo","WenJuanXing","Westerndigital","Whatsapp","WiFiMaster","Wikimedia","Wikipedia",
  "WildRift","WoLai","Wordpress","WorldofWarcraft","Wteam","Xbox","XiamiMusic","XianYu","XiaoGouKeJi","XiaoHongShu",
  "XiaoMi","XiaoYuanKeJi","XieCheng","XingKongWuXian","XueErSi","XueQiu","Xunlei","YYeTs","Yandex","YiChe",
  "YiXiaKeJi","YiZhiBo","YouMengChuangXiang","YouTube","YouTubeMusic","YouZan","Youku","YuanFuDao","YunFanJiaSu","ZDNS",
  "Zalo","Zee","ZeeTV","Zendesk","ZhangYue","ZhiYinManKe","ZhiYunZhong","Zhihu","ZhihuAds","ZhongGuoShiHua",
  "ZhongWeiShiJi","ZhongXingTongXun","ZhongYuanYiShang","ZhuanZhuan","Zoho","aiXcoder","eBay","friDay","iCloud","iCloudPrivateRelay",
  "iFlytek","iQIYI","iQIYIIntl","iTalkBB","ifanr","myTVSUPER","zhanqi"
];

// Свои шаблоны (byfox): /rules/<name>/{clash/rules.yaml | loon|shadowrocket/rules.list}
let _tplOwn = new Set();
function _byfoxUrlFor(platform, name) {
  const p = (platform === 'shadowrocket') ? 'shadowrocket' : (platform === 'loon') ? 'loon' : 'clash';
  const file = (p === 'clash') ? 'rules.yaml' : 'rules.list';
  return `https://byfox.dev/data/awg-panel/rules/${encodeURIComponent(name)}/${p}/${file}`;
}
// У blackmatrix7 обычно <Имя>/<Имя>.list. Но самые большие списки разбиты надвое:
// в <Имя>.list остаются только DOMAIN-KEYWORD/IP-CIDR/URL-REGEX, а все домены —
// в <Имя>_Domain.list. Брать первый файл = молча получить огрызок: у Advertising
// это 781 строка и НОЛЬ доменов вместо 257 094.
// У AdGuardSDNSFilter и EasyPrivacy файла <Имя>.list нет вовсе — только _Domain.
// Список сверен по всем 667 шаблонам из blackmatrix7.txt (HEAD на оба имени);
// пересверить при заметном обновлении каталога bm7.
const TPL_DOMAIN_SPLIT = new Set([
  'Advertising', 'AdvertisingLite', 'AdvertisingTest', 'AdGuardSDNSFilter',
  'EasyPrivacy', 'Privacy', 'Apple', 'Alibaba', 'Tencent', 'Global',
  'GlobalMedia', 'Proxy', 'China', 'ChinaMax', 'ChinaMaxNoIP',
  'ChinaMaxNoMedia', 'ChinaNoMedia', 'ChinaTest', 'IPTVOther',
]);

function _tplUrlFor(platform, name) {
  if (_tplOwn.has(name)) return _byfoxUrlFor(platform, name);
  let urlPlat, ext;
  if (platform === 'shadowrocket')      { urlPlat = 'Shadowrocket'; ext = '.list'; }
  else if (platform === 'loon')         { urlPlat = 'Loon';         ext = '.list'; }
  else                                  { urlPlat = 'Clash';        ext = '.yaml'; }
  const file = TPL_DOMAIN_SPLIT.has(name) ? `${name}_Domain` : name;
  return `https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/${urlPlat}/${encodeURIComponent(name)}/${encodeURIComponent(file)}${ext}`;
}

// Живая библиотека шаблонов: сервер обновляет её из blackmatrix7.txt раз в 7 дней
// (/api/xray/rule-templates). TPL_SERVICES — вшитый фолбэк, если кэша ещё нет.
let _tplServices = TPL_SERVICES;
let _tplServicesLoaded = false;
async function loadRuleTemplates() {
  try {
    const res = await fetch(API + '/api/xray/rule-templates');
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.services) && data.services.length) _tplServices = data.services;
      if (Array.isArray(data.own)) _tplOwn = new Set(data.own);
    }
  } catch (e) { /* фолбэк на вшитый TPL_SERVICES */ }
  _tplServicesLoaded = true;
}

let _tplPlatform = null;

async function openTemplatePicker(platform) {
  _tplPlatform = platform;
  const titles = {lists: 'Шаблоны', global: 'Шаблоны — Clash (Global)', shadowrocket: 'Шаблоны — Shadowrocket', loon: 'Шаблоны — Loon', clash: 'Шаблоны — Clash'};
  document.getElementById('tplModalTitle').textContent = titles[platform] || 'Шаблоны';
  document.getElementById('tplSearch').value = '';
  _renderTemplates();
  document.getElementById('templatePickerModal').classList.remove('hidden');
  setTimeout(() => { const s = document.getElementById('tplSearch'); if (s) s.focus(); }, 50);
  if (!_tplServicesLoaded) { await loadRuleTemplates(); if (_tplPlatform === platform) _renderTemplates(); }
}

function _renderTemplates() {
  const platform = _tplPlatform;
  const q = document.getElementById('tplSearch').value.trim().toLowerCase();
  const list = document.getElementById('tplList');
  const existingUrls = new Set();
  const cat = (typeof _ruleListCatalog === 'object' && _ruleListCatalog) ? (_ruleListCatalog[platform] || []) : [];
  cat.forEach(r => { if (r && r.url) existingUrls.add(String(r.url).trim().toLowerCase()); });
  const all = [...new Set([..._tplOwn, ..._tplServices])].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  const available = all.filter(s => !existingUrls.has(_tplUrlFor(platform, s).toLowerCase()));
  const filtered = q ? available.filter(s => s.toLowerCase().includes(q)) : available;
  if (!filtered.length) {
    const msg = available.length === 0 ? 'Все шаблоны уже добавлены.' : 'Ничего не найдено.';
    list.innerHTML = `<div style="color:var(--text3);font-size:13px;padding:12px;grid-column:1/-1;text-align:center;">${msg}</div>`;
    return;
  }
  list.innerHTML = filtered.map(s => {
    const safe = s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    return `<button type="button" class="btn btn-sm btn-ghost tpl-cell" onclick="_pickTemplate('${s.replace(/'/g, "\\'")}')" title="${safe}">${safe}</button>`;
  }).join('');
}

function _pickTemplate(name) {
  const platform = _tplPlatform;
  if (!platform) return;
  const sfx = {lists: 'Lists', global: 'Global', shadowrocket: 'Shadow', loon: 'Loon', clash: 'Clash'}[platform];
  const url = _tplUrlFor(platform, name);
  const urlRadio = document.querySelector(`input[name="new${sfx}Kind"][value="url"]`);
  if (urlRadio && !urlRadio.checked) { urlRadio.checked = true; _updNewKind(sfx); }
  document.getElementById('new' + sfx + 'Name').value = name;
  document.getElementById('new' + sfx + 'Url').value = url;
  _updNewBtns(sfx);
  closeModal('templatePickerModal');
}

function _updEditKind(platform, id) {
  const row = document.querySelector(`[data-platform="${platform}"][data-id="${CSS.escape(id)}"]`);
  if (!row) return;
  const kind = row.querySelector(`input[name="editKind_${id}"]:checked`).value;
  // 'auto' — тот же textarea, что и «Вручную»: разница только в том, что при
  // сохранении строки прогоняются через _autoConvertRules (сайт → DOMAIN-SUFFIX).
  row.querySelector('.edit-url').style.display = kind === 'url' ? '' : 'none';
  row.querySelector('.edit-rules').style.display = kind === 'url' ? 'none' : '';
  const hint = row.querySelector('.edit-auto-hint');
  if (hint) hint.style.display = kind === 'auto' ? '' : 'none';
}

function _setRowMode(row, editing) {
  row.querySelectorAll('.rml-view').forEach(el => el.classList.toggle('hidden', editing));
  row.querySelectorAll('.rml-edit').forEach(el => el.classList.toggle('hidden', !editing));
}

let _editingRow = null;

function cancelEditRuleList() {
  if (_editingRow) {
    _setRowMode(_editingRow, false);
    _editingRow = null;
  }
}

function startEditRuleList(platform, id) {
  cancelEditRuleList();
  const row = document.querySelector(`[data-platform="${platform}"][data-id="${CSS.escape(id)}"]`);
  if (!row) return;
  _setRowMode(row, true);
  _editingRow = row;
  const nameInput = row.querySelector('[data-edit-name]');
  if (nameInput) nameInput.focus();
}

async function saveEditRuleList(platform, id) {
  const row = document.querySelector(`[data-platform="${platform}"][data-id="${CSS.escape(id)}"]`);
  if (!row) return;
  const name = row.querySelector('[data-edit-name]').value.trim();
  const kind = row.querySelector(`input[name="editKind_${id}"]:checked`).value;
  if (!name) { toast('Имя обязательно'); return; }
  // Look at whichever field is currently visible / filled.
  const url = (row.querySelector('[data-edit-url]').value || '').trim();
  const rulesText = row.querySelector('[data-edit-rules]').value || '';
  const rules = rulesText.split('\n').map(s => s.trim()).filter(Boolean);
  const payload = {name};
  if (kind === 'auto' && rules.length) {
    const conv = _autoConvertRules(rules);
    if (!conv.length) { toast('Не распознал ни одного сайта или IP'); return; }
    payload.rules = conv;
  } else if (kind === 'rules' && rules.length) {
    payload.rules = rules;
  } else if (kind === 'url' && url) {
    if (!/^https?:\/\//.test(url)) {
      toast('Если это URL .list — он должен начинаться с http(s)://. Если это домены/IP — переключите на «Свой список».');
      return;
    }
    payload.url = _canonRuleUrl(platform, url);
  } else if (rules.length) {
    payload.rules = rules;
  } else if (url) {
    if (!/^https?:\/\//.test(url)) {
      toast('Если это URL .list — он должен начинаться с http(s)://. Если это домены/IP — переключите на «Свой список».');
      return;
    }
    payload.url = _canonRuleUrl(platform, url);
  } else {
    toast('Заполните URL или список правил');
    return;
  }
  const res = await fetch(
    API + '/api/xray/rule-lists/' + encodeURIComponent(platform) + '/' + encodeURIComponent(id),
    {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }
  );
  const data = await res.json();
  if (res.ok) {
    toast('Список обновлён');
    _editingRow = null;
    await loadRuleListCatalogInto();
    refreshXray();
  } else {
    toast(translateError(data.error) || 'Ошибка сохранения');
  }
}

function renderRuleListManager() {
  _renderManagerPane('lists', 'ruleListBodyLists');
  _renderManagerPane('global', 'ruleListBodyGlobal');
  _applyRmUi();
}

// Политика правила: что клиент делает с трафиком, попавшим под это правило.
// Порядок кнопок и подписи заданы явно; 'proxy' — дефолт и прежнее поведение.
const RULE_POLICY_BTNS = [
  ['direct', 'Direct', 'Напрямую, мимо VPN'],
  ['reject', 'Block',  'Заблокировать'],
  ['proxy',  'VPN',    'Через VPN (группа прокси)'],
];

function _rulePolicyOf(r) {
  const p = String((r && r.policy) || 'proxy').toLowerCase();
  return RULE_POLICY_BTNS.some(([v]) => v === p) ? p : 'proxy';
}

// Как и порядок — сохраняется сразу по клику, отдельной кнопки нет.
async function setRuleListPolicy(platform, id, policy) {
  const arr = _ruleListCatalog[platform] || [];
  const row = arr.find(r => String(r.id) === String(id));
  if (!row || _rulePolicyOf(row) === policy) return;
  const prev = row.policy;
  row.policy = policy;
  renderRuleListManager();
  const res = await fetch(API + '/api/xray/rule-lists/' + encodeURIComponent(platform) +
                          '/' + encodeURIComponent(id) + '/policy', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({policy}),
  });
  if (!res.ok) {
    row.policy = prev;
    toast('Ошибка сохранения политики');
    renderRuleListManager();
    return;
  }
  refreshXray();
}

// --- Персональная политика правила (только у одного клиента) ---------------
// Каталожная policy — общая для всех, но одному клиенту список бывает нужен с
// другой политикой (кому Block, кому Direct). Это переопределение живёт на
// клиенте (rule_policy) и видно только в его профиле.
function _clientRulePolicyMap(c) {
  const ov = c && c.rule_policy;
  if (!ov || typeof ov !== 'object') return {};
  const out = {};
  Object.keys(ov).forEach(k => {
    const v = String(ov[k] || '').toLowerCase();
    if (RULE_POLICY_BTNS.some(([val]) => val === v)) out[k] = v;
  });
  return out;
}

// Выбор политики = выбор ОДНОГО значения из трёх, поэтому не модалка с
// оверлеем, а поповер у самого бейджа: клик по варианту сразу применяет.
// Значение, совпавшее с каталогом, переопределением не пишется (отправляем
// policy=''), поэтому смена политики в каталоге такого клиента снова догонит.
let _rulePolPop = null, _rulePolPopAnchor = null, _rulePolPopGuard = false;

function closeRulePolPop() {
  if (!_rulePolPop) return;
  _rulePolPop.remove();
  _rulePolPop = null;
  _rulePolPopAnchor = null;
  document.removeEventListener('mousedown', _rulePolPopOutside, true);
  document.removeEventListener('keydown', _rulePolPopKey, true);
  window.removeEventListener('scroll', closeRulePolPop, true);
  window.removeEventListener('resize', closeRulePolPop);
}
function _rulePolPopOutside(e) {
  if (!_rulePolPop || _rulePolPop.contains(e.target)) return;
  // Повторный клик по тому же бейджу должен закрывать, а не закрыть-и-открыть:
  // mousedown закрывает, и следующий за ним click съедается этим флагом.
  _rulePolPopGuard = !!(_rulePolPopAnchor && _rulePolPopAnchor.contains(e.target));
  closeRulePolPop();
}
function _rulePolPopKey(e) {
  if (e.key === 'Escape') { e.stopPropagation(); closeRulePolPop(); }
}

function openRulePolPop(el) {
  const uuid = el.dataset.uuid, platform = el.dataset.plat, ruleId = el.dataset.rid;
  // Поповер общий для протоколов: чей это клиент — говорит data-kind бейджа.
  const kind = el.dataset.kind || 'xray';
  const c = _protoFindClient(kind, uuid);
  if (!c) return;
  closeRulePolPop();
  const catRow = (_ruleListCatalog[platform] || []).find(r => String(r.id) === String(ruleId));
  const catPol = _rulePolicyOf(catRow);
  const cur = _clientRulePolicyMap(c)[ruleId] || catPol;
  const pop = document.createElement('div');
  pop.className = 'rule-pol-pop';
  pop.innerHTML =
    '<div class="rpp-head">Только этому клиенту</div>' +
    RULE_POLICY_BTNS.map(([v, label]) =>
      `<button type="button" class="rpp-item${v === cur ? ' active' : ''}" data-pol="${v}" data-badge="${v}">` +
      `<span class="rule-pol" data-pol="${v}">${label}</span>` +
      (v === catPol ? '<span class="rpp-hint">как в каталоге</span>' : '') +
      '</button>').join('');
  // position: fixed по rect бейджа — карточку клиента можно скроллить, и
  // absolute-поповер уехал бы вместе с потоком или обрезался бы overflow'ом.
  document.body.appendChild(pop);
  const r = el.getBoundingClientRect();
  const w = pop.offsetWidth, h = pop.offsetHeight;
  let left = r.left, top = r.bottom + 6;
  if (left + w > window.innerWidth - 8) left = window.innerWidth - w - 8;
  if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 6);
  pop.style.left = Math.max(8, left) + 'px';
  pop.style.top = top + 'px';
  pop.querySelectorAll('.rpp-item').forEach(b => b.addEventListener('click', () => {
    closeRulePolPop();
    setClientRulePolicy(kind, uuid, platform, ruleId, b.dataset.pol === catPol ? '' : b.dataset.pol);
  }));
  _rulePolPop = pop;
  _rulePolPopAnchor = el;
  document.addEventListener('mousedown', _rulePolPopOutside, true);
  document.addEventListener('keydown', _rulePolPopKey, true);
  window.addEventListener('scroll', closeRulePolPop, true);
  window.addEventListener('resize', closeRulePolPop);
}

async function setClientRulePolicy(kind, uuid, platform, ruleId, policy) {
  const c = _protoFindClient(kind, uuid);
  if (!c) return;
  const ov = _clientRulePolicyMap(c);
  if ((ov[ruleId] || '') === policy) return;
  const map = Object.assign({}, ov);
  if (policy) map[ruleId] = policy; else delete map[ruleId];
  c.rule_policy = map;                  // оптимистично: бейдж перекрашивается сразу
  _protoRerender(kind);
  const res = await fetch(_protoClientUrl(kind, uuid, '/rule-policy'), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: ruleId, policy}),
  });
  if (!res.ok) {
    toast('Ошибка сохранения политики');
    // Откат оптимистичной правки — перечитываем состояние у того протокола,
    // чьей карточке принадлежит бейдж.
    if (kind === 'hysteria') { try { hyRerender(true); } catch (e) {} } else refreshXray();
    return;
  }
  const btn = RULE_POLICY_BTNS.find(([v]) => v === policy);
  toast(btn ? 'Только этому клиенту: ' + btn[1] : 'Политика как в каталоге');
}

// Делегирование: сетка правил перерисовывается через innerHTML, живые
// обработчики на бейджах не выжили бы.
document.addEventListener('click', e => {
  const el = e.target.closest && e.target.closest('.rule-pol[data-uuid]');
  if (!el) return;
  e.stopPropagation();
  if (_rulePolPopGuard) { _rulePolPopGuard = false; return; }
  openRulePolPop(el);
});

// Порядок каталога = приоритет в конфиге. Стрелки двигают запись и СРАЗУ
// сохраняют новый порядок (reorder), кнопку жать не надо.
async function _persistRuleOrder(platform) {
  const ids = (_ruleListCatalog[platform] || []).map(r => r.id);
  const res = await fetch(API + '/api/xray/rule-lists/' + encodeURIComponent(platform) + '/reorder', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({order: ids}),
  });
  if (!res.ok) { toast('Ошибка сохранения порядка'); await loadRuleListCatalogInto(); return; }
  refreshXray();
}

function ruleListMoveTop(platform, id) {
  const arr = _ruleListCatalog[platform] || [];
  const i = arr.findIndex(r => String(r.id) === String(id));
  if (i <= 0) return;
  const [row] = arr.splice(i, 1);
  arr.unshift(row);
  renderRuleListManager();
  _persistRuleOrder(platform);
}

function ruleListMoveUp(platform, id) {
  const arr = _ruleListCatalog[platform] || [];
  const i = arr.findIndex(r => String(r.id) === String(id));
  if (i <= 0) return;
  const [row] = arr.splice(i, 1);
  arr.splice(i - 1, 0, row);
  renderRuleListManager();
  _persistRuleOrder(platform);
}

function ruleListMoveDown(platform, id) {
  const arr = _ruleListCatalog[platform] || [];
  const i = arr.findIndex(r => String(r.id) === String(id));
  if (i < 0 || i >= arr.length - 1) return;
  const [row] = arr.splice(i, 1);
  arr.splice(i + 1, 0, row);
  renderRuleListManager();
  _persistRuleOrder(platform);
}

// Кнопка «Добавить» — только добавляет новую запись (активна, когда поля валидны).
async function addRuleList(platform) {
  const sfx = {lists: 'Lists', global: 'Global'}[platform];
  const kind = document.querySelector(`input[name="new${sfx}Kind"]:checked`).value;
  const name = document.getElementById('new' + sfx + 'Name').value.trim();
  const url = document.getElementById('new' + sfx + 'Url').value.trim();
  const rulesRaw = document.getElementById('new' + sfx + 'Rules').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!name) { await openAlert({title: 'Нет названия', body: 'У новой записи должно быть название.'}); return; }
  const payload = {platform, name};
  if (kind === 'url') {
    if (!/^https?:\/\//i.test(url)) {
      await openAlert({title: 'Неверная ссылка', body: 'URL файла должен начинаться с http(s)://. Для доменов/IP выберите «Вручную» или «Автоматический».'});
      return;
    }
    if (platform === 'global') {
      if (!url.toLowerCase().endsWith('.yaml')) { await openAlert({title: 'Неверная ссылка', body: 'Для Global ссылка должна заканчиваться на .yaml.'}); return; }
    } else if (!/\.(list|yaml)$/i.test(url)) {
      await openAlert({title: 'Неверная ссылка', body: 'Ссылка должна заканчиваться на .list или .yaml.'}); return;
    }
    payload.url = url;
  } else {
    // 'rules' (Вручную) — как есть; 'auto' (Автоматический) — конвертируем в DOMAIN-SUFFIX.
    const rules = (kind === 'auto') ? _autoConvertRules(rulesRaw) : rulesRaw;
    if (!rules.length) { await openAlert({title: 'Пустой список', body: 'Впишите домены/IP хотя бы одной строкой.'}); return; }
    payload.rules = rules;
  }
  const res = await fetch(API + '/api/xray/rule-lists', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { toast(translateError(data.error) || 'Ошибка добавления'); return; }
  document.getElementById('new' + sfx + 'Name').value = '';
  document.getElementById('new' + sfx + 'Url').value = '';
  document.getElementById('new' + sfx + 'Rules').value = '';
  _updNewBtns(sfx);
  toast('Список добавлен: ' + name);
  await loadRuleListCatalogInto();
  _rmKeepAddFormVisible(sfx);
  refreshXray();
}

// Новая карточка встаёт над формой и сдвигает её вниз, под прилипший низ окна
// с «Закрыть». Докручиваем окно так, чтобы кнопки формы снова были видны.
function _rmKeepAddFormVisible(sfx) {
  const btn = document.getElementById('addBtn' + sfx);
  const box = btn && btn.closest('.modal');
  if (!box) return;
  const foot = box.querySelector(':scope > .modal-actions');
  const limit = foot ? foot.getBoundingClientRect().top : box.getBoundingClientRect().bottom;
  const over = btn.getBoundingClientRect().bottom + 12 - limit;
  if (over > 0) box.scrollTop += over;
}

async function deleteRuleList(platform, id, name) {
  const ok = await openConfirm({
    title: 'Удалить список правил?',
    body: 'Список «' + escHtml(name) + '» будет удалён из каталога и снят со всех клиентов.',
    okLabel: 'Удалить',
    danger: true,
  });
  if (!ok) return;
  const res = await fetch(
    API + '/api/xray/rule-lists/' + encodeURIComponent(platform) + '/' + encodeURIComponent(id),
    {method: 'DELETE'}
  );
  if (res.ok) {
    toast('Список удалён');
    await loadRuleListCatalogInto();
    refreshXray();
  } else {
    toast('Ошибка удаления');
  }
}

// Очистить весь каталог текущей вкладки. Выборки клиентов сохраняются —
// повторно добавленный шаблон с тем же id снова загорится.
async function clearRuleListPlatform(platform) {
  const cat = _ruleListCatalog[platform] || [];
  if (!cat.length) { toast('Вкладка уже пуста'); return; }
  const labels = {lists: 'Списки правил', global: 'Global'};
  const ok = await openConfirm({
    title: 'Очистить вкладку?',
    body: 'Все ' + cat.length + ' записей вкладки «' + escHtml(labels[platform] || platform) +
          '» будут удалены из каталога. Выборки на клиентах сохранятся — добавите шаблон с тем же именем, и он снова включится.',
    okLabel: 'Очистить',
    danger: true,
  });
  if (!ok) return;
  const res = await fetch(API + '/api/xray/rule-lists/' + encodeURIComponent(platform) + '/clear', {method: 'POST'});
  if (res.ok) {
    toast('Вкладка очищена');
    await loadRuleListCatalogInto();
    refreshXray();
  } else {
    toast('Ошибка очистки');
  }
}

// ============================================================
// Mihomo — каскад через второй VPN
// ============================================================
// Вкладка появляется только когда движок реально установлен на сервере.
// Всё состояние приходит одним /api/mihomo/status; тяжёлые списки (профили,
// узлы, правила) грузятся отдельно и только при открытой вкладке.

let _mhStatus = null;
let _mhSafeLeft = 0;      // секунд до автоотката, тикает локально
let _mhProfiles = [];
let _mhProxies = null;
let _mhRules = null;

const MH_RULES_RENDER_LIMIT = 600;

function mhIsTabOpen() {
  const sec = document.getElementById('sectionMihomo');
  return !!sec && !sec.classList.contains('hidden');
}

async function mhRefreshStatus() {
  try {
    const r = await fetch(API + '/api/mihomo/status', {credentials: 'same-origin'});
    if (!r.ok) return;
    _mhStatus = await r.json();
    _mhSafeLeft = _mhStatus.safe_seconds_left || 0;
  } catch (e) {
    return;
  }
  const tab = document.getElementById('tabMihomo');
  if (tab) tab.classList.toggle('hidden', !_mhStatus.installed);
  // Движок снесли, а вкладка была открыта — уводим на первую доступную.
  if (!_mhStatus.installed && currentTab === 'mihomo') {
    // Уводим на первый включённый протокол, а не жёстко на AWG: он может быть
    // спрятан через «Скрыть протоколы».
    const enabledP = new Set((_serverConfig && _serverConfig.enabled_protocols) || ALL_PROTOCOLS);
    switchTab(ALL_PROTOCOLS.find(p => enabledP.has(p)) || 'awg');
  }
  mhRenderStatus();
  // Счётчик трафика живёт в самом профиле и растёт на сервере, поэтому при
  // открытой вкладке список надо именно перезапрашивать: перерисовки из кеша
  // недостаточно, число так и осталось бы прежним.
  if (mhIsTabOpen()) mhLoadProfiles();
  else if (_mhProfiles.length) mhRenderProfiles();
  const modal = document.getElementById('mihomoModal');
  if (modal && !modal.classList.contains('hidden')) mhRenderModal();
}

// Полное обновление вкладки: статус + все списки.
async function mhRefresh() {
  await mhRefreshStatus();
  if (!_mhStatus || !_mhStatus.installed) return;
  await mhLoadProfiles();
  if (_mhStatus.api_ok) {
    await Promise.all([mhLoadProxies(), mhLoadRules()]);
  } else {
    _mhProxies = null;
    _mhRules = null;
    mhRenderProxies();
    mhRenderRules();
  }
}

function mhRenderStatus() {
  const s = _mhStatus;
  if (!s) return;
  const nameEl = document.getElementById('mhProfileName');
  const metaEl = document.getElementById('mhProfileMeta');
  if (nameEl) {
    nameEl.textContent = s.active_profile_name || '—';
    nameEl.classList.toggle('green', !!s.active_profile_name);
  }
  if (metaEl) {
    metaEl.textContent = s.profiles_count
      ? 'профилей в панели: ' + s.profiles_count
      : 'профиль не добавлен';
  }

  // Плитка связи со вторым сервером. Живость проверяется фоновым дозвоном
  // сквозь текущий узел — «движок работает» само по себе ещё ничего не значит.
  const up = s.upstream || {};
  const upEl = document.getElementById('mhUpstreamState');
  const upMeta = document.getElementById('mhUpstreamMeta');
  if (upEl && upMeta) {
    const setCls = (cls) => {
      upEl.classList.toggle('green', cls === 'green');
      upEl.classList.toggle('orange', cls === 'orange');
      upEl.classList.toggle('red', cls === 'red');
    };
    // Одно число и в плитке, и на карточке профиля: накопительно скачано через
    // активный профиль. Показываем всегда, в том числе нулевое. Перед ним —
    // адрес второго сервера, чтобы было видно, с кем именно связь.
    const total = (s.active_profile_server ? s.active_profile_server + ' · ' : '') +
                  'total: ' + formatBytesShort(s.active_profile_dl);
    if (!s.running) {
      upEl.textContent = 'движок опущен';
      setCls('orange');
      upMeta.textContent = total;
    } else if (up.ok) {
      upEl.textContent = up.delay + ' мс';
      setCls('green');
      // Имя узла тут не показываем: в профиле оно произвольное («Yandex»,
      // «node-1») и о сервере ничего не сообщает. Адрес — на карточке профиля.
      const parts = [total];
      if (up.speed_dl) parts.push(formatBytesShort(up.speed_dl) + '/с');
      upMeta.textContent = parts.join(' · ');
    } else if (up.checked) {
      upEl.textContent = 'нет связи';
      setCls('red');
      upMeta.textContent = total;
    } else {
      upEl.textContent = 'проверяем…';
      setCls('orange');
      upMeta.textContent = total;
    }
  }

  const svc = document.getElementById('mhService');
  if (svc) {
    svc.textContent = s.running ? 'работает' : 'остановлен';
    svc.classList.toggle('green', !!s.running);
    svc.classList.toggle('orange', !s.running);
  }
  const api = document.getElementById('mhApiState');
  if (api) {
    if (!s.running) api.textContent = '';
    else api.textContent = s.api_ok ? 'API отвечает' : 'API не отвечает';
  }

  const safe = document.getElementById('mhSafeToggle');
  if (safe) {
    safe.checked = !!s.safe_mode;
    const row = safe.closest('.switch-row');
    if (row) row.classList.toggle('is-on', !!s.safe_mode);
  }
  mhRenderSafeBanner();

  const setSw = (id, on, disabled) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.checked = !!on;
    el.disabled = !!disabled;
    const row = el.closest('.switch-row');
    if (row) {
      row.classList.toggle('is-on', !!on);
      row.style.opacity = disabled ? '0.5' : '';
    }
  };
  // Включить каскад можно только установленному и запущенному протоколу.
  // Строку не прячем — рядом пишем, почему тумблер неактивен. Уже включённый
  // каскад оставляем кликабельным, чтобы его можно было снять и у лежащего
  // сервиса. Статус опрашивается раз в 15 с — тумблер оживёт сам.
  const ps = s.proto_state || {};
  const cascadeSw = (kind, id, noteId, on, availableOld) => {
    const st = ps[kind] || {installed: !!availableOld, running: !!availableOld};
    const why = !st.installed ? 'протокол не установлен' : (!st.running ? 'протокол не запущен' : '');
    setSw(id, on, !!why && !on);
    const note = document.getElementById(noteId);
    if (note) {
      note.textContent = why ? '— ' + why : '';
      note.classList.toggle('hidden', !why);
    }
  };
  cascadeSw('xray', 'mhCascadeXray', 'mhNoteXray', s.cascade_xray, s.xray_available);
  cascadeSw('mtg', 'mhCascadeMtg', 'mhNoteMtg', s.cascade_mtg, s.mtg_available);
  cascadeSw('hysteria', 'mhCascadeHysteria', 'mhNoteHysteria', s.cascade_hysteria, s.hysteria_available);
  cascadeSw('tgweb', 'mhCascadeTgweb', 'mhNoteTgweb', s.cascade_tgweb, s.tgweb_available);

  const warn = document.getElementById('mhCascadeWarn');
  if (warn) {
    const msgs = [];
    // Намерение есть, а в конфигах пусто — штатное ожидание запуска движка.
    const waiting = [];
    if (s.cascade_xray_pending) waiting.push('XRay');
    if (s.cascade_mtg_pending) waiting.push('MTProto');
    if (s.cascade_hysteria_pending) waiting.push('Hysteria');
    if (s.cascade_tgweb_pending) waiting.push('Telegram WEB');
    if (waiting.length) {
      msgs.push('Ждёт запуска движка: ' + waiting.join(', ') +
                '. В конфиги ничего не записано — клиенты пока выходят напрямую.');
    }
    // А вот обратное — аномалия: в конфиге каскад есть, хотя мы его не просили.
    if (!s.cascade_xray && s.cascade_xray_live) msgs.push('XRay: каскад есть в конфиге, хотя выключен в панели.');
    if (!s.cascade_mtg && s.cascade_mtg_live) msgs.push('mtg: каскад есть в конфиге, хотя выключен в панели.');
    if (!s.cascade_hysteria && s.cascade_hysteria_live) msgs.push('Hysteria: каскад есть в конфиге, хотя выключен в панели.');
    if (!s.cascade_tgweb && s.cascade_tgweb_live) msgs.push('Telegram WEB: каскад есть в конфиге, хотя выключен в панели.');
    if ((s.cascade_xray_live || s.cascade_mtg_live || s.cascade_hysteria_live || s.cascade_tgweb_live) && !s.api_ok) {
      msgs.push('Каскад в конфигах, но движок не отвечает — через три минуты панель снимет каскад сама.');
    }
    warn.innerHTML = msgs.map(escHtml).join('<br>');
    warn.classList.toggle('hidden', msgs.length === 0);
  }
}

// Баннер безопасного режима с обратным отсчётом. Секунды тикают локально,
// сервер переспрашивается обычным опросом статуса.
let _mhSafeTicker = null;

function mhFmtLeft(sec) {
  const m = Math.floor(sec / 60), r = sec % 60;
  return m + ':' + (r < 10 ? '0' : '') + r;
}

function mhRenderSafeBanner() {
  const banner = document.getElementById('mhSafeBanner');
  const s = _mhStatus;
  if (!banner || !s) return;
  banner.classList.toggle('hidden', !s.safe_mode);
  if (!s.safe_mode) {
    if (_mhSafeTicker) { clearInterval(_mhSafeTicker); _mhSafeTicker = null; }
    return;
  }
  const mins = Math.round((s.safe_window_sec || 300) / 60);
  if (_mhSafeLeft > 0) {
    // Отсчёт вынесен в отдельный узел: инлайновая подстановка внутри фразы
    // разрезала бы текстовый узел, и перевод такой строки не находился бы.
    banner.innerHTML =
      '<div>Идёт пробный запуск — по истечении окна панель сама снимет каскад с XRay, mtg, Hysteria и Telegram WEB, ' +
      'погасит движок и выключит автозапуск. Если связь с сервером пропадёт, всё вернётся ' +
      'в исходное без вас.</div>' +
      '<div class="mh-banner-row"><span class="mh-countdown">До автоотката ' +
      escHtml(mhFmtLeft(_mhSafeLeft)) + '</span>' +
      '<button class="btn btn-sm btn-ghost" onclick="mhSafeExtend()">Продлить</button></div>';
  } else {
    banner.innerHTML =
      'Безопасный режим взведён. Запустите движок — начнётся окно ' + mins + ' мин, ' +
      'по истечении которого всё вернётся в исходное само. Автозапуск при перезагрузке выключен.';
  }
  if (!_mhSafeTicker) {
    _mhSafeTicker = setInterval(() => {
      if (_mhSafeLeft > 0) { _mhSafeLeft--; mhRenderSafeBanner(); }
    }, 1000);
  }
}

async function mhSafeExtend() {
  const r = await fetch(API + '/api/mihomo/safe-extend', {method: 'POST'});
  const j = await r.json().catch(() => ({}));
  if (!j.ok) { toast(j.error || 'Не удалось'); return; }
  _mhStatus = j;
  _mhSafeLeft = j.safe_seconds_left || 0;
  mhRenderStatus();
  toast('Окно продлено');
}

async function mhToggleService() {
  const s = _mhStatus;
  if (!s) return;
  const action = s.running ? 'stop' : 'start';
  if (action === 'start') showBusyOverlay('Запускаем движок', 'Ждём ответа по API и применяем каскад');
  else if (s.cascade_xray_live || s.cascade_mtg_live) {
    showBusyOverlay('Останавливаем движок', 'Сначала снимаем каскад с конфигов');
  }
  try {
    const r = await fetch(API + '/api/mihomo/service', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: action}),
    });
    const j = await r.json().catch(() => ({}));
    if (j && typeof j.installed !== 'undefined') {
      _mhStatus = j;
      _mhSafeLeft = j.safe_seconds_left || 0;
    }
    if (!j.ok) { toast(j.error || 'Не удалось'); return; }
    const applied = (j.applied || []).length;
    toast(action === 'start'
      ? ('Движок запущен' + (applied ? ' · каскад применён' : ''))
      : 'Движок остановлен');
  } finally {
    hideBusyOverlay();
  }
  mhRefresh();
}

async function mhSetSafeMode(on) {
  const r = await fetch(API + '/api/mihomo/safe-mode', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled: !!on}),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) { toast(j.error || 'Не удалось'); mhRefreshStatus(); return; }
  _mhStatus = j;
  _mhSafeLeft = j.safe_seconds_left || 0;
  mhRenderStatus();
  toast(on ? 'Безопасный режим включён' : 'Безопасный режим выключен');
}

async function mhSetCascade(kind, on) {
  const payload = {};
  payload[kind] = !!on;
  // XRay перезапустится только если движок готов принять трафик; иначе это
  // просто галочка на будущее и оверлей был бы обманом.
  const willRestart = (kind === 'xray' || kind === 'hysteria' || kind === 'tgweb') &&
                      _mhStatus && _mhStatus.running && _mhStatus.api_ok;
  if (willRestart) {
    showBusyOverlay('Перенастраиваем ' + ({xray: 'XRay', hysteria: 'Hysteria', tgweb: 'Telegram WEB'}[kind]),
                    'Сервис перезапускается');
  }
  try {
    const r = await fetch(API + '/api/mihomo/cascade', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const j = await r.json().catch(() => ({}));
    if (j && typeof j.installed !== 'undefined') {
      _mhStatus = j;
      _mhSafeLeft = j.safe_seconds_left || 0;
    }
    if (!j.ok) {
      toast(j.error || 'Не удалось');
    } else if (on && j.pending) {
      toast('Включится при запуске движка');
    } else {
      toast(on ? 'Каскад включён' : 'Каскад выключен');
    }
  } catch (e) {
    toast('Сеть: не удалось');
  } finally {
    if (willRestart) hideBusyOverlay();
  }
  mhRenderStatus();
  setTimeout(() => mhRefreshStatus(), 1500);
}

// --- Профили ------------------------------------------------------------

async function mhLoadProfiles() {
  try {
    const r = await fetch(API + '/api/mihomo/profiles', {credentials: 'same-origin'});
    const j = await r.json();
    _mhProfiles = j.profiles || [];
  } catch (e) {
    _mhProfiles = [];
  }
  mhRenderProfiles();
}

function mhPlural(n, one, few, many) {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b > 1 && b < 5) return few;
  if (b === 1) return one;
  return many;
}

function mhRenderProfiles() {
  const box = document.getElementById('mhProfilesList');
  if (!box) return;
  if (!_mhProfiles.length) {
    box.innerHTML = '<div class="mh-empty">Профилей пока нет. Добавьте профиль второго сервера — ' +
                    'ссылкой на подписку, вставкой YAML или ссылками на узлы.</div>';
    return;
  }
  box.innerHTML = _mhProfiles.map(p => {
    const srcLabel = p.source === 'url' ? 'подписка'
                   : p.source === 'links' ? 'ссылки на узлы'
                   : 'вставлен текстом';
    const meta = [
      srcLabel,
      p.nodes_count + ' ' + mhPlural(p.nodes_count, 'узел', 'узла', 'узлов'),
      p.rules_count + ' ' + mhPlural(p.rules_count, 'правило', 'правила', 'правил'),
      'обновлён ' + fmtAuditTs(p.updated),
    ].join(' · ');
    // Профиль без правил гонит через второй VPN всё подряд — это надо видеть
    // на карточке, а не выяснять по списку правил.
    const matchAll = (p.match && p.match !== 'DIRECT')
      ? '<div class="mh-item-m mh-src-note-cold">весь трафик клиентов идёт через второй VPN</div>' : '';
    const actActivate = p.active ? '' :
      '<button class="btn btn-sm btn-success" data-mh-act="activate" data-mh-id="' + escAttr(p.id) + '">Сделать активным</button>';
    const actRefresh = p.source === 'url' ?
      '<button class="btn btn-sm btn-ghost" data-mh-act="refresh" data-mh-id="' + escAttr(p.id) + '" title="Перекачать по ссылке">Обновить</button>' : '';
    const actEdit =
      '<button class="btn btn-sm btn-ghost" data-mh-act="edit" data-mh-id="' + escAttr(p.id) + '" title="Изменить профиль">Изменить</button>';
    // Адрес второго сервера — из секции proxies профиля. Имя узла произвольное,
    // а вот host:port однозначно отвечает «куда мы вообще подключаемся».
    const addr = p.server
      ? '<div class="mh-item-m">сервер: ' + escHtml(p.server + (p.port ? ':' + p.port : '')) +
        (p.proxy_type ? ' · ' + escHtml(p.proxy_type) : '') + '</div>'
      : '';
    // DNS профиля показываем справочно — панель его не применяет. Список
    // подрезаем: резолверов бывает и десяток, а карточка не про них.
    let dns = '';
    if (p.dns && p.dns.length) {
      // Тип подписан явно: по одной ссылке не видно, DoH это или DoH3, а разница
      // существенная. Шифрованные идут первыми — голые IP обычно их бутстрап.
      const shown = p.dns.slice(0, 5).map(d => d.kind + ' ' + d.value).join(' · ');
      // «+N», а не «и ещё N»: внутрь паттерна перевода группа копируется как
      // есть, и русский хвост протёк бы в английскую версию.
      const more = p.dns.length > 5 ? ' · +' + (p.dns.length - 5) : '';
      dns = '<div class="mh-item-m">DNS профиля: ' + escHtml(shown + more) + ' — не применяется</div>';
    }
    const badge = p.active ? ' <span class="badge badge-rule">активен</span>' : '';
    // Скачано через этот профиль за всё время. Счётчик живёт в самом профиле,
    // поэтому переживает рестарты движка и виден когда тот опущен.
    const total = '<div class="mh-item-m">total: ' +
      escHtml(formatBytesShort(p.bytes_dl)) + '</div>';
    return '<div class="mh-item ' + (p.active ? 'is-active' : '') + '">' +
             '<div class="mh-item-b">' +
               '<div class="mh-item-t">' + escHtml(p.name) + badge + '</div>' +
               '<div class="mh-item-m">' + escHtml(meta) + '</div>' + addr + matchAll + dns + total +
             '</div>' +
             '<div class="mh-item-a">' + actActivate + actEdit + actRefresh +
               '<button class="btn btn-sm btn-ghost" data-mh-act="delete" data-mh-id="' + escAttr(p.id) + '" title="Удалить профиль">&#10005;</button>' +
             '</div>' +
           '</div>';
  }).join('');
  // id профиля передаём через data-* и слушатели: escHtml не экранирует кавычки,
  // и инлайновый onclick со строкой ломает атрибут.
  box.querySelectorAll('button[data-mh-act]').forEach(b => {
    b.addEventListener('click', () => mhProfileAction(b.dataset.mhAct, b.dataset.mhId));
  });
}

async function mhProfileAction(act, id) {
  if (act === 'edit') { mhOpenEditProfile(id); return; }
  if (act === 'delete') {
    const prof = _mhProfiles.find(p => p.id === id);
    const ok = await openConfirm({
      title: 'Удалить профиль?',
      body: 'Профиль «' + escHtml((prof && prof.name) || '') + '» будет удалён из панели. ' +
            'На втором сервере ничего не изменится.',
      okLabel: 'Удалить',
      danger: true,
    });
    if (!ok) return;
    const r = await fetch(API + '/api/mihomo/profiles/' + encodeURIComponent(id), {method: 'DELETE'});
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { toast(j.error || 'Не удалось'); return; }
    toast(j.note ? 'Профиль удалён, ' + j.note : 'Профиль удалён');
  } else {
    const url = API + '/api/mihomo/profiles/' + encodeURIComponent(id) + '/' + act;
    const r = await fetch(url, {method: 'POST'});
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { toast(j.error || 'Не удалось'); return; }
    toast(act === 'activate' ? 'Профиль активен' : 'Профиль перекачан');
  }
  mhRefresh();
}

let _mhEditId = '';

function mhProfModalReset(title, okLabel) {
  const err = document.getElementById('mhProfErr');
  err.style.display = 'none';
  err.textContent = '';
  document.getElementById('mhProfTitle').textContent = title;
  document.getElementById('mhProfSaveBtn').textContent = okLabel;
  document.getElementById('mihomoProfileModal').classList.remove('hidden');
}

function mhOpenAddProfile() {
  _mhEditId = '';
  document.getElementById('mhProfName').value = '';
  document.getElementById('mhProfRaw').value = '';
  mhFillRulesSelect('');
  mhProfDetectReset();
  mhProfModalReset('Профиль второго сервера', 'Добавить');
}

// Донор правил для профиля из ссылок: сам узел ничего о маршрутизации не знает,
// правила берём из уже добавленного clash-профиля второго сервера.
function mhFillRulesSelect(current) {
  const sel = document.getElementById('mhProfRules');
  if (!sel) return;
  const opts = ['<option value="">всё через второй VPN</option>'];
  _mhProfiles.forEach(p => {
    if (p.id === _mhEditId || p.rules_count < 2) return;
    opts.push('<option value="' + escAttr(p.id) + '">правила из профиля «' +
              escHtml(p.name) + '»</option>');
  });
  sel.innerHTML = opts.join('');
  sel.value = current || '';
  if (sel.value !== (current || '')) sel.value = '';   // донора удалили
  sel.onchange = () => { mhProfRulesNote(); mhProfInspect(true); };
  mhProfRulesNote();
}

function mhProfRulesNote() {
  const sel = document.getElementById('mhProfRules');
  const note = document.getElementById('mhProfRulesNote');
  if (!sel || !note) return;
  note.textContent = sel.value
    ? 'Через второй VPN пойдёт только перечисленное в правилах, остальное — напрямую с этого сервера.'
    : 'Через второй VPN пойдёт весь трафик клиентов: у ссылки на узел своих правил нет.';
}

async function mhOpenEditProfile(id) {
  // Тело профиля тянем отдельным запросом: в списке его нет, он бывает большим.
  let j = {};
  try {
    const r = await fetch(API + '/api/mihomo/profiles/' + encodeURIComponent(id) + '/raw',
                          {credentials: 'same-origin'});
    j = await r.json();
  } catch (e) { j = {}; }
  if (!j.ok) { toast(j.error || 'Не удалось открыть профиль'); return; }
  _mhEditId = id;
  document.getElementById('mhProfName').value = j.name || '';
  // Правится ровно то, что вставляли: ссылка, YAML или список ссылок.
  document.getElementById('mhProfRaw').value = j.text || '';
  mhFillRulesSelect(j.rules_from || '');
  mhProfDetectReset();
  mhProfModalReset('Изменить профиль', 'Сохранить');
  mhProfInspect(true);
}

// --- Разбор вставленного текста ------------------------------------------
// Одно поле на всё, поэтому единственная защита от «вставил и гадай» — сразу
// показать, что панель поняла, и не давать сохранить непонятое.

let _mhInspectTimer = 0;
let _mhInspectSeq = 0;
let _mhInspectOk = false;

function mhProfDetectReset() {
  const box = document.getElementById('mhProfDetect');
  if (box) { box.classList.add('hidden'); box.innerHTML = ''; }
  document.getElementById('mhProfRulesBox').classList.add('hidden');
  _mhInspectOk = false;
  mhProfSaveState();
}

function mhProfSaveState() {
  const btn = document.getElementById('mhProfSaveBtn');
  if (btn) btn.disabled = !_mhInspectOk;
}

function mhProfTextChanged() {
  clearTimeout(_mhInspectTimer);
  _mhInspectOk = false;
  mhProfSaveState();
  const box = document.getElementById('mhProfDetect');
  if (!(document.getElementById('mhProfRaw').value || '').trim()) { mhProfDetectReset(); return; }
  if (box) {
    box.classList.remove('hidden');
    box.innerHTML = '<div class="mh-det-h">Проверяем…</div>';
  }
  // Ссылку на подписку панель реально скачивает, так что дёргать на каждую
  // букву нельзя — ждём паузы в наборе.
  _mhInspectTimer = setTimeout(() => mhProfInspect(false), 600);
}

async function mhProfInspect(immediate) {
  const text = (document.getElementById('mhProfRaw').value || '').trim();
  if (!text) { mhProfDetectReset(); return; }
  if (immediate) clearTimeout(_mhInspectTimer);
  const seq = ++_mhInspectSeq;
  let j = {};
  try {
    const r = await fetch(API + '/api/mihomo/inspect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text: text, rules_from: document.getElementById('mhProfRules').value || ''}),
    });
    j = await r.json();
  } catch (e) { j = {error: 'панель не ответила'}; }
  if (seq !== _mhInspectSeq) return;   // пришёл ответ на устаревший ввод
  mhRenderDetect(j);
}

function mhKindTitle(j) {
  if (j.kind === 'url') {
    return j.inner === 'links' ? 'Ссылка на подписку — список узлов'
                               : 'Ссылка на подписку — clash-профиль';
  }
  if (j.kind === 'clash') return 'Clash-профиль';
  if (j.kind === 'links') return 'Ссылки на узлы';
  return 'Не понял, что это';
}

function mhRenderDetect(j) {
  const box = document.getElementById('mhProfDetect');
  const rulesBox = document.getElementById('mhProfRulesBox');
  if (!box) return;
  box.classList.remove('hidden');
  const bad = !!(j.error || j.kind === 'unknown' || j.kind === 'empty');
  _mhInspectOk = !bad;
  mhProfSaveState();
  rulesBox.classList.toggle('hidden', !j.needs_rules);
  if (bad) {
    box.innerHTML = '<div class="mh-det-h is-bad">' + escHtml(mhKindTitle(j)) + '</div>' +
                    '<div class="mh-det-sum">' + escHtml(j.error ||
                      'Ожидается ссылка на подписку, clash-конфиг или ссылки на узлы.') + '</div>';
    return;
  }
  const sum = [
    j.nodes.length + ' ' + mhPlural(j.nodes.length, 'узел', 'узла', 'узлов'),
    j.rules_count + ' ' + mhPlural(j.rules_count, 'правило', 'правила', 'правил'),
  ];
  if (j.providers) sum.push(j.providers + ' ' + mhPlural(j.providers, 'набор', 'набора', 'наборов'));
  if (j.size) sum.push('скачано ' + formatBytesShort(j.size));
  const rows = j.nodes.slice(0, 12).map(n =>
    '<div class="mh-det-row is-ok"><span class="mh-det-mark">&#10003;</span>' +
    '<span class="mh-det-txt">' + escHtml((n.type || '?') + ' · ' + (n.name || '') +
      (n.server ? ' · ' + n.server + (n.port ? ':' + n.port : '') : '')) + '</span></div>').join('');
  const more = j.nodes.length > 12
    ? '<div class="mh-det-row"><span class="mh-det-mark">·</span><span>+' +
      (j.nodes.length - 12) + '</span></div>' : '';
  // Строки, которые не разобрались, показываем поимённо: иначе узел молча
  // исчезает и пользователь об этом не узнаёт.
  const probs = (j.problems || []).slice(0, 8).map(p =>
    '<div class="mh-det-row is-bad"><span class="mh-det-mark">&#10007;</span>' +
    '<span class="mh-det-txt">строка ' + p.line + ': ' + escHtml(p.reason) + ' — ' +
    escHtml(p.text) + '</span></div>').join('');
  box.innerHTML = '<div class="mh-det-h">' + escHtml(mhKindTitle(j)) + '</div>' +
                  '<div class="mh-det-sum">' + escHtml(sum.join(' · ')) + '</div>' +
                  rows + more + probs;
}

async function mhSaveProfile() {
  const btn = document.getElementById('mhProfSaveBtn');
  const err = document.getElementById('mhProfErr');
  const body = {
    name: (document.getElementById('mhProfName').value || '').trim(),
    text: document.getElementById('mhProfRaw').value || '',
    rules_from: document.getElementById('mhProfRules').value || '',
  };
  if (!body.name) {
    err.textContent = 'Укажите название профиля';
    err.style.display = 'block';
    return;
  }
  btn.disabled = true;
  btn.classList.add('is-loading');
  try {
    const editing = !!_mhEditId;
    const r = await fetch(API + '/api/mihomo/profiles' + (editing ? '/' + encodeURIComponent(_mhEditId) : ''), {
      method: editing ? 'PUT' : 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) {
      err.textContent = j.error || 'Не удалось добавить';
      err.style.display = 'block';
      return;
    }
    closeModal('mihomoProfileModal');
    // Часть ссылок могла не разобраться — молчать нельзя, иначе узел просто
    // «потеряется» без следа.
    const skipped = (j.warn && j.warn.length) ? ', пропущено строк: ' + j.warn.length : '';
    toast((editing ? 'Профиль сохранён' : 'Профиль добавлен') + skipped);
    _mhEditId = '';
    mhRefresh();
  } finally {
    mhProfSaveState();   // не «включить», а вернуть состояние разбора
    btn.classList.remove('is-loading');
  }
}

// --- Узлы второго сервера ------------------------------------------------

async function mhLoadProxies() {
  try {
    const r = await fetch(API + '/api/mihomo/proxies', {credentials: 'same-origin'});
    const j = await r.json();
    _mhProxies = j.ok ? j : null;
  } catch (e) {
    _mhProxies = null;
  }
  mhRenderProxies();
}

function mhRenderProxies() {
  // Карточка появляется, только когда есть что показать: пустой список при
  // опущенном движке или профиле без узлов — лишний блок на странице.
  const card = document.getElementById('mhProxiesCard');
  const box = document.getElementById('mhProxiesList');
  if (!box) return;
  // GLOBAL и PASS-RULE движок заводит сам: первая работает только в mode:
  // global (панель всегда ставит rule), вторая — служебная заглушка. К профилю
  // второго сервера они отношения не имеют и выглядели как его группы.
  const builtin = ['DIRECT', 'REJECT', 'REJECT-DROP', 'COMPATIBLE', 'PASS', 'GLOBAL', 'PASS-RULE'];
  const builtinTypes = ['passrule', 'compatible', 'direct', 'reject', 'rejectdrop'];
  const isBuiltin = p => builtin.indexOf((p.name || '').toUpperCase()) >= 0 ||
                         builtinTypes.indexOf((p.type || '').toLowerCase()) >= 0;
  const groups = ((_mhProxies && _mhProxies.groups) || []).filter(g => !isBuiltin(g));
  const nodes = ((_mhProxies && _mhProxies.nodes) || []).filter(n => !isBuiltin(n));
  const nothing = !_mhProxies || (!groups.length && !nodes.length);
  if (card) card.classList.toggle('hidden', nothing);
  if (nothing) return;
  const rows = [];
  groups.forEach(g => {
    const opts = (g.options || []).map(o =>
      '<option value="' + escAttr(o) + '"' + (o === g.now ? ' selected' : '') + '>' + escHtml(o) + '</option>').join('');
    rows.push(
      '<div class="mh-item">' +
        '<div class="mh-item-b">' +
          '<div class="mh-item-t">' + escHtml(g.name) + '</div>' +
          '<div class="mh-item-m">группа · ' + escHtml(g.type || '') + '</div>' +
        '</div>' +
        '<div class="mh-item-a">' +
          '<select class="mh-filter" style="width:auto;" data-mh-group="' + escAttr(g.name) + '">' + opts + '</select>' +
          '<button class="btn btn-sm btn-ghost" data-mh-test="' + escAttr(g.now || g.name) + '">Проверить</button>' +
        '</div>' +
      '</div>');
  });
  nodes.forEach(n => {
    const d = (typeof n.delay === 'number' && n.delay > 0) ? ' · ' + n.delay + ' мс' : '';
    rows.push(
      '<div class="mh-item">' +
        '<div class="mh-item-b">' +
          '<div class="mh-item-t">' + escHtml(n.name) + '</div>' +
          '<div class="mh-item-m">' + escHtml(n.type || '') + escHtml(d) + '</div>' +
        '</div>' +
        '<div class="mh-item-a">' +
          '<button class="btn btn-sm btn-ghost" data-mh-test="' + escAttr(n.name) + '">Проверить</button>' +
        '</div>' +
      '</div>');
  });
  box.innerHTML = rows.join('');
  box.querySelectorAll('select[data-mh-group]').forEach(sel => {
    sel.addEventListener('change', () => mhSelectNode(sel.dataset.mhGroup, sel.value));
  });
  box.querySelectorAll('button[data-mh-test]').forEach(b => {
    b.addEventListener('click', () => mhTestNode(b.dataset.mhTest, b));
  });
}

async function mhSelectNode(group, name) {
  const r = await fetch(API + '/api/mihomo/select', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({group: group, name: name}),
  });
  const j = await r.json().catch(() => ({}));
  toast(j.ok ? ('Выбран узел: ' + name) : (j.error || 'Не удалось'));
  if (j.ok) mhLoadProxies();
}

async function mhTestNode(name, btn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Дозвон…';
  try {
    const r = await fetch(API + '/api/mihomo/test', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: name}),
    });
    const j = await r.json().catch(() => ({}));
    if (j.ok && j.delay) {
      btn.textContent = j.delay + ' мс';
      toast('Связь есть: ' + name + ' — ' + j.delay + ' мс');
      setTimeout(() => { btn.textContent = old; btn.disabled = false; }, 4000);
      return;
    }
    toast(j.error || 'Узел недоступен');
  } catch (e) {
    toast('Сеть: не удалось');
  }
  btn.textContent = old;
  btn.disabled = false;
}

// --- Правила -------------------------------------------------------------

async function mhLoadRules() {
  try {
    const r = await fetch(API + '/api/mihomo/rules', {credentials: 'same-origin'});
    const j = await r.json();
    _mhRules = j.ok ? j : null;
  } catch (e) {
    _mhRules = null;
  }
  mhRenderRules();
}

function mhRuleClass(p) {
  const up = (p || '').toUpperCase();
  if (up === 'DIRECT') return 'is-direct';
  if (up === 'REJECT' || up === 'REJECT-DROP') return 'is-block';
  return 'is-proxy';
}

// Движок зовёт этот тип «RuleSet», а профиль на диске — «RULE-SET»: список
// правил приходит то оттуда, то отсюда, поэтому сравниваем без дефисов и
// регистра. Иначе строки набора оставались без счётчика, а сам набор попадал
// вторым списком в «не в правилах».
function mhIsRuleSet(r) {
  return (r.type || '').toUpperCase().replace(/-/g, '') === 'RULESET';
}

function _mhEyeSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
}
function _mhReloadSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
}

// Одна таблица на всё: набор — такая же строка правила, только с числом
// адресов и кнопками. Раньше наборы шли отдельным рядом чипов сверху, и одно
// и то же имя приходилось искать в двух местах карточки.
function mhRuleRowHtml(r, prov, live) {
  const cnt = prov
    ? (prov.count === null || typeof prov.count === 'undefined'
        ? escHtml(prov.behavior || 'набор')
        : escHtml(String(prov.count)) + ' ' + mhPlural(prov.count, 'адрес', 'адреса', 'адресов'))
    : '';
  // Пустая колонка действий у обычных правил: без неё политика в строках с
  // набором и без него стояла на разной глубине.
  let acts = '<span class="mh-rule-a"></span>';
  if (prov) {
    acts = '<span class="mh-rule-a">' +
      '<button class="mh-rule-act" data-mh-prov-view="' + escAttr(prov.name) +
      '" title="Показать адреса набора" aria-label="Показать адреса набора">' + _mhEyeSvg() + '</button>' +
      (live ? '<button class="mh-rule-act" data-mh-prov="' + escAttr(prov.name) +
              '" title="Перекачать набор" aria-label="Перекачать набор">' + _mhReloadSvg() + '</button>' : '') +
      '</span>';
  }
  return '<div class="mh-rule">' +
    '<span class="mh-rule-t">' + escHtml(r.type || '') + '</span>' +
    '<span class="mh-rule-p">' + escHtml(r.payload || '') + '</span>' +
    (cnt ? '<span class="mh-rule-n">' + cnt + '</span>' : '') +
    (r.unused
      ? '<span class="mh-rule-x mh-rule-unused">не в правилах</span>'
      : '<span class="mh-rule-x ' + mhRuleClass(r.proxy) + '">' + escHtml(r.proxy || '') + '</span>') +
    acts +
    '</div>';
}

function mhRenderRules() {
  const card = document.getElementById('mhRulesCard');
  const box = document.getElementById('mhRulesList');
  if (!box) return;
  const provs = (_mhRules && _mhRules.providers) || [];
  const allRules = (_mhRules && _mhRules.rules) || [];
  // Хвостовой MATCH панель дописывает сама — правилом профиля он не является.
  const own = allRules.filter(r => (r.type || '').toUpperCase() !== 'MATCH');
  // Карточку целиком прячем, когда у активного профиля правил нет: «всё через
  // второй VPN» — это не список, и пустая таблица только сбивает с толку.
  const nothing = !_mhRules || (!provs.length && !own.length);
  if (card) card.classList.toggle('hidden', nothing);
  if (nothing) return;
  // source=engine — то, что реально загружено в память движка (с раскрытыми
  // наборами). source=profile — разбор активного профиля, когда движок опущен:
  // размеры наборов оттуда неизвестны, зато список правил виден всегда.
  const fromProfile = _mhRules.source === 'profile';
  const srcNote = document.getElementById('mhRulesSource');
  if (srcNote) {
    srcNote.textContent = fromProfile
      ? 'Движок опущен — показан разбор активного профиля. Сколько записей внутри наборов, известно только запущенному движку.'
      : 'Прочитано у работающего движка: это то, что реально загружено.';
    srcNote.classList.toggle('mh-src-note-cold', fromProfile);
  }
  const provMap = {};
  provs.forEach(p => { provMap[p.name] = p; });
  const fEl = document.getElementById('mhRuleFilter');
  const q = ((fEl && fEl.value) || '').trim().toLowerCase();
  let rules = allRules.slice();
  // Набор, объявленный в профиле, но не упомянутый ни в одном правиле, иначе
  // исчез бы вместе с рядом чипов — показываем строкой без политики.
  const used = {};
  rules.forEach(r => { if (mhIsRuleSet(r)) used[r.payload] = 1; });
  provs.forEach(p => {
    // Тип пишем так же, как его назвал источник списка: движок отдаёт
    // «RuleSet», разбор профиля — «RULE-SET», и вперемешку они выглядят
    // как два разных вида правил.
    if (!used[p.name]) {
      rules.push({type: fromProfile ? 'RULE-SET' : 'RuleSet', payload: p.name, proxy: '', unused: true});
    }
  });
  if (q) {
    rules = rules.filter(r =>
      (r.payload || '').toLowerCase().indexOf(q) >= 0 ||
      (r.type || '').toLowerCase().indexOf(q) >= 0 ||
      (r.proxy || '').toLowerCase().indexOf(q) >= 0);
  }
  const total = rules.length;
  const shown = rules.slice(0, MH_RULES_RENDER_LIMIT);
  let html = shown.map(r => mhRuleRowHtml(
    r, mhIsRuleSet(r) ? provMap[r.payload] : null, !fromProfile)).join('');
  if (!shown.length) {
    html = '<div class="mh-empty" style="padding:10px 11px;">Ничего не найдено.</div>';
  } else if (total > shown.length) {
    html += '<div class="mh-rule" style="color:var(--text3);"><span class="mh-rule-p">Показано ' +
            shown.length + ' из ' + total + ' — уточните фильтр.</span></div>';
  }
  box.innerHTML = html;
  box.querySelectorAll('button[data-mh-prov]').forEach(b => {
    b.addEventListener('click', () => mhRefreshProvider(b.dataset.mhProv, b));
  });
  box.querySelectorAll('button[data-mh-prov-view]').forEach(b => {
    b.addEventListener('click', () => mhOpenProvider(b.dataset.mhProvView, b));
  });
}

async function mhRefreshProvider(name, btn) {
  if (btn) btn.classList.add('is-busy');
  const r = await fetch(API + '/api/mihomo/providers/' + encodeURIComponent(name) + '/refresh', {method: 'POST'});
  const j = await r.json().catch(() => ({}));
  toast(j.ok ? ('Набор обновлён: ' + name) : (j.error || 'Не удалось'));
  if (btn) btn.classList.remove('is-busy');
  if (j.ok) mhLoadRules();
}

// --- Что внутри набора ----------------------------------------------------
// API движка отдаёт только размер набора, поэтому адреса панель читает из
// файла, который движок скачал рядом со своим конфигом.

let _mhProvData = null;

async function mhOpenProvider(name, btn) {
  if (btn) btn.classList.add('is-busy');
  try {
    const r = await fetch(API + '/api/mihomo/providers/' + encodeURIComponent(name) + '/payload',
                          {credentials: 'same-origin'});
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { toast(j.error || 'Не удалось прочитать набор'); return; }
    _mhProvData = j;
    document.getElementById('mhProvTitle').textContent = name;
    const bits = [];
    if (j.behavior) bits.push(j.behavior);
    if (j.format) bits.push(j.format);
    bits.push(j.total + ' ' + mhPlural(j.total, 'адрес', 'адреса', 'адресов'));
    if (j.total > (j.items || []).length) bits.push('показаны первые ' + j.items.length);
    if (j.path) bits.push(j.path);
    // Каждый кусок — свой span: переводчик работает по текстовым узлам, и
    // склеенную строку «classical · yaml · 481 адрес · …» он бы не нашёл.
    document.getElementById('mhProvSub').innerHTML =
      bits.map(b => '<span>' + escHtml(b) + '</span>').join(' · ');
    document.getElementById('mhProvFilter').value = '';
    mhRenderProviderItems();
    document.getElementById('mihomoProviderModal').classList.remove('hidden');
  } catch (e) {
    toast('Сеть: не удалось');
  } finally {
    if (btn) btn.classList.remove('is-busy');
  }
}

function mhRenderProviderItems() {
  const box = document.getElementById('mhProvList');
  if (!box || !_mhProvData) return;
  const fEl = document.getElementById('mhProvFilter');
  const q = ((fEl && fEl.value) || '').trim().toLowerCase();
  let items = _mhProvData.items || [];
  if (q) items = items.filter(x => (x || '').toLowerCase().indexOf(q) >= 0);
  const shown = items.slice(0, MH_RULES_RENDER_LIMIT);
  let html = shown.map(x =>
    '<div class="mh-rule"><span class="mh-rule-p">' + escHtml(x) + '</span></div>').join('');
  if (!shown.length) {
    html = '<div class="mh-empty" style="padding:10px 11px;">Ничего не найдено.</div>';
  } else if (items.length > shown.length) {
    html += '<div class="mh-rule" style="color:var(--text3);"><span class="mh-rule-p">Показано ' +
            shown.length + ' из ' + items.length + ' — уточните фильтр.</span></div>';
  }
  box.innerHTML = html;
}

// --- Модалка движка -------------------------------------------------------

function openMihomoModal() {
  mhRenderModal();
  document.getElementById('mihomoModal').classList.remove('hidden');
  mhRefreshStatus();
}

function mhRenderModal() {
  const s = _mhStatus;
  const inst = document.getElementById('mhInstallBlock');
  const has = document.getElementById('mhInstalledBlock');
  if (!inst || !has) return;
  const installed = !!(s && s.installed);
  inst.classList.toggle('hidden', installed);
  has.classList.toggle('hidden', !installed);
  if (!installed || !s) return;

  document.getElementById('mhModalVer').textContent = s.current || '—';
  const meta = document.getElementById('mhModalVerMeta');
  const checked = s.last_check ? fmtAuditTs(s.last_check) : 'ещё не проверялось';
  if (s.has_update && s.latest) {
    meta.innerHTML = '<span style="color:var(--orange,#fbbf24);">Доступна ' + escHtml(s.latest) +
                     '</span> · проверено ' + escHtml(checked);
  } else {
    meta.innerHTML = '<span style="color:var(--green);">Актуальная версия</span> · проверено ' + escHtml(checked);
  }
  const iv = document.getElementById('mhInterval');
  if (iv && document.activeElement !== iv) iv.value = s.check_interval_days || 7;
  const setSw = (id, on) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.checked = !!on;
    const row = el.closest('.switch-row');
    if (row) row.classList.toggle('is-on', !!on);
  };
  setSw('mhAutoUpdate', s.auto_update);
  setSw('mhAutostart', s.autostart);
  const asw = document.getElementById('mhAutostart');
  if (asw) asw.disabled = !!s.safe_mode;
}

async function mhInstall() {
  const btn = document.getElementById('mhInstallBtn');
  btn.disabled = true;
  btn.classList.add('is-loading');
  showBusyOverlay('Ставим mihomo', 'Качаем релиз с GitHub');
  try {
    const r = await fetch(API + '/api/mihomo/install', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}',
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { toast(j.error || 'Установка не удалась'); return; }
    toast('Mihomo установлен: ' + (j.version || ''));
    await mhRefreshStatus();
    await loadSystemVersions(true);
  } finally {
    hideBusyOverlay();
    btn.disabled = false;
    btn.classList.remove('is-loading');
  }
}

async function mhUninstall() {
  const ok = await openConfirm({
    title: 'Удалить mihomo?',
    body: 'Каскад будет снят с XRay и mtg, движок остановлен, бинарь, юнит, сторож и ' +
          '/etc/mihomo удалены. Профили останутся в панели. Клиенты продолжат работать ' +
          'напрямую через этот сервер.',
    okLabel: 'Удалить',
    danger: true,
  });
  if (!ok) return;
  showBusyOverlay('Удаляем mihomo', 'Снимаем каскад и чистим сервер');
  try {
    const r = await fetch(API + '/api/mihomo/uninstall', {method: 'POST'});
    const j = await r.json().catch(() => ({}));
    if (!j.ok) { toast(j.error || 'Не удалось'); return; }
    toast('Mihomo удалён');
    closeModal('mihomoModal');
    await mhRefreshStatus();
    await loadSystemVersions(true);
  } finally {
    hideBusyOverlay();
  }
}

async function mhCheckVersion() {
  const btn = document.getElementById('mhCheckVerBtn');
  btn.disabled = true;
  btn.classList.add('is-loading');
  try {
    await loadSystemVersions(true);
    await mhRefreshStatus();
    const s = _mhStatus;
    if (s && s.has_update) toast('Доступна версия ' + s.latest);
    else toast('Установлена актуальная версия');
  } finally {
    btn.disabled = false;
    btn.classList.remove('is-loading');
  }
}

async function mhSaveSettings() {
  const body = {
    auto_update: document.getElementById('mhAutoUpdate').checked,
    check_interval_days: parseInt(document.getElementById('mhInterval').value, 10) || 7,
    autostart: document.getElementById('mhAutostart').checked,
  };
  const r = await fetch(API + '/api/mihomo/settings', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) { toast(j.error || 'Не сохранено'); mhRefreshStatus(); return; }
  _mhStatus = j;
  mhRenderModal();
  mhRenderStatus();
}
