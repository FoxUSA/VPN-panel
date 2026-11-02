/* Telegram WEB-прокси — вторая половина вкладки «Telegram».
 *
 * Вкладка одна на два вида прокси Telegram: классический MTProto (mtg, разметка
 * в index.html) и WEB (этот файл). Пакет сам встраивается: переключатель
 * «MTProto | WEB» сверху секции, своя панель, адаптер общей модалки ⚙. Если файл
 * не загрузится, вкладка останется обычной вкладкой MTProto.
 *
 * Карточки клиентов повторяют карточки XRay — те же хелперы кнопок и классы,
 * общие модалки (расписание, лимит, фильтр IP) получают kind 'tgweb'.
 */
(function () {
  'use strict';

  var API = (typeof window.API === 'string') ? window.API : '';
  var KIND = 'tgweb';
  var SEG_KEY = 'awgPanel:tgSeg';
  var CACHE_KEY = 'awgPanel:tgwebCache:v1';
  var state = { status: null, clients: [], host: '', slug: '', stale: false };
  var _collapsed = {};
  var _seg = null;

  function esc(s) {
    return (typeof escHtml === 'function') ? escHtml(s) : String(s == null ? '' : s);
  }
  function say(msg) {
    if (typeof toast === 'function') toast(msg); else console.log(msg);
  }
  function busy(t, sub) { if (typeof showBusyOverlay === 'function') showBusyOverlay(t, sub); }
  function unbusy() { if (typeof hideBusyOverlay === 'function') hideBusyOverlay(); }

  function req(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    if (opts.body && typeof opts.body !== 'string') {
      opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(API + '/api/tgweb' + path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    });
  }

  function cfgEnabled(kind) {
    var cfg = (typeof _serverConfig !== 'undefined') ? _serverConfig : window._serverConfig;
    var list = cfg && cfg.enabled_protocols;
    return !Array.isArray(list) || list.indexOf(kind) >= 0;
  }

  // --- переключатель «MTProto | WEB» ------------------------------------------

  function readSeg() {
    try { return localStorage.getItem(SEG_KEY) || ''; } catch (e) { return ''; }
  }
  function writeSeg(v) {
    try { localStorage.setItem(SEG_KEY, v); } catch (e) {}
  }

  // Какой вид показан. Его спрашивает блок версий в app.js (_versionKind).
  window.tgSegment = function () { return _seg || 'mtg'; };

  function setSeg(v, silent) {
    var mtgOn = cfgEnabled('mtg'), webOn = cfgEnabled(KIND);
    if (v === 'web' && !webOn) v = 'mtg';
    if (v === 'mtg' && !mtgOn && webOn) v = 'web';
    _seg = v;
    if (!silent) writeSeg(v);
    var pm = document.getElementById('tgPaneMtg'), pw = document.getElementById('tgPaneWeb');
    if (pm) pm.classList.toggle('hidden', v !== 'mtg');
    if (pw) pw.classList.toggle('hidden', v !== 'web');
    var bar = document.getElementById('tgSeg');
    if (bar) {
      bar.querySelectorAll('button').forEach(function (b) {
        b.classList.toggle('active', b.getAttribute('data-seg') === v);
      });
    }
    if (typeof renderVersionBox === 'function') renderVersionBox();
    if (v === 'web' && typeof currentTab !== 'undefined' && currentTab === 'mtg') refresh();
  }

  function applyOwnVisibility() {
    var mtgOn = cfgEnabled('mtg'), webOn = cfgEnabled(KIND);
    var tab = document.getElementById('tabMtg');
    // Вкладка «Telegram» видна, пока включён хотя бы один из двух видов.
    if (tab) tab.classList.toggle('hidden', !mtgOn && !webOn);
    var sec = document.getElementById('sectionMtg');
    if (sec && !mtgOn && !webOn) sec.classList.add('hidden');
    var bar = document.getElementById('tgSeg');
    // Переключатель нужен, только когда видов два.
    if (bar) bar.classList.toggle('hidden', !(mtgOn && webOn));
    if (!_seg) {
      var saved = readSeg();
      _seg = saved || 'mtg';
    }
    setSeg(_seg, true);
  }

  // --- встраивание ------------------------------------------------------------

  function mount() {
    var sec = document.getElementById('sectionMtg');
    if (!sec || document.getElementById('tgPaneWeb')) return false;
    var tab = document.getElementById('tabMtg');
    if (tab && tab.firstChild && tab.firstChild.nodeType === 3) tab.firstChild.nodeValue = 'Telegram';

    // Всё, что было в секции MTProto, уходит в свою панель как есть — id
    // элементов не меняются, refreshMtg() и остальной код MTProto их находят.
    var paneMtg = document.createElement('div');
    paneMtg.id = 'tgPaneMtg';
    while (sec.firstChild) paneMtg.appendChild(sec.firstChild);

    var bar = document.createElement('div');
    bar.id = 'tgSeg';
    bar.className = 'tg-seg';
    bar.innerHTML =
      '<button type="button" data-seg="mtg">MTProto</button>' +
      '<button type="button" data-seg="web">WEB</button>';
    bar.addEventListener('click', function (ev) {
      var b = ev.target.closest ? ev.target.closest('button[data-seg]') : null;
      if (b) setSeg(b.getAttribute('data-seg'));
    });

    var paneWeb = document.createElement('div');
    paneWeb.id = 'tgPaneWeb';
    paneWeb.className = 'hidden';
    paneWeb.innerHTML = sectionHtml();
    paneWeb.addEventListener('click', onSectionClick);

    sec.appendChild(bar);
    sec.appendChild(paneMtg);
    sec.appendChild(paneWeb);

    try {
      if (typeof ALL_PROTOCOLS !== 'undefined' && ALL_PROTOCOLS.indexOf(KIND) < 0) ALL_PROTOCOLS.push(KIND);
      if (typeof PROTO_LABELS !== 'undefined') {
        PROTO_LABELS.tgweb = 'Telegram WEB';
        if (PROTO_LABELS.mtg) PROTO_LABELS.mtg = 'Telegram MTProto';
      }
    } catch (e) {}

    var origVis = window.applyVisibilityFromConfig;
    if (typeof origVis === 'function') {
      window.applyVisibilityFromConfig = function () {
        origVis.apply(this, arguments);
        applyOwnVisibility();
      };
    }
    var origSwitch = window.switchTab;
    if (typeof origSwitch === 'function') {
      window.switchTab = function (t) {
        origSwitch.apply(this, arguments);
        if (t === 'mtg' && _seg === 'web') refresh();
      };
    }
    var origRefresh = window.refreshAll;
    if (typeof origRefresh === 'function') {
      // Общий опрос панели (раз в 15 с) и общие модалки после сохранения зовут
      // refreshAll — дописываем себя, когда WEB на экране.
      var ticks = 0;
      window.refreshAll = function () {
        var r = origRefresh.apply(this, arguments);
        if (typeof currentTab !== 'undefined' && currentTab === 'mtg' && _seg === 'web') {
          refresh();
        } else if ((ticks++ % 4) === 0 && cfgEnabled(KIND)) {
          // Вне экрана — только статус и раз в минуту: точке в шапке нужно
          // знать, жив ли WEB, а список клиентов тут не нужен.
          req('/status').then(function (st) {
            state.status = st;
            try { if (typeof _protoRunning !== 'undefined') _protoRunning.tgweb = st.installed ? !!st.active : null; } catch (e) {}
            try { if (typeof _updateHeaderDot === 'function') _updateHeaderDot(); } catch (e) {}
          }).catch(function () {});
        }
        return r;
      };
    }
    registerSvcAdapter();
    return true;
  }

  function sectionHtml() {
    return '' +
      '<div id="tgBanner" class="tg-banner hidden"></div>' +
      '<div class="stats-bar stats-bar--4">' +
        '<div class="stat-card">' +
          '<div class="label">Клиенты</div>' +
          '<div class="value accent" style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;">' +
            '<span id="tgTotal">0</span>' +
            '<span class="tg-sub">всего</span><span style="color:var(--text3);">·</span>' +
            '<span id="tgOnline" style="color:var(--green);">0</span><span class="tg-sub">онлайн</span>' +
          '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="label">Адрес</div>' +
          '<div class="value" id="tgHost" style="font-size:16px;overflow-wrap:anywhere;">—</div>' +
          '<div id="tgHostSub" class="tg-tile-sub">порт 443</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="label">Вход на 443</div>' +
          '<div class="value" id="tgMode" style="font-size:18px;">—</div>' +
          '<div id="tgModeSub" class="tg-tile-sub"></div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="label" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<span>Сервис telemt</span>' +
            '<button class="stat-icon" data-tg="settings" title="Настройки: запуск, перезапуск, ' +
              'префикс, проверки цепочки, удаление">&#9881;</button>' +
          '</div>' +
          '<div class="value orange" id="tgService">—</div>' +
        '</div>' +
      '</div>' +
      '<div class="toolbar">' +
        '<h2>Клиенты WEB-прокси</h2>' +
        '<div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;">' +
          '<button class="btn btn-sm btn-ghost" data-tg="logs">Логи</button>' +
          '<button class="btn btn-sm btn-success" data-tg="add">+ Новый клиент</button>' +
          '<button id="tgCollapseAllBtn" class="btn-collapse" data-tg="collapseall" title="Свернуть всех" ' +
            'aria-label="Свернуть всех">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
            'stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>' +
          '</button>' +
        '</div>' +
      '</div>' +
      '<div id="tgList" class="peers-list"></div>';
  }

  // --- данные -----------------------------------------------------------------

  function refresh() {
    return Promise.all([
      req('/status').catch(function () { return null; }),
      req('/clients').catch(function () { return null; })
    ]).then(function (res) {
      if (res[0]) state.status = res[0];
      if (res[1]) {
        state.clients = res[1].clients || [];
        state.host = res[1].host || '';
        state.slug = res[1].slug || '';
      }
      state.stale = false;
      try {
        localStorage.setItem(CACHE_KEY, JSON.stringify({
          status: state.status, clients: state.clients, host: state.host, slug: state.slug
        }));
      } catch (e) {}
      render();
    });
  }

  // Прошлый ответ — сразу на экран, живой придёт через пару секунд. Онлайн из
  // кеша не берём: он уже неправда.
  function hydrateFromCache() {
    var c = null;
    try { c = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null'); } catch (e) {}
    if (!c || !Array.isArray(c.clients)) return;
    state.status = c.status || null;
    state.clients = c.clients.map(function (x) { return Object.assign({}, x, { conns: 0, ips_now: [] }); });
    state.host = c.host || '';
    state.slug = c.slug || '';
    state.stale = true;
    try { render(); } catch (e) { console.error(e); }
  }

  window.tgwebClients = function () { return state.clients; };
  window.tgwebRerender = function (force) { return force ? refresh() : render(); };

  // --- рендер -----------------------------------------------------------------

  function fmtBytes(n) {
    if (typeof formatBytesShort === 'function') {
      try { return formatBytesShort(Number(n) || 0); } catch (e) {}
    }
    n = Number(n) || 0;
    var u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + u[i];
  }
  function fmtDate(ts) {
    if (!ts) return '—';
    if (typeof _fmtServerTs === 'function') {
      try { return _fmtServerTs(ts, true) || '—'; } catch (e) {}
    }
    var d = new Date(ts * 1000), p = function (n) { return String(n).padStart(2, '0'); };
    return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' +
           p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function ico(fn, args) {
    try { if (typeof window[fn] === 'function') return window[fn].apply(null, args); } catch (e) {}
    return '';
  }
  function isOnline(c) { return (c.ips_now || []).length > 0 || (c.conns || 0) > 0; }

  function render() {
    var st = state.status || {};
    var set = function (id, val) { var el = document.getElementById(id); if (el) el.textContent = val; };
    set('tgTotal', state.clients.length);
    set('tgOnline', state.clients.filter(isOnline).length);
    set('tgHost', state.host || st.host || '—');

    // Кто принимает 443 для WEB (front.py): установлен — фактический режим,
    // нет — тот, в котором WEB встал бы сейчас.
    var fr = st.installed ? (st.front || '') : (st.front_want || '');
    var modeEl = document.getElementById('tgMode');
    if (modeEl) {
      modeEl.textContent = FRONT_LABEL[fr] || (st.front_reason ? 'занят' : '—');
      modeEl.className = 'value ' + (fr ? 'green' : 'orange');
    }
    set('tgModeSub', fr ? (FRONT_SUB[fr] || '') : (REASON_SHORT[st.front_reason] || ''));
    set('tgHostSub', fr === 'xray' ? 'порт 443 — общий с XRay' : 'порт 443');

    if (!state.stale) {
      try { if (typeof _protoRunning !== 'undefined') _protoRunning.tgweb = st.installed ? !!st.active : null; } catch (e) {}
      try { if (typeof _updateHeaderDot === 'function') _updateHeaderDot(); } catch (e) {}
    }
    var svc = document.getElementById('tgService');
    if (svc) {
      svc.textContent = !st.installed ? 'не установлен' : (st.active ? 'работает' : 'остановлен');
      svc.className = 'value ' + (!st.installed ? 'orange' : (st.active ? 'green' : 'red'));
    }
    renderBanner(st);

    var list = document.getElementById('tgList');
    if (!list) return;
    if (!st.installed && !state.clients.length) {
      list.innerHTML = '';
    } else if (!state.clients.length) {
      list.innerHTML = '<div class="empty-state"><div class="icon">&#9992;</div>' +
        '<p>Клиентов пока нет. У каждого будет своя ссылка: отключить одного — остальные работают.</p></div>';
    } else {
      list.innerHTML = state.clients.map(clientCard).join('');
    }
    refreshCollapseAllBtn();
  }

  // Почему 443 не наш — коротко для плитки; полный текст приходит в front_why.
  var FRONT_LABEL = { xray: 'через XRay', nginx: 'сам (nginx)' };
  var FRONT_SUB = { xray: 'XRay в TLS, WEB за его фоллбеком', nginx: 'XRay на 443 нет — WEB слушает сам' };
  var REASON_SHORT = {
    reality: 'XRay в Reality — нужен TLS', nginx_sites: 'занят сайтами nginx',
    foreign: 'занят другим сервисом', no_cert: 'нет сертификата домена', hold: 'придержан для XRay',
  };

  function frontWarn(st) {
    var html = '<div class="tg-banner-warn">' + esc(st.front_why || '443 сейчас не наш.');
    if (st.front_reason === 'reality') {
      html += ' <a href="#" data-tg="xraysec">⚙ XRay → «Режим на 443»</a>';
    }
    return html + '</div>';
  }

  function renderBanner(st) {
    var b = document.getElementById('tgBanner');
    if (!b) return;
    var blocked = st.installed && st.active && !st.front && st.front_reason !== 'hold';
    var need = !st.installed || !st.active || blocked;
    b.classList.toggle('hidden', !need || !state.status);
    if (!need) return;
    var html;
    if (!st.installed) {
      html = '<b>Telegram WEB-прокси</b> — новый тип прокси Telegram (Desktop 7.1+, iOS и Android 13.0+): ' +
        'трафик идёт обычным HTTPS через ваш домен на 443 и снаружи не отличается от браузера. ' +
        'Панель поставит движок telemt и nginx и сама подключит их к 443: за XRay, если он там в режиме TLS, ' +
        'или напрямую, если XRay на 443 нет, — и проверит цепочку целиком.';
      if (!st.front_want) html += frontWarn(st);
      html += '<div style="margin-top:10px;"><button class="btn btn-primary" data-tg="install"' +
        (st.front_want ? '' : ' disabled') + '>Установить и запустить</button></div>';
    } else if (blocked) {
      html = '<b>WEB-прокси не принимает клиентов:</b> 443 сейчас не его.' + frontWarn(st);
    } else {
      html = 'Сервис telemt не запущен — клиенты WEB не подключатся. Панель перепроверит конфиг, nginx и фоллбек ' +
        'XRay и поднимет его; причина падения — в data/logs/tgweb_access.log.' +
        '<div style="margin-top:10px;"><button class="btn btn-primary" data-tg="start">Запустить</button></div>';
    }
    b.innerHTML = html;
  }

  function allCollapsed() {
    return state.clients.length > 0 &&
           state.clients.every(function (c) { return _collapsed[c.id] !== false; });
  }
  function refreshCollapseAllBtn() {
    var btn = document.getElementById('tgCollapseAllBtn');
    if (!btn) return;
    var col = allCollapsed();
    btn.classList.toggle('is-collapsed', col);
    btn.title = col ? 'Развернуть всех' : 'Свернуть всех';
  }

  function lastSeenItem(c) {
    if (!c.last_ip) return '';
    var geo = c.geo || {};
    var place = [geo.country, geo.city].filter(Boolean).join(', ');
    var val = esc(c.last_ip) + (place ? ' · ' + esc(place) : '') + (geo.org ? ' · ' + esc(geo.org) : '');
    var when = isOnline(c) ? ' <span style="font-weight:normal;color:var(--green);">сейчас</span>'
      : (c.last_seen ? ' <span style="font-weight:normal;">' + esc(fmtDate(c.last_seen)) + '</span>' : '');
    return '<div class="peer-meta-item"><span class="lbl" style="color:var(--text2);">on-line:' + when + '</span>' +
           '<span class="val">' + val + '</span></div>';
  }

  function clientCard(c) {
    var off = !!c.disabled;
    var on = isOnline(c);
    var id = String(c.id);
    var call = function (act) { return "tgAct('" + act + "','" + id + "')"; };
    var collapsed = _collapsed[id] !== false;
    var dot = off ? 'disabled' : (on ? 'online' : 'offline');
    var limitTxt = c.limit_gb
      ? ' &middot; limit: ' + c.limit_gb + ' GB' + (c.disabled_by_limit ? ' (исчерпан)' : '') : '';
    var badges = '';
    if ((c.ips_now || []).length) {
      badges += '<span class="badge badge-rule">IP сейчас: ' + c.ips_now.length + '</span> ';
    }
    if (c.max_ips) badges += '<span class="badge badge-rule">Лимит IP: ' + c.max_ips + '</span> ';
    if (c.disabled_by_limit) badges += '<span class="badge badge-rule">Лимит трафика исчерпан</span> ';
    if (c.scheduled_action) {
      badges += '<span class="badge badge-rule">' + (c.scheduled_action === 'delete' ? 'Удаление' : 'Отключение') +
        ' ' + esc(c.scheduled_at || '') + '</span>';
    }
    return '' +
      '<div class="peer-card' + (collapsed ? ' collapsed' : '') + '" data-id="' + esc(id) + '">' +
        '<div class="peer-top">' +
          '<div class="peer-name">' +
            '<div class="peer-name-row">' +
              '<span class="status-dot ' + dot + '" title="' + (off ? 'Отключён' : (on ? 'Онлайн' : 'Не подключён')) +
              '"></span>' + esc(c.name) +
              '<span class="traffic-total traffic-total--inline" title="Суммарный трафик">total: ' +
                fmtBytes(c.total) + limitTxt + '</span>' +
            '</div>' +
            '<div class="peer-name-badge">' + badges + '</div>' +
          '</div>' +
          '<div class="peer-actions">' +
            '<button class="btn btn-sm btn-ghost" onclick="' + call('link') + '">Конфиг</button>' +
            '<button class="btn btn-sm btn-ghost" onclick="' + call('logs') + '">Логи</button>' +
            ico('allowIpBtnHtml', [call('allowip'),
              ((c.allow_ips || []).length + (c.block_ips || []).length) > 0,
              'Фильтрация по IP (зелёный = список задан)']) +
            ico('pencilBtnHtml', [call('rename')]) +
            ico('trashBtnHtml', [call('delete')]) +
            ico('powerBtnHtml', [call('toggle'), off]) +
            ico('scheduleBtnHtml', [call('sched'), c.scheduled_action || null]) +
            ico('collapseBtnHtml', [id, collapsed]).replace(/onclick="[^"]*"/, 'onclick="' + call('collapse') + '"') +
          '</div>' +
        '</div>' +
        '<div class="peer-meta">' +
          '<div class="peer-meta-item"><span class="lbl">ID</span><span class="val">' + esc(id) + '</span></div>' +
          '<div class="peer-meta-item"><span class="lbl">Создан</span><span class="val">' +
            esc(fmtDate(c.created)) + '</span></div>' +
          lastSeenItem(c) +
          '<div class="peer-meta-item"><span class="lbl">Трафик</span><span class="val">' +
            fmtBytes(c.total) + '</span></div>' +
          '<div class="peer-meta-item"><span class="lbl">Одновременно IP</span><span class="val">' +
            (c.max_ips ? c.max_ips : 'без ограничения') +
            ' <a href="#" class="tg-inline-edit" onclick="' + call('maxips') + ';return false;">изменить</a>' +
          '</span></div>' +
        '</div>' +
      '</div>';
  }

  // --- действия ---------------------------------------------------------------

  function onSectionClick(ev) {
    var el = ev.target.closest ? ev.target.closest('[data-tg]') : null;
    if (!el) return;
    ev.preventDefault();
    var act = el.getAttribute('data-tg');
    if (act === 'add') return addClient();
    if (act === 'collapseall') return toggleAll();
    if (act === 'settings') return openSettings();
    if (act === 'logs') return showLogs(null);
    if (act === 'install') return install();
    if (act === 'start') return startService();
    if (act === 'xraysec' && typeof openProtoSvcModal === 'function') return openProtoSvcModal('xray');
  }

  function toggleAll() {
    if (!state.clients.length) return;
    var collapse = !allCollapsed();
    state.clients.forEach(function (c) { _collapsed[c.id] = collapse ? true : false; });
    render();
  }

  window.tgAct = function (act, id) {
    if (act === 'collapse') {
      _collapsed[id] = _collapsed[id] === false;
      return render();
    }
    var c = state.clients.filter(function (x) { return String(x.id) === String(id); })[0];
    if (!c) return;
    if (act === 'link') return showLink(c);
    if (act === 'logs') return showLogs(c);
    if (act === 'rename') return renameClient(c);
    if (act === 'toggle') return toggleClient(c);
    if (act === 'delete') return deleteClient(c);
    if (act === 'maxips') return editMaxIps(c);
    if (act === 'allowip' && typeof openAllowIpModal === 'function') {
      return openAllowIpModal(id, c.name, KIND);
    }
    if (act === 'sched' && typeof openScheduleModal === 'function') {
      return openScheduleModal(KIND, id, c.name, c.scheduled_action || null, c.scheduled_at || null,
        c.traffic_reset_day != null ? c.traffic_reset_day : null,
        c.limit_gb != null ? c.limit_gb : null);
    }
  };

  function refreshVersions() {
    try { if (typeof loadSystemVersions === 'function') return loadSystemVersions(true); } catch (e) {}
    return Promise.resolve();
  }

  // Установка — общий путь панели (applyProtoInstall): подтверждение, фоновая
  // задача, шаги на затемнении. Тот же, что у кнопки в блоке версий.
  function install() {
    if (typeof applyProtoInstall === 'function') {
      return Promise.resolve(applyProtoInstall(KIND)).then(function () { return refresh(); });
    }
    say('Установка недоступна: обновите панель');
  }

  function startService() {
    busy('Запускаю Telegram WEB', 'Проверяю конфиг, nginx и фоллбек XRay');
    return req('/heal', { method: 'POST' })
      .then(function (j) { say(j.note || 'Запущен'); })
      .catch(function (e) { say('Не удалось: ' + e.message); })
      .then(function () { unbusy(); return refresh(); });
  }

  function addClient() {
    var ov = modal('Новый клиент WEB-прокси',
      field('tgNewName', 'Имя клиента (например, mama_iphone)', '') +
      '<div class="input-hint"></div>' +
      '<div class="tg-hint">У клиента будет своя ссылка и QR. Отключение, лимит и удаление касаются только его.</div>',
      [{ text: 'Создать', cls: 'btn-success', keepOpen: true, act: function (o) {
        var name = ((o.querySelector('#tgNewName') || {}).value || '').trim();
        if (!name) return;
        var btn = o.querySelector('[data-btn]');
        if (btn) { btn.disabled = true; btn.textContent = 'Создаём…'; }
        req('/clients', { method: 'POST', body: { name: name } })
          .then(function (j) {
            o.remove();
            say('Клиент «' + name + '» создан');
            // Ссылки уже в ответе — окно открываем сразу, а список догружается
            // фоном: опрос трафика у telemt не должен держать пользователя.
            if (j.client && j.client.links) showLink(j.client);
            return refresh().then(function () {
              if (j.client && j.client.links) return;
              var c = state.clients.filter(function (x) { return x.id === (j.client || {}).id; })[0];
              if (c) showLink(c);
            });
          })
          .catch(function (e) {
            say(e.message);
            if (btn) { btn.disabled = false; btn.textContent = 'Создать'; }
          });
      } }]);
    nameInput(ov, '#tgNewName', true);
  }

  function renameClient(c) {
    var ov = modal('Переименовать клиента', field('tgRenName', 'Новое имя', c.name) +
      '<div class="input-hint"></div>',
      [{ text: 'OK', cls: 'btn-primary', act: function (o) {
        var name = ((o.querySelector('#tgRenName') || {}).value || '').trim();
        if (!name || name === c.name) return;
        req('/clients/' + encodeURIComponent(c.id), { method: 'PUT', body: { name: name } })
          .then(function () { say('Переименовано в «' + name + '»'); return refresh(); })
          .catch(function (e) { say(e.message); });
      } }]);
    nameInput(ov, '#tgRenName', true);
  }

  function nameInput(ov, sel, enterSubmits) {
    var inp = ov.querySelector(sel);
    if (!inp) return;
    inp.addEventListener('input', function () {
      if (typeof _sanitizeClientNameInput === 'function') _sanitizeClientNameInput(inp);
      else inp.value = inp.value.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
    });
    if (enterSubmits) {
      inp.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { var b = ov.querySelector('[data-btn]'); if (b) b.click(); }
      });
    }
    inp.focus();
    inp.select();
  }

  function toggleClient(c) {
    req('/clients/' + encodeURIComponent(c.id) + '/disable', { method: 'POST', body: { disabled: !c.disabled } })
      .then(function () { say(c.disabled ? 'Клиент включён' : 'Клиент отключён — его сессии оборваны'); return refresh(); })
      .catch(function (e) { say(e.message); });
  }

  function deleteClient(c) {
    modal('Удалить клиента', '<div class="tg-hint">Клиент «' + esc(c.name) + '» потеряет доступ сразу, ' +
      'его ссылка перестанет работать. Остальные клиенты не заметят.</div>',
      [{ text: 'Удалить', cls: 'btn-danger', act: function () {
        req('/clients/' + encodeURIComponent(c.id), { method: 'DELETE' })
          .then(function () { say('Клиент «' + c.name + '» удалён'); return refresh(); })
          .catch(function (e) { say(e.message); });
      } }]);
  }

  function editMaxIps(c) {
    var ov = modal('Одновременные IP — ' + esc(c.name),
      field('tgMaxIps', 'Сколько разных IP может держать клиент одновременно (0 — без ограничения)',
            String(c.max_ips || 0), 'number') +
      '<div class="tg-hint">Против раздачи одной ссылки на десяток человек. Телефон, переходящий между Wi-Fi ' +
      'и мобильной сетью, на короткое время виден с двух адресов — для одного человека разумно 2–3. ' +
      'Применяется без перезапуска.</div>',
      [{ text: 'Сохранить', cls: 'btn-success', act: function (o) {
        var n = parseInt(((o.querySelector('#tgMaxIps') || {}).value || '0'), 10) || 0;
        req('/clients/' + encodeURIComponent(c.id) + '/max-ips', { method: 'POST', body: { max_ips: n } })
          .then(function () { say(n ? 'Лимит IP: ' + n : 'Лимит IP снят'); return refresh(); })
          .catch(function (e) { say(e.message); });
      } }]);
    var inp = ov.querySelector('#tgMaxIps');
    if (inp) { inp.maxLength = 4; inp.focus(); inp.select(); }
  }

  // --- окно «Конфиг»: ссылка, QR, ручной ввод ---------------------------------

  function copy(text, what) {
    if (!text) return say('Пусто');
    navigator.clipboard.writeText(text).then(function () { say((what || 'Скопировано')); });
  }

  function showLink(c) {
    var L = c.links || {};
    var copyRow = function (label, val, key) {
      return '<div class="tg-copy-row"><span class="lbl">' + esc(label) + '</span>' +
        '<code class="tg-code">' + esc(val || '—') + '</code>' +
        '<button class="btn btn-sm btn-ghost" data-copy="' + key + '">Копировать</button></div>';
    };
    var ov = modal('Конфиг — ' + esc(c.name),
      (c.disabled ? '<div class="tg-banner-warn" style="margin-bottom:10px;">Клиент отключён — по ссылке ' +
        'сейчас не подключиться.</div>' : '') +
      '<div class="tg-qr" id="tgQr"></div>' +
      '<div class="tg-hint" style="margin-bottom:12px;">Камера телефона → откроется Telegram и предложит добавить ' +
        'прокси. Или отправьте ссылку человеку: нажатие на неё делает то же самое.</div>' +
      '<div class="tg-link-actions">' +
        '<button class="btn btn-sm btn-success" data-copy="tme">&#128203; Копировать ссылку</button>' +
        '<button class="btn btn-sm btn-ghost" data-open="tg">Открыть в Telegram</button>' +
      '</div>' +
      copyRow('Ссылка t.me', L.tme, 'tme') +
      copyRow('Ссылка tg://', L.tg, 'tg') +
      '<details class="tg-manual"><summary>Ввести вручную</summary>' +
        '<div class="tg-hint" style="margin:8px 0;">Telegram → Настройки → Данные и память → Прокси → ' +
        'Добавить прокси → тип <b>WEB</b>. В форму обычного MTProto эти значения вводить нельзя — ' +
        'это был бы голый MTProxy на 443, его видно и режут.</div>' +
        copyRow('Сервер', L.manual_server, 'server') +
        copyRow('Секрет', L.manual_secret, 'secret') +
      '</details>' +
      '<div class="tg-hint" style="margin-top:12px;">Нужен Telegram Desktop 7.1+, iOS 13.0+ (iOS 15 и новее) ' +
        'или Android 13.0+. Старый клиент ответит «обновите приложение». На телефонах WEB работает, пока ' +
        'Telegram открыт на экране; звонки через него не идут.</div>',
      [{ text: 'Новый ключ', cls: 'btn-ghost', keepOpen: true, act: function (o) { regenSecret(c, o); } }],
      true);
    var box = ov.querySelector('#tgQr');
    if (box && L.tg && typeof QRCode !== 'undefined') {
      try {
        new QRCode(box, { text: L.tg, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
      } catch (e) { box.textContent = 'QR недоступен'; }
    }
    var vals = { tme: L.tme, tg: L.tg, server: L.manual_server, secret: L.manual_secret };
    ov.querySelectorAll('[data-copy]').forEach(function (b) {
      b.addEventListener('click', function () { copy(vals[b.getAttribute('data-copy')], 'Скопировано'); });
    });
    var openBtn = ov.querySelector('[data-open]');
    if (openBtn) openBtn.addEventListener('click', function () { if (L.tg) window.location.href = L.tg; });
  }

  function regenSecret(c, linkModal) {
    modal('Новый ключ для ' + esc(c.name),
      '<div class="tg-hint">Старая ссылка перестанет работать сразу — человеку нужно будет добавить новую. ' +
      'Остальных клиентов это не касается.</div>',
      [{ text: 'Выдать новый', cls: 'btn-danger', act: function () {
        req('/clients/' + encodeURIComponent(c.id) + '/secret', { method: 'POST' })
          .then(function () {
            if (linkModal) linkModal.remove();
            say('Новый ключ выдан');
            return refresh().then(function () {
              var n = state.clients.filter(function (x) { return x.id === c.id; })[0];
              if (n) showLink(n);
            });
          })
          .catch(function (e) { say(e.message); });
      } }]);
  }

  // --- логи -------------------------------------------------------------------

  function geoTxt(g) {
    g = g || {};
    return [[g.country, g.city].filter(Boolean).join(', '), g.org].filter(Boolean).join(' · ');
  }

  function showLogs(c) {
    var ov = modal('Логи WEB-прокси' + (c ? ' — ' + esc(c.name) : ''),
      '<div class="tg-tabs"><button class="active" data-ltab="online">Онлайн</button>' +
      '<button data-ltab="archive">Архив IP</button>' +
      '<button class="btn btn-sm btn-ghost tg-logs-reload" data-reload="1">Обновить</button></div>' +
      '<div id="tgLogsBody" class="tg-logs"><div class="tg-hint">Загружаю…</div></div>', [], true);
    var tab = 'online', data = null;
    var paint = function () {
      var body = ov.querySelector('#tgLogsBody');
      if (!body || !data) return;
      var rows;
      if (tab === 'online') {
        rows = (data.online || []).map(function (s) {
          return '<tr><td>' + esc(s.name || s.user) + '</td><td>' + esc(s.ip || '—') + '</td><td>' +
            esc(geoTxt(s.geo)) + '</td><td>' + esc(s.carrier || '') + '</td><td>' + esc(String(s.streams || 0)) +
            '</td></tr>';
        });
        body.innerHTML = rows.length
          ? '<table class="tg-table"><thead><tr><th>Клиент</th><th>IP</th><th>Где</th><th>Канал</th>' +
            '<th>Потоков</th></tr></thead><tbody>' + rows.join('') + '</tbody></table>'
          : '<div class="tg-hint">' + (data.online_error ? 'API telemt не ответил: ' + esc(data.online_error)
                                                            : 'Сейчас никто не подключён.') + '</div>';
      } else {
        rows = (data.archive || []).map(function (r) {
          return '<tr><td>' + esc(fmtDate(r.ts)) + '</td><td>' + esc(r.name || r.user) + '</td><td>' +
            esc(r.ip) + '</td><td>' + esc(geoTxt(r.geo)) + '</td></tr>';
        });
        body.innerHTML = rows.length
          ? '<table class="tg-table"><thead><tr><th>Последний раз</th><th>Клиент</th><th>IP</th><th>Где</th>' +
            '</tr></thead><tbody>' + rows.join('') + '</tbody></table>'
          : '<div class="tg-hint">Подключений ещё не было.</div>';
      }
    };
    var load = function () {
      req('/logs' + (c ? '?client=' + encodeURIComponent(c.id) : ''))
        .then(function (j) { data = j; paint(); })
        .catch(function (e) {
          var body = ov.querySelector('#tgLogsBody');
          if (body) body.innerHTML = '<div class="tg-hint">Не удалось: ' + esc(e.message) + '</div>';
        });
    };
    ov.querySelectorAll('[data-ltab]').forEach(function (b) {
      b.addEventListener('click', function () {
        tab = b.getAttribute('data-ltab');
        ov.querySelectorAll('[data-ltab]').forEach(function (x) { x.classList.toggle('active', x === b); });
        paint();
      });
    });
    var rb = ov.querySelector('[data-reload]');
    if (rb) rb.addEventListener('click', load);
    load();
  }

  // --- «Отдать 443 WEB-прокси» ---------------------------------------------------
  // Явный выбор админа, когда 443 держит XRay (Reality, или TLS, но XRay ему не
  // нужен): XRay останавливается и снимается с автозапуска, WEB занимает 443.

  function canTake443(st) {
    var x = st.xray || {};
    return !!(st.installed && st.front !== 'nginx' && x.installed && x.port === 443 &&
              st.front_reason !== 'nginx_sites' && st.front_reason !== 'foreign');
  }

  function take443() {
    modal('Отдать 443 WEB-прокси',
      '<div class="tg-hint"><b>XRay (VLESS) будет остановлен и выключен из автозапуска</b> — все клиенты XRay ' +
      'на этом сервере перестанут подключаться. 443 займёт Telegram WEB: nginx с сертификатом домена, сайт и ' +
      'вход в панель останутся на 443. Hysteria, AmneziaWG и MTProto это не затронет.<br><br>' +
      'Вернуть XRay можно в любой момент: запустите его в режиме TLS — WEB уйдёт за его фоллбек сам. ' +
      'В режиме Reality XRay с WEB на 443 не уживётся.</div>',
      [{ text: 'Остановить XRay и отдать 443', cls: 'btn-danger', act: function () {
        busy('Отдаю 443 WEB-прокси', 'Останавливаю XRay, переключаю nginx на 443');
        req('/take443', { method: 'POST' })
          .then(function (j) {
            if (j && j.async && typeof _pollDepFix === 'function') {
              return _pollDepFix('take443:tgweb', null, Date.now(), 'Переключение 443', 2 * 60 * 1000)
                .then(function (d) { if (!d.ok) throw new Error(d.msg); return d; });
            }
            return j;
          })
          .then(function () { say('443 у Telegram WEB'); })
          .catch(function (e) { say('Не удалось: ' + e.message); })
          .then(function () {
            unbusy();
            if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
            refresh();
          });
      } }]);
  }

  // --- общая модалка ⚙ ----------------------------------------------------------

  function openSettings() {
    if (typeof window.openProtoSvcModal === 'function') return window.openProtoSvcModal(KIND);
    say('Модалка настроек протокола недоступна');
  }

  function registerSvcAdapter() {
    var reg = window.PROTO_SVC;
    if (!reg) return;
    reg.tgweb = {
      title: 'Telegram WEB',
      load: function () {
        return req('/status').then(function (st) {
          state.status = st;
          return { installed: !!st.installed, active: !!st.active, autostart: !!st.autostart,
                   unit: 'telemt', st: st };
        });
      },
      optionsHtml: function (s) {
        var st = s.st || {};
        var p = st.ports || {};
        var row = function (k, v) {
          return '<div class="tg-kv"><span>' + esc(k) + '</span><b>' + esc(v == null || v === '' ? '—' : v) + '</b></div>';
        };
        return '' +
          '<div class="psvc-sec-h">Цепочка</div>' +
          row('Домен', st.host) +
          row('Префикс пути', st.slug) +
          row('Вход на 443', FRONT_LABEL[st.front] || ('не наш' + (REASON_SHORT[st.front_reason]
                                                                 ? ': ' + REASON_SHORT[st.front_reason] : ''))) +
          row('Режим XRay на 443', (st.xray_mode || '—').toUpperCase()) +
          (st.front === 'nginx'
            ? row('nginx', '443 с сертификатом ' + (st.host || '—'))
            : row('Фоллбек XRay → nginx', st.wired ? ('127.0.0.1:' + p.nginx_port + (st.wired_in_sync ? '' : ' (расходится)'))
                                                  : 'не подключён')) +
          row('Сайт и панель дальше', st.prev_dest ? '127.0.0.1:' + st.prev_dest : '—') +
          row('Вход telemt / API', (p.web_port || '—') + ' / ' + (p.api_port || '—') + ' (127.0.0.1)') +
          row('Выход к Telegram', st.cascade_live ? 'через ВПН2 (каскад)' : 'напрямую') +
          '<div class="psvc-row-d" style="margin:6px 0 14px;">' + esc((st.front_why || '').replace(/([^.!?])\s*$/, '$1.')) + ' Ссылка WEB не ' +
            'содержит порта — клиент всегда идёт на 443, поэтому другой порт невозможен. Внутренние порты ' +
            'занесены в реестр портов панели — их не займёт другой сервис.</div>' +
          '<div class="psvc-actions" style="margin:0 0 14px;display:flex;gap:8px;flex-wrap:wrap;">' +
            '<button class="btn btn-sm btn-ghost" id="tgHealBtn">Перепроверить и починить цепочку</button>' +
            '<button class="btn btn-sm btn-ghost" id="tgSlugBtn">Новый префикс пути</button>' +
            (canTake443(st) ? '<button class="btn btn-sm btn-danger" id="tgTake443Btn">Отдать 443 WEB-прокси</button>' : '') +
          '</div>' +
          '<div class="psvc-row-d">Новый префикс перевыпускает ссылки <b>всех</b> клиентов — нужен, только если ' +
            'префикс засветился. Каскад через ВПН2 включается на вкладке Mihomo.</div>';
      },
      onMount: function (root) {
        var heal = root.querySelector('#tgHealBtn');
        if (heal) heal.addEventListener('click', function () {
          busy('Проверяю цепочку WEB-прокси', 'Конфиг telemt, блок nginx, фоллбек XRay');
          req('/heal', { method: 'POST' })
            .then(function (j) { say(j.note || 'Готово'); })
            .catch(function (e) { say('Не удалось: ' + e.message); })
            .then(function () {
              unbusy();
              if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
              refresh();
            });
        });
        var take = root.querySelector('#tgTake443Btn');
        if (take) take.addEventListener('click', take443);
        var slug = root.querySelector('#tgSlugBtn');
        if (slug) slug.addEventListener('click', function () {
          modal('Новый префикс пути',
            '<div class="tg-hint">Ссылки <b>всех</b> клиентов перестанут работать сразу, каждому нужно будет ' +
            'выдать новую. Делайте это, только если префикс засветился (например, ссылку выложили в открытый ' +
            'доступ).</div>',
            [{ text: 'Сменить префикс', cls: 'btn-danger', act: function () {
              busy('Меняю префикс', 'telemt, nginx и XRay перечитывают настройки');
              req('/slug', { method: 'POST' })
                .then(function () { say('Префикс сменён — перевыдайте ссылки клиентам'); })
                .catch(function (e) { say('Не удалось: ' + e.message); })
                .then(function () {
                  unbusy();
                  if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
                  refresh();
                });
            } }]);
        });
      },
      svcAction: function (action) {
        if (action === 'restart' || action === 'start') return req('/restart', { method: 'POST' });
        if (action === 'stop') return req('/stop', { method: 'POST' });
        return req('/autostart', { method: 'POST', body: { enabled: action === 'autostart_on' } });
      },
      restartNote: 'Перезапуск обрывает живые сессии WEB — клиенты переподключаются сами за пару секунд.',
      install: install,
      uninstall: {
        label: 'Удалить Telegram WEB с сервера',
        body: 'Общий фоллбек XRay вернётся туда, куда вёл раньше (сайт и вход в панель продолжат работать), ' +
              'блок nginx awg-panel-tgweb будет снят — если WEB держал 443 сам, порт освободится, — сервис ' +
              'telemt остановлен, бинарь и конфиг удалены. Сам nginx остаётся. MTProto, XRay, AmneziaWG и ' +
              'Hysteria это не затронет.',
        run: function (purge) {
          return req('/uninstall', { method: 'POST', body: { purge_data: !!purge } })
            .then(function (j) { refreshVersions(); refresh(); return j || { ok: true }; })
            .catch(function (e) { return { ok: false, error: e.message }; });
        },
      },
      afterAction: function () { refresh(); },
    };
  }

  // --- модалки (alert/confirm/prompt в панели не используются) -----------------

  function field(id, label, value, type) {
    // Числа — текстовым полем с inputmode=numeric: стрелки type=number
    // уродливы и не нужны, а телефон и так откроет цифровую клавиатуру.
    var attrs = type === 'number'
      ? 'type="text" inputmode="numeric" pattern="[0-9]*" autocomplete="off" ' +
        'oninput="this.value=this.value.replace(/\\D+/g,\'\')"'
      : 'type="' + (type || 'text') + '"';
    return '<label class="tg-field"><span>' + esc(label) + '</span>' +
           '<input id="' + id + '" ' + attrs + ' value="' + esc(value) + '"></label>';
  }

  function modal(title, bodyHtml, buttons, wide) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay tg-modal';
    var btns = (buttons || []).map(function (b, i) {
      return '<button class="btn ' + (b.cls || 'btn-ghost') + '" data-btn="' + i + '">' + esc(b.text) + '</button>';
    }).join('');
    ov.innerHTML = '<div class="modal' + (wide ? ' modal-wide' : '') + '">' +
        '<h3>' + title + '</h3>' +
        '<div class="tg-modal-body">' + bodyHtml + '</div>' +
        '<div class="modal-actions"><button class="btn btn-ghost" data-close="1">Закрыть</button>' + btns + '</div>' +
      '</div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function (e) {
      if (e.target.getAttribute && e.target.getAttribute('data-close')) { ov.remove(); return; }
      var idx = e.target.getAttribute && e.target.getAttribute('data-btn');
      if (idx === null || idx === undefined) return;
      var b = buttons[+idx];
      if (b && b.act) b.act(ov);
      if (b && !b.keepOpen) ov.remove();
    });
    return ov;
  }

  // --- старт ------------------------------------------------------------------

  function boot() {
    if (!mount()) return;
    applyOwnVisibility();
    hydrateFromCache();
    // После перезагрузки страницы прямо на вкладке — данные сразу. Иначе их
    // подтянет общий опрос (refreshAll) после входа.
    if (typeof currentTab !== 'undefined' && currentTab === 'mtg' && _seg === 'web') refresh();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
