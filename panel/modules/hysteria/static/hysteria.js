/* Вкладка Hysteria 2.
 *
 * Пакет самостоятельно встраивается в панель: добавляет кнопку вкладки, свою
 * секцию и оборачивает switchTab. В index.html и app.js правок нет — если этот
 * файл не загрузится, остальные протоколы продолжат работать как раньше.
 */
(function () {
  'use strict';

  var API = (typeof window.API === 'string') ? window.API : '';
  var TAB = 'hysteria';
  var state = { status: null, clients: [], settings: null, global: null, catalog: null };
  // id → false означает «развёрнут»; по умолчанию карточки свёрнуты, как у XRay.
  var _collapsed = {};
  // Псевдо-клиент «Глобальные правила»: тот же приём, что у XRay, — карточка
  // живёт в общем списке и пользуется общими хелперами по своему «id».
  var GID = '__hysteria_global__';

  function esc(s) {
    return (typeof escHtml === 'function') ? escHtml(s) : String(s == null ? '' : s);
  }
  function say(msg) {
    if (typeof toast === 'function') toast(msg); else console.log(msg);
  }

  function req(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    if (opts.body && typeof opts.body !== 'string') {
      opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(API + '/api/hysteria' + path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    });
  }

  // --- встраивание в панель -------------------------------------------------

  function mountTab() {
    var tabs = document.querySelector('.tabs') ||
               (document.getElementById('tabXray') || {}).parentNode;
    if (!tabs || document.getElementById('tabHysteria')) return false;
    var btn = document.createElement('button');
    btn.className = 'tab-btn';
    btn.id = 'tabHysteria';
    btn.textContent = 'Hysteria';
    btn.addEventListener('click', function () { switchTab(TAB); });
    tabs.appendChild(btn);

    var host = (document.getElementById('sectionMihomo') ||
                document.getElementById('sectionMtg'));
    if (!host) return false;
    var sec = document.createElement('div');
    sec.id = 'sectionHysteria';
    sec.className = 'hidden';
    sec.innerHTML = sectionHtml();
    host.parentNode.insertBefore(sec, host.nextSibling);

    // TAB_IDS/ALL_PROTOCOLS/PROTO_LABELS — const, но это массивы и объект:
    // мутировать можно, переприсваивать нельзя. Так вкладка и чекбокс в
    // «Скрыть протоколы / платформы» появляются без единой правки app.js.
    try { if (typeof TAB_IDS !== 'undefined') TAB_IDS.push(TAB); } catch (e) {}
    try {
      if (typeof ALL_PROTOCOLS !== 'undefined' && ALL_PROTOCOLS.indexOf(TAB) < 0) ALL_PROTOCOLS.push(TAB);
      if (typeof PROTO_LABELS !== 'undefined') PROTO_LABELS.hysteria = 'Hysteria 2';
    } catch (e) {}

    // Видимость вкладки: app.js перебирает жёсткий список протоколов, нас там нет,
    // поэтому дополняем его своим проходом после оригинала.
    var origVis = window.applyVisibilityFromConfig;
    if (typeof origVis === 'function') {
      window.applyVisibilityFromConfig = function () {
        origVis.apply(this, arguments);
        applyOwnVisibility();
      };
    }

    var orig = window.switchTab;
    if (typeof orig === 'function') {
      window.switchTab = function (tab) {
        orig.apply(this, arguments);
        if (tab === TAB) refresh();
      };
    }
    sec.addEventListener('click', onSectionClick);
    // Тумблер журнала живёт в модалке настроек протокола — она вне нашей секции,
    // поэтому слушаем документ, а не sec.
    document.addEventListener('change', function (ev) {
      if (ev.target && ev.target.id === 'hyAccessLog') toggleAccessLog(ev.target.checked);
      if (ev.target && ev.target.id === 'hyHop') toggleHop(ev.target);
      if (ev.target && ev.target.id === 'hySniff') toggleSniff(ev.target);
    });
    registerSvcAdapter();
    return true;
  }

  function sectionHtml() {
    return '' +
      '<div class="stats-bar stats-bar--4">' +
        '<div class="stat-card">' +
          '<div class="label" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<span>Клиенты</span>' +
            '<button class="stat-icon" data-hy="streams" title="Активные соединения всех клиентов прямо сейчас" ' +
              'aria-label="Активные соединения">&#8646;</button>' +
          '</div>' +
          '<div class="value accent" style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;">' +
            '<span id="hyTotal">0</span>' +
            '<span style="font-size:13px;color:var(--text3);font-weight:normal;">всего</span>' +
            '<span style="color:var(--text3);">·</span>' +
            '<span id="hyOnline" style="color:var(--green);">0</span>' +
            '<span style="font-size:13px;color:var(--text3);font-weight:normal;">онлайн</span>' +
          '</div>' +
        '</div>' +
        // Адрес подключения и маскировочный сайт — РАЗНЫЕ вещи, поэтому и плитки
        // разные. Адрес клиент указывает в профиле; маскировка — то, что видит
        // посторонний, постучавшийся на этот порт обычным HTTP/3.
        '<div class="stat-card">' +
          // Порт правится прямо с плитки: это единственное место, где он виден
          // всем сразу, а лезть за ним в ⚙ не очевидно — так же, как у AWG и MTProto.
          '<div class="label" style="display:flex;justify-content:space-between;align-items:center;gap:6px;">' +
            // nowrap: без него «АДРЕС ПОДКЛЮЧЕНИЯ» ломается на две строки — карандаш
            // отъедает у подписи ровно столько, сколько ей не хватало.
            '<span style="white-space:nowrap;">Адрес подключения</span>' +
            '<button class="stat-icon" data-hy="port" title="Сменить UDP-порт Hysteria" ' +
              'aria-label="Сменить UDP-порт">&#9998;</button>' +
          '</div>' +
          '<div class="value" id="hyHost" style="font-size:18px;">—</div>' +
          '<div id="hyPort" style="font-size:12px;color:var(--text3);margin-top:4px;"></div>' +
          '<div id="hysteriaPortConflict" class="hidden" style="font-size:11px;color:var(--orange);margin-top:4px;"></div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="label" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<span>Маскировка под</span>' +
            '<button class="stat-icon" data-hy="mask" title="Сменить маскировочный сайт" ' +
              'aria-label="Сменить маскировочный сайт">&#9998;</button>' +
          '</div>' +
          '<div class="value green" id="hyMask" style="font-size:18px;overflow-wrap:anywhere;">—</div>' +
          '<div style="font-size:12px;color:var(--text3);margin-top:4px;">что отдаётся чужому запросу</div>' +
        '</div>' +
        // Версию не дублируем: её показывает общий блок версий протокола справа
        // от вкладок — там же, где у AWG/XRay/mtg, вместе с кнопкой обновления.
        '<div class="stat-card">' +
          '<div class="label" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<span>Сервис Hysteria</span>' +
            '<button class="stat-icon" data-hy="settings" ' +
              'title="Настройки протокола: порт, маскировка, обфускация, перезапуск, удаление">&#9881;</button>' +
          '</div>' +
          '<div class="value orange" id="hyService">—</div>' +
        '</div>' +
      '</div>' +
      '<div id="hyNotInstalled" class="hy-banner hidden">' +
        '<span id="hyBannerText"></span>' +
        '<div style="margin-top:10px;"><button class="btn btn-primary" data-hy="setup"><span id="hyBannerBtn">Установить и запустить</span></button></div>' +
      '</div>' +
      '<div class="toolbar">' +
        '<h2>Клиенты Hysteria</h2>' +
        // Тумблер журнала и кнопки сервиса переехали в общую модалку настроек
        // протокола (⚙ на плитке «Сервис») — тулбар у всех протоколов одинаков.
        '<div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;">' +
          '<button class="btn btn-sm btn-ghost" data-hy="catalog" title="Каталог списков RULE-SET (Shadowrocket + Loon + Clash)">Списки правил</button>' +
          '<button class="btn btn-sm btn-success" data-hy="add">+ Новый клиент</button>' +
          '<button id="hyCollapseAllBtn" class="btn-collapse" data-hy="collapseall" title="Свернуть всех" aria-label="Свернуть всех">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>' +
          '</button>' +
        '</div>' +
      '</div>' +
      '<div id="hyList" class="peers-list"></div>';
  }

  function applyOwnVisibility() {
    // _serverConfig объявлен в app.js через let — а let/const на верхнем уровне
    // скрипта НЕ становятся свойствами window. window._serverConfig поэтому был
    // всегда undefined, и вкладка не пряталась никогда. Читаем по имени, как
    // ALL_PROTOCOLS выше: глобальная лексическая область у скриптов общая.
    var cfg = (typeof _serverConfig !== 'undefined') ? _serverConfig : window._serverConfig;
    var tab = document.getElementById('tabHysteria');
    if (!tab) return;
    // Ключа нет вовсе (совсем старый server.json) — показываем: скрыть протокол
    // пользователь всегда может сам, а вот найти невидимую вкладку — нет.
    var list = cfg && cfg.enabled_protocols;
    var on = !Array.isArray(list) || list.indexOf(TAB) >= 0;
    tab.classList.toggle('hidden', !on);
    var sec = document.getElementById('sectionHysteria');
    if (sec && !on) sec.classList.add('hidden');
  }

  // --- рендер ---------------------------------------------------------------

  function refresh() {
    return Promise.all([
      req('/status').catch(function () { return null; }),
      req('/clients').catch(function () { return { clients: [] }; }),
      loadCatalog()
    ]).then(function (res) {
      state.status = res[0];
      state.clients = (res[1] && res[1].clients) || [];
      // Глобальные правила приезжают вместе со статусом — отдельный запрос был
      // бы лишним, состояние у них крошечное.
      if (res[0] && res[0].global) state.global = res[0].global;
      state.stale = false;
      try {
        localStorage.setItem(CACHE_KEY, JSON.stringify({
          status: state.status, clients: state.clients, catalog: state.catalog, global: state.global
        }));
      } catch (e) {}
      render();
    });
  }

  // Последний ответ прошлой сессии — список клиентов рисуется сразу, а не
  // после systemctl/GitHub/API ядра на бэке. Онлайн из кеша не берём: он уже
  // неправда; живой refresh() перерисует через пару секунд.
  var CACHE_KEY = 'awgPanel:hyCache:v1';
  function hydrateFromCache() {
    var c = null;
    try { c = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null'); } catch (e) {}
    if (!c || !Array.isArray(c.clients)) return;
    state.status = c.status || null;
    state.clients = c.clients.map(function (x) { return Object.assign({}, x, { devices: 0 }); });
    state.catalog = c.catalog || state.catalog;
    state.global = c.global || state.global;
    state.stale = true;
    try { render(); } catch (e) { console.error(e); }
  }

  function loadCatalog() {
    // Каталог правил в панели ОДИН на все протоколы: и списки клиента, и
    // серверные глобальные правила берутся из него же. Перечитываем каждый раз:
    // каталог правит общий менеджер «Списки правил», и закешированная копия
    // показывала бы удалённые записи и прятала добавленные.
    return fetch(API + '/api/xray/rule-lists', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        var raw = (j && j.lists) || {};
        state.catalog = Array.isArray(raw)
          ? { lists: raw, global: [] }
          : { lists: raw.lists || [], global: raw.global || [] };
        return state.catalog;
      })
      // Сеть отвалилась — оставляем прошлый каталог: обнулить его значило бы
      // показать «Каталог пуст» и снести галочки в глазах пользователя.
      .catch(function () {
        if (!state.catalog) state.catalog = { lists: [], global: [] };
        return state.catalog;
      });
  }

  function render() {
    var st = state.status || {};
    var set = function (id, val) {
      var el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    set('hyTotal', state.clients.length);
    set('hyOnline', state.clients.filter(function (c) { return (c.devices || 0) > 0; }).length);
    set('hyHost', st.host || '—');
    set('hyPort', st.port ? ('UDP ' + st.port + ' (QUIC) — с TCP-портом XRay не пересекается') : '');
    // Столкновение по UDP видно только здесь: соседей у Hysteria двое —
    // AmneziaWG и инбаунд Hysteria внутри XRay, — и оба живут в своих файлах.
    // Без подписи конфликт всплывал бы только тогда, когда сервис уже не поднялся.
    var conflictEl = document.getElementById('hysteriaPortConflict');
    if (conflictEl) {
      conflictEl.textContent = st.conflict || '';
      conflictEl.classList.toggle('hidden', !st.conflict);
    }
    // Маскировка: то, что hysteria отдаёт постороннему запросу на этот же порт.
    // Пустой адрес — это не «не задано», а режим «голый 404».
    var maskEl = document.getElementById('hyMask');
    if (maskEl) {
      var maskUrl = (st.masquerade || '').trim();
      maskEl.textContent = maskUrl ? maskUrl.replace(/^https?:\/\//, '') : 'голый 404';
      maskEl.style.color = maskUrl ? '' : 'var(--text3)';
    }

    // Точка состояния в шапке панели горит, если жив хоть один протокол —
    // Hysteria должна в этом участвовать наравне с остальными.
    if (!state.stale) {
      try { if (typeof _protoRunning !== 'undefined') _protoRunning.hysteria = !!st.active; } catch (e) {}
      try { if (typeof _updateHeaderDot === 'function') _updateHeaderDot(); } catch (e) {}
    }

    var svc = document.getElementById('hyService');
    if (svc) {
      var active = !!st.active;
      svc.textContent = !st.installed ? 'не установлен' : (active ? 'работает' : 'остановлен');
      svc.className = 'value ' + (!st.installed ? 'orange' : (active ? 'green' : 'red'));
    }
    // Баннер нужен не только когда бинаря нет, но и когда сервис лежит: иначе
    // после неудачной установки кнопка исчезала и повторить попытку было нечем.
    var banner = document.getElementById('hyNotInstalled');
    if (banner) {
      var needsAction = !st.installed || !st.active;
      banner.classList.toggle('hidden', !needsAction);
      if (needsAction) {
        set('hyBannerText', st.installed
          ? ('Бинарь установлен, но сервис не запущен. Панель перегенерирует конфиг и поднимет его заново. ' +
             'Если снова упадёт — причина будет в data/logs/hysteria_access.log.')
          : ('Hysteria 2 на сервере не установлена. Панель скачает бинарь с GitHub, выпустит самоподписанный ' +
             'сертификат и поднимет сервис на UDP-порту — трафик XRay на TCP/443 это не затронет.'));
        set('hyBannerBtn', st.installed ? 'Запустить заново' : 'Установить и запустить');
      }
    }

    var logSw = document.getElementById('hyAccessLog');
    if (logSw) {
      logSw.checked = !!st.access_log;
      var row = logSw.closest ? logSw.closest('.switch-row') : null;
      if (row) row.classList.toggle('is-on', !!st.access_log);
    }

    var list = document.getElementById('hyList');
    if (!list) return;
    var cards = globalCard();
    if (!state.clients.length) {
      cards += '<div class="empty-state"><div class="icon">&#9881;</div>' +
               '<p>Клиентов пока нет. Создайте первого, чтобы начать.</p></div>';
    } else {
      cards += state.clients.map(clientCard).join('');
    }
    list.innerHTML = cards;
    refreshCollapseAllBtn();
  }

  function allCollapsed() {
    return state.clients.length > 0 &&
           state.clients.every(function (c) { return _collapsed[c.id] !== false; });
  }

  function refreshCollapseAllBtn() {
    var btn = document.getElementById('hyCollapseAllBtn');
    if (!btn) return;
    var col = allCollapsed();
    btn.classList.toggle('is-collapsed', col);
    btn.title = col ? 'Развернуть всех' : 'Свернуть всех';
    btn.setAttribute('aria-label', btn.title);
  }

  function toggleAllCards() {
    if (!state.clients.length) return;
    var collapse = !allCollapsed();
    state.clients.forEach(function (c) { _collapsed[c.id] = collapse ? true : false; });
    render();
  }

  // --- псевдо-карточка «Глобальные правила» ---------------------------------
  //
  // У hysteria список доступа один на весь сервер (в момент авторизации юзер
  // известен, в момент маршрутизации — уже нет), поэтому серверные правила
  // могут быть только общими. Вид и логика — как у Global rules XRay: правки
  // копятся в pending, «Применить» их фиксирует.

  function gState() {
    return (state.global && state.global.pending) ||
           { enabled: false, mode: 'lists', lists: [], countries: [] };
  }
  function gApplied() {
    return (state.global && state.global.applied) ||
           { enabled: false, mode: 'lists', lists: [], countries: [] };
  }

  function gNorm(s) {
    if (!s || !s.enabled) return '{"enabled":false}';
    return JSON.stringify({
      enabled: true,
      mode: s.mode || 'lists',
      lists: (s.lists || []).slice().map(String).sort(),
      countries: (s.countries || []).slice().map(function (c) { return String(c).toUpperCase(); }).sort()
    });
  }
  function gDirty() { return gNorm(gState()) !== gNorm(gApplied()); }

  function globalCard() {
    var pending = gState(), applied = gApplied();
    var enabled = !!pending.enabled;
    var mode = pending.mode || 'lists';
    if (!(GID in _collapsed)) _collapsed[GID] = true;
    var collapsed = _collapsed[GID] !== false;
    var st = state.status || {};

    var badge;
    if (!applied.enabled) {
      badge = '<span class="badge badge-rule" style="opacity:.6;">Global rules выключены</span>';
    } else if (applied.mode === 'lists') {
      badge = '<span class="badge badge-rule">Списки правил [' + (applied.lists || []).length + ']</span>';
    } else if (applied.mode === 'via') {
      badge = '<span class="badge badge-rule">Страны ✔ — не блокируем [' + (applied.countries || []).length + ']</span>';
    } else {
      badge = '<span class="badge badge-rule">Страны ✔ — блокируем [' + (applied.countries || []).length + ']</span>';
    }
    if (st.cascade) {
      badge += ' <span class="badge badge-rule">Каскад через ВПН2</span>';
    }
    var dot = applied.enabled
      ? '<span class="status-dot online"></span>'
      : '<span class="status-dot disabled" title="Global rules выключены"></span>';

    var sw = function (m, label) {
      var on = enabled && mode === m;
      return '<label class="geo-switch' + (on ? ' on' : '') + '" title="' + esc(label) + '">' +
        '<input type="checkbox"' + (on ? ' checked' : '') +
        ' onchange="hyGlobal(\'mode\',\'' + m + '\',this.checked)">' +
        '<span class="switch-slider"></span>' +
        '<span class="geo-switch-label">' + esc(label) + '</span></label>';
    };

    var body;
    if (!enabled) {
      body = '<div style="color:var(--text3);font-size:12px;text-align:center;padding:40px 0;">' +
             'Global rules выключены. Правила в карточках клиентов работают как обычно — ' +
             'они действуют в профиле клиента, а не на сервере.</div>';
    } else if (mode === 'lists') {
      body = globalListsBlock(pending);
    } else if (typeof renderCountrySelector === 'function') {
      // Режимы по странам работают через geoip.dat. Панель отдаёт свои базы
      // только если рядом стоит XRay; иначе hysteria качает их сама, и на
      // сервере без доступа к GitHub правила молча не заработают.
      var geoWarn = (state.global && state.global.geo_files === false)
        ? '<div class="hy-hint" style="margin-bottom:10px;">Базы geoip.dat на сервере не найдены ' +
          '(их кладёт установщик XRay). Hysteria попробует скачать их сама при первом запуске — ' +
          'если сервер не ходит на GitHub, правила по странам не сработают.</div>'
        : '';
      body = geoWarn + renderCountrySelector(GID, (pending.countries || []).map(String), mode);
    } else {
      body = '<div class="hy-empty">Выбор стран недоступен.</div>';
    }

    var applyBtn = gDirty()
      ? '<button class="btn btn-sm btn-success" onclick="hyGlobal(\'apply\')" title="Применить изменения">Применить</button>'
      : '';
    var total = (st.totals || {});
    var totalBytes = (total.tx || 0) + (total.rx || 0);
    var g = state.global || {};
    // Ежемесячный сброс общего счётчика — как в Global rules XRay: та же общая
    // модалка расписания, у неё показан только Раздел 2.
    var resetDay = (applied.traffic_reset_day != null) ? applied.traffic_reset_day : null;
    var dnsOn = (typeof _globalDnsDefault !== 'undefined' &&
                 _globalDnsDefault && _globalDnsDefault.mode === 'set');

    return '' +
      '<div class="peer-card' + (collapsed ? ' collapsed' : '') + '" data-global-card="1">' +
        '<div class="peer-top">' +
          '<div class="peer-name">' +
            '<div class="peer-name-row">' + dot + 'Global rules' +
              '<span class="traffic-total traffic-total--inline" title="Суммарный трафик Hysteria (↓ + ↑)">total: ' +
                fmtBytes(totalBytes) + '</span>' +
            '</div>' +
            '<div class="peer-name-badge">' + badge + '</div>' +
          '</div>' +
          '<div class="peer-actions">' + applyBtn +
            '<button class="btn btn-sm btn-ghost" onclick="hyGlobal(\'logs\')">Логи</button>' +
            '<button class="btn-act" onclick="hyGlobal(\'refresh\')" title="Перекачать списки правил с источников и применить заново. Это не перезапуск сервиса — меняется только содержимое правил." aria-label="Перекачать списки правил">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/></svg>' +
            '</button>' +
            ico('dnsCfgBtnHtml', ["hyGlobal('dns')", dnsOn, 'DNS-дефолт для новых юзеров']) +
            ico('powerBtnHtml', ["hyGlobal('toggle')", !enabled]) +
            ico('scheduleBtnHtml', ["hyGlobal('sched')", resetDay ? 'active' : null]) +
            ico('collapseBtnHtml', [GID, collapsed]).replace(
              /onclick="[^"]*"/, 'onclick="hyAct(\'collapse\',\'' + GID + '\')"') +
          '</div>' +
        '</div>' +
        '<div class="peer-meta">' +
          '<div class="peer-meta-item"><span class="lbl">Обновлено</span>' +
            '<span class="val">' + esc(g.last_update || '—') + '</span></div>' +
          '<div class="peer-meta-item"><span class="lbl">Строк в acl</span>' +
            '<span class="val">' + (g.acl_rules || 0) + '</span></div>' +
          '<div class="peer-meta-item"><span class="lbl">Трафик Hysteria (всего)</span>' +
            '<span class="val">↓ ' + fmtBytes(total.rx || 0) + ' &middot; ↑ ' + fmtBytes(total.tx || 0) + '</span></div>' +
        '</div>' +
        '<div class="rule-list-section">' +
          '<div class="geo-mode-switches">' +
            sw('lists', 'Списки правил') +
            sw('via', 'Страны ✔ — не блокируем') +
            sw('direct', 'Страны ✔ — блокируем') +
          '</div>' +
          '<div class="geo-body">' + body + '</div>' +
        '</div>' +
      '</div>';
  }

  function globalListsBlock(pending) {
    var cat = (state.catalog && state.catalog.global) || [];
    if (!cat.length) {
      return '<div class="rule-list-empty">Каталог Global пуст. Откройте «Списки правил» на вкладке XRay → Global.</div>';
    }
    var sel = {};
    (pending.lists || []).forEach(function (id) { sel[String(id)] = true; });
    var rows = cat.map(function (r) {
      var view = r.url
        ? '<button class="rule-view" title="Открыть .yaml" onclick="window.open(\'' +
          esc(r.url) + '\',\'_blank\',\'noopener\')">&#128065;</button>'
        : '<span class="rule-view" title="Свой список" style="cursor:default;color:var(--text3);">&#9776;</span>';
      return '<div class="rule-list-row">' +
        '<label class="switch"><input type="checkbox"' + (sel[String(r.id)] ? ' checked' : '') +
        ' onchange="hyGlobal(\'list\',\'' + esc(r.id) + '\',this.checked)">' +
        '<span class="switch-slider"></span></label>' +
        '<span class="rule-name" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' + view +
      '</div>';
    }).join('');
    var allOn = cat.every(function (r) { return sel[String(r.id)]; });
    var n = Object.keys(sel).length;
    return '<div style="margin-top:10px;">' +
      '<div class="plat-block-head pbh-static">' +
        '<span class="pbh-title">Списки <span class="pbh-count">[' + n + '/' + cat.length + ']</span></span>' +
        '<button class="btn btn-sm btn-ghost pbh-all" onclick="hyGlobal(\'listAll\',' + (allOn ? 'false' : 'true') + ')">' +
        (allOn ? 'Выключить все' : 'Включить все') + '</button>' +
      '</div>' +
      '<div class="rule-list-grid" style="margin-top:6px;">' + rows + '</div></div>';
  }

  function gSavePending(patch) {
    // Правки уезжают на сервер сразу, но НЕ применяются: применение
    // перезапускает hysteria и рвёт живые сессии, это делает только «Применить».
    var s = Object.assign({}, gState(), patch || {});
    if (!state.global) state.global = {};
    state.global.pending = s;
    render();
    return req('/global', { method: 'POST', body: s })
      .then(function (j) { state.global = j; render(); })
      .catch(function (e) { say(e.message); });
  }

  window.hyGlobal = function (act, a, b) {
    var s = gState();
    if (act === 'toggle') return gSavePending({ enabled: !s.enabled });
    if (act === 'mode') {
      return b ? gSavePending({ enabled: true, mode: a }) : gSavePending({ enabled: false });
    }
    if (act === 'list') {
      var set = (s.lists || []).map(String).filter(function (x) { return x !== String(a); });
      if (b) set.push(String(a));
      return gSavePending({ lists: set });
    }
    if (act === 'listAll') {
      var cat = (state.catalog && state.catalog.global) || [];
      return gSavePending({ lists: a ? cat.map(function (r) { return String(r.id); }) : [] });
    }
    if (act === 'countries') return gSavePending({ countries: a });
    if (act === 'logs') return window.open('/static/logs.html?hy=global', '_blank', 'noopener');
    if (act === 'streams') return showStreams(null);
    // DNS-дефолт общий на всю панель (server.json), поэтому зовём ту же модалку
    // с тем же kind, что и Global rules XRay, — своей копии настройки нет.
    if (act === 'dns' && typeof openDnsModal === 'function') {
      return openDnsModal('global', '__global__', 'Global rules');
    }
    if (act === 'sched' && typeof openScheduleModal === 'function') {
      var rd = gApplied().traffic_reset_day;
      return openScheduleModal('hysteria_global', GID, 'Global rules', null, null,
                               rd != null ? rd : null, null);
    }
    if (act === 'apply' || act === 'refresh') {
      var busy = (act === 'apply') ? 'Применяем правила' : 'Перекачиваем списки';
      if (typeof showBusyOverlay === 'function') {
        showBusyOverlay(busy, 'Hysteria перезапускается — живые сессии оборвутся');
      }
      return req('/global/' + (act === 'apply' ? 'apply' : 'refresh'), { method: 'POST' })
        .then(function (j) { state.global = j; say('Правила применены'); return refresh(); })
        .catch(function (e) { say(e.message); })
        .then(function () { if (typeof hideBusyOverlay === 'function') hideBusyOverlay(); });
    }
  };

  // Выбор стран рисует общий хелпер панели, а он зовёт функции XRay по id
  // клиента. Перехватываем свои id — и псевдо-клиента Global rules, и обычных
  // клиентов Hysteria: у оригинала они не нашлись бы в списке XRay, и клик по
  // стране молча ничего не делал бы.
  function isOurs(id) {
    id = String(id);
    if (id === GID) return true;
    return state.clients.some(function (c) { return String(c.id) === id; });
  }

  (function wrapCountryHelpers() {
    var origToggle = window.toggleClientCountry;
    if (typeof origToggle === 'function') {
      window.toggleClientCountry = function (id, code, on) {
        if (!isOurs(id)) return origToggle.apply(this, arguments);
        var cc = String(code).toUpperCase();
        if (String(id) === GID) {
          var cur = (gState().countries || []).map(function (c) { return String(c).toUpperCase(); });
          cur = cur.filter(function (c) { return c !== cc; });
          if (on) cur.push(cc);
          return window.hyGlobal('countries', cur);
        }
        var c = state.clients.filter(function (x) { return String(x.id) === String(id); })[0];
        if (!c) return;
        var set = pCountries(c).filter(function (x) { return x !== cc; });
        if (on) set.push(cc);
        return window.hyRule('countries', id, set);
      };
    }
    var origSearch = window.updateCountrySearch;
    if (typeof origSearch === 'function') {
      window.updateCountrySearch = function (id, q) {
        if (!isOurs(id)) return origSearch.apply(this, arguments);
        if (typeof _countrySearchByUuid !== 'undefined') _countrySearchByUuid[id] = q;
        render();
        // Полная перерисовка секции убивает фокус — возвращаем его в поле того
        // же клиента (у каждой карточки поле своё, ищем по её DOM-узлу).
        var card = document.querySelector('#sectionHysteria .peer-card' +
          (String(id) === GID ? '[data-global-card]' : '[data-id="' + id + '"]'));
        var inp = card && card.querySelector('.country-search-row input');
        if (inp) { inp.focus(); inp.setSelectionRange(q.length, q.length); }
      };
    }
  })();

  // Байты форматирует общий хелпер панели: он знает про переключатель языка,
  // и своя копия давала бы «ГБ» на английской версии рядом с «GB» у XRay.
  function fmtBytes(n) {
    if (typeof formatBytesShort === 'function') {
      try { return formatBytesShort(Number(n) || 0); } catch (e) {}
    }
    n = Number(n) || 0;
    var u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n < 10 ? 2 : 1)) + ' ' + u[i];
  }

  // Иконки и классы карточки — те же, что у клиентов XRay: источник истины там,
  // поэтому кнопки строим их же хелперами, а не своими символами.
  function ico(fn, args, fallback) {
    try {
      if (typeof window[fn] === 'function') return window[fn].apply(null, args);
    } catch (e) {}
    return fallback || '';
  }

  function ruleIds(c) {
    var rl = (c && c.rule_lists) || {};
    return Array.isArray(rl) ? rl : (rl.lists || []);
  }

  // Бейдж показывает ПРИМЕНЁННОЕ состояние — то, что реально лежит в выдаваемом
  // клиенту профиле. Свитчи ниже показывают pending (что правят прямо сейчас).
  function ruleBadge(c) {
    var mode = c.geo_mode || 'off';
    var cnt = (c.geo_countries || []).length;
    if (mode === 'lists') return '<span class="badge badge-rule">Списки правил</span>';
    if (mode === 'via') return '<span class="badge badge-rule">Страны с VPN [' + cnt + ']</span>';
    if (mode === 'direct') return '<span class="badge badge-rule">Страны без VPN [' + cnt + ']</span>';
    return '<span class="badge badge-rule" style="opacity:.6;">Правила не применяются</span>';
  }

  // --- pending / applied ------------------------------------------------------
  //
  // Как у XRay: режим, страны и режим исключений копятся в pending, а профиль
  // клиента собирается по applied. Пока они расходятся, в карточке горит
  // «Применить» — иначе клиент, перекачавший конфиг посреди правки, получил бы
  // полуготовые правила.

  function pMode(c) {
    return (c.geo_mode_pending != null ? c.geo_mode_pending : (c.geo_mode || 'off')) || 'off';
  }
  function pCountries(c) {
    return (c.geo_countries_pending || c.geo_countries || []).map(function (s) {
      return String(s).toUpperCase();
    });
  }
  function pListsDefault(c) {
    var v = (c.lists_default_pending != null) ? c.lists_default_pending
                                              : (c.lists_default || 'direct');
    return (v === 'vpn' || v === 'block') ? v : 'direct';
  }
  // Отпечаток: страны важны только в via/direct, режим исключений — только в
  // lists. Иначе «включил режим → выключил» оставлял бы «Применить» гореть.
  function geoNorm(mode, countries, listsDefault) {
    mode = mode || 'off';
    var cs = (mode === 'via' || mode === 'direct')
      ? (countries || []).map(function (s) { return String(s).toUpperCase(); }).slice().sort()
      : [];
    var ld = (mode === 'lists')
      ? ((listsDefault === 'vpn' || listsDefault === 'block') ? listsDefault : 'direct')
      : '';
    return mode + '|' + cs.join(',') + '|' + ld;
  }
  function geoDirty(c) {
    return geoNorm(pMode(c), pCountries(c), pListsDefault(c))
        !== geoNorm(c.geo_mode || 'off', c.geo_countries || [], c.lists_default || 'direct');
  }

  function clientCard(c) {
    var off = !!c.disabled;
    var online = (c.devices || 0) > 0;
    var id = String(c.id);
    var call = function (act) { return "hyAct('" + act + "','" + id + "')"; };
    var collapsed = _collapsed[id] !== false;   // по умолчанию свёрнут, как у XRay
    var dot = off ? 'disabled' : (online ? 'online' : 'offline');
    var limitTxt = c.limit_gb
      ? ' &middot; limit: ' + c.limit_gb + ' GB' + (c.disabled_by_limit ? ' (исчерпан)' : '')
      : '';
    return '' +
      '<div class="peer-card' + (collapsed ? ' collapsed' : '') + '" data-id="' + esc(id) + '">' +
        '<div class="peer-top">' +
          '<div class="peer-name">' +
            '<div class="peer-name-row">' +
              '<span class="status-dot ' + dot + '" title="' +
                (off ? 'Отключён' : (online ? 'Онлайн' : 'Не подключён')) + '"></span>' +
              esc(c.name) +
              '<span class="traffic-total traffic-total--inline" title="Суммарный трафик">total: ' +
                fmtBytes(c.total) + limitTxt + '</span>' +
            '</div>' +
            '<div class="peer-name-badge">' + ruleBadge(c) +
              (c.devices ? ' <span class="badge badge-rule">Устройств: ' + c.devices + '</span>' : '') +
            '</div>' +
          '</div>' +
          '<div class="peer-actions">' +
            (geoDirty(c)
              ? '<button class="btn btn-sm btn-success" onclick="hyRule(\'apply\',\'' + esc(id) +
                '\')" title="Применить изменения правил">Применить</button>'
              : '') +
            '<button class="btn btn-sm btn-ghost" onclick="' + call('config') + '">Конфиг</button>' +
            '<button class="btn btn-sm btn-ghost" onclick="' + call('logs') + '">Логи</button>' +
            // DNS и фильтрация по IP — общие модалки панели, им передаём kind.
            ico('dnsCfgBtnHtml', ["hyAct('dns','" + id + "')",
                                  ico('_dnsIconState', [c], ''),
                                  ico('_dnsIconTitle', [ico('_dnsIconState', [c], '')],
                                      'Настройка DNS')]) +
            ico('allowIpBtnHtml', ["hyAct('allowip','" + id + "')",
                                   ((c.allow_ips || []).length + (c.block_ips || []).length) > 0,
                                   'Фильтрация по IP (зелёный = список задан)']) +
            ico('pencilBtnHtml', [call('rename')]) +
            ico('trashBtnHtml', [call('delete')]) +
            ico('powerBtnHtml', [call('toggle'), off]) +
            ico('scheduleBtnHtml', [call('sched'), c.scheduled_action || null]) +
            ico('collapseBtnHtml', [id, collapsed]).replace(
              /onclick="[^"]*"/, 'onclick="hyAct(\'collapse\',\'' + id + '\')"') +
          '</div>' +
        '</div>' +
        '<div class="peer-meta">' +
          '<div class="peer-meta-item"><span class="lbl">ID</span>' +
            '<span class="val">' + esc(id.slice(0, 8)) + '…' + esc(id.slice(-4)) + '</span></div>' +
          '<div class="peer-meta-item"><span class="lbl">Создан</span>' +
            '<span class="val">' + esc(fmtDate(c.created)) + '</span></div>' +
          lastSeenItem(c) +
          '<div class="peer-meta-item"><span class="lbl">Трафик</span>' +
            '<span class="val">↓ ' + fmtBytes(c.rx) + ' &middot; ↑ ' + fmtBytes(c.tx) + '</span></div>' +
        '</div>' +
        rulesSectionHtml(c) +
      '</div>';
  }

  function fmtDate(ts) {
    if (!ts) return '—';
    // Формат панели: DD.MM.YYYY HH:MM:SS, в системной зоне СЕРВЕРА — тем же
    // хелпером, что рисует даты в карточках AWG/XRay, иначе время «поехало» бы
    // относительно соседних вкладок на компьютере в другой зоне.
    if (typeof _fmtServerTs === 'function') {
      try { return _fmtServerTs(ts, true) || '—'; } catch (e) {}
    }
    var d = new Date(ts * 1000), p = function (n) { return String(n).padStart(2, '0'); };
    return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' +
           p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  // Строка «on-line: <когда> / <IP · страна, город · оператор>» — ровно как в
  // карточке XRay. Без последнего IP пункта нет вовсе: пустая строка «—» только
  // занимала бы место в сетке.
  function lastSeenItem(c) {
    if (!c.last_ip) return '';
    var geo = c.geo || {};
    var place = [geo.country, geo.city].filter(Boolean).join(', ');
    var val = esc(c.last_ip) + (place ? ' · ' + esc(place) : '') +
              (geo.org ? ' · ' + esc(geo.org) : '');
    var when = c.last_seen
      ? ' <span style="font-weight:normal;">' + esc(fmtDate(c.last_seen)) + '</span>' : '';
    return '<div class="peer-meta-item">' +
      '<span class="lbl" style="color:var(--text2);">on-line:' + when + '</span>' +
      '<span class="val" title="' + esc(c.last_seen ? fmtDate(c.last_seen) : '') + '">' + val + '</span></div>';
  }

  // --- действия -------------------------------------------------------------

  function onSectionClick(ev) {
    var btn = ev.target.closest ? ev.target.closest('button') : null;
    if (!btn) return;
    var top = btn.getAttribute('data-hy');
    if (!top) return;
    ev.preventDefault();
    if (top === 'add') return addClient();
    if (top === 'collapseall') return toggleAllCards();
    if (top === 'setup') return setupService();
    if (top === 'settings') return openSettings();
    if (top === 'mask') return openMaskModal();
    if (top === 'port') {
      // Модалка смены порта общая на все протоколы (app.js): один вид и один
      // текст предупреждения про перевыдачу ссылок у AWG, MTProto и Hysteria.
      if (typeof openPortModal === 'function') return openPortModal('hysteria');
      return openSettings();
    }
    if (top === 'streams') return showStreams(null);
    if (top === 'catalog') {
      // Каталог один на все протоколы — открываем тот же менеджер, что у XRay.
      if (typeof showRuleListManager === 'function') return showRuleListManager();
      return say('Менеджер списков недоступен');
    }
  }

  // Кнопки карточки строятся хелперами app.js, а те кладут inline onclick —
  // поэтому нужна одна глобальная точка входа.
  window.hyAct = function (act, id) {
    if (act === 'collapse') {
      _collapsed[id] = _collapsed[id] === false;
      return render();
    }
    var client = state.clients.filter(function (c) { return String(c.id) === String(id); })[0];
    if (!client) return;
    if (act === 'config') return showConfig(client);
    if (act === 'logs') return window.open('/static/logs.html?hy=' + encodeURIComponent(id),
                                           '_blank', 'noopener');
    if (act === 'streams') return showStreams(client);
    if (act === 'rename') return renameClient(client);
    if (act === 'toggle') return toggleClient(client);
    if (act === 'delete') return deleteClient(client);
    // Общие модалки панели: тот же вид и то же поведение, что у XRay.
    if (act === 'dns' && typeof openDnsModal === 'function') {
      return openDnsModal('hysteria', id, client.name);
    }
    if (act === 'allowip' && typeof openAllowIpModal === 'function') {
      return openAllowIpModal(id, client.name, 'hysteria');
    }
    if (act === 'sched' && typeof openScheduleModal === 'function') {
      return openScheduleModal('hysteria', id, client.name,
        client.scheduled_action || null,
        // Старые записи хранили unix-время, новые — дату, как у XRay.
        typeof client.scheduled_at === 'number'
          ? (client.scheduled_at ? new Date(client.scheduled_at * 1000).toISOString().slice(0, 10) : null)
          : (client.scheduled_at || null),
        client.traffic_reset_day != null ? client.traffic_reset_day : null,
        client.limit_gb != null ? client.limit_gb : null);
    }
  };

  // Общие модалки берут список клиентов через этот хук — так им не нужно знать,
  // где Hysteria хранит своё состояние.
  window.hyClients = function () { return state.clients; };

  // Общие модалки после сохранения дёргают refreshAll() — он обновляет вкладки
  // панели, но про нашу не знает. Дописываем себя в хвост, чтобы карточки
  // перерисовывались после DNS, фильтра IP и расписания.
  (function wrapRefreshAll() {
    var orig = window.refreshAll;
    if (typeof orig !== 'function') return;
    window.refreshAll = function () {
      var r = orig.apply(this, arguments);
      if (typeof currentTab !== 'undefined' && currentTab === TAB) refresh();
      return r;
    };
  })();

  // Установка идёт в фоне: панель отвечает сразу, а результат приходит через
  // опрос задачи. Синхронно её делать нельзя — бинарь тянется с GitHub, и
  // gunicorn убивает воркер по таймауту, отдавая браузеру HTML-страницу 502
  // вместо JSON. Ждёт общий хелпер панели — тот же, что ждёт установку XRay и
  // сборку модуля AWG.
  function awaitJob(id, hint, limitMs) {
    if (typeof _pollDepFix !== 'function') return Promise.resolve({ ok: true, msg: '' });
    return _pollDepFix(id, null, Date.now(), hint, limitMs || 10 * 60 * 1000);
  }

  // Блок версий справа от вкладок живёт в app.js и сам себя не перечитывает.
  // Без этого вызова он оставался с «не установлен» и кнопкой «Установить»
  // даже после успешной установки — ровно это и выглядело как «панель зависла».
  function refreshVersions() {
    try {
      if (typeof loadSystemVersions === 'function') return loadSystemVersions(true);
    } catch (e) {}
    return Promise.resolve();
  }

  // Единственный путь установки: баннер на вкладке, кнопка «Запустить» в
  // модалке сервиса и её же «Установить» ведут сюда, чтобы ожидание задачи и
  // обновление обеих плашек были в одном месте.
  function runSetup(title, sub) {
    if (typeof showBusyOverlay === 'function') showBusyOverlay(title, sub);
    return req('/setup', { method: 'POST' })
      .then(function (j) {
        // Старая панель без фонового механизма отвечает синхронно — тогда
        // ждать нечего, результат уже в ответе.
        if (j && j.async) {
          return awaitJob('install:hysteria',
                          'Скачиваем бинарь, выпускаем сертификат, поднимаем сервис');
        }
        return { ok: true, msg: (j && j.note) || '' };
      })
      .catch(function (e) { return { ok: false, msg: e.message }; })
      .then(function (res) {
        say(res.ok ? (res.msg || 'Hysteria 2 установлена и запущена')
                   : ('Не удалось установить: ' + res.msg));
        // Плитки и блок версий читают разные эндпоинты — обновляем оба.
        return Promise.all([refresh(), refreshVersions()])
          .then(function () { return res; }, function () { return res; });
      })
      .then(function (res) {
        if (typeof hideBusyOverlay === 'function') hideBusyOverlay();
        return res;
      });
  }

  function setupService() {
    return runSetup('Устанавливаю Hysteria 2',
                    'Скачиваю бинарь, выпускаю сертификат, поднимаю сервис');
  }

  function toggleAccessLog(on) {
    // Уровень логирования задаётся в юните, поэтому сервис перезапускается —
    // предупреждаем и держим оверлей, иначе тумблер выглядит мгновенным.
    if (typeof showBusyOverlay === 'function') {
      showBusyOverlay(on ? 'Включаем журнал' : 'Выключаем журнал',
                      'Hysteria перезапускается — живые сессии оборвутся');
    }
    req('/access-log', { method: 'POST', body: { enabled: !!on } })
      .then(function () {
        say(on ? 'Журнал назначений включён' : 'Журнал назначений выключен');
        return refresh();
      })
      .catch(function (e) { say(e.message); return refresh(); })
      .then(function () { if (typeof hideBusyOverlay === 'function') hideBusyOverlay(); });
  }

  // Порт-хоппинг. Основной порт не меняется — диапазон добавляется, поэтому
  // выданные ссылки работают как раньше; описание прямо так и говорит, иначе
  // тумблер читается как «всем перевыдавать».
  function hopRow(hop) {
    hop = hop || {};
    var desc;
    if (hop.supported === false) {
      desc = 'Включить нельзя: ' + esc2(hop.why || '') + '.';
    } else if (hop.active) {
      desc = 'Клиенты меняют порт раз в ' + esc2(hop.interval) + ' с в диапазоне <b>' + esc2(hop.active) +
        '/udp</b>, сервер принимает весь диапазон. ';
    } else {
      desc = 'Операторы в РФ душат долгий UDP-поток на одном порту — с хоппингом клиент регулярно ' +
        'переходит на другой порт из диапазона. ';
    }
    if (hop.supported !== false) {
      desc += 'Основной порт не меняется: выданные ссылки и QR работают как раньше, хоппинг получают ' +
        'профили по подписке и новые ссылки. Переключение перезапускает сервис.';
    }
    return svcSwitchRow('hyHop', 'Порт-хоппинг', desc, !!hop.enabled);
  }

  function toggleHop(el) {
    var on = !!el.checked;
    if (typeof showBusyOverlay === 'function') {
      showBusyOverlay(on ? 'Включаем порт-хоппинг' : 'Выключаем порт-хоппинг',
                      'Hysteria перезапускается — живые сессии оборвутся');
    }
    req('/hop', { method: 'POST', body: { enabled: on } })
      .then(function (r) {
        var h = (r && r.hop) || {};
        say(on ? ('Порт-хоппинг включён: ' + (h.active || h.range || '') + '/udp') : 'Порт-хоппинг выключен');
      })
      .catch(function (e) {
        el.checked = !on;
        say(e.message);
      })
      .then(function () {
        if (typeof hideBusyOverlay === 'function') hideBusyOverlay();
        if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
        return refresh();
      });
  }

  function toggleSniff(el) {
    var on = !!el.checked;
    if (typeof showBusyOverlay === 'function') {
      showBusyOverlay(on ? 'Включаем определение доменов' : 'Выключаем определение доменов',
                      'Hysteria перезапускается — живые сессии оборвутся');
    }
    req('/sniff', { method: 'POST', body: { enabled: on } })
      .then(function () { say(on ? 'Определение доменов включено' : 'Определение доменов выключено'); })
      .catch(function (e) { el.checked = !on; say(e.message); })
      .then(function () {
        if (typeof hideBusyOverlay === 'function') hideBusyOverlay();
        if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
        return refresh();
      });
  }

  // Смена маскировочного сайта — прямо с плитки: это единственная настройка
  // Hysteria, которую можно поменять одним перезапуском сервиса и ничего не
  // перевыдавая клиентам. Остальное — в общей модалке настроек протокола.
  function openMaskModal() {
    var cur = (((state.status || {}).masquerade) || '').trim();
    var ov = modal('Маскировочный сайт',
      '<div class="hy-hint">Что hysteria отдаст постороннему, который постучится на этот порт обычным ' +
      'HTTP/3-запросом. «Проксировать сайт» — она сходит на указанный адрес и вернёт его ответ: порт ' +
      'выглядит обычным веб-сервером. «Голый 404» — отвечает коротким 404 и никуда не ходит: нужен там, ' +
      'где исходящие запросы с сервера к одному и тому же сайту на каждый чужой коннект сами выдают ' +
      'прикрытие. На подключение клиентов не влияет ни то, ни другое — ссылки и профили остаются ' +
      'прежними. Не путать с адресом подключения: он в соседней плитке.</div>' +
      '<label class="hy-field"><span>Режим</span>' +
        '<select id="hyMaskMode">' +
          '<option value="proxy"' + (cur ? ' selected' : '') + '>Проксировать чужой сайт</option>' +
          '<option value="404"' + (cur ? '' : ' selected') + '>Отдавать голый 404</option>' +
        '</select></label>' +
      '<div id="hyMaskUrlWrap"' + (cur ? '' : ' class="hidden"') + '>' +
        field('hyMaskInput', 'Адрес сайта (например, https://www.bing.com)', cur, 'text') +
      '</div>' +
      '<div class="input-hint"></div>', [
      { text: 'Сохранить и перезапустить', cls: 'btn-success', keepOpen: true, act: function (o) {
          var mode = ((o.querySelector('#hyMaskMode') || {}).value) || 'proxy';
          var val = (((o.querySelector('#hyMaskInput') || {}).value) || '').trim();
          if (mode === '404') {
            val = '';                    // пустой адрес и есть режим «голый 404»
          } else if (!/^https?:\/\/[^\s]+$/i.test(val)) {
            return say('Нужен полный адрес с http:// или https://');
          }
          var btn = o.querySelector('[data-btn]');
          if (btn) { btn.disabled = true; btn.textContent = 'Применяем…'; }
          if (typeof showBusyOverlay === 'function') {
            showBusyOverlay('Меняем маскировку', 'Hysteria перезапускается — живые сессии оборвутся');
          }
          req('/settings', { method: 'POST', body: { masquerade_url: val } })
            .then(function () { o.remove(); say('Маскировка изменена, сервис перезапущен'); return refresh(); })
            .catch(function (e) {
              say(e.message);
              if (btn) { btn.disabled = false; btn.textContent = 'Сохранить и перезапустить'; }
            })
            .then(function () { if (typeof hideBusyOverlay === 'function') hideBusyOverlay(); });
        } }
    ]);
    var modeSel = ov.querySelector('#hyMaskMode');
    var urlWrap = ov.querySelector('#hyMaskUrlWrap');
    if (modeSel && urlWrap) {
      modeSel.addEventListener('change', function () {
        urlWrap.classList.toggle('hidden', modeSel.value !== 'proxy');
      });
    }
    var inp = ov.querySelector('#hyMaskInput');
    if (inp) { inp.focus(); inp.select(); }
  }

  // Модалка создания повторяет XRay: имя, тумблер «без правил» и тот же каталог
  // списков с предвыбором. Иначе клиента приходилось бы заводить пустым и потом
  // отдельно идти в его карточку за правилами.
  function addClient() {
    var cat = catalogLists();
    var offByDefault = (typeof NEW_CLIENT_OFF_BY_DEFAULT !== 'undefined')
      ? NEW_CLIENT_OFF_BY_DEFAULT : { has: function () { return false; } };
    var rows = cat.length
      ? cat.map(function (r) {
          var view = r.url
            ? '<button class="rule-view" title="Открыть .list в новом окне" onclick="window.open(\'' +
              esc(r.url) + '\',\'_blank\',\'noopener\')">&#128065;</button>'
            : '<span class="rule-view" title="Свой список (' + ((r.rules || []).length) +
              ' правил)" style="cursor:default;color:var(--text3);">&#9776;</span>';
          return '<div class="rule-list-row">' +
            '<label class="switch"><input type="checkbox" data-rule-id="' + esc(r.id) + '"' +
            (offByDefault.has(r.id) ? '' : ' checked') + '>' +
            '<span class="switch-slider"></span></label>' +
            '<span class="rule-name" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' +
            view + '</div>';
        }).join('')
      : '<div class="rule-list-empty">Каталог пуст. Сначала добавьте списки.</div>';

    var body = '' +
      field('hyNewName', 'Имя клиента (например, iphone)', '', 'text') +
      '<div class="input-hint"></div>' +
      '<label class="checkbox-row"><input type="checkbox" id="hyNewNoRules">' +
        '<span>Не использовать правила (полный VPN, без списков и стран)</span></label>' +
      '<div class="rule-list-section" id="hyNewRulesBlock" style="margin-top:0;">' +
        '<div class="rule-list-head"><span>Списки в VPN ' +
          '<span style="text-transform:none;letter-spacing:0;">(если выбрано — режим «только списки в VPN»)</span></span></div>' +
        '<div style="margin-top:8px;">' +
          '<div class="plat-block-head pbh-static">' +
            '<span class="pbh-title">Списки правил ' +
              '<span class="pbh-count" id="hyNewCount">[' + cat.length + '/' + cat.length + ']</span></span>' +
            '<button type="button" class="btn btn-sm btn-ghost pbh-all" id="hyNewAll"' +
              (cat.length ? '' : ' disabled') + '>Выключить все</button>' +
          '</div>' +
          '<div class="rule-list-grid" id="hyNewRuleGrid" style="margin-top:6px;">' + rows + '</div>' +
        '</div>' +
      '</div>';

    var ov = modal('Новый клиент Hysteria', body, [
      { text: 'Создать', cls: 'btn-success', keepOpen: true, act: function (o) {
          var name = ((o.querySelector('#hyNewName') || {}).value || '').trim();
          if (!name) return;
          var noRules = !!(o.querySelector('#hyNewNoRules') || {}).checked;
          var ids = [];
          if (!noRules) {
            o.querySelectorAll('#hyNewRuleGrid input[type=checkbox]:checked')
              .forEach(function (el) { ids.push(el.getAttribute('data-rule-id')); });
          }
          var btn = o.querySelector('[data-btn]');
          if (btn) { btn.disabled = true; btn.textContent = 'Создаём…'; }
          req('/clients', { method: 'POST',
                            body: { name: name, no_rules: noRules, rule_lists: { lists: ids } } })
            .then(function (j) {
              o.remove();
              say('Клиент «' + name + '» создан');
              return refresh().then(function () {
                var c = state.clients.filter(function (x) {
                  return String(x.id) === String((j.client || {}).id);
                })[0];
                if (c) showConfig(c);          // как у XRay: сразу показываем конфиг
              });
            })
            .catch(function (e) {
              say(e.message);
              if (btn) { btn.disabled = false; btn.textContent = 'Создать'; }
            });
        } }
    ]);

    // Счётчик [выбрано/всего] и «Включить/Выключить все» — как в модалке XRay.
    var grid = ov.querySelector('#hyNewRuleGrid');
    var allBtn = ov.querySelector('#hyNewAll');
    var syncCount = function () {
      var boxes = grid ? grid.querySelectorAll('input[type=checkbox]') : [];
      var on = grid ? grid.querySelectorAll('input[type=checkbox]:checked').length : 0;
      var cnt = ov.querySelector('#hyNewCount');
      if (cnt) cnt.textContent = '[' + on + '/' + boxes.length + ']';
      if (allBtn) allBtn.textContent = (boxes.length && on === boxes.length)
        ? 'Выключить все' : 'Включить все';
    };
    if (grid) {
      grid.addEventListener('change', syncCount);
      syncCount();
    }
    if (allBtn) {
      allBtn.addEventListener('click', function () {
        var boxes = grid.querySelectorAll('input[type=checkbox]');
        var on = grid.querySelectorAll('input[type=checkbox]:checked').length;
        var turnOn = !(boxes.length && on === boxes.length);
        boxes.forEach(function (b) { b.checked = turnOn; });
        syncCount();
      });
    }

    var noRulesEl = ov.querySelector('#hyNewNoRules');
    var block = ov.querySelector('#hyNewRulesBlock');
    if (noRulesEl && block) {
      noRulesEl.addEventListener('change', function () {
        block.style.opacity = noRulesEl.checked ? '0.4' : '';
        block.style.pointerEvents = noRulesEl.checked ? 'none' : '';
      });
    }
    var inp = ov.querySelector('#hyNewName');
    if (inp) {
      inp.addEventListener('input', function () {
        if (typeof _sanitizeClientNameInput === 'function') _sanitizeClientNameInput(inp);
        else inp.value = inp.value.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
      });
      inp.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { var b = ov.querySelector('[data-btn]'); if (b) b.click(); }
      });
      inp.focus();
    }
  }

  function renameClient(c) {
    prompt_('Переименовать клиента', 'Новое имя', c.name, function (name) {
      if (!name || name === c.name) return;
      req('/clients/' + encodeURIComponent(c.id), { method: 'PUT', body: { name: name } })
        .then(function () { say('Переименовано в «' + name + '»'); return refresh(); })
        .catch(function (e) { say(e.message); });
    });
  }

  function toggleClient(c) {
    req('/clients/' + encodeURIComponent(c.id) + '/disable',
        { method: 'POST', body: { disabled: !c.disabled } })
      .then(function () { return refresh(); })
      .catch(function (e) { say(e.message); });
  }

  function deleteClient(c) {
    confirm_('Удалить клиента', 'Клиент «' + c.name + '» потеряет доступ сразу. Ссылка станет нерабочей.',
      function () {
        req('/clients/' + encodeURIComponent(c.id), { method: 'DELETE' })
          .then(function () { say('Клиент «' + c.name + '» удалён'); return refresh(); })
          .catch(function (e) { say(e.message); });
      });
  }

  // Вкладки конфига — тот же набор и тот же порядок, что у XRay: ссылка+QR,
  // затем три клиента. У каждого — Config URL (профиль перекачивается сам, и
  // правила в нём обновляются) и содержимое этого URL текстом.
  // Порядок и вид — как в конфиге XRay: у каждой платформы РОВНО ОДИН способ
  // импорта (ссылка профиля), а текст ниже — то же самое содержимое на случай,
  // когда ссылку открыть неоткуда. Никаких «либо так, либо сяк».
  var TABS = [
    { id: 'link',  title: 'Ссылка + QR', urlKey: 'sub', plat: 'shadowrocket',
      urlNote: '— только сервер, без правил',
      note: 'Быстрый вариант «просто прокси»: отсканируйте QR камерой телефона или вставьте ссылку. ' +
            'Сертификат самоподписанный, но клиент сверяет его отпечаток (pinSHA256) — ' +
            '«доверять любому сертификату» включать не нужно.' },
    { id: 'shadowrocket', title: 'Shadowrocket', urlKey: 'shadowrocket', plat: 'shadowrocket',
      urlNote: '— сервер + правила (списки и/или диапазоны стран)',
      // Это КОНФИГ ([General]/[Proxy]/[Rule]), а не подписка: «Type: Subscribe»
      // ждёт список серверов и на конфиге отвечает «не удалось получить серверы».
      where: 'Куда: Shadowrocket → вкладка <b>Конфигурация</b> (Config) → <b>+</b> → вставить ссылку → ' +
             '<b>Загрузить</b> → нажать на файл → <b>Использовать конфигурацию</b>.',
      note: 'Профиль по этой ссылке Shadowrocket перекачивает сам, поэтому правила у клиента ' +
            'обновляются без перевыдачи конфига. Диапазоны стран — наши rule-set’ы из баз MaxMind, ' +
            'свою GeoLite2 настраивать не нужно.' },
    { id: 'loon',  title: 'Loon', urlKey: 'loon', plat: 'loon',
      urlNote: '— сервер + правила (списки и/или диапазоны стран)',
      where: 'Куда: Loon → <b>Configuration</b> → <b>+</b> → вставить ссылку. Или сразу кнопкой «Открыть в Loon Pro».',
      note: 'Ссылку hysteria2:// Loon не понимает — ему нужен профиль целиком, и панель отдаёт его ' +
            'по ссылке ниже как файл .conf. Loon перекачивает профиль сам, правила обновляются без ' +
            'перевыдачи. Если импорт по ссылке недоступен, кнопка «Скачать файл» сохранит тот же ' +
            'профиль на устройство.' },
    { id: 'clash', title: 'Clash / mihomo', urlKey: 'clash', plat: 'clash',
      urlNote: '— Clash.Meta YAML (Clash Verge Rev, Clash Meta для Android)',
      where: 'Куда: <b>Profiles</b> → <b>New profile</b> → вставить ссылку.',
      note: 'Профиль перекачивается по ссылке сам. Отпечаток сертификата уже подставлен в fingerprint. ' +
            'Для правил по имени процесса (PROCESS-NAME) включите TUN-mode в настройках Clash.' }
  ];

  // Что кодировать в QR вкладки. Схемы — из мануалов приложений:
  //   Shadowrocket (README → URL-Schemes): shadowrocket://add/{url} — подписка,
  //     shadowrocket://config/add/{url} — конфиг;
  //   Loon: loon://import?url= — та же схема, что у кнопки «Открыть в Loon Pro»;
  //   Clash Meta для Android сканирует голый URL профиля.
  // Камера iPhone открывает приложение сама — ссылку набирать не нужно.
  function qrHtml(t, urls) {
    var q = qrFor(t, urls);
    if (!q) return '';
    return '<div class="lbl hy-conf-cap">' + q.cap + ' <span class="hy-url-note">' + q.note + '</span></div>' +
           '<div class="hy-qr" data-qrtab="' + t.id + '"></div>';
  }

  function qrFor(t, urls) {
    var u = urls[t.urlKey];
    if (!u) return null;
    if (t.id === 'sub') {
      return { text: 'shadowrocket://add/' + u, cap: 'QR подписки',
               note: '— камера iPhone → откроется Shadowrocket и добавит подписку' };
    }
    if (t.id === 'shadowrocket') {
      return { text: 'shadowrocket://config/add/' + u, cap: 'QR конфига',
               note: '— камера iPhone → откроется Shadowrocket и установит конфиг' };
    }
    if (t.id === 'loon') {
      return { text: 'loon://import?url=' + encodeURIComponent(u), cap: 'QR профиля',
               note: '— камера iPhone → откроется Loon Pro (Loon Lite схему не поддерживает)' };
    }
    if (t.id === 'clash') {
      return { text: u, cap: 'QR со ссылкой на профиль',
               note: '— Clash Meta для Android: Profiles → + → скан QR' };
    }
    return null;
  }

  // Подписка Shadowrocket — первым блоком на его вкладке, как у XRay
  // («1. Subscription URL», «2. Config URL»): подписка — только сервер, конфиг —
  // сервер + правила. Это не вкладка, а описание блока для urlBlockHtml/qrFor.
  var SUB_BLOCK = { id: 'sub', urlKey: 'sub', label: '1. Подписка',
    urlNote: '— только сервер, без правил',
    where: 'Куда: Shadowrocket → <b>+</b> → <b>Type: Subscribe</b> → вставить ссылку.' };

  // Панель за пределами /api/hysteria — общие эндпоинты вроде /api/profile-access.
  function reqPanel(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    if (opts.body && typeof opts.body !== 'string') {
      opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(API + path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) { var e = new Error(j.message || j.error || ('HTTP ' + r.status)); e.data = j; throw e; }
        return j;
      });
    });
  }

  // Разбор «почему нет ссылки» рисуется на месте: диагноз по шагам и кнопка,
  // которая чинит здесь же. Отсылать в другой раздел бесполезно — мы не знаем,
  // что у человека на сервере, а панель это выясняет сама.
  function accessStepsHtml(rep) {
    var steps = (rep.steps || []).map(function (s) {
      return '<div class="hy-acc-step">' +
        '<span class="hy-acc-dot ' + esc(s.state || 'warn') + '"></span>' +
        '<div><b>' + esc(s.title) + '</b><div>' + esc(s.detail) + '</div></div></div>';
    }).join('');

    var fixes = (rep.fixes || []).map(function (f) {
      return '<div class="hy-acc-fix">' +
        '<div class="hy-acc-fix-txt"><b>' + esc(f.title) + '</b>' +
          '<div>' + esc(f.detail) + '</div></div>' +
        '<button class="btn btn-sm ' + (f.danger ? 'btn-ghost' : 'btn-success') + '" ' +
          'data-accessfix="' + esc(f.action) + '" data-port="' + (f.port || 0) + '" ' +
          'data-insecure="' + (f.needs_insecure ? '1' : '') + '" ' +
          'data-danger="' + (f.danger ? '1' : '') + '">' +
          (f.danger ? 'Разрешить' : 'Исправить') + '</button></div>';
    }).join('');

    var manual = (rep.manual || []).map(function (m) {
      return '<div class="hy-acc-manual"><div>' + esc(m.title) + '</div>' +
        '<div class="hy-acc-cmd"><code>' + esc(m.cmd) + '</code>' +
        '<button class="btn btn-sm btn-ghost" data-copytext="' + esc(m.cmd) + '">Копировать</button>' +
        '</div></div>';
    }).join('');

    // Тот же блок показывается и после починки — заголовок с подписью обязаны
    // это отражать, иначе он уверяет «ссылки нет» поверх зелёных галок.
    var head = rep.ok
      ? 'Ссылки на профили работают'
      : 'Ссылки на профиль нет — вот почему';
    var foot = rep.ok
      ? ('База ссылок: ' + esc(rep.base || '') + '. Закройте и откройте конфиг заново, ' +
         'если ссылка ещё не появилась.')
      : ('Пока ссылки нет, профиль рабочий: скопируйте его текст ниже и сохраните файлом — ' +
         'клиент импортирует файл так же, как ссылку. Обновляться сам такой профиль не будет, ' +
         'при смене правил его нужно перевыдать.');
    return '<div class="hy-acc-title">' + head + '</div>' +
      '<div class="hy-acc-steps">' + steps + '</div>' +
      (fixes ? '<div class="hy-acc-fixes">' + fixes + '</div>' : '') +
      (manual || '') +
      '<div class="hy-acc-foot">' + foot + '</div>';
  }

  function loadAccess(ov, c) {
    var boxes = ov.querySelectorAll('[data-access]');
    if (!boxes.length) return;
    reqPanel('/api/profile-access').then(function (rep) {
      var html = accessStepsHtml(rep);
      boxes.forEach(function (b) { b.innerHTML = html; });
    }).catch(function (e) {
      boxes.forEach(function (b) {
        b.innerHTML = '<div class="hy-acc-title">Ссылки на профиль нет</div>' +
          '<div class="hy-acc-foot">Разобраться не удалось: ' + esc(e.message) +
          '. Скопируйте текст профиля ниже и сохраните его файлом.</div>';
      });
    });
  }

  // Кнопка «Исправить». Всё, что панель делает сама, идёт одним запросом: она
  // подберёт свободный порт, поднимет свой nginx-блок, откроет ufw и пересчитает
  // ссылки. HTTP-вариант (нет сертификата) требует отдельного подтверждения:
  // профиль содержит пароль.
  function applyAccessFix(ov, c, btn) {
    var action = btn.getAttribute('data-accessfix');
    var port = parseInt(btn.getAttribute('data-port') || '0', 10);
    var needsInsecure = btn.getAttribute('data-insecure') === '1';
    var go = function (insecure) {
      btn.disabled = true;
      var was = btn.textContent;
      btn.textContent = 'Применяем…';
      reqPanel('/api/profile-access/fix', {
        method: 'POST',
        body: { action: action, port: port || undefined, insecure: !!insecure }
      }).then(function (rep) {
        if (rep.base) {
          say('Готово: профили отдаются по ' + rep.base);
          ov.remove();
          showConfig(c);          // перерисуем конфиг — ссылки уже есть
        } else {
          say('Применено, но ссылок всё ещё нет');
          loadAccess(ov, c);
        }
      }).catch(function (e) {
        btn.disabled = false;
        btn.textContent = was;
        say(e.message);
      });
    };
    if (needsInsecure || btn.getAttribute('data-danger') === '1') {
      confirm_('Отдавать профиль по HTTP?',
        'Сертификата на сервере нет, поэтому ссылка будет http://. Профиль содержит пароль — ' +
        'по HTTP он пойдёт открытым текстом и его увидит любой, кто слушает канал. ' +
        'Надёжнее выпустить сертификат командой ниже, а этот вариант оставить как временный.',
        function () { go(true); });
      return;
    }
    go(false);
  }

  function urlBlockHtml(t, url) {
    if (!url) {
      // Пусто = панель снаружи не опубликована. Чем именно — выясняет
      // /api/profile-access уже после вставки в DOM.
      return '<div class="hy-access" data-access="1">' +
             '<div class="hy-acc-title">Проверяем, почему нет ссылки…</div></div>';
    }
    var loonBtn = (t.id === 'loon')
      ? '<button class="btn btn-sm btn-ghost" data-loon="' + esc(url) + '" ' +
        'title="Импорт через URL Scheme. Loon Lite схему не поддерживает — там вставьте ссылку вручную">' +
        'Открыть в Loon Pro</button>'
      : '';
    return '<div class="hy-url-box">' +
      '<div class="lbl">' + (t.label || 'Ссылка на профиль') + ' <span class="hy-url-note">' + t.urlNote + '</span></div>' +
      '<div class="hy-url">' + esc(url) + '</div>' +
      '<div class="hy-conf-actions">' +
        '<button class="btn btn-sm btn-success" data-copyurl="' + t.urlKey + '">&#128203; Копировать ссылку</button>' +
        loonBtn +
        '<button class="btn btn-sm btn-ghost" data-openurl="' + esc(url) + '?download=1" ' +
          'title="Сохранить профиль файлом — если импорт по ссылке недоступен">Скачать файл</button>' +
      '</div>' +
      '<div class="hy-url-where">' + t.where + '</div></div>';
  }

  // Скрытие платформы в «Настройки → Протоколы» действует и здесь: у XRay
  // прячутся его вкладки конфига, у нас — свои. Вкладка «Ссылка + QR» остаётся
  // всегда: это единственный способ подключиться без профиля.
  function visibleTabs() {
    var fn = window.isPlatformEnabled;
    if (typeof fn !== 'function') return TABS;
    return TABS.filter(function (t) { return t.id === 'link' || fn(t.plat); });
  }

  function showConfig(c) {
    req('/clients/' + encodeURIComponent(c.id) + '/config').then(function (cfg) {
      var urls = cfg.urls || {};
      var tabs = visibleTabs();
      var body = '<div class="hy-tabs">' +
        tabs.map(function (t, i) {
          return '<button class="hy-tab' + (i === 0 ? ' is-on' : '') + '" data-tab="' + t.id + '">' +
                 esc(t.title) + '</button>';
        }).join('') + '</div>' +
        tabs.map(function (t, i) {
          var text = (t.id === 'link') ? (cfg.link || '') : (cfg[t.id] || '');
          return '<div class="hy-pane' + (i === 0 ? '' : ' hidden') + '" data-pane="' + t.id + '">' +
            '<div class="hy-hint">' + t.note + '</div>' +
            (t.id === 'shadowrocket' ? urlBlockHtml(SUB_BLOCK, urls.sub) + qrHtml(SUB_BLOCK, urls) : '') +
            (t.id === 'link'
              ? '<div class="lbl hy-conf-cap">QR узла <span class="hy-url-note">— скан в приложении: ' +
                'один сервер, сам не обновляется</span></div><div class="hy-qr" id="hyQr"></div>'
              : urlBlockHtml(t.id === 'shadowrocket' ? Object.assign({ label: '2. Конфиг' }, t) : t,
                             urls[t.urlKey])) +
            // QR с импортом в приложение — ссылку не нужно ни пересылать, ни
            // набирать руками. Что именно кодируется, решает qrFor().
            qrHtml(t, urls) +
            '<div class="lbl hy-conf-cap">' +
              (t.id === 'link' ? 'Ссылка' : 'Содержимое профиля (то же, что по ссылке выше)') + '</div>' +
            '<pre class="hy-conf">' + esc(text) + '</pre>' +
            '<div class="hy-conf-actions">' +
              '<button class="btn btn-sm btn-primary" data-copy="' +
                (t.id === 'link' ? 'link' : t.id) + '">Скопировать текст</button>' +
            '</div>' +
          '</div>';
        }).join('');

      // modal-wide — как у конфига XRay: в панели лежат длинные URL и куски
      // профиля, в узкой модалке они превращаются в лапшу.
      var ov = modal('Конфиг — ' + esc(c.name), body, [], true);
      ov.addEventListener('click', function (e) {
        var el = e.target;
        var tab = el.getAttribute && el.getAttribute('data-tab');
        if (tab) {
          ov.querySelectorAll('.hy-tab').forEach(function (b) {
            b.classList.toggle('is-on', b.getAttribute('data-tab') === tab);
          });
          ov.querySelectorAll('.hy-pane').forEach(function (p) {
            p.classList.toggle('hidden', p.getAttribute('data-pane') !== tab);
          });
          return;
        }
        var cu = el.getAttribute && el.getAttribute('data-copyurl');
        if (cu) {
          navigator.clipboard.writeText(urls[cu] || '').then(function () { say('Ссылка скопирована'); });
          return;
        }
        // Loon Pro умеет URL Scheme — импорт в один тап с телефона.
        var loon = el.getAttribute && el.getAttribute('data-loon');
        if (loon) {
          window.location.href = 'loon://import?url=' + encodeURIComponent(loon);
          return;
        }
        // Открытие ссылки профиля браузером: телефон сохранит .conf/.yaml файлом,
        // и его можно скормить клиенту вручную, если импорт по URL недоступен.
        var ou = el.getAttribute && el.getAttribute('data-openurl');
        if (ou) {
          window.open(ou, '_blank', 'noopener');
          return;
        }
        // Кнопка автопочинки доступа — правим здесь же, не уводя в настройки.
        if (el.getAttribute && el.getAttribute('data-accessfix')) {
          applyAccessFix(ov, c, el);
          return;
        }
        var ct = el.getAttribute && el.getAttribute('data-copytext');
        if (ct) {
          navigator.clipboard.writeText(ct).then(function () { say('Команда скопирована'); });
          return;
        }
        var cp = el.getAttribute && el.getAttribute('data-copy');
        if (cp) {
          navigator.clipboard.writeText(cfg[cp] || '').then(function () { say('Скопировано'); });
        }
      });
      loadAccess(ov, c);
      var box = ov.querySelector('#hyQr');
      if (box && typeof QRCode !== 'undefined' && cfg.link) {
        try { new QRCode(box, { text: cfg.link, width: 200, height: 200 }); } catch (e) {}
      }
      // Вкладка Clash скрыта в момент отрисовки — QRCode пишет в canvas
      // фиксированного размера, поэтому это не мешает.
      ov.querySelectorAll('[data-qrtab]').forEach(function (qbox) {
        var t = TABS.concat([SUB_BLOCK]).filter(function (x) { return x.id === qbox.getAttribute('data-qrtab'); })[0];
        var q = t && qrFor(t, urls);
        if (q && typeof QRCode !== 'undefined') {
          try { new QRCode(qbox, { text: q.text, width: 200, height: 200 }); } catch (e) {}
        }
      });
    }).catch(function (e) { say(e.message); });
  }

  // c === null — соединения всех клиентов сразу (кнопка в карточке правил).
  function showStreams(c) {
    var path = c ? ('/clients/' + encodeURIComponent(c.id) + '/streams')
                 : '/clients/__all__/streams';
    req(path).then(function (j) {
      var items = (j && j.items) || [];
      var names = {};
      state.clients.forEach(function (x) { names[String(x.id)] = x.name; });
      var body = '<div class="hy-hint">Снимок открытых прямо сейчас потоков. История с адресами ' +
        'назначения — в «Логах»: она пишется, только когда включён тумблер «Логи».</div>';
      if (j && j.error) {
        body += '<div class="hy-conf">Статистика недоступна: ' + esc(j.error) + '</div>';
      } else if (!items.length) {
        body += '<div class="hy-empty">Сейчас активных соединений нет.</div>';
      } else {
        body += '<div class="hy-streams">' + items.map(function (s) {
          var who = c ? '' : '<span class="hy-stream-user">' +
            esc(names[String(s.user)] || String(s.user).slice(0, 8)) + '</span>';
          return '<div class="hy-stream-row">' + who +
            '<span class="hy-stream-addr">' + esc(s.sniffed || s.addr) + '</span>' +
            '<span class="hy-stream-bytes">↓ ' + fmtBytes(s.rx) + ' · ↑ ' + fmtBytes(s.tx) + '</span>' +
          '</div>';
        }).join('') + '</div>';
      }
      modal('Активные соединения' + (c ? ' — ' + esc(c.name) : ''), body, [
        { text: 'Обновить', keepOpen: true, act: function (ov) { ov.remove(); showStreams(c); } }
      ]);
    }).catch(function (e) { say(e.message); });
  }

  // --- блок правил клиента (в точности как у XRay) --------------------------
  //
  // Каталог в панели ОДИН на все протоколы, поэтому и вид у блока общий: те же
  // классы, те же режимы, тот же «Режим исключений» и тот же поповер политики
  // по клику на бейдж. Отличие одно: у Hysteria правила живут только в профиле
  // клиента (серверный acl у неё общий на всех), поэтому «Применить» не нужно —
  // изменения попадают в конфиг при следующем его открытии.

  // Свёрнутость сетки правил по клиенту: ключ есть = свёрнута.
  var _rulesCollapsed = {};

  function catalogLists() {
    var cat = (state.catalog && state.catalog.lists) || [];
    // Копия: порядок самого каталога — это приоритет правил, сортировать его
    // на месте нельзя. Сортировка по имени такая же, как в карточках XRay.
    return cat.slice().sort(function (a, b) {
      return String(a.name || '').localeCompare(String(b.name || ''), 'en',
        { sensitivity: 'base', numeric: true });
    });
  }

  function policyOf(r) {
    if (typeof _rulePolicyOf === 'function') return _rulePolicyOf(r);
    return (r && r.policy) || 'proxy';
  }

  function policyBtn(pol) {
    if (typeof RULE_POLICY_BTNS !== 'undefined') {
      for (var i = 0; i < RULE_POLICY_BTNS.length; i++) {
        if (RULE_POLICY_BTNS[i][0] === pol) return RULE_POLICY_BTNS[i];
      }
      return RULE_POLICY_BTNS[RULE_POLICY_BTNS.length - 1];
    }
    return [pol, pol, pol];
  }

  // Три режима — свитча мало, поэтому радиогруппа (те же классы, что у XRay).
  var LISTS_DEFAULT_OPTS = [
    ['direct', 'Direct', 'Остальной трафик — в обход VPN, напрямую с IP клиента'],
    ['vpn',    'VPN',    'Остальной трафик — через VPN'],
    ['block',  'Block',  'Остальной трафик — блокируется'],
  ];
  function listsDefaultHtml(c) {
    // Показываем PENDING (что правит пользователь) — в силу вступает по «Применить».
    var cur = pListsDefault(c);
    var hint = 'Режим исключений определяет, куда идёт весь остальной трафик — тот, что не попал ни в один включённый список. Direct — в обход VPN, напрямую с IP клиента. VPN — через VPN. Block — блокируется.';
    var id = esc(c.id);
    var opts = LISTS_DEFAULT_OPTS.map(function (o) {
      return '<label class="ld-opt' + (cur === o[0] ? ' on' : '') + '" title="' + esc(o[2]) + '">' +
        '<input type="radio" name="ld_' + id + '"' + (cur === o[0] ? ' checked' : '') +
        ' onchange="hyRule(\'listsDefault\',\'' + id + '\', \'' + o[0] + '\')">' +
        '<span>' + o[1] + '</span></label>';
    }).join('');
    return '<span class="lists-default" title="' + esc(hint) + '">' +
      '<span class="lists-default-cap">Режим исключений:</span>' +
      '<span class="lists-default-radios">' + opts + '</span></span>';
  }

  function rulesGridHtml(c) {
    var cat = catalogLists();
    var sel = {};
    ruleIds(c).forEach(function (id) { sel[String(id)] = true; });
    var ov = (c.rule_policy && typeof c.rule_policy === 'object') ? c.rule_policy : {};
    var expanded = !_rulesCollapsed[c.id];
    var rows = cat.length
      ? cat.map(function (r) {
          var rid = String(r.id);
          var own = ov[rid] || '';
          var pol = own || policyOf(r);
          var btn = policyBtn(pol);
          var hint = btn[2] + ' · ' + (own
            ? 'Своя политика этого клиента, клик — сменить'
            : 'Клик — своя политика для этого клиента');
          var view = r.url
            ? '<button class="rule-view" title="Открыть .list" onclick="window.open(\'' +
              esc(r.url) + '\',\'_blank\',\'noopener\')">&#128065;</button>'
            : '<span class="rule-view" title="Свой список (' + ((r.rules || []).length) +
              ' правил)" style="cursor:default;color:var(--text3);">&#9776;</span>';
          return '<div class="rule-list-row">' +
            '<label class="switch"><input type="checkbox"' + (sel[rid] ? ' checked' : '') +
            ' onchange="hyRule(\'list\',\'' + esc(c.id) + '\',\'' + esc(rid) + '\',this.checked)">' +
            '<span class="switch-slider"></span></label>' +
            '<span class="rule-name" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' +
            // data-kind читает общий поповер политики из app.js — он один на все протоколы.
            '<span class="rule-pol' + (own ? ' own' : '') + '" data-pol="' + esc(pol) + '"' +
            ' data-kind="hysteria" data-uuid="' + esc(c.id) + '" data-plat="lists"' +
            ' data-rid="' + esc(rid) + '" title="' + esc(hint) + '">' + btn[1] + '</span>' +
            view + '</div>';
        }).join('')
      : '<div class="rule-list-empty">Каталог пуст. Откройте «Списки правил» сверху и добавьте нужные через «Шаблоны».</div>';
    var chosen = cat.filter(function (r) { return sel[String(r.id)]; }).length;
    var allOn = cat.length > 0 && chosen === cat.length;
    return '<div style="margin-top:10px;">' +
      '<div class="plat-block-head" onclick="hyRule(\'fold\',\'' + esc(c.id) + '\')">' +
        '<span class="pbh-title"><span class="pbh-caret">' + (expanded ? '▾' : '▸') + '</span>' +
        ' Списки правил <span class="pbh-count">[' + chosen + '/' + cat.length + ']</span></span>' +
        '<span class="pbh-mode" onclick="event.stopPropagation()">' + listsDefaultHtml(c) + '</span>' +
        '<button class="btn btn-sm btn-ghost pbh-all"' +
        ' onclick="event.stopPropagation();hyRule(\'listAll\',\'' + esc(c.id) + '\',' + (allOn ? 'false' : 'true') + ')"' +
        (cat.length ? '' : ' disabled') + '>' + (allOn ? 'Выключить все' : 'Включить все') + '</button>' +
      '</div>' +
      '<div class="rule-list-grid" style="margin-top:6px;' + (expanded ? '' : 'display:none;') + '">' +
      rows + '</div></div>';
  }

  function rulesSectionHtml(c) {
    var mode = pMode(c);
    var sw = function (m, label) {
      var on = mode === m;
      return '<label class="geo-switch' + (on ? ' on' : '') + '" title="' + esc(label) + '">' +
        '<input type="checkbox"' + (on ? ' checked' : '') +
        ' onchange="hyRule(\'mode\',\'' + esc(c.id) + '\',\'' + m + '\',this.checked)">' +
        '<span class="switch-slider"></span>' +
        '<span class="geo-switch-label">' + esc(label) + '</span></label>';
    };
    var body;
    if (mode === 'lists') {
      body = rulesGridHtml(c);
    } else if ((mode === 'via' || mode === 'direct') && typeof renderCountrySelector === 'function') {
      body = renderCountrySelector(c.id, pCountries(c), mode);
    } else {
      body = '<div style="color:var(--text3);font-size:12px;text-align:center;padding:60px 0;">' +
             'Все режимы выключены — весь трафик идёт через VPN.</div>';
    }
    return '<div class="rule-list-section">' +
      '<div class="geo-mode-switches">' +
        sw('lists', 'Списки правил') + sw('via', 'Страны с VPN') + sw('direct', 'Страны без VPN') +
      '</div>' +
      '<div class="geo-body">' + body + '</div></div>';
  }

  // Единая точка входа для инлайновых обработчиков блока правил.
  window.hyRule = function (act, id, a, b) {
    if (act === 'fold') {
      _rulesCollapsed[id] = !_rulesCollapsed[id];
      return render();
    }
    var c = state.clients.filter(function (x) { return String(x.id) === String(id); })[0];
    if (!c) return;
    var post = function (path, body, patch) {
      Object.assign(c, patch);       // оптимистично: блок перерисовывается сразу
      render();
      return req('/clients/' + encodeURIComponent(id) + path, { method: 'POST', body: body })
        .catch(function (e) { say(e.message); return refresh(); });
    };
    // Режим, страны и режим исключений правят PENDING: на сервере ничего не
    // меняется до «Применить». Членство в списках — сразу, как у XRay.
    if (act === 'mode') {
      var mode = b ? a : 'off';
      return post('/geo-mode', { mode: mode }, { geo_mode_pending: mode });
    }
    if (act === 'list') {
      var ids = ruleIds(c).map(String).filter(function (x) { return x !== String(a); });
      if (b) ids.push(String(a));
      return post('/rule-lists', { lists: ids, geo_mode: pMode(c) },
                  { rule_lists: { lists: ids } });
    }
    if (act === 'listAll') {
      var all = a ? catalogLists().map(function (r) { return String(r.id); }) : [];
      return post('/rule-lists', { lists: all, geo_mode: pMode(c) },
                  { rule_lists: { lists: all } });
    }
    if (act === 'listsDefault') {
      return post('/lists-default', { mode: a }, { lists_default_pending: a });
    }
    if (act === 'countries') {
      return post('/geo-countries', { countries: a }, { geo_countries_pending: a });
    }
    if (act === 'apply') {
      return req('/clients/' + encodeURIComponent(id) + '/geo-apply', { method: 'POST' })
        .then(function (j) {
          Object.assign(c, {
            geo_mode: j.geo_mode, geo_countries: j.geo_countries,
            lists_default: j.lists_default,
            geo_mode_pending: j.geo_mode_pending,
            geo_countries_pending: j.geo_countries_pending,
            lists_default_pending: j.lists_default_pending
          });
          render();
          say('Правила применены');
        })
        .catch(function (e) { say(e.message); return refresh(); });
    }
  };

  // Общий поповер политики правит клиента оптимистично и зовёт перерисовку
  // через _protoRerender(kind). force=true — перечитать состояние с сервера.
  window.hyRerender = function (force) { return force ? refresh() : render(); };


  // --- настройки протокола --------------------------------------------------
  //
  // Своей модалки у Hysteria больше нет: настройки, управление сервисом и
  // удаление живут в общей модалке панели (⚙ на плитке «Сервис»). Сюда пакет
  // отдаёт только то, что знает про себя сам.

  function openSettings() {
    if (typeof window.openProtoSvcModal === 'function') return window.openProtoSvcModal(TAB);
    say('Модалка настроек протокола недоступна');
  }

  function esc2(s) { return esc(s); }

  function registerSvcAdapter() {
    var reg = window.PROTO_SVC;
    if (!reg) return;
    reg.hysteria = {
      title: 'Hysteria 2',
      load: function () {
        // Состояние сервиса — из /status, значения формы — из /settings: пароль
        // обфускации в статус намеренно не едет, а маскировка там лежит под
        // другим ключом. Одного запроса тут не хватает.
        return Promise.all([req('/status'), req('/settings')]).then(function (r) {
          var st = r[0] || {}, cfg = r[1] || {};
          // Статус держим целиком: форме нужны конфликт порта и кандидат, а они
          // считаются панельным реестром портов и в /settings не лежат.
          state.status = st;
          return {
            installed: !!st.installed,
            active: !!st.active,
            autostart: !!st.enabled,
            unit: 'hysteria-server',
            cfg: cfg,
            st: st,
          };
        });
      },
      optionsHtml: function (s) {
        var c = s.cfg || {};
        var st = s.st || {};
        var f = function (id, label, value, type, hint) {
          return '<label class="psvc-field"><span>' + esc2(label) + '</span>' +
            '<input class="psvc-inp" id="' + id + '" type="' + type + '" value="' + esc2(value) + '"></label>' +
            (hint ? '<div class="psvc-row-d" style="margin:-8px 0 12px;">' + hint + '</div>' : '');
        };
        var hint = function (t) {
          return '<div class="psvc-row-d" style="margin:-8px 0 12px;">' + t + '</div>';
        };
        var masqOn = !!(c.masquerade_url || '').trim();
        return '' +
          // Порт — общим блоком панели, как у AWG/MTProto и инбаунда в XRay:
          // отдельная операция с подтверждением и откатом, не поле «Сохранить».
          // Конфликт порта показывает этот же блок.
          '<div id="hysteriaPortBox"><div class="psvc-note">Читаю порт…</div></div>' +
          hint('Hysteria слушает UDP, XRay — TCP: один и тот же номер порта им не мешает, это разные сокеты. ' +
            '<b>443/udp — лучший выбор:</b> снаружи это обычный HTTP/3, а UDP на других портах мобильные ' +
            'операторы часто режут как подозрительный QUIC.') +
          '<div class="psvc-sec-h" style="margin-top:18px;">Подключение</div>' +
          f('hySetSni', 'Адрес подключения (SNI)', c.sni || '', 'text',
            'Домен или IP, который попадёт в клиентские ссылки. Пусто — берётся общий адрес сервера панели. ' +
            'Это НЕ маскировочный сайт.') +

          '<div class="psvc-sec-h" style="margin-top:18px;">Маскировка</div>' +
          '<label class="psvc-field"><span>Что видит посторонний</span>' +
            '<select class="psvc-inp" id="hySetMaskMode">' +
              '<option value="proxy"' + (masqOn ? ' selected' : '') + '>Проксировать чужой сайт</option>' +
              '<option value="404"' + (masqOn ? '' : ' selected') + '>Отдавать голый 404</option>' +
            '</select></label>' +
          '<div id="hySetMaskWrap"' + (masqOn ? '' : ' class="hidden"') + '>' +
            '<label class="psvc-field"><span>Адрес сайта</span>' +
            '<input class="psvc-inp" id="hySetMask" type="text" value="' + esc2(c.masquerade_url || '') +
            '" placeholder="https://www.bing.com"></label>' +
          '</div>' +
          hint('Что hysteria отдаёт постороннему, постучавшемуся на этот порт обычным HTTP/3. ' +
            'В режиме прокси она сходит на указанный сайт и вернёт его ответ — порт выглядит обычным ' +
            'веб-сервером. Голый 404 никуда не ходит: он нужен там, где исходящие запросы сервера к одному ' +
            'и тому же сайту на каждый чужой коннект сами выдают прикрытие. ' +
            'На подключение клиентов не влияет ни то, ни другое.') +

          '<div class="psvc-sec-h" style="margin-top:18px;">Обфускация</div>' +
          '<div class="psvc-pair">' +
            '<label class="psvc-field"><span>Пароль salamander</span>' +
            '<input class="psvc-inp" id="hySetObfs" type="text" value="' + esc2(c.obfs_password || '') + '"></label>' +
            '<div class="psvc-field"><span>&nbsp;</span>' +
            '<button class="btn btn-sm btn-ghost" id="hyGenObfs" style="height:34px;">Сгенерировать</button></div>' +
          '</div>' +
          hint('Маскирует сам QUIC: без него трафик опознаётся по сигнатуре протокола. Пароль общий для всех ' +
            'клиентов и входит в каждую ссылку — смена требует перевыдачи ссылок. ' +
            'Пусто — обфускация выключена.') +

          '<div class="psvc-sec-h" style="margin-top:18px;">Скорость</div>' +
          '<div class="psvc-pair">' +
            '<label class="psvc-field"><span>Вниз, Мбит/с</span>' +
            '<input class="psvc-inp" id="hySetDown" type="number" value="' + esc2(c.down_mbps || 0) + '"></label>' +
            '<label class="psvc-field"><span>Вверх, Мбит/с</span>' +
            '<input class="psvc-inp" id="hySetUp" type="number" value="' + esc2(c.up_mbps || 0) + '"></label>' +
          '</div>' +
          hint('Потолок полосы всего сервиса, а не лимит трафика клиента: месячные лимиты живут в карточке ' +
            'клиента. 0 в обоих полях — без ограничения.') +

          '<div class="psvc-actions" style="margin:14px 0 12px;">' +
            '<button class="btn btn-sm btn-success" id="hySaveSettings">Сохранить настройки</button>' +
          '</div>' +
          hopRow(st.hop) +
          svcSwitchRow('hySniff', 'Определение доменов (sniff)',
            'Если клиент прислал голый IP вместо домена, сервер вычитает домен из начала соединения ' +
            '(TLS, HTTP, QUIC). Тогда доменные правила Hysteria на сервере и журнал назначений работают и ' +
            'для такого трафика, а в «Активных соединениях» виден домен. Нужно редко: Shadowrocket, Loon и ' +
            'Clash обычно и так присылают домен — IP шлют приложения, которые резолвят адреса сами или ходят ' +
            'на зашитые IP (тот же Telegram). Цена — немного процессора и до 2 с ожидания на старте ' +
            'TCP-соединения. Ссылки не меняются; переключение перезапускает сервис.',
            !!st.sniff) +
          svcSwitchRow('hyAccessLog', 'Журнал назначений',
            'hysteria пишет адреса запросов только на уровне debug, поэтому тумблер меняет уровень ' +
            'логирования в юните и перезапускает сервис. Подключения пишутся в лог всегда.',
            !!c.access_log);
      },
      onMount: function (root) {
        var btn = root.querySelector('#hySaveSettings');
        if (btn) btn.addEventListener('click', function () { saveSettings(root, btn); });
        // Кнопка горит, только когда в форме есть правки: зелёная при нетронутых
        // полях читается как «что-то не сохранено».
        var markClean = function (clean) {
          if (!btn) return;
          btn.disabled = clean;
          btn.classList.toggle('btn-success', !clean);
          btn.classList.toggle('btn-ghost', clean);
          btn.title = clean ? 'Изменений нет — сохранять нечего' : '';
        };
        markClean(true);
        ['#hySetSni', '#hySetMaskMode', '#hySetMask', '#hySetObfs', '#hySetDown', '#hySetUp'].forEach(function (sel) {
          var el = root.querySelector(sel);
          if (!el) return;
          el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', function () { markClean(false); });
        });
        root._hyMarkClean = markClean;

        // Режим маскировки прячет поле адреса: в конфиге это одно решение
        // (пустой адрес = 404), но два поля в UI читаются понятнее одного.
        var mode = root.querySelector('#hySetMaskMode');
        var wrap = root.querySelector('#hySetMaskWrap');
        if (mode && wrap) {
          mode.addEventListener('change', function () {
            wrap.classList.toggle('hidden', mode.value !== 'proxy');
          });
        }

        if (typeof window.loadProtoPort === 'function') window.loadProtoPort('hysteria');

        var gen = root.querySelector('#hyGenObfs');
        if (gen) {
          gen.addEventListener('click', function () {
            // 16 hex-символов — столько же, сколько панель генерирует сама.
            var b = new Uint8Array(8);
            if (window.crypto && window.crypto.getRandomValues) {
              window.crypto.getRandomValues(b);
            } else {
              for (var i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
            }
            var inp = root.querySelector('#hySetObfs');
            if (inp) {
              inp.value = Array.prototype.map.call(b, function (x) {
                return ('0' + x.toString(16)).slice(-2);
              }).join('');
            }
            // Программная запись не шлёт input — кнопку зажигаем сами.
            if (root._hyMarkClean) root._hyMarkClean(false);
            say('Новый пароль — не забудьте «Сохранить» и перевыдать ссылки');
          });
        }
      },
      svcAction: function (action) {
        if (action === 'restart') return req('/restart', { method: 'POST' });
        if (action === 'stop') return req('/stop', { method: 'POST' });
        // «Запустить» — это та же setup(): она чинит конфиг и юнит, если их
        // размыло, и потому может уйти в фон так же, как первая установка.
        if (action === 'start') {
          return runSetup('Запускаю Hysteria 2', 'Проверяю бинарь и конфиг, поднимаю сервис')
            .then(function (res) { return { ok: res.ok, error: res.ok ? '' : res.msg }; });
        }
        var on = (action === 'autostart_on');
        return req('/autostart', { method: 'POST', body: { enabled: on } });
      },
      restartNote: 'Перезапуск обрывает живые сессии: QUIC не переживает смену процесса. ' +
                   'Клиенты переподключаются сами в течение нескольких секунд.',
      install: function () {
        return runSetup('Устанавливаю Hysteria 2',
                        'Скачиваю бинарь, выпускаю сертификат, поднимаю сервис');
      },
      uninstall: {
        label: 'Удалить Hysteria 2 с сервера',
        body: 'Сервис будет остановлен и выключен из автозапуска, затем удалены бинарь ' +
              '<code>/usr/local/bin/hysteria</code> и юнит <code>hysteria-server</code>. ' +
              'Вкладка Hysteria скроется. XRay, AmneziaWG и MTProto это не затронет.',
        run: function (purge) {
          return req('/uninstall', { method: 'POST', body: { purge_data: !!purge } })
            .then(function (j) {
              // Бинаря больше нет — блок версий обязан это показать, иначе там
              // останется версия удалённого протокола.
              refreshVersions();
              return j || { ok: true };
            })
            .catch(function (e) { return { ok: false, error: e.message }; });
        },
      },
      afterAction: function () { refresh(); },
    };
  }

  // Такой же ряд «тумблер + описание», как у остальных протоколов в общей
  // модалке. Своей копии стилей не заводим — классы там же.
  function svcSwitchRow(id, label, desc, on) {
    return '<div class="psvc-row">' +
      '<div class="psvc-row-body">' +
        '<div class="psvc-row-t">' + esc2(label) + '</div>' +
        '<div class="psvc-row-d">' + desc + '</div>' +
      '</div>' +
      '<label class="switch-row' + (on ? ' is-on' : '') + '" style="margin:0;flex:0 0 auto;">' +
        '<span class="switch switch-tinted">' +
          '<input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '>' +
          '<span class="switch-slider"></span>' +
        '</span>' +
      '</label></div>';
  }

  function saveSettings(root, btn) {
    var v = function (id) { return ((root.querySelector('#' + id) || {}).value || ''); };
    if (btn) { btn.disabled = true; btn.textContent = 'Сохраняем…'; }
    if (typeof showBusyOverlay === 'function') {
      showBusyOverlay('Применяем настройки Hysteria', 'Сервис перезапускается — живые сессии оборвутся');
    }
    req('/settings', { method: 'POST', body: {
      sni: v('hySetSni').trim(), obfs_password: v('hySetObfs').trim(),
      // Режим «404» = пустой адрес: в конфиге это одно поле, выбор нужен в UI.
      masquerade_url: (v('hySetMaskMode') === '404') ? '' : v('hySetMask').trim(),
      down_mbps: v('hySetDown'), up_mbps: v('hySetUp')
    } }).then(function (r) {
      say(r && r.restarted === false
        ? 'Настройки сохранены — сервис остановлен, применятся при запуске'
        : 'Настройки применены, сервис перезапущен');
      return refresh();
    }).catch(function (e) {
      say(e.message);
    }).then(function () {
      if (typeof hideBusyOverlay === 'function') hideBusyOverlay();
      if (btn) { btn.disabled = false; btn.textContent = 'Сохранить настройки'; }
      if (typeof window.loadProtoSvc === 'function') window.loadProtoSvc();
    });
  }

  function field(id, label, value, type) {
    return '<label class="hy-field"><span>' + esc(label) + '</span>' +
           '<input id="' + id + '" type="' + type + '" value="' + esc(value) + '"></label>';
  }

  // --- свои модалки (alert/confirm/prompt в панели не используются) ----------

  function modal(title, bodyHtml, buttons, wide) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay hy-modal';
    var btns = (buttons || []).map(function (b, i) {
      return '<button class="btn ' + (b.cls || 'btn-ghost') + '" data-btn="' + i + '">' + esc(b.text) + '</button>';
    }).join('');
    ov.innerHTML = '<div class="modal' + (wide ? ' modal-wide' : '') + '">' +
        '<h3>' + title + '</h3>' +
        '<div class="hy-modal-body">' + bodyHtml + '</div>' +
        '<div class="modal-actions"><button class="btn btn-ghost" data-close="1">Закрыть</button>' + btns + '</div>' +
      '</div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function (e) {
      if (e.target.getAttribute('data-close')) { ov.remove(); return; }
      var idx = e.target.getAttribute && e.target.getAttribute('data-btn');
      if (idx === null || idx === undefined) return;
      var b = buttons[+idx];
      if (b && b.act) b.act(ov);
      if (b && !b.keepOpen) ov.remove();
    });
    return ov;
  }

  function prompt_(title, label, value, cb) {
    // Пустой .input-hint кладём заранее: _setHint из app.js ищет именно его и
    // создаёт сам только когда у поля есть следующий сосед — у нас input лежит
    // последним внутри <label>, и подсказка просто не появлялась бы.
    var ov = modal(title, field('hyPromptInput', label, value || '', 'text') +
      '<div class="input-hint"></div>', [
      { text: 'OK', cls: 'btn-primary', act: function (o) {
          cb(((o.querySelector('#hyPromptInput') || {}).value || '').trim());
        } }
    ]);
    var inp = ov.querySelector('#hyPromptInput');
    if (inp) {
      // Тот же фильтр ввода, что в модалках AWG/XRay: недопустимые символы не
      // набираются вовсе, пробелы становятся «_», кнопка гаснет на пустом имени.
      inp.addEventListener('input', function () {
        if (typeof _sanitizeClientNameInput === 'function') {
          _sanitizeClientNameInput(inp);
        } else {
          inp.value = inp.value.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
        }
      });
      inp.focus();
      inp.select();
    }
  }

  function confirm_(title, text, cb) {
    modal(title, '<div class="hy-hint">' + esc(text) + '</div>', [
      { text: 'Удалить', cls: 'btn-danger', act: cb }
    ]);
  }

  // --- старт ----------------------------------------------------------------

  function boot() {
    if (!mountTab()) return;
    applyOwnVisibility();
    hydrateFromCache();
    // Если панель уже показывает нашу вкладку (после перезагрузки страницы) —
    // подтянем данные сразу.
    if (typeof currentTab !== 'undefined' && currentTab === TAB) refresh();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
