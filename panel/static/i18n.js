/* ============================================================================
 * i18n.js — runtime RU→EN translation layer for the byFox.dev panel.
 *
 * Russian stays the source of truth in HTML / app.js / app.py. When the active
 * language is "en" we flip *visible* text to English at the DOM level:
 *   - an initial pass over the document (login screen + dashboard),
 *   - a MutationObserver that re-translates anything app.js renders later.
 * Switching back to "ru" restores the saved originals (WeakMap), no reload.
 *
 * The dictionary lives in window.I18N_EN = { exact:{...}, patterns:[[re,repl]] }.
 * It is built/extended in i18n-dict.js, loaded before this file.
 * ==========================================================================*/
(function () {
  'use strict';

  var LS_KEY = 'awgPanel:lang';

  // --- language state --------------------------------------------------------
  function detectLang() {
    try {
      var saved = localStorage.getItem(LS_KEY);
      if (saved === 'ru' || saved === 'en') return saved;
    } catch (e) {}
    var nav = ((navigator.language || navigator.userLanguage || '') + '').toLowerCase();
    return nav.indexOf('ru') === 0 ? 'ru' : 'en';
  }

  var LANG = detectLang();
  window.i18nLang = function () { return LANG; };

  function persist(l) {
    try { localStorage.setItem(LS_KEY, l); } catch (e) {}
  }

  // Mirror the language into a cookie so the server can localize geo names
  // (country/city in logs and cards) to match the UI language.
  function syncCookie() {
    try { document.cookie = 'lang=' + LANG + ';path=/;max-age=31536000;samesite=Lax'; } catch (e) {}
  }

  // --- dictionary ------------------------------------------------------------
  function dict() {
    var d = window.I18N_EN || {};
    if (!d.exact) d.exact = {};
    if (!d.patterns) d.patterns = [];
    return d;
  }

  // Look up the English for an already-trimmed Russian key. Tries the exact
  // dictionary (keys may be stored raw or whitespace-collapsed), then regex
  // patterns. Returns null when nothing matches.
  function lookup(t) {
    if (!t) return null;
    var d = dict();
    if (d.exact[t] != null) return d.exact[t];
    var c = t.replace(/\s+/g, ' ');
    if (c !== t && d.exact[c] != null) return d.exact[c];
    var pats = d.patterns;
    for (var i = 0; i < pats.length; i++) {
      var r = applyPattern(t, pats[i][0], pats[i][1]);
      if (r == null && c !== t) r = applyPattern(c, pats[i][0], pats[i][1]);
      if (r != null) return r;
    }
    return null;
  }

  // Pattern replacement where a captured Russian piece is translated too:
  // «Есть что поправить: Автозапуск AmneziaWG выключен» → the inner phrase goes
  // through tr() as well. Groups are always shorter than the input, so the
  // recursion ends; values without Cyrillic (ports, domains) are kept as is.
  function applyPattern(t, re, rep) {
    re.lastIndex = 0;
    var m = re.exec(t);
    re.lastIndex = 0;
    if (!m) return null;
    var out = rep.replace(/\$(\d)/g, function (_, n) {
      var g = m[+n];
      if (g == null) return '';
      return (CYR.test(g) && g.length < t.length) ? tr(g) : g;
    });
    return t.slice(0, m.index) + out + t.slice(m.index + m[0].length);
  }

  var CYR = /[А-Яа-яЁё]/;
  function isCyr(ch) { return !!ch && CYR.test(ch); }
  function cyrCount(s) { var m = s.match(/[А-Яа-яЁё]/g); return m ? m.length : 0; }

  // Fallback for strings the exact/pattern lookup can't match as a whole:
  // server-assembled multi-line blocks (dependency/health/paths descriptions),
  // interpolated "label: value" nodes, etc. Replaces known RU phrases by
  // substring, but only at Cyrillic word boundaries so we never corrupt a
  // longer word (e.g. "Логи" must not match inside "технологии").
  function phraseReplace(s) {
    var ph = dict().phrases;
    if (!ph || !ph.length) return s;
    var out = s, changed = false;
    for (var i = 0; i < ph.length; i++) {
      var ru = ph[i][0], en = ph[i][1];
      var idx = out.indexOf(ru);
      while (idx !== -1) {
        var before = idx > 0 ? out.charAt(idx - 1) : '';
        var after = (idx + ru.length < out.length) ? out.charAt(idx + ru.length) : '';
        if (!isCyr(before) && !isCyr(after)) {
          out = out.slice(0, idx) + en + out.slice(idx + ru.length);
          changed = true;
          idx = out.indexOf(ru, idx + en.length);
        } else {
          idx = out.indexOf(ru, idx + ru.length);
        }
      }
    }
    return changed ? out : s;
  }

  // Translate a raw string RU→EN, preserving leading/trailing whitespace.
  // One-directional: English input matches no key, so this is idempotent.
  function tr(s) {
    if (!s) return s;
    var lead = s.match(/^\s*/)[0];
    var tail = s.match(/\s*$/)[0];
    var key = s.trim();
    if (!key) return s;
    var d0 = dict();
    // Whole-string exact match first (multi-line keys exist too).
    if (d0.exact[key] != null && d0.exact[key] !== key) return lead + d0.exact[key] + tail;
    // Multi-line strings (tooltips assembled with "\n") — translate line by
    // line so each line can hit exact/patterns on its own. Accepted only when
    // no Russian is left: otherwise it is a sentence wrapped inside a template
    // literal, and the whitespace-collapsed lookup below handles it whole.
    if (key.indexOf('\n') !== -1 && CYR.test(key)) {
      var ls = s.split('\n');
      for (var li = 0; li < ls.length; li++) {
        if (ls[li].trim()) ls[li] = tr(ls[li]);
      }
      var joined = ls.join('\n');
      if (!CYR.test(joined)) return joined;
    }
    var en = lookup(key);
    if (en != null && en !== key) return lead + en + tail;
    // Emoji / symbol prefix, e.g. "📋 Копировать ссылку" → keep the prefix.
    var pm = key.match(/^([^0-9A-Za-zА-Яа-яЁё]+)(.+)$/);
    if (pm) {
      var en2 = lookup(pm[2].trim());
      if (en2 != null && en2 !== pm[2].trim()) return lead + pm[1] + en2 + tail;
    }
    // Phrase-level substring fallback for assembled / interpolated content.
    if (CYR.test(key)) {
      var pr = phraseReplace(s);
      // Text from multi-line template literals arrives with "\n      " inside,
      // while dictionary phrases are stored whitespace-collapsed — try the
      // collapsed form too (edges kept as in the original) and keep whichever
      // leaves less Russian.
      var mid = key.replace(/\s+/g, ' ');
      if (mid !== key) {
        var pc = phraseReplace(mid);
        if (pc !== mid && cyrCount(pc) < cyrCount(pr)) return lead + pc + tail;
      }
      if (pr !== s) return pr;
    }
    return s;
  }
  window.i18nTr = tr;

  // --- DOM translation -------------------------------------------------------
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, CODE: 1, PRE: 1, TEXTAREA: 1, NOSCRIPT: 1 };
  // Skip verbatim/technical blocks: code/command output, config dumps. NOTE: do
  // not skip ".cmd" — on the install page it is just a flex wrapper whose copy
  // button + label are translatable; the command itself lives in a ".code" child.
  var SKIP_CLASS = /(^|\s)(code|config-block|dep-cmd|no-i18n|qrcode)(\s|$)/;
  var ATTR_LIST = ['title', 'placeholder', 'aria-label'];

  // originals for reversibility
  var textOrig = new WeakMap();   // textNode -> ru string
  var attrOrig = new WeakMap();   // element  -> { attrName: ru string }

  function inSkip(node) {
    var el = node.nodeType === 3 ? node.parentNode : node;
    while (el && el.nodeType === 1) {
      if (SKIP_TAGS[el.tagName]) return true;
      var cls = el.getAttribute && el.getAttribute('class');
      if (cls && SKIP_CLASS.test(cls)) return true;
      if (el.getAttribute && el.getAttribute('data-i18n') === 'off') return true;
      el = el.parentNode;
    }
    return false;
  }

  function translateTextNode(node) {
    if (inSkip(node)) return;
    var orig = textOrig.has(node) ? textOrig.get(node) : node.nodeValue;
    var out = tr(orig);
    if (out !== node.nodeValue) {
      if (!textOrig.has(node)) textOrig.set(node, orig);
      node.nodeValue = out;
    }
  }

  function translateAttrs(el) {
    if (el.nodeType !== 1 || inSkip(el)) return;
    for (var i = 0; i < ATTR_LIST.length; i++) {
      var a = ATTR_LIST[i];
      if (!el.hasAttribute(a)) continue;
      var saved = attrOrig.get(el) || {};
      var orig = (a in saved) ? saved[a] : el.getAttribute(a);
      var out = tr(orig);
      if (out !== el.getAttribute(a)) {
        if (!(a in saved)) { saved[a] = orig; attrOrig.set(el, saved); }
        el.setAttribute(a, out);
      }
    }
    // value="" on buttons / submit inputs
    if (el.tagName === 'INPUT') {
      var t = (el.getAttribute('type') || '').toLowerCase();
      if (t === 'button' || t === 'submit') {
        var saved2 = attrOrig.get(el) || {};
        var o2 = ('value' in saved2) ? saved2.value : el.value;
        var out2 = tr(o2);
        if (out2 !== el.value) {
          if (!('value' in saved2)) { saved2.value = o2; attrOrig.set(el, saved2); }
          el.value = out2;
        }
      }
    }
  }

  function walk(root, fn) {
    if (!root) return;
    if (root.nodeType === 3) { fn(root); return; }
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    // text nodes
    var tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var n;
    while ((n = tw.nextNode())) fn(n);
  }

  function translateNode(root) {
    if (!root) return;
    if (root.nodeType === 3) { translateTextNode(root); return; }
    if (root.nodeType === 1) translateAttrs(root);
    walk(root, translateTextNode);
    // attributes on descendants
    if (root.querySelectorAll) {
      var sel = root.querySelectorAll('[title],[placeholder],[aria-label],input[type=button],input[type=submit]');
      for (var i = 0; i < sel.length; i++) translateAttrs(sel[i]);
    }
  }

  function restoreNode(root) {
    walk(root || document.body, function (node) {
      if (textOrig.has(node)) node.nodeValue = textOrig.get(node);
    });
    var els = (root || document.body).querySelectorAll('[title],[placeholder],[aria-label],input[type=button],input[type=submit]');
    for (var i = 0; i < els.length; i++) {
      var saved = attrOrig.get(els[i]);
      if (!saved) continue;
      for (var a in saved) {
        if (a === 'value') els[i].value = saved[a];
        else els[i].setAttribute(a, saved[a]);
      }
    }
  }

  // --- MutationObserver ------------------------------------------------------
  var observer = null;
  function startObserver() {
    if (observer || !window.MutationObserver) return;
    observer = new MutationObserver(function (muts) {
      observer.disconnect();
      try {
        for (var i = 0; i < muts.length; i++) {
          var m = muts[i];
          if (m.type === 'characterData') {
            translateTextNode(m.target);
          } else if (m.type === 'attributes') {
            translateAttrs(m.target);
          } else {
            for (var j = 0; j < m.addedNodes.length; j++) translateNode(m.addedNodes[j]);
          }
        }
      } catch (e) { /* never let translation break the app */ }
      connectObserver();
    });
    connectObserver();
  }
  function connectObserver() {
    if (!observer) return;
    observer.observe(document.body, {
      childList: true, subtree: true, characterData: true,
      attributes: true, attributeFilter: ATTR_LIST
    });
  }
  function stopObserver() {
    if (observer) { observer.disconnect(); observer = null; }
  }

  // --- apply / toggle --------------------------------------------------------
  function updateToggleLabel() {
    var lbls = document.querySelectorAll('.lang-label');
    for (var i = 0; i < lbls.length; i++) lbls[i].textContent = LANG === 'ru' ? 'RU' : 'EN';
  }

  var origTitle = null;
  function applyTitle() {
    if (origTitle === null) origTitle = document.title;
    if (LANG === 'en') {
      var en = lookup((origTitle || '').trim());
      if (en) document.title = en;
    } else if (origTitle != null) {
      document.title = origTitle;
    }
  }

  function applyLang() {
    document.documentElement.setAttribute('lang', LANG);
    syncCookie();
    updateToggleLabel();
    applyTitle();
    if (LANG === 'en') {
      if (document.body) translateNode(document.body);
      startObserver();
    } else {
      stopObserver();
      if (document.body) restoreNode(document.body);
    }
  }
  // Re-run a full pass (used by app.js right after the dashboard is revealed).
  window.i18nApply = function () { if (LANG === 'en' && document.body) translateNode(document.body); };

  function setLang(l) {
    if (l !== 'ru' && l !== 'en') return;
    if (l === LANG) return;
    LANG = l;
    persist(l);
    applyLang();
    // Re-fetch server data so geo names (country/city) come back in the new
    // language right away instead of waiting for the next poll.
    try { if (typeof window.refreshAll === 'function') window.refreshAll(); } catch (e) {}
  }
  window.i18nSet = setLang;
  window.i18nToggle = function () { setLang(LANG === 'ru' ? 'en' : 'ru'); };

  // --- boot ------------------------------------------------------------------
  function wireToggle() {
    var btns = document.querySelectorAll('.lang-toggle');
    for (var i = 0; i < btns.length; i++) {
      var btn = btns[i];
      if (btn._i18nWired) continue;
      btn._i18nWired = true;
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        window.i18nToggle();
      });
    }
    updateToggleLabel();
  }

  function boot() {
    wireToggle();
    applyLang();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
