(function () {
  // ---- theme switcher ------------------------------------------------------
  // The head applies the stored theme before first paint; here we keep the <select> in sync and
  // persist + recolour charts on change. localStorage may throw (private mode) - never let it break
  // the page. "system" follows the OS via CSS; the other three pin a palette.
  var THEMES = { graphite: 1, cream: 1, system: 1, hacker: 1 };
  function storedTheme() { try { return localStorage.getItem('propolis-theme'); } catch (e) { return null; } }
  function applyTheme(t) {
    if (!THEMES[t]) t = 'graphite';
    document.documentElement.setAttribute('data-theme', t);
    if (typeof propolisSyncChartTheme === 'function') propolisSyncChartTheme();
    propolisInitCharts(document);
    document.dispatchEvent(new CustomEvent('propolis:themechange'));
  }
  var sel = document.getElementById('theme-select');
  if (sel) {
    var cur = storedTheme(); if (!THEMES[cur]) cur = 'graphite';
    sel.value = cur;
    sel.addEventListener('change', function () {
      var t = THEMES[sel.value] ? sel.value : 'graphite';
      try { localStorage.setItem('propolis-theme', t); } catch (e) {}
      applyTheme(t);
    });
  }
  // The OS theme changing only matters while "system" is selected; CSS handles the recolour, we just
  // resync the canvas colours.
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if ((storedTheme() || 'graphite') === 'system') { if (typeof propolisSyncChartTheme === 'function') propolisSyncChartTheme(); propolisInitCharts(document); }
    });
  }

  // ---- Operations dropdown -------------------------------------------------
  var opsBtn = document.getElementById('opsbtn');
  var opsList = document.getElementById('opslist');
  var opsMenu = document.getElementById('opsmenu');
  function opsItems() { return opsList ? Array.prototype.slice.call(opsList.querySelectorAll('[role="menuitem"]')) : []; }
  function openOps() {
    if (!opsList) return;
    opsList.hidden = false; opsMenu.classList.add('open'); opsBtn.setAttribute('aria-expanded', 'true');
  }
  function closeOps(focusBtn) {
    if (!opsList) return;
    opsList.hidden = true; opsMenu.classList.remove('open'); opsBtn.setAttribute('aria-expanded', 'false');
    if (focusBtn && opsBtn) opsBtn.focus();
  }
  if (opsBtn) {
    opsBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (opsList.hidden) { openOps(); } else { closeOps(false); }
    });
    opsBtn.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); openOps(); var it = opsItems(); if (it.length) it[0].focus(); }
    });
    opsList.addEventListener('keydown', function (e) {
      var it = opsItems(); var i = it.indexOf(document.activeElement);
      if (e.key === 'Escape') { e.preventDefault(); closeOps(true); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); if (i < it.length - 1) it[i + 1].focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (i > 0) it[i - 1].focus(); else opsBtn.focus(); }
    });
    document.addEventListener('click', function (e) { if (opsMenu && !opsMenu.contains(e.target)) closeOps(false); });
  }

  // ---- evidence drawer -----------------------------------------------------
  var drawer = document.getElementById('drawer');
  var scrim = document.getElementById('drawer-scrim');
  var closeBtn = document.getElementById('drawer-close');
  var lastTrigger = null;
  function focusables() {
    return drawer.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])');
  }
  function openDrawer(trigger) {
    lastTrigger = trigger || document.activeElement;
    scrim.hidden = false; scrim.classList.add('open');
    drawer.classList.add('open');
    drawer.removeAttribute('inert'); drawer.removeAttribute('aria-hidden');
    drawer.setAttribute('aria-modal', 'true');
    setTimeout(function () { try { closeBtn.focus(); } catch (e) {} }, 0);
  }
  function closeDrawer() {
    if (!drawer.classList.contains('open')) return;
    scrim.classList.remove('open'); scrim.hidden = true;
    drawer.classList.remove('open');
    if (lastTrigger && lastTrigger.focus) { try { lastTrigger.focus(); } catch (e) {} }
    lastTrigger = null;
    drawer.removeAttribute('aria-modal');
    drawer.setAttribute('aria-hidden', 'true'); drawer.inert = true;
  }
  if (drawer) {
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
    if (scrim) scrim.addEventListener('click', closeDrawer);
    drawer.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var f = focusables(); if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && drawer.classList.contains('open')) closeDrawer(); });
    // HTMX drives the load: an ".insp" trigger carries hx-get to the drawer fragment. Open the
    // drawer as its request starts, and (re)focus once the real content has swapped in.
    document.body.addEventListener('htmx:beforeRequest', function (e) {
      var t = e.detail.elt;
      if (t && t.classList && t.classList.contains('insp')) openDrawer(t);
    });
    document.body.addEventListener('htmx:afterSwap', function (e) {
      if (e.detail.target && e.detail.target.id === 'drawer-body') { try { closeBtn.focus(); } catch (err) {} }
    });
    // If HTMX fails to load the dossier, don't strand the operator in an empty drawer.
    document.body.addEventListener('htmx:responseError', function (e) {
      if (e.detail.elt && e.detail.elt.classList && e.detail.elt.classList.contains('insp')) {
        document.getElementById('drawer-body').innerHTML = '<p class="empty-line">Could not load evidence. <a href="' + e.detail.elt.getAttribute('href') + '">Open the full page</a>.</p>';
      }
    });
  }

  // ---- confirmations and back links ----------------------------------------
  // Markup carries the intent as data attributes rather than inline onclick handlers, which the
  // Content-Security-Policy refuses. Delegated from the document so a detail page swapped into the
  // evidence drawer gets the same behaviour as a full page load.
  document.addEventListener('click', function (e) {
    var confirmEl = e.target.closest && e.target.closest('[data-confirm]');
    if (confirmEl && !window.confirm(confirmEl.getAttribute('data-confirm'))) {
      e.preventDefault();
      return;
    }
    var backEl = e.target.closest && e.target.closest('[data-history-back]');
    if (backEl && window.history.length > 1) {
      e.preventDefault();
      window.history.back();
    }
    var copyEl = e.target.closest && e.target.closest('[data-copy]');
    if (copyEl) {
      e.preventDefault();
      copyText(copyEl.getAttribute('data-copy'), copyEl);
    }
  });

  // ---- indicator copy buttons -----------------------------------------------
  // Copies the button's data-copy text. The clipboard API needs a secure context (loopback or
  // TLS); anywhere else a selected off-screen textarea and execCommand do the job. The button says
  // whether it worked rather than failing silently.
  function copyText(text, button) {
    function done(ok) {
      var label = button.getAttribute('data-label') || button.textContent;
      button.setAttribute('data-label', label);
      button.textContent = ok ? 'copied' : 'copy failed';
      setTimeout(function () { button.textContent = label; }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      return;
    }
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.className = 'offscreen-copy';
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    document.body.removeChild(area);
    done(ok);
  }

  // A button that asks for confirmation renders disabled and is enabled only here, once the
  // listener above exists: before that a click would submit without asking, and a delete cannot be
  // undone from the UI. If this script never loads, the buttons stay disabled. Content swapped in
  // later (the evidence drawer) is armed as htmx loads it.
  function armConfirmations(root) {
    var buttons = root.querySelectorAll ? root.querySelectorAll('[data-confirm][disabled]') : [];
    for (var i = 0; i < buttons.length; i++) buttons[i].disabled = false;
  }
  armConfirmations(document);
  document.body.addEventListener('htmx:load', function (e) { armConfirmations(e.target); });
})();

