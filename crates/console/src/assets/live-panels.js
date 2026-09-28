// A polled panel that stops refreshing is the quietest way this console can mislead: htmx leaves
// the last successful render in place when a poll fails, and every relative age on it ("4 minutes
// ago", "never") was computed by the SERVER at that render, so it keeps reading as current while
// the real gap grows. Any element carrying `data-live="<what it is>"` gets a banner naming how
// long ago its numbers were actually measured, and is dimmed until a refresh succeeds.
//
// Staleness is decided TWO ways, because the obvious one is not sufficient:
//
// * htmx's error/timeout events, which cover a refused connection or a 500.
// * An age watchdog on the clock, which covers everything else. A request that is accepted and
//   then simply never answered fires no event at all: htmx's own default request timeout is 0
//   (no limit), so the xhr stays open indefinitely and the panel goes on presenting a reading it
//   took minutes ago as the current one. Observed directly against a server that accepted the
//   status poll and held it: after 143 seconds the page still said "Probed: just now". So each
//   polled panel gets a bounded request timeout (turning a hang into `htmx:timeout`) AND its
//   freshness is aged independently of whether any request ever completes.
(function () {
  var live = document.querySelectorAll('[data-live]');
  if (!live.length) return;

  // How long a single poll may hang before it is abandoned and reported as a timeout. Short
  // enough that a stall is visible well inside one poll interval, long enough that an ordinary
  // slow query (the fleet status runs several) is not cut off and reported as a fault.
  var REQUEST_TIMEOUT_MS = 15000;
  // How often the watchdog re-checks ages. Independent of any poll interval - it must keep
  // running precisely when the polls are not.
  var WATCHDOG_TICK_MS = 5000;

  function bannerId(el) { return 'stale-banner-' + (el.id || 'live'); }

  // The panel's own poll interval, read from `hx-trigger` ("every 30s"), so a panel that polls
  // slowly is not declared stale on a faster panel's schedule. Falls back to 30s for an element
  // whose trigger this cannot read.
  function pollIntervalMs(el) {
    var m = /every\s+([0-9]*\.?[0-9]+)\s*(ms|s|m)?/.exec(el.getAttribute('hx-trigger') || '');
    if (!m) return 30000;
    var n = parseFloat(m[1]);
    if (!isFinite(n) || n <= 0) return 30000;
    var unit = m[2] || 's';
    return unit === 'ms' ? n : unit === 'm' ? n * 60000 : n * 1000;
  }

  // Two whole missed refreshes plus the time one hung request is allowed to take, so a single
  // slow answer never raises the banner but a panel that has genuinely stopped updating does.
  function staleAfterMs(el) {
    return 2 * pollIntervalMs(el) + REQUEST_TIMEOUT_MS + WATCHDOG_TICK_MS;
  }

  function markFresh(el) {
    el.setAttribute('data-live-at', String(Date.now()));
    el.removeAttribute('data-stale');
    var b = document.getElementById(bannerId(el));
    if (b) b.remove();
  }

  function markStale(el, why) {
    var at = Number(el.getAttribute('data-live-at'));
    var secs = at ? Math.round((Date.now() - at) / 1000) : null;
    var age = secs === null ? 'when this page was opened'
      : secs < 90 ? secs + ' seconds ago'
      : Math.round(secs / 60) + ' minutes ago';
    el.setAttribute('data-stale', 'true');
    var b = document.getElementById(bannerId(el));
    if (!b) {
      b = document.createElement('div');
      b.id = bannerId(el);
      b.className = 'degraded';
      b.setAttribute('role', 'status');
      el.parentNode.insertBefore(b, el);
    }
    b.textContent = 'This ' + (el.getAttribute('data-live') || 'reading') + ' has stopped '
      + 'refreshing (' + why + '). What is shown below was measured ' + age + '; the ages it '
      + 'states have not moved since. Reload the page to retry.';
  }

  // The element that owns the poll, walking up from whatever htmx reported.
  function owner(e) {
    var el = (e.detail && (e.detail.elt || e.detail.target)) || null;
    while (el && el.nodeType === 1 && !el.hasAttribute('data-live')) el = el.parentElement;
    return (el && el.nodeType === 1 && el.hasAttribute('data-live')) ? el : null;
  }

  Array.prototype.forEach.call(live, function (el) {
    markFresh(el);
    // Bound the request itself. htmx's `hx-request` is read at request time, so setting it here
    // applies to every poll this element makes from now on, and it is set from ONE place so a new
    // `data-live` panel cannot be added without it. Without a bound, `xhr.timeout` stays 0 and a
    // server that accepts the request and never answers produces neither a swap nor an event.
    if (!el.getAttribute('hx-request')) {
      el.setAttribute('hx-request', '{"timeout": ' + REQUEST_TIMEOUT_MS + '}');
    }
  });

  // The watchdog: ages the last SUCCESSFUL refresh, whatever the in-flight request is doing.
  // Everything above this point reacts to an event; this is the part that still fires when there
  // is no event to react to.
  setInterval(function () {
    Array.prototype.forEach.call(live, function (el) {
      if (el.getAttribute('data-stale') === 'true') return;
      var at = Number(el.getAttribute('data-live-at'));
      if (!at || Date.now() - at < staleAfterMs(el)) return;
      markStale(el, 'no refresh has come back');
    });
  }, WATCHDOG_TICK_MS);

  document.body.addEventListener('htmx:responseError', function (e) {
    var el = owner(e); if (el) markStale(el, 'the server answered with an error');
  });
  document.body.addEventListener('htmx:sendError', function (e) {
    var el = owner(e); if (el) markStale(el, 'the server could not be reached');
  });
  document.body.addEventListener('htmx:timeout', function (e) {
    var el = owner(e); if (el) markStale(el, 'the server did not answer in time');
  });
  document.body.addEventListener('htmx:afterSwap', function (e) {
    var el = owner(e); if (el) markFresh(el);
  });
})();
