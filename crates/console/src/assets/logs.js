(function () {
  var lines = document.getElementById('log-lines');
  var viewer = document.getElementById('log-viewer');
  var levelFilter = document.getElementById('log-level-filter');
  var textFilter = document.getElementById('log-text-filter');
  var pauseBtn = document.getElementById('log-pause-toggle');
  var statusEl = document.getElementById('log-connection-status');
  var hiddenEl = document.getElementById('log-hidden');
  var hiddenText = document.getElementById('log-hidden-text');
  var showAll = document.getElementById('log-show-all');
  var autoScroll = true;
  var MAX_LINES = 2000;
  // A fold that keeps growing in a long-open tab keeps its count but only this many member rows.
  var MAX_MEMBERS = 500;
  // Distinct values a fold's summary names per field before it counts the rest (routes::logs).
  var SUMMARY_VALUES = 4;
  var RANK = { ERROR: 5, WARN: 4, INFO: 3, DEBUG: 2, TRACE: 1 };

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text;
  }

  function rank(level) {
    return RANK[(level || '').toString().toUpperCase()] || RANK.INFO;
  }

  function levelSlug(level) {
    var l = (level || '').toString().toLowerCase();
    if (l === 'error' || l === 'warn' || l === 'info' || l === 'debug' || l === 'trace') return l;
    return 'info';
  }

  function clockTime(ts) {
    var t = (ts || '').toString();
    return t.charAt(13) === ':' ? t.slice(11, 19) : t;
  }

  function passesLevel(line) {
    var want = levelFilter.value;
    return !want || rank(line.dataset.level) >= rank(want);
  }

  function matchesFilters(line) {
    if (!passesLevel(line)) return false;
    var wantText = textFilter.value.trim().toLowerCase();
    if (wantText && line.textContent.toLowerCase().indexOf(wantText) === -1) return false;
    return true;
  }

  function updateHidden() {
    var rows = lines.getElementsByClassName('log-line');
    var below = 0;
    for (var i = 0; i < rows.length; i++) {
      if (!passesLevel(rows[i])) below++;
    }
    hiddenText.textContent = below + ' lower-level row' + (below === 1 ? '' : 's') + ' hidden';
    hiddenEl.hidden = below === 0;
  }

  function applyFilters() {
    var rows = lines.getElementsByClassName('log-line');
    for (var i = 0; i < rows.length; i++) {
      rows[i].style.display = matchesFilters(rows[i]) ? '' : 'none';
    }
    updateHidden();
  }

  function scrollToBottomIfFollowing() {
    if (autoScroll) viewer.scrollTop = viewer.scrollHeight;
  }

  function span(cls, text) {
    var s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    return s;
  }

  function kv(key, value) {
    var s = span('log-kv', '');
    s.dataset.key = key;
    s.dataset.more = '0';
    s.appendChild(span('log-k', key));
    s.appendChild(document.createTextNode('='));
    var vals = span('log-vals', '');
    vals.appendChild(span('log-v', value));
    s.appendChild(vals);
    return s;
  }

  function memberRow(entry) {
    var tr = document.createElement('tr');
    var time = document.createElement('td');
    time.className = 'log-time mono';
    time.textContent = clockTime(entry.timestamp);
    var cell = document.createElement('td');
    var fields = entry.fields || [];
    if (!fields.length) cell.appendChild(span('dim', 'no fields'));
    fields.forEach(function (f) {
      var pair = span('log-kv', '');
      pair.appendChild(span('log-k', f.key));
      pair.appendChild(document.createTextNode('='));
      pair.appendChild(span('log-v', f.value));
      cell.appendChild(pair);
      cell.appendChild(document.createTextNode(' '));
    });
    tr.appendChild(time);
    tr.appendChild(cell);
    return tr;
  }

  function buildLine(entry) {
    var slug = levelSlug(entry.level);
    var line = document.createElement('div');
    line.className = 'log-line level-' + slug;
    line.dataset.level = (entry.level || '').toString().toUpperCase();
    line.dataset.target = entry.target || '';
    line.dataset.message = entry.message || '';
    line.dataset.count = '1';
    var fields = entry.fields || [];

    var summary = document.createElement(fields.length ? 'summary' : 'div');
    summary.className = 'log-summary';
    var time = span('log-time mono', clockTime(entry.timestamp));
    time.title = entry.timestamp || '';
    summary.appendChild(time);
    summary.appendChild(span('log-level-badge log-level-badge-' + slug, entry.level || ''));
    summary.appendChild(span('log-target mono', entry.target || ''));
    var message = span('log-message', entry.message || '');
    fields.forEach(function (f) {
      message.appendChild(document.createTextNode(' '));
      message.appendChild(kv(f.key, f.value));
    });
    summary.appendChild(message);

    if (!fields.length) {
      line.appendChild(summary);
      return line;
    }
    var details = document.createElement('details');
    details.className = 'log-entry';
    details.appendChild(summary);
    var detail = document.createElement('div');
    detail.className = 'log-detail';
    var dl = document.createElement('dl');
    dl.className = 'log-fields';
    fields.forEach(function (f) {
      var dt = document.createElement('dt');
      dt.textContent = f.key;
      var dd = document.createElement('dd');
      dd.className = 'mono';
      dd.textContent = f.value;
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    detail.appendChild(dl);
    details.appendChild(detail);
    line.appendChild(details);
    return line;
  }

  // Turns a single-entry line into a fold: a count badge, and a member table in place of the
  // field list. `first` is the entry the line was built from, recovered from its own markup.
  function makeFold(line) {
    var details = line.querySelector('details.log-entry');
    var summary = line.querySelector('.log-summary');
    if (!details) {
      details = document.createElement('details');
      details.className = 'log-entry';
      var asSummary = document.createElement('summary');
      asSummary.className = 'log-summary';
      while (summary.firstChild) asSummary.appendChild(summary.firstChild);
      details.appendChild(asSummary);
      details.appendChild(document.createElement('div')).className = 'log-detail';
      line.replaceChild(details, summary);
      summary = asSummary;
    }
    var detail = details.querySelector('.log-detail');
    var timeEl = summary.querySelector('.log-time');
    var first = { timestamp: timeEl.title, fields: [] };
    var dl = detail.querySelector('dl.log-fields');
    if (dl) {
      var dts = dl.getElementsByTagName('dt');
      var dds = dl.getElementsByTagName('dd');
      for (var i = 0; i < dts.length; i++) first.fields.push({ key: dts[i].textContent, value: dds[i].textContent });
      dl.remove();
    }
    var table = document.createElement('table');
    table.className = 'log-members';
    var tbody = document.createElement('tbody');
    tbody.appendChild(memberRow(first));
    table.appendChild(tbody);
    detail.appendChild(table);
    var message = summary.querySelector('.log-message');
    var count = span('log-count', 'x1');
    var firstKv = message.querySelector('.log-kv');
    if (firstKv) {
      message.insertBefore(count, firstKv);
      message.insertBefore(document.createTextNode(' '), firstKv);
    } else {
      message.appendChild(document.createTextNode(' '));
      message.appendChild(count);
    }
  }

  function addSummaryValue(message, key, value) {
    var pairs = message.querySelectorAll('.log-kv');
    var pair = null;
    for (var i = 0; i < pairs.length; i++) if (pairs[i].dataset.key === key) pair = pairs[i];
    if (!pair) {
      message.appendChild(document.createTextNode(' '));
      message.appendChild(kv(key, value));
      return;
    }
    var vals = pair.querySelector('.log-vals');
    var seen = vals.querySelectorAll('.log-v');
    for (var j = 0; j < seen.length; j++) if (seen[j].textContent === value) return;
    if (seen.length < SUMMARY_VALUES) {
      vals.appendChild(document.createTextNode('/'));
      vals.appendChild(span('log-v', value));
      return;
    }
    // Past the listed values a new one is only counted; whether it was already counted cannot be
    // told without keeping every value, so this can overcount a value that recurs. It is a hint.
    var more = parseInt(pair.dataset.more || '0', 10) + 1;
    pair.dataset.more = String(more);
    var moreEl = pair.querySelector('.log-more');
    if (!moreEl) {
      moreEl = span('log-more', '');
      pair.appendChild(moreEl);
    }
    moreEl.textContent = '/+' + more;
  }

  // Folds `entry` into `line` (same INFO target and message, adjacent), as routes::logs does
  // for the page's first render.
  function foldInto(line, entry) {
    var count = parseInt(line.dataset.count || '1', 10);
    if (count === 1) makeFold(line);
    count++;
    line.dataset.count = String(count);
    var summary = line.querySelector('.log-summary');
    var time = summary.querySelector('.log-time');
    time.textContent = clockTime(entry.timestamp);
    time.title = entry.timestamp || '';
    summary.querySelector('.log-count').textContent = 'x' + count;
    var message = summary.querySelector('.log-message');
    (entry.fields || []).forEach(function (f) { addSummaryValue(message, f.key, f.value); });
    var tbody = line.querySelector('table.log-members tbody');
    tbody.appendChild(memberRow(entry));
    while (tbody.children.length > MAX_MEMBERS) tbody.removeChild(tbody.firstChild);
  }

  function appendEntry(entry) {
    var empty = document.getElementById('log-empty');
    if (empty) empty.remove();

    var last = lines.lastElementChild;
    var level = (entry.level || '').toString().toUpperCase();
    if (level === 'INFO' && last && last.dataset.level === 'INFO' &&
        last.dataset.target === (entry.target || '') && last.dataset.message === (entry.message || '')) {
      foldInto(last, entry);
      last.style.display = matchesFilters(last) ? '' : 'none';
    } else {
      var line = buildLine(entry);
      if (!matchesFilters(line)) line.style.display = 'none';
      lines.appendChild(line);
      while (lines.children.length > MAX_LINES) {
        lines.removeChild(lines.firstChild);
      }
      updateHidden();
    }
    scrollToBottomIfFollowing();
  }

  levelFilter.addEventListener('change', applyFilters);
  textFilter.addEventListener('input', applyFilters);
  showAll.addEventListener('click', function () {
    levelFilter.value = '';
    applyFilters();
  });

  pauseBtn.addEventListener('click', function () {
    autoScroll = !autoScroll;
    pauseBtn.textContent = autoScroll ? 'Pause' : 'Resume';
    pauseBtn.classList.toggle('active', !autoScroll);
    scrollToBottomIfFollowing();
  });

  applyFilters();
  viewer.scrollTop = viewer.scrollHeight;

  if (typeof EventSource === 'undefined') {
    setStatus('live tail unsupported in this browser');
  } else {
    var source = new EventSource('/logs/stream');
    source.onopen = function () { setStatus('live'); };
    source.onerror = function () { setStatus('reconnecting...'); };
    source.onmessage = function (event) {
      try {
        appendEntry(JSON.parse(event.data));
      } catch (e) {
        // malformed payload - skip it, the stream itself keeps going.
      }
    };
  }
})();
