(function () {
  var lines = document.getElementById('log-lines');
  var viewer = document.getElementById('log-viewer');
  var levelFilter = document.getElementById('log-level-filter');
  var textFilter = document.getElementById('log-text-filter');
  var pauseBtn = document.getElementById('log-pause-toggle');
  var statusEl = document.getElementById('log-connection-status');
  var autoScroll = true;
  var MAX_LINES = 2000;

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text;
  }

  function levelSlug(level) {
    var l = (level || '').toString().toLowerCase();
    if (l === 'error' || l === 'warn' || l === 'info' || l === 'debug' || l === 'trace') return l;
    return 'info';
  }

  function matchesFilters(line) {
    var wantLevel = levelFilter.value;
    if (wantLevel && line.dataset.level !== wantLevel) return false;
    var wantText = textFilter.value.trim().toLowerCase();
    if (wantText && line.textContent.toLowerCase().indexOf(wantText) === -1) return false;
    return true;
  }

  function applyFilters() {
    var rows = lines.getElementsByClassName('log-line');
    for (var i = 0; i < rows.length; i++) {
      rows[i].style.display = matchesFilters(rows[i]) ? '' : 'none';
    }
  }

  function scrollToBottomIfFollowing() {
    if (autoScroll) viewer.scrollTop = viewer.scrollHeight;
  }

  function appendEntry(entry) {
    var empty = document.getElementById('log-empty');
    if (empty) empty.remove();

    var slug = levelSlug(entry.level);

    var line = document.createElement('div');
    line.className = 'log-line level-' + slug;
    line.dataset.level = (entry.level || '').toString().toUpperCase();

    var time = document.createElement('span');
    time.className = 'log-time mono';
    time.textContent = entry.timestamp || '';

    var level = document.createElement('span');
    level.className = 'log-level-badge log-level-badge-' + slug;
    level.textContent = entry.level || '';

    var target = document.createElement('span');
    target.className = 'log-target mono';
    target.textContent = entry.target || '';

    var message = document.createElement('span');
    message.className = 'log-message';
    message.textContent = entry.message || '';

    line.appendChild(time);
    line.appendChild(level);
    line.appendChild(target);
    line.appendChild(message);

    if (!matchesFilters(line)) line.style.display = 'none';

    lines.appendChild(line);

    while (lines.children.length > MAX_LINES) {
      lines.removeChild(lines.firstChild);
    }

    scrollToBottomIfFollowing();
  }

  levelFilter.addEventListener('change', applyFilters);
  textFilter.addEventListener('input', applyFilters);

  pauseBtn.addEventListener('click', function () {
    autoScroll = !autoScroll;
    pauseBtn.textContent = autoScroll ? 'Pause' : 'Resume';
    pauseBtn.classList.toggle('active', !autoScroll);
    scrollToBottomIfFollowing();
  });

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
