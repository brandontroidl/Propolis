/* Apply the stored theme before first paint so there is no flash. No stored preference (or a private
   window that throws) keeps the server default, Graphite. Kept tiny and dependency-free. */
(function () {
  try {
    var t = localStorage.getItem('propolis-theme');
    if (t === 'cream' || t === 'system' || t === 'hacker' || t === 'graphite') {
      document.documentElement.setAttribute('data-theme', t);
    }
  } catch (e) {}
})();
