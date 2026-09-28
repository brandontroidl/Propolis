// Chart global defaults, read from the active theme's CSS custom properties (set on <html> by the
// head theme-init script before this runs), so charts recolour with the theme. propolisSyncChartTheme
// is re-called by the theme switcher after a change; falls back to the graphite values if a property
// is unreadable.
function propolisSyncChartTheme() {
  if (typeof Chart === 'undefined') return;
  var cs = getComputedStyle(document.documentElement);
  var prop = function (name, fallback) { var v = cs.getPropertyValue(name).trim(); return v || fallback; };
  Chart.defaults.color = prop('--text-muted', '#a79c8a');
  Chart.defaults.borderColor = prop('--border', '#332c24');
  Chart.defaults.font.family = prop('--font-mono', 'ui-monospace, monospace');
}
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.display = false;
Chart.defaults.animation.duration = 0;
propolisSyncChartTheme();

// Chart (re)initialisation for any canvas carrying data-chart, including canvases delivered by an
// HTMX swap. This lives on the parent page, not inside the swapped fragment, because a fragment's
// own <script> is not reliably executed after a swap and an onload-based shim is racier still: a
// hidden data-URI image may never fire load at all when the browser serves it from cache, which
// left the timeline canvas silently blank on some swaps and not others.
//
// Chart.js refuses to bind a second chart to a canvas that already has one, so an existing
// instance is destroyed first. Colours are read from the active theme's CSS custom properties so a
// chart matches whatever theme is live, and the theme switcher re-runs this to recolour on change.
function propolisInitCharts(root) {
  if (typeof Chart === 'undefined') return;
  var cs = getComputedStyle(document.documentElement);
  var line = (cs.getPropertyValue('--chart-line').trim() || '#e0a43f');
  var fill = (cs.getPropertyValue('--chart-fill').trim() || 'rgba(224,164,63,0.13)');
  var pointBorder = (cs.getPropertyValue('--chart-point-border').trim() || '#1a1613');
  (root || document).querySelectorAll('canvas[data-chart]').forEach(function (el) {
    var labelsEl = document.getElementById(el.dataset.labels);
    var valuesEl = document.getElementById(el.dataset.values);
    if (!labelsEl || !valuesEl) return;
    var existing = Chart.getChart(el);
    if (existing) existing.destroy();
    new Chart(el, {
      type: 'line',
      data: {
        labels: JSON.parse(labelsEl.textContent),
        datasets: [{
          data: JSON.parse(valuesEl.textContent),
          borderColor: line,
          backgroundColor: fill,
          borderWidth: 2,
          fill: true,
          tension: parseFloat(el.dataset.tension || '0'),
          pointRadius: parseInt(el.dataset.pointRadius || '0', 10),
          pointHoverRadius: 4,
          pointBackgroundColor: line,
          pointBorderColor: pointBorder,
          pointBorderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
        plugins: { tooltip: { displayColors: false } },
      },
    });
  });
}
document.addEventListener('DOMContentLoaded', function () { propolisInitCharts(document); });
// afterSettle, not afterSwap: HTMX's settle phase strips the canvas width/height/style Chart.js
// set, clearing the chart. Initialising after settle lets Chart.js win the last write.
document.addEventListener('htmx:afterSettle', function (e) { propolisInitCharts(e.detail.target); });
