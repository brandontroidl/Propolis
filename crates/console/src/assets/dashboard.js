// The protocol bar chart is not a line chart, so it lives outside propolisInitCharts. It reads the
// active theme's --chart-line at build time and re-renders on the theme-change event the switcher
// dispatches, so it recolours with everything else.
(function () {
  function renderProto() {
    if (typeof Chart === 'undefined') return;
    var el = document.getElementById('protoChart'); if (!el) return;
    var color = getComputedStyle(document.documentElement).getPropertyValue('--chart-line').trim() || '#e0a43f';
    var ex = Chart.getChart(el); if (ex) ex.destroy();
    new Chart(el, {
      type: 'bar',
      data: {
        labels: JSON.parse(document.getElementById('proto-labels').textContent),
        datasets: [{
          data: JSON.parse(document.getElementById('proto-data').textContent),
          backgroundColor: color,
          borderRadius: 4,
          maxBarThickness: 20,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 } },
          y: { grid: { display: false }, ticks: { autoSkip: false } },
        },
        plugins: { tooltip: { displayColors: false } },
      },
    });
  }
  document.addEventListener('DOMContentLoaded', renderProto);
  document.addEventListener('propolis:themechange', renderProto);
})();
