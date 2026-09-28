// Point each panel's Download link at the format its own select currently shows. One delegated
// listener covers every download_row() on the page; the .txt href in the markup is the no-JS default.
document.addEventListener('change', function (e) {
  if (!e.target.classList || !e.target.classList.contains('dl-fmt')) return;
  var go = e.target.parentElement.querySelector('.dl-go');
  if (go) go.href = '/feed/download/' + go.dataset.feed + '/' + e.target.value;
});
