// Runs before the app bundle (index.html; a same-origin script, so CSP script-src 'self' allows it). It applies the
// stored color mode and table density, so a dark-mode user never sees a light page first. Keys: web/src/preferences.ts.
/* global document, localStorage, window */
(function () {
  var root = document.documentElement;
  try {
    var scheme = localStorage.getItem('alice.colorScheme');
    if (scheme !== 'light' && scheme !== 'dark') {
      scheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    root.setAttribute('data-mantine-color-scheme', scheme);
    if (localStorage.getItem('alice.density') === 'compact') root.setAttribute('data-density', 'compact');
  } catch {
    // Storage is blocked: the app applies its defaults when it starts.
  }
})();
