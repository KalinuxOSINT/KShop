// Applique le thème immédiatement pour éviter le flash blanc/noir
(function() {
  const theme = localStorage.getItem('kn-theme') || 'light';
  document.documentElement.setAttribute('data-theme', theme);
})();
