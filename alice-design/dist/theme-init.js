try {
  const preference = localStorage.getItem('alice-theme') || 'system';
  document.documentElement.dataset.theme = preference === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : preference;
} catch { /* A blocked preference store must not block the interface. */ }
