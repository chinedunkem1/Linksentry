(() => {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const btn = document.getElementById('scan-btn');
  const btnLabel = btn.querySelector('.btn-label');
  const spinner = btn.querySelector('.btn-spinner');
  const results = document.getElementById('results');
  const errorBox = document.getElementById('scan-error');
  const copyReportBtn = document.getElementById('copy-report-btn');

  let lastReportId = null;

  function setLoading(loading) {
    btn.disabled = loading;
    spinner.hidden = !loading;
    btnLabel.textContent = loading ? 'Scanning…' : 'Scan link';
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    setLoading(true);
    errorBox.hidden = true;

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scan failed. Please try again.');
      LSRender.render(data);
      lastReportId = data.reportId || null;
      copyReportBtn.hidden = !lastReportId;
      results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
      errorBox.textContent = err.message || 'Something went wrong. Please try again.';
      errorBox.hidden = false;
      results.hidden = true;
    } finally {
      setLoading(false);
    }
  });

  copyReportBtn.addEventListener('click', async () => {
    if (!lastReportId) return;
    await navigator.clipboard.writeText(`${location.origin}/r/${lastReportId}`);
    copyReportBtn.textContent = 'Link copied!';
    setTimeout(() => (copyReportBtn.textContent = 'Copy report link'), 1800);
  });

  document.getElementById('scan-again').addEventListener('click', () => {
    results.hidden = true;
    input.value = '';
    input.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  /* Swap header CTA depending on sign-in state. */
  fetch('/api/me').then((r) => r.json()).then(({ user }) => {
    const slot = document.getElementById('nav-account');
    if (!slot) return;
    if (user) {
      slot.textContent = 'Dashboard';
      slot.href = '/dashboard';
    }
  }).catch(() => { /* leave defaults */ });
})();
