(() => {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const btn = document.getElementById('scan-btn');
  const btnLabel = btn.querySelector('.btn-label');
  const spinner = btn.querySelector('.btn-spinner');
  const results = document.getElementById('results');
  const example = document.getElementById('example-report');
  const errorBox = document.getElementById('scan-error');
  const copyReportBtn = document.getElementById('copy-report-btn');

  let lastReportId = null;

  function setLoading(loading) {
    btn.disabled = loading;
    spinner.hidden = !loading;
    btnLabel.textContent = loading ? 'Scanning…' : 'Scan link';
  }

  async function runScan(url) {
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
      copyReportBtn.textContent = 'Copy report link';
      if (window.innerWidth <= 900) {
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    } catch (err) {
      errorBox.textContent = err.message || 'Something went wrong. Please try again.';
      errorBox.hidden = false;
      results.hidden = true;
      if (example) example.hidden = false;
    } finally {
      setLoading(false);
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (url) runScan(url);
  });

  for (const chip of document.querySelectorAll('.sample-chip')) {
    chip.addEventListener('click', () => {
      input.value = chip.dataset.url;
      runScan(chip.dataset.url);
    });
  }

  copyReportBtn.addEventListener('click', async () => {
    if (!lastReportId) return;
    await navigator.clipboard.writeText(`${location.origin}/r/${lastReportId}`);
    copyReportBtn.textContent = 'Link copied';
    setTimeout(() => (copyReportBtn.textContent = 'Copy report link'), 1800);
  });

  document.getElementById('scan-again').addEventListener('click', () => {
    results.hidden = true;
    if (example) example.hidden = false;
    input.value = '';
    input.focus();
    document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  /* Swap the header CTA when already signed in. */
  fetch('/api/me').then((r) => r.json()).then(({ user }) => {
    const slot = document.getElementById('nav-account');
    if (slot && user) {
      slot.textContent = 'Dashboard';
      slot.href = '/dashboard';
    }
  }).catch(() => { /* leave default */ });
})();
