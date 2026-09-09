  (async () => {
    const id = location.pathname.split('/').pop();
    const errBox = document.getElementById('report-error');
    try {
      const res = await fetch('/api/report/' + encodeURIComponent(id));
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Report not found.');
      document.title = `Scan report: ${data.domain} — Linkaware`;
      document.getElementById('report-id-line').textContent =
        `Report ${id} · scanned ${new Date(data.scannedAt).toLocaleString()}`;
      LSRender.render(data);

      document.getElementById('copy-link-btn').addEventListener('click', async () => {
        await navigator.clipboard.writeText(location.href);
        const btn = document.getElementById('copy-link-btn');
        btn.textContent = 'Copied';
        setTimeout(() => (btn.textContent = 'Copy link'), 1800);
      });
      document.getElementById('download-json-btn').addEventListener('click', () => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `linkaware-report-${id}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    } catch (err) {
      errBox.textContent = err.message;
      errBox.hidden = false;
    }
  })();
