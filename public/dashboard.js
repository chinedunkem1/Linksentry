(() => {
  const $ = (id) => document.getElementById(id);

  let me = null;

  function toast(message) {
    const node = document.createElement('div');
    node.className = 'toast';
    node.textContent = message;
    document.body.appendChild(node);
    setTimeout(() => node.remove(), 3200);
  }

  function verdictChip(verdict) {
    const span = document.createElement('span');
    span.className = 'verdict-chip ' + verdict;
    span.textContent = verdict === 'safe' ? 'Low risk' : verdict === 'caution' ? 'Caution' : 'High risk';
    return span;
  }

  function td(content) {
    const cell = document.createElement('td');
    if (content instanceof Node) cell.appendChild(content);
    else cell.textContent = content;
    return cell;
  }

  function reportLink(reportId) {
    const a = document.createElement('a');
    a.href = '/r/' + reportId;
    a.textContent = 'View';
    a.style.color = 'var(--accent)';
    return a;
  }

  async function api(path, options = {}) {
    const res = await fetch(path, {
      headers: options.body ? { 'Content-Type': 'application/json' } : {},
      ...options,
    });
    const data = await res.json();
    if (res.status === 401 && path !== '/api/me') { location.href = '/login'; throw new Error('unauthorized'); }
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  /* ---------------- account ---------------- */

  async function loadMe() {
    const data = await api('/api/me');
    if (!data.user) { location.href = '/login'; return; }
    me = data.user;
    $('account-email').textContent = me.email;

    const pct = Math.min(100, (me.apiUsage.used / me.apiUsage.quota) * 100);
    $('usage-fill').style.width = pct + '%';
    $('usage-text').textContent =
      `${me.apiUsage.used.toLocaleString()} / ${me.apiUsage.quota.toLocaleString()} API scans used in ${me.apiUsage.month}`;

    $('bulk-sub').textContent =
      `Paste one URL per line — up to ${me.bulkLimit} per batch, unlimited batches.`;

    if (me.isAdmin) {
      const nav = document.querySelector('.site-nav');
      const link = document.createElement('a');
      link.href = '/admin';
      link.textContent = 'Admin';
      nav.appendChild(link);
    }

  }

  /* ---------------- API keys ---------------- */

  async function loadKeys() {
    const { keys } = await api('/api/keys');
    const active = keys.filter((k) => !k.revokedAt);
    $('keys-table').hidden = active.length === 0;
    $('keys-empty').hidden = active.length > 0;
    const body = $('keys-body');
    body.replaceChildren();
    for (const key of active) {
      const tr = document.createElement('tr');
      const prefix = document.createElement('span');
      prefix.style.fontFamily = 'var(--mono)';
      prefix.style.fontSize = '0.78rem';
      prefix.textContent = key.prefix;
      tr.appendChild(td(prefix));
      tr.appendChild(td(key.label));
      tr.appendChild(td(String(key.usedThisMonth)));
      const revoke = document.createElement('button');
      revoke.className = 'link-btn';
      revoke.textContent = 'Revoke';
      revoke.addEventListener('click', async () => {
        if (!confirm(`Revoke key ${key.prefix}? Apps using it will stop working.`)) return;
        await api('/api/keys/' + key.id, { method: 'DELETE' });
        toast('Key revoked.');
        loadKeys();
      });
      tr.appendChild(td(revoke));
      body.appendChild(tr);
    }
  }

  $('create-key-btn').addEventListener('click', async () => {
    try {
      const label = prompt('Label for this key (e.g. "production"):', 'default');
      if (label === null) return;
      const created = await api('/api/keys', { method: 'POST', body: JSON.stringify({ label }) });
      $('new-key-value').textContent = created.key;
      $('new-key-box').hidden = false;
      loadKeys();
    } catch (err) {
      toast(err.message);
    }
  });

  $('copy-key-btn').addEventListener('click', async () => {
    await navigator.clipboard.writeText($('new-key-value').textContent);
    toast('API key copied to clipboard.');
  });

  /* ---------------- bulk scan ---------------- */

  $('bulk-btn').addEventListener('click', async () => {
    const urls = $('bulk-input').value.split('\n').map((u) => u.trim()).filter(Boolean);
    if (urls.length === 0) return toast('Paste at least one URL first.');
    const btn = $('bulk-btn');
    btn.disabled = true;
    $('bulk-status').textContent = `Scanning ${urls.length} URL${urls.length === 1 ? '' : 's'}… this can take a moment.`;
    try {
      const data = await api('/api/bulk-scan', { method: 'POST', body: JSON.stringify({ urls }) });
      const body = $('bulk-body');
      body.replaceChildren();
      for (const row of data.results) {
        const tr = document.createElement('tr');
        const urlCell = td(row.url);
        urlCell.className = 'cell-url';
        tr.appendChild(urlCell);
        if (row.ok) {
          tr.appendChild(td(verdictChip(row.verdict)));
          tr.appendChild(td(String(row.score)));
          tr.appendChild(td(reportLink(row.reportId)));
        } else {
          const err = td(row.error);
          err.colSpan = 3;
          err.style.color = 'var(--danger)';
          tr.appendChild(err);
        }
        body.appendChild(tr);
      }
      $('bulk-table').hidden = false;
      $('bulk-status').textContent = `Done — ${data.results.filter((r) => r.ok).length}/${data.count} scanned.`;
      loadHistory();
    } catch (err) {
      $('bulk-status').textContent = '';
      toast(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  /* ---------------- history ---------------- */

  async function loadHistory() {
    const { scans } = await api('/api/history');
    $('history-table').hidden = scans.length === 0;
    $('history-empty').hidden = scans.length > 0;
    $('clear-history-btn').hidden = scans.length === 0;
    const body = $('history-body');
    body.replaceChildren();
    for (const scan of scans) {
      const tr = document.createElement('tr');
      const urlCell = td(scan.url);
      urlCell.className = 'cell-url';
      tr.appendChild(urlCell);
      tr.appendChild(td(verdictChip(scan.verdict)));
      tr.appendChild(td(String(scan.score)));
      tr.appendChild(td(scan.source));
      tr.appendChild(td(new Date(scan.createdAt + 'Z').toLocaleString()));
      tr.appendChild(td(reportLink(scan.reportId)));
      body.appendChild(tr);
    }
  }

  $('clear-history-btn').addEventListener('click', async () => {
    if (!confirm('Delete your entire scan history? This cannot be undone.')) return;
    await api('/api/history', { method: 'DELETE' });
    toast('History cleared.');
    loadHistory();
  });

  /* ---------------- logout ---------------- */

  $('logout-btn').addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    location.href = '/';
  });

  /* ---------------- init ---------------- */

  loadMe().then(() => Promise.all([loadKeys(), loadHistory()])).catch((err) => {
    if (err.message !== 'unauthorized') toast(err.message);
  });
})();
