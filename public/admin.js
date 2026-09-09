  (async () => {
    const $ = (id) => document.getElementById(id);
    const td = (content) => {
      const cell = document.createElement('td');
      if (content instanceof Node) cell.appendChild(content); else cell.textContent = content;
      return cell;
    };
    const chip = (verdict) => {
      const s = document.createElement('span');
      s.className = 'verdict-chip ' + verdict;
      s.textContent = verdict === 'safe' ? 'Low risk' : verdict === 'caution' ? 'Caution' : 'High risk';
      return s;
    };
    const when = (iso) => iso ? new Date(iso + 'Z').toLocaleString() : '—';

    try {
      const meRes = await fetch('/api/me');
      const { user } = await meRes.json();
      if (!user) { location.href = '/login'; return; }
      $('admin-email').textContent = user.email;

      const res = await fetch('/api/admin/overview');
      if (res.status === 403) {
        $('denied').textContent = 'This page is for the site owner only. Your account (' + user.email + ') is not in ADMIN_EMAILS.';
        $('denied').hidden = false;
        return;
      }
      const data = await res.json();

      $('stat-users').textContent = data.totals.users;
      $('stat-apiscans').textContent = data.totals.apiScans;
      $('stat-scans').textContent = data.totals.scans;
      $('stat-today').textContent = data.totals.scansToday;
      $('stat-keys').textContent = data.totals.apiKeys;

      const ub = $('users-body');
      for (const u of data.users) {
        const tr = document.createElement('tr');
        tr.appendChild(td(String(u.id)));
        tr.appendChild(td(u.email));
        tr.appendChild(td(when(u.createdAt)));
        tr.appendChild(td(String(u.scanCount)));
        tr.appendChild(td(String(u.activeKeys)));
        tr.appendChild(td(u.lastScanAt ? when(u.lastScanAt) : '—'));
        ub.appendChild(tr);
      }

      const sb = $('scans-body');
      for (const s of data.recentScans) {
        const tr = document.createElement('tr');
        const urlCell = td(s.url); urlCell.className = 'cell-url';
        tr.appendChild(urlCell);
        tr.appendChild(td(chip(s.verdict)));
        tr.appendChild(td(String(s.score)));
        tr.appendChild(td(s.source));
        tr.appendChild(td(s.email || 'anonymous'));
        tr.appendChild(td(when(s.createdAt)));
        sb.appendChild(tr);
      }

      $('admin-content').hidden = false;
    } catch (err) {
      $('denied').textContent = 'Could not load admin data: ' + err.message;
      $('denied').hidden = false;
    }
  })();
