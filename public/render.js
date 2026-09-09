/**
 * Shared scan-result renderer — used by the homepage scanner and the
 * shareable report page. Expects the report DOM (see index.html).
 */
window.LSRender = (() => {
  const VERDICT = {
    safe: {
      pill: 'Clear',
      headline: 'No threats detected',
      color: 'var(--safe)',
      text: 'None of our checks raised a flag. Stay cautious anyway with pages that ask for passwords or payment details.',
      icon: '<path d="M20 6 9 17l-5-5"/>',
    },
    caution: {
      pill: 'Caution',
      headline: 'Worth a closer look',
      color: 'var(--caution)',
      text: 'This link shows traits often associated with unsafe sites. Read the findings below before you open it.',
      icon: '<path d="M12 9v4M12 17h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>',
    },
    dangerous: {
      pill: 'High risk',
      headline: 'This link looks dangerous',
      color: 'var(--danger)',
      text: 'Multiple strong risk indicators were found. We recommend you do not open this link.',
      icon: '<path d="M18 6 6 18M6 6l12 12"/>',
    },
  };

  const CHECK = '<path d="M20 6 9 17l-5-5"/>';
  const WARN = '<path d="M12 9v4M12 17h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>';
  const DASH = '<path d="M5 12h14"/>';

  const $ = (id) => document.getElementById(id);

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function icon(paths, size) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', size);
    svg.setAttribute('height', size);
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.4');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.innerHTML = paths;
    return svg;
  }

  function formatAge(days) {
    if (days < 60) return `${days} days`;
    if (days < 730) return `${Math.round(days / 30)} months`;
    return `${Math.floor(days / 365)} years`;
  }

  function animateScore(target, node) {
    // Set the true value first so it stays correct even if animation frames
    // never run (background tab, reduced motion).
    node.textContent = target;
    const start = performance.now();
    function frame(now) {
      const t = Math.min(1, (now - start) / 900);
      node.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  /** Condenses the findings list into the at-a-glance summary rows. */
  function summaryRows(data) {
    const has = (id) => data.findings.some((f) => f.id === id);
    const worst = (ids) => data.findings.filter((f) => ids.includes(f.id));
    const rows = [];

    const flagged = data.reputation && data.reputation.flaggedBy.length > 0;
    rows.push({
      label: 'Malware &amp; threat databases',
      state: flagged ? 'bad' : 'ok',
      value: flagged ? `Flagged by ${data.reputation.flaggedBy.join(', ')}` : 'Not detected',
    });

    const phish = worst(['brand-impersonation', 'typosquat', 'wrong-tld-lookalike', 'punycode', 'userinfo', 'phish-keywords']);
    rows.push({
      label: 'Phishing patterns',
      state: phish.some((f) => f.severity === 'high' || f.severity === 'critical') ? 'bad'
           : phish.length ? 'warn' : 'ok',
      value: phish.length ? phish[0].title : 'Not detected',
    });

    const hops = (data.redirectChain || []).length - 1;
    rows.push({
      label: 'Redirect chain',
      state: has('downgrade') ? 'bad' : hops > 2 ? 'warn' : 'ok',
      value: hops <= 0 ? 'No redirects' : `${hops} redirect${hops === 1 ? '' : 's'}`,
    });

    rows.push({
      label: 'Connection',
      state: has('no-https') || has('cert-expired') || has('cert-self-signed') ? 'bad'
           : has('cert-invalid') ? 'warn' : 'ok',
      value: has('no-https') ? 'Not encrypted'
           : has('cert-expired') ? 'Expired certificate'
           : has('cert-self-signed') ? 'Self-signed certificate'
           : has('cert-invalid') ? 'Certificate unverified'
           : 'Encrypted (HTTPS)',
    });

    if (data.domainInfo) {
      const days = data.domainInfo.ageDays;
      rows.push({
        label: 'Domain age',
        state: days < 30 ? 'bad' : days < 180 ? 'warn' : 'ok',
        value: `${formatAge(days)} old`,
      });
    } else if (!data.reachable) {
      rows.push({ label: 'Site reachable', state: 'warn', value: 'No response' });
    }

    return rows;
  }

  function render(data) {
    const v = VERDICT[data.verdict] || VERDICT.caution;

    $('verdict-pill').textContent = v.pill;
    $('verdict-pill').className = 'verdict-pill ' + data.verdict;
    $('verdict-headline').textContent = v.headline;
    $('verdict-text').textContent = v.text;
    $('scanned-url').textContent = data.finalUrl && data.finalUrl !== data.url
      ? `${data.url} → ${data.finalUrl}`
      : data.url;

    const orb = $('status-orb');
    orb.setAttribute('data-verdict', data.verdict);
    orb.replaceChildren(icon(v.icon, 26));

    const fill = $('risk-fill');
    if (fill) {
      fill.style.width = Math.max(2, data.score) + '%';
      fill.style.background = v.color;
    }
    animateScore(data.score, $('gauge-score'));

    // Summary rows
    const rowsEl = $('check-rows');
    if (rowsEl) {
      rowsEl.replaceChildren();
      for (const row of summaryRows(data)) {
        const li = document.createElement('li');
        const label = el('span', 'check-label');
        label.innerHTML = row.label;
        const value = el('span', 'check-value ' + row.state);
        value.appendChild(icon(row.state === 'ok' ? CHECK : row.state === 'neutral' ? DASH : WARN, 14));
        value.appendChild(document.createTextNode(row.value));
        li.append(label, value);
        rowsEl.appendChild(li);
      }
    }

    // Redirect chain
    const redirectList = $('redirect-list');
    redirectList.replaceChildren();
    if (data.redirectChain && data.redirectChain.length > 1) {
      data.redirectChain.forEach((hop, i) => {
        const li = el('li');
        li.appendChild(el('span', 'hop-num', i === 0 ? 'start' : `hop ${i}`));
        li.appendChild(el('span', null, hop.url));
        if (hop.status) li.appendChild(el('span', 'hop-status', String(hop.status)));
        redirectList.appendChild(li);
      });
      $('redirect-panel').hidden = false;
    } else {
      $('redirect-panel').hidden = true;
    }

    // Domain / hosting / certificate / page metadata
    const domainPanel = $('domain-panel');
    domainPanel.replaceChildren();
    const lines = [];
    if (data.domainInfo) {
      let line = `${data.domainInfo.domain} — registered ${data.domainInfo.registered} (${formatAge(data.domainInfo.ageDays)} old)`;
      if (data.domainInfo.registrar) line += ` via ${data.domainInfo.registrar}`;
      lines.push(['Domain', line]);
      if (data.domainInfo.nameservers?.length) {
        lines.push(['Nameservers', data.domainInfo.nameservers.join(', ')]);
      }
    } else if (data.domain) {
      lines.push(['Domain', data.domain]);
    }
    if (data.hosting && data.hosting.org) {
      let host = data.hosting.org;
      const place = [data.hosting.city, data.hosting.country].filter(Boolean).join(', ');
      if (place) host += ` — ${place}`;
      if (data.hosting.ip) host += ` (${data.hosting.ip})`;
      lines.push(['Hosted by', host]);
    }
    if (data.certificate) {
      lines.push(['Certificate', `issued by ${data.certificate.issuer}, valid until ${data.certificate.validTo}`]);
    }
    if (data.securityHeaders) {
      const sh = data.securityHeaders;
      lines.push(['Security headers', `grade ${sh.grade}${sh.present.length ? ` — has ${sh.present.join(', ')}` : ' — none present'}`]);
    }
    if (data.technology && (data.technology.server || data.technology.stack?.length)) {
      const parts = [];
      if (data.technology.server) parts.push(data.technology.server);
      if (data.technology.stack?.length) parts.push(data.technology.stack.join(', '));
      lines.push(['Technology', parts.join(' · ')]);
    }
    if (data.pageTitle) lines.push(['Page title', `“${data.pageTitle}”`]);
    if (lines.length > 0) {
      for (const [label, value] of lines) {
        const row = el('div');
        row.appendChild(el('strong', null, label + ': '));
        row.append(value);
        domainPanel.appendChild(row);
      }
      domainPanel.hidden = false;
    } else {
      domainPanel.hidden = true;
    }

    // Screenshot preview (rendered in a remote sandbox, never on this device)
    const shotPanel = $('screenshot-panel');
    if (shotPanel) {
      const img = $('screenshot-img');
      if (data.screenshotUrl && data.reachable) {
        img.src = data.screenshotUrl;
        img.alt = `Preview of ${data.finalUrl}`;
        shotPanel.hidden = false;
        img.onerror = () => { shotPanel.hidden = true; };
      } else {
        shotPanel.hidden = true;
      }
    }

    // Detailed findings
    const findingsList = $('findings');
    findingsList.replaceChildren();
    for (const f of data.findings) {
      const li = el('li', 'finding');
      li.appendChild(el('span', 'finding-badge ' + f.severity, f.severity));
      const body = el('div');
      body.appendChild(el('h4', null, f.title));
      body.appendChild(el('p', null, f.detail));
      li.appendChild(body);
      findingsList.appendChild(li);
    }

    $('scan-meta').textContent =
      `Scanned in ${(data.durationMs / 1000).toFixed(1)}s · ${new Date(data.scannedAt).toLocaleString()}`;

    const example = $('example-report');
    if (example) example.hidden = true;
    $('results').hidden = false;
  }

  return { render, formatAge };
})();
