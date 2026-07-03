/**
 * Shared scan-result renderer — used by the homepage scanner and the
 * shareable report page. Expects the standard results DOM (see index.html).
 */
window.LSRender = (() => {
  const CIRCUMFERENCE = 2 * Math.PI * 52;

  const VERDICT_COPY = {
    safe: {
      label: 'Low risk',
      color: 'var(--safe)',
      text: 'No significant risk indicators were found. As always, stay cautious with pages that request passwords or payment details.',
    },
    caution: {
      label: 'Caution advised',
      color: 'var(--caution)',
      text: 'This link shows characteristics commonly associated with unsafe sites. Review the findings below before visiting.',
    },
    dangerous: {
      label: 'High risk',
      color: 'var(--danger)',
      text: 'Multiple strong risk indicators detected. We recommend you do not open this link.',
    },
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function formatAge(days) {
    if (days < 60) return `${days} days`;
    if (days < 730) return `${Math.round(days / 30)} months`;
    return `${Math.floor(days / 365)} years`;
  }

  function animateScore(target, node) {
    const start = performance.now();
    const duration = 900;
    function frame(now) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      node.textContent = Math.round(target * eased);
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function render(data) {
    const $ = (id) => document.getElementById(id);
    const copy = VERDICT_COPY[data.verdict] || VERDICT_COPY.caution;

    $('verdict-pill').textContent = copy.label;
    $('verdict-pill').className = 'verdict-pill ' + data.verdict;
    $('verdict-text').textContent = copy.text;
    $('scanned-url').textContent = data.finalUrl && data.finalUrl !== data.url
      ? `${data.url}  →  ${data.finalUrl}`
      : data.url;

    const gaugeFill = $('gauge-fill');
    gaugeFill.style.stroke = copy.color;
    gaugeFill.style.strokeDashoffset = CIRCUMFERENCE * (1 - data.score / 100);
    animateScore(data.score, $('gauge-score'));

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

    // Domain / certificate / hosting / page metadata
    const domainPanel = $('domain-panel');
    domainPanel.replaceChildren();
    const lines = [];
    if (data.domainInfo) {
      let domainLine = `${data.domainInfo.domain} — registered ${data.domainInfo.registered} (${formatAge(data.domainInfo.ageDays)} old)`;
      if (data.domainInfo.registrar) domainLine += ` via ${data.domainInfo.registrar}`;
      lines.push(['Domain', domainLine]);
      if (data.domainInfo.nameservers?.length) {
        lines.push(['Nameservers', data.domainInfo.nameservers.join(', ')]);
      }
    } else if (data.domain) {
      lines.push(['Domain', data.domain]);
    }
    if (data.hosting && data.hosting.org) {
      let hostLine = data.hosting.org;
      const place = [data.hosting.city, data.hosting.country].filter(Boolean).join(', ');
      if (place) hostLine += ` — ${place}`;
      if (data.hosting.ip) hostLine += ` (${data.hosting.ip})`;
      lines.push(['Hosted by', hostLine]);
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
    if (data.reputation) {
      lines.push(['Threat databases', data.reputation.flaggedBy.length
        ? `FLAGGED by ${data.reputation.flaggedBy.join(', ')}`
        : `checked ${data.reputation.sources.join(', ')} — no listings`]);
    }
    if (data.pageTitle) {
      lines.push(['Page title', `“${data.pageTitle}”`]);
    }
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

    // Screenshot preview (renders in a remote sandbox, never on this device)
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

    // Findings
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
    $('results').hidden = false;
  }

  return { render, formatAge };
})();
