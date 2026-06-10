// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Phase 11.B (#507) — Social mapping per-client view.
// Consumes the Phase A JSON contract (GET /social/graph/{token}) and
// renders a d3.js force-directed graph with:
//   - site nodes (favicons fetched via /social/favicon/{domain})
//   - tracker nodes (default cyber-cyan; family taxonomy in Phase C)
//   - edges with stroke-width = log(reuse_count+1)*2 (locked in
//     design lock round 2)
//   - tap-to-focus on tracker nodes → bottom-sheet detail
//   - wipe modal with 3-second countdown before confirm enable
//   - empty state when no data
// No CDN dependency: d3 v7 is self-hosted at /toolbox/d3.v7.min.js.

(() => {
  'use strict';
  if (typeof d3 === 'undefined') {
    console.error('[social] d3 missing — abort');
    return;
  }

  const body = document.body;
  const token = body.dataset.token;
  // i18n is injected via <script>window.__SOCIAL_I18N__ = { … }</script>
  // in the template head — keeps FR apostrophes intact (was a JSON.parse
  // crash when inlined as a data-* attribute).
  const i18n = window.__SOCIAL_I18N__ || {};

  // ─── i18n helper ───
  function t(key, vars = {}) {
    let s = i18n[key] || key;
    for (const [k, v] of Object.entries(vars)) {
      s = s.replace(`{${k}}`, v);
    }
    return s;
  }

  // ─── DOM refs ───
  const svgEl = document.getElementById('social-graph');
  const svg = d3.select(svgEl);
  const ndEl = document.getElementById('node-detail');
  const wipeModal = document.getElementById('wipe-modal');

  // ─── data binding helper ───
  function bind(key, value) {
    const el = document.querySelector(`[data-bind="${key}"]`);
    if (el) el.textContent = value;
  }

  // Phase 12.B — show/hide the "challenged your humanity" banner.
  function updateAntibotTile(sites, vendors) {
    const el = document.getElementById('antibot-alert');
    if (!el) return;
    if (!sites) { el.hidden = true; return; }
    const v = (vendors || []).join(', ');
    el.textContent = t('antibot_alert', { n: sites }) + (v ? ' — ' + v : '');
    el.hidden = false;
  }

  // ─── graph state ───
  let simulation = null;

  function svgSize() {
    // Measure actual rendered size so the force center scales with the
    // viewport.  Falls back to a sane default if the layout hasn't
    // settled yet.
    const r = svgEl.getBoundingClientRect();
    return { W: Math.max(r.width, 320), H: Math.max(r.height, 320) };
  }

  function clearGraph() {
    svg.selectAll('*').remove();
    if (simulation) simulation.stop();
  }

  function render(graph) {
    clearGraph();
    const { W, H } = svgSize();
    svg.attr('viewBox', `0 0 ${W} ${H}`);

    bind('total_trackers', graph.stats.total_trackers || 0);
    bind('total_sites', graph.stats.total_sites || 0);
    // Phase 12.B — "challenged your humanity" alert tile.
    updateAntibotTile(graph.stats.antibot_sites || 0, graph.stats.antibot_vendors || []);

    // Empty graph → just return ; the stats tiles already show 0/0 and
    // the user knows.  No persistent overlay message.
    if (!graph.nodes.length) return;

    // ── Round-Eye central hotspot (Phase 12.A) ──────────────────────
    // The user's device is the EYE at the centre of the storm : every
    // visited site orbits it, and every tracker that recognises the
    // device reaches in toward the eye.  Sites link to the eye, trackers
    // link to their sites — so the eye is the gravitational centre and
    // the densest tracker clusters become the visible "hot spots".
    const EYE_ID = 'eye:device';

    // Build d3 dataset: sites are union of all node.sites + tracker nodes themselves.
    const siteSet = new Set();
    for (const n of graph.nodes) for (const s of (n.sites || [])) siteSet.add(s);

    const nodes = [];
    const idx = new Map();
    // The eye node, pinned to centre.
    idx.set(EYE_ID, nodes.length);
    nodes.push({ id: EYE_ID, label: '', kind: 'eye', fx: W / 2, fy: H / 2 });
    for (const s of siteSet) {
      idx.set('site:' + s, nodes.length);
      nodes.push({ id: 'site:' + s, label: s, kind: 'site' });
    }
    for (const n of graph.nodes) {
      idx.set('tracker:' + n.domain, nodes.length);
      nodes.push({
        id: 'tracker:' + n.domain,
        label: n.domain,
        kind: 'tracker',
        hits: n.hits,
        sites: n.sites,
        first_seen: n.first_seen,
        last_seen: n.last_seen,
        cdn_vendor: n.cdn_vendor || null,
        cache_status: n.cache_status || null,
        antibot_vendor: n.antibot_vendor || null,
      });
    }

    // Edges: eye → each site (gravity), then tracker → each of its sites.
    const links = [];
    for (const s of siteSet) {
      links.push({ source: EYE_ID, target: 'site:' + s, reuse: 1, spoke: true });
    }
    for (const n of graph.nodes) {
      const trackerKey = 'tracker:' + n.domain;
      for (const s of (n.sites || [])) {
        links.push({
          source: trackerKey,
          target: 'site:' + s,
          reuse: n.hits,
        });
      }
    }
    // Phase A edges (cross-site shared trackers) also stamped as
    // dashed accent links for emphasis.
    const accentLinks = [];
    for (const e of (graph.edges || [])) {
      const a = 'site:' + e.src;
      const b = 'site:' + e.dst;
      if (idx.has(a) && idx.has(b)) {
        accentLinks.push({
          source: a, target: b, reuse: e.reuse_count, accent: true,
        });
      }
    }

    // Phase 11.B v4 — when we have many nodes (last test: 86 trackers +
    // 60 sites = 146 nodes) the default force layout spreads them far
    // outside the viewport, and the first autoFit caught the simulation
    // mid-flight so only a single node was visible.  Scale the forces
    // with node count and pre-warm the simulation synchronously before
    // first render so layout is already settled.
    const N = nodes.length;
    const chargeStr = N > 80 ? -28 : N > 30 ? -55 : -90;
    const R = Math.min(W, H) / 2;
    // Three concentric rings : eye (centre) → sites (inner) → trackers
    // (outer).  The radial force is now the DOMINANT force (strong pull
    // to the ring), charge is weak (just spreads nodes along the ring),
    // and links are weak springs so they don't yank nodes off-ring.
    const ringR = d => d.kind === 'eye' ? 0 : d.kind === 'site' ? R * 0.40 : R * 0.80;
    simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink([...links, ...accentLinks]).id(d => d.id)
        .distance(d => d.spoke ? R * 0.40 : 24).strength(0.08))
      .force('charge', d3.forceManyBody().strength(chargeStr).distanceMax(R * 0.6))
      .force('radial', d3.forceRadial(ringR, W / 2, H / 2)
        .strength(d => d.kind === 'eye' ? 0 : 0.9))
      .force('collide', d3.forceCollide().radius(N > 120 ? 9 : N > 60 ? 13 : 20))
      .alphaDecay(0.04);

    // Phase 11.B v3 — content group that owns links + nodes ; the
    // d3.zoom behavior applies its transform here so pan/pinch don't
    // move the SVG itself (or its viewBox).
    const content = svg.append('g').attr('class', 'content');

    // Visible ring guides — the "Round-Eye" levels : inner = your sites,
    // outer = the trackers reaching in.  Drawn first so they sit behind.
    const guides = content.append('g').attr('class', 'ring-guides');
    [['ring-inner', R * 0.40], ['ring-outer', R * 0.80]].forEach(([cls, rad]) => {
      guides.append('circle').attr('class', cls)
        .attr('cx', W / 2).attr('cy', H / 2).attr('r', rad);
    });

    const linkSel = content.append('g').attr('class', 'links')
      .selectAll('line').data([...links, ...accentLinks]).join('line')
      .attr('class', d => d.accent ? 'edge accent' : 'edge')
      .attr('stroke-width', d => Math.max(1, Math.log(1 + (d.reuse || 0)) * 1.8))
      .attr('stroke-dasharray', d => d.accent ? '4,3' : null);

    const nodeG = content.append('g').attr('class', 'nodes')
      .selectAll('g').data(nodes).join('g')
      .attr('class', d => 'node node-' + d.kind)
      .call(d3.drag()
        .on('start', (ev, d) => { if (d.kind === 'eye') return; if (!ev.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (ev, d) => { if (d.kind === 'eye') return; d.fx = ev.x; d.fy = ev.y; })
        .on('end', (ev, d) => { if (d.kind === 'eye') return; if (!ev.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on('click', (ev, d) => focusNode(d, linkSel));

    // CDN palette — distinct lens per edge-network vendor (Phase 12.A).
    const CDN_COLORS = {
      Cloudflare: '#f48120', Fastly: '#ff282d', Akamai: '#0099cc',
      CloudFront: '#ff9900', Google: '#4285f4', Vercel: '#ffffff',
      Netlify: '#00c7b7', BunnyCDN: '#ffb347', KeyCDN: '#3686ff',
      Sucuri: '#00a651', 'Imperva/Incapsula': '#ff5a00', 'edge-cache': '#9aa0a6',
    };
    function nodeColor(d) {
      if (d.kind === 'eye') return 'var(--cinnabar)';
      if (d.kind === 'site') return 'var(--gold-hermetic)';
      // Phase 12.B — anti-bot hosts get the highest-severity lens.
      if (d.antibot_vendor) return 'var(--cinnabar)';
      if (d.cdn_vendor && CDN_COLORS[d.cdn_vendor]) return CDN_COLORS[d.cdn_vendor];
      return 'var(--cyber-cyan)';
    }

    // The central eye : concentric pulse rings + iris.
    const eyeSel = nodeG.filter(d => d.kind === 'eye');
    eyeSel.append('circle').attr('class', 'eye-halo').attr('r', 26);
    eyeSel.append('circle').attr('class', 'eye-sclera').attr('r', 15);
    eyeSel.append('circle').attr('class', 'eye-iris').attr('r', 7);
    eyeSel.append('circle').attr('class', 'eye-pupil').attr('r', 3);

    // Phase 12.B — anti-bot hosts get a severe pulsing warning ring.
    nodeG.filter(d => d.kind === 'tracker' && d.antibot_vendor)
      .append('circle').attr('class', 'antibot-ring').attr('r', 12);

    // Site + tracker nodes.
    nodeG.filter(d => d.kind !== 'eye').append('circle')
      .attr('r', d => d.kind === 'tracker' ? 7 : 10)
      .attr('fill', nodeColor)
      .attr('stroke', d => (d.kind === 'tracker' && (d.cdn_vendor || d.antibot_vendor)) ? '#0a0a0f' : null)
      .attr('stroke-width', d => (d.kind === 'tracker' && (d.cdn_vendor || d.antibot_vendor)) ? 1.5 : 0);

    nodeG.filter(d => d.kind !== 'eye').append('text')
      .attr('x', 12).attr('y', 4)
      .text(d => (d.antibot_vendor ? '🤖 ' : '') + (d.label.length > 22 ? d.label.slice(0, 21) + '…' : d.label));

    // ─── pan + pinch-zoom on the SVG (transform applies to content) ──
    // Drag on a node calls d3.drag, drag on empty SVG calls d3.zoom's
    // pan ; pinch and wheel always zoom.  Touch-action: none on the
    // svg (css) keeps the browser from intercepting these gestures.
    const zoom = d3.zoom()
      .scaleExtent([0.2, 6])
      .filter((ev) => {
        // Allow pan when the gesture didn't start on a node element.
        // Allow all wheel + touch (multi-finger pinch).
        if (ev.type === 'wheel' || (ev.touches && ev.touches.length > 1)) return true;
        return !ev.target.closest('.node');
      })
      .on('zoom', (ev) => content.attr('transform', ev.transform));
    svg.call(zoom).on('dblclick.zoom', () => autoFit(800));

    // Auto-fit using node data positions (not getBBox — which can be
    // skewed by text labels far outside the actual node cluster).
    function autoFit(duration = 600) {
      if (!nodes.length) return;
      const xs = nodes.map(n => n.x).filter(Number.isFinite);
      const ys = nodes.map(n => n.y).filter(Number.isFinite);
      if (!xs.length) return;
      const x0 = Math.min(...xs), x1 = Math.max(...xs);
      const y0 = Math.min(...ys), y1 = Math.max(...ys);
      const bw = Math.max(x1 - x0, 100);
      const bh = Math.max(y1 - y0, 100);
      const pad = 60;
      const scale = Math.min(
        (W - pad * 2) / bw,
        (H - pad * 2) / bh,
        2.5,
      );
      const cx = (x0 + x1) / 2;
      const cy = (y0 + y1) / 2;
      const tx = W / 2 - cx * scale;
      const ty = H / 2 - cy * scale;
      svg.transition().duration(duration).call(
        zoom.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale),
      );
    }

    // Pre-warm the simulation synchronously so the layout is already
    // settled before the user sees the first frame.  300 ticks is
    // enough for ~150 nodes to find their resting positions.
    for (let i = 0; i < 300; i++) simulation.tick();

    // Now bind the live tick so subsequent micro-drift updates the DOM.
    simulation.on('tick', () => {
      linkSel
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Render once immediately with the pre-warmed positions.
    linkSel
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    nodeG.attr('transform', d => `translate(${d.x},${d.y})`);

    // Allow a gentle re-settle for visual polish (low alpha so it
    // barely moves) and fit-to-viewport immediately.
    simulation.alpha(0.05).restart();
    requestAnimationFrame(() => autoFit(0));
    // Re-fit on viewport resize.
    let resizeTimer;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        const sz = svgSize();
        svg.attr('viewBox', `0 0 ${sz.W} ${sz.H}`);
        autoFit(400);
      }, 150);
    });
  }

  // ─── focus / detail panel ───
  function focusNode(node, linkSel) {
    if (node.kind !== 'tracker') { ndEl.hidden = true; return; }
    bind('nd_domain', node.label);
    bind('nd_country', '—');  // Phase C dependency (GeoIP)
    bind('nd_asn',     '—');
    bind('nd_cdn', node.cdn_vendor ? (node.cdn_vendor + (node.cache_status ? ' · ' + node.cache_status : '')) : '—');
    bind('nd_antibot', node.antibot_vendor ? ('🤖 ' + node.antibot_vendor) : '—');
    bind('nd_sites',   (node.sites || []).join(', ') || '—');
    bind('nd_first_seen', node.first_seen ? new Date(node.first_seen * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—');
    bind('nd_last_seen',  node.last_seen  ? new Date(node.last_seen  * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—');
    ndEl.hidden = false;

    // Pulse the edges that touch this node
    linkSel.classed('focused', l => l.source.id === node.id || l.target.id === node.id);
  }

  // ─── wipe modal ───
  function openWipe() {
    if (!wipeModal) return;
    const confirmBtn = wipeModal.querySelector('[data-action="confirm-wipe"]');
    const countdown = wipeModal.querySelector('[data-bind="wipe_countdown"]');
    confirmBtn.disabled = true;
    let n = 3;
    countdown.hidden = false;
    countdown.textContent = t('wipe_modal_countdown', { n });
    const iv = setInterval(() => {
      n--;
      if (n <= 0) {
        clearInterval(iv);
        countdown.hidden = true;
        confirmBtn.disabled = false;
      } else {
        countdown.textContent = t('wipe_modal_countdown', { n });
      }
    }, 1000);
    wipeModal.showModal();
  }
  function cancelWipe() {
    if (wipeModal) wipeModal.close();
  }
  async function confirmWipe() {
    try {
      const r = await fetch(`/social/wipe/${encodeURIComponent(token)}`, { method: 'POST' });
      if (!r.ok) throw new Error('http ' + r.status);
      const j = await r.json();
      wipeModal.close();
      alert(t('wipe_success', { n: j.rows_deleted || 0 }));
      fetchGraph();
    } catch (e) {
      console.error('[social] wipe failed', e);
      alert(t('error'));
    }
  }

  // ─── event delegation ───
  document.addEventListener('click', (ev) => {
    const a = ev.target.closest('[data-action]');
    if (!a) return;
    switch (a.dataset.action) {
      case 'close-nd':     ndEl.hidden = true; break;
      case 'open-wipe':    openWipe(); break;
      case 'cancel-wipe':  cancelWipe(); break;
      case 'confirm-wipe': confirmWipe(); break;
    }
  });

  // ─── fetch + bootstrap ───
  async function fetchGraph() {
    try {
      const r = await fetch(`/social/graph/${encodeURIComponent(token)}?since=86400`);
      if (!r.ok) throw new Error('http ' + r.status);
      const g = await r.json();
      render(g);
    } catch (e) {
      console.error('[social] fetch failed', e);
    }
  }
  fetchGraph();
})();
