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

    // Empty graph → just return ; the stats tiles already show 0/0 and
    // the user knows.  No persistent overlay message.
    if (!graph.nodes.length) return;

    // Build d3 dataset: sites are union of all node.sites + tracker nodes themselves.
    const siteSet = new Set();
    for (const n of graph.nodes) for (const s of (n.sites || [])) siteSet.add(s);

    const nodes = [];
    const idx = new Map();
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
      });
    }

    // Edges: connect tracker → each of its sites.  Phase B uses a
    // simple uniform stroke ; reuse count via stroke-width.
    const links = [];
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

    simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink([...links, ...accentLinks]).id(d => d.id).distance(70))
      .force('charge', d3.forceManyBody().strength(-180))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collide', d3.forceCollide().radius(22));

    // Phase 11.B v3 — content group that owns links + nodes ; the
    // d3.zoom behavior applies its transform here so pan/pinch don't
    // move the SVG itself (or its viewBox).
    const content = svg.append('g').attr('class', 'content');

    const linkSel = content.append('g').attr('class', 'links')
      .selectAll('line').data([...links, ...accentLinks]).join('line')
      .attr('class', d => d.accent ? 'edge accent' : 'edge')
      .attr('stroke-width', d => Math.max(1, Math.log(1 + (d.reuse || 0)) * 1.8))
      .attr('stroke-dasharray', d => d.accent ? '4,3' : null);

    const nodeG = content.append('g').attr('class', 'nodes')
      .selectAll('g').data(nodes).join('g')
      .attr('class', d => 'node node-' + d.kind)
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
        .on('end', (ev, d) => { if (!ev.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on('click', (ev, d) => focusNode(d, linkSel));

    nodeG.append('circle')
      .attr('r', d => d.kind === 'tracker' ? 7 : 10)
      .attr('fill', d => d.kind === 'tracker' ? 'var(--cyber-cyan)' : 'var(--gold-hermetic)');

    nodeG.append('text')
      .attr('x', 12).attr('y', 4)
      .text(d => d.label.length > 22 ? d.label.slice(0, 21) + '…' : d.label);

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

    // Auto-fit once the simulation cools so all nodes are visible.
    let fitDone = false;
    function autoFit(duration = 600) {
      if (!nodes.length) return;
      const bbox = content.node().getBBox();
      if (!bbox.width || !bbox.height) return;
      const pad = 28;
      const scale = Math.min(
        (W - pad * 2) / bbox.width,
        (H - pad * 2) / bbox.height,
        2.5,
      );
      const tx = (W - bbox.width * scale) / 2 - bbox.x * scale;
      const ty = (H - bbox.height * scale) / 2 - bbox.y * scale;
      svg.transition().duration(duration).call(
        zoom.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale),
      );
    }

    simulation.on('tick', () => {
      linkSel
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
      if (!fitDone && simulation.alpha() < 0.1) {
        fitDone = true;
        autoFit();
      }
    });
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
