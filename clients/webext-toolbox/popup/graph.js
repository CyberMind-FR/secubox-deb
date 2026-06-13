// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Dependency-free mini "Round-Eye" cartographie : the device at the
// centre, top trackers on an outer ring, radius/colour by hits + tier.
// A compact stand-in for the full d3 view served at /social/{token}.

const SVGNS = "http://www.w3.org/2000/svg";
const PAL = {
  base: "#c9a84c",   // gold
  cdn: "#00d4ff",    // cyan
  ab: "#e63946",     // cinnabar (anti-bot)
  opg: "#6e40c9",    // void purple (operator-grade)
  eye: "#00ff41",    // matrix green
  link: "#2a2a3a",
};

function el(name, attrs) {
  const n = document.createElementNS(SVGNS, name);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}

function tierOf(node) {
  if (node.opgrade_vendor) return "opg";
  if (node.antibot_vendor) return "ab";
  if (node.cdn_vendor) return "cdn";
  return "base";
}

function renderGraph(svg, data) {
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const W = 260, H = 180, cx = W / 2, cy = H / 2;

  const nodes = (data && data.nodes ? data.nodes.slice() : [])
    .sort((a, b) => (b.hits || 0) - (a.hits || 0))
    .slice(0, 14);

  if (!nodes.length) {
    const t = el("text", { x: cx, y: cy, fill: "#6b6b7a", "font-size": 11,
      "text-anchor": "middle" });
    t.textContent = "Aucun traceur détecté pour l'instant";
    svg.appendChild(t);
    return;
  }

  const maxHits = Math.max(...nodes.map((n) => n.hits || 1));
  const R = 66;

  // spokes first (under the dots)
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    const x = cx + Math.cos(a) * R, y = cy + Math.sin(a) * R;
    svg.appendChild(el("line", { x1: cx, y1: cy, x2: x, y2: y,
      stroke: PAL.link, "stroke-width": 1 }));
  });

  // tracker dots
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    const x = cx + Math.cos(a) * R, y = cy + Math.sin(a) * R;
    const r = 3 + Math.round(6 * Math.sqrt((n.hits || 1) / maxHits));
    const fill = PAL[tierOf(n)];
    const c = el("circle", { cx: x, cy: y, r, fill, "fill-opacity": 0.85 });
    const title = el("title", {});
    title.textContent = `${n.domain} — ${n.hits || 0} hits`
      + (n.cdn_vendor ? ` · ${n.cdn_vendor}` : "")
      + (n.antibot_vendor ? ` · anti-bot ${n.antibot_vendor}` : "")
      + (n.opgrade_vendor ? ` · opérateur ${n.opgrade_vendor}` : "");
    c.appendChild(title);
    svg.appendChild(c);
  });

  // the eye (device) at the centre
  svg.appendChild(el("circle", { cx, cy, r: 13, fill: "#0c0c12",
    stroke: PAL.eye, "stroke-width": 2 }));
  svg.appendChild(el("circle", { cx, cy, r: 4.5, fill: PAL.eye }));
}

globalThis.renderGraph = renderGraph;
