// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Harnais jsdom du test #2915 : charge la page netdiag, simule les API et rend un JSON des constats.
const fs = require('fs');
const path = process.argv[2];
let JSDOM;
for (const p of [process.env.JSDOM_PATH, 'jsdom', '/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-sbxos/node_modules/jsdom']) {
  if (!p) continue;
  try { ({ JSDOM } = require(p)); break; } catch (e) { /* suivant */ }
}
if (!JSDOM) { console.log(JSON.stringify({ absent: true })); process.exit(0); }
const html = fs.readFileSync(path, 'utf8');
const appels = [];
const t0 = 1792300000;
function rep(corps, statut) { return Promise.resolve({ ok: (statut || 200) < 400, status: statut || 200, json: () => Promise.resolve(corps) }); }
function serie(a) { return a.map((v, i) => [t0 + i * 300, v]); }
function fetchSimule(url, opts) {
  opts = opts || {};
  const m = (opts.method || 'GET').toUpperCase();
  appels.push({ m, url, corps: opts.body || null });
  if (url.startsWith('/api/v1/netdiag/status')) return rep({ success: true, tools_available: { ping: true, iperf3: true } });
  if (url.startsWith('/api/v1/netdiag/interfaces')) return rep({ success: true, interfaces: [{ name: 'eth0', state: 'UP', mac: '02:00:00:00:00:01', mtu: 1500, type: 'ether', addresses: [{ address: '192.0.2.10', prefix: 24 }] }] });
  if (url.startsWith('/api/v1/netdiag/routes')) return rep({ success: true, ipv4: [{ dst: 'default', gateway: '192.0.2.1', dev: 'eth0', metric: 100, scope: 'global' }, { dst: '192.0.2.0/24', dev: 'eth0', metric: 0, scope: 'link' }], ipv6: [{ dst: '2001:db8::/64', dev: 'eth0', metric: 256, protocol: 'kernel' }] });
  if (url.startsWith('/api/v1/netdiag/arp')) return rep({ success: true, entries: [{ ip: '192.0.2.1', mac: '02:00:00:00:00:fe', interface: 'eth0', state: ['REACHABLE'] }] });
  if (url.startsWith('/api/v1/netdiag/connections')) return rep({ success: true, connections: [] });
  if (url.startsWith('/api/v1/netdiag/ports')) return rep({ success: true, ports: [] });
  if (url.startsWith('/api/v1/routes/rules')) return rep({ ipv4: [{ priority: 100, selector: 'from 192.0.2.0/24', action: 'lookup', table: 'wan2' }, { priority: 32766, selector: 'all', action: 'lookup', table: 'main' }], ipv6: [] });
  if (url.startsWith('/api/v1/routes/tables')) return rep({ tables: [{ id: 254, name: 'main' }] });
  if (url.startsWith('/api/v1/routes/routes') && m !== 'GET') return rep({ success: true });
  if (url.startsWith('/api/v1/routes/flush')) return rep({ success: true });
  if (url.startsWith('/api/v1/hub/netstats/summary')) return rep({ stale: false, network_drops: 7 });
  if (url.startsWith('/api/v1/hub/netstats/series')) return rep({ in_bps: { eth2: serie([1000, 2000, 3000]) }, out_bps: { eth2: serie([500, 600, 700]) }, drops: { input_policy: serie([3, 2, 2]) } });
  return rep({}, 404);
}
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'https://box.test/netdiag/', pretendToBeVisual: true,
  beforeParse(w) { w.fetch = fetchSimule; } });
const w = dom.window, d = w.document;
const attendre = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  await attendre(300);
  const out = { iframes: d.querySelectorAll('iframe').length };
  out.formRoute = !!d.getElementById('rtForm');
  out.supprimerIPv4 = [...d.querySelectorAll('#bR4 button')].filter(b => /Supprimer/.test(b.textContent)).length;
  out.reglesLignes = d.querySelectorAll('#rgBody tr').length;
  out.tablesLignes = d.querySelectorAll('#rgTables tr').length;
  // suppression avec confirmation integree : 1er clic = demande, pas d'appel DELETE
  const bs = [...d.querySelectorAll('#bR4 button')].filter(b => /Supprimer/.test(b.textContent));
  bs[0].click(); await attendre(50);
  out.deleteAvantAveu = appels.some(a => a.m === 'DELETE');
  const conf = [...d.querySelectorAll('#bR4 button')].find(b => /Confirmer/.test(b.textContent));
  out.aveuAffiche = !!conf;
  if (conf) { conf.click(); await attendre(80); }
  out.deleteApresAveu = appels.filter(a => a.m === 'DELETE' && a.url.startsWith('/api/v1/routes/routes')).map(a => a.corps);
  // ajout d'une route
  const f = d.getElementById('rtForm');
  f.hidden = false;
  f.elements.destination.value = '198.51.100.0/24'; f.elements.gateway.value = '192.0.2.254';
  f.dispatchEvent(new w.Event('submit', { cancelable: true, bubbles: true })); await attendre(80);
  out.post = appels.filter(a => a.m === 'POST' && a.url.startsWith('/api/v1/routes/routes')).map(a => a.corps);
  // temps reel
  d.getElementById('o-direct').click(); await attendre(250);
  out.tuilesDirect = d.getElementById('dTuiles').textContent;
  out.cartesDirect = d.querySelectorAll('#dIfaces .itf').length;
  out.dropsDirect = d.querySelectorAll('#dDrops .drop').length;
  out.ancienOngletSoc = !!d.getElementById('o-soc'); out.ancienOngletGestion = !!d.getElementById('o-gestion');
  console.log(JSON.stringify(out));
  process.exit(0);
})();
