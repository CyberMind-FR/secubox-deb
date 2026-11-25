// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Fonctions pures du composant partagé (#3945) : relevés, séries, position, dates.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { pur } = createRequire(import.meta.url)('../www/shared/pouls.js');

test('une valeur douteuse est non mesurée, jamais zéro', () => {
  for (const v of [null, undefined, NaN, Infinity, -1, 1e308, '12', [], {}, true]) assert.equal(pur.nombre(v), null);
  assert.equal(pur.nombre(0), 0);
  assert.deepEqual(pur.serie([1, null, 'x', NaN, 0], ['a', 2, 'c'.repeat(99)]), { v: [1, null, null, null, 0], l: ['a', '', 'c'.repeat(40), '', ''] });
  assert.deepEqual(pur.serie(null, null), { v: [], l: [] });
  assert.equal(pur.serie(Array(5000).fill(1), i => 'n' + i).l[0], 'n4600');          // les 400 dernières, avec LEUR date
});

test('relevés : triés, dédoublés, bornés ; codes et nombres hostiles écartés ; pays null gardé', () => {
  const l = pur.instants([
    { t: 300, pays: [{ code: 'FR', n: 3 }, { code: 'fr', n: 9 }, { code: '<b>', n: 1 }, { code: '__proto__', n: 1 }, { code: 'DE', n: NaN }, null] },
    { genere_le: 100, pays: null }, { t: 100, pays: [] }, null, 'x', { t: 'x', pays: [] }, { t: 1e300, pays: [] }]);
  assert.deepEqual(l, [{ t: 100, m: null }, { t: 300, m: { FR: 3 } }]);
  assert.equal(pur.instants('x').length, 0);
  assert.equal(pur.instants(Array.from({ length: 90 }, (_, i) => ({ t: i + 1, pays: [] }))).length, 13);
  const codes = [...Array(26 * 26).keys()].map(i => ({ code: String.fromCharCode(65 + i / 26, 65 + i % 26), n: 1 }));
  assert.equal(Object.keys(pur.instants([{ t: 1, pays: codes }])[0].m).length, 60);
});

test('jamais de mélange entre mesuré et non mesuré', () => {
  assert.equal(pur.melange(2, 4, .5), 3);
  assert.equal(pur.melange(null, 4, .4), null);
  assert.equal(pur.melange(null, 4, .6), 4);
  assert.equal(pur.melange(0, null, .4), 0);
});

test('trajet : part du présent, atteint le plus ancien, rebondit, finit ; rien sous deux mesures', () => {
  for (const n of [0, 1]) assert.equal(pur.trajet(0, n), null);
  assert.equal(pur.trajet(NaN, 5), null);
  for (const n of [2, 13, 60, 400]) {
    assert.equal(pur.trajet(0, n).p, n - 1);
    let min = n, fin = 0, avant = n;
    for (let ms = 0; ms < 40000; ms += 33) {
      const r = pur.trajet(ms, n);
      if (!r) { fin = ms; break; }
      assert.ok(r.p >= -.01 && r.p <= n - 1 + .33, String(r.p));
      if (r.direct) assert.equal(Math.round(r.p), n - 1);
      min = Math.min(min, r.p); avant = r.p;
    }
    assert.ok(min < .1 && fin > 0 && fin < 22000 && Math.abs(avant - (n - 1)) < .05, `${n} ${min} ${fin} ${avant}`);
  }
});

test('dates du passé', () => {
  assert.equal(pur.ecart(1000, 1010), 'à l’instant');
  assert.equal(pur.ecart(0, 720), 'il y a 12 min');
  assert.equal(pur.ecart(0, 7500), 'il y a 2 h 05');
  assert.match(pur.ecart(1764000000, 1764000000 + 90000), /^le \d/);
});

test('machine lente : 24 retards de plus de 25 ms en moyenne, ou 3 des 10 derniers au-delà de 50', () => {
  assert.equal(pur.lent(Array(23).fill(40)), false);
  assert.equal(pur.lent(Array(24).fill(26)), true);
  assert.equal(pur.lent(Array(24).fill(8)), false);
  assert.equal(pur.lent([60, 60, 1, 1, 60]), true);
  assert.equal(pur.lent([60, 60, ...Array(9).fill(1), 60]), false);
});
