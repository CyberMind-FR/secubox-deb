// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SBXOS :: déclinaison de l'art au build (#1612). Masters 512 px (git) →
 * dist/art/icons/<id>-<64|128|256>[-alerte|-succes].webp. Les états sont
 * CALCULÉS : teinte de l'état en OKLab, luminosité et chroma ramenées à la
 * cible, relief conservé (validé par Gandalf le 2026-09-28). Jamais agrandi.
 */
import sharp from 'sharp';
import { readFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const ici = (p) => fileURLToPath(new URL(p, import.meta.url));
const man = JSON.parse(await readFile(ici('../sbx-sdk/icons/manifest.json'), 'utf8'));
const SORTIE = ici('../dist/art/icons/');
const TAILLES = [64, 128, 256];
const ETATS = { alerte: '#F43F5E', succes: '#22C55E' };
sharp.concurrency(2);

const lin = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const srgb = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * Math.max(c, 0) ** (1 / 2.4) - 0.055);
function versOklab(r, g, b) {
  r = lin(r); g = lin(g); b = lin(b);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
          1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
          0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s];
}
function depuisOklab(L, a, b) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [srgb(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
          srgb(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
          srgb(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s)];
}
const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
const mediane = (v) => { const s = v.slice().sort((x, y) => x - y); return s[s.length >> 1] || 1e-3; };

function teinte(px, cible) {
  const n = px.length / 4, L = new Float64Array(n), C = new Float64Array(n);
  const opL = [], opC = [];
  for (let i = 0; i < n; i++) {
    const [l, a, b] = versOklab(px[4 * i] / 255, px[4 * i + 1] / 255, px[4 * i + 2] / 255);
    L[i] = l; C[i] = Math.hypot(a, b);
    if (px[4 * i + 3] > 153) { opL.push(l); opC.push(C[i]); }
  }
  const [Lc, ac, bc] = versOklab(...hex(cible));
  const Cc = Math.hypot(ac, bc), h = Math.atan2(bc, ac);
  const g = Math.log(Lc) / Math.log(Math.max(mediane(opL), 1e-3));
  const k = Cc / Math.max(mediane(opC), 1e-3);
  const out = Buffer.from(px);
  for (let i = 0; i < n; i++) {
    const L2 = Math.max(L[i], 1e-4) ** g;
    let c2 = C[i] * k, rgb;
    for (let t = 0; t < 12; t++) {
      rgb = depuisOklab(L2, c2 * Math.cos(h), c2 * Math.sin(h));
      if (rgb.every((v) => v >= -0.002 && v <= 1.002)) break;
      c2 *= 0.9;
    }
    for (let j = 0; j < 3; j++) out[4 * i + j] = Math.round(Math.min(1, Math.max(0, rgb[j])) * 255);
  }
  return out;
}

await mkdir(SORTIE, { recursive: true });
let n = 0;
for (const ic of man.icones) {
  const src = ici('../sbx-sdk/icons/' + ic.master);
  const base = sharp(src).ensureAlpha();
  const { data, info } = await base.clone().resize(256, 256).raw().toBuffer({ resolveWithObject: true });
  const variantes = { '': data };
  for (const [e, c] of Object.entries(ETATS)) variantes['-' + e] = teinte(data, c);
  for (const [suffixe, buf] of Object.entries(variantes)) {
    for (const t of TAILLES) {
      await sharp(buf, { raw: { width: info.width, height: info.height, channels: 4 } })
        .resize(t, t).webp({ quality: 86, alphaQuality: 90, effort: 4 })
        .toFile(`${SORTIE}${ic.id}-${t}${suffixe}.webp`);
      n++;
    }
  }
}
console.log(`art : ${n} fichiers d'icônes dans dist/art/icons/`);
