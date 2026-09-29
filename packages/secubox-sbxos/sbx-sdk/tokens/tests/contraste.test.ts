// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/** Contraste WCAG AA (4,5:1) de chaque couleur de TEXTE sur chaque FOND d'Aurora (#1614). */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const css = readFileSync(new URL('../tokens.css', import.meta.url), 'utf8');
const jeton = (n: string) => {
  const m = new RegExp(`--sbx-${n}:\\s*(#[0-9a-fA-F]{6})`).exec(css);
  if (!m) throw new Error(`jeton --sbx-${n} absent`);
  return m[1];
};
const lum = (hex: string) => {
  const c = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
export const contraste = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

const TEXTES = ['encre', 'doux', 'pale', 'cyan',
  // #1678 : couleurs employées en texte (libellés d'état, chiffres, étoile).
  'vert', 'ambre', 'alerte-texte', 'violet-texte', 'bleu', 'or'];
const FONDS = ['fond', 'surface', 'relief'];

describe('contraste des jetons', () => {
  for (const t of TEXTES) for (const f of FONDS) {
    it(`--sbx-${t} sur --sbx-${f} ≥ 4,5:1`, () => {
      expect(contraste(jeton(t), jeton(f))).toBeGreaterThanOrEqual(4.5);
    });
  }
});

// #1678 : chaque état de carte a un jeton, et il pointe vers un jeton existant.
const ETATS = ['vivant', 'direct', 'veille', 'horsligne', 'verrou', 'selection', 'favori'];
describe('états de carte', () => {
  for (const e of ETATS) {
    it(`--sbx-etat-${e} renvoie à un jeton défini`, () => {
      const m = new RegExp(`--sbx-etat-${e}:\\s*var\\(--sbx-([a-z-]+)\\)`).exec(css);
      expect(m, `--sbx-etat-${e}`).not.toBeNull();
      expect(css).toMatch(new RegExp(`--sbx-${m![1]}:\\s*#`));
    });
  }
});
