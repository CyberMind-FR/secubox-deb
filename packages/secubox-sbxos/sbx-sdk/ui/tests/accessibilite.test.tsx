// @vitest-environment jsdom
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * Accessibilité (axe-core, #1614) des composants d'Aurora rendus sur fixtures.
 * Le contraste est vérifié par contraste.test.ts (jsdom ne calcule pas les couleurs).
 */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import axe from 'axe-core';
import { FluxHall } from '../FluxHall';
import { SbxIcon } from '@sbx/icons';
import { Lieu } from '../../../app/src/Lieu';
import { Reglages } from '../../../app/src/Reglages';

async function defauts(html: string) {
  document.documentElement.lang = 'fr';
  document.title = 'Aurora';
  document.body.innerHTML = `<main>${html}</main>`;
  const r = await axe.run(document, { iframes: false, rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } });
  return r.violations.filter(v => v.impact === 'serious' || v.impact === 'critical')
    .map(v => `${v.id} : ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
}

describe('accessibilité', () => {
  it('témoin : axe détecte une image sans texte alternatif', async () => {
    expect((await defauts('<img src="x.webp">')).some(d => d.startsWith('image-alt'))).toBe(true);
  });
  it('FluxHall', async () => {
    const html = renderToStaticMarkup(<FluxHall evenements={[
      { id: '1', titre: 'Sauvegarde terminée', priorite: 1, at: 1, icone: 'sauvegarde', lien: '/x' },
      { id: '2', titre: 'Sondes bloquées', priorite: 9, at: 2, icone: 'waf', etat: 'alerte' }]} apercu />);
    expect(await defauts(html)).toEqual([]);
  });
  it('SbxIcon : nom accessible, ou décorative', async () => {
    expect(await defauts(renderToStaticMarkup(<><SbxIcon id="radio" /><SbxIcon id="hall" label="" /></>))).toEqual([]);
  });
  it('Théâtre (Lieu)', async () => {
    expect(await defauts(renderToStaticMarkup(<Lieu titre="Billets" url="https://billets.exemple.test/" ferme={() => {}} />))).toEqual([]);
  });
  it('Réglages', async () => {
    expect(await defauts(renderToStaticMarkup(<Reglages man={null} ferme={() => {}} />))).toEqual([]);
  });
});
