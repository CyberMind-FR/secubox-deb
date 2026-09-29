// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * CARTE LÉGÈRE d'Aurora dans le Hall (#1616) : module TypeScript sans React,
 * ≤ 15 Ko gzip. Trois activités, les raccourcis des Espaces, le protocole sbx
 * côté enfant. Tout est inséré en TEXTE (createElement / textContent).
 */
import './carte.css';
import { activites, lienLocal, manifeste } from '@sbx/data';
import { ecoute, demandeOuverture } from '@sbx/protocol';

const racine = document.getElementById('racine')!;
racine.className = 'carte-legere';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, txt?: string) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt !== undefined) e.textContent = txt;
  return e;
}

async function dessine() {
  const [acts, man] = await Promise.all([activites(3), manifeste()]);
  racine.replaceChildren();
  const tete = el('div', 'cl-tete');
  tete.append(el('b', 'cl-logo', 'SBXOS'), el('span', 'cl-sous', 'Aurora'));
  const plein = el('a', 'cl-plein', 'Ouvrir ↗') as HTMLAnchorElement;
  plein.href = '/sbxos/aurora/'; plein.target = '_blank'; plein.rel = 'noopener';
  plein.addEventListener('click', (e) => { if (demandeOuverture('sbxos')) e.preventDefault(); });
  tete.append(plein);
  const liste = el('ol', 'cl-flux');
  liste.dataset.aide = 'Ce qui compte maintenant';
  for (const a of acts.slice(0, 3)) {
    const li = el('li');
    const l = lienLocal(a.context?.lien);
    const t = `${a.qui ?? 'Quelqu’un'} · ${a.context?.titre ?? 'Nouvelle activité'}`;
    if (l) { const x = el('a', undefined, t) as HTMLAnchorElement; x.href = l; x.target = '_top'; li.append(x); }
    else li.textContent = t;
    liste.append(li);
  }
  if (!acts.length) liste.append(el('li', 'cl-vide', 'Rien de nouveau.'));
  const espaces = el('nav', 'cl-espaces');
  espaces.setAttribute('aria-label', 'Espaces');
  for (const e of man?.espaces ?? []) {
    const b = el('a', undefined, e.nom) as HTMLAnchorElement;
    b.href = `/sbxos/aurora/?espace=${encodeURIComponent(e.id)}`; b.target = '_blank'; b.rel = 'noopener';
    espaces.append(b);
  }
  racine.append(tete, liste, espaces);
}

ecoute({ relis: dessine });
dessine();
