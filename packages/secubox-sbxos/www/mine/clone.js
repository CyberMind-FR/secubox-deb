// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: LE CLONE DU HALL (#1349).
 *
 * SBX OS montre CE QUE LE HALL MONTRE. Sans cette règle, ce sont deux bureaux
 * qui divergent lentement — et celui qu'on regarde le moins finit par mentir.
 *
 * DEUX SOURCES, ET CHACUNE RÉPOND À UNE QUESTION DIFFÉRENTE :
 *
 *   curation.json   CE QU'ON MONTRE — extrait du `FEATURED` du Hall au moment
 *                   de construire le paquet. C'est un JUGEMENT humain, versionné
 *                   avec le code. Le registre complet compte 121 services ; un
 *                   bureau à 121 tuiles est un mur, pas un bureau.
 *
 *   le registre     CE QUI RÉPOND — /api/v1/webos/public/services, lu en direct.
 *                   Installé, actif, en bonne santé. Une tuile qui ouvre un
 *                   service éteint est une promesse non tenue.
 *
 * LE REGISTRE NE PEUT QU'ÉCARTER, JAMAIS AJOUTER. S'il tombe, on garde la
 * curation entière plutôt que de vider le bureau : mieux vaut une tuile qui
 * mène à un service endormi qu'un écran vide qui ne dit rien.
 *
 * LE PROFIL DÉCIDE ENSUITE. `profil_min` n'est pas dans la curation du Hall —
 * il n'en a pas besoin, lui masque par CSS selon la session. On l'ajoute ici,
 * et le défaut est `user` : un invité ne voit que ce qui est explicitement
 * public. Se tromper dans ce sens ne montre pas trop ; l'inverse, si.
 */

/** Ce qu'un invité peut voir sans rien demander. Tout le reste exige `user`. */
const PUBLIC = new Set(['radio', 'billets', 'peertube', 'metanews']);

/** Où la curation et le registre se trouvent, par défaut. */
const CURATION = './mine/curation.json';
const REGISTRE = '/api/v1/webos/public/services';

async function json(url, options) {
  const r = await fetch(url, Object.assign({ credentials: 'same-origin' }, options));
  if (!r.ok) throw new Error(`${url} : HTTP ${r.status}`);
  // UN 200 QUI N'EST PAS DU JSON N'EST PAS UNE RÉPONSE : sur un vhost qui ne
  // monte pas cette API, le repli SPA rend la coquille avec un 200. Le dire ici
  // évite un message parlant de syntaxe là où la route est simplement absente.
  const ct = r.headers.get('content-type') || '';
  if (ct.indexOf('json') < 0) throw new Error(`${url} : réponse non-JSON`);
  return r.json();
}

/**
 * Construit le manifeste de la Mine à partir du Hall.
 *
 * @param {{profil?: string, curation?: string, registre?: string}} opts
 * @returns {Promise<object>} au format attendu par `Mine`
 */
export async function cloneDuHall({ profil = 'guest',
                                    curation = CURATION,
                                    registre = REGISTRE } = {}) {
  const doc = await json(curation);
  const lieux = Array.isArray(doc.lieux) ? doc.lieux : [];

  // L'état vivant est un CONFORT : son absence ne vide pas le bureau.
  let sante = null;
  try {
    const r = await json(registre);
    sante = new Map((r.services || []).map(s => [s.id, s]));
  } catch (e) {
    sante = null;
  }

  const carlettes = [];
  for (const l of lieux) {
    if (!l.id || !l.url) continue;
    if (sante) {
      const s = sante.get(l.id);
      // On n'écarte QUE sur une information POSITIVE d'absence. Un service que
      // le registre ne connaît pas (les cartes de groupe du Hall, par exemple)
      // n'est pas pour autant éteint — l'ignorance n'est pas une preuve.
      if (s && (s.installed === false || s.active === false)) continue;
    }
    carlettes.push({
      id: l.id,
      titre: l.label || l.id,
      icone: l.icon || '⬛',
      couleur: l.color || undefined,
      url: 'https://' + String(l.url).replace(/^https?:\/\//, ''),
      profil_min: PUBLIC.has(l.id) ? 'guest' : 'user',
      // `lan` voyage : une carlette réservée au réseau local ne doit pas
      // s'afficher à un client distant, et c'est la Mine qui tranchera.
      lan: !!l.lan,
    });
  }

  return {
    version: 1,
    nom: 'SBX OS',
    profil,
    invitation: null,
    _source: 'clone du Hall — curation extraite + registre vivant',
    carlettes,
  };
}
