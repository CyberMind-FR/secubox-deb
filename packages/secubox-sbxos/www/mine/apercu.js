// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: LES APERÇUS VIVANTS (#1358).
 *
 * UNE VIGNETTE QUI DIT CE QU'ELLE CONTIENT ÉVITE D'Y ENTRER. « Radio » ne dit
 * rien ; « Radio — Sacred Spirit » dit s'il vaut la peine d'ouvrir. C'est la
 * différence entre un bureau qu'on parcourt et un bureau qu'on lit.
 *
 * DU TEXTE, PAS DES IMAGES, et ce n'est pas une facilité :
 *
 *   • la CSP du Hall pose `img-src 'self' data:` — une pochette tierce serait
 *     BLOQUÉE, et la relayer ferait de la box un mandataire d'images ;
 *   • un damier de vingt-cinq vignettes qui chargent chacune une image coûte
 *     plus qu'il ne rend, surtout sur un téléphone en 4G ;
 *   • et le titre est ce qu'on lit de toute façon. La pochette décore.
 *
 * ON NE SONDE QUE CE QUI EST VISIBLE, et l'on s'ARRÊTE quand l'onglet passe en
 * arrière-plan. Sans cette règle, une PWA installée interroge la box toutes les
 * vingt secondes, toute la journée, dans la poche de quelqu'un — pour un écran
 * que personne ne regarde.
 *
 * LE SILENCE EST UNE INFORMATION. Une radio qui ne joue rien doit le DIRE ; une
 * vignette qui garde le dernier titre affiché ment tranquillement.
 */

/** Toutes les vingt secondes : un titre change en minutes, pas en secondes. */
const CADENCE_MS = 20000;

/**
 * LES SONDES SONT DÉCLARÉES ICI, pas dans la curation.
 *
 * La curation est EXTRAITE du Hall (elle décrit des lieux) ; savoir quelle API
 * raconte l'état d'un service est une connaissance de SBX OS. Les mélanger
 * ferait qu'une régénération de la curation effacerait ces réglages.
 *
 * `lit` reçoit le document et rend une phrase courte, ou une chaîne vide quand
 * il n'y a rien à dire — une vignette muette vaut mieux qu'une vignette qui
 * invente.
 */
export const SONDES = {
  radio: {
    url: '/api/v1/radio/current',
    lit: (d) => {
      if (!d || d.silence) return 'silence';
      const p = d.piste || {};
      if (!p.titre) return '';
      return p.auteur ? `${p.auteur} — ${p.titre}` : String(p.titre);
    },
  },
};

async function sonde(def) {
  const r = await fetch(def.url, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(String(r.status));
  // UN 200 QUI N'EST PAS DU JSON N'EST PAS UNE RÉPONSE : sur un vhost qui ne
  // monte pas cette API, le repli SPA rend la coquille avec un 200.
  const ct = r.headers.get('content-type') || '';
  if (ct.indexOf('json') < 0) throw new Error('non-JSON');
  return def.lit(await r.json());
}

/**
 * Tient les aperçus à jour sur un damier.
 *
 * @param {() => Array} carlettes ce qui est affiché, relu à chaque tour
 * @param {(id: string, texte: string) => void} pose applique un aperçu
 */
export function suitLesApercus(carlettes, pose) {
  let minuteur = null;

  async function tour() {
    // On ne sonde QUE ce qui est réellement affiché : sonder un service masqué
    // coûte une requête pour un texte que personne ne verra.
    const vus = new Set((carlettes() || []).map(c => c.id));
    for (const [id, def] of Object.entries(SONDES)) {
      if (!vus.has(id)) continue;
      try {
        pose(id, await sonde(def));
      } catch (e) {
        // UN APERÇU EST UN CONFORT : son échec n'a pas à se voir. Une vignette
        // sans aperçu reste une vignette ; une vignette qui affiche « erreur »
        // apprend seulement que nous avons échoué.
        pose(id, '');
      }
    }
  }

  function relance() {
    clearInterval(minuteur);
    // `hidden` du document : onglet en arrière-plan, écran éteint, application
    // rangée. Continuer à sonder là serait payer de la batterie pour rien.
    if (document.hidden) return;
    tour();
    minuteur = setInterval(tour, CADENCE_MS);
  }

  document.addEventListener('visibilitychange', relance);
  relance();
  return () => { clearInterval(minuteur); document.removeEventListener('visibilitychange', relance); };
}
