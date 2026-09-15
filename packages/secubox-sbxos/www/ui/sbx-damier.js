// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: <sbx-damier> — la grille du Hall (#1293).
 *
 * LE DAMIER EST LE BUREAU. Il ne connaît ni la Mine ni le stockage : on lui
 * DONNE une liste de carlettes composées, il les dispose et il signale ce que
 * l'utilisateur fait. Cette ignorance est volontaire — c'est elle qui permet de
 * l'employer pour le Hall, pour les favoris, et pour l'écran de réglages avec
 * exactement le même composant.
 *
 * LA GRILLE EST EN CSS PURE, et c'est un choix qui se paie en confort plus
 * tard : `auto-fill` avec une largeur minimale fait passer de deux colonnes sur
 * téléphone à six sur grand écran sans une ligne de JavaScript, sans point de
 * rupture à maintenir, et sans reflow au redimensionnement.
 *
 * USAGE
 *
 *     const d = document.querySelector('sbx-damier');
 *     d.carlettes = [{id, titre, icone, couleur, badge, favori, masque}, …];
 *     d.addEventListener('ouvrir',  e => …);   // e.detail.id
 *     d.addEventListener('options', e => …);
 *     d.addEventListener('ordre',   e => …);   // e.detail.ids, après un glisser
 *
 * ATTRIBUTS
 *   rangeable   présent = les vignettes se glissent pour être réordonnées
 *   min         largeur minimale d'une vignette (défaut 5.5rem)
 *   densite     serree | normale | large — voir ci-dessous
 *   etiquettes  toujours | jamais — le nom sous l'icône
 *   colonnes    auto | un nombre — plafond de colonnes sur grand écran
 *
 * TROIS RÉGLAGES, ET PAS UN DE PLUS (#1293).
 *
 * La tentation était d'exposer chaque variable CSS — largeur, écart, marge,
 * taille d'icône. C'est un piège : des molettes qui doivent S'ACCORDER entre
 * elles laissent fabriquer des grilles contradictoires, et la faute retombe
 * sur l'utilisateur qui « a mal réglé ». La DENSITÉ est donc une seule
 * molette qui bouge largeur, écart et icône ensemble, dans des proportions
 * déjà accordées.
 *
 * Les deux autres sont indépendantes parce qu'elles répondent à des questions
 * différentes : « est-ce que je veux lire les noms ? » et « est-ce que je
 * veux douze colonnes sur mon 27 pouces ? ». Aucune ne peut contredire les
 * autres — c'est le critère qui les a fait retenir.
 */

import './sbx-carlette.js';

/**
 * LES PALIERS DE DENSITÉ. Largeur, écart et icône bougent ENSEMBLE : une
 * vignette étroite avec un grand écart fait une grille trouée, une vignette
 * large avec un écart serré fait un mur. Ces triplets sont accordés une fois
 * ici, et l'interface ne propose que les triplets.
 */
const DENSITES = {
  serree:  { min: '4.2rem', ecart: '.45rem', icone: '1.35rem' },
  normale: { min: '5.5rem', ecart: '.7rem',  icone: '1.9rem'  },
  large:   { min: '7.4rem', ecart: '1rem',   icone: '2.5rem'  },
};
export const NOMS_DENSITE = Object.keys(DENSITES);

const GABARIT = document.createElement('template');
GABARIT.innerHTML = `
<style>
  :host { display: block; }
  .grille {
    display: grid;
    /* auto-fill + minmax : LA règle qui rend tout le reste responsive. */
    grid-template-columns: repeat(auto-fill, minmax(var(--min, 5.5rem), 1fr));
    gap: var(--ecart, .7rem);
    padding: var(--marge, .2rem);
    /* PLAFOND DE COLONNES. « auto-fill » seul donne douze colonnes minuscules sur
       un grand écran — techniquement responsive, illisible en pratique. On
       borne donc la LARGEUR de la grille plutôt que de compter les colonnes en
       JavaScript : le calcul reste dans le moteur de rendu, et rien ne se
       recalcule au redimensionnement. « --large-max » vaut « none » par défaut. */
    max-width: var(--large-max, none);
    margin-inline: auto;
  }
  /* L'étiquette se retire par une variable, pas par une classe : la carlette
     vit dans un autre arbre d'ombre, et seule une propriété personnalisée
     traverse la frontière. */
  :host([etiquettes="jamais"]) { --carlette-etiquette: none; }
  .vide {
    padding: 2.5rem 1rem;
    text-align: center;
    color: var(--encre-terne, #9ca3af);
    font-size: .84rem;
    line-height: 1.5;
  }
  /* Pendant un glisser : la vignette saisie s'efface, la place se voit. */
  ::slotted(sbx-carlette[data-saisie]) { opacity: .35; }
  .creux { outline: 2px dashed var(--accent, #38bdf8); outline-offset: 2px;
           border-radius: 22%; }
</style>
<div class="grille" part="grille"></div>
<div class="vide" hidden><slot name="vide">Rien à afficher.</slot></div>`;

export class SbxDamier extends HTMLElement {
  static get observedAttributes() {
    return ['min', 'rangeable', 'densite', 'etiquettes', 'colonnes'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' }).appendChild(GABARIT.content.cloneNode(true));
    this._grille = this.shadowRoot.querySelector('.grille');
    this._vide = this.shadowRoot.querySelector('.vide');
    this._carlettes = [];
    this._saisie = null;
  }

  connectedCallback() {
    this.#applique();
    this.#peint();
    // Les événements des carlettes remontent (composed) ; on les laisse passer
    // plutôt que de les ré-émettre : l'appelant écoute le damier OU la
    // carlette, au choix, et `detail.id` est le même.
    this._grille.addEventListener('dragover', this.#survol);
    this._grille.addEventListener('drop', this.#depose);
    this._grille.addEventListener('dragend', this.#finGlisser);
  }

  attributeChangedCallback(nom, _a, v) {
    // `min` reste accepté pour les appels qui veulent une largeur précise ; il
    // passe APRÈS la densité, donc il la précise plutôt que de la contredire.
    if (nom === 'min') this.style.setProperty('--min', v || '5.5rem');
    if (nom === 'rangeable') this.#peint();
    if (nom === 'densite' || nom === 'colonnes') this.#applique();
  }

  /** Traduit densité et plafond de colonnes en variables CSS. */
  #applique() {
    const d = DENSITES[this.getAttribute('densite')] || DENSITES.normale;
    if (!this.hasAttribute('min')) this.style.setProperty('--min', d.min);
    this.style.setProperty('--ecart', d.ecart);
    this.style.setProperty('--carlette-icone', d.icone);

    const c = this.getAttribute('colonnes');
    const n = Number(c);
    // LE PLAFOND SE CALCULE À PARTIR DE LA DENSITÉ COURANTE, sinon un réglage
    // « 6 colonnes » posé en densité large donnerait six colonnes écrasées
    // quand on repasse en serré. Les deux molettes restent indépendantes parce
    // que la seconde se relit à chaque changement de la première.
    this.style.setProperty('--large-max',
      (c && c !== 'auto' && n > 0)
        ? `calc(${n} * (${d.min} + ${d.ecart}))`
        : 'none');
  }

  /** @param {Array} liste carlettes déjà composées par le Hall */
  set carlettes(liste) {
    this._carlettes = Array.isArray(liste) ? liste : [];
    this.#peint();
  }
  get carlettes() { return this._carlettes; }

  /** Les ids dans l'ordre AFFICHÉ — ce que le Hall doit mémoriser. */
  get ids() {
    return [...this._grille.querySelectorAll('sbx-carlette')].map(c => c.id);
  }

  // — rendu ————————————————————————————————————————————————————

  #peint() {
    if (!this._grille) return;
    const rangeable = this.hasAttribute('rangeable');
    this._grille.textContent = '';

    for (const c of this._carlettes) {
      const el = document.createElement('sbx-carlette');
      el.id = c.id;
      el.setAttribute('titre', c.titre ?? '');
      el.setAttribute('icone', c.icone ?? '⬛');
      if (c.couleur) el.setAttribute('couleur', c.couleur);
      if (c.badge) el.setAttribute('badge', String(c.badge));
      if (c.favori) el.setAttribute('favori', '');
      if (c.masque) el.setAttribute('masque', '');
      if (rangeable) {
        el.draggable = true;
        el.addEventListener('dragstart', this.#debutGlisser);
      }
      this._grille.appendChild(el);
    }

    const vide = this._carlettes.length === 0;
    this._grille.hidden = vide;
    this._vide.hidden = !vide;
  }

  // — glisser-déposer ————————————————————————————————————————————
  //
  // On implémente le réordonnancement à la main plutôt que d'ajouter une
  // bibliothèque : le besoin tient en trois écouteurs, et une dépendance de
  // plus dans une PWA hors-ligne est un fichier de plus à mettre en cache.

  #debutGlisser = (ev) => {
    this._saisie = ev.currentTarget;
    this._saisie.dataset.saisie = '';
    ev.dataTransfer.effectAllowed = 'move';
    // Firefox exige une donnée pour démarrer un glisser.
    ev.dataTransfer.setData('text/plain', this._saisie.id);
  };

  #survol = (ev) => {
    if (!this._saisie) return;
    ev.preventDefault();                       // autorise le dépôt
    const cible = ev.target.closest('sbx-carlette');
    if (!cible || cible === this._saisie) return;

    // On insère AVANT ou APRÈS selon le côté survolé : sans ça, une vignette
    // ne peut jamais être déposée en dernière position.
    const r = cible.getBoundingClientRect();
    const apres = (ev.clientX - r.left) > r.width / 2;
    cible.parentNode.insertBefore(this._saisie,
      apres ? cible.nextSibling : cible);
  };

  #depose = (ev) => {
    if (!this._saisie) return;
    ev.preventDefault();
    this.#finGlisser();
  };

  #finGlisser = () => {
    if (!this._saisie) return;
    delete this._saisie.dataset.saisie;
    this._saisie = null;
    this.dispatchEvent(new CustomEvent('ordre', {
      bubbles: true, composed: true, detail: { ids: this.ids },
    }));
  };
}

customElements.define('sbx-damier', SbxDamier);
