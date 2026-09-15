// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: <sbx-carlette> — la vignette du damier (#1293).
 *
 * UNE CARLETTE N'EST PAS UNE ICÔNE D'APPLICATION, C'EST UN LIEU. C'est toute la
 * différence de langage du Hall : on n'ouvre pas « PeerTube », on entre au
 * Cinéma. La vignette porte donc un nom de lieu, une couleur d'ambiance, et un
 * état — pas un logo d'éditeur.
 *
 * TOUT EST CARRÉ, ET LE DAMIER S'EN CHARGE. La carlette ne décide jamais de sa
 * taille : elle remplit ce qu'on lui donne (`aspect-ratio: 1`). C'est ce qui
 * permet au damier de passer de deux colonnes sur téléphone à six sur écran
 * large sans qu'une seule ligne de JavaScript ne s'en mêle.
 *
 * USAGE
 *
 *     <sbx-carlette
 *        id="cinema" titre="Cinéma" icone="🎬" couleur="#7c3aed"
 *        badge="3" favori theatre="cinema"></sbx-carlette>
 *
 * ATTRIBUTS
 *   id        identifiant du module (sert aux événements)
 *   titre     le nom du LIEU, pas du logiciel
 *   icone     un emoji — jamais du balisage
 *   couleur   #rrggbb d'ambiance ; à défaut, une teinte dérivée du titre
 *   badge     pastille de comptage (« non vu ») ; absent ou "0" = rien
 *   favori    présent = mis en avant
 *   masque    présent = grisé (vue réglages uniquement)
 *
 * ÉVÉNEMENTS (tous `composed`, pour franchir le Shadow DOM)
 *   ouvrir    clic simple, ou Entrée/Espace
 *   options   appui long, clic droit, ou touche ContextMenu
 *
 * ACCESSIBILITÉ. La carlette est un vrai bouton : `role=button`, `tabindex=0`,
 * et Entrée/Espace font ce que le clic fait. Un damier qu'on ne peut pas
 * parcourir au clavier n'est pas un bureau, c'est une affiche.
 */

const GABARIT = document.createElement('template');
GABARIT.innerHTML = `
<style>
  /* LA GARDE DOIT ÊTRE RÉPÉTÉE DANS CHAQUE RACINE D'OMBRE.
   *
   * « [hidden] { display: none } » vient du navigateur, donc cède devant toute
   * règle d'auteur posant « display » — et « .badge » pose « display:inline-flex ».
   * Un badge « hidden » restait donc affiché : une pastille rouge VIDE sur
   * chaque vignette du damier.
   *
   * La même garde existe dans la feuille du document (#1356), mais une feuille
   * de document NE TRAVERSE PAS le shadow DOM. Il faut la répéter ici — c'est
   * le prix de l'encapsulation, et l'oublier redonne exactement le même bug
   * dans un endroit où l'on ne pense pas à le chercher.
   */
  [hidden] { display: none !important; }

  :host {
    display: block;
    aspect-ratio: 1;            /* le damier impose la largeur, la hauteur suit */
    -webkit-tap-highlight-color: transparent;
  }
  :host([masque]) { opacity: .38; }

  .tuile {
    position: relative;
    width: 100%; height: 100%;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center; gap: .35rem;
    border-radius: 22%;          /* en % : la courbure suit la taille */
    border: 1px solid var(--bord, rgba(255,255,255,.14));
    background:
      linear-gradient(160deg,
        color-mix(in srgb, var(--teinte) 34%, transparent),
        color-mix(in srgb, var(--teinte) 12%, transparent));
    color: var(--encre, #f4f4f5);
    cursor: pointer;
    user-select: none;
    /* L'ANIMATION EST DOUCE ET COURTE. Un bureau se parcourt vite ; une
       transition longue donne l'impression que l'appareil rame. */
    transition: transform .16s cubic-bezier(.2,.8,.3,1),
                box-shadow .16s ease, border-color .16s ease;
  }
  .tuile:hover { border-color: color-mix(in srgb, var(--teinte) 60%, transparent); }
  .tuile:active { transform: scale(.94); }
  .tuile:focus-visible {
    outline: 2px solid var(--teinte);
    outline-offset: 3px;
  }

  .icone {
    /* LA DENSITÉ DU DAMIER PASSE PAR ICI. « --carlette-icone » est posée par le
       damier ; le « clamp » reste le défaut, pour une carlette employée seule.
       Le repli n'est pas une valeur fixe mais le clamp lui-même : une carlette
       hors damier doit rester responsive. */
    font-size: var(--carlette-icone, clamp(1.6rem, 9vw, 2.6rem));
    line-height: 1;
    /* L'emoji ne doit pas être sélectionnable : un appui long doit ouvrir NOS
       options, pas le sélecteur de texte du système. */
    pointer-events: none;
  }
  /* L'APERÇU : ce que le lieu contient MAINTENANT. Une ligne, coupée net.
     Il passe SOUS le titre et n'agrandit pas la vignette — le damier doit
     rester un damier, pas une liste. */
  .apercu {
    display: var(--carlette-apercu, block);
    font-size: clamp(.52rem, 2.2vw, .62rem);
    font-weight: 500;
    opacity: .72;
    text-align: center;
    padding: 0 .35rem;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    pointer-events: none;
  }
  .apercu:empty { display: none; }

  .titre {
    /* Retirée par le damier via « --carlette-etiquette: none ». On ne masque pas
       par « visibility » : la place doit être RENDUE, sinon les vignettes sans
       nom gardent un vide sous l'icône. */
    display: var(--carlette-etiquette, block);
    font-size: clamp(.62rem, 2.8vw, .78rem);
    font-weight: 600;
    letter-spacing: .01em;
    text-align: center;
    padding: 0 .4rem;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    pointer-events: none;
  }

  /* Le favori se voit SANS lire : une étoile en coin, pas un mot. */
  .favori {
    position: absolute; top: 7%; right: 8%;
    font-size: .74rem; line-height: 1;
    filter: drop-shadow(0 1px 2px rgba(0,0,0,.4));
    pointer-events: none;
  }

  /* Le badge « non vu » : un compte, en haut à gauche pour ne pas heurter
     l'étoile. Il est le seul élément qui bouge — c'est lui qui appelle. */
  .badge {
    position: absolute; top: 6%; left: 7%;
    min-width: 1.15rem; height: 1.15rem;
    padding: 0 .25rem;
    display: inline-flex; align-items: center; justify-content: center;
    border-radius: 999px;
    background: var(--alerte, #ef4444);
    color: #fff;
    font-size: .6rem; font-weight: 800;
    font-variant-numeric: tabular-nums;
    box-shadow: 0 1px 4px rgba(0,0,0,.35);
    pointer-events: none;
  }

  @media (prefers-reduced-motion: reduce) {
    .tuile { transition: none; }
    .tuile:active { transform: none; }
  }
</style>
<div class="tuile" part="tuile" role="button" tabindex="0">
  <span class="badge" hidden></span>
  <span class="favori" hidden>⭐</span>
  <span class="icone"></span>
  <span class="titre"></span>
  <span class="apercu"></span>
</div>`;

/**
 * Teinte de repli, dérivée du titre.
 *
 * Deux carlettes sans couleur déclarée doivent quand même se distinguer — un
 * damier monochrome ne se lit pas. On dérive donc une teinte STABLE du nom :
 * le même module garde sa couleur d'une session à l'autre, ce qu'un tirage au
 * hasard ne donnerait pas.
 */
function teinteDe(texte) {
  let h = 0;
  for (let i = 0; i < texte.length; i++) h = (h * 31 + texte.charCodeAt(i)) % 360;
  return `hsl(${h} 62% 52%)`;
}

export class SbxCarlette extends HTMLElement {
  static get observedAttributes() {
    return ['titre', 'icone', 'couleur', 'badge', 'favori', 'masque', 'apercu'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' }).appendChild(GABARIT.content.cloneNode(true));
    this._tuile = this.shadowRoot.querySelector('.tuile');
    this._minuterie = null;
  }

  connectedCallback() {
    const t = this._tuile;
    t.addEventListener('click', this.#ouvre);
    t.addEventListener('keydown', this.#touche);
    t.addEventListener('contextmenu', this.#menu);
    // APPUI LONG = OPTIONS, comme sur un vrai bureau mobile. On l'implémente à
    // la main : `contextmenu` n'est pas déclenché de façon fiable au toucher.
    t.addEventListener('pointerdown', this.#debutAppui);
    ['pointerup', 'pointercancel', 'pointerleave'].forEach(
      e => t.addEventListener(e, this.#finAppui));
    this.#peint();
  }

  disconnectedCallback() {
    this.#finAppui();
  }

  attributeChangedCallback() { this.#peint(); }

  // — interactions ————————————————————————————————————————————————

  #emet(nom) {
    this.dispatchEvent(new CustomEvent(nom, {
      bubbles: true, composed: true,
      detail: { id: this.id, titre: this.getAttribute('titre') || '' },
    }));
  }

  #ouvre = (ev) => {
    // Après un appui long, le `click` qui suit ne doit pas ouvrir en plus des
    // options — sinon un appui long ouvre le menu ET le lieu.
    if (this._longFait) { this._longFait = false; ev.preventDefault(); return; }
    this.#emet('ouvrir');
  };

  #touche = (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();          // Espace ferait défiler la page
      this.#emet('ouvrir');
    } else if (ev.key === 'ContextMenu') {
      ev.preventDefault();
      this.#emet('options');
    }
  };

  #menu = (ev) => { ev.preventDefault(); this.#emet('options'); };

  #debutAppui = () => {
    this._longFait = false;
    clearTimeout(this._minuterie);
    // 500 ms : au-delà l'attente se sent, en deçà un clic hésitant déclenche
    // le menu par erreur.
    this._minuterie = setTimeout(() => {
      this._longFait = true;
      if (navigator.vibrate) navigator.vibrate(12);  // le geste se confirme
      this.#emet('options');
    }, 500);
  };

  #finAppui = () => { clearTimeout(this._minuterie); };

  // — rendu ————————————————————————————————————————————————————

  #peint() {
    const r = this.shadowRoot;
    if (!r) return;
    const titre = this.getAttribute('titre') || '';
    const icone = this.getAttribute('icone') || '⬛';

    // textContent et jamais innerHTML : le titre vient du manifeste, donc du
    // réseau. Le traiter comme du texte est ce qui rend l'insertion sûre sans
    // avoir à échapper quoi que ce soit.
    r.querySelector('.titre').textContent = titre;
    r.querySelector('.icone').textContent = icone;
    this._tuile.setAttribute('aria-label', titre);

    const couleur = this.getAttribute('couleur');
    this._tuile.style.setProperty('--teinte',
      /^#[0-9a-f]{6}$/i.test(couleur || '') ? couleur : teinteDe(titre || 'sbx'));

    const fav = this.hasAttribute('favori');
    r.querySelector('.favori').hidden = !fav;

    // textContent et jamais innerHTML : l'aperçu vient d'un service, donc du
    // réseau. Un titre de morceau peut contenir n'importe quoi.
    r.querySelector('.apercu').textContent = this.getAttribute('apercu') || '';

    const n = parseInt(this.getAttribute('badge') || '0', 10);
    const badge = r.querySelector('.badge');
    badge.hidden = !(n > 0);
    if (n > 0) {
      badge.textContent = n > 99 ? '99+' : String(n);
      // Le badge doit s'ENTENDRE aussi : un lecteur d'écran ne voit pas la
      // pastille rouge.
      this._tuile.setAttribute('aria-label', `${titre}, ${n} non vu${n > 1 ? 's' : ''}`);
    }
  }
}

customElements.define('sbx-carlette', SbxCarlette);
