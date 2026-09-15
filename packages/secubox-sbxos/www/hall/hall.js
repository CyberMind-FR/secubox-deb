// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: L'ÉTAT DU HALL — ce que l'utilisateur a décidé (#1293).
 *
 * DEUX SOURCES, ET IL FAUT LES DISTINGUER SANS CESSE :
 *
 *   • LA MINE dit ce qui est DISPONIBLE. C'est la box qui décide, selon le
 *     profil. L'utilisateur ne peut pas s'accorder un module.
 *   • LE HALL dit ce qui est MONTRÉ, et comment. C'est l'utilisateur qui
 *     décide : l'ordre, les favoris, ce qu'il masque, son écran d'ouverture.
 *
 * Les mélanger produirait l'un ou l'autre des deux bugs classiques : soit un
 * module retiré par l'administrateur resterait affiché parce qu'il était dans
 * l'ordre mémorisé, soit les préférences de chacun sauteraient à chaque
 * régénération du manifeste. On les garde donc séparés, et c'est
 * `compose()` — et lui seul — qui les marie.
 *
 * TOUT VIT DANS LE NAVIGATEUR. Aucune préférence ne part vers la box : ce que
 * quelqu'un masque sur son téléphone ne regarde que son téléphone. C'est aussi
 * ce qui permet à deux appareils du même compte d'avoir deux dispositions.
 */

const CLE = 'sbxos.hall';

/** Écrans d'ouverture admis. « hall » est le défaut et le repli universel. */
export const ECRANS = ['hall', 'favoris', 'cinema', 'radio', 'billets', 'cloud'];

/** Thèmes admis. `auto` suit le réglage du système. */
export const THEMES = ['auto', 'clair', 'sombre'];

const VIDE = Object.freeze({
  ordre: [],        // ids, dans l'ordre voulu ; les absents suivent
  favoris: [],      // ids mis en avant
  masques: [],      // ids que l'utilisateur ne veut PAS voir
  ecran: 'hall',    // ce qui s'ouvre au lancement
  theme: 'auto',
});

/**
 * L'état du Hall. Émet `change` à chaque modification — c'est ce qui permet au
 * damier de se redessiner sans que personne n'ait à l'appeler.
 */
export class Hall extends EventTarget {
  constructor({ stockage = localStorage } = {}) {
    super();
    this.stockage = stockage;
    this.etat = this.#relire();
  }

  #relire() {
    try {
      const brut = JSON.parse(this.stockage.getItem(CLE) || 'null');
      if (!brut || typeof brut !== 'object') return { ...VIDE };
      const tab = (x) => (Array.isArray(x) ? x.filter(v => typeof v === 'string') : []);
      return {
        ordre: tab(brut.ordre),
        favoris: tab(brut.favoris),
        masques: tab(brut.masques),
        ecran: ECRANS.includes(brut.ecran) ? brut.ecran : 'hall',
        theme: THEMES.includes(brut.theme) ? brut.theme : 'auto',
      };
    } catch {
      // Stockage illisible : on repart d'un Hall par défaut plutôt que de
      // refuser de démarrer. Perdre des préférences est désagréable ; ne pas
      // ouvrir du tout est inacceptable.
      return { ...VIDE };
    }
  }

  #ecrit() {
    try {
      this.stockage.setItem(CLE, JSON.stringify(this.etat));
    } catch { /* quota ou navigation privée : l'état reste en mémoire */ }
    this.dispatchEvent(new CustomEvent('change', { detail: this.etat }));
  }

  // — Lecture ————————————————————————————————————————————————————

  estFavori(id) { return this.etat.favoris.includes(id); }
  estMasque(id) { return this.etat.masques.includes(id); }
  get ecran() { return this.etat.ecran; }
  get theme() { return this.etat.theme; }

  /**
   * COMPOSE LE DAMIER : marie ce que la Mine autorise avec ce que
   * l'utilisateur a rangé.
   *
   * Règles, dans cet ordre :
   *   1. on part des carlettes AUTORISÉES — rien d'autre n'entre jamais ;
   *   2. les favoris passent devant, dans leur ordre de mise en favori ;
   *   3. puis l'ordre personnalisé ;
   *   4. puis les nouvelles venues, dans l'ordre du manifeste — une carlette
   *      qu'on vient d'accorder doit APPARAÎTRE, pas se perdre en fin de liste
   *      parce qu'elle n'était pas dans l'ordre mémorisé.
   *
   * @param {Array} autorisees carlettes validées par la Mine
   * @param {{avecMasques?: boolean}} opts `avecMasques` pour l'écran de réglages
   */
  compose(autorisees, { avecMasques = false } = {}) {
    const parId = new Map(autorisees.map(c => [c.id, c]));
    const sortie = [];
    const pris = new Set();

    const pousse = (id) => {
      const c = parId.get(id);
      if (!c || pris.has(id)) return;
      if (!avecMasques && this.estMasque(id)) return;
      pris.add(id);
      sortie.push({ ...c, favori: this.estFavori(id), masque: this.estMasque(id) });
    };

    this.etat.favoris.forEach(pousse);
    this.etat.ordre.forEach(pousse);
    autorisees.forEach(c => pousse(c.id));   // les nouvelles, en dernier recours
    return sortie;
  }

  // — Écriture ————————————————————————————————————————————————————

  basculeFavori(id) {
    const i = this.etat.favoris.indexOf(id);
    if (i >= 0) this.etat.favoris.splice(i, 1);
    else {
      this.etat.favoris.push(id);
      // Mettre en favori quelque chose de masqué serait contradictoire : on
      // démasque, plutôt que de laisser un favori invisible.
      this.demasque(id, { silencieux: true });
    }
    this.#ecrit();
  }

  masque(id, { silencieux = false } = {}) {
    if (!this.etat.masques.includes(id)) this.etat.masques.push(id);
    const f = this.etat.favoris.indexOf(id);
    if (f >= 0) this.etat.favoris.splice(f, 1);
    if (!silencieux) this.#ecrit();
  }

  demasque(id, { silencieux = false } = {}) {
    const i = this.etat.masques.indexOf(id);
    if (i >= 0) this.etat.masques.splice(i, 1);
    if (!silencieux) this.#ecrit();
  }

  basculeMasque(id) {
    this.estMasque(id) ? this.demasque(id) : this.masque(id);
  }

  /**
   * Déplace `id` à la position `versIndex` de l'ordre COMPOSÉ.
   *
   * On réécrit l'ordre complet à partir de la liste affichée plutôt que de
   * bricoler l'ancien tableau : l'ordre mémorisé peut contenir des ids
   * disparus, et un décalage d'index sur une liste trouée range les vignettes
   * n'importe où — le genre de bug qu'on ne voit qu'après trois modules
   * retirés.
   */
  reordonne(idsAffiches, id, versIndex) {
    const liste = idsAffiches.filter(x => x !== id);
    const i = Math.max(0, Math.min(liste.length, versIndex));
    liste.splice(i, 0, id);
    // On conserve en queue les ids connus mais non affichés (masqués, ou
    // appartenant à un autre profil) : les perdre effacerait un rangement que
    // l'utilisateur retrouverait en démasquant.
    const vus = new Set(liste);
    this.etat.ordre = liste.concat(this.etat.ordre.filter(x => !vus.has(x)));
    this.#ecrit();
  }

  set ecran(v) {
    if (!ECRANS.includes(v)) return;
    this.etat.ecran = v;
    this.#ecrit();
  }

  set theme(v) {
    if (!THEMES.includes(v)) return;
    this.etat.theme = v;
    this.#ecrit();
  }

  /** Remet le Hall à neuf — sans toucher au manifeste, qui n'est pas à nous. */
  reinitialise() {
    this.etat = { ...VIDE };
    this.#ecrit();
  }
}

/**
 * Applique un thème au document.
 *
 * `auto` ne pose RIEN : c'est `prefers-color-scheme` qui tranche. Poser un
 * attribut « auto » obligerait la CSS à connaître trois états au lieu de deux,
 * pour un résultat identique.
 */
export function appliqueTheme(theme, racine = document.documentElement) {
  if (theme === 'clair' || theme === 'sombre') {
    racine.setAttribute('data-theme', theme === 'clair' ? 'light' : 'dark');
  } else {
    racine.removeAttribute('data-theme');
  }
}
