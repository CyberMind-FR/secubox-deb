// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SBX OS :: LA MINE DES APPS — d'où vient le bureau (#1293).
 *
 * LE PRINCIPE. La PWA ne sait pas, à l'installation, ce qu'elle aura à montrer.
 * Elle charge un MANIFESTE, et c'est lui qui décide : quelles carlettes, dans
 * quel ordre, avec quels droits. Deux personnes installent la même application
 * et n'obtiennent pas le même bureau — c'est le profil qui fait la différence,
 * pas une réinstallation.
 *
 * POURQUOI CE N'EST PAS UN DÉTAIL D'IMPLÉMENTATION. Un visiteur qui demande une
 * invitation et l'obtient doit voir son Hall s'ouvrir SANS RIEN RÉINSTALLER. Si
 * la liste des modules était codée dans l'application, il faudrait publier une
 * nouvelle version à chaque changement de droits. En la chargeant, on la rend
 * vivante : la Mine change d'avis, la PWA suit.
 *
 * V1 — AUCUN BACKEND. Le manifeste est un fichier servi à côté de l'app, et les
 * profils sont simulés dans le navigateur. Le parcours complet est jouable, y
 * compris l'invitation ; ce qui manque est la contrepartie serveur, pas la
 * mécanique. Le contrat de données ci-dessous est déjà celui que la V2 servira.
 *
 * CE QU'ON NE FAIT JAMAIS, MÊME EN V1 : faire confiance au manifeste sans le
 * valider. Un manifeste est une donnée distante ; s'il arrivait un jour d'une
 * origine compromise, il ne doit pas pouvoir injecter n'importe quoi dans le
 * DOM ni ouvrir n'importe quelle URL. D'où `valide()`, appliqué à chaque champ.
 */

/** Profils reconnus, du moins au plus doté. L'ordre COMPTE : il sert à comparer. */
export const PROFILS = ['guest', 'user', 'admin'];

/** Où la Mine cherche le manifeste, par défaut. Surchargée par `Mine.source`. */
const SOURCE_DEFAUT = './mine/manifeste.json';

/** Clés de stockage local. Préfixées pour ne pas heurter un autre outil. */
const CLE_MANIFESTE = 'sbxos.manifeste';
const CLE_PROFIL = 'sbxos.profil';

/**
 * Formes admises. Une carlette dont un champ sort de ces bornes est ÉCARTÉE —
 * on préfère un bureau incomplet à un bureau qui exécute n'importe quoi.
 */
const RE_ID = /^[a-z][a-z0-9_-]{0,31}$/;
const RE_ICONE = /^[\p{Emoji}\p{Emoji_Presentation}‍️]{1,4}$/u;
const SCHEMES_ADMIS = new Set(['https:', 'http:']);

/** Un avertissement de validation : ce qu'on a écarté, et pourquoi. */
export class Grief {
  constructor(champ, valeur, raison) {
    this.champ = champ;
    this.valeur = valeur;
    this.raison = raison;
  }
  toString() {
    return `${this.champ} = ${JSON.stringify(this.valeur)} — ${this.raison}`;
  }
}

/**
 * Valide UNE carlette. Rend la carlette nettoyée, ou `null` si elle est
 * irrécupérable. Les griefs sont poussés dans `griefs` plutôt que levés : un
 * module mal formé ne doit pas faire disparaître les onze autres.
 */
export function valideCarlette(brut, griefs = []) {
  if (!brut || typeof brut !== 'object') {
    griefs.push(new Grief('carlette', brut, 'ce n’est pas un objet'));
    return null;
  }
  const id = String(brut.id ?? '');
  if (!RE_ID.test(id)) {
    griefs.push(new Grief('id', brut.id, 'identifiant hors format'));
    return null;
  }
  const titre = String(brut.titre ?? '').trim();
  if (!titre || titre.length > 40) {
    griefs.push(new Grief('titre', brut.titre, 'titre vide ou trop long'));
    return null;
  }

  // L'ICÔNE EST UN EMOJI, PAS DU BALISAGE. C'est ce qui permet de l'insérer
  // comme du texte sans jamais passer par innerHTML.
  let icone = String(brut.icone ?? '').trim();
  if (!RE_ICONE.test(icone)) {
    griefs.push(new Grief('icone', brut.icone, 'icône non emoji — remplacée'));
    icone = '⬛';
  }

  // L'URL est la partie la plus sensible : c'est elle qu'on ouvrira.
  let url = null;
  if (brut.url != null) {
    try {
      const u = new URL(String(brut.url), location.href);
      if (!SCHEMES_ADMIS.has(u.protocol)) {
        griefs.push(new Grief('url', brut.url, `schéma refusé (${u.protocol})`));
      } else {
        url = u.href;
      }
    } catch {
      griefs.push(new Grief('url', brut.url, 'URL illisible'));
    }
  }

  const theatre = String(brut.theatre ?? '').trim();
  const profilMin = PROFILS.includes(brut.profil_min) ? brut.profil_min : 'guest';

  return {
    id,
    titre,
    icone,
    url,
    // Le théâtre est le LIEU qu'ouvre la carlette. Vide = simple lien.
    theatre: RE_ID.test(theatre) ? theatre : '',
    profil_min: profilMin,
    couleur: /^#[0-9a-f]{6}$/i.test(String(brut.couleur ?? '')) ? brut.couleur : null,
    description: String(brut.description ?? '').slice(0, 160),
  };
}

/**
 * Valide un manifeste complet.
 * @returns {{profil: string, carlettes: Array, griefs: Grief[], version: number}}
 */
export function valideManifeste(brut) {
  const griefs = [];
  const doc = brut && typeof brut === 'object' ? brut : {};
  const profil = PROFILS.includes(doc.profil) ? doc.profil : 'guest';
  if (doc.profil && !PROFILS.includes(doc.profil)) {
    griefs.push(new Grief('profil', doc.profil, 'profil inconnu — guest appliqué'));
  }
  const liste = Array.isArray(doc.carlettes) ? doc.carlettes : [];
  if (!Array.isArray(doc.carlettes)) {
    griefs.push(new Grief('carlettes', doc.carlettes, 'liste absente'));
  }
  const vues = new Set();
  const carlettes = [];
  for (const c of liste) {
    const ok = valideCarlette(c, griefs);
    if (!ok) continue;
    if (vues.has(ok.id)) {
      griefs.push(new Grief('id', ok.id, 'doublon — seule la première est gardée'));
      continue;
    }
    vues.add(ok.id);
    carlettes.push(ok);
  }
  return {
    profil,
    carlettes,
    griefs,
    version: Number.isFinite(doc.version) ? doc.version : 1,
    nom: String(doc.nom ?? 'SBX OS').slice(0, 40),
    // Le manifeste peut annoncer que l'invitation est en attente : c'est ce qui
    // permet à la PWA de re-sonder toute seule au lieu d'exiger un geste.
    invitation: doc.invitation === 'en_attente' ? 'en_attente'
      : doc.invitation === 'accordee' ? 'accordee' : null,
  };
}

/** `a` est-il au moins aussi doté que `b` ? */
export function profilSuffit(a, b) {
  return PROFILS.indexOf(a) >= PROFILS.indexOf(b);
}

/**
 * LA MINE. Charge, valide, mémorise — et prévient quand le bureau change.
 *
 * Elle garde le DERNIER manifeste valide en stockage local : c'est ce qui rend
 * l'ouverture hors ligne possible, et instantanée même en ligne (on affiche le
 * connu, puis on rafraîchit).
 */
export class Mine extends EventTarget {
  constructor({ source = SOURCE_DEFAUT, stockage = localStorage } = {}) {
    super();
    this.source = source;
    this.stockage = stockage;
    this.manifeste = this.#relire();
    this._sondage = null;
  }

  #relire() {
    try {
      const brut = this.stockage.getItem(CLE_MANIFESTE);
      return brut ? valideManifeste(JSON.parse(brut)) : null;
    } catch {
      // Un stockage illisible (navigation privée, quota, données corrompues)
      // ne doit pas empêcher l'application de démarrer.
      return null;
    }
  }

  #memorise(m) {
    try {
      this.stockage.setItem(CLE_MANIFESTE, JSON.stringify({
        profil: m.profil, carlettes: m.carlettes, version: m.version,
        nom: m.nom, invitation: m.invitation,
      }));
      this.stockage.setItem(CLE_PROFIL, m.profil);
    } catch { /* stockage indisponible : on continue sans mémoire */ }
  }

  get profil() {
    return this.manifeste?.profil ?? 'guest';
  }

  /** Les carlettes que CE profil a le droit de voir. */
  carlettesAutorisees() {
    const p = this.profil;
    return (this.manifeste?.carlettes ?? []).filter(c => profilSuffit(p, c.profil_min));
  }

  /**
   * Va chercher le manifeste. Rend `true` si le bureau a CHANGÉ — c'est cette
   * réponse, et non le simple succès du chargement, qui doit décider d'un
   * réaffichage : re-dessiner un damier identique fait clignoter l'écran pour
   * rien.
   */
  async charge({ signal } = {}) {
    const rep = await fetch(this.source, {
      signal, cache: 'no-cache', credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (!rep.ok) throw new Error(`manifeste : HTTP ${rep.status}`);
    const m = valideManifeste(await rep.json());

    const avant = JSON.stringify(this.manifeste?.carlettes ?? null) + '|' + (this.manifeste?.profil ?? '');
    const apres = JSON.stringify(m.carlettes) + '|' + m.profil;
    const change = avant !== apres;

    this.manifeste = m;
    this.#memorise(m);
    if (m.griefs.length) {
      this.dispatchEvent(new CustomEvent('griefs', { detail: m.griefs }));
    }
    this.dispatchEvent(new CustomEvent('charge', { detail: { manifeste: m, change } }));
    if (change) this.dispatchEvent(new CustomEvent('change', { detail: m }));
    return change;
  }

  /**
   * SONDAGE D'INVITATION. Tant que l'invitation est en attente, on re-demande
   * le manifeste à intervalle régulier : le jour où l'administrateur valide, le
   * Hall s'ouvre tout seul. C'est la promesse « aucune réinstallation ».
   *
   * L'intervalle croît à chaque essai (jusqu'à un plafond) : une PWA laissée
   * ouverte une nuit ne doit pas marteler la box toutes les dix secondes.
   */
  sondeInvitation({ depart = 10000, plafond = 120000 } = {}) {
    this.arreteSondage();
    let delai = depart;
    const tour = async () => {
      try {
        await this.charge();
        if (this.manifeste?.invitation !== 'en_attente') {
          this.arreteSondage();
          this.dispatchEvent(new CustomEvent('invitation', { detail: this.manifeste }));
          return;
        }
      } catch { /* hors ligne : on retentera, sans bruit */ }
      delai = Math.min(plafond, Math.round(delai * 1.6));
      this._sondage = setTimeout(tour, delai);
    };
    this._sondage = setTimeout(tour, delai);
  }

  arreteSondage() {
    if (this._sondage) { clearTimeout(this._sondage); this._sondage = null; }
  }
}
