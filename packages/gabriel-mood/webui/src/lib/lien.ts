// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// LE LIEN ENTRE LES VUES : une capture, plusieurs écrans.
//
// LE PROBLÈME QU'IL RÉSOUT N'EST PAS COSMÉTIQUE. La carte du Hall (`/micro`)
// et le cockpit (`/mega`) sont deux documents. Si chacun ouvrait sa WebSocket,
// il y aurait DEUX sessions — donc deux étalons distincts, chacun apprenant la
// même voix de son côté, et deux lectures différentes de la même personne au
// même instant. C'est exactement l'incohérence qu'on ne peut pas expliquer à
// l'écran.
//
// Et il y aurait DEUX captures du micro, donc deux fois le débit réseau et
// deux fois le calcul sur la board, pour une seule voix.
//
// DONC : UN SEUL MENEUR. Celui où l'on a cliqué « écouter » tient le micro et
// la WebSocket, et rediffuse chaque image. Les autres vues SUIVENT — elles
// n'ouvrent rien et se contentent d'afficher. `BroadcastChannel` porte cela
// entre documents de MÊME ORIGINE, ce que sont la carte et le cockpit dès lors
// qu'ils sont servis par le même vhost.
//
// SI LE MENEUR DISPARAÎT (onglet fermé, iframe retirée), les suiveurs cessent
// de recevoir. On le DIT au bout de deux secondes plutôt que de laisser à
// l'écran une dernière image figée qui passerait pour une mesure en cours.

import type { Image } from './micro'

export type Role = 'seul' | 'meneur' | 'suiveur'

type Trame =
  | { t: 'image'; img: Image }
  | { t: 'bonjour' }            // « qui mène ? »
  | { t: 'jemene' }             // « moi »
  | { t: 'jarrete' }

const CANAL = 'gabriel-mood'
const SILENCE_MAX = 2000

export class Lien {
  role: Role = 'seul'
  #canal: BroadcastChannel | null = null
  #dernier = 0
  #minuteur: number | undefined
  #surImage: (i: Image) => void
  #surRole: (r: Role) => void

  constructor(surImage: (i: Image) => void, surRole: (r: Role) => void) {
    this.#surImage = surImage
    this.#surRole = surRole
    // BroadcastChannel manque encore par endroits (et dans certains contextes
    // restreints). Son absence ne doit pas empêcher la vue de fonctionner
    // SEULE — elle empêche seulement la synchronisation.
    try {
      this.#canal = new BroadcastChannel(CANAL)
    } catch {
      this.#canal = null
      return
    }
    this.#canal.onmessage = (ev: MessageEvent<Trame>) => this.#recoit(ev.data)
    // On demande qui mène. Silence = personne : on reste « seul », prêt à
    // prendre le micro si on nous le demande.
    this.#canal.postMessage({ t: 'bonjour' } satisfies Trame)
  }

  #pose(r: Role) {
    if (this.role === r) return
    this.role = r
    this.#surRole(r)
  }

  #recoit(m: Trame) {
    switch (m.t) {
      case 'bonjour':
        // Quelqu'un arrive : s'il y a un meneur, il se signale.
        if (this.role === 'meneur') this.#canal?.postMessage({ t: 'jemene' } satisfies Trame)
        break
      case 'jemene':
        if (this.role !== 'meneur') this.#pose('suiveur')
        break
      case 'jarrete':
        if (this.role === 'suiveur') this.#pose('seul')
        break
      case 'image':
        if (this.role === 'meneur') return // notre propre écho, ignoré
        this.#pose('suiveur')
        this.#dernier = Date.now()
        this.#surImage(m.img)
        this.#veille()
        break
    }
  }

  // Le meneur peut disparaître sans prévenir — un onglet qu'on ferme n'envoie
  // rien. On surveille donc le SILENCE, plutôt que d'attendre un adieu poli.
  #veille() {
    clearTimeout(this.#minuteur)
    this.#minuteur = window.setTimeout(() => {
      if (this.role === 'suiveur' && Date.now() - this.#dernier >= SILENCE_MAX) {
        this.#pose('seul')
      }
    }, SILENCE_MAX + 200)
  }

  /** À appeler quand CETTE vue prend le micro. */
  prendLaMain() {
    this.#pose('meneur')
    this.#canal?.postMessage({ t: 'jemene' } satisfies Trame)
  }

  /** À appeler quand cette vue rend le micro. */
  rendLaMain() {
    if (this.role === 'meneur') this.#canal?.postMessage({ t: 'jarrete' } satisfies Trame)
    this.#pose('seul')
  }

  /** Rediffuse une image aux autres vues (meneur seulement). */
  diffuse(img: Image) {
    if (this.role !== 'meneur') return
    this.#canal?.postMessage({ t: 'image', img } satisfies Trame)
  }

  ferme() {
    this.rendLaMain()
    clearTimeout(this.#minuteur)
    this.#canal?.close()
    this.#canal = null
  }
}
