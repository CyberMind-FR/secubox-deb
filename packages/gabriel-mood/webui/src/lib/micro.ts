// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Le micro et le fil : capture locale, analyse sur la board.
//
// L'AUTORISATION N'EST DEMANDÉE QU'AU CLIC. Une page qui réclame le micro au
// chargement est une page qu'on referme — et elle le mérite.

export type Image = {
  timestamp: number; fft: number[]; pitch: number; energy: number
  calm: number; joy: number; stress: number; anger: number
  fatigue: number; focus: number
  state: string; motif?: string; reference?: string
  confidence: number; activation: number
  trends?: Record<string, number>
  vad: boolean; speech_rate: number; jitter: number; shimmer: number
  clarity: number; latency_ms: number; cpu: number
  calibration: number; observations?: number
  ambiance?: { bpm: number; pulsation: number; part: number; dominante: boolean; presente: boolean }
  source_reelle: boolean; reserve: string
}

export type Etat = 'arrete' | 'demande' | 'ecoute' | 'refuse' | 'erreur'

// LA CLÉ DE RÉFÉRENCE : fabriquée ICI, gardée ICI.
//
// Le serveur ne l'attribue pas — il ne peut donc pas relier deux visites
// autrement que par ce que ce navigateur lui présente. Effacer le stockage du
// navigateur suffit à redevenir inconnu, et le bouton « Oublier » efface aussi
// la ligne côté board.
//
// CE QU'ELLE PERMET, ET C'EST LE PRIX ASSUMÉ : deux visites qui présentent la
// même clé sont, par construction, reconnues comme la même personne. C'est ce
// qui évite de tout réapprendre à chaque rechargement.
const CLE_REF = 'gabriel-mood-ref'

export function cleReference(): string {
  try {
    const v = localStorage.getItem(CLE_REF)
    if (v && /^[0-9a-f]{16,64}$/.test(v)) return v
    const b = new Uint8Array(16)
    crypto.getRandomValues(b)
    const neuf = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
    localStorage.setItem(CLE_REF, neuf)
    return neuf
  } catch {
    // Stockage refusé (navigation privée, réglage strict) : on fonctionne
    // sans, simplement la référence ne survivra pas au rechargement.
    return ''
  }
}

export function oublieCleReference() {
  try { localStorage.removeItem(CLE_REF) } catch { /* rien à faire */ }
}

export class Micro {
  etat: Etat = 'arrete'
  motif = ''
  session = ''
  reprise = ''
  derniere: Image | null = null
  octetsEnvoyes = 0

  #ctx: AudioContext | null = null
  #flux: MediaStream | null = null
  #ws: WebSocket | null = null
  #surImage: (i: Image) => void
  #surEtat: (e: Etat, motif: string) => void

  constructor(surImage: (i: Image) => void, surEtat: (e: Etat, m: string) => void) {
    this.#surImage = surImage
    this.#surEtat = surEtat
  }

  #pose(e: Etat, motif = '') {
    this.etat = e; this.motif = motif; this.#surEtat(e, motif)
  }

  async demarre() {
    if (this.etat === 'ecoute' || this.etat === 'demande') return
    this.#pose('demande')
    try {
      // 48 kHz EXPLICITEMENT. Le serveur refuse tout autre échantillonnage
      // plutôt que de rééchantillonner en silence : un flux à 44,1 kHz lu
      // comme du 48 décalerait toutes les hauteurs de 8,8 %, soit presque un
      // demi-ton et demi, sans que rien ne le signale.
      this.#ctx = new AudioContext({ sampleRate: 48000 })
      if (this.#ctx.sampleRate !== 48000) {
        throw new Error(
          `ce navigateur impose ${this.#ctx.sampleRate} Hz ; le module attend 48 000 Hz`)
      }
      this.#flux = await navigator.mediaDevices.getUserMedia({
        audio: {
          // ON COUPE LES TRAITEMENTS DU NAVIGATEUR, et c'est essentiel : la
          // suppression de bruit et surtout le contrôle automatique de gain
          // modifient précisément ce qu'on mesure. Un AGC ramène toutes les
          // énergies au même niveau — l'indice d'activation, qui repose sur
          // l'énergie, deviendrait plat par construction.
          echoCancellation: false,
          noiseSuppression: false,
          autoGainControl: false,
          channelCount: 1,
        },
      })
      // RÉSOLU CONTRE LA PAGE, pas contre une racine supposée : le même
      // paquet est servi à la racine d'un vhost dédié ET sous un préfixe de
      // l'admin. Un chemin absolu aurait marché à un endroit sur deux.
      await this.#ctx.audioWorklet.addModule(
        new URL('capteur.js', document.baseURI).href)

      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      this.#ws = new WebSocket(`${proto}://${location.host}/ws/mood`)
      this.#ws.binaryType = 'arraybuffer'

      await new Promise<void>((ok, ko) => {
        this.#ws!.onopen = () => ok()
        this.#ws!.onerror = () => ko(new Error('la board ne répond pas'))
      })
      this.#ws.send(JSON.stringify({
        type: 'bonjour', sampleRate: 48000, ref: cleReference(),
      }))

      this.#ws.onmessage = (ev) => {
        if (typeof ev.data !== 'string') return
        const m = JSON.parse(ev.data)
        if (m.type === 'pret') { this.session = m.session; return }
        if (m.type === 'reprise') { this.reprise = m.motif || ''; return }
        if (m.type === 'refus') { this.arrete(); this.#pose('erreur', m.motif); return }
        this.derniere = m as Image
        this.#surImage(m as Image)
      }
      this.#ws.onclose = () => { if (this.etat === 'ecoute') this.#pose('arrete') }

      const src = this.#ctx.createMediaStreamSource(this.#flux)
      const nœud = new AudioWorkletNode(this.#ctx, 'capteur')
      nœud.port.onmessage = (ev: MessageEvent<ArrayBuffer>) => {
        if (this.#ws?.readyState === WebSocket.OPEN) {
          this.#ws.send(ev.data)
          this.octetsEnvoyes += ev.data.byteLength
        }
      }
      // Le worklet n'est PAS relié à la destination : on écoute pour analyser,
      // pas pour réémettre. Le relier renverrait la voix dans les haut-parleurs
      // et créerait une boucle, ce que personne n'attend d'un analyseur.
      src.connect(nœud)
      this.#pose('ecoute')
    } catch (e: any) {
      this.arrete()
      const refus = e?.name === 'NotAllowedError' || e?.name === 'SecurityError'
      this.#pose(refus ? 'refuse' : 'erreur', String(e?.message || e))
    }
  }

  arrete() {
    // ON COUPE LE MICRO POUR DE BON. Laisser la piste ouverte garderait la
    // pastille d'enregistrement allumée dans l'onglet : le navigateur dirait
    // vrai, et nous aurions menti.
    this.#flux?.getTracks().forEach((t) => t.stop())
    this.#flux = null
    this.#ws?.close(); this.#ws = null
    this.#ctx?.close(); this.#ctx = null
    if (this.etat === 'ecoute') this.#pose('arrete')
  }
}
