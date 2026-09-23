<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     LE SPECTRE, EN DEUX LECTURES : les barres disent l'instant, le
     spectrogramme dit les dernières secondes. L'un sans l'autre ne suffit pas —
     une voix se reconnaît à son mouvement, pas à un arrêt sur image. -->
<script lang="ts">
  let { bandes = [] as number[], voix = false, hauteur = 190 } = $props()

  let canevas: HTMLCanvasElement | undefined = $state()
  let cascade: HTMLCanvasElement | undefined = $state()

  // Le spectrogramme défile par COPIE DE SOI-MÊME décalée d'un pixel : garder
  // un historique de colonnes et tout redessiner coûterait cent fois plus cher
  // pour le même résultat. C'est la vieille astuce, et elle reste la bonne.
  function pousseColonne(vals: number[]) {
    if (!cascade) return
    const c = cascade.getContext('2d')
    if (!c) return
    const { width: L, height: H } = cascade
    c.drawImage(cascade, -1, 0)
    const pas = H / vals.length
    for (let i = 0; i < vals.length; i++) {
      const v = Math.max(0, Math.min(1, (vals[i] + 100) / 100))
      // Palette nuit → cyan → ambre : lisible, et le haut du spectre ne se
      // confond pas avec le fond quand il est faible.
      const r = v > .72 ? 255 * (v - .72) / .28 : 0
      const g = 229 * Math.pow(v, 1.6)
      const b = 255 * Math.pow(v, 1.1)
      c.fillStyle = `rgb(${r | 0},${g | 0},${b | 0})`
      c.fillRect(L - 1, H - (i + 1) * pas, 1, Math.ceil(pas))
    }
  }

  function dessineBarres(vals: number[]) {
    if (!canevas) return
    const c = canevas.getContext('2d')
    if (!c) return
    const { width: L, height: H } = canevas
    c.clearRect(0, 0, L, H)
    const largeur = L / vals.length
    for (let i = 0; i < vals.length; i++) {
      const v = Math.max(0, Math.min(1, (vals[i] + 100) / 100))
      const h = v * H
      const grad = c.createLinearGradient(0, H, 0, H - h)
      grad.addColorStop(0, voix ? 'rgba(70,229,255,.95)' : 'rgba(90,110,140,.7)')
      grad.addColorStop(1, voix ? 'rgba(159,244,255,.35)' : 'rgba(90,110,140,.15)')
      c.fillStyle = grad
      c.fillRect(i * largeur, H - h, Math.max(1, largeur - 1), h)
    }
  }

  // $effect suit `bandes` : on redessine quand une image arrive, pas sur une
  // boucle d'animation. Vingt images par seconde suffisent, et un
  // requestAnimationFrame à soixante redessinerait trois fois la même chose.
  $effect(() => {
    const v = bandes
    if (!v.length) return
    dessineBarres(v)
    pousseColonne(v)
  })

  // Les canevas sont dimensionnés en PIXELS RÉELS : sans cela, tout est flou
  // sur un écran à forte densité, et le spectrogramme bave au défilement.
  function ajuste(el: HTMLCanvasElement) {
    const r = () => {
      const d = window.devicePixelRatio || 1
      el.width = Math.max(1, el.clientWidth * d)
      el.height = Math.max(1, el.clientHeight * d)
    }
    r()
    const o = new ResizeObserver(r)
    o.observe(el)
    return { destroy: () => o.disconnect() }
  }
</script>

<div class="spectre" style="--h:{hauteur}px">
  <div class="etiquette dim mono">FFT · instant</div>
  <canvas bind:this={canevas} use:ajuste class="barres"></canvas>
  <div class="etiquette dim mono">Spectrogramme · 50 Hz → 8 kHz, échelle log</div>
  <canvas bind:this={cascade} use:ajuste class="cascade"></canvas>
</div>

<style>
  .spectre { display: grid; gap: 4px; }
  .etiquette { font-size: .68rem; letter-spacing: .08em; text-transform: uppercase; }
  canvas { width: 100%; display: block; border-radius: 14px; background: rgba(5,7,15,.6); }
  .barres  { height: calc(var(--h) * .52); }
  .cascade { height: calc(var(--h) * .48); }
</style>
