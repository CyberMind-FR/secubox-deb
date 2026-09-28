<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     LES SIX INDICES DANS LE TEMPS, sur un seul axe.
     Une photographie ne dit pas si le calme monte ou s'effondre ; six courbes
     le disent d'un coup d'œil. Les émoticônes sont posées à DROITE, à la
     hauteur de leur courbe : c'est là que se trouve la valeur du moment, donc
     là qu'on les cherche, et ça évite une légende qu'il faudrait relire.

     ON NE TRACE PAS LES REFUS. Quand le module dit « bruit » ou « pas assez de
     voix », il n'y a pas de lecture : y mettre des zéros ferait plonger les six
     courbes à chaque silence, et l'on croirait à un effondrement là où il n'y
     avait personne qui parlait. Le trait s'interrompt, et c'est la vérité. -->
<script lang="ts">
  import type { Image } from './src/lib/micro'

  let { image = null as Image | null, secondes = 90, hauteur = 190 } = $props()

  type Point = { t: number; v: Record<string, number> | null }
  const ETATS = ['calm', 'joy', 'stress', 'anger', 'fatigue', 'focus'] as const
  const EMOJI: Record<string, string> = {
    calm: '😌', joy: '😊', stress: '😬', anger: '😠', fatigue: '😴', focus: '🤔',
  }
  const NOM: Record<string, string> = {
    calm: 'Calme', joy: 'Joie', stress: 'Tension', anger: 'Colère',
    fatigue: 'Fatigue', focus: 'Concentration',
  }
  const TEINTE: Record<string, string> = {
    calm: '#5cf0a8', joy: '#ffd45e', stress: '#ff9f4d',
    anger: '#ff6b7a', fatigue: '#9a8cff', focus: '#46e5ff',
  }

  let points: Point[] = $state([])
  let canevas: HTMLCanvasElement | undefined = $state()
  let survol: number | null = $state(null)

  // À vingt images par seconde, quatre-vingt-dix secondes feraient mille huit
  // cents points pour quelques centaines de pixels. On n'en garde qu'un par
  // demi-seconde : au-delà, on redessine des points qui tombent sur le même
  // pixel — du calcul pur, invisible à l'écran.
  const PAS_MS = 500
  let dernierPris = 0

  $effect(() => {
    const img = image
    if (!img) return
    const t = img.timestamp
    if (t - dernierPris < PAS_MS) return
    dernierPris = t
    const refus = img.state === 'indetermine'
    points = [...points, {
      t,
      v: refus ? null : {
        calm: img.calm, joy: img.joy, stress: img.stress,
        anger: img.anger, fatigue: img.fatigue, focus: img.focus,
      },
    }].slice(-Math.ceil((secondes * 1000) / PAS_MS))
  })

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

  const MARGE_D = 34 // place pour les émoticônes, en pixels CSS

  $effect(() => {
    const pts = points
    if (!canevas) return
    const c = canevas.getContext('2d')
    if (!c) return
    const d = window.devicePixelRatio || 1
    const L = canevas.width, H = canevas.height
    const droite = MARGE_D * d
    const large = Math.max(1, L - droite)
    c.clearRect(0, 0, L, H)

    // Grille : 0, 25, 50, 75, 100 %. Discrète — elle sert à situer, pas à lire.
    c.strokeStyle = 'rgba(255,255,255,.06)'
    c.lineWidth = 1 * d
    c.font = `${9 * d}px ui-monospace, monospace`
    c.fillStyle = 'rgba(159,179,204,.55)'
    for (let g = 0; g <= 4; g++) {
      const y = H - (g / 4) * H
      c.beginPath(); c.moveTo(0, y); c.lineTo(large, y); c.stroke()
      if (g > 0 && g < 4) c.fillText(`${g * 25}%`, 3 * d, y - 3 * d)
    }
    if (pts.length < 2) {
      c.fillStyle = 'rgba(159,179,204,.5)'
      c.font = `${11 * d}px system-ui, sans-serif`
      c.fillText('en attente de lectures…', 8 * d, H / 2)
      return
    }

    const x = (i: number) => (i / (pts.length - 1)) * large
    for (const k of ETATS) {
      c.strokeStyle = TEINTE[k]
      c.lineWidth = (k === image?.state ? 2.4 : 1.3) * d
      c.globalAlpha = k === image?.state ? 1 : 0.62
      c.beginPath()
      let leve = true
      pts.forEach((p, i) => {
        // TRAIT INTERROMPU sur un refus : on ne relie pas deux mesures
        // séparées par un trou, ce serait inventer ce qui s'est passé entre.
        if (!p.v) { leve = true; return }
        const y = H - p.v[k] * H
        if (leve) { c.moveTo(x(i), y); leve = false } else { c.lineTo(x(i), y) }
      })
      c.stroke()

      // L'émoticône à hauteur de sa courbe, sur la marge de droite.
      const dernier = [...pts].reverse().find((p) => p.v)
      if (dernier?.v) {
        const y = H - dernier.v[k] * H
        c.globalAlpha = 1
        c.font = `${13 * d}px system-ui, "Segoe UI Emoji", sans-serif`
        c.fillText(EMOJI[k], large + 7 * d, y + 5 * d)
      }
    }
    c.globalAlpha = 1
  })

  const derniere = $derived(points.filter((p) => p.v).at(-1)?.v ?? null)
  function fleche(k: string) {
    const t = image?.trends?.[k]
    if (t === undefined || Math.abs(t) < 0.02) return '→'
    return t > 0 ? '↗' : '↘'
  }
</script>

<div class="tend">
  <canvas bind:this={canevas} use:ajuste style="height:{hauteur}px"></canvas>

  <!-- LA LÉGENDE PORTE LES POURCENTAGES ET LES PENTES. C'est elle qu'on lit
       quand on veut un chiffre ; la courbe sert à voir le mouvement. -->
  <ul class="legende">
    {#each ETATS as k}
      <li class:tete={k === image?.state}
          onmouseenter={() => (survol = ETATS.indexOf(k))}
          onmouseleave={() => (survol = null)}>
        <span class="pastille" style="background:{TEINTE[k]}"></span>
        <span class="e">{EMOJI[k]}</span>
        <span class="n">{NOM[k]}</span>
        <span class="v mono">{derniere ? Math.round(derniere[k] * 100) + ' %' : '—'}</span>
        <span class="p mono" class:monte={(image?.trends?.[k] ?? 0) > 0.02}
              class:baisse={(image?.trends?.[k] ?? 0) < -0.02}>{fleche(k)}</span>
      </li>
    {/each}
  </ul>
</div>

<style>
  .tend { display: grid; gap: 8px; }
  canvas { width: 100%; display: block; border-radius: 14px; background: rgba(5,7,15,.55); }
  .legende { list-style: none; margin: 0; padding: 0; display: grid; gap: 3px;
    grid-template-columns: repeat(auto-fit, minmax(168px, 1fr)); }
  .legende li { display: grid; grid-template-columns: 7px 1.1rem 1fr auto 1rem;
    align-items: center; gap: 6px; font-size: .74rem; padding: 2px 5px;
    border-radius: 8px; }
  .legende li.tete { background: rgba(70,229,255,.07); font-weight: 600; }
  .pastille { width: 7px; height: 7px; border-radius: 50%; }
  .n { color: var(--encre-2); overflow: hidden; text-overflow: ellipsis; }
  .legende li.tete .n { color: var(--encre); }
  .v { text-align: right; }
  .p { text-align: center; color: var(--encre-2); }
  .p.monte { color: #5cf0a8; }
  .p.baisse { color: #ff9f4d; }
</style>
