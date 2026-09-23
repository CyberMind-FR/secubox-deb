<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     LE COCKPIT. Dense, parce qu'il montre des mesures qui se lisent ensemble —
     une hauteur sans son débit ni son énergie ne dit rien. Mais la densité a
     un prix : plus une page a l'air instrumentée, plus on croit ce qu'elle
     affiche. D'où la bande de réserve, qui n'est jamais repliée, et l'état
     « indéterminé » traité comme une réponse normale et non comme une panne. -->
<script lang="ts">
  import FFTCanvas from './FFTCanvas.svelte'
  import EmojiGauge from './EmojiGauge.svelte'
  import { Micro, type Image, type Etat } from './src/lib/micro'
  import { Lien, type Role } from './src/lib/lien'

  let img: Image | null = $state(null)
  let etat: Etat = $state('arrete')
  let motif = $state('')
  let journal: string[] = $state([])
  let montreJSON = $state(false)
  let role: Role = $state('seul')

  // UNE SEULE CAPTURE, PLUSIEURS ÉCRANS. Si la carte du Hall tient déjà le
  // micro, ce cockpit la SUIT au lieu d'ouvrir une seconde session : deux
  // sessions, ce serait deux étalons apprenant la même voix chacun de son
  // côté, et deux lectures différentes de la même personne au même instant.
  const lien = new Lien(
    (i) => { img = i },
    (r) => { role = r },
  )

  const micro = new Micro(
    (i) => {
      img = i
      lien.diffuse(i)
      // Le flux JSON garde les vingt dernières images : au-delà, le DOM
      // grossit sans que personne ne relise le haut.
      journal = [JSON.stringify(abrege(i)), ...journal].slice(0, 20)
    },
    (e, m) => {
      etat = e; motif = m
      if (e === 'ecoute') lien.prendLaMain()
      else if (role === 'meneur') lien.rendLaMain()
    },
  )

  // On abrège la FFT dans le flux affiché : cent vingt-huit nombres par image,
  // vingt fois par seconde, rendraient le journal illisible ET coûteux à
  // rendre. Le reste est montré intégralement.
  function abrege(i: Image) {
    return { ...i, fft: `[${i.fft.length} bandes]` as unknown as number[] }
  }

  const carrelettes = $derived([
    { n: 'Pitch',   v: img?.pitch ? img.pitch.toFixed(1) : '—', u: 'Hz',
      d: img?.clarity ? `clarté ${(img.clarity * 100).toFixed(0)} %` : 'non voisé' },
    { n: 'Débit',   v: img?.speech_rate ? img.speech_rate.toFixed(0) : '—', u: 'syll/min',
      d: 'sommets d’énergie, pas des mots' },
    { n: 'Énergie', v: img ? (img.energy * 100).toFixed(1) : '—', u: '% RMS',
      d: img ? `jitter ${img.jitter.toFixed(2)} % · shimmer ${img.shimmer.toFixed(2)} dB` : '' },
    { n: 'Latence', v: img ? img.latency_ms.toFixed(0) : '—', u: 'ms',
      d: 'analyse + file d’attente' },
    { n: 'CPU',     v: img ? (img.cpu * 100).toFixed(1) : '—', u: '% cœur',
      d: 'mesuré, pas estimé' },
    { n: 'VAD',     v: img?.vad ? 'voix' : 'silence', u: '',
      d: img?.vad ? 'trame retenue pour l’analyse' : 'trame écartée' },
  ])

  async function oublie() {
    if (!confirm('Effacer tout l’historique conservé sur la board ?')) return
    await fetch('/api/mood/oubli', { method: 'POST' })
    journal = []
  }
</script>

<div class="cockpit">
  <!-- ── BANDEAU ───────────────────────────────────────────────────────── -->
  <header class="verre bandeau">
    <div class="marque">
      <span class="logo">◆</span>
      <div>
        <div class="titre">Gabriel Mood</div>
        <div class="dim petit">indices prosodiques · analyse locale</div>
      </div>
    </div>

    <div class="live" class:actif={etat === 'ecoute' || role === 'suiveur'}>
      <span class="pastille" class:pouls={(etat === 'ecoute' || role === 'suiveur') && img?.vad}></span>
      <span class="mono">{etat === 'ecoute' ? 'LIVE' : role === 'suiveur' ? 'SYNCHRONISÉ' : 'HORS LIGNE'}</span>
    </div>

    <div class="actions">
      {#if etat === 'ecoute'}
        <button onclick={() => micro.arrete()}>⏹ Arrêter</button>
      {:else if role === 'suiveur'}
        <span class="dim petit">🎙 une autre vue tient le micro — affichage synchronisé</span>
      {:else}
        <button class="primaire" onclick={() => micro.demarre()}
                disabled={etat === 'demande'}>
          {etat === 'demande' ? '…' : '🎙 Écouter'}
        </button>
      {/if}
      <button class="danger" onclick={oublie} title="Efface l’historique conservé">
        🧹 Oublier
      </button>
    </div>
  </header>

  <!-- LA RÉSERVE N'EST NI REPLIABLE NI DISCRÈTE. Elle est la première chose
       sous le bandeau, parce qu'un cockwatch qui clignote est TRÈS convaincant
       et que c'est précisément le problème. -->
  <div class="reserve">
    <strong>Ce module ne lit pas les émotions.</strong>
    Il mesure une hauteur, une énergie, un débit, une irrégularité — et n'en
    tire que des <em>indices</em>, relatifs à votre propre voix, à cette pièce
    et à ce moment. L'activation (posé ↔ activé) est le seul axe
    acoustiquement solide ; tout le reste est une tendance faible.
    À n'utiliser ni pour évaluer quelqu'un, ni pour décider quoi que ce soit
    le concernant.
  </div>

  {#if etat === 'refuse'}
    <div class="avis">🎙 Le micro a été refusé. Rien ne peut être analysé — et
      c'est votre droit le plus strict. Le bouton reste là si vous changez d'avis.</div>
  {:else if etat === 'erreur'}
    <div class="avis erreur">⚠ {motif}</div>
  {:else if img && !img.source_reelle}
    <div class="avis erreur">⚠ VOIX FABRIQUÉE — démonstration. Rien de ce qui
      s'affiche ne vient de quelqu'un.</div>
  {/if}

  {#if etat === 'ecoute' && img && img.calibration < 1}
    <div class="avis">
      Étalonnage {Math.round(img.calibration * 100)} % — le module apprend
      <em>votre</em> ordinaire. Tant qu'il ne le connaît pas, un écart ne veut
      rien dire, et aucun état n'est affirmé. Comptez quelques minutes de parole.
      <div class="jauge-cal"><i style="width:{img.calibration * 100}%"></i></div>
    </div>
  {/if}

  <!-- ── CORPS ─────────────────────────────────────────────────────────── -->
  <main class="grille">
    <section class="verre bloc humeur">
      <h2>Lecture</h2>
      <EmojiGauge
        etat={img?.state ?? 'indetermine'}
        confiance={img?.confidence ?? 0}
        activation={img?.activation ?? 0}
        etalonnage={img?.calibration ?? 0}
        indices={{
          calm: img?.calm ?? 0, joy: img?.joy ?? 0, stress: img?.stress ?? 0,
          anger: img?.anger ?? 0, fatigue: img?.fatigue ?? 0, focus: img?.focus ?? 0,
        }} />
    </section>

    <section class="verre bloc spectre">
      <h2>Spectre</h2>
      <FFTCanvas bandes={img?.fft ?? []} voix={img?.vad ?? false} />
    </section>

    <section class="carrelettes">
      {#each carrelettes as c}
        <div class="verre carrelette">
          <div class="dim petit etiq">{c.n}</div>
          <div class="chiffre mono">{c.v}<span class="unite dim">{c.u}</span></div>
          <div class="dim minuscule">{c.d}</div>
        </div>
      {/each}
    </section>

    <section class="verre bloc flux">
      <h2>
        Flux JSON
        <button class="mini" onclick={() => (montreJSON = !montreJSON)}>
          {montreJSON ? 'masquer' : 'afficher'}
        </button>
      </h2>
      {#if montreJSON}
        <pre class="mono journal">{journal.join('\n')}</pre>
      {:else}
        <p class="dim petit">Les vingt dernières images, telles qu'elles
          arrivent. C'est ce que reçoit l'interface — rien de plus, rien de moins.</p>
      {/if}
    </section>
  </main>

  <footer class="dim minuscule pied">
    Aucun échantillon audio n'est écrit sur le disque. Le son traverse le réseau
    local, est analysé sur la board, et disparaît. Seuls des agrégats par minute
    sont conservés, et « Oublier » les efface.
  </footer>
</div>

<style>
  .cockpit { max-width: 1240px; margin: 0 auto; padding: 18px 16px 40px;
    display: grid; gap: 14px; }

  .bandeau { display: grid; grid-template-columns: 1fr auto auto; gap: 16px;
    align-items: center; padding: 14px 18px; }
  .marque { display: flex; align-items: center; gap: 12px; }
  .logo { font-size: 1.6rem; color: var(--cyan); text-shadow: 0 0 18px rgba(70,229,255,.6); }
  .titre { font-size: 1.15rem; font-weight: 650; letter-spacing: .015em; }
  .petit { font-size: .74rem; }
  .minuscule { font-size: .68rem; }

  .live { display: flex; align-items: center; gap: 8px; font-size: .76rem;
    letter-spacing: .12em; color: var(--encre-2); }
  .live.actif { color: var(--rouge); }
  .pastille { width: 9px; height: 9px; border-radius: 50%; background: #3a4a63; }
  .live.actif .pastille { background: var(--rouge); box-shadow: 0 0 12px var(--rouge); }
  .actions { display: flex; gap: 8px; }

  .reserve { border-radius: var(--r); padding: 11px 15px; font-size: .79rem;
    line-height: 1.5; color: #ffe3b0;
    background: rgba(255,194,77,.07); border: 1px solid rgba(255,194,77,.26); }
  .reserve strong { color: var(--ambre); }

  .avis { border-radius: var(--r); padding: 10px 14px; font-size: .79rem;
    background: rgba(70,229,255,.07); border: 1px solid var(--bord); }
  .avis.erreur { background: rgba(255,107,122,.09); border-color: rgba(255,107,122,.32); }
  .jauge-cal { height: 4px; margin-top: 8px; border-radius: 999px;
    background: rgba(255,255,255,.08); overflow: hidden; }
  .jauge-cal i { display: block; height: 100%; background: var(--cyan);
    transition: width .5s ease; }

  .grille { display: grid; gap: 14px;
    grid-template-columns: minmax(280px, 340px) 1fr;
    grid-template-areas: "humeur spectre" "carrelettes carrelettes" "flux flux"; }
  .humeur { grid-area: humeur; }
  .spectre { grid-area: spectre; }
  .carrelettes { grid-area: carrelettes; display: grid; gap: 10px;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
  .flux { grid-area: flux; }
  @media (max-width: 860px) {
    .grille { grid-template-columns: 1fr;
      grid-template-areas: "humeur" "spectre" "carrelettes" "flux"; }
    .bandeau { grid-template-columns: 1fr; justify-items: start; }
  }

  .bloc { padding: 15px 17px; }
  h2 { margin: 0 0 12px; font-size: .74rem; letter-spacing: .13em;
    text-transform: uppercase; color: var(--encre-2); font-weight: 600;
    display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .mini { padding: .18rem .6rem; font-size: .68rem; border-radius: 10px;
    text-transform: none; letter-spacing: 0; }

  .carrelette { padding: 12px 14px; display: grid; gap: 3px; border-radius: var(--r); }
  .etiq { letter-spacing: .1em; text-transform: uppercase; }
  .chiffre { font-size: 1.5rem; font-weight: 600; color: var(--cyan-b); }
  .unite { font-size: .72rem; margin-left: .3rem; font-weight: 400; }

  /* Le flux défile dans SON conteneur : la page ne doit jamais partir en
     largeur à cause d'une ligne JSON un peu longue. */
  .journal { margin: 0; max-height: 240px; overflow: auto; font-size: .68rem;
    line-height: 1.55; color: var(--encre-2); white-space: pre; }
  .pied { text-align: center; padding-top: 6px; }
</style>
