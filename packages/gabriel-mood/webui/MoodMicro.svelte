<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     LA VUE /micro : la carte du Hall.
     Elle tient dans une tuile, donc elle doit choisir. Ce qu'elle garde —
     l'emoji, l'axe d'activation, un spectre, l'état du micro — et surtout ce
     qu'elle ne perd pas : la réserve. Une carte d'humeur dans une grille de
     services est encore plus exposée au malentendu qu'un cockpit, parce qu'on
     la lit d'un coup d'œil et sans contexte.

     ELLE NE PREND JAMAIS LE MICRO TOUTE SEULE. Une tuile qui se met à écouter
     parce qu'on a ouvert le Hall serait une trahison, même techniquement
     autorisée. Il faut un clic, ici comme ailleurs. -->
<script lang="ts">
  import { Micro, type Image, type Etat } from './src/lib/micro'
  import { Lien, type Role } from './src/lib/lien'

  let img: Image | null = $state(null)
  let etat: Etat = $state('arrete')
  let role: Role = $state('seul')
  let motif = $state('')

  const lien = new Lien(
    (i) => { img = i },                       // une autre vue mène : on suit
    (r) => { role = r; if (r === 'seul' && etat !== 'ecoute') img = null },
  )
  const micro = new Micro(
    (i) => { img = i; lien.diffuse(i) },
    (e, m) => {
      etat = e; motif = m
      if (e === 'ecoute') lien.prendLaMain()
      else if (role === 'meneur') lien.rendLaMain()
    },
  )

  const EMOJI: Record<string, string> = {
    calm: '😌', joy: '😊', stress: '😬', anger: '😠',
    fatigue: '😴', focus: '🤔', indetermine: '…',
  }
  const NOM: Record<string, string> = {
    calm: 'Calme', joy: 'Joie', stress: 'Tension', anger: 'Colère',
    fatigue: 'Fatigue', focus: 'Concentration', indetermine: 'Indéterminé',
  }
  const tete = $derived(img?.state && img.state in EMOJI ? img.state : 'indetermine')
  const opacite = $derived(0.34 + Math.min(img?.confidence ?? 0, 0.72) * 0.9)
  const actif = $derived(etat === 'ecoute' || role === 'suiveur')

  // LE HALL OUVRE LA GRANDE VUE, PAS NOUS. Encadré, on lui demande par le
  // protocole sbx ; hors cadre, on y va directement. Ouvrir un onglet depuis
  // une iframe ferait perdre la barre du Hall et tout ce qui y joue.
  function ouvreMega() {
    const url = location.origin + '/'
    if (parent !== window) {
      try { parent.postMessage({ sbx: 'ouvre', url }, '*'); return } catch { /* on retombe */ }
    }
    location.href = url
  }
</script>

<div class="carte">
  <div class="tete">
    <span class="pastille" class:vivant={actif} class:pouls={actif && img?.vad}></span>
    <span class="dim mono minus">
      {#if role === 'suiveur'}suit une autre vue
      {:else if etat === 'ecoute'}à l'écoute
      {:else}en veille{/if}
    </span>
    <button class="ouvrir" onclick={ouvreMega} title="Ouvrir le cockpit complet">⤢</button>
  </div>

  <div class="corps">
    <div class="visage" style="opacity:{opacite}">{EMOJI[tete]}</div>
    <div class="dit">
      <div class="nom">{NOM[tete]}</div>
      {#if img && img.calibration < 1 && actif}
        <div class="dim minus">étalonnage {Math.round(img.calibration * 100)} %</div>
      {:else if actif && img}
        <div class="dim minus mono">
          {img.pitch ? img.pitch.toFixed(0) + ' Hz' : '—'} ·
          {img.speech_rate ? img.speech_rate.toFixed(0) + ' syll/min' : '—'}
        </div>
      {:else}
        <div class="dim minus">personne n'est écouté</div>
      {/if}
    </div>
  </div>

  <div class="axe" title="Activation — le seul axe acoustiquement solide">
    <div class="piste"><div class="curseur" style="left:{((img?.activation ?? 0) + 1) / 2 * 100}%"></div></div>
  </div>

  <!-- Le spectre en miniature : il dit « ça vit » mieux qu'aucun libellé. -->
  <div class="spectre" aria-hidden="true">
    {#each (img?.fft ?? new Array(32).fill(-100)).filter((_, i) => i % 4 === 0) as v}
      <i style="height:{Math.max(2, Math.min(100, (v + 100)))}%"></i>
    {/each}
  </div>

  <div class="pied">
    {#if etat === 'ecoute'}
      <button class="agir" onclick={() => micro.arrete()}>⏹ arrêter</button>
    {:else if role === 'suiveur'}
      <span class="dim minus">une autre vue tient le micro</span>
    {:else}
      <button class="agir primaire" onclick={() => micro.demarre()}
              disabled={etat === 'demande'}>🎙 écouter</button>
    {/if}
  </div>

  {#if etat === 'refuse'}
    <div class="avis">micro refusé — c'est votre droit</div>
  {:else if etat === 'erreur'}
    <div class="avis">{motif.slice(0, 80)}</div>
  {/if}

  <!-- LA RÉSERVE TIENT EN UNE LIGNE ICI, mais elle y est. Une carte d'humeur
       se lit d'un coup d'œil : c'est justement là qu'un emoji se prend pour
       un diagnostic. -->
  <div class="reserve">Indices acoustiques — pas un état intérieur.</div>
</div>

<style>
  :global(body) { background: transparent; }
  .carte { display: grid; gap: 7px; padding: 10px 12px; font-size: 13px; }
  .tete { display: flex; align-items: center; gap: 7px; }
  .minus { font-size: .66rem; }
  .pastille { width: 7px; height: 7px; border-radius: 50%; background: #3a4a63; flex: 0 0 auto; }
  .pastille.vivant { background: var(--rouge); box-shadow: 0 0 10px var(--rouge); }
  .ouvrir { margin-left: auto; padding: .1rem .45rem; font-size: .8rem; border-radius: 9px; }

  .corps { display: flex; align-items: center; gap: 11px; }
  .visage { font-size: 2.4rem; line-height: 1; transition: opacity .35s ease; }
  .nom { font-weight: 600; font-size: .95rem; }

  .piste { position: relative; height: 3px; border-radius: 999px;
    background: linear-gradient(90deg, rgba(92,240,168,.35), rgba(70,229,255,.35), rgba(255,194,77,.45)); }
  .curseur { position: absolute; top: -3.5px; width: 10px; height: 10px; margin-left: -5px;
    border-radius: 50%; background: var(--cyan); box-shadow: 0 0 10px rgba(70,229,255,.8);
    transition: left .3s ease; }

  .spectre { display: flex; align-items: flex-end; gap: 1px; height: 26px; }
  .spectre i { flex: 1; background: linear-gradient(180deg, rgba(159,244,255,.75), rgba(70,229,255,.25));
    border-radius: 1px 1px 0 0; transition: height .1s linear; }

  .pied { display: flex; align-items: center; min-height: 26px; }
  .agir { width: 100%; padding: .3rem .6rem; font-size: .74rem; border-radius: 11px; }
  .avis { font-size: .66rem; color: var(--ambre); }
  .reserve { font-size: .62rem; color: var(--encre-2); opacity: .8;
    border-top: 1px solid var(--bord); padding-top: 5px; }
</style>
