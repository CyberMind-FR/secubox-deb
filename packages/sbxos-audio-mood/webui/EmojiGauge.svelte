<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     L'EMOJI EST LA PARTIE LA PLUS DANGEREUSE DE CETTE INTERFACE.
     Un visage porte une certitude qu'aucun chiffre ne porte : 😠 se lit « il
     est en colère », jamais « indice de colère à 0,31 ». On l'encadre donc de
     trois façons — il pâlit quand la confiance est basse, il devient « … » dès
     que rien ne se détache, et la barre des six indices reste TOUJOURS visible
     à côté de lui, pour qu'on voie ce qui a été écarté. -->
<script lang="ts">
  let {
    etat = 'indetermine', confiance = 0, indices = {} as Record<string, number>,
    activation = 0, fiabilite = 0, observations = 0,
  } = $props()


  const EMOJI: Record<string, string> = {
    calm: '😌', joy: '😊', stress: '😬', anger: '😠',
    fatigue: '😴', focus: '🤔', indetermine: '…',
  }
  const NOM: Record<string, string> = {
    calm: 'Calme', joy: 'Joie', stress: 'Tension', anger: 'Colère',
    fatigue: 'Fatigue', focus: 'Concentration', indetermine: 'Indéterminé',
  }
  const ORDRE = ['calm', 'joy', 'stress', 'anger', 'fatigue', 'focus']

  // L'opacité SUIT la confiance : un visage pâle se lit comme une hypothèse,
  // un visage franc comme une observation. C'est la seule grammaire visuelle
  // que tout le monde comprend sans lire la légende.
  const opacite = $derived(0.34 + Math.min(confiance, 0.72) * 0.9)
  const tete = $derived(etat in EMOJI ? etat : 'indetermine')
</script>

<div class="jauge">
  <div class="visage" style="opacity:{opacite}" title="{NOM[tete]}">{EMOJI[tete]}</div>
  <div class="dit">
    <div class="nom">{NOM[tete] ?? etat}</div>
    {#if etat === 'indetermine'}
      <div class="dim petit">
        {#if observations < 1}
          Première mesure en cours — aucune voix encore observée.
        {:else}
          Signal insuffisant pour lire quoi que ce soit.
        {/if}
      </div>
    {:else}
      <!-- LE POURCENTAGE DE L'INDICE DE TÊTE, en grand et en premier : c'est
           le chiffre qu'on cherche. La confiance le suit, plus petite — elle
           dit à quel point cette lecture se détache des cinq autres, ce qui
           est une question différente et secondaire. -->
      <div class="part mono">{Math.round((indices[tete] ?? 0) * 100)}<span class="pc">%</span></div>
      <div class="dim petit mono">confiance {(confiance * 100).toFixed(0)} %
        · référence {(fiabilite * 100).toFixed(0)} % ({observations})</div>
    {/if}
  </div>

  <div class="axe" title="Activation : le seul axe acoustiquement solide">
    <span class="dim petit">posé</span>
    <div class="piste"><div class="curseur" style="left:{(activation + 1) / 2 * 100}%"></div></div>
    <span class="dim petit">activé</span>
  </div>

  <ul class="indices">
    {#each ORDRE as cle}
      <li>
        <span class="e">{EMOJI[cle]}</span>
        <span class="l dim">{NOM[cle]}</span>
        <div class="barre"><i style="width:{(indices[cle] ?? 0) * 100}%"></i></div>
        <span class="v mono dim">{((indices[cle] ?? 0) * 100).toFixed(0)}</span>
      </li>
    {/each}
  </ul>
</div>

<style>
  .jauge { display: grid; gap: 12px; }
  .visage { font-size: 4.2rem; line-height: 1; transition: opacity .35s ease; }
  .nom { font-size: 1.15rem; font-weight: 600; letter-spacing: .01em; }
  .part { font-size: 1.85rem; font-weight: 650; color: var(--cyan-b); line-height: 1.05; }
  .pc { font-size: .85rem; margin-left: 2px; opacity: .65; }
  .petit { font-size: .74rem; }
  .axe { display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 8px; }
  .piste { position: relative; height: 4px; border-radius: 999px;
    background: linear-gradient(90deg, rgba(92,240,168,.35), rgba(70,229,255,.35), rgba(255,194,77,.45)); }
  .curseur { position: absolute; top: -4px; width: 12px; height: 12px; margin-left: -6px;
    border-radius: 50%; background: var(--cyan); box-shadow: 0 0 12px rgba(70,229,255,.8);
    transition: left .3s ease; }
  .indices { list-style: none; margin: 0; padding: 0; display: grid; gap: 5px; }
  .indices li { display: grid; grid-template-columns: 1.3rem 7.2rem 1fr 2.2rem;
    align-items: center; gap: 8px; font-size: .78rem; }
  .barre { height: 6px; border-radius: 999px; background: rgba(255,255,255,.06); overflow: hidden; }
  .barre i { display: block; height: 100%; border-radius: 999px;
    background: linear-gradient(90deg, rgba(70,229,255,.85), rgba(159,244,255,.5));
    transition: width .3s ease; }
  .v { text-align: right; }
</style>
