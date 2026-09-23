<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
     Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
     Source-Disclosed License — All rights reserved except as expressly granted.

     L'HUMEUR D'ENSEMBLE : ce que plusieurs voix donnent, sans qu'aucune se
     voie. Chacun garde sa page et sa lecture ; seule la moyenne est publiée,
     et seulement quand il y a assez de monde pour qu'elle cache ceux qui la
     composent.

     LE PANNEAU AFFICHE SON PROPRE REFUS, et c'est volontaire : « pas encore
     assez de monde » est une information utile, et la voir explique la règle
     mieux qu'une page de documentation. -->
<script lang="ts">
  type Commun = {
    participants: number; suffisant: boolean; seuil: number
    indices?: Record<string, number>; activation?: number; tete?: string
    base_commune: number; base_active: boolean; detail: string
  }

  let c: Commun | null = $state(null)
  let erreur = $state('')

  const EMOJI: Record<string, string> = {
    calm: '😌', joy: '😊', stress: '😬', anger: '😠', fatigue: '😴', focus: '🤔',
  }
  const NOM: Record<string, string> = {
    calm: 'Calme', joy: 'Joie', stress: 'Tension', anger: 'Colère',
    fatigue: 'Fatigue', focus: 'Concentration',
  }
  const ORDRE = ['calm', 'joy', 'stress', 'anger', 'fatigue', 'focus']

  // Toutes les cinq secondes : une moyenne de groupe ne bouge pas à vingt
  // images par seconde, et l'interroger à ce rythme ferait travailler la board
  // pour rien.
  $effect(() => {
    let vivant = true
    const lis = async () => {
      try {
        const r = await fetch('api/mood/commun', { credentials: 'same-origin' })
        if (vivant) { c = await r.json(); erreur = '' }
      } catch (e: any) { if (vivant) erreur = String(e?.message || e) }
    }
    lis()
    const t = setInterval(lis, 5000)
    return () => { vivant = false; clearInterval(t) }
  })
</script>

<div class="ens">
  {#if erreur}
    <p class="dim petit">⚠ {erreur}</p>
  {:else if !c}
    <p class="dim petit">…</p>
  {:else}
    <div class="compte">
      <span class="n mono">{c.participants}</span>
      <span class="dim petit">voix {c.participants > 1 ? 'lues' : 'lue'} en ce moment
        · seuil de publication {c.seuil}</span>
    </div>

    {#if c.suffisant && c.indices}
      <div class="tete">
        <span class="e">{EMOJI[c.tete ?? 'calm']}</span>
        <span class="nom">{NOM[c.tete ?? 'calm']}</span>
        <span class="dim petit mono">domine l'ensemble</span>
      </div>
      <ul class="barres">
        {#each ORDRE as k}
          <li>
            <span class="l dim">{EMOJI[k]} {NOM[k]}</span>
            <div class="b"><i style="width:{(c.indices[k] ?? 0) * 100}%"></i></div>
            <span class="v mono dim">{Math.round((c.indices[k] ?? 0) * 100)} %</span>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="refus">🔒 {c.detail}</p>
    {/if}

    <p class="dim minuscule base">
      Base commune : {c.base_commune} ordinaire{c.base_commune > 1 ? 's' : ''} mis en
      commun{c.base_active ? ', elle sert de repère à qui vient d’arriver' : ' — inactive sous le seuil'}.
      Un départ efface la contribution.
    </p>
  {/if}
</div>

<style>
  .ens { display: grid; gap: 9px; }
  .petit { font-size: .74rem; }
  .minuscule { font-size: .66rem; }
  .compte { display: flex; align-items: baseline; gap: 8px; }
  .n { font-size: 1.6rem; font-weight: 650; color: var(--cyan-b); }
  .tete { display: flex; align-items: center; gap: 8px; }
  .tete .e { font-size: 1.5rem; }
  .tete .nom { font-weight: 600; }
  .barres { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
  .barres li { display: grid; grid-template-columns: 9.5rem 1fr 2.6rem;
    align-items: center; gap: 8px; font-size: .74rem; }
  .b { height: 6px; border-radius: 999px; background: rgba(255,255,255,.06); overflow: hidden; }
  .b i { display: block; height: 100%; border-radius: 999px;
    background: linear-gradient(90deg, rgba(92,240,168,.8), rgba(70,229,255,.5));
    transition: width .5s ease; }
  .v { text-align: right; }
  .refus { margin: 0; font-size: .76rem; line-height: 1.5; color: #ffe3b0;
    background: rgba(255,194,77,.07); border: 1px solid rgba(255,194,77,.26);
    border-radius: 14px; padding: 9px 12px; }
  .base { border-top: 1px solid var(--bord); padding-top: 6px; margin: 0; }
</style>
