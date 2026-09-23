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
  import FFTCanvas from './FFTCanvas.svelte'
  import { Micro, type Image, type Etat } from './src/lib/micro'
  import { Lien, type Role } from './src/lib/lien'
  import { lumierePour, lumiereNeutre, vautLaPeine, type Lumiere } from './src/lib/couleur'

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
  const ORDRE = ['calm', 'joy', 'stress', 'anger', 'fatigue', 'focus']
  const tete = $derived(img?.state && img.state in EMOJI ? img.state : 'indetermine')
  const indices = $derived({
    calm: img?.calm ?? 0, joy: img?.joy ?? 0, stress: img?.stress ?? 0,
    anger: img?.anger ?? 0, fatigue: img?.fatigue ?? 0, focus: img?.focus ?? 0,
  } as Record<string, number>)
  const opacite = $derived(0.34 + Math.min(img?.confidence ?? 0, 0.72) * 0.9)
  const actif = $derived(etat === 'ecoute' || role === 'suiveur')

  // LA LAMPE SUIT L'HUMEUR — mais seulement si quelqu'un écoute (#1331).
  //
  // ON N'ALLUME RIEN AU CHARGEMENT. Sans le garde `aEmis`, ouvrir le Hall
  // suffirait à changer la lumière d'une pièce : un effet physique déclenché
  // par personne, pour une carte que l'on n'a même pas regardée. La première
  // émission ne peut donc venir que d'une écoute réelle.
  //
  // ET ON REND LA LAMPE EN PARTANT. Quand l'écoute s'arrête, on repasse au
  // blanc chaud : laisser un rouge au mur après la fin de la mesure, ce serait
  // une affirmation qui survit à ce qui la justifiait.
  //
  // LE HALL DÉCIDE S'IL OBÉIT. Il connaît la lampe et il porte la session ;
  // hors LAN, son propre relais rendra 403. D'ici, on ne fait que dire ce
  // qu'on lit — on ne commande rien.
  let derniere: Lumiere | null = null
  let aEmis = false
  $effect(() => {
    if (parent === window) return          // hors cadre : personne à qui parler
    if (!actif && !aEmis) return           // jamais écouté : la lampe ne nous regarde pas
    const l = actif ? lumierePour(tete, img?.confidence ?? 0) : lumiereNeutre()
    if (!vautLaPeine(derniere, l)) return
    derniere = l
    aEmis = actif || aEmis
    try { parent.postMessage({ sbx: 'mood-lumiere', ...l }, '*') } catch { /* cadre parti */ }
  })

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
      {#if img?.age_s}
        <!-- UNE LECTURE TENUE DIT SON ÂGE. Sans cela elle se lirait comme une
             mesure en cours, alors que la personne s'est tue. -->
        <div class="dim minus">mesuré il y a {img.age_s.toFixed(0)} s</div>
      {:else if img && img.calibration < 0.75 && actif}
        <div class="dim minus">référence {Math.round(img.calibration * 100)} %
          · {img.observations ?? 0} mesures</div>
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

  <!-- LE SPECTRE *ET* LE SPECTROGRAMME, par le composant du cockpit.
       La carte n'avait que des barres : elles disent l'instant, pas le
       mouvement — et une voix se reconnaît à son mouvement. Réutiliser le
       composant plutôt que d'en réécrire un petit évite surtout qu'ils
       divergent : deux rendus du même signal finissent toujours par ne plus
       se ressembler, et l'on ne sait alors plus lequel croire. -->
  <div class="spectro">
    <FFTCanvas bandes={img?.fft ?? []} voix={img?.vad ?? false} hauteur={78} compact />
  </div>

  <!-- L'HISTOGRAMME DES SIX INDICES. Il tenait dans la place laissée vide, et
       il change la nature de la carte : un emoji seul se lit comme un verdict,
       six barres montrent ce qui a été ÉCARTÉ. C'est la même information qu'au
       cockpit, et c'est justement pour ça qu'elle doit être là — la carte est
       ce qu'on regarde le plus souvent. -->
  <div class="histo" aria-label="répartition des indices">
    {#each ORDRE as k}
      <div class="col" title="{NOM[k]} {Math.round((indices[k] ?? 0) * 100)} %">
        <div class="tube"><i style="transform:scaleY({Math.max(0.02, indices[k] ?? 0)})"
                             class:tete={k === tete}></i></div>
        <span class="ic">{EMOJI[k]}</span>
      </div>
    {/each}
  </div>

  <!-- LES MÉTRIQUES, MÊME QUAND RIEN N'EST VOISÉ. C'est ce qui manquait le
       plus : une carte qui dit « à l'écoute · 0 mesure · Indéterminé » sans
       rien montrer de ce qu'elle entend laisse croire à une panne. Le niveau
       et l'état du VAD répondent tout de suite à « pourquoi il ne dit rien ». -->
  <div class="metriques mono">
    <span title="Hauteur de la voix">{img?.pitch ? img.pitch.toFixed(0) : '—'}<b>Hz</b></span>
    <span title="Débit syllabique">{img?.speech_rate ? img.speech_rate.toFixed(0) : '—'}<b>syl</b></span>
    <span title="Énergie RMS">{img ? (img.energy * 100).toFixed(0) : '—'}<b>%</b></span>
    <span class:on={img?.vad} title="Détection de voix">{img?.vad ? 'voix' : 'silence'}</span>
    {#if img?.ambiance?.bpm}
      <span class="amb" title="Ambiance détectée dans la pièce">{Math.round(img.ambiance.bpm)}<b>bpm</b></span>
    {/if}
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
  /* LA CARTE ÉPOUSE LA HAUTEUR QU'ON LUI DONNE, au lieu que je devine un
     nombre de pixels. Le Hall fixe la taille de la tuile ; deviner laissait
     soit du vide en bas, soit un débordement — et la bonne valeur change avec
     le contenu affiché (l'avis d'ambiance, le message de reprise…).
     Ce qui reste va à l'histogramme, qui est ce qui gagne le plus à être grand. */
  :global(html, body) { height: 100%; background: transparent; }
  /* `100dvh` ET PAS `100%` : `min-height: 100%` se résout contre le parent, et
     le parent (`#carte`) a une hauteur automatique — la règle ne s'appliquait
     donc à rien, et il restait quatre-vingts pixels de vide en bas de la
     tuile. La hauteur de la fenêtre, elle, ne dépend d'aucune chaîne de
     parents. `dvh` plutôt que `vh` pour les navigateurs mobiles, dont la barre
     d'adresse fait varier la seconde. */
  .carte { display: flex; flex-direction: column; gap: 7px;
    padding: 10px 12px; font-size: 13px; min-height: 100dvh; }
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

  /* Un fond, même au repos : sans lui, un spectre vide est indiscernable
     d'un trou dans la mise en page, et l'on cherche ce qui manque. */
  /* LA PLACE SE PARTAGE ENTRE LES DEUX, avec un plafond sur chacun. Laisser
     l'histogramme tout prendre donnait six grandes boîtes vides tant que
     personne ne parle — techniquement correct, visuellement inquiétant. Les
     bornes hautes gardent les deux à une taille où ils se lisent sans que
     l'un écrase l'autre. */
  .spectre { display: flex; align-items: flex-end; gap: 1px;
    flex: 1 1 auto; min-height: 26px; max-height: 64px;
    background: rgba(5,7,15,.45); border-radius: 7px; padding: 2px; }
  .spectro { flex: 1 1 auto; min-height: 72px; max-height: 96px; overflow: hidden; }

  /* MISE À L'ÉCHELLE, PAS HAUTEUR EN POURCENTAGE — et c'est ce qui avait fait
     disparaître le spectre. Une hauteur en pourcentage se résout contre le
     parent, qui doit avoir une hauteur DÉFINIE ; en rendant `.spectre`
     flexible (`flex: 1 1 auto` avec des bornes) sa hauteur est devenue
     indéfinie pour ce calcul, et toutes les barres sont tombées à zéro. La
     carte s'affichait donc parfaitement, sans son spectre.
     `scaleY` sur une barre pleine hauteur ne dépend d'aucun parent, et se
     compose en plus sur le GPU — ce qui ne gâche rien à vingt images/seconde. */
  .spectre i { flex: 1; height: 100%; transform-origin: bottom;
    background: linear-gradient(180deg, rgba(159,244,255,.75), rgba(70,229,255,.25));
    border-radius: 1px 1px 0 0; transition: transform .1s linear; will-change: transform; }

  /* L'histogramme : six colonnes, l'emoji sous chacune. Pas de libellé texte —
     la place ne le permet pas, et l'emoji suffit à identifier la colonne ; le
     `title` donne le nom et le pourcentage au survol. */
  /* L'HISTOGRAMME PREND LA PLACE QUI RESTE. C'est lui qui la mérite : six
     barres plus hautes se comparent mieux, et c'est la seule chose de cette
     carte qui gagne réellement à s'étirer. */
  .histo { display: grid; grid-template-columns: repeat(6, 1fr); gap: 4px;
    align-items: stretch; flex: 1 1 auto; min-height: 44px; max-height: 96px; }
  .col { display: grid; grid-template-rows: 1fr auto; gap: 2px; justify-items: center; }
  .tube { width: 100%; display: flex; align-items: flex-end;
    background: rgba(255,255,255,.05); border-radius: 5px; overflow: hidden; }
  /* Même raison que pour le spectre : la colonne vit dans une rangée de
     grille en `1fr`, dont la hauteur n'est pas définie pour un pourcentage. */
  .tube i { display: block; width: 100%; height: 100%; transform-origin: bottom;
    border-radius: 5px 5px 0 0; background: rgba(70,229,255,.45);
    transition: transform .3s ease; will-change: transform; }
  /* La colonne de tête se détache, sinon six barres voisines se lisent comme
     une égalité alors qu'il y a un classement. */
  .tube i.tete { background: linear-gradient(180deg, var(--cyan), rgba(70,229,255,.5)); }
  .ic { font-size: .72rem; line-height: 1; opacity: .75; }

  .metriques { display: flex; flex-wrap: wrap; gap: 4px; font-size: .64rem;
    flex: 0 0 auto; }
  .metriques span { padding: 2px 6px; border-radius: 7px;
    background: rgba(255,255,255,.04); color: var(--encre-2);
    border: 1px solid transparent; }
  .metriques b { font-weight: 400; opacity: .55; margin-left: 1px; }
  .metriques span.on { color: var(--cyan-b); border-color: rgba(70,229,255,.3); }
  .metriques span.amb { color: var(--ambre); border-color: rgba(255,194,77,.28); }

  .pied { display: flex; align-items: center; min-height: 26px; flex: 0 0 auto; }
  .agir { width: 100%; padding: .3rem .6rem; font-size: .74rem; border-radius: 11px; }
  .avis { font-size: .66rem; color: var(--ambre); }
  /* La réserve reste en bas quoi qu'il arrive : c'est la dernière chose lue,
     et elle ne doit pas flotter au milieu quand la carte est haute. */
  .reserve { font-size: .62rem; color: var(--encre-2); opacity: .8;
    border-top: 1px solid var(--bord); padding-top: 5px;
    margin-top: auto; flex: 0 0 auto; }
</style>
