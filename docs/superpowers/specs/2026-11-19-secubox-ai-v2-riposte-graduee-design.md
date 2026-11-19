<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox AI V2 — réponse graduée défensive (#3583, phase 4/5)

Date : 2026-11-19. Statut : conception, à valider par le propriétaire. Complète (ne remplace pas)
`docs/superpowers/specs/2026-11-14-secubox-ai-v2-design.md` et
`docs/superpowers/specs/2026-11-18-secubox-ai-v2-correlation-outils-auto-design.md` (branche #3583). Ce qui n'est
pas dit ici reste comme dans ces deux specs.

## Intention

Le propriétaire (19/11) veut une **réponse graduée face à un attaquant répété** : plus l'attaquant insiste, plus la
réponse monte. Formulé dans un premier jet sous une forme offensive (« contre-attaque », « trafic inversé », « cibler
les faiblesses de l'attaquant ») — **refusé et reformulé** : SecuBox vise la certification CSPN ANSSI, la riposte
active (*hack-back*) est illégale, frappe souvent une victime intermédiaire (botnet, proxy, machine compromise d'un
tiers innocent) et sort du périmètre défensif. La réponse graduée retenue est **entièrement défensive et locale** :
tout se passe sur l'infrastructure de l'utilisateur ; **aucun paquet n'est émis vers l'attaquant au-delà de ce que la
box répondrait normalement**. C'est la mise en échelle des gestes du catalogue V2 (§ 4 du complément), pilotée par la
persistance mesurée dans le dossier d'attaquant.

## Objectifs (en plus des deux specs V2)

1. **Échelle de réponse à trois niveaux**, attachée au dossier d'attaquant/campagne :
   - **N1 observer** : trace, corrélation, enrichissement du dossier ; aucune action réseau.
   - **N2 contenir** : geste du catalogue qui limite l'attaquant sur notre infrastructure (ban nft, quarantaine DNS,
     isolation de zone, limitation de débit, rejet DoH/DoT) — appliqué d'office quand le code juge le cas sûr.
   - **N3 usager** : escalade quand l'attaque **persiste** (ban long, propagation au maillage, redirection vers un
     leurre) — même règle « cas sûr décidé par le code », mais sur des seuils de récidive plus hauts.
2. **Déclencheur de montée = persistance mesurée**, pas une appréciation du modèle : nombre de tentatives, fenêtre de
   temps, nombre de couches touchées, appartenance à une campagne, récidive après un ban expiré.
3. **Chaque niveau est réversible et plafonné** : les plafonds de gk2 par geste restent ceux du complément V2
   (`ban` 60/h et 400/j, etc.) ; aucun geste nouveau, aucune règle écrite à la main depuis gk3.

## Non-objectifs

- **Aucune action offensive.** Pas de scan en retour, pas de paquet forgé vers l'attaquant, pas d'exploitation d'une
  faiblesse de l'attaquant, pas d'« injection de trafic inversé » (ce serait un déni de service émis par la box).
- Pas de nouveau capteur ni d'IDS (comme V2 C10) : on relie et on échelonne ce qui existe.
- Pas de geste hors du catalogue audité (V2 décision 3) ; pas de règle nftables/nginx/WireGuard écrite depuis gk3.
- Pas les appareils de la maison : ils restent l'affaire de `secubox-garde`. Ici, les attaquants d'Internet vers gk2.
- Pas de limitation de débit « amplifiée » ni de réponse plus grosse que la requête (anti-réflexion).

## Anti-objectifs (ce qui rendrait la fonction nuisible)

- Une montée de niveau décidée par le modèle de langue plutôt que par le code sur des chiffres (le modèle explique et
  propose, il ne décide ni du cas sûr, ni de la montée — cf. [[feedback_ia_jamais_inventer]]).
- Un geste N3 sans seuil de récidive distinct de N2 : l'escalade perdrait son sens.
- Émettre quoi que ce soit vers l'attaquant : la box ne devient jamais une source d'attaque, même « en retour ».
- Un plafond franchi en montant les niveaux : les plafonds du complément V2 valent pour la **somme** des gestes, pas par
  niveau.

## Conception

### 1. L'échelle, attachée au dossier

Le dossier d'attaquant/campagne (complément V2 § 2) porte un champ `niveau` (`observer` | `contenir` | `usager`) et un
`niveau_depuis` (horodatage). Le corrélateur, à chaque passe, recalcule le niveau **cible** à partir des signaux de
persistance (ci-dessous) et le compare au niveau courant. Une montée déclenche le(s) geste(s) du niveau atteint ; une
accalmie (fenêtre sans nouvelle preuve) fait **redescendre** le niveau, sans défaire les bans encore actifs (ils
expirent seuls).

### 2. Signaux de persistance (chiffres, pas d'avis)

Mesurés sur le dossier, sans le modèle :

- `tentatives` : nombre d'événements attribués à l'attaquant dans la fenêtre.
- `couches` : nombre de couches distinctes touchées (nft, WAF, DPI, DNS, leurres, auth, hôte, garde).
- `fenetre_s` : durée entre la première et la dernière preuve.
- `campagne` : l'attaquant partage une empreinte d'outil avec d'autres sources.
- `recidive` : nouvelle preuve **après** l'expiration d'un ban précédent de la même adresse/bloc.

Seuils (déclaratifs, `/etc/secubox/ai/riposte.toml`, valeurs de départ à affiner au banc) :

- N2 `contenir` dès `tentatives ≥ n2_tentatives` **ou** `couches ≥ 2` **ou** règle critique touchée (ex. sonde `/.env`).
- N3 `usager` dès `recidive` vraie **ou** `campagne` vraie avec `tentatives ≥ n3_tentatives` **ou** `couches ≥ 3`.

### 3. Correspondance niveau → gestes du catalogue (aucun geste nouveau)

| Niveau | Geste(s) du catalogue V2 | Cas sûr (décidé par le code) |
|---|---|---|
| N1 observer | *(aucun)* enrichissement du dossier | toujours |
| N2 contenir | `ban` adresse ; `quarantaine_dns` ; `isoler_zone` ; `limite_debit` ; `rejet_doh_dot` | cible présente dans le relevé, publique (jamais une IP privée), sous plafond |
| N3 usager | `ban` long ; `ban_bloc` /24 ; `propager_maillage` ; `rediriger_leurre` | en plus de N2 : récidive ou campagne confirmée par ≥ 2 traits, bloc homogène pour `ban_bloc` |

Le « cas sûr » reste **la garde d'actord** : jamais une adresse privée, cible réellement vue dans le relevé, action du
catalogue fermé, plafonds de gk2 respectés (cf. [[project_actor_autoban_propose.md]], [[project_waf_auto_bans_2238]]).

### 4. Les 5 scénarios de référence (banc)

1. **Scan répété `/.env`, `/.git`** — N2 : ban WAF 7 j dès la 1ʳᵉ touche (règle critique existante). N3 si plusieurs
   IP du même /24 : `ban_bloc`. Jamais : sonder l'IP en retour.
2. **Bourrage SASL (mail)** — N2 : ban de même motif `auth_smtp:sasl_failed` (déjà en place). N3 si récidive :
   quarantaine + alerte garde (courriel/SMS).
3. **Flot de requêtes (saturation applicative)** — N2 : `limite_debit` nft (`limit rate`, jamais de réponse amplifiée).
   N3 si persistance : ban temporaire. **Jamais** de « trafic inversé ».
4. **Appareil interne qui contourne le DNS** — N2 : `rejet_doh_dot` + redirection DNS forcée vers la box (chaîne
   `sbx_tv_force` existante). *(Frontière garde : un appareil interne reste piloté par garde ; ici seulement si l'IA
   propose, garde applique.)*
5. **Campagne multi-sources, même empreinte** — N2 : ban du groupe. N3 : dossier, `propager_maillage` (~17 min),
   `rediriger_leurre` pour épuiser l'outil sur une cible sans valeur.

### 5. Console (prolonge V2 phase 6 / Radar #3811)

Dans l'onglet Chaîne/Dossier : le `niveau` courant et son historique, les signaux de persistance qui l'ont fixé, les
gestes appliqués par niveau et leur effet (le ban a-t-il fait cesser le trafic ?), et un bouton **« défaire »** par
geste et **« redescendre le niveau »**. Le modèle de langue résume (« cet attaquant est monté en N3 après récidive sur
le /24 ») ; il ne fixe pas le niveau. Maquette Aurora avant code (comme Radar+Chaîne, validés 14/11).

## Laissé au constructeur

- Les valeurs exactes des seuils (`n2_tentatives`, `n3_tentatives`, fenêtres) : départ raisonnable + affinage au banc
  gk4-gk7, jamais sur gk2 d'abord.
- La structure du champ `niveau`/`niveau_depuis` dans `dossiers` (migration dédiée).
- Le fichier `riposte.toml` et son schéma.
- Le point d'application : gk3 **propose** le niveau et le geste par `ai-ban` ; l'application reste le chemin audité de
  gk2 (jamais de règle écrite depuis gk3). Pour un appareil interne (scénario 4), c'est garde qui applique.

## Décisions prises par l'assistant (à vérifier)

- **Refus du cadrage offensif initial.** La réponse graduée est défensive et locale. Si le propriétaire veut malgré
  tout une capacité active (retour de paquets, exploitation de l'attaquant), c'est hors de ce design et hors du
  périmètre SecuBox/CSPN : à rediscuter explicitement, pas à présumer.
- **La montée de niveau est pilotée par le code sur des chiffres**, jamais par le modèle de langue.
- **La redescente de niveau ne défait pas les bans actifs** : ils expirent seuls, pour ne pas rouvrir une porte encore
  utile.
- **Frontière garde** : un appareil interne reste du ressort de `secubox-garde` ; l'IA peut proposer, garde applique.

Liens : [[project_secubox_ai_v2]] · [[project_actor_autoban_propose.md]] · [[feedback_ia_jamais_inventer]] ·
[[project_waf_auto_bans_2238]] · [[project_tri_netflix_dns_3226]].
