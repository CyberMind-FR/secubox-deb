<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Conseils IA applicables : bans d'office pour les cas sûrs, un clic sinon — conception

Issue : #3716. Suite de #3583 (secubox-ai) et de #3509 (contrôle par le relais, pas par une consigne).
Maquette validée : https://claude.ai/artifact/E1u86yMqyabB8Bki8Ho4KL (pages `Main` et `Regles`).
Plan : `docs/superpowers/plans/2026-11-14-conseils-ia-applicables.md`.

## Intention

L'onglet Menaces du POC secubox-ai (gk0) lit gk2, écrit un résumé et émet des propositions. Le relais les contrôle
déjà (catalogue fermé, cible présente dans le relevé), mais elles restent du texte à recopier dans gk2. On les rend
**applicables** :

- un **cas sûr**, reconnu par le **code du relais**, s'applique d'office ;
- un conseil hors cas sûr devient un bouton « Appliquer » (un clic) ;
- campagne et service restent un lien vers gk2.

Le modèle écrit ; le relais vérifie et décide ; gk2 revérifie ce qu'il peut, borne et trace.

## Décisions du propriétaire (2026-11-14, arrêtées)

| Sujet | Décision |
|---|---|
| Mode par défaut | **Automatique pour les cas sûrs** ; les autres conseils en un clic. Trois modes : proposer / un clic / automatique. |
| Ordre | D'abord le POC gk0 (`/home/reepost/poc-secubox-ai/relais/relais.py` + `index.html`), référence de comportement ; puis portage dans secubox-ai (#3583). |
| Cas sûr | Bloc /24 dont **≥ 20 adresses** sont **déjà bannies** par le WAF, **seulement** des catégories reconnaissance/scanner dans ses alertes, **aucune** adresse de la box, du LAN, du maillage ni d'un pair ; durée **24 h**. Décidé par le code du relais, jamais par le modèle. |
| Adresse seule | Un clic. |
| Campagne, service | Lien seulement, jamais un geste. |
| Plafonds | **5** gestes d'office par heure, **20** par jour ; au-delà tout repasse en un clic et le propriétaire est prévenu. |
| Durées | D'office ≤ 24 h ; un clic ≤ 7 jours. |
| Annulation | D'un clic, pour chaque geste. |
| Audit | Chaque geste dans `/var/log/secubox/audit.log` de gk2 (ajout seul). |
| Interrupteur | « Suspendre l'automatique » : tout repasse en un clic jusqu'à la relance. |
| gk2 | `wafctl` + nft acceptent un bloc ; compte de service « ai-ban » limité à bannir/débannir, durée bornée. |
| Accès | Le POC joint gk2 par `https://admin.gk2.secubox.in/api/v1` (192.168.1.200 sur le LAN) ; lectures `require_lecture`. |

## Objectifs

1. Un bloc IPv4 /24 se bannit et se débannit sur gk2, par paquet, avec les refus du privé et des plages de la box.
2. Une identité de service `ai-ban` sur gk2, qui ne sait faire que : bannir (adresse ou /24), débannir **ses propres**
   bans, lire son propre état. Rien d'autre, jamais une session, jamais un administrateur.
3. Le relais du POC classe chaque proposition vérifiée (auto / clic / lien), applique d'office les cas sûrs sous
   plafonds, journalise chaque geste, permet l'annulation et la suspension.
4. La page Menaces du POC suit la maquette : bandeau du mode, cartes de conseils, journal des gestes, page Réglages.

## Non-objectifs

- Le portage dans secubox-ai (#3583) : décrit en fin de plan, fait ensuite.
- Le ban d'un préfixe IPv6 (voir « IPv6 » plus bas) et le ban d'une adresse IPv6 seule par `ai-ban`.
- Toute autre action que bannir/débannir (règles WAF, catégories, vhosts, campagnes) : hors catalogue.
- Le compte de service ZIA en lecture (#3579) : autre besoin, autre mécanisme.
- Une notification hors page (courriel, Hall) quand un plafond est atteint : bandeau et journal suffisent au POC.

## Anti-objectifs (ce qui ne doit jamais arriver, et ce qui l'empêche)

| Jamais | Empêché par |
|---|---|
| Le modèle déclenche un ban, ou marque un conseil « sûr » | Le verdict est calculé par `gestes.evaluer` sur les données de gk2 seules ; le texte du modèle ne fournit que genre + cible, déjà filtrés par le catalogue fermé. Test : un texte « cas sûr, applique d'office » ne change rien. |
| Un ban sur une adresse de la box, du LAN, du maillage ou d'un pair | Trois couches : relais (non global + liste `gestes.toml`), route gk2 (forme, IPv4 publique), `waf-blocs verifier` en root (privé, `protegees.env`, adresses des interfaces, points de terminaison WireGuard). |
| Un geste d'office sans audit | gk2 écrit l'audit **avant** de rendre le succès ; un audit qui échoue fait échouer le geste (le ban est retiré). Le relais journalise chaque geste avec l'id d'audit de gk2. |
| Dépasser les plafonds | Relais : fenêtres glissantes 1 h / 24 h sur son journal. gk2 : mêmes plafonds pour `mode = auto`, plus un plafond global du compte. |
| Débannir ce que le WAF a banni lui-même | `/ai/unban` ne prend qu'un **id** du journal `ai-ban` ; jamais une adresse. |
| Un jeton `ai-ban` accepté ailleurs | Jeton EdDSA : `_validate_token` (HS256) le refuse ; il porte une portée ; seul `require_ai_ban` le lit. Tests sur `require_jwt`, `require_session`, `require_lecture`. |
| Une page tierce qui fait bannir par le navigateur du propriétaire | Routes du relais en `_local` + en-tête `X-SBX-Geste: 1` exigé + corps JSON (un formulaire inter-sites ne peut poser ni l'un ni l'autre sans pré-vol CORS, que le relais ne sert pas). |
| L'automatique actif sur gk2 avant le go | Le déploiement pose `suspendu = true` ; seul le propriétaire relance. |

## Architecture

```
POC gk0 (relais, compte reepost)                         gk2 (production)
───────────────────────────────                         ─────────────────
relevé  ── GET require_lecture ───────────────────────► /api/v1/waf/{bans,alerts,bans/history,…}
modèle → propositions → filtrer_propositions (catalogue fermé, cible connue)
        → gestes.evaluer (cas sûr ? règles en code)
        → gestes.decider (mode, suspendu, plafonds)
        → d'office ou clic : jeton EdDSA ai-ban (≤ 60 s, aud=gk2, jti, empreinte du corps)
                         ── POST ──────────────────────► /api/v1/waf/ai/ban    require_ai_ban
                                                          bornes, plafonds, recontrôle du cas sûr (auto)
                                                          sudo wafctl ban | systemd-run wafctl ban-bloc
                                                            → waf-blocs verifier (root) → nft
                                                          journal ai-ban.jsonl + audit.log
        ◄── {id, fin} ─────────────────────────────────
journal gestes.jsonl ; page : carte + « Annuler » ───── POST /api/v1/waf/ai/unban {id}
                                                    ─── GET  /api/v1/waf/ai/etat
```

### gk2 — bans de bloc (nft + `wafctl`)

Constat : `wafctl ban` n'accepte qu'une adresse (`ipaddress.ip_address`) ; les ensembles `inet secubox waf_ban{,6}`
sont créés par **sbxwaf** (`NftBanner.Ensure`) en `flags timeout; counter;`, **sans** `interval`. sbxwaf vide et
recrée la chaîne `waf_drop` à chaque démarrage et migre (supprime/recrée) un ensemble qui n'a pas sa forme ; ses
lecteurs (`ElementsAvecCompteurs`, `_get_bans`, sbx-authwatch) attendent des **adresses**, pas des préfixes.

**Décision (choix de Claude, à contester) : une table à part, `inet secubox_waf_blocs`**, et non un drapeau
`interval` sur `waf_ban`. Ajouter `interval` à `waf_ban` imposerait de changer sbxwaf (Go, toolbox-ng), sa migration
(qui supprimerait l'ensemble en service et ses bans manuels), et chaque lecteur d'éléments ; une table séparée ne
touche à rien de cela et ne peut pas être effacée par le `flush chain waf_drop` de sbxwaf.

```
table inet secubox_waf_blocs {
  set blocs4 { type ipv4_addr; flags interval, timeout; counter; }
  chain entree { type filter hook input priority -101; policy accept; ip saddr @blocs4 counter drop; }
}
```

- Livrée en `/usr/share/secubox/waf/blocs.nft` (idiome créer-puis-supprimer du fichier de rate-limit, rejouable).
- Priorité -101 : juste avant `waf_drop` (-100). Même portée que lui : crochet `input` (HAProxy sur l'hôte).
- **Persistance** : état root `/var/lib/secubox-waf-blocs/blocs.json` (0600, dossier 0700, hors de
  `/var/lib/secubox` partagé ; écriture par fichier temporaire + `os.replace`, relue et validée avant le
  remplacement). `secubox-waf-blocs.service` (oneshot root, `PartOf=` et `ReloadPropagatedFrom=nftables.service`)
  rejoue la table et les blocs non échus avec leur temps restant au démarrage et après un rechargement du pare-feu.
- **Script `waf-blocs`** (`/usr/sbin`, `python3 -I`, bibliothèque standard) : `verifier <ip|cidr>`,
  `ajouter <cidr> <secondes>`, `retirer <cidr>`, `lister`, `reappliquer`. `wafctl` expose `ban-bloc`, `unban-bloc`,
  `blocs` et lui délègue.
- **Bloc accepté** : IPv4, exactement /24, adresse de réseau (bits d'hôte nuls). Choix de Claude : pas d'autre
  longueur, aucun appelant n'en a besoin et un préfixe plus large multiplie les dégâts collatéraux.
- **Refus** (codes de sortie de `verifier`) : 1 invalide, 2 privé/réservé (même liste `INTERDITS` que `wafctl ban`),
  3 recoupe une plage de `/etc/secubox/waf/protegees.env` (`SECUBOX_WAF_PROTEGEES`, #3450), 4 contient une adresse
  d'une interface de la box (`ip -j addr`), 5 contient le point de terminaison d'un pair WireGuard
  (`wg show all endpoints`). Choix de Claude : `wafctl ban` (adresse seule, tous appelants) passe désormais aussi
  par `verifier` — « jamais la box ni un pair » vaut pour tout ban, pas seulement pour l'IA.
- **Durées** : 1 h à 7 j pour un bloc.
- Sudoers (`secubox`) : `systemd-run --wait --pipe --collect --quiet /usr/sbin/wafctl ban-bloc *` et `unban-bloc *`
  (le contrôleur écrit hors des `ReadWritePaths` de l'agrégateur : `systemd-run`, comme `secubox-profiles`), et
  `wafctl blocs` (lecture).

### gk2 — compte de service « ai-ban »

État des lieux : secubox-auth ne connaît que des sessions HS256 (`jwt_secret` lu par tous les modules, `jti`
inscrit au registre) ; `_validate_token` **refuse** tout jeton qui porte `scope` (#942) ; #3579 (compte ZIA en
lecture) n'est pas fait. Le seul précédent de jeton à portée est le **porteur délégué du pilotage** (#3126 L5) :
EdDSA, clé publique root dans un arbre root, durée ≤ 60 s, `aud` = nom de la box.

**Décision (choix de Claude, à contester) : `ai-ban` n'est pas un compte de secubox-auth, c'est une identité par
clé**, sur le modèle du pilotage :

- **Clé privée Ed25519 sur la box de l'IA seulement** : POC gk0 `/etc/secubox/secrets/ai-ban/ai-ban.key`
  (`reepost`, 0600, dossier 0700) ; plus tard secubox-ai `/etc/secubox/secrets/ai/ai-ban.key` (`secubox-ai`, 0600).
  Jamais dans le code, un TOML ou le dépôt.
- **Clés publiques sur gk2** : `/etc/secubox-comptes-service/ai-ban/<empreinte>.pub` (dossier et fichiers
  root:root, non inscriptibles par le groupe ni les autres, lus sans suivre de lien par `_lire_fichier_root`).
  gk2 ne détient **aucun** secret capable de frapper un jeton `ai-ban` (contrairement à un HS256).
- **Jeton par requête** : en-tête `alg = EdDSA`, `kid` = empreinte SHA-256 de la clé publique ; réclamations
  `sub = "ai-ban"`, `aud` = `nom_box_locale()` de gk2 (`gk2`), `portee = "waf-ban"`, `iat`, `exp` (≤ `iat` + 60 s,
  dérive 5 s), `jti` (32 hex, **usage unique**, cache de rejeu en mémoire jusqu'à échéance), `corps` = SHA-256 du
  corps brut (choix de Claude : un jeton capturé ne vaut que pour ce geste-là).
- **Garde** : `secubox_core/compte_service.py`, `garde_compte_service("ai-ban")` → `require_ai_ban`. Liste fermée
  des comptes en code (`{"ai-ban": "waf-ban"}`). Refus : 401 (jeton absent, signature, échéance, rejeu) ou 403
  (portée, audience), audité (motif, jamais le jeton), une ligne par motif toutes les 10 s au plus.
- **Rotation** : nouvelle paire sur la box de l'IA, `wafctl cle-ai-ban ajouter <fichier.pub>` sur gk2 (root, par
  le propriétaire), bascule du relais, puis `wafctl cle-ai-ban retirer <empreinte>`. Deux clés au plus à la fois.
- **Révocation** : `wafctl cle-ai-ban retirer <empreinte>` ou `retirer --toutes` ; effet immédiat (relecture du
  dossier à chaque changement). Ces verbes ne sont **pas** dans le sudoers de `secubox`. Chacun est audité.

Exception à `RULES-CODE.md` § 3 (route mutante sans `require_jwt`) : écrite dans le tableau des exceptions avec son
test, par la tâche qui crée les routes.

### gk2 — routes `/api/v1/waf/ai/*`

Servies là où `/api/v1/waf/` l'est (agrégateur, `User=secubox`, `NoNewPrivileges=false` : c'est ce qui permet déjà
le `sudo wafctl ban` de `POST /ban`). Code dans `composants/waf/api/gestes_ia.py`, branché sur `main.py`.

| Route | Corps / réponse | Règles |
|---|---|---|
| `POST /ai/ban` | `{cible, duree_s, mode: auto|clic, conseil, motif}` → `{id, cible, fin, audit}` | Cible : IPv4 publique seule ou /24 exact. Durée : clic 3 600 à 604 800 s ; auto ≤ 86 400 s et bloc seulement. **Auto : recontrôle** — ≥ 20 adresses du bloc dans `waf_ban`, motifs ⊆ catégories sûres. Plafonds auto 5/h, 20/j ; plafond du compte 30/h, 100/j (choix de Claude). |
| `POST /ai/unban` | `{id}` → `{id, etat}` | Seulement un id du journal `ai-ban`, actif ; idempotent si déjà levé ou échu. |
| `GET /ai/etat` | → `{actifs, compteurs, plafonds}` | Bans `ai-ban` actifs, compteurs des fenêtres. |

- Journal `/var/lib/secubox/waf/ai-ban.jsonl` (ajout seul) : `ban` et `annule`, avec `id`, `cible`, `fin`, `mode`,
  `conseil`, `jti`. Il fait foi pour les plafonds et pour « ses propres bans ».
- Audit `module = waf`, `by = ai-ban`, actions `ai-ban`, `ai-unban`, `ai-ban-refus`. L'`id` du geste est l'id
  d'audit rendu au relais (« audit gk2 n° … » de la maquette).
- Refus métier en 409 avec un `motif` machine-lisible (`privee`, `protegee`, `box`, `pair`, `pas_sur`,
  `plafond_auto`, `plafond_compte`, `duree`) ; forme invalide en 422.

### POC gk0 — relais

Nouveau module `relais/gestes.py` (fonctions pures + journal + jeton), branché dans `relais.py`.

- **Règles du cas sûr en code** (`SEUIL_BLOC = 20`, `CATEGORIES_SURES = {"scanners", "recon_crawler"}`,
  `DUREE_AUTO_S = 86400`). Choix de Claude, à contester : `waf_fingerprint` et `product_absent_probes` sont aussi
  de la reconnaissance mais ne sont **pas** dans la liste de départ ; les ajouter est une ligne.
- **Données** : la liste **complète** des bans (`/waf/bans`, pas les 8 blocs du relevé), les alertes (`/waf/alerts`)
  et l'historique par adresse (`/waf/bans/history?hours=24&limit=1000`, `top_categories`). Toute catégorie hors
  liste, ou un motif inconnu (`waf`), sur une adresse du bloc ⇒ pas sûr.
- **Protégées côté relais** : toute adresse non globale, plus `relais/gestes.toml` (`protegees = [...]` : adresses
  publiques de gk2 et gk0, points de terminaison des pairs), rempli au déploiement d'après gk2.
- **Décision** (`decider`) : mode `proposer` ⇒ lien ; `clic` ⇒ clic ; `auto` ⇒ d'office si sûr, non suspendu, sous
  plafonds, sinon clic avec un avis (« plafond atteint », « automatique suspendu »).
- **Journal** `relais/gestes.jsonl` (ajout seul) : `applique`, `refuse`, `annule`, `ignore`, `echu`, avec l'id gk2.
  Les plafonds se comptent dessus (fenêtres glissantes de 3 600 s et 86 400 s, choix de Claude).
- **Réglages** `[gestes]` de `limites.toml` (double tampon existant) : `mode` (défaut `auto`), `suspendu`
  (défaut `false`).
- **Suspendu, l'évaluation continue** (choix de Claude) : un cas sûr porte l'étiquette « serait appliqué d'office »
  et un bouton un clic — le propriétaire juge la règle avant de la relancer.
- **Routes** (toutes `_local`, en-tête `X-SBX-Geste: 1`, corps JSON) : `GET /menaces/gestes`,
  `POST /menaces/appliquer`, `POST /menaces/annuler`, `POST /menaces/ignorer`, `POST /menaces/automatique`,
  `POST /menaces/mode`.

### POC gk0 — page

Selon la maquette : bandeau du mode (vert actif, orange suspendu ou plafond), lien Réglages, bouton
« Suspendre l'automatique » / « Relancer » ; cartes « appliqué d'office » (+ Annuler, fin prévue, n° d'audit),
« attend ton clic » (Appliquer · durée 4 h / 24 h / 7 j, Ignorer), « à examiner » (lien gk2) ; colonne « Gestes
appliqués » (heure, geste, état) ; vue Réglages (trois modes, tableau par type de conseil, garde-fous). DOM construit
par `el()`/`textContent`, comme le reste de la page.

## IPv6 : pas de /64 dans ce lot

Décision (choix de Claude, à contester) : **IPv4 /24 seulement**, et `ai-ban` ne bannit pas d'adresse IPv6.
Le critère sûr (« ≥ 20 adresses déjà bannies dans le bloc ») ne se transpose pas : une seule machine tient souvent un
/64 entier, donc 20 adresses d'un /64 peuvent être **un** hôte, et le grain d'un opérateur est plutôt /48 ou /56 —
une règle à concevoir sur mesures réelles. Le relevé du relais ne regroupe d'ailleurs que l'IPv4. À ouvrir en issue
suivante si le propriétaire le veut.

## Laissé au constructeur

- Noms internes, découpage des fonctions privées, messages d'erreur exacts (hors codes `motif`).
- Mise en forme fine de la page tant que la maquette est suivie.
- Détail du test nft réel (`unshare -rn`) s'il n'est pas permis sur la machine de build : le marquer `skip` et le
  faire au banc.

## Essais et banc

gk2 est la **production** : rien ne s'y essaie d'abord.

| Où | Quoi |
|---|---|
| Poste de build (gk0) | pytest : `waf-blocs` (nft simulé), `compte_service`, routes `ai/*` (wafctl simulé), `gestes.py`, page ; nft réel en espace de noms (`unshare -rn nft -c -f`). `visudo -c`, `sh -n`, `shellcheck`. |
| Banc (gk6, maître de test) | Paquets par apt ; `ban-bloc 203.0.113.0/24 1h` (plage de documentation, inoffensive) : élément nft, compteur, `nft list` ; `systemctl reload nftables` ⇒ bloc rejoué ; redémarrage de `secubox-waf-ng` ⇒ table intacte ; refus (privé, `protegees.env`, adresse d'interface, pair) ; clé `ai-ban` posée ; relais du POC pointé sur gk6 : un clic, d'office, annulation, plafonds, suspension, rejeu, mauvaise audience, jeton admin sur `/ai/ban`, jeton `ai-ban` sur `POST /ban`. Journaux AppArmor. |
| gk2 | Après banc vert : `df -h /`, paquets par apt, un seul redémarrage de l'agrégateur, clé publique posée, essai d'un clic sur `203.0.113.0/24` 1 h puis annulation, lignes d'audit vérifiées. **Automatique laissé suspendu** (`suspendu = true`). |
| gk0 | Clé privée posée, `gestes.toml` rempli d'après gk2, relais redémarré, page vérifiée. |

**L'automatique sur gk2 attend le go du propriétaire après le banc** : c'est lui qui clique « Relancer ».
L'issue se ferme (`closes #3716`) une fois déployée **et** ce go donné.

## Critères de réussite

- Un bloc /24 se bannit et se lève sur gk2, survit à un rechargement du pare-feu, refuse privé/protégé/box/pair.
- `ai-ban` ne peut rien d'autre que ses trois routes ; ses jetons sont refusés partout ailleurs.
- Le relais applique d'office un cas sûr, jamais un autre ; plafonds et suspension tiennent ; chaque geste a sa
  ligne d'audit sur gk2 et son entrée au journal du relais ; l'annulation d'un clic marche.
