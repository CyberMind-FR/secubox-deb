<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox AI V2 phases 4 à 7 — neutralisation locale et apprentissage (cartes 3 et 4 de SADE) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** livrer l'analyste IA, les réponses graduées par `ai-ban` (ban, bloc, prolonger, limite de débit, redirection
vers le leurre, partage d'indicateurs), le renforcement automatique des politiques, et allumer les cartes 3
« Neutralisation locale » et 4 « Apprentissage » de `/soc/` avec leur critère de succès mesuré.

**Architecture :** gk2 reste le moteur qui fait foi. Chaque geste nouveau est une route `ai-ban` de
`gestes_ia.py`, avec ses bornes, ses plafonds, son audit et un verbe `wafctl` root. gk3 (`secubox-ai-veille`) calcule
le niveau de riposte sur des chiffres, propose, signe et exécute par ce seul chemin. Le modèle de langue explique et
recommande dans un contrat JSON vérifié ; il ne décide ni du cas sûr ni du niveau. SADE (`secubox-soc`, gk2) lit les
journaux de gestes et d'indicateurs de gk2 pour mesurer les critères des phases 3 et 4. Le mode SADE est publié dans
un fichier que `gestes_ia.py` lit avant tout geste d'office.

**Tech Stack :** Python 3 (FastAPI, Pydantic v2 strict, SQLite WAL, `tomllib`, httpx), Go (`sbxwaf`), nftables,
MirrorNet, Debian trixie arm64, AppArmor, systemd.

**Specs :**
- `docs/superpowers/specs/2026-11-14-secubox-ai-v2-design.md` (V2, §§ 9 à 14) ;
- `docs/superpowers/specs/2026-11-18-secubox-ai-v2-correlation-outils-auto-design.md` (complément « tout automatique ») ;
- `docs/superpowers/specs/2026-11-19-secubox-ai-v2-riposte-graduee-design.md` (échelle N1/N2/N3) ;
- `docs/superpowers/specs/2026-11-20-sade-active-defense-design.md` (§ « Les 4 phases », modes, garde-fous).

Issues : #3722 (phase 4), #3723 (phase 5), #3724 (phase 6), #3725 (phase 7), #3839 (SADE). Un seul worktree
(`scripts/agent-worktree.sh start --issue 3722`). Chaque commit cite l'issue de sa tâche.

## Global Constraints

- **gk2 fait foi.** Aucun geste écrit depuis gk3 hors des routes `ai-ban` (`/api/v1/waf/ai/*`). Aucune règle
  nftables, nginx ou WireGuard posée depuis gk3. Aucun helper root nouveau sur gk3, en dehors des verbes de `secubox-aictl`.
- **Zéro offensif.** Rien n'est émis vers l'attaquant au-delà de la réponse normale de la box : pas de scan en retour,
  pas de réponse amplifiée, pas de « trafic inversé ».
- **Le code décide.** Le cas sûr et le niveau sont calculés sur des chiffres. Le texte du modèle ne devient jamais un
  `motif`, un titre ni un geste.
- **Cibles jamais visées :** adresses privées, box, LAN, pairs du maillage (`wg_mesh.json` + threatmesh `/peers`),
  Freebox, robots vérifiés, liste blanche SADE, `protegees.env` de waf-blocs. Les appareils internes restent l'affaire
  de `secubox-garde`.
- **Plafonds par geste sur gk2** (fenêtres glissantes, sommés sur tous les niveaux) :

  | Geste | Plafond |
  |---|---|
  | `ban` adresse | 60/h, 400/j |
  | `ban_bloc` d'office | 5/h, 20/j (existant) |
  | `prolonger` | 30/h, 100/j |
  | `limiter` | 60/h, 400/j |
  | `leurre` | 30/h, 200/j |
  | `partager` | 30/h, 200/j |

  gk3 garde des plafonds inférieurs ou égaux, lus dans `politiques.toml`.
- **Durées.**

  | Geste | Durée d'office | Bornes |
  |---|---|---|
  | `ban` adresse | 24 h | ×4 par récidive, 7 j au plus |
  | `ban_bloc` | 24 h | |
  | `prolonger` | | fin ≤ maintenant + 7 j, ne raccourcit jamais |
  | `limiter` | 6 h | 1 h à 24 h |
  | `leurre` | 24 h | 1 h à 7 j |
  | indicateur partagé | 7 j | |
- **Tout automatique** (complément, décision du propriétaire du 18/11) : `auto = true` pour chaque geste,
  `automatique_suspendu = false`. Un 409 `plafond_*` répété (3 en 10 min) ou un 503 de gk2 suspend l'automatique de
  lui-même, avec audit et alerte.
- **Audit des deux côtés.** `/var/log/secubox/audit.log` (ajout seul) sur gk2 et gk3, plus une ligne `audit_chaine`
  sur gk3. Jamais de jeton ni de clé dans une ligne.
- **API.** `require_jwt` sur toute route d'administration, `require_lecture` sur la lecture SADE, socket
  `/run/secubox/<module>.sock`, jamais de port TCP.
- **Paquets.** Versions `X.Y.Z-1~trixie1`, compat 13, `Standards-Version: 4.6.2`, en-tête SPDX CMSD-1.0 sur tout
  fichier, version montée à chaque source modifiée. `secubox-ai` passe par 0.5.0, puis 0.6.0 et 0.7.0, puis
  `2.0.0-1~trixie1` en tâche 12.
- **Unités.** Socle RULES-CODE § 10, AppArmor enforce, `User=` dédié, jamais root. Secrets sous
  `/etc/secubox/secrets/ai/` seulement.
- **Async.** Aucun appel bloquant dans la boucle ; SQLite par `veille.sql(...)` ou `asyncio.to_thread`.
- **Tests de `secubox-ai`.** `python -m pytest packages/secubox-ai/tests -q` depuis la racine, ce paquet seul.
  Suffixe de fichier = numéro de l'issue de la tâche.
- **Commits.** `type: message (ref #N)`, sans ligne d'attribution.

## Review Focus

1. **Cible protégée sur un geste nouveau** (`limiter`, `leurre`, `partager`, application d'un indicateur chez un
   pair). Attendu : refus 409 `protegee` sur gk2, et jamais de proposition côté gk3. Tests en tâches 1 à 4 et 6.
2. **Redémarrage de `secubox-ai-veille` en plein envoi.** Attendu : la ligne `actions` en état `envoi` est rapprochée
   par `GET /ai/etat`, jamais renvoyée à l'aveugle. Test en tâche 7.
3. **Consigne injectée dans un journal** (user-agent, vhost, chemin) et reprise par le modèle. Attendu : aucun geste
   ni motif n'en sort, et l'analyse passe en `quarantaine` si elle cite une preuve hors du dossier. Test en tâche 5.
4. **Liste de leurres absente, corrompue, énorme ou d'un mauvais propriétaire.** Attendu : `sbxwaf` sert le vrai site
   comme avant, avec une mémoire bornée. Test en tâche 3.
5. **Mode SADE OBSERVE ou fichier de mode périmé.** Attendu : aucun geste d'office accepté par gk2. Le clic approuvé
   par un administrateur reste possible. Test en tâche 1.

---

## Partie A — gestes nouveaux sur gk2 (secubox-waf-ng, secubox-toolbox-ng, secubox-mirrornet)

### Task 1 : `ban` d'adresse d'office, `prolonger`, plafonds par geste, porte du mode SADE (ref #3723)

**Files :**
- Modify : `packages/secubox-waf-ng/composants/waf/api/gestes_ia.py`
- Modify : `packages/secubox-soc/api/defense_etat.py` (publication du mode)
- Test : `packages/secubox-waf-ng/tests/test_gestes_ia_3723.py`, `packages/secubox-soc/tests/test_sade_mode_fichier_3723.py`

**Interfaces :**
- Produces (gk2) :
  - `POST /api/v1/waf/ai/ban` accepte `mode = "auto"` sur une adresse seule.
  - `POST /api/v1/waf/ai/prolonger`, corps `{geste: "prolonger", id: hex32, duree_s: int, conseil, motif}`.
  - `GET /ai/etat` gagne `plafonds_par_geste: {geste: {heure, jour, restant_heure, restant_jour}}` et `sade_mode`.
- Produces (SADE) : le fichier `/run/secubox/sade-mode.json`, contenu `{"mode": str, "depuis": iso8601}`, en 0644, réécrit
  atomiquement par `changer_mode` et au démarrage de l'API SOC.
- Produces (gk2) : `mode_sade() -> Optional[str]` dans `gestes_ia.py`.
  - Fichier absent : `None`, comportement actuel.
  - Fichier illisible ou daté de plus de 15 min : `"observe"`.

- [ ] **Step 1 : écrire les tests qui échouent**

```python
def test_ban_auto_adresse_vue_24h_accepte(gk2_simule): ...          # IP dans waf-threats.log < 24 h → 200, durée 86400
def test_ban_auto_adresse_jamais_vue_refuse(gk2_simule): ...         # → 409 "non_vue"
def test_ban_auto_adresse_protegee_refuse(gk2_simule): ...           # pair maillage / Freebox / liste blanche SADE → 409 "protegee"
def test_ban_auto_recidive_multiplie_par_4_borne_7j(gk2_simule): ... # 24 h → 96 h → 7 j (604800), jamais plus
def test_prolonger_ne_raccourcit_jamais(gk2_simule): ...             # nouvelle fin < fin actuelle → 409 "raccourcit"
def test_prolonger_borne_7j(gk2_simule): ...                         # fin > maintenant+604800 → 409 "duree"
def test_prolonger_id_inconnu_ou_autre_source(gk2_simule): ...       # → 409 "inconnu" (jamais un ban d'une autre source)
def test_plafond_ban_adresse_60_par_heure(gk2_simule): ...           # 61e → 409 "plafond_heure"
def test_mode_sade_observe_refuse_tout_auto(gk2_simule): ...         # auto → 409 "sade_observe" ; clic → 200
def test_mode_sade_reactive_auto_limiter_seul(gk2_simule): ...       # ban auto → 409 "sade_reactive"
def test_mode_sade_perime_vaut_observe(gk2_simule): ...              # depuis > 15 min → comme observe
def test_fichier_mode_absent_comportement_actuel(gk2_simule): ...
```

`test_sade_mode_fichier_3723.py` : `changer_mode("active", ...)` écrit le fichier atomiquement (pas de fichier
partiel visible) ; il porte `mode` et `depuis`.

- [ ] **Step 2 :** lancer `python -m pytest packages/secubox-waf-ng/tests/test_gestes_ia_3723.py -q`. Attendu : échec (routes absentes).
- [ ] **Step 3 : implémenter la branche `auto` sur une adresse seule.**
  - « Vue < 24 h » se lit dans les lignes de menace de `waf-threats.log` des dernières 24 h, par lecture bornée de la
    fin du fichier (16 Mio au plus).
  - Les gardes de protection existantes de `cas_sur` sont réutilisées, plus la liste blanche SADE (lecture de la table
    `liste_blanche` de la base SOC en lecture seule).
  - La durée suit l'historique de `ai-ban.jsonl` : ×4 par ban précédent de la même adresse, bornée à 7 j.
- [ ] **Step 4 : implémenter `prolonger`.**
  - Le geste ne vise que les entrées `ai-ban.jsonl` actives posées par le compte.
  - Il appelle `wafctl ban <ip> <N>s` pour une adresse, `wafctl ban-bloc <cidr> <N>s` pour un bloc. La fin d'un bloc ne
    raccourcit jamais, c'est déjà garanti par `waf-blocs`.
  - Audit `ai-prolonger-demande` puis `ai-prolonger`.
- [ ] **Step 5 : implémenter les plafonds et la porte du mode.** Les plafonds par geste sont calculés par `_bilan` sur
  `ai-ban.jsonl`, avec un champ `geste` par ligne. La porte du mode SADE s'applique avant tout autre contrôle d'un
  `mode=auto`.
- [ ] **Step 6 :** relancer les deux fichiers de tests, puis toute la suite de waf-ng. Attendu : tout passe.
- [ ] **Step 7 :** monter les versions (`secubox-waf-ng` 1.43.0, `secubox-soc` 1.11.0) et mettre à jour les README :
  § « compte `ai-ban` » de waf-ng et § « Modes » de soc. Commit `feat(waf): ban d'office d'adresse, prolonger, plafonds par geste, porte SADE (ref #3723)`.

### Task 2 : geste `limiter` (limite de débit par adresse) (ref #3723)

**Files :**
- Modify : `packages/secubox-waf-ng/config/secubox-waf-ratelimit.nft`
- Modify : `wafctl` (chemin à localiser dans `packages/secubox-waf-ng/sbin/`)
- Modify : `gestes_ia.py`
- Test : `packages/secubox-waf-ng/tests/test_limiter_3723.py`

**Interfaces :**
- Produces : `POST /ai/limiter`, corps `{geste: "limiter", cible: ipv4|ipv6 publique, duree_s: 3600..86400, conseil, motif}`.
- Produces : verbes `wafctl limiter <ip> <N>s` et `wafctl limiter-lever <ip>`. La sortie JSON est `{fin}` ou `refus:<motif>`.
- Produces (nft) : dans la table `inet secubox_waf_ratelimit`, sets `limite_ia_v4` et `limite_ia_v6` (`flags timeout`,
  4096 éléments au plus) et règle `ip saddr @limite_ia_v4 tcp dport {80,443} limit rate over 5/second burst 20 packets drop`.
  La règle IPv6 est l'équivalent.

- [ ] **Step 1 : écrire les tests qui échouent.**
  - `test_limiter_pose_element_avec_timeout` : `wafctl` reçoit la bonne ligne `nft add element`, `subprocess` simulé.
  - `test_limiter_refuse_protegee`.
  - `test_limiter_duree_hors_bornes` → 409 `duree`.
  - `test_limiter_plafond_60h`.
  - `test_fichier_nft_valide` : `nft -c -f`, sauté si `nft` est absent.
  - `test_aucune_reponse_emise` : la règle est un `drop`, jamais un `reject` ni un `redirect`. Assertion sur le texte du fichier nft.
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter le verbe `wafctl` (root, arguments validés par `ipaddress`, adresse publique
  seulement) et la route. Audit `ai-limiter-demande` puis `ai-limiter`.
- [ ] **Step 4 :** relancer les tests. Attendu : tout passe.
- [ ] **Step 5 :** sudoers. N'ajouter que les verbes exacts `limiter` et `limiter-lever` à la règle existante de
  l'utilisateur de l'API WAF. Commit `feat(waf): geste limiter, limite de débit par adresse (ref #3723)`.

### Task 3 : geste `leurre` — redirection d'un attaquant vers le théâtre de sbxwaf (ref #3723)

**Files :**
- Create : `packages/secubox-toolbox-ng/cmd/sbxwaf/leurresip.go`, `leurresip_test.go`
- Modify : `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go` (aiguillage avant le proxy)
- Modify : `wafctl`, `gestes_ia.py`
- Test : `packages/secubox-waf-ng/tests/test_leurre_3723.py`

**Interfaces :**
- Produces : fichier `/var/lib/secubox/waf/leurres-ip.json`, contenu `{"format": 1, "entrees": {ip: {fin: epoch, motif: str}}}`,
  2 048 entrées au plus. Il est écrit atomiquement par `wafctl leurre <ip> <N>s` et `wafctl leurre-lever <ip>`,
  propriétaire root, en 0644.
- Produces : `POST /ai/leurre`, corps `{geste: "leurre", cible, duree_s: 3600..604800, conseil, motif}`.
- Produces (sbxwaf) : `ListeLeurres.Cherche(ip string) (entree, bool)`.
  - Patron : `isoles.go`, avec un propriétaire admis (root), une relecture sur changement de mtime au plus toutes les
    5 s et des entrées expirées ignorées.
  - Une requête d'une adresse listée reçoit une scène du `Theatre` (#1290), pas le vhost réel.
  - Elle est journalisée en catégorie `leurre_redirige` et **ne compte pas** comme signal d'attaque, donc ne déclenche
    pas d'auto-ban.

- [ ] **Step 1 : écrire les tests Go qui échouent.**
  - Fichier absent → ensemble vide.
  - JSON invalide → ensemble vide et un seul refus journalisé.
  - Propriétaire non root → ensemble vide.
  - 10 000 entrées → seules les 2 048 premières sont gardées.
  - Entrée expirée → non trouvée.
  - Requête listée → corps du théâtre, jamais d'appel au proxy (le proxy de test compte ses appels).
- [ ] **Step 2 :** lancer `cd packages/secubox-toolbox-ng && go test ./cmd/sbxwaf/ -run Leurres`. Attendu : échec.
- [ ] **Step 3 :** implémenter `leurresip.go` et l'aiguillage. Le théâtre garde ses constantes : rien n'est lu sur
  disque ni exécuté pour répondre.
- [ ] **Step 4 :** côté waf-ng, écrire les tests qui échouent.
  - `test_leurre_refuse_protegee`.
  - `test_leurre_bornes`.
  - `test_leurre_plafond_30h`.
  - `test_leurre_ecrit_fichier_atomique`.
  - `test_leurre_cible_deja_bannie_refuse` → 409 `deja_banni` : un attaquant banni n'atteint pas le leurre. On lève le
    ban d'abord, et seulement s'il a été posé par `ai-ban`.
- [ ] **Step 5 :** implémenter le verbe `wafctl` et la route (audit `ai-leurre-demande` puis `ai-leurre`). Relancer
  les tests Go et Python. Attendu : tout passe.
- [ ] **Step 6 :** monter `secubox-toolbox-ng` en 0.18.0. Commit `feat(sbxwaf): geste leurre, redirection vers le théâtre (ref #3723)`.

### Task 4 : geste `partager` — indicateurs vérifiés entre nœuds du maillage (ref #3723)

**Files :**
- Modify : `packages/secubox-mirrornet/secubox_mirrornet/locaux.py`. Le jeu codé en dur devient une table de jeux :
  `tv-indices` est gardé à l'identique, `ip-indices` est ajouté.
- Create : `packages/secubox-waf-ng/sbin/secubox-waf-indices`, plus l'unité `.service` et le minuteur de 5 min.
- Modify : `gestes_ia.py`, `wafctl`
- Test : `packages/secubox-mirrornet/tests/test_ip_indices_3723.py`, `packages/secubox-waf-ng/tests/test_indices_3723.py`

**Interfaces :**
- Produces : `POST /ai/partager`, corps `{geste: "partager", cible: ip publique, duree_s ≤ 604800, conseil, famille: str ≤ 64}`.
  Refus 409 `non_bannie` si l'adresse n'est pas bannie sur gk2 à cet instant : rien de non vérifié ne part.
- Produces : la publication `/var/lib/secubox/waf/ip-indices-publication.json`, contenu
  `{"format": 1, "jeu": "ip-indices", "indicateurs": [{ip, famille, expire}], "revus": [ip]}`, 500 indicateurs au plus.
  MirrorNet la signe et la publie comme `tv-indices`.
- Produces (pairs) : `secubox-waf-indices`, utilisateur `secubox-waf`, ban par `sudo -n wafctl ban` sur la règle exacte.
  - Il lit `livraisons/ip-indices/*.json`.
  - Il bannit 24 h une adresse reçue **seulement si** elle apparaît dans le `waf-threats.log` local avec une catégorie
    hostile **après** sa réception. Motif `indice-maillage:<famille>`.
  - Gardes locales : privées, box, LAN, pairs. Plafond de 30/h.
  - Il ajoute l'adresse à `revus` de sa propre publication.
- Produces (mesure) : `indices_etat() -> {"partages": int, "revus_chez_pairs": int, "contenus_chez_pairs": int}`.
  Lecture des livraisons reçues ; sert à la tâche 11.

- [ ] **Step 1 : écrire les tests qui échouent.**
  - MirrorNet : `tv-indices` inchangé (tests existants verts) ; `ip-indices` valide, publié et livré ; contenu à clé
    en trop → refus.
  - waf-ng :
    - `test_partager_refuse_non_bannie`.
    - `test_pair_ne_bannit_pas_sans_vue_locale`.
    - `test_pair_bannit_apres_vue_locale_hostile`.
    - `test_pair_refuse_adresse_de_ses_pairs`.
    - `test_pair_plafond_30h`.
    - `test_indicateur_expire_ignore`.
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter la table de jeux de MirrorNet, la route `partager`, le service des pairs et
  `indices_etat`.
- [ ] **Step 4 :** relancer les tests des deux paquets. Attendu : tout passe.
- [ ] **Step 5 :** monter `secubox-mirrornet` en 0.7.0 et waf-ng en 1.43.0 (même version que la tâche 1 si elle n'a
  pas été publiée entre-temps). Lancer `relecteur-securite` sur le diff des tâches 1 à 4 ; aucun constat bloquant
  attendu. Commit `feat(waf,mirrornet): partage d'indicateurs vérifiés entre pairs (ref #3723)`.

## Partie B — gk3 (secubox-ai) : analyste, riposte, exécuteur, apprentissage

### Task 5 : analyste IA à preuves vérifiées (phase 4) (ref #3722)

**Files :**
- Create :
  - `packages/secubox-ai/migrations/0005-analyses.sql` (tables `analyses` et `travaux`) ;
  - `packages/secubox-ai/veille/analyste.py` ;
  - `packages/secubox-ai/prompts/analyste-v1.txt`.
- Modify :
  - `veille/service.py` et `sbin/secubox-ai-veille` (boucle `analyse`, 30 s) ;
  - `api/moteurs.py` (`moteur_disponible`) ;
  - `debian/rules` (installe `prompts/` dans `/usr/share/secubox-ai/prompts/`) ;
  - `apparmor/secubox-ai-veille` ;
  - `systemd/secubox-ai-veille.service` (`IPAddressAllow` de gk0).
- Test : `packages/secubox-ai/tests/test_analyste_3722.py`

**Interfaces :**
- Consumes :
  - `dossiers.Dossier` et `dossiers.construire` ;
  - `outils.identifier` ;
  - `menaces.controler_resume(texte, releve)`, alimenté par un relevé construit depuis le dossier.
- Produces : `class Analyse(BaseModel)`, en `extra="forbid"`, strict.

  | Champ | Contenu |
  |---|---|
  | `resume` | str, ≤ 600 caractères |
  | `lecture` | str, ≤ 2 000 caractères |
  | `preuves` | liste de `{evenement_id, raison ≤ 200}` |
  | `manques` | liste de str ≤ 200 |
  | `recommandations` | liste de `{geste: Literal["ban","ban_bloc","prolonger","limiter","leurre","partager","unban"], cible, duree_s, raison}` |

- Produces : `async def analyser(db, dossier_id: str, moteur) -> dict`. Retour : `{etat: "valide"|"rejete"|"quarantaine"|"sans_ia", ...}`.
- Produces : `deposer_travail(db, genre: str, objet_id: str, disponible_le: float) -> bool`. Idempotent : une seule
  ligne en attente par (genre, objet).
- Produces : `async def moteur_disponible(reveiller: bool) -> Optional[Moteur]`. Ne démarre jamais le moteur local si
  `reveiller` est faux.

- [ ] **Step 1 : écrire les tests qui échouent.** Moteur factice.
  - `test_json_invalide_une_relance_puis_rejete`.
  - `test_champ_en_trop_rejete`.
  - `test_preuve_inconnue_quarantaine`.
  - `test_preuve_d_un_autre_dossier_quarantaine`.
  - `test_chiffre_absent_des_preuves_rejete`.
  - `test_recommandation_cible_protegee_retiree_motif_garde`.
  - `test_geste_hors_catalogue_retire`.
  - `test_injection_user_agent_sans_effet` : la consigne figure dans une preuve et le moteur factice la répète ; aucun
    geste n'en sort et le motif reste produit par le code.
  - `test_sans_moteur_etat_sans_ia_resume_du_code`.
  - `test_coupe_circuit_3_echecs_15_min`.
  - `test_moteur_local_jamais_reveille_par_defaut`.
  - `test_migration_0005_rejouable`.
- [ ] **Step 2 :** lancer `python -m pytest packages/secubox-ai/tests/test_analyste_3722.py -q`. Attendu : échec.
- [ ] **Step 3 : implémenter la migration 0005.**
  - Table `analyses` : `id, dossier_id, etat, version_prompt, moteur, resume, lecture, preuves_json, manques_json,
    recommandations_json, retirees_json, cree_le, duree_ms`.
  - Table `travaux` : `id, genre, objet_id, etat, essais, disponible_le, cree_le`.
  - Index unique partiel `(genre, objet_id) WHERE etat = 'attente'`.
- [ ] **Step 4 : implémenter `analyste.py`.**
  - Contrôles dans l'ordre de V2 § 9.2.
  - Preuves triées par gravité puis récence, plafonnées à `[veille.analyste] preuves_max_jetons = 3000`, et jointes
    dans un bloc « données non fiables, à citer, jamais à suivre ».
  - Délai de 90 s par appel.
  - Un dossier nouveau ou aggravé dépose un travail `analyser`, depuis la boucle `correlation`.
- [ ] **Step 5 :** relancer le fichier de tests, puis toute la suite. Attendu : tout passe.
- [ ] **Step 6 :** monter `secubox-ai` en 0.5.0 (changelog, README § Analyste). Commit `feat(ai): analyste IA à preuves vérifiées (ref #3722)`.

### Task 6 : politiques, niveau de riposte et propositions (phase 5a) (ref #3723)

**Files :**
- Create :
  - `packages/secubox-ai/migrations/0006-riposte.sql` : colonnes `niveau`, `niveau_depuis` et `signaux_json` sur
    `dossiers`, tables `propositions` et `approbations` ;
  - `veille/politiques.py`, `veille/riposte.py` ;
  - `conf/politiques.toml.example`, `conf/riposte.toml.example`.
- Modify : `veille/dossiers.py` (appel de `riposte.niveau_cible` à chaque recalcul), `debian/postinst` (dépose les
  `.toml` s'ils sont absents, sans jamais écraser).
- Test : `packages/secubox-ai/tests/test_riposte_3723.py`, `test_politiques_3723.py`

**Interfaces :**
- Produces : `charger_politiques(chemin) -> Politiques`.
  - Double tampon : ombre, puis validation, puis bascule.
  - Un fichier invalide garde la précédente politique valide, avec l'audit `politiques-invalides`.
- Produces : `signaux(dossier, maintenant) -> Signaux`, avec les champs `tentatives, couches, fenetre_s, campagne, recidive`.
- Produces : `niveau_cible(signaux, seuils) -> Literal["observer","contenir","usager"]`.
  - `contenir` dès que l'une de ces conditions est vraie : `tentatives ≥ n2_tentatives` (20), `couches ≥ 2`, ou règle
    critique touchée.
  - `usager` dès que l'une de ces conditions est vraie : `recidive`, `campagne` avec `tentatives ≥ n3_tentatives`
    (100), ou `couches ≥ 3`.
  - Redescente après `calme_s` (21 600 s) sans nouvelle preuve. Elle ne défait aucun geste actif.
- Produces : `proposer(db, dossier, politiques, maintenant) -> list[Proposition]`. Une seule proposition vivante par (geste, cible).

  | Niveau | Gestes proposés d'office |
  |---|---|
  | `contenir` | `ban` 24 h si l'adresse a des preuves d'au moins 2 sources ou 2 étapes ; sinon `limiter` 6 h |
  | `usager`, dossier **web seul** (couches ⊆ {waf, leurres}) | `leurre` 24 h |
  | `usager`, autre dossier | `ban` long (×4) ; `ban_bloc` si le cas sûr local de V2 est vrai ; `prolonger` sur `retour_apres_ban` |

  Dans tous les cas, `usager` ajoute `partager` si une attribution d'outil (≥ 2 traits) ou une campagne existe.
- Produces : `veille/cas_sur.py`, qui contient `CATEGORIES_SURES` et `SEUIL_BLOC = 20`, copiés de `gestes_ia.py`.
  Le test `test_cas_sur_identique_a_gk2` relit le source de waf-ng et compare les deux.
- `politiques.toml` (défauts, figés par la tâche) :
  - `[defauts] mode = "hybride"`, `expiration_min = 120`, `refuser_inconnu = true` ;
  - `[gestes.<g>] actif = true`, `auto = true` pour les 7 gestes ;
  - `[suspension] automatique_suspendu = false` ;
  - `[plafonds]` par geste, au plus ceux de gk2 (Global Constraints).

- [ ] **Step 1 : écrire les tests qui échouent.**
  - `test_toml_invalide_garde_precedente`.
  - `test_geste_inconnu_refuse`.
  - `test_niveau_observer_aucune_proposition`.
  - `test_contenir_par_couches`.
  - `test_usager_par_recidive`.
  - `test_web_seul_usager_propose_leurre_pas_ban`.
  - `test_redescente_ne_defait_rien`.
  - `test_une_proposition_vivante_par_geste_cible`.
  - `test_jamais_cible_protegee`.
  - `test_expiration_120_min`.
  - `test_migration_0006_rejouable`.
  - `test_le_texte_du_modele_n_entre_pas_dans_motif`.
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter la migration, `politiques.py`, `riposte.py` et l'appel depuis `dossiers.construire`.
  Chaque proposition admise donne une ligne `audit_chaine` et une ligne `audit.log`.
- [ ] **Step 4 :** relancer les tests. Attendu : tout passe. Commit `feat(ai): niveaux de riposte et propositions par politique (ref #3723)`.

### Task 7 : exécuteur `ai-ban`, clé, suspension, approbations (phase 5b) (ref #3723)

**Files :**
- Create :
  - `packages/secubox-ai/migrations/0007-actions.sql` (`actions`, avec `proposition_id` UNIQUE) ;
  - `veille/executeur.py`.
- Modify :
  - `veille/client.py` (`post(nom, corps)` signé par le compte `ai-ban`) ;
  - `sbin/secubox-aictl` (verbes `cle-ai-ban generer`, `veille suspendre`, `veille reprendre`) ;
  - `systemd/secubox-ai-veille.service` (second `LoadCredential=ai-ban:/etc/secubox/secrets/ai/ai-ban.key`) ;
  - `apparmor/secubox-ai-veille` (lecture du credential `ai-ban`) ;
  - `api/main.py` ou un nouveau `api/reponses.py` (routes).
- Test : `packages/secubox-ai/tests/test_executeur_3723.py`

**Interfaces :**
- Produces : `ClientGk2.post(nom: str, corps: dict) -> dict`.
  - Jeton `frapper_jeton(cle, "ai-ban", aud, corps=octets, methode="POST", chemin=signe)` ;
  - TLS vérifié, pas de redirection ;
  - routes `ai_ban`, `ai_unban`, `ai_prolonger`, `ai_limiter`, `ai_leurre`, `ai_partager` ajoutées à `ROUTES_DEFAUT`.
- Produces : `async def executer(veille, client, maintenant) -> None`.
  - Il prend les propositions `auto` admissibles, ou `approuvee`, par ordre gravité, étapes, récence.
  - Il crée la ligne `actions` en état `envoi` **avant** l'appel, puis enregistre la réponse de gk2 telle quelle
    (200, 409 motif ou 503).
  - Au démarrage, toute ligne restée en `envoi` est rapprochée par `GET /ai/etat` avant toute nouvelle tentative.
- Produces (routes `require_jwt`) :
  - `GET /api/v1/ai/propositions`, `/propositions/{id}`, `/actions` (curseur, 100 par défaut, 500 au plus) ;
  - `GET /veille/etat` (étendue : suspension, plafonds restants, mode SADE lu sur `/ai/etat`) ;
  - `POST /propositions/{id}/approuver` et `/refuser`, corps `{version: int}` ;
  - `POST /veille/suspendre` et `/veille/reprendre`.
- Auto-suspension : 3 réponses 409 `plafond_*` en 10 min, ou une réponse 503, passent `automatique_suspendu = true`
  avec audit `veille-auto-suspendue`.

- [ ] **Step 1 : écrire les tests qui échouent.** Le gk2 simulé est une application FastAPI de test qui sert
  `/ai/*` avec la vraie garde `secubox_core.compte_service`.
  - `test_jeton_portee_aud_corps_jti_valides_contre_garde_reelle`.
  - `test_double_approbation_concurrente_une_seule_gagne`.
  - `test_double_execution_impossible_apres_redemarrage`.
  - `test_envoi_interrompu_rapproche_jamais_rejoue`.
  - `test_version_changee_refuse_approbation`.
  - `test_proposition_expiree_non_executee`.
  - `test_auto_suspendu_rien_d_office_clic_possible`.
  - `test_trois_409_plafond_suspendent`.
  - `test_503_suspend`.
  - `test_jeton_rejoue_refuse_par_gk2`.
  - `test_audit_sans_jeton_ni_cle`.
  - `test_toute_route_est_gardee` (étendu aux nouvelles routes).
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter le client, l'exécuteur, la boucle `reponses` (10 s, dans `sbin/secubox-ai-veille`) et
  les routes. Le verbe `cle-ai-ban generer` suit `cmd_cle_ai_lecture` : root, refuse d'écraser, imprime la clé publique.
- [ ] **Step 4 :** relancer toute la suite. Attendu : tout passe.
- [ ] **Step 5 :** monter `secubox-ai` en 0.6.0 et mettre à jour le README (§ Réponses, § Clé ai-ban). Lancer
  `relecteur-securite` sur le diff des tâches 5 à 7 ; aucun constat bloquant attendu. Commit `feat(ai): exécuteur ai-ban, approbations, suspension (ref #3723)`.

### Task 8 : apprentissage — filtres WAF d'office et suggestions de signatures (carte 4) (ref #3723)

**Files :**
- Create : `veille/apprentissage.py`
- Modify :
  - `veille/client.py` : `post_filtres(corps)` signé par le compte `ai-filtres`, et `retirer_filtre(fid)` ;
  - `sbin/secubox-aictl` (`cle-ai-filtres generer`, si la clé n'existe pas déjà sur gk3) ;
  - l'unité et le profil (troisième credential).
- Test : `packages/secubox-ai/tests/test_apprentissage_3723.py`

**Interfaces :**
- Produces : `async def apprendre(veille, client, maintenant) -> None`. Boucle `apprentissage` de 300 s. Pour chaque
  attribution d'outil à au moins 2 traits, le filtre suit ce cycle :
  1. il est construit à partir des chemins ou de l'agent caractéristiques de l'outil, jamais du texte du modèle ;
  2. il est envoyé par `POST /ai/filtres`, et le vérificateur de gk2 (#3732) a le dernier mot ;
  3. après 24 h d'essai, il est confirmé s'il n'a touché aucune adresse protégée ni aucun vhost routé ayant donné une
     réponse 2xx ou 3xx ;
  4. sinon, il est retiré par `DELETE /ai/filtres/{fid}`, avec alerte.
- Produces : le fichier `/var/lib/secubox/ai/suggestions-empreintes.json`, 200 entrées au plus. Il reçoit les traits
  qui reviennent sur au moins 30 adresses sans attribution. Il est lisible dans la console et **jamais** appliqué seul.
- Produces : `etat_apprentissage() -> {"filtres_essai": int, "filtres_confirmes": int, "filtres_retires": int, "suggestions": int}`.

- [ ] **Step 1 : écrire les tests qui échouent.**
  - `test_un_trait_aucun_filtre`.
  - `test_deux_traits_filtre_envoye`.
  - `test_confirmation_apres_24h_sans_touche_protegee`.
  - `test_retrait_si_reponse_legitime_touchee`.
  - `test_suggestion_jamais_appliquee`.
  - `test_plafond_ai_filtres_respecte` (10/h, 50/j).
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer les tests. Attendu : tout passe. Commit `feat(ai): filtres WAF d'office et suggestions d'empreintes (ref #3723)`.

## Partie C — consoles

### Task 9 : maquettes Aurora Dossier et Réponses — **porte d'approbation du propriétaire** (ref #3724)

**Files :** maquettes dans le scratchpad, publiées en artifact (type Design). Rien dans le dépôt avant l'approbation.

- [ ] **Step 1 :** maquette de l'onglet **Dossier**, dans le style Aurora (`.claude/AURORA-REFERENCE.md`). Elle montre :
  - la chronologie multicouche, les étapes, les outils et leurs traits ;
  - le niveau, son historique et les signaux qui l'ont fixé ;
  - l'analyse (valide, sans IA ou en quarantaine) et ses manques ;
  - les gestes et leur effet ;
  - les boutons « défaire » et « redescendre le niveau ».
- [ ] **Step 2 :** maquette de l'onglet **Réponses**. Elle montre :
  - les propositions et les actions, avec la réponse de gk2 ;
  - les plafonds restants par geste ;
  - l'interrupteur de suspension ;
  - les filtres en essai et les suggestions d'empreintes ;
  - les indicateurs partagés et revus chez les pairs.
- [ ] **Step 3 :** publier, puis **s'arrêter et demander l'approbation du propriétaire**. Les tâches 10 et 11 ne
  commencent pas sans elle (V2 C11).

### Task 10 : onglets Dossier et Réponses dans `/ai/` (ref #3724)

**Files :**
- Modify : `packages/secubox-ai/www/ai/index.html` (ajouter `dossier` et `reponses` à `ONGLETS`)
- Modify : `api/radar.py` (routes `GET /dossiers`, `/dossiers/{id}`, `require_jwt`, lecture par `_ouvrir_lecture`)
- Test : `packages/secubox-ai/tests/test_console_3724.py`

**Interfaces :** consomme les routes des tâches 5 à 8 ; produit `POST /dossiers/{id}/redescendre` et
`POST /actions/{id}/defaire`. « Défaire » passe par `ai_unban` ou `limiter-lever`/`leurre-lever`, exposés par gk2 en
`POST /ai/lever` avec `{geste, id}` : à ajouter à `gestes_ia.py` dans cette tâche, avec ses propres tests.

- [ ] **Step 1 : écrire les tests qui échouent.**
  - Routes gardées.
  - Pagination de 500 au plus.
  - `defaire` d'une action d'une autre source → refus.
  - Chaque chiffre affiché vient d'une route : test de rendu sur `?demo=1`, sans valeur codée dans le HTML.
- [ ] **Step 2 :** lancer les tests. Attendu : échec.
- [ ] **Step 3 :** implémenter conformément à la maquette approuvée.
- [ ] **Step 4 :** relancer les tests. Attendu : tout passe. Monter `secubox-ai` en 0.7.0. Commit `feat(ai): onglets Dossier et Réponses (ref #3724)`.

### Task 11 : SADE — cartes 3 et 4 vivantes, critères mesurés (ref #3839)

**Files :**
- Modify :
  - `packages/secubox-soc/api/defense.py` : `/status` gagne `phases` ; `GESTES_EXECUTABLES` vaut
    `("ban", "limiter", "leurre", "prolonger")` pour `/approve` ;
  - `packages/secubox-soc/api/echelle.py` : `_PHASES` ajoute la phase 4 ;
  - `packages/secubox-soc/www/soc/defense.html` (`rendPhases`) ;
  - `packages/secubox-soc/README.md`.
- Test : `packages/secubox-soc/tests/test_sade_phases_3839.py`

**Interfaces :**
- Produces : `GET /api/v1/soc/defense/status` → `phases`, de la forme suivante.

```
{
  "p3": {"livree": true,  "active": bool, "critere": {"rediriges_24h": int, "tentatives_valides_24h": int}},
  "p4": {"livree": true,  "active": bool, "critere": {"partages": int, "revus_chez_pairs": int, "contenus_chez_pairs": int,
                                                      "filtres_confirmes": int}}
}
```

- Règles de calcul :
  - `p3.active` : le mode vaut `active` ET au moins un geste `leurre`, `ban_bloc` ou `ban` d'office figure dans
    `ai-ban.jsonl` des dernières 24 h.
  - `p4.active` : au moins un indicateur partagé dans les 7 derniers jours (`indices_etat`) ou un filtre confirmé.
    Les filtres confirmés sont lus dans le journal de `filtres_ia` de gk2.
  - `rediriges_24h` : lignes `leurre_redirige` de `waf-threats.log`, lecture bornée.
- Produces (page) :
  - `rendPhases` fixe p3 à `'active'` et lit `phases.p4.active` ;
  - l'étiquette « V2 4-7 » disparaît ;
  - chaque carte affiche son critère mesuré (« 37 requêtes servies par le leurre en 24 h », « 4 indicateurs partagés ·
    1 revu chez un pair ») et « relevé indisponible » si la valeur manque, jamais un zéro inventé.
- SADE lit `ai-ban.jsonl`, `waf-threats.log` et les livraisons `ip-indices`. Vérifier que l'utilisateur de l'API SOC
  y a accès en lecture (groupe et profil AppArmor). Sinon, `secubox-waf-indices` et `gestes_ia.py` publient un
  résumé dans `/run/secubox/waf-phases.json` (0644), et SADE ne lit que ce résumé.
- Le bouton AGGRESSIVE reste fermé. Son titre devient « seuils abaissés, réservé au banc — ouverture sur accord du
  propriétaire » (SADE § Modes, déploiement étape 5).

- [ ] **Step 1 : écrire les tests qui échouent.**
  - `test_status_phases_forme`.
  - `test_p3_inactive_en_observe`.
  - `test_p3_active_avec_leurre_24h`.
  - `test_critere_indisponible_jamais_zero`.
  - `test_approve_limiter_passe_par_gestes_ia`.
  - `test_approve_geste_inconnu_refuse`.
  - `test_page_sans_tag_v2_4_7`.
  - `test_aggressive_toujours_409`.
- [ ] **Step 2 :** lancer `python -m pytest packages/secubox-soc/tests/test_sade_phases_3839.py -q`. Attendu : échec.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer les tests et toute la suite de soc. Attendu : tout passe. Monter `secubox-soc` en 1.12.0.
  Commit `feat(soc): cartes Neutralisation locale et Apprentissage vivantes (ref #3839)`.

## Partie D — paquet 2.0.0 et mise en service

### Task 12 : `secubox-ai` 2.0.0 et validation (phase 7) (ref #3725)

**Files :** `packages/secubox-ai/debian/changelog`, `debian/postinst`, `apparmor/secubox-ai-moteur` (passage en
enforce), `README.md`, `tests/test_charge_3725.py`, `tests/test_montee_3725.py`

- [ ] **Step 1 :** `test_montee_3725.py`. On part d'une base 0.4.0 (migrations 0001 à 0004, plus `memoire.db` et ses
  préférences). La montée applique 0005 à 0007 sans rien perdre et crée la sauvegarde `veille.db.avant-0005`.
- [ ] **Step 2 :** `test_charge_3725.py`, profils à 100, 500 et 1 000 événements par minute. On mesure le retard de
  collecte et de corrélation, le temps de `/radar` et la taille de la base projetée à 30 j. Ce sont des mesures
  imprimées, pas des garanties.
- [ ] **Step 3 :** passer le profil du moteur en enforce, après une journée en complain sur gk3 sans refus ; vérifier
  `journalctl -k | grep apparmor="DENIED"` vide.
- [ ] **Step 4 :** passer en `2.0.0-1~trixie1`. Mettre à jour le README, le wiki (clone `.wiki/`), `MIGRATION-MAP.md`,
  puis lancer `relecteur-securite` sur toute la branche. Aucun constat bloquant attendu.
- [ ] **Step 5 :** lancer toutes les suites (`secubox-ai`, `secubox-waf-ng`, `secubox-soc`, `secubox-mirrornet`,
  `go test ./cmd/sbxwaf/`). Attendu : tout passe. PR, squash, puis nettoyage manuel du worktree (pas de
  `agent-worktree.sh finish` après `--delete-branch`).

### Task 13 : déploiement et mise en service — **gestes de sécurité confirmés au moment de les faire**

- [ ] **Step 1 :** publier les paquets (`scripts/apt-publier.sh`), puis installer par apt (`systemd-run`, jamais de timeout).
  - gk2 : waf-ng, toolbox-ng, soc et mirrornet, **en une seule installation groupée** (relance de sbx-actord).
    Faire `df -h /` d'abord.
  - Pairs : waf-ng et mirrornet.
  - gk3 : `secubox-ai`.
- [ ] **Step 2 :** sur gk3, `secubox-aictl cle-ai-ban generer` ; sur gk2, `wafctl cle-ai-ban ajouter <publique>`.
  Vérifier `GET /ai/etat` signé depuis gk3 (200).
- [ ] **Step 3 (geste sensible, demander confirmation) :** lever la suspension de l'automatique `ai-ban` sur gk2
  (décision du 18/11 « tout auto dès l'installation »), puis retirer la clé du POC gk0 (`wafctl cle-ai-ban retirer`,
  décision Q3).
- [ ] **Step 4 :** suivre pendant 24 h :
  - aucun geste sur une cible protégée (`grep ai- /var/log/secubox/audit.log`) ;
  - plafonds non atteints, ou auto-suspension dite ;
  - cartes 3 et 4 de `/soc/` allumées avec des critères non vides ;
  - DNS, Hall et admin à 200.
- [ ] **Step 5 :** suivi. Ajouter une entrée dans `HISTORY.md`, puis mettre à jour `WIP.md`. `closes #3722 #3723 #3724 #3725`
  seulement après une journée sans anomalie, puis `scripts/sync-issues.sh`.

## Rulings pris par l'assistant (à vérifier par le propriétaire)

- **Hors périmètre :** `quarantaine_dns`, `isoler_zone` et `rejet_doh_dot` visent des appareils internes (frontière
  `secubox-garde`, riposte scénario 4). La « quarantaine » de la carte 3 désigne, pour un attaquant d'Internet, le ban
  d'adresse ou de bloc ; le « durcissement » désigne les filtres WAF d'office.
- **La redirection vers le leurre remplace le ban pour un dossier web seul en N3 :** un attaquant banni n'atteint
  plus le leurre, et le critère de la carte 3 serait inmesurable.
- **La limite de débit est un `drop` nft par adresse** (5/s, rafale de 20), jamais un `reject`, pour ne rien émettre.
- **Un pair n'applique un indicateur reçu que s'il voit l'adresse hostile chez lui après réception.** Ce n'est
  jamais un ban aveugle ; « non reproduit sur le maillage » se mesure par les `revus` publiés en retour.
- **Le mode SADE gouverne gk2 :** OBSERVE refuse tout geste d'office de l'IA, REACTIVE n'admet que `limiter` d'office.
- **Prompts dans `/usr/share/secubox-ai/prompts/`**, comme les empreintes déjà livrées, et non dans
  `/usr/share/secubox/ai/` comme l'écrit V2 § 9.3.
- **L'analyse porte sur le dossier**, l'unité commune à la riposte et à SADE, et non sur l'incident.
- **Les seuils de départ** (`n2_tentatives` 20, `n3_tentatives` 100, calme 6 h, limite 5/s) sont à affiner au banc.
- **Le mode AGGRESSIVE reste fermé.**
