# SecuBox AI V2 — phases 1 à 3 (veille, collecteur, corrélateur, dossiers, outils) — plan

> **Pour les agents :** sous-compétence REQUISE : superpowers:subagent-driven-development (recommandé) ou
> superpowers:executing-plans, tâche par tâche. Étapes en cases à cocher (`- [ ]`).

**But :** sur gk3, un service `secubox-ai-veille` qui collecte en continu les sources de sécurité de gk2 (et ses
nouvelles sources : garde, actord, DNS, leurres), les relie en incidents puis en **dossiers d'attaquant** avec étapes
et **outils identifiés sur preuves**, sans encore agir (les réponses automatiques sont la phase 5, plan suivant).

**Architecture :** évolution du paquet `secubox-ai` (branche `feature/3583-secubox-ai-passer-le-poc-gk0-en-paquets`).
Un second processus Python `secubox-ai-veille` (seul écrivain de `/var/lib/secubox/ai/veille.db`, SQLite WAL) avec trois
boucles : collecte (30 s / 5 min selon la source), corrélation (60 s), rétention (horaire). Lecture de gk2 seulement par
GET signés du compte de service `ai-lecture` ; les routes manquantes s'ajoutent **dans les paquets propriétaires de
gk2**. Tout est déterministe : aucun appel au modèle de langue dans ce plan.

**Pile :** Python 3.13 (trixie), SQLite, httpx/aiohttp déjà utilisés par `secubox-ai` (voir `api/menaces.py`),
`secubox_core.compte_service` (jetons EdDSA), Go pour sbxwaf seulement si une route l'exige (aucune prévue).

**Spec :** `docs/superpowers/specs/2026-11-14-secubox-ai-v2-design.md` (§ 5-8, branche #3583),
`docs/superpowers/specs/2026-11-14-secubox-ai-v2-phase0-sources.md` (relevé réel, § 4-6, branche #3583),
complément `docs/superpowers/specs/2026-11-18-secubox-ai-v2-correlation-outils-auto-design.md` (branche
`feature/3795-ia-v2-complement`). Jeu de référence anonymisé : `packages/secubox-ai/tests/donnees/` (branche #3583).

## Contraintes globales

- `AGENTS.md`, `.claude/RULES-CODE.md` (§ 8 horodatages UTC RFC 3339, § 10 socle des services) ; utilisateur dédié
  `secubox-ai`, AppArmor enforce (profil `secubox-ai-veille`), aucun port TCP, aucun secret dans le code (clé privée
  `ai-lecture` sous `/etc/secubox/secrets/ai/ai-lecture.key`, root 0600, remise par `LoadCredential=`).
- `veille.db` : WAL, `foreign_keys = ON`, `busy_timeout = 5000`, migrations `/usr/lib/secubox/ai/migrations/NNNN-*.sql`
  appliquées au démarrage après sauvegarde `veille.db.avant-NNNN` (une seule gardée) ; jamais supprimée à la purge.
- Champs venant de gk2 = **données non fiables** (tronqués, jamais interprétés comme instructions).
- Familles et gravités **telles que gk2 les nomme** ; `bloc24` calculé ; horodatages locaux convertis en UTC ; plages
  de documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) gardées mais exclues des corrélations.
- Rétention : événements 30 j, incidents 365 j, mesures 30 j. Garde d'espace : collecte suspendue sous 1 Gio libre de
  `/var/lib`.
- Aucune attribution d'outil sans ≥ 2 traits indépendants (couches différentes, ou champs que l'outil ne fixe pas
  ensemble ; agent HTTP + chemins du même outil = **un** trait) ; chaque entrée du catalogue a une `source`.
- Versions `X.Y.Z-1~trixie1`. Paquets touchés sur gk2 : `secubox-core` d'abord si `common/` change (puis `Depends`
  versionné), puis `secubox-waf-ng`, `secubox-garde`, `secubox-ad-guard`.
- Jamais `git stash` ; worktree #3583 ; déploiement par apt, gk2 puis gk3.

## Décision prise pour ce plan

- **Q2 de V2 (compte de lecture)** : adoption de la proposition de la phase 0 (§ 4) — compte `ai-lecture`, portée
  `waf-lecture`, GET seulement, réclamations `methode` et `chemin` liées au jeton, garde
  `require_lecture_ou_compte("ai-lecture")` sans repli anonyme. À confirmer par le propriétaire (#3726).

## Points de vigilance

1. Rotation de `waf-threats.log` pendant une lecture : finir `.1` puis repartir à 0 sans trou ni doublon →
   **Tâche 3** `test_flux_rotation_sans_trou`.
2. gk2 injoignable plusieurs heures : curseur `en_panne`, reprise sans perte depuis la position gardée, espacement
   après refus 401 → **Tâche 5** `test_reprise_apres_panne`, `test_espacement_apres_401`.
3. Lignes de l'autotest du WAF (`SecuBox-WAF-SelfTest/1`) et du LAN (`client_ip = local`) : jamais d'incident →
   **Tâche 6** `test_autotest_et_lan_jamais_incident`.
4. Base verrouillée par l'API pendant une écriture de la veille : transactions courtes, pas d'échec de boucle →
   **Tâche 1** `test_ecriture_concurrente_api_veille`.
5. Un outil inconnu dont un seul trait correspond : « inconnu » avec le trait, jamais un nom → **Tâche 8**
   `test_un_seul_trait_inconnu`.

---

### Tâche 1 : socle de la veille (`veille.db`, service, rétention) — #3719

**Fichiers :** `packages/secubox-ai/veille/__init__.py`, `veille/base.py`, `veille/retention.py`,
`veille/service.py` (boucles asynchrones, sans encore de collecte ni corrélation), `migrations/0001-socle.sql`
(tables de V2 § 6 utiles aux phases 1-3 : `schema_migrations`, `curseurs`, `evenements`, `campagnes`, `blocs`,
`incidents`, `incident_preuves`, `mesures`, `audit_chaine`), `sbin/secubox-ai-veille`,
`systemd/secubox-ai-veille.service`, `apparmor/secubox-ai-veille`, `debian/*` (installation, postinst enable --now),
`tests/test_veille_socle_3719.py`.

**Interfaces produites :**
- `veille.base.ouvrir(chemin: Path) -> sqlite3.Connection` (pragmas ci-dessus, applique les migrations manquantes avec
  sauvegarde) ; `veille.base.migrer(db, dossier: Path) -> list[int]`.
- `veille.retention.purger(db, maintenant: datetime) -> dict[str, int]` (lots de 1 000).
- `veille.service.Veille(db, horloge, boucles: list[Boucle])` ; `Boucle(nom, intervalle_s, fonction)` ; une boucle qui
  lève est journalisée et réessayée au tour suivant, jamais fatale.
- [ ] Tests : `test_migrations_idempotentes_et_sauvegarde`, `test_retention_par_lots`, `test_boucle_en_erreur_continue`,
  `test_ecriture_concurrente_api_veille` (deux connexions, écriture pendant lecture), `test_garde_espace_suspend`.
- [ ] Échec, implémentation, succès ; unité `User=secubox-ai`, `ReadWritePaths=/var/lib/secubox/ai`, socle RULES § 10.
- [ ] Commit `feat(ai): socle de la veille V2 (ref #3719)`.

### Tâche 2 : compte de service `ai-lecture` (common + gk2) — #3720 (prérequis)

**Fichiers :** `common/secubox_core/compte_service.py` (compte `ai-lecture` → `waf-lecture` ; réclamations `methode`,
`chemin` vérifiées pour ce compte ; `require_lecture_ou_compte(compte)` sans repli anonyme si un porteur EdDSA est
présent), `packages/secubox-core/debian/changelog` (version suivante), wafctl `cle-ai-lecture` (sur le modèle de
`cle-ai-ban`), tests de `secubox_core`.

**Interfaces :**
- `frapper_jeton(cle_privee_pem, "ai-lecture", aud, b"", maintenant, methode="GET", chemin="/api/v1/waf/...")`.
- `require_lecture_ou_compte("ai-lecture")` : dépendance FastAPI ; porteur EdDSA présent → vérifié (compte, portée,
  méthode, chemin, jti, ≤ 60 s) ou 401 ; absent → comportement de `require_lecture` inchangé.
- [ ] Tests : jeton valide sur le bon chemin → OK ; autre chemin → 401 ; POST → 401 ; jeton mal formé → 401 (jamais
  anonyme) ; sans porteur → `require_lecture` ; jeton `ai-ban` refusé ; rejeu refusé.
- [ ] `secubox-core` monté ; les paquets qui utilisent la nouvelle garde portent `secubox-core (>= <nouvelle>~)`.
- [ ] Commit `feat(core): compte de service ai-lecture (ref #3720)`.

### Tâche 3 : routes de lecture manquantes sur gk2 (secubox-waf-ng) — #3720

**Fichiers :** `packages/secubox-waf-ng/composants/waf/api/` (route `GET /waf/menaces/flux?depuis=<inode>:<octet>&max=N`,
`depuis=<époque>` sur `/waf/enforcement` lu depuis la fin, `limite` sur `/waf/campaigns`, `GET /waf/mesures` et
`GET /waf/actord/propositions` en lecture), garde `require_lecture_ou_compte("ai-lecture")` sur toutes les routes du
tableau § 4 de la phase 0 (+ `/waf/ai/etat` ouvert à `ai-lecture` en lecture), tests, version suivante.

**Interfaces :**
- `/waf/menaces/flux` → `{"lignes": [{"position": "<inode>:<octet>", "ligne": {...}}], "suivant": "<inode>:<octet>",
  "rotation": bool}` ; `max` ≤ 2 000 ; à inode changé : finit `waf-threats.log.1` depuis l'octet puis le courant depuis 0.
- [ ] Tests : `test_flux_curseur`, `test_flux_rotation_sans_trou`, `test_flux_max_borne`, `test_enforcement_depuis`,
  `test_campagnes_limite`, `test_routes_ai_lecture_get_seulement`.
- [ ] Commit `feat(waf): routes de lecture de la veille V2 (ref #3720)`.

### Tâche 4 : routes de lecture des sources ajoutées (garde, ad-guard, leurres) — complément #3795

**Fichiers :** `packages/secubox-garde/api/main.py` (`/historique` et `/etat` acceptent `ai-lecture` avec contenu
complet, via `require_lecture_ou_compte`), `packages/secubox-ad-guard/` (`GET /api/v1/adguard/dnsguard/alertes?depuis=`
en lecture, `ai-lecture`), leurres de service (#3728 : trouver le paquet propriétaire, route de lecture des contacts et
identifiants tentés, **jamais** les mots de passe en clair — empreinte SHA-256 et longueur seulement), tests et versions.
- [ ] Tests par route : anonyme LAN inchangé ; `ai-lecture` → contenu complet ; autre compte → 401.
- [ ] Commits `feat(garde|ad-guard|<leurres>): lecture pour la veille V2 (ref #3795)`.

### Tâche 5 : collecteur de gk3 — #3720

**Fichiers :** `packages/secubox-ai/veille/client.py` (GET signé `ai-lecture`, `trust_env=False`, délai court, base
`menaces_url` de `ai.toml`), `veille/sources/*.py` (une source par fichier : `menaces`, `bans`, `bans_actifs`, `blocs`,
`campagnes`, `decisions`, `reevaluations`, `posture`, `garde`, `actord`, `dns`, `leurres`), `veille/normaliser.py`,
`veille/collecte.py`, tests sur le jeu de référence.

**Interfaces :**
- `Source` (protocole) : `nom: str`, `intervalle_s: int`, `async lire(client, curseur: str|None) -> Lot(evenements:
  list[Evenement], curseur: str|None, faits: dict)`.
- `normaliser.evenement(source, brut: dict) -> Evenement` (dataclass alignée sur la table) ; empreinte SHA-256 de V2 § 6.
- `collecte.passe(db, client, sources, maintenant) -> dict[str, str]` (état par source) ; insertion idempotente ;
  `curseurs.etat` = `ok` | `en_panne` | `suspendu` ; après un 401 : espacement exponentiel plafonné à 15 min et une
  seule ligne d'audit par motif et par 10 min.
- [ ] Tests : `test_normalisation_jeu_reference` (180 menaces, familles, UTC, `local`, autotest marqué),
  `test_idempotence`, `test_reprise_apres_panne`, `test_espacement_apres_401`, `test_sources_ajoutees_garde_dns_actord`,
  `test_rapprochement_compteurs` (± 1 % avec `/waf/stats` sur un échantillon simulé).
- [ ] Commit `feat(ai): collecteur de la veille V2 (ref #3720)`.

### Tâche 6 : corrélateur d'incidents — #3721

**Fichiers :** `veille/correlation.py`, `veille/regles.py`, `migrations/0002-…` si besoin, tests.

**Interfaces :**
- `correler(db, maintenant, fenetre_s=1800) -> list[Incident]` ; règles nommées (V2 § 8) : `multi_source`,
  `multi_service`, `bloc_mixte`, `retour_apres_ban`, `campagne_etendue`, `leurre_puis_attaque` ; complément :
  `meme_outil_multi_adresses` (après Tâche 8), `garde_et_waf`. Gravité = max des preuves (+1 cran pour
  `leurre_puis_attaque`) ; `calme` après 6 h sans preuve, `clos` après 7 j.
- [ ] Tests (sur le jeu de référence + cas construits) : une par règle ; `test_autotest_et_lan_jamais_incident` ;
  `test_plages_documentation_exclues` ; `test_incident_etendu_pas_duplique` ; `test_calme_puis_clos`.
- [ ] Commit `feat(ai): corrélateur d'incidents multi-sources (ref #3721)`.

### Tâche 7 : dossiers d'attaquant et étapes — complément #3795

**Fichiers :** `migrations/0003-dossiers.sql` (`dossiers(id, cle, type 'acteur'|'campagne', gravite, etapes_json,
outils_json, premiere_vue, derniere_vue, maj_le)`, `dossier_incidents`, `dossier_evenements`), `veille/dossiers.py`,
tests.

**Interfaces :**
- `construire(db, maintenant) -> list[Dossier]` : clé = acteur d'actord si connu, sinon adresse ; campagne = acteurs
  regroupés par même outil identifié, même bloc, ou même cible dans la même fenêtre.
- Étapes (règles déterministes nommées) : `reperage` (scanners, `host_anomaly`, SYN sans état), `essais` (sondes de
  produits absents, leurres, identifiants tentés), `exploitation` (règles WAF d'attaque, risques DPI d'exploitation),
  `persistance` (retour après ban, rotation d'adresses du même outil) ; chaque étape garde ses preuves et ses heures.
- [ ] Tests : `test_dossier_chronologie_multicouche`, `test_etapes_enchainees`, `test_campagne_meme_outil`,
  `test_dossier_sans_actord_par_adresse`.
- [ ] Commit `feat(ai): dossiers d'attaquant et étapes (ref #3795)`.

### Tâche 8 : catalogue d'empreintes et identification des outils — complément #3795

**Fichiers :** `packages/secubox-ai/empreintes/*.toml` (installés sous `/usr/share/secubox-ai/empreintes/`), lecture
d'un fichier local opérateur `/etc/secubox/ai/empreintes.local.toml`, `veille/outils.py`, tests.

**Interfaces :**
- Entrée : `{outil, version?, couche, traits: [{type: "agent"|"chemins"|"ordre_requetes"|"banniere"|"identifiants"|
  "ja4"|"rythme_ports", motif|valeurs, couche}], source: "<URL ou relevé gk2 daté>"}` ; entrée sans `source` → refusée
  au chargement.
- `identifier(dossier) -> list[Attribution(outil, traits_concordants, confiance: "forte"|"moyenne")]` ; ≥ 2 traits
  indépendants requis (règle de la contrainte globale), sinon `Attribution(outil="inconnu", traits_observes=[...])`.
- Premier catalogue : outils web et leurres (Nuclei, sqlmap, Nikto, gobuster/ffuf/dirbuster, WPScan, Censys/Shodan/
  zgrab en cartographie, Masscan/Zmap par la seule couche disponible, Mirai et dérivés par identifiants de leurre),
  chaque trait sourcé (documentation publique de l'outil ou relevé de gk2 daté).
- Suggestions du modèle hors périmètre de ce plan (phase 4).
- [ ] Tests : `test_deux_traits_independants_attribuent`, `test_un_seul_trait_inconnu`,
  `test_agent_et_chemins_meme_outil_un_trait`, `test_entree_sans_source_refusee`, `test_echappement_motifs` (motifs
  compilés avec délai borné, pas de ReDoS).
- [ ] Commit `feat(ai): identification des outils sur empreintes sourcées (ref #3795)`.

### Tâche 9 : livraison (contrôleur, avec le propriétaire)

- [ ] `relecteur-securite` sur la branche ; corrections.
- [ ] Ordre : `secubox-core` → `secubox-waf-ng`, `secubox-garde`, `secubox-ad-guard`, paquet des leurres → gk2 ;
  `wafctl cle-ai-lecture` sur gk2 avec la clé publique générée sur gk3 ; `secubox-ai` → gk3.
- [ ] Vérifier sur gk3 : curseurs `ok`, ± 1 % avec `/waf/stats` sur 24 h, incidents et dossiers sur des données réelles,
  aucune attribution sans deux traits ; suivi `HISTORY.md`/`WIP.md` ; plan suivant : phases 4-7 (analyste, réponses
  tout automatiques, console, paquet 2.0.0).
