<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Filtres WAF de l'IA — lot 1 (Nuclei, vérificateur, leurres HTTP) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** le relais du POC (gk0) tire des filtres des modèles Nuclei, les vérifie et les envoie à gk2, qui les revérifie et
les applique d'office comme leurres HTTP de sbxwaf, bannis selon leur gravité.

**Architecture :** gk0 collecte et propose (aucune IA au lot 1 : Nuclei est extrait par le code) ; gk2 décide : route du
compte de service `ai-filtres` (secubox-waf-ng) → `secubox-cvectl filtres-ia` (root, écriture 4R de
`waf-rules.json`) → trois catégories `ia_filtres_{critique,haute,moyenne}` que sbxwaf bannit avec leur propre seuil et
leur propre durée.

**Tech Stack :** Python 3 (FastAPI, pytest), Go (sbxwaf), shell (sudoers), POC hors dépôt (`~/poc-secubox-ai/relais`).

**Spec :** `docs/superpowers/specs/2026-11-15-filtres-waf-ia-avis-poc-design.md`

## Global Constraints

- Un filtre est une donnée ; tout motif de `waf-rules.json` est **généré et échappé par le code** (jamais rédigé par un modèle, jamais une expression libre reçue).
- Leurre seulement si le produit est **absent selon deux sources concordantes** : inventaire `cve-triage` ET `haproxy-routes.json` ; un doute vaut « présent » → rejet `present` au lot 1 (les propositions sont le lot 4).
- Gravité calculée par le code : critique = KEV, ou famille `rce`, ou EPSS ≥ 0,5 → seuil 1, ban 168 h ; haute = CVSS ≥ 7 ou EPSS ≥ 0,1 → seuil 1, ban 24 h ; moyenne/inconnue → seuil 3 en 24 h, ban 4 h.
- Plafonds : 10 filtres nouveaux par heure glissante, 50 par jour.
- Spécificité : refus si moins de 8 caractères utiles (hors `/`) ou si le chemin est parmi les 200 plus fréquents du trafic légitime de gk2.
- Collision de motif ou d'id avec `product_absent_probes`, `product_absent_probes_ban` ou une autre catégorie : rejet `deja_couvert`, l'existant fait foi.
- Chaque décision auditée dans `/var/log/secubox/audit.log` ; écriture de `waf-rules.json` par `leurres.ecrire_regles` (verrou, copie de retour, relecture, rollback).
- Rien de lourd sur gk2 : la route et le ctl lisent au plus 64 Mio de journaux nginx par appel.
- Versions : monter `secubox-toolbox-ng`, `secubox-security-posture`, `secubox-core`, `secubox-waf-ng` (`X.Y.Z-1~trixie1`, changelog daté, `ref #3732`). Déploiement : banc gk6 d'abord, gk2 sur accord du propriétaire, installations groupées.

## Review Focus

- Un modèle Nuclei malveillant (chemin `/`, `/index.php`, motif énorme, caractères de contrôle) → rejeté avec motif, rien n'est écrit.
- Un produit présent sur gk2 mais absent de l'inventaire (servi par un vhost) → jamais appliqué en leurre.
- Une régénération de `cve-triage` (`waf-rules generate --apply`) après application → les catégories `ia_filtres_*` restent intactes.
- Le relais renvoie deux fois le même lot (réseau coupé) → aucun doublon, plafonds non consommés deux fois.
- sbxwaf redémarré avec un `waf-rules.json` portant `ban_seuil`/`ban_duree` → chargé ; un ancien sbxwaf qui ignore ces champs ne plante pas.

---

### Task 1 : sbxwaf — seuil et durée de ban par catégorie

**Files :**
- Modify : `packages/secubox-toolbox-ng/cmd/sbxwaf/rules.go` (structure de catégorie), `packages/secubox-toolbox-ng/cmd/sbxwaf/main.go:765-790` (chemin `escalate`), la fonction `appliquerBan`
- Test : `packages/secubox-toolbox-ng/cmd/sbxwaf/ia_filtres_test.go`
- Modify : `packages/secubox-toolbox-ng/debian/changelog` (0.16.0)

**Interfaces :**
- Produces : champs JSON facultatifs d'une catégorie `escalate` : `"ban_seuil": int` (1–10) et `"ban_duree": string` (durée Go, 1h–168h). Absents → comportement actuel (`-escalate-threshold`, `-nft-ban-duration`).

- [ ] **Step 1 : tests Go**, dans `ia_filtres_test.go` :
  - `TestEscalate_SeuilParCategorie` : catégorie `escalate` avec `ban_seuil: 1` → le 1er hit d'une IP rend la page de ban et appelle le banneur une fois.
  - `TestEscalate_DureeParCategorie` : `ban_duree: "168h"` → le banneur reçoit 168 h ; sans le champ → `-nft-ban-duration`.
  - `TestEscalate_ValeursHorsBornesIgnorees` : `ban_seuil: 0` ou `50`, `ban_duree: "9000h"` ou illisible → valeurs par défaut, journal d'avertissement, pas de panique.
  - `TestEscalate_SansChampsInchange` : catégorie existante sans les champs → seuil 3 sur 24 h, comme avant.
- [ ] **Step 2 :** `go test ./cmd/sbxwaf/ -run Escalate` → échec (champs inconnus).
- [ ] **Step 3 :** lire les deux champs au chargement des règles, bornés ; un compteur `escalate` par catégorie quand `ban_seuil` est donné (sinon le compteur partagé actuel) ; `appliquerBan(ip, cat, sev, duree time.Duration)` avec la durée de la catégorie ou la durée globale.
- [ ] **Step 4 :** `go test ./cmd/sbxwaf/` → tout passe (y compris les tests existants).
- [ ] **Step 5 :** changelog 0.16.0, commit `feat(sbxwaf): seuil et durée de ban par catégorie escalate (ref #3732)`.

### Task 2 : cve-triage — module `filtres_ia` (forme, gravité, motif, vérifications, catégories)

**Files :**
- Create : `packages/secubox-security-posture/composants/cve-triage/api/wafgen/filtres_ia.py`
- Modify : `.../wafgen/leurres.py` (`MODES` et `valider` acceptent les trois catégories `ia_filtres_*` en `escalate`, avec `ban_seuil`/`ban_duree`)
- Test : `packages/secubox-security-posture/composants/cve-triage/tests/test_filtres_ia_3732.py`

**Interfaces :**
- Consumes : `leurres.ecrire_regles(chemin, transformer, action=, detail=, acteur=)`, `emit.motif(path)`, `inventory.gather_present()`.
- Produces :
  - `class Filtre` (dataclass) : `id: str` (`ID_RE`), `version: int ≥ 1`, `cve: str` (`CVE-\d{4}-\d{4,7}`), `produit: str` (≤ 64), `famille: str` (dans `FAMILLES`), `motif_type: Literal["chemin_exact","chemin_prefixe","parametre_egal","corps_contient"]`, `motif: str` (≤ 256, imprimable), `parametre: str | None`, `kev: bool`, `epss: float | None`, `cvss: float | None`, `sources: list[dict]`.
  - `FAMILLES = {"rce","lfi","sqli","auth_bypass","ssrf","deserialisation","xss","traversal","divulgation","autre"}`
  - `lire_filtre(obj: object) -> Filtre` (lève `Refus("forme: …")`).
  - `gravite(f: Filtre) -> Literal["critique","haute","moyenne"]`.
  - `motif_regex(f: Filtre) -> str` : `chemin_exact` → `emit.motif(chemin)+"(?:$|[?#])"` ; `chemin_prefixe` → `emit.motif(chemin)` ; `parametre_egal` → `[?&]` + `re.escape(parametre)` + `=` + `re.escape(motif)` ; `corps_contient` → `re.escape(motif)`.
  - `CATEGORIES = {"critique": ("ia_filtres_critique", 1, "168h"), "haute": ("ia_filtres_haute", 1, "24h"), "moyenne": ("ia_filtres_moyenne", 3, "4h")}`.
  - `verifier(f, *, present: set[str], vhosts: set[str], frequents: set[str], existants: dict[str, str]) -> str | None` : motif de rejet (`specificite`, `frequent`, `present`, `deja_couvert`) ou `None`.
  - `appliquer_filtres(filtres: list, *, chemin=RULES_PATH, etat=ETAT_PLAFONDS, maintenant: int, acteur: str) -> dict` : `{"appliques": [id], "rejets": [{"id","motif"}], "inchanges": [id]}` ; plafonds 10/h et 50/j comptés dans `ETAT_PLAFONDS = /var/lib/secubox/cve-triage/filtres-ia-plafonds.json` (seuls les nouveaux `id` comptent) ; un `id` déjà présent avec la même `version` → `inchanges`.
  - `retirer_filtre(fid: str, *, chemin=RULES_PATH, acteur: str) -> dict`.
  - `chemins_frequents(journaux: list[Path], budget: int = 64 << 20, n: int = 200) -> set[str]` : chemins (sans requête) des lignes nginx de statut < 400.

- [ ] **Step 1 : tests** (`test_filtres_ia_3732.py`, fichiers temporaires, aucun accès système) :
  - `test_forme_refusee` : motif vide, > 256 car., caractère de contrôle, famille inconnue, cve mal formée → `Refus` contenant `forme`.
  - `test_gravite` : `kev=True` → critique ; famille `rce` → critique ; `epss=0.5` → critique ; `cvss=7.5` → haute ; `epss=0.12` → haute ; rien → moyenne.
  - `test_motif_echappe` : `chemin_exact "/cgi-bin/.%2e/bin/sh"` → la regex reconnaît `"/cgi-bin/.%2e/bin/sh"` et `"/cgi-bin/.%2e/bin/sh?x=1"`, pas `"/cgi-bin/.%2e/bin/shell"` ; un motif `"a.*b"` est traité littéralement (`re.escape`).
  - `test_specificite` : `"/admin"` → `specificite` ; `"/index.php"` présent dans `frequents` → `frequent`.
  - `test_produit_present_deux_sources` : produit dans `present` → `present` ; produit dont le nom apparaît dans un vhost → `present`.
  - `test_deja_couvert` : même regex qu'un motif de `product_absent_probes` → `deja_couvert`.
  - `test_categories_ecrites_et_cve_triage_intact` : après `appliquer_filtres`, `waf-rules.json` contient `ia_filtres_critique` (`mode: escalate`, `ban_seuil: 1`, `ban_duree: "168h"`, `generated: true`) et toutes les autres catégories inchangées ; un second appel à `leurres.appliquer` (régénération `cve-triage`) laisse `ia_filtres_*` identiques.
  - `test_plafonds` : 12 filtres nouveaux dans la même heure → 10 appliqués, 2 rejets `plafond` ; renvoyer les mêmes 10 → `inchanges`, plafond non consommé.
  - `test_retirer` : `retirer_filtre` enlève le motif de sa catégorie et l'audit porte `filtres-ia-retirer`.
  - `test_chemins_frequents_borne` : journal de 3 lignes 200 et 1 ligne 404 → seuls les chemins 200 ; un budget de 10 octets ne lit pas au-delà.
- [ ] **Step 2 :** `pytest composants/cve-triage/tests/test_filtres_ia_3732.py` → échec (module absent).
- [ ] **Step 3 :** écrire `filtres_ia.py` aux signatures ci-dessus ; étendre `MODES` et `valider` dans `leurres.py` (les trois catégories en `escalate`, `generated: true`, champs `ban_seuil` 1–10 et `ban_duree` dans {4h,24h,168h}).
- [ ] **Step 4 :** `pytest composants/cve-triage/tests/` → tout passe (tests #3584 compris).
- [ ] **Step 5 :** commit `feat(cve-triage): filtres de l'IA — forme, gravité, motif, vérifications (ref #3732)`.

### Task 3 : `secubox-cvectl filtres-ia` (verbe root, sudoers)

**Files :**
- Modify : `.../wafgen/cli.py` (sous-commande `filtres-ia appliquer|retirer|lister [--apply] --json`, entrée sur STDIN ≤ 256 Kio comme `leurre`), `.../sbin/secubox-cvectl`, sudoers de `secubox-security-posture` (lignes exactes pour l'utilisateur de `secubox-waf.service`), `debian/changelog`
- Test : `.../tests/test_filtres_ia_cli_3732.py`

**Interfaces :**
- Consumes : Task 2 (`appliquer_filtres`, `retirer_filtre`, `lire_filtre`).
- Produces : `sudo -n /usr/sbin/secubox-cvectl filtres-ia appliquer --apply --json` ; STDIN `{"acteur": "ai-filtres:<kid>", "filtres": [...]}` ; STDOUT le bilan JSON ; codes 0 ok, 2 usage, 3 refusé ; jamais de trace Python. `retirer` : STDIN `{"acteur", "id"}`. `lister` : catégories `ia_filtres_*` et leurs motifs.

- [ ] **Step 1 : tests** : `test_appliquer_sans_apply_n_ecrit_rien`, `test_stdin_trop_gros_refuse` (code 2), `test_json_invalide_code_2_sans_trace`, `test_sudoers_lignes_exactes` (la ligne autorise exactement `filtres-ia appliquer --apply --json` et `filtres-ia retirer --apply --json`, rien d'autre).
- [ ] **Step 2 :** lancer → échec.
- [ ] **Step 3 :** implémenter la sous-commande ; inventaire par `inventory.gather_present()`, vhosts par `/etc/secubox/waf/haproxy-routes.json`, chemins fréquents par `chemins_frequents(glob("/var/log/nginx/*access.log"))`.
- [ ] **Step 4 :** tests du paquet → passent.
- [ ] **Step 5 :** changelog `secubox-security-posture` (version suivante), commit `feat(cvectl): verbe filtres-ia (ref #3732)`.

### Task 4 : compte de service `ai-filtres` et route `/api/v1/waf/ai/filtres`

**Files :**
- Modify : `common/secubox_core/compte_service.py` (`COMPTES_SERVICE["ai-filtres"] = "waf-filtres"`, dépendance `require_ai_filtres` sur le modèle de `require_ai_ban`), `debian/changelog` de `secubox-core`
- Create : `packages/secubox-waf-ng/composants/waf/api/filtres_ia.py` (routeur, préfixe `/ai/filtres`, servi par le processus désigné comme `gestes_ia`)
- Modify : `packages/secubox-waf-ng/composants/waf/api/main.py` (inclusion du routeur), `wafctl cle-ai-ban` → accepter `cle-ai-filtres ajouter|retirer` (même code, autre dossier `/etc/secubox-comptes-service/ai-filtres`), postinst (dossier), `debian/changelog`
- Test : `packages/secubox-waf-ng/composants/waf/tests/test_filtres_ia_3732.py`, `common/tests/` (compte de service)

**Interfaces :**
- Consumes : Task 3 (commande sudo exacte et format STDIN/STDOUT).
- Produces : `POST /api/v1/waf/ai/filtres` (`require_ai_filtres`), corps `{"filtres": [≤ 50]}` → 200 bilan du ctl ; 409 si tout est rejeté ; 503 si le ctl est injoignable ; `DELETE /api/v1/waf/ai/filtres/{id}` → retrait ; `GET /api/v1/waf/ai/filtres` (`require_ai_filtres`) → liste. Chaque appel audité (`ai-filtres-*`).

- [ ] **Step 1 : tests** : jeton `ai-ban` refusé sur `/ai/filtres` (audience) et inversement ; corps de 51 filtres → 422 ; le ctl reçoit l'acteur `ai-filtres:<kid>` et le corps tel quel ; échec du ctl → 503 audité ; route absente hors du processus désigné (`SECUBOX_WAF_GESTES_IA`).
- [ ] **Step 2 :** lancer → échec.
- [ ] **Step 3 :** implémenter sur le patron de `gestes_ia.py` (corps brut signé, `_corps`, audit qui lève).
- [ ] **Step 4 :** tests de `secubox-waf-ng` et de `common` → passent.
- [ ] **Step 5 :** changelogs, commit `feat(waf): compte de service ai-filtres et route /ai/filtres (ref #3732)`.

### Task 5 : relais POC gk0 — collecte Nuclei, gravité, vérification locale, envoi

**Files (hors dépôt, sauvegardes `*.avant-filtres`) :**
- Create : `~/poc-secubox-ai/relais/filtres.py`, `~/poc-secubox-ai/relais/tests/test_filtres.py`
- Modify : `~/poc-secubox-ai/relais/relais.py` (tâche de fond 1×/jour, routes de lecture `/api/v1/ai/filtres` pour la page à venir)

**Interfaces :**
- Consumes : Task 4 (route, format), clé du compte `ai-filtres` dans `~/.config/secubox-ai/ai-filtres/` (même outillage que `ai-ban`).
- Produces : `collecter_nuclei(depot: Path) -> list[dict]` (git `projectdiscovery/nuclei-templates` cloné/mis à jour dans `~/poc-secubox-ai/sources/nuclei`, seuls les modèles `http` à CVE dont la requête est un chemin unique) ; `enrichir(cands, kev: set[str], epss: dict[str, float]) -> list[dict]` (KEV : `known_exploited_vulnerabilities.json` de la CISA ; EPSS : CSV quotidien du FIRST ; caches 24 h) ; `filtre_depuis_nuclei(modele: dict) -> dict | None` (anti-invention : le motif est une sous-chaîne exacte du modèle) ; `envoyer(filtres: list[dict]) -> dict` (lots de 50, jeton signé du corps brut) ; journal `filtres.jsonl` (envoyés, appliqués, rejets et motif) — base du suivi du lot 5.

- [ ] **Step 1 : tests** : un modèle Nuclei `raw` à chemin unique → filtre `chemin_exact` ; un modèle multi-requêtes ou sans CVE → `None` ; motif absent du texte du modèle → `None` ; `enrichir` pose `kev`/`epss` ; `envoyer` découpe 120 filtres en 3 lots et signe chaque corps ; un 409/503 de gk2 est journalisé, jamais réessayé en boucle (1 essai par jour).
- [ ] **Step 2 :** lancer → échec.
- [ ] **Step 3 :** implémenter ; aucune exécution de modèle Nuclei, jamais ; téléchargements depuis gk0 seulement.
- [ ] **Step 4 :** tests du relais → passent.
- [ ] **Step 5 :** relancer le relais **au repos** (aucun travail en cours, moteur inactif).

### Task 6 : banc gk6 puis gk2

- [ ] **Step 1 :** construire et publier les quatre paquets ; installer **ensemble** sur gk6 (une seule relance de `sbx-actord`).
- [ ] **Step 2 :** clé `ai-filtres` posée sur gk6 ; envoi d'un lot réel depuis le relais vers gk6 ; vérifier : catégories `ia_filtres_*` présentes, un hit sur un motif `critique` depuis une adresse de test publique → ban 168 h, ligne de menace, audit ; un produit présent sur gk6 → rejet `present` ; `waf-rules generate --apply` → `ia_filtres_*` intactes.
- [ ] **Step 3 :** retirer la clé de banc et les bans de test ; demander l'accord du propriétaire pour gk2 ; installer les quatre paquets ensemble sur gk2 ; mesurer la mémoire avant/après.
- [ ] **Step 4 :** suivi : entrée datée `.claude/HISTORY.md`, `.claude/WIP.md`, READMEs des paquets (route, verbe, champs de catégorie).

## Reporté (rulings)

- Récidive « un cran au-dessus » : reportée au lot 5 (suivi) — sbxwaf n'a pas de récidive par catégorie ; au lot 1 la durée est fixe par gravité.
- Exploit-DB, Metasploit, avis (IA) : lot 2 ; leurres de service : lot 3 ; propositions et rejeu sur trafic légitime : lot 4 ; page « Filtres » (maquette Aurora d'abord) et historique : lot 5.
