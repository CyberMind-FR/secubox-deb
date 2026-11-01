<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->
# mochabinleds — plan d'implémentation

> **Pour les agents :** sous-skill requis : superpowers:subagent-driven-development (recommandé) ou
> superpowers:executing-plans. Étapes en cases à cocher (`- [ ]`).

**But :** 8 séquences LED de supervision dont les niveaux sont relatifs à l'activité habituelle de
la box, avec une référence évolutive tirée des stats temps réel.

**Architecture :** un nouveau collecteur `secubox-led-flux` (compte `secubox-leds`, espace réseau
de l'hôte) relève les compteurs toutes les 10 s, tient la référence évolutive et publie des
**niveaux** 0..4 dans `/run/secubox-leds/flux.json`. Le moteur `secubox-led-pulse` lit ces niveaux
par un nouveau type de source `flux` ; il garde `PrivateNetwork=yes` et aucune capacité.

**Pile :** Python 3.13 (stdlib seule : json, sqlite3, math, os), systemd, AppArmor, pytest.

**Spec :** `docs/superpowers/specs/2026-11-01-mochabinleds-design.md`

## Contraintes globales

- Paquet `packages/secubox-led-heartbeat`, version `2.4.0-1~trixie1`, `debian/compat` 13.
- En-tête SPDX CMSD-1.0 sur tout nouveau fichier.
- Démon LED inchangé côté confinement : `PrivateNetwork=yes`, `CapabilityBoundingSet=` vide, AppArmor enforce.
- Collecteur : compte `secubox-leds` (jamais root), `Nice=19`, `CPUWeight=10`, `IOWeight=10`, AppArmor
  enforce, seule capacité `CAP_NET_ADMIN` (lecture des compteurs nftables `sbx_drop_*`), écriture
  uniquement dans `/run/secubox-leds/` et `/var/lib/secubox-leds/`.
- Coût : collecteur < 1 % d'un cœur sur gk2 (mesuré sur 10 min).
- Niveaux : 0 normal (vert), 1 activité (cyan), 2 attention (jaune), 3 dégradation (orange),
  4 critique (rouge, **absolu seulement**) ; `None` = inconnu ; apprentissage = violet.
- Référence : 168 tranches horaires de la semaine, EWMA demi-vie 7 j ; tendance courte EWMA demi-vie
  1 h ; niveau contre la plus haute des deux ; apprentissage 24 h (niveau plafonné à 1) ;
  `z < 1` → 0, `1 ≤ z < 2` → 1, `2 ≤ z < 3` → 2, `z ≥ 3` → 3 ; dénominateur `max(dispersion, plancher)`.
- Persistance référence : `/var/lib/secubox-leds/reference.json`, écriture atomique toutes les 15 min.
- Rotation : ~8 s par séquence ; adaptative `duree × (1 + niveau max)`, plafond 24 s ; priorité alerte
  sur niveau 4, rappel toutes les 30 s si plusieurs séquences en 4.
- Jamais CrowdSec ; aucun secret ; aucune lecture de `/etc/secubox/secrets/`.

## Décisions prises dans ce plan (écarts à la spec)

- **Le collecteur calcule les niveaux** (la spec §3 les plaçait dans le moteur) : la référence a besoin
  de chaque relevé et d'un répertoire inscriptible ; le moteur reste ainsi sans état ni écriture.
- **SOC :** `secubox-soc` ne publie aucun fichier (seulement `soc.sock`, sous JWT). Ce lot lit
  `/var/lib/secubox/soc/alerts.json` s'il existe (type existant `alertes_json`) ; sinon la séquence SOC
  est « inconnu ». Publication côté SOC : issue séparée.
- **FIREWALL :** entrées/sorties = paquets WAN (`/proc/net/dev`), bloqués = somme des compteurs nftables
  `sbx_drop_*` (`nft -j list counters`) — d'où `CAP_NET_ADMIN` au seul collecteur.

## Points de revue (non couverts par les tests de tâche, à vérifier délibérément)

1. Compteur remis à zéro (redémarrage d'un module) : débit négatif → ignoré, jamais un pic.
2. Horloge qui recule ou saute (NTP au démarrage) : pas de tranche corrompue, pas de division par 0.
3. `reference.json` corrompu, tronqué ou d'un autre propriétaire : repart en apprentissage, sans planter.
4. gk1 très calme (moyenne ≈ 0) : 1 ou 2 événements ne dépassent pas « activité » grâce au plancher.
5. Attaque soutenue sur gk2 pendant 1 h : reste ≥ « attention » (référence longue), ne redevient pas
   vert au bout de 10 min.

Chaque point a son test dans la tâche indiquée.

---

### Tâche 1 : référence évolutive

**Fichiers :**
- Créer : `usr/lib/secubox-led-heartbeat/reference.py`
- Test : `tests/test_reference_3361.py`

**Interfaces — produit :**
- `class Reference` : `__init__(self, demi_vie_longue=7*86400, demi_vie_courte=3600, apprentissage=86400)`
- `Reference.observer(self, cle: str, valeur: float, t: float) -> None`
- `Reference.niveau(self, cle: str, valeur: float, t: float, plancher: float) -> int | None` (0..3)
- `Reference.vers_dict(self) -> dict` ; `Reference.depuis_dict(d: dict) -> Reference` (classmethod,
  tout dict invalide → référence vide)
- `tranche(t: float) -> int` (0..167, heure locale, lundi 0 h = 0)

- [ ] **Étape 1 : tests**
  - `test_tranche_lundi_minuit_et_dimanche_23h` : 0 et 167.
  - `test_apprentissage_plafonne_a_activite` : moins de 24 h d'observations → `niveau(...)` ≤ 1 même
    pour une valeur 100 × la moyenne.
  - `test_niveaux_par_ecart_reduit` : moyenne 10, dispersion 2 → valeurs 11, 13, 15, 17 → 0, 1, 2, 3.
  - `test_plancher_box_calme` (point 4) : 30 j de zéros, plancher 5 → valeur 2 → 0, valeur 12 → 1.
  - `test_attaque_soutenue_reste_visible` (point 5) : 30 j à 10/min puis 1 h à 200/min → niveau ≥ 2 à
    la fin de l'heure.
  - `test_hausse_durable_devient_normale` : 30 j à 10 puis 21 j à 50 → valeur 50 → niveau 0.
  - `test_horloge_recule` (point 2) : observation à t puis t − 3600 → aucune exception, niveau défini.
  - `test_aller_retour_dict` et `test_dict_invalide_repart_vide` (point 3).
- [ ] **Étape 2 :** `pytest tests/test_reference_3361.py` → échec (module absent).
- [ ] **Étape 3 :** implémenter. Moyenne et variance EWMA par `(cle, tranche)` et `(cle, "court")` ;
  facteur `α = 1 − 2^(−Δt/demi_vie)` avec `Δt` borné à `[0, 3600]` ; niveau = max des deux niveaux.
- [ ] **Étape 4 :** tests verts.
- [ ] **Étape 5 :** commit `feat(led-heartbeat): référence évolutive par tranche horaire (ref #3361)`.

### Tâche 2 : relevés bruts

**Fichiers :**
- Créer : `usr/lib/secubox-led-heartbeat/releves.py`
- Test : `tests/test_releves_3361.py` (+ jeux de données sous `tests/donnees/`)

**Interfaces — produit :** `releves(racine: Path = Path("/"), wan: str = "eth2") -> dict[str, float]`,
clés exactes :
`reseau.octets_in`, `reseau.octets_out`, `reseau.connexions`, `fw.paquets_in`, `fw.paquets_out`,
`fw.bloques`, `waf.requetes` (`connections.https`), `waf.blocages` (`waf.waf_blocked`),
`waf.attaques` (`waf.alerts_today`), `actor.evenements` (len `mesures`), `actor.suspects`
(`niveau` ≥ 2), `actor.critiques` (`niveau` ≥ 4), `adguard.requetes`, `adguard.trackers`
(lignes de `detections` du jour), `adguard.appareils` (len `devices`),
`services.actifs` (`summary.ok`), `services.degrades` (checks `ok=false` avec `systemd_active=true`),
`services.arretes` (checks `systemd_active=false`).
`compteurs_nft(sortie_json: str) -> float` (somme des `packets` des compteurs `sbx_drop_*`).
Une source illisible → clé absente (jamais d'exception).

- [ ] **Étape 1 :** tests sur racine simulée (fichiers `proc/net/dev`, `proc/sys/net/netfilter/nf_conntrack_count`,
  `var/cache/secubox/metrics-cache.json`, `run/secubox/actord-mesures.json`,
  `var/cache/secubox/health-doctor.json`, base SQLite ad-guard minimale) : une valeur attendue par clé ;
  `test_source_absente_cle_absente` ; `test_json_casse_cle_absente` ; `test_compteurs_nft_somme_sbx_drop`.
- [ ] **Étape 2 :** échec attendu.
- [ ] **Étape 3 :** implémenter (SQLite en `mode=ro` URI, lecture JSON bornée à 4 Mio).
- [ ] **Étape 4 :** verts. **Étape 5 :** commit `feat(led-heartbeat): relevés bruts du collecteur (ref #3361)`.

### Tâche 3 : collecteur `secubox-led-flux`

**Fichiers :**
- Créer : `usr/sbin/secubox-led-flux`, `usr/lib/secubox-led-heartbeat/flux.py`,
  `systemd/secubox-led-flux.service`, `apparmor/secubox-led-flux`
- Modifier : `debian/rules`, `debian/postinst` (compte système `secubox-leds`, `/var/lib/secubox-leds` 0750)
- Test : `tests/test_flux_3361.py`

**Interfaces :**
- Consomme : `Reference` (tâche 1), `releves`, `compteurs_nft` (tâche 2).
- Produit : `/run/secubox-leds/flux.json` =
  `{"genere_le": <epoch>, "niveaux": {"<cle>": 0..4|null}, "apprentissage": <bool>}` ;
  `pas_de_collecte(ref, prec: dict, valeurs: dict, t: float, planchers: dict) -> dict[str, int|None]`.
- Les clés `*.octets_*`, `*.paquets_*`, `fw.bloques`, `waf.blocages`, `adguard.requetes` sont des
  compteurs cumulés → débit par minute avant `observer`; les autres sont des jauges.
- Niveau 4 (absolu) : `services.arretes > 0`, `actor.critiques > 0`.

- [ ] **Étape 1 :** tests : `test_compteur_remis_a_zero_ignore` (point 1) ; `test_niveau_4_service_arrete` ;
  `test_ecriture_atomique` (fichier jamais partiel : écrit `.tmp` puis `os.replace`) ;
  `test_reference_sauvee_toutes_les_15_min` ; `test_unite_confinee` (unité : `User=secubox-leds`,
  `Nice=19`, `CPUWeight=10`, `AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `ProtectSystem=strict`, `ReadWritePaths=` limité aux deux répertoires, `RuntimeDirectory=secubox-leds`).
- [ ] **Étape 2 :** échec. **Étape 3 :** implémenter (boucle 10 s ; `nft` lancé par chemin absolu
  `/usr/sbin/nft -j list counters`, délai 5 s). **Étape 4 :** verts.
- [ ] **Étape 5 :** commit `feat(led-heartbeat): collecteur secubox-led-flux (ref #3361)`.

### Tâche 4 : moteur — source `flux`, niveau 4, ordonnancement

**Fichiers :**
- Modifier : `usr/lib/secubox-led-heartbeat/ledcouches.py`, `apparmor/secubox-led-pulse`
  (`/run/secubox-leds/flux.json r,`)
- Test : `tests/test_moteur_mochabinleds_3361.py`

**Interfaces :**
- `SourceFlux(Source)` : type `"flux"`, lit `niveaux[cle]` de `flux.json`, propriétaire attendu
  `secubox-leds`, `fraicheur_max` 60 s ; `apprentissage=true` → la couche s'affiche en violet.
- Palette de couche : 5 entrées (niveaux 0..4) ; une palette de 4 entrées reçoit `"rouge"` en 5ᵉ.
- `Ordonnanceur` : durée effective `min(duree × (1 + niveau_max), 24)` ; niveau 4 → la couche en
  cause passe en tête, rythme `eclats`, jusqu'au retour < 4 ; plusieurs couches en 4 → alternance,
  chacune revient au plus tard toutes les 30 s.

- [ ] **Étape 1 :** tests : `test_source_flux_lit_le_niveau`, `test_flux_perime_inconnu`,
  `test_mauvais_proprietaire_inconnu`, `test_palette_4_completee_rouge`,
  `test_duree_adaptative_plafonnee_24`, `test_priorite_alerte_interrompt`,
  `test_deux_alertes_alternent_30s`, `test_couches_existantes_inchangees` (les tests 3290 restent verts).
- [ ] **Étapes 2-4 :** rouge, implémentation, vert (suite complète `pytest tests`).
- [ ] **Étape 5 :** commit `feat(led-heartbeat): source flux, niveau critique, rotation adaptative (ref #3361)`.

### Tâche 5 : 8 séquences par défaut, paquet

**Fichiers :**
- Modifier : `etc/secubox/leds.toml` (8 couches `par_led` : systeme, reseau, firewall, waf, actor,
  adguard, services, soc ; `duree = 8` ; sources `flux` ; planchers par clé dans `[flux.planchers]`),
  `debian/changelog` (2.4.0-1~trixie1), `README.md`, `debian/control` (Depends: `nftables`, `python3`)
- Test : `tests/test_config_mochabinleds_3361.py`

- [ ] **Étape 1 :** tests : la config livrée se charge sans avertissement ; 8 couches dans l'ordre de la
  planche ; chaque source `flux` référence une clé produite par la tâche 2.
- [ ] **Étapes 2-4 :** rouge, implémentation, vert + `dpkg-buildpackage` OK.
- [ ] **Étape 5 :** commit `feat(led-heartbeat): 8 séquences mochabinleds par défaut, 2.4.0 (ref #3361)`.

### Tâche 6 : banc et mesure (hors code)

- [ ] Revue `relecteur-securite` (unité, AppArmor, `CAP_NET_ADMIN`) avant PR.
- [ ] gk6 : installer, 10 min de mesure CPU du collecteur (< 1 %), lecture des niveaux.
- [ ] gk2 : idem, œil du propriétaire ; gk1 : vérifier qu'une hausse locale ressort.
- [ ] Suivi : HISTORY.md, WIP.md, README du paquet.
