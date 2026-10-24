<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Maillage, projet 2 : services des pairs et liens directs — plan d'implémentation

> **Pour les agents :** SOUS-COMPÉTENCE REQUISE : superpowers:subagent-driven-development (recommandé) ou superpowers:executing-plans. Les étapes utilisent des cases `- [ ]`.

**Objectif :** chaque Hall montre les services publics des autres box du maillage (rubrique « Pairs »), et les pairs se relient en WireGuard direct, le maître restant le chemin de secours.

**Architecture :** (A) l'annuaire publie, par nœud, des offres signées « service » tirées des noms publics de la box ; un cache fichier des services des AUTRES nœuds est écrit par le même minuteur ; webos le sert en lecture et le Hall l'affiche. (B) le maître publie la liste de ses pairs vivants sur le master-link (7331, maillage seulement) ; un exécuteur root sur chaque pair l'applique en ajoutant des pairs `/32` dans `wg_mesh.json`, d'où `sbx-mesh-up` rend la configuration WireGuard.

**Pile :** Python 3 (FastAPI, pytest), bash, systemd, nginx, WireGuard, JS natif (Hall v2).

**Spec :** `docs/superpowers/specs/2026-10-24-maillage-pairs-services-design.md`

## Décisions prises au plan (écarts assumés avec la spec, à relire)

- **Pas de signature de la liste des pairs.** La clé de l'ancre est une clé WireGuard (X25519), pas une clé de signature. La liste est lue sur le master-link **par le tunnel WireGuard, à l'adresse maillée du maître**, et seulement si la clé WireGuard de ce pair-maître dans `wg_mesh.json` est celle de l'ancre (`ancre.accepte`). L'authenticité vient du tunnel (un pair `/32` ne peut pas usurper `10.10.0.1`). Côté maître, nginx n'accepte l'appel que d'une source `10.10.0.0/24`.
- **Services lus par un cache fichier**, pas par appel à l'annuaire : l'API de l'annuaire exige un jeton en lecture (#1256, #3136) ; un cache fichier écrit par le minuteur évite de relayer des jetons dans webos.
- **Pare-feu inchangé** : les règles d'entrée `iifname "wg-mesh"` existantes (8799, 8798, 53 depuis `10.10.0.0/24`, UDP 51820-51825) couvrent le trafic pair à pair ; aucune règle nouvelle, et `ip_forward` reste réservé au maître.
- **Les liens directs vivent dans `wg_mesh.json`** (entrées `"direct": true`), pas dans des `wg set` : `sbx-mesh-up` fait `wg syncconf` depuis ce fichier et effacerait tout ajout à chaud.
- **Seuls les pairs vivants sont publiés** par le maître (poignée de main < 10 min) : `wg_mesh.json` de gk2 porte des clones périmés (mêmes adresses 192.168.1.94 / .82 sous plusieurs noms).

## Contraintes globales

- En-tête SPDX CMSD-1.0 sur tout fichier créé (`scripts/license-headers.py`) ; commentaires et messages en français.
- Versions : annuaire `0.15.0-1~trixie1`, webos `1.20.0-1~trixie1`, p2p `1.19.0-1~trixie1` (une entrée de changelog par paquet, créée par la première tâche du paquet et complétée par les suivantes).
- Tests : `cd packages/<paquet> && python3 -m pytest tests -q` (jamais `pytest packages/` : collision des modules `api/`).
- Écritures de fichiers d'état : atomiques (`.tmp` puis `os.replace`). Entrées validées par regex stricte avant tout usage dans une commande ou une configuration.
- Toute décision d'exposition ou de lien : une ligne JSON dans `/var/log/secubox/audit.log` (`{"ts","module":"p2p","evenement",…}`, UTC RFC 3339).
- Aucun secret, aucune écriture hors des dossiers du paquet ; service non root sauf CLI confinée existante.
- Le dépôt ne livre aucun nom de domaine de box (`tests/test_aucun_vhost_gk2_3117.py`) : les tests n'emploient que des noms d'exemple.

## Points à contrôler en revue (Review Focus)

1. Un pair hostile annonce un service dont l'URL sort du domaine qu'il a déclaré → jamais affiché (Task 2).
2. Un pair du maître porte l'IP du maître, l'IP locale, une IP hors `10.10.0.0/24`, une clé invalide ou un nom/endpoint à saut de ligne → ignoré, rien d'écrit (Task 6).
3. Liste du maître illisible, vide ou maître injoignable → les liens directs existants ne bougent pas (Task 7).
4. Un pair mort (clone périmé, NAT) → jamais publié par le maître (Task 5), et un lien direct sans poignée de main depuis 3 minutes est retiré puis non retenté pendant 1 h (Task 6).
5. Cache absent, corrompu ou annuaire absent → `/public/pairs` répond `{"pairs": [], "disponible": false}` et le Hall le dit, jamais une erreur 500 (Tasks 3 et 4).

---

## Partie A — services des pairs dans chaque Hall

### Task 1 : l'annuaire publie les services publics de la box

**Fichiers :**
- Modifier : `packages/secubox-annuaire/annuaire/offres.py`
- Modifier : `packages/secubox-annuaire/systemd/secubox-annuaire-offres.timer`
- Créer : `packages/secubox-annuaire/tests/test_offres_services_3133.py`
- Modifier : `packages/secubox-annuaire/tests/test_offres_reelles_3021.py` (assertion de la minuterie : `OnUnitActiveSec=1h`)
- Modifier : `packages/secubox-annuaire/debian/changelog` (entrée `0.15.0-1~trixie1`)

**Interfaces :**
- Consomme : `offres._offre(name, kind, endpoint, description="", **scope)`, `offres.collecter_faits(...)`.
- Produit :
  - `offres.WEBOS_SOCK = "/run/secubox/webos.sock"`
  - `offres.EXCLUS_SERVICES: frozenset[str] = {"admin", "acces", "wpad", "boot"}`
  - `offres.services_des_noms(noms: Optional[dict]) -> List[Dict[str, Any]]` — `noms` est la réponse de `GET /public/noms` (`{"domaine","noeud","noms":[…]}`) ; chaque nom `<libellé>.<domaine>` à un seul niveau, hors exclus, rend `_offre(name=<libellé>, kind="service", endpoint="https://<nom>", description="<libellé> (<noeud>)", channel="public", service=<libellé>, domaine=<domaine>)`. Entrée absente, mal formée, domaine ou nom invalides : liste vide / nom ignoré. Au plus 64 offres.
  - `offres.lire_noms_webos(sock: str = WEBOS_SOCK, delai: float = 3.0) -> Optional[dict]` — GET `/public/noms` par socket Unix ; `None` si le socket manque, si le délai est dépassé ou si la réponse n'est pas un objet JSON.
  - `collecter_faits(..., webos_sock: str = WEBOS_SOCK)` ajoute `services_des_noms(lire_noms_webos(webos_sock))` avant le tri existant.

- [ ] **Étape 1 : écrire les tests qui échouent** (`test_offres_services_3133.py`) : `services_des_noms` sur `{"domaine":"gk3.exemple.test","noeud":"gk3","noms":["hall.gk3.exemple.test","admin.gk3.exemple.test","a.b.gk3.exemple.test","hall.autre.test","wpad.gk3.exemple.test"]}` rend exactement l'offre `hall` (endpoint `https://hall.gk3.exemple.test`, `scope.source == "sync"`, `scope.domaine == "gk3.exemple.test"`) ; entrées `None`, `{}`, `{"domaine":"x y"}`, `{"noms":"hall"}` rendent `[]` ; 100 noms valides rendent 64 offres. `lire_noms_webos` sur un socket Unix de test (serveur `http.server` sur `AF_UNIX`, voir le gabarit `_UnixSocketHTTPServer` de `packages/secubox-p2p/tests/test_annuaire_client.py`) rend le JSON ; sur un chemin absent rend `None`. `collecter_faits(webos_sock=<socket de test>)` contient l'offre `service` ; sans socket, les tests existants (`["app","app","onion"]`) restent inchangés.
- [ ] **Étape 2 : lancer, constater l'échec** — `cd packages/secubox-annuaire && python3 -m pytest tests/test_offres_services_3133.py -q` : échec, fonctions absentes.
- [ ] **Étape 3 : implémenter** `services_des_noms`, `lire_noms_webos` (module `http.client` + connexion Unix, jamais de réseau) et le branchement dans `collecter_faits`. Minuterie : `OnUnitActiveSec=1h` (le commentaire dit pourquoi : les services d'une box changent plus vite que ses onions).
- [ ] **Étape 4 : lancer** la suite du paquet — tout vert.
- [ ] **Étape 5 : valider** `git add` des fichiers ci-dessus ; `git commit -m "feat: annuaire, les services publics de la box deviennent des offres signées (ref #3133)"`.

### Task 2 : le cache des services des autres nœuds

**Fichiers :**
- Créer : `packages/secubox-annuaire/annuaire/pairs_services.py`
- Modifier : `packages/secubox-annuaire/sbin/annuairectl` (verbe `pairs-cache`, enregistré à côté de `offer-sync`, l.410)
- Modifier : `packages/secubox-annuaire/systemd/secubox-annuaire-offres.service` (un `ExecStart=/usr/sbin/annuairectl pairs-cache` après `offer-sync`)
- Créer : `packages/secubox-annuaire/tests/test_pairs_services_3133.py`
- Modifier : `packages/secubox-annuaire/debian/changelog`

**Interfaces :**
- Consomme : `annuaire.verbs._get_offers(journal)`, `annuaire.verbs._get_nodes(journal)` (dernier `NodeRecord` auto-signé par `did`, champs `did`, `boxname`, `ddns`, `mesh_ip`), `offres.SOURCE`, `cmd_offer_sync` pour l'ouverture du journal et de la clé.
- Produit :
  - `pairs_services.CACHE_PATH = Path("/var/lib/secubox/annuaire/services-pairs.json")`
  - `pairs_services.construire(journal, did_local: str) -> Dict[str, Any]` — `{"version": 1, "genere": "<UTC RFC 3339>", "pairs": [{"did","boxname","domaine","mesh_ip","services":[{"nom","endpoint","description"}]}]}`. Retient les offres `kind == "service"` dont `provider != did_local`, dont le fournisseur est un nœud connu (`_get_nodes`) avec un `ddns` non vide, et dont le **nom d'hôte de l'endpoint** (`https://` seulement) se termine par `"." + ddns` ; tri stable par `boxname` puis `nom` ; au plus 32 pairs × 64 services.
  - `pairs_services.ecrire(donnees: Dict, chemin: Path = CACHE_PATH) -> None` — atomique (`.tmp` + `os.replace`), mode 0644.
  - `pairs_services.lire(chemin: Path = CACHE_PATH) -> Optional[Dict]` — `None` si absent, illisible ou `version != 1`.
  - `annuairectl pairs-cache` : construit et écrit ; un journal illisible **laisse l'ancien cache en place** et sort en échec.

- [ ] **Étape 1 : tests** : sur un `Journal` temporaire (gabarit de `test_offres_reelles_3021.py` : `Journal`, `generate_keypair`, `genesis`, `offer_service`), deux nœuds distincts publient un `NodeRecord` (via `verbs.publish_node`) puis des offres `service`. Vérifier : (a) l'offre d'un autre nœud dans son domaine apparaît ; (b) **l'offre dont l'URL sort du `ddns` déclaré est absente** (Review Focus 1) ; (c) les offres du nœud local sont absentes ; (d) une offre révoquée est absente ; (e) nœud sans `NodeRecord` : absent ; (f) `lire` rend `None` pour un fichier absent, corrompu, `{"version": 2}` ; (g) un second `ecrire` ne laisse aucun `.tmp` ; (h) le texte de `annuairectl`, du service et de `debian/rules` porte le verbe `pairs-cache` (motif de `test_le_ctl_et_l_unite_portent_les_verbes`).
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter** `pairs_services.py` et le verbe `pairs-cache` (même ouverture du journal que `cmd_offer_sync`) ; câbler l'unité.
- [ ] **Étape 4 : suite du paquet verte** ; `ruff check` sur les fichiers touchés sans régression.
- [ ] **Étape 5 : commit** `feat: annuaire, cache des services des autres nœuds (ref #3133)`.

### Task 3 : webos sert les services des pairs

**Fichiers :**
- Créer : `packages/secubox-webos/api/pairs.py`
- Modifier : `packages/secubox-webos/api/main.py` (route `GET /public/pairs` dans `public_router`, à côté de `/noms`, l.481)
- Créer : `packages/secubox-webos/tests/test_pairs_3133.py`
- Modifier : `packages/secubox-webos/debian/changelog` (entrée `1.20.0-1~trixie1`)

**Interfaces :**
- Consomme : le fichier du cache (Tâche 2, même schéma), `require_lecture` déjà importé dans `main.py`.
- Produit :
  - `pairs.CACHE = Path("/var/lib/secubox/annuaire/services-pairs.json")`
  - `pairs.lire_cache(chemin: Path = CACHE) -> Dict[str, Any]` — `{"pairs": [...], "genere": <str|None>, "disponible": bool}` ; fichier absent/corrompu/`version != 1` : `{"pairs": [], "genere": None, "disponible": False}` ; ne rend jamais plus de 32 pairs ni de 64 services par pair ; ne rend que des champs `str` bornés (nom ≤ 63, endpoint ≤ 255 et commençant par `https://`).
  - `GET /public/pairs` avec `Depends(require_lecture)`.

- [ ] **Étape 1 : tests** (`TestClient`, `dependency_overrides[main.require_lecture]`, motif de `test_endpoints.py`) : cache valide → pairs rendus ; absent → `disponible: false` et statut 200 ; JSON corrompu → idem ; `endpoint` en `javascript:` ou `http://` ou plus de 255 car. → service écarté ; sans session et mode tableau de bord inactif (`monkeypatch.setattr(secubox_core.auth, "mode_tableau_de_bord_actif", lambda: False)`) → 401/403. Le motif `test_verdict_lan.py` (location nginx) n'est pas touché : `/api/v1/webos/` couvre déjà la route.
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter** `pairs.py` et la route.
- [ ] **Étape 4 : suite du paquet verte** (`cd packages/secubox-webos && python3 -m pytest tests -q`).
- [ ] **Étape 5 : commit** `feat: webos, GET /public/pairs sert les services des autres box (ref #3133)`.

### Task 4 : rubrique « Pairs » dans le Hall v2

**Fichiers :**
- Modifier : `packages/secubox-webos/www/hall/hall-v2.js` (`RUBRIQUES` l.53-70, `rendMosaique` l.207, nouvelles `chargePairs`, `tuilePair`)
- Modifier : `packages/secubox-webos/www/hall/hall-v2.css` (styles de `.sbx-ptuile`, groupes par nœud)
- Créer : `packages/secubox-webos/tests/test_pairs_hall_3133.py`
- Modifier : `packages/secubox-webos/debian/changelog`

**Interfaces :**
- Consomme : `GET /api/v1/webos/public/pairs` (Tâche 3), `ICONES` et `ico(n)` du Hall, motif `chargeApps`/`tuileApp` (`appsRefus` sur 401/403).
- Produit : entrée `{id:'pairs', nom:'Pairs', ic:<icône réseau existante de ICONES>, nav:'mosaique'}` dans `RUBRIQUES` ; `chargePairs(cb)` (fetch, cache mémoire 5 min, 401/403 → message de session) ; `tuilePair(nom_noeud, service)` — un lien `https://…` en `target="_blank" rel="noopener"`, **textes posés par `textContent`**, jamais d'`innerHTML`.

- [ ] **Étape 1 : tests** : (a) texte (motif `test_hall_v2_2996.py`) : `"{id:'pairs',nom:'Pairs'" in JS`, `"function tuilePair(" in JS`, `"innerHTML" not in` le bloc ajouté ; (b) navigateur (motif `test_applications_2996.py`, fixture `nav`, `pytest.importorskip("playwright.sync_api")`) : réponse simulée de `/public/pairs` avec deux nœuds ; clic sur `.sbx-side .sbx-rub[data-rub='pairs']` ; attendre `#view-mosaique:not(.hidden) .sbx-mosaique[data-vue='pairs']` ; les tuiles portent le nom du nœud et des liens `https://`; un service au nom `<img src=x onerror=window.PWNED=1>` est affiché comme **texte** (`window.PWNED` indéfini) ; `disponible:false` → message « Aucun autre nœud ne publie de service pour l’instant » ; 401 → message de session ; `erreurs == []` ; (c) `test_js_syntaxe.py` passe (`node --check`).
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter** la rubrique (pas de double navigation : sidebar seulement, #2996).
- [ ] **Étape 4 : suite du paquet verte.**
- [ ] **Étape 5 : commit** `feat: Hall v2, rubrique Pairs (ref #3133)`.

---

## Partie B — liens directs entre pairs

### Task 5 : le maître publie la liste de ses pairs vivants

**Fichiers :**
- Modifier : `packages/secubox-p2p/nginx/p2p-masterlink.conf` (carte `$p2p_pair_maille` et en-tête `X-SecuBox-Pair`)
- Modifier : `packages/secubox-p2p/api/main.py` (route `GET /master-link/pairs`)
- Créer : `packages/secubox-p2p/api/pairs_directs.py` (début : `liste_publiable`)
- Créer : `packages/secubox-p2p/tests/test_liste_pairs_3133.py`
- Modifier : `packages/secubox-p2p/debian/changelog` (entrée `1.19.0-1~trixie1`)

**Interfaces :**
- Consomme : `get_wg_mesh_config()` (`peers[]` : `public_key`, `mesh_ip`, `name`, `endpoint`), `mesh.load_handshakes()` (`{clé: horodatage}` lu dans `/run/secubox/p2p/wg-mesh-handshakes.json`), `mesh.valid_wg_key(key)`, `require_lecture`.
- Produit :
  - `pairs_directs.valider_pair(p: Any, reseau: str = "10.10.0.0/24") -> Optional[Dict[str, str]]` — filtre commun aux Tâches 5 et 6 : nom `^[a-z0-9][a-z0-9-]{0,30}$` (aucun caractère de contrôle), `mesh_ip` IPv4 dans `reseau`, clé WireGuard valide (`mesh.valid_wg_key`), endpoint `a.b.c.d:port` privé (RFC 1918, hors `reseau`, port 1-65535) ; rend `{"nom","mesh_ip","cle_publique","endpoint"}` normalisé ou `None`.
  - `pairs_directs.liste_publiable(etat: dict, poignees: dict, maintenant: float, age_max_s: int = 600) -> List[Dict[str, str]]` — `[{"nom","mesh_ip","cle_publique","endpoint"}]` pour les pairs de rôle pair (`allowed_ips` en `/32`) dont la dernière poignée de main a moins de `age_max_s` secondes ; clé valide, `mesh_ip` dans `10.10.0.0/24`, endpoint `a.b.c.d:port` privé (RFC 1918, hors `10.10.0.0/24`) ; trié par `mesh_ip` ; **dédoublonné par clé publique** (garde la poignée la plus récente) ; au plus 32.
  - `GET /master-link/pairs` → `{"version": 1, "pairs": [...]}`. Garde : `X-SecuBox-Pair: 1` (posé par nginx seulement pour une source `10.10.0.0/24`) **ou** `require_lecture` ; refus sinon.
  - nginx : `geo $remote_addr $p2p_pair_maille { default 0; 10.10.0.0/24 1; }` et `proxy_set_header X-SecuBox-Pair $p2p_pair_maille;` dans le `location` existant (la valeur est toujours écrasée côté nginx, un client ne peut pas la forger).

- [ ] **Étape 1 : tests** : état de gk2 simulé avec sept pairs dont deux clones périmés (poignée > 10 min ou absente) et deux entrées de **même clé** → seuls les vivants, sans doublon ; endpoint public (`8.8.8.8:51822`), endpoint avec saut de ligne, nom avec saut de ligne, clé invalide, `mesh_ip` hors réseau → écartés ; route : avec `X-SecuBox-Pair: 1` → 200 sans jeton ; sans l'en-tête et sans session → 401/403 ; avec `X-SecuBox-Pair: 0` → 401/403 ; texte de `p2p-masterlink.conf` : la carte `geo` et `proxy_set_header X-SecuBox-Pair` y sont, et `test_verdict_lan.py` reste vert.
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter.**
- [ ] **Étape 4 : suite du paquet verte.**
- [ ] **Étape 5 : commit** `feat: p2p, le maître publie la liste de ses pairs vivants (ref #3133)`.

### Task 6 : le calcul des liens directs (logique pure)

**Fichiers :**
- Modifier : `packages/secubox-p2p/api/pairs_directs.py`
- Créer : `packages/secubox-p2p/tests/test_pairs_directs_3133.py`
- Modifier : `packages/secubox-p2p/debian/changelog`

**Interfaces :**
- Consomme : `pairs_directs.valider_pair` (Task 5), `ancre.lire()` / `ancre.accepte(ancre, cle_maitre)`, format d'un pair de `wg_mesh.json` (`public_key`, `allowed_ips`, `mesh_ip`, `name`, `endpoint`).
- Produit :
  - `pairs_directs.calculer(etat: dict, liste: List[Any], poignees: Dict[str, float], maintenant: float, refuses: Dict[str, float], delai_poignee_s: int = 180, retente_apres_s: int = 3600) -> Dict[str, Any]` — rend `{"ajouts": [pair…], "retraits": [cle_publique…], "refuses": {cle: jusqua}}`.
    - Ajout : pair valide, ni soi-même (clé de `etat["public_key"]`), ni le maître (pair `allowed_ips` en `/24`), ni une `mesh_ip` ou une clé déjà présente en entrée **non directe**, ni refusé en cours.
    - Retrait : entrée `"direct": true` absente de la liste, **ou** sans poignée de main de moins de `delai_poignee_s` alors que `"direct_depuis"` date de plus de `delai_poignee_s` ; ce dernier cas inscrit la clé dans `refuses` (`maintenant + retente_apres_s`).
    - Les entrées non directes ne sont **jamais** retirées.
  - `pairs_directs.appliquer(etat: dict, calcul: Dict[str, Any], maintenant: float) -> dict` — rend un nouvel état : pairs ajoutés avec `{"public_key","allowed_ips": "<ip>/32","mesh_ip","name","endpoint","direct": True,"direct_depuis": int(maintenant)}`, retirés supprimés ; ne modifie rien d'autre.

- [ ] **Étape 1 : tests** (Review Focus 2 et 4) : liste contenant l'IP du maître, la sienne, une clé déjà connue non directe, un nom `a\nb`, un endpoint `1.2.3.4:51822`, un `mesh_ip` `10.10.1.5` → aucun ajout ; deux pairs valides → deux ajouts ; pair direct disparu de la liste → retrait ; pair direct sans poignée depuis plus de 3 min → retrait **et** entrée dans `refuses`, puis non réajouté avant `jusqua` ; pair direct jeune (moins de 3 min) sans poignée → conservé ; entrée non directe jamais retirée même absente de la liste ; `appliquer` laisse intacts le pair du maître et les champs inconnus de l'état ; un second calcul sur l'état appliqué ne propose rien (idempotence).
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter** (fonctions pures, aucune lecture de fichier, aucun appel réseau).
- [ ] **Étape 4 : suite du paquet verte.**
- [ ] **Étape 5 : commit** `feat: p2p, calcul des liens directs entre pairs (ref #3133)`.

### Task 7 : l'exécuteur root et sa minuterie

**Fichiers :**
- Créer : `packages/secubox-p2p/sbin/secubox-maillage-pairs`
- Créer : `packages/secubox-p2p/systemd/secubox-maillage-pairs.service`
- Créer : `packages/secubox-p2p/systemd/secubox-maillage-pairs.timer`
- Modifier : `packages/secubox-p2p/debian/rules` (installation du script et des unités, motif de `secubox-relais-maillage`, boucle l.62-68)
- Modifier : `packages/secubox-p2p/debian/postinst` (`systemctl enable` + `start` de la minuterie, motif de `secubox-relais-maillage.timer`)
- Modifier : `packages/secubox-p2p/README.md`
- Créer : `packages/secubox-p2p/tests/test_maillage_pairs_3133.py`
- Modifier : `packages/secubox-p2p/debian/changelog`

**Interfaces :**
- Consomme : `pairs_directs.calculer/appliquer/valider_pair`, `ancre.lire/accepte/audit`, `/var/lib/secubox/p2p/wg_mesh.json`, `/run/secubox/p2p/wg-mesh-handshakes.json`, réglage `/etc/secubox/p2p.toml` `[maillage] liens_directs = true` (défaut `true`).
- Produit : CLI `secubox-maillage-pairs` (root, Python 3, `#!/usr/bin/env python3`), sous-commandes `synchroniser` (défaut) et `etat` ; variables d'environnement de test `SBX_PAIRS_ETAT`, `SBX_PAIRS_POIGNEES`, `SBX_PAIRS_ANCRE`, `SBX_PAIRS_REFUSES` (`/var/lib/secubox/p2p/pairs-directs-refuses.json`), `SBX_PAIRS_MAITRE_URL` (le test fournit une URL locale).
  - `synchroniser` : (1) sort sans rien faire si `role == "master"`, si le réglage est faux, ou s'il n'y a pas d'ancre ; (2) trouve dans `wg_mesh.json` le pair maître (`allowed_ips` en `/24`) et **exige que sa clé soit celle de l'ancre** (`ancre.accepte`), sinon journalise et sort ; (3) lit `http://<mesh_ip du maître>:7331/api/v1/p2p/master-link/pairs` (délai 6 s) ; (4) **échec réseau, JSON invalide, `version != 1` ou `pairs` absent : sort sans rien changer** (Review Focus 3) ; une liste **vide valide** retire seulement les liens directs ; (5) `calculer`, `appliquer`, écriture atomique de `wg_mesh.json` en conservant propriétaire et mode ; (6) une ligne d'audit par ajout/retrait/refus (`evenement`: `pair_direct_ajoute`, `pair_direct_retire`, `pair_direct_refuse`) ; le changement de `wg_mesh.json` déclenche `secubox-p2p-mesh.path` donc `sbx-mesh-up`.
  - Unité : `Type=oneshot`, `ExecStart=/usr/sbin/secubox-maillage-pairs synchroniser`, `After=wg-quick@wg-mesh.service`, `TimeoutStartSec=2min` ; minuterie : `OnBootSec=3min`, `OnActiveSec=3min`, `OnUnitActiveSec=5min`, `RandomizedDelaySec=30s`, `Persistent=true`.

- [ ] **Étape 1 : tests** (le script exige root : tester le module Python par `importlib` depuis le fichier, motif de `_python_de` ou chargement direct, avec les variables d'environnement vers `tmp_path` et un serveur HTTP local pour la liste) : maître absent de l'état → rien ; clé du maître ≠ ancre → rien et aucune requête ; liste valide → `wg_mesh.json` reçoit les pairs `direct: true` (propriétaire/mode conservés, autres champs intacts) et l'audit est écrit ; **serveur qui renvoie 500 / du texte / `{"version":2}` → fichier inchangé** ; liste vide valide → seuls les directs disparaissent ; réglage `liens_directs = false` → rien ; textes de l'unité, de la minuterie, de `debian/rules` et du `postinst` portent le script et la minuterie ; rendu : `mesh.render_wg_conf(état avec un pair direct)` contient `AllowedIPs = 10.10.0.x/32`, `Endpoint = …` et `PersistentKeepalive = 25`, et le pair maître garde `/24`.
- [ ] **Étape 2 : constater l'échec.**
- [ ] **Étape 3 : implémenter** le script, les unités, le câblage Debian, le README (section « Liens directs »).
- [ ] **Étape 4 : suite du paquet verte** ; `shellcheck`/`ruff` sans régression sur les fichiers touchés.
- [ ] **Étape 5 : commit** `feat: p2p, secubox-maillage-pairs relie les pairs en direct (ref #3133)`.

### Task 8 : banc et suivi (par le contrôleur, pas par un sous-agent)

- [ ] Relecture de sécurité de la branche entière (liste signée absente, source `10.10.0.0/24`, valeurs injectées dans `wg_mesh.json`, `X-SecuBox-Pair`).
- [ ] Construction des trois paquets, publication apt, installation : **gk1 d'abord**, puis gk2 (maître), puis gk3 ; jamais d'installation locale par `dpkg -i`.
- [ ] Banc (spec, « Tests et preuves ») : le Hall de gk1 montre les services de gk3 (cache écrit après la collecte horaire : lancer `systemctl start secubox-annuaire-offres` sur chaque box) ; `wg show wg-mesh` de gk1 montre gk3 en `/32` avec poignée de main ; arrêt temporaire du pair de gk3 chez le maître puis retour ; contrôle qu'un lien mort est retiré après 3 minutes.
- [ ] `HISTORY.md`, `WIP.md`, README des paquets ; fermeture de #3133 seulement après déploiement.
