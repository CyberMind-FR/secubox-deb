<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# DPI enrichi par les données d'ad-guard — plan d'implémentation (#1960)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** la page du DPI étiquette les destinations qu'il ne classe pas avec la connaissance d'ad-guard, et montre une section « Appareils du LAN (vue DNS) », sans jamais mélanger mesure et déduction.

**Architecture :** ad-guard publie un fichier d'échange en lecture seule (`dpi-feed.json`) ; le DPI lit ce fichier et les fichiers de données d'ad-guard (`services.txt`, listes), sans exécuter de code d'ad-guard ; le DPI reste en lecture seule (aucune écriture de `rules.json`, `sbxdpi` inchangé).

**Tech Stack :** Python 3.11+ (FastAPI), JS sans dépendance (`textContent`), fichiers JSON écrits atomiquement.

**Spec :** `docs/superpowers/specs/2026-10-04-dpi-enrichi-adguard-design.md`

## Global Constraints

- Le DPI **ne modifie jamais** `/etc/secubox/dpi/rules.json` ni `sbxdpi` ; il **n'importe aucun module d'ad-guard** : il lit des fichiers de données.
- Une règle du DPI qui connaît un nom **gagne toujours** sur l'étiquette d'ad-guard.
- Une donnée absente, périmée (> 15 min) ou corrompue ⇒ `{"disponible": false}` ou comportement actuel inchangé ; jamais de chiffre périmé présenté comme frais.
- La section « vue DNS » n'affiche **aucun volume** ; chaque ligne porte « vu au DNS » ; la section DPI garde « mesuré par le DPI ».
- Fichier d'échange : `0640 secubox:secubox`, écriture atomique (`os.replace`), lecture sans suivre les liens symboliques, 10 services par appareil au plus, fenêtre = jour courant (UTC), aucun nom invalide, ni secret, ni cookie, ni URL.
- Rendu des nouvelles sections par `textContent` uniquement (la page existante garde ses `innerHTML` historiques : non étendus).
- Routes d'admin : `require_jwt` ; routes synchrones si elles lisent des fichiers volumineux.
- En-tête SPDX CMSD-1.0 ; commits `type: message (ref #1960)` **sans** ligne d'attribution Claude ; versions : `secubox-ad-guard` 1.6.0, `secubox-dpi` 1.5.0.
- Source d'abord ; vérifier `dpkg -l` sur gk2 avant de bâtir (ad-guard 1.5.0, dpi 1.4.19-1~bookworm2) ; après déploiement, **redémarrer `secubox-aggregator` et vérifier par l'adresse publique** (`curl -sk https://127.0.0.1/api/v1/dpi/... -H "Host: admin.gk2.secubox.in"`).
- Jamais de `git stash`.

## Review Focus

1. **Nom hostile** (`"; x`, `<img>`, majuscules, très long) dans `services.txt`, les listes ou le fichier d'échange : jamais classé ni recopié ; page sans exécution de HTML.
2. **Fichier d'échange remplacé par un lien symbolique, corrompu, périmé, énorme** : refusé ou `disponible: false`, jamais d'exception.
3. **Règle du DPI contre étiquette d'ad-guard** : la règle du DPI gagne ; étiquette absente si rien ne correspond.
4. **Confidentialité** : le fichier d'échange ne contient que des agrégats (top 10 services, types, compteurs) — jamais la liste des noms demandés ni un historique.
5. **Appareil du LAN sans MAC connue** : regroupé par adresse, jamais fusionné avec un autre ; la box et la passerelle exclues.

---

## File Structure

| Fichier | Responsabilité |
|---|---|
| `packages/secubox-ad-guard/api/dnstv_dpifeed.py` (créer) | construit et écrit le fichier d'échange |
| `packages/secubox-ad-guard/api/dnstv.py` (modifier) | `Magasin.compteurs_detail` |
| `packages/secubox-ad-guard/sbin/secubox-adguard-auto` (modifier) | rafraîchit le fichier toutes les 5 min |
| `packages/secubox-dpi/api/adguard_enrich.py` (créer) | lit `services.txt` et les listes, classe un nom, enrichit `/usage` |
| `packages/secubox-dpi/api/main.py` (modifier) | enrichissement de `/usage`, route `GET /lan_dns` |
| `packages/secubox-dpi/www/dpi/index.html` (modifier) | sections « non classées étiquetées » et « Appareils du LAN (vue DNS) » |
| `tests/` des deux paquets (créer) | un fichier par module |

Tests : `cd packages/secubox-ad-guard && python -m pytest tests -q` ; `cd packages/secubox-dpi && python -m pytest tests -q` (vérifier d'abord que le `conftest.py` de `secubox-dpi` met le paquet et `common/` sur le chemin).

---

### Task 1 : fichier d'échange d'ad-guard

**Files :** créer `api/dnstv_dpifeed.py` ; modifier `api/dnstv.py` ; tester `tests/test_dnstv_dpifeed.py` (paquet `secubox-ad-guard`).

**Interfaces :**
- `Magasin.compteurs_detail(depuis_jour:str) -> dict[str, dict[str, tuple[int,int]]]` : client → domaine → (requêtes, dont bloquées).
- `construire(compteurs, voisins, etat, services, exclus, maintenant) -> dict` : `{"version":1,"genere":int,"fenetre":"jour courant (UTC)","appareils":[{"nom","mac","adresses":[…],"mode","origine","requetes","bloquees","domaines","services":[{"organisation","type","requetes","bloquees"}…≤10],"types":{type:requetes}}]}` trié par requêtes décroissantes ; appareils sans MAC regroupés par adresse ; `nom` = nom déclaré dans `etat` (même MAC ou même adresse) sinon `appareil <4 derniers hex de la MAC>` ou l'adresse.
- `ecrire_feed(feed, dossier=None)` (atomique, `0640`), `charger_feed(dossier=None) -> dict | None` (sans suivre les liens, `None` si absent/corrompu).
- Un domaine non valide (`dnstv.valider_domaine`) n'est ni compté ni recopié ; une organisation vient de `ClasseurServices` ; un nom inconnu compte dans le service `inconnu`.

- [ ] **Step 1 : tests rouges** — couvrir : (a) deux adresses d'une même MAC (IPv4 + IPv6) donnent **un** appareil avec adresses regroupées ; (b) un appareil sans MAC reste séparé ; (c) la box et la passerelle (`exclus`) n'apparaissent pas ; (d) top 10 services plafonné et trié ; (e) types agrégés ; (f) taux : `bloquees` ≤ `requetes` ; (g) nom hostile ignoré ; (h) nom d'appareil repris de l'état déclaré ; (i) écriture atomique, `0640`, lien symbolique refusé en lecture, JSON corrompu ⇒ `None` ; (j) le fichier ne contient **aucun nom de domaine** hors des organisations et types (vie privée : grep des domaines d'entrée absent du JSON sérialisé).

```python
def test_le_feed_ne_contient_aucun_nom_de_domaine_brut():
    feed = F.construire({"192.168.1.95": {"cloudreplay.ftven.fr": (30, 0), "7cd77.v.fwmrm.net": (12, 12)}}, {}, ETAT, SERVICES, set(), T0)
    brut = json.dumps(feed, ensure_ascii=False)
    assert "cloudreplay" not in brut and "fwmrm.net" not in brut and "France Télévisions" in brut
```

- [ ] **Step 2 :** `pytest tests/test_dnstv_dpifeed.py -q` → Expected : FAIL. **Step 3 : implémenter** `construire` (regroupement par `dnstv.regrouper_sources`, classification par `ClasseurServices.classer`, regroupement par organisation, 10 premiers par requêtes), `ecrire_feed` (`tempfile.mkstemp` + `os.fchmod 0o640` + `os.replace`), `charger_feed` (`os.O_NOFOLLOW`, lecture plafonnée à 1 Mio). **Step 4 :** `pytest tests -q` → Expected : PASS. **Step 5 :** commit `feat: fichier d'echange ad-guard pour le DPI (ref #1960)`.

---

### Task 2 : le moteur d'ad-guard rafraîchit le fichier

**Files :** modifier `sbin/secubox-adguard-auto` ; tester `tests/test_dnstv_dpifeed.py`.

**Interfaces :** `rafraichir_feed(maintenant, voisins, locales, passerelles, force=False) -> bool` dans `secubox-adguard-auto` : écrit le fichier si `etat["actif"]` et si le fichier a plus de `PERIODE_FEED_S = 300` s (ou absent) ; rend vrai s'il l'a écrit. Appelé au début de `main()`, **avant** la sortie anticipée « aucun appareil auto », et **hors** du verrou des règles.

- [ ] **Step 1 : tests rouges** — (a) POC actif sans appareil `auto` ⇒ le fichier est quand même écrit ; (b) deux passages à moins de 300 s ⇒ une seule écriture ; (c) POC inactif ⇒ rien écrit ; (d) une erreur de lecture de la base ne fait pas échouer le script (retour 0, message sur stderr) ; (e) le passage normal du moteur n'est pas ralenti (aucune dépendance sur le verrou). 
- [ ] **Step 2 :** FAIL attendu. **Step 3 : implémenter.** **Step 4 :** `pytest tests -q`. **Step 5 :** commit `feat: le moteur rafraichit le fichier d'echange toutes les 5 minutes (ref #1960)`.

---

### Task 3 : étiquettes d'ad-guard dans le DPI

**Files :** créer `packages/secubox-dpi/api/adguard_enrich.py` ; tester `packages/secubox-dpi/tests/test_adguard_enrich.py`.

**Interfaces :** `charger_services(chemin) -> list[tuple[str,str,str]]` (suffixe, organisation, type ; `_`→espace ; plus long suffixe d'abord ; ligne invalide ignorée) ; `charger_listes(dossier) -> dict[str,str]` (domaine → catégorie ; fichiers `advertising|tracking|telemetry|social.txt`) ; `class Etiqueteur(services, listes)` avec `.etiqueter(hote) -> dict` : `{}` ou `{"organisation","type","categorie","source":"ad-guard"}` ; `enrichir_usage(usage: dict, etiqueteur, classer_dpi) -> dict` : pour chaque entrée de `usage["unknown"]` que `classer_dpi(nom)` ne connaît pas, ajoute `etiquette` ; ajoute `usage["adguard"] = {"etiquetes": n, "total": m}` ; ne retire ni ne déplace rien.

- [ ] **Step 1 : tests rouges** — (a) un suffixe de `services.txt` (`fwmrm.net`, `ftven.fr`) étiquette `7cd77.v.fwmrm.net` (publicité) ; (b) une catégorie de liste étiquette un domaine absent de `services.txt` ; (c) **la règle du DPI gagne** : si `classer_dpi` connaît le nom, aucune étiquette ; (d) nom hostile, majuscules, IP seule, point final, `host=None` ⇒ `{}` sans exception ; (e) données absentes ⇒ `enrichir_usage` rend `usage` identique octet pour octet ; (f) l'usage d'origine n'est pas modifié (copie) ; (g) 4 000 noms inconnus s'étiquettent en moins d'une seconde (borne de performance).
- [ ] **Step 2 :** FAIL attendu (`ModuleNotFoundError`). **Step 3 : implémenter** (analyse de texte seulement, `re.fullmatch` sur les noms, plafonds de lecture 1 Mio). **Step 4 :** `pytest tests/test_adguard_enrich.py -q`. **Step 5 :** commit `feat: etiquettes ad-guard pour les destinations non classees du DPI (ref #1960)`.

---

### Task 4 : API du DPI

**Files :** modifier `packages/secubox-dpi/api/main.py` ; tester `packages/secubox-dpi/tests/test_lan_dns.py`.

**Interfaces :** `GET /usage` (inchangé hors ajout des champs `etiquette` et `adguard`) ; `GET /lan_dns` (`require_jwt`) → `{"disponible": True, "age_s": int, "fenetre": str, "appareils": [...]}` ou `{"disponible": False, "raison": "absent|périmé|illisible"}` ; constantes `ADGUARD_FEED = Path("/var/lib/secubox/ad-guard/dnstv/dpi-feed.json")`, `ADGUARD_LISTES = Path("/usr/share/secubox/ad-guard/lists")`, `FEED_PEREMPTION_S = 900`. Lecture avec `O_NOFOLLOW`, plafond 2 Mio, structure revalidée (`version == 1`, liste d'appareils, chaînes bornées).

- [ ] **Step 1 : tests rouges** — gardes (401 sans jeton), fichier absent/périmé/corrompu/lien symbolique/énorme ⇒ `disponible: False` sans exception, appareils hostiles (noms HTML) rendus tels quels en JSON (l'échappement est côté page), `/usage` enrichi quand le feed et les listes existent, `/usage` identique quand ils manquent, la règle du DPI gagne dans `/usage`.
- [ ] **Step 2 :** FAIL attendu. **Step 3 : implémenter.** **Step 4 :** `pytest tests -q`. **Step 5 :** commit `feat: route lan_dns et enrichissement de usage dans l'API du DPI (ref #1960)`.

---

### Task 5 : page du DPI

**Files :** modifier `packages/secubox-dpi/www/dpi/index.html` ; tester `packages/secubox-dpi/tests/test_ui_lan_dns.py` (Chromium via Playwright, comme `secubox-ad-guard/tests/test_dnstv_ui.py`).

**Contenu :** (1) carte **« Destinations non classées »** : les entrées de `/usage.unknown` avec leur étiquette « d'après ad-guard » (organisation, type, badge « publicité »/« pistage » si la catégorie le dit) ; (2) carte **« Appareils du LAN (vue DNS) »** : par appareil, nom, adresses, mode, requêtes, taux de blocage, services (top 10), avec la mention **« vu au DNS — noms demandés, pas de volumes »** et l'âge des données ; (3) la mention **« mesuré par le DPI »** sur les cartes existantes. `textContent` uniquement ; `disponible: false` ⇒ message explicite (« données ad-guard absentes ou périmées »), jamais d'exception ; rafraîchissement 30 s.

- [ ] **Step 1 : tests navigateur rouges** — rendu avec données ; **texte piégé** (`<img onerror>`) en nom, adresse, organisation ⇒ aucun nœud `img`, `window.__pwn` indéfini ; `disponible:false` ⇒ message ; API HTML 502 ⇒ aucune exception ; absence de mot « octets » / « volume » dans la section DNS.
- [ ] **Step 2 :** FAIL attendu. **Step 3 : implémenter.** **Step 4 :** tests du paquet. **Step 5 :** commit `feat: sections non classees et appareils du LAN dans la page du DPI (ref #1960)`.

---

### Task 6 : paquets, déploiement, essai réel

- [ ] **Step 1 :** `debian/changelog` + README des deux paquets (route `lan_dns`, fichier d'échange, limites) ; `secubox-ad-guard` 1.6.0 ; `secubox-dpi` 1.5.0.
- [ ] **Step 2 :** suites complètes, `ruff`, `dpkg-buildpackage -us -uc -b -d` pour les deux.
- [ ] **Step 3 :** base : `ssh root@192.168.1.200 'dpkg -l secubox-ad-guard secubox-dpi'` (1.5.0 et 1.4.19-1~bookworm2) ; s'arrêter si le dépôt ou la box dépasse.
- [ ] **Step 4 :** relecture de sécurité (sous-agent `relecteur-securite`) sur le diff complet avant tout déploiement ; corriger Critique et Important avec un test rouge chacun.
- [ ] **Step 5 : déployer** (`dpkg -i` des deux, `reprepro includedeb`, `systemctl restart secubox-group@g1`, `systemctl restart secubox-aggregator`), vérifier **par l'adresse publique** `dpi/usage` (champ `adguard`), `dpi/lan_dns`, la page, et la présence du fichier `0640`.
- [ ] **Step 6 : essai réel** : la liste « inconnu » du DPI se réduit (nombre d'entrées étiquetées affiché), la section LAN montre les TV avec la mention « vu au DNS », la page ne plante pas quand le fichier est supprimé puis recréé.
- [ ] **Step 7 :** HISTORY/WIP, mémoire ; `closes #1960` **seulement** après validation du propriétaire ; PR, fusion, nettoyage.

---

## Self-Review

**Couverture de la spec.** §2 A → T3/T4/T5 ; §2 B′ → T1/T2/T4/T5 ; §3 architecture (fichier d'échange, lecture des données, route, page) → T1–T5 ; §4 sécurité → Review Focus 1–5 et tests T1/T3/T4 ; §5 tests → un fichier par tâche ; §6 livraison → T6 ; §7 limites → mentions dans la page (T5) et le README (T6). Aucune lacune relevée ; la piste C reste hors périmètre, comme dit dans la spec.

**Placeholders.** Les tests des tâches 2 à 5 sont décrits par cas, pas écrits en code ; l'implémentateur les écrit avant le code, dans le style des tâches précédentes de #1954/#1959. Un seul extrait est donné en code (T1, vie privée). `conftest.py` de `secubox-dpi` à vérifier au démarrage de T3.

**Cohérence des types.** `compteurs_detail` (T1) alimente `construire` (T1) ; `ecrire_feed/charger_feed` (T1) et le chemin `ADGUARD_FEED` (T4) désignent le même fichier ; l'`Etiqueteur` (T3) est utilisé par `/usage` (T4) ; les champs de `/lan_dns` (T4) sont ceux que lit la page (T5).

**Points ouverts.** La page du DPI contient déjà des `innerHTML` historiques (non étendus ici, à traiter à part) ; `/usage` n'est pas consommé par la page du DPI mais par la carte du Hall (`secubox-webos/www/hall/cardlets/dpi.html`) : T5 ajoute la carte à la page du DPI, la carte du Hall n'est pas modifiée ; la fenêtre « jour courant (UTC) » est à confirmer comme suffisante avec le propriétaire.
