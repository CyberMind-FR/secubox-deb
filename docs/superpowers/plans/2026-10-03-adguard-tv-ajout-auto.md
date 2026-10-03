<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ad-guard TV — ajout automatique, puits complet, agrégation — plan d'implémentation (#1959)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** les TV et streamers qui utilisent gk2 comme DNS sont détectés par comportement, ajoutés au périmètre en mode `auto` avec le profil de base, gardent le puits de production complet, et mettent en commun ce qu'ils apprennent.

**Architecture :** modules purs testables (détecteur, profil/agrégation, ajout) branchés sur le moteur de #1954 (minuterie `secubox-adguard-auto`) ; une seule porte privilégiée inchangée (`secubox-adguard-tv regles-appliquer`) ; le rendu Unbound des appareils `auto` passe à `view-first: yes` sans zone transparente (mesuré sur Unbound 1.17.1).

**Tech Stack :** Python 3.11+ (3.13 sur Trixie), FastAPI, SQLite (compteurs existants), Unbound 1.17.1, systemd, JS sans dépendance (`textContent`).

**Spec :** `docs/superpowers/specs/2026-10-03-adguard-tv-ajout-auto-design.md`

## Global Constraints

- Aucun mitmproxy, aucune inspection HTTPS, aucun contournement de DRM.
- Écritures de règles/état : sous `dnstv_regles.verrou()` ; le contrôleur root relit et revalide tout (liens symboliques refusés) — inchangé.
- Toute route d'écriture : `require_jwt` ; lecture : `require_lecture` ; les routes qui appellent le contrôleur sont **synchrones** (`def`).
- `ajout_auto` est **faux par défaut dans le paquet** ; seul un administrateur l'active. Plafond **3 nouveaux appareils par jour**, **un rechargement du DNS par heure au plus**, **32 adresses au plus** (limite de `valider_etat`).
- Un appareil ajouté automatiquement reçoit **uniquement** le profil de base (graine + agrégé) en règles confirmées ; tout autre blocage suit le cycle de #1954 (essai, confirmation).
- Identité d'un appareil = **MAC** (table des voisins), jamais l'adresse ; un appareil sans MAC connue n'est **jamais** ajouté automatiquement.
- Les requêtes de la box elle-même ne sont **pas** journalisées (`dnstv_recents`, `dnstv_counts`).
- Aucune organisation inventée dans l'interface ; rendu par `textContent` ; aucun libellé de l'API pris tel quel pour une décision.
- En-tête SPDX CMSD-1.0 sur tout fichier ; version `1.5.0-1~bookworm1` ; commits `type: message (ref #1959)`, **sans** ligne d'attribution Claude ; pas de mention « CyberMind Produits SASU ».
- Source d'abord (aucune édition live) ; vérifier `dpkg -l secubox-ad-guard` sur gk2 avant de bâtir (déployé : 1.4.3) ; **après chaque mise à jour, redémarrer `secubox-aggregator` (il sert ce module dans son processus) et vérifier PAR L'ADRESSE PUBLIQUE** (`curl -sk https://127.0.0.1/api/v1/ad-guard/adblock-tv/... -H "Host: admin.gk2.secubox.in"`), jamais seulement par le socket du module.
- Aucune option systemd reposant sur seccomp dans les unités qui appellent sudo (`LockPersonality`, `ProtectKernelTunables`, `SystemCallFilter`…) : elles activent NoNewPrivileges d'office (mesuré le 2026-10-03).

## Review Focus

1. **Appareil sans MAC connue** (adresse seule) ou MAC « tout à zéro » : jamais ajouté ; une MAC ignorée n'est jamais rajoutée.
2. **MAC, nom ou domaine hostile** (`"; reboot`, `../`, majuscules, très long) dans les compteurs, l'état ou les règles : jamais écrit dans la configuration Unbound.
3. **Plafonds** : le 4ᵉ appareil du jour, l'ajout moins d'une heure après un changement et la 33ᵉ adresse sont différés ou refusés **sans erreur** ni boucle.
4. **Une IPv6 de confidentialité qui change** est rattachée à l'appareil ; une adresse non vue depuis 7 jours est retirée, mais **une adresse au moins reste**.
5. **Téléphone ou ordinateur qui regarde le même replay** : le signal peut passer ; le retrait et l'ignorance en un clic doivent suffire ; la box, la passerelle et les adresses locales ne sont jamais détectées.
6. **Mode `puits=false` ou appareils `observe`/`block`** : rendu transparent comme avant (aucune régression de #1954).
7. **Boucle d'auto-renforcement de l'agrégation** : les règles issues du profil lui-même ne comptent pas pour l'agréger.

---

## File Structure

| Fichier | Responsabilité |
|---|---|
| `api/dnstv.py` (modifier) | champs d'état (`mode_defaut`, `ajout_auto`, `ignores`, `mac`/`origine`/`ajoute`/`preuve`/`puits`), rendu `view-first`, `Magasin.ajouter(exclus)`, `compteurs_clients`, `adresses_locales` |
| `api/dnstv_regles.py` (modifier) | `proposer(..., motif=)` |
| `api/dnstv_profil.py` (créer) | graine, profil agrégé, équipement d'un appareil, candidats agrégés |
| `api/dnstv_detecteur.py` (créer) | détection « TV/streamer probable » |
| `api/dnstv_ajout.py` (créer) | ajout, suivi des adresses, plafonds, état de suivi |
| `api/dnstv_auto.py` (modifier) | agrégation à la fin de `tick` |
| `sbin/secubox-adguard-auto` (modifier) | enchaîne ajout → tick → application |
| `sbin/secubox-adguard-dnsfeed` (modifier) | ignore les requêtes de la box |
| `sbin/secubox-adguard-tv` (modifier) | `puits` dans l'instantané, audit des appareils ajoutés/retirés |
| `api/dnstv_routes.py`, `www/ad-guard/index.html` (modifier) | routes et panneau |
| `lists/profil-tv-base.txt`, `lists/MANIFEST.json` (créer/modifier) | graine du profil (35 domaines validés) |
| `tests/test_dnstv_*.py` (créer) | un fichier par module |

Chemins de test : `cd packages/secubox-ad-guard && python -m pytest tests -q` (le `conftest.py` met le paquet et `common/` sur le chemin). Les extraits de test réutilisent les aides existantes (`tests/test_dnstv_auto_moteur.py` : `charger`, `evt`, `coupure`…).

---

### Task 1 : le journal ignore les requêtes de la box

**Files :** modifier `api/dnstv.py` (`Magasin.ajouter`, `adresses_locales`), `sbin/secubox-adguard-dnsfeed` (`suivre`) ; tester `tests/test_dnstv_biblio.py`.

**Interfaces :** produit `dnstv.adresses_locales(executer=None) -> set[str]` ; `Magasin.ajouter(evts, exclus: set[str] | None = None) -> int` (ignore les événements dont `client in exclus`) ; `suivre(lignes, magasin, cl, recharger=classeur, locales=dnstv.adresses_locales)`.

- [ ] **Step 1 : test rouge**

```python
def test_adresses_locales_lit_toutes_les_adresses_de_la_box():
    sortie = '[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"},{"local":"::1"}]},{"ifname":"eth2","addr_info":[{"local":"192.168.1.200"},{"local":"2a01:e0a:dec:c4e0::200"},{"local":"fe80::f2ad:4eff:fe27:889b"}]}]'
    class R:
        stdout = sortie
    loc = dnstv.adresses_locales(executer=lambda *a, **k: R())
    assert {"127.0.0.1", "::1", "192.168.1.200", "2a01:e0a:dec:c4e0::200"} <= loc


def test_les_requetes_de_la_box_ne_sont_pas_journalisees(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    evts = [(dnstv.Evenement(t, "192.168.1.200", "a.example.com", "A", "NOERROR", "ALLOWED"), ""),
            (dnstv.Evenement(t, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), "")]
    assert m.ajouter(evts, exclus={"192.168.1.200"}) == 1
    assert [x["client"] for x in m.recents(depuis=t - 5)] == ["192.168.1.95"]
    assert [c["client"] for c in m.par_client()] == ["192.168.1.95"]


def test_adresses_locales_commande_absente_donne_au_moins_le_bouclage():
    def echec(*a, **k):
        raise OSError("ip absent")
    assert dnstv.adresses_locales(executer=echec) == {"127.0.0.1", "::1"}
```

- [ ] **Step 2 :** `pytest tests/test_dnstv_biblio.py -q -k "locales or box_ne_sont"` → Expected : FAIL.
- [ ] **Step 3 : implémenter**

```python
# api/dnstv.py
def adresses_locales(executer=None) -> set:
    """Toutes les adresses de la box : ses propres requêtes DNS (≈ 11 000 en 20 min) saturaient dnstv_recents. Toujours au moins le bouclage."""
    import subprocess
    out = {"127.0.0.1", "::1"}
    try:
        r = (executer or subprocess.run)(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10)
        for itf in json.loads(r.stdout or "[]"):
            for a in itf.get("addr_info", []):
                v = a.get("local")
                if v:
                    out.add(str(ipaddress.ip_address(v)))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return out
```

`Magasin.ajouter(self, evts, exclus=None)` : en tête de boucle, `if exclus and e.client in exclus: continue`. Dans `sbin/secubox-adguard-dnsfeed` : `suivre(..., locales=dnstv.adresses_locales)` ; `locales_cache = locales()` recalculé toutes les `RECHARGE_S` ; `magasin.ajouter(lot, locales_cache)` aux deux endroits.

- [ ] **Step 4 :** `pytest tests -q` → Expected : PASS (aucune régression). **Step 5 :** commit `fix: le journal ignore les requetes de la box (ref #1959)`.

---

### Task 2 : état étendu et rendu `puits` (puits de production complet)

**Files :** modifier `api/dnstv.py` (`valider_etat`, `ETAT_DEFAUT`, `rendre_unbound`), `sbin/secubox-adguard-tv` (`instantane`) ; tester `tests/test_dnstv_puits.py`, `tests/test_dnstv_biblio.py` (égalités d'état), `tests/test_dnstv_banc_unbound.py` (Unbound réel).

**Interfaces :** `valider_etat` accepte et revalide : clients `mac` (`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, jamais `00:00:00:00:00:00`), `origine` (`admin|auto`), `ajoute` (entier ≥ 0), `preuve` (≤ 120 car.), `puits` (booléen) ; racine `mode_defaut` (`off|observe|auto|block`, défaut `auto`), `ajout_auto` (booléen, défaut faux), `ignores` (≤ 64 MAC). **Un client n'émet un champ que s'il n'est pas à sa valeur par défaut** (`mac` si connue, `origine` si `auto`, `ajoute`/`preuve` si renseignés, `puits` si faux) : les anciens états gardent le même format. Deux clients de même nom doivent avoir le même `mode` et le même `puits`, sinon `ErreurTV`. `rendre_unbound` : pour un appareil `auto` avec `puits` vrai, la vue porte `view-first: yes`, ses règles, et **pas** de `local-zone: "." transparent` ; avec `puits` faux, comme aujourd'hui.

- [ ] **Step 1 : tests rouges** (`tests/test_dnstv_puits.py`)

```python
import pytest
from api import dnstv

def etat(**kw):
    c = {"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}
    c.update(kw)
    return {"actif": True, "clients": [c]}

def bloc_auto(sortie):
    return sortie.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]

def test_vue_auto_avec_puits_complet_par_defaut():
    out = dnstv.rendre_unbound(etat(), {}, {"tv-banc": ["videos-pub.ftv-publicite.fr"]})
    b = bloc_auto(out)
    assert "view-first: yes" in b and 'local-zone: "." transparent' not in b
    assert 'local-zone: "videos-pub.ftv-publicite.fr." always_nxdomain' in b

def test_puits_faux_rend_l_ancien_comportement_transparent():
    b = bloc_auto(dnstv.rendre_unbound(etat(puits=False), {}, {}))
    assert 'local-zone: "." transparent' in b and "view-first" not in b

def test_observe_et_block_restent_transparents():
    out = dnstv.rendre_unbound(etat(mode="block"), {"a.example": "advertising"}, None)
    assert 'name: "sbx-tv-block"' in out and out.split('name: "sbx-tv-block"')[1].count('local-zone: "." transparent') == 1

def test_champs_revalides():
    base = dict(ip="192.168.1.95", nom="TV 4e95", mode="auto")
    assert dnstv.valider_etat({"actif": True, "clients": [dict(base, mac="38:07:16:93:4e:95", origine="auto", ajoute=1800000000, preuve="fwmrm.net ×12")]})["clients"][0]["mac"] == "38:07:16:93:4e:95"
    for mauvais in (dict(base, mac="00:00:00:00:00:00"), dict(base, mac="38:07:16:93:4E:95"), dict(base, mac='x"; reboot'), dict(base, origine="root"),
                    dict(base, puits="oui"), dict(base, ajoute=-1), dict(base, preuve="x" * 500)):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [mauvais]})

def test_defauts_racine_et_anciens_etats_inchanges():
    e = dnstv.valider_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV", "mode": "observe"}]})
    assert e["mode_defaut"] == "auto" and e["ajout_auto"] is False and e["ignores"] == []
    assert e["clients"][0] == {"ip": "192.168.1.95", "nom": "TV", "mode": "observe"}      # aucun champ ajouté tant qu'il est à sa valeur par défaut
    for mauvais in ({"mode_defaut": "inconnu"}, {"ajout_auto": "oui"}, {"ignores": ["pas-une-mac"]}, {"ignores": ["38:07:16:93:4e:95"] * 65}):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [], **mauvais})

def test_meme_nom_meme_puits():
    cs = [{"ip": "192.168.1.95", "nom": "TV", "mode": "auto"}, {"ip": "2a01::1", "nom": "TV", "mode": "auto", "puits": False}]
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({"actif": True, "clients": cs})
```

- [ ] **Step 2 :** `pytest tests/test_dnstv_puits.py -q` → Expected : FAIL.
- [ ] **Step 3 : implémenter** (`api/dnstv.py`) — constantes `MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")`, `MODES_DEFAUT = ("off", "observe", "auto", "block")` ; dans `valider_etat`, par client :

```python
mac = c.get("mac", "")
if mac and (not isinstance(mac, str) or not MAC_RE.match(mac) or mac == "00:00:00:00:00:00"):
    raise ErreurTV("adresse MAC invalide")
origine = c.get("origine", "admin")
if origine not in ("admin", "auto"):
    raise ErreurTV("origine inconnue")
ajoute = c.get("ajoute", 0)
if not isinstance(ajoute, int) or isinstance(ajoute, bool) or ajoute < 0:
    raise ErreurTV("date d'ajout invalide")
preuve = c.get("preuve", "")
if not isinstance(preuve, str) or len(preuve) > 120:
    raise ErreurTV("preuve trop longue")
puits = c.get("puits", True)
if not isinstance(puits, bool):
    raise ErreurTV("puits : booléen attendu")
entree = {"ip": ip, "nom": nom, "mode": mode}
if mac: entree["mac"] = mac
if origine == "auto": entree["origine"] = "auto"
if ajoute: entree["ajoute"] = ajoute
if preuve: entree["preuve"] = preuve
if not puits: entree["puits"] = False
```

Après la boucle : cohérence « même nom ⇒ même mode et même `puits` » ; racine : `mode_defaut` (défaut `auto`, dans `MODES_DEFAUT`), `ajout_auto` (booléen), `ignores` (liste de ≤ 64 MAC valides, dédoublonnée) ; retour `{"actif", "clients", "auto_essai", "mode_defaut", "ajout_auto", "ignores"}`. `ETAT_DEFAUT` reçoit les mêmes défauts. `rendre_unbound` : pour chaque `nom` auto, `puits = all(c.get("puits", True) ...)`, `if puits: L.append("    view-first: yes")` avant les zones de règles, et la zone `"." transparent` seulement si `not puits`. `sbin/secubox-adguard-tv` : dans `instantane`, `modes` devient `[ip, mode, nom, puits]` (un changement de `puits` déclenche donc le rechargement complet, voulu).

- [ ] **Step 4 :** mettre à jour les 2-3 tests d'égalité d'état existants (`test_dnstv_biblio.py` : `auto_essai` + `mode_defaut` + `ajout_auto` + `ignores`) puis `pytest tests -q` → Expected : PASS.
- [ ] **Step 5 : essai sur un vrai Unbound jetable** (`tests/test_dnstv_banc_unbound.py::test_puits_complet_et_regles_de_la_vue`, `skipif` sans `unbound`/`unbound-control`/`dig`), même mécanique que `test_ajout_retrait_a_chaud` : global `bloque.sbx. always_nxdomain` + `ok.sbx.` statique ; vue `view-first: yes` + règle `regle.sbx.` ; vérifier global bloqué, `ok.sbx` servi, règle refusée, puis `view_local_zone` à chaud. À jouer sur gk2 (Unbound 1.17.1, sans pytest : doublure de `pytest`, voir la session du 2026-10-03). **Step 6 :** commit `feat: etat etendu et vue auto avec puits de production complet (ref #1959)`.

---

### Task 3 : détecteur « TV/streamer probable »

**Files :** créer `api/dnstv_detecteur.py` ; modifier `api/dnstv.py` (`Magasin.compteurs_clients`) ; tester `tests/test_dnstv_detecteur.py`.

**Interfaces :** `Magasin.compteurs_clients(depuis_jour: str) -> dict[str, dict[str, int]]` (client → domaine → requêtes, toutes décisions) ; `Detection` (dataclass : `source:str, adresses:list[str], mac:str, score:int, preuve:str`) ; `detecter(compteurs: dict[str, dict[str,int]], voisins: dict[str,str], services: ClasseurServices, declencheurs: tuple[str,...], exclus: set[str], min_declencheurs:int=5, min_services:int=2) -> list[Detection]` — regroupe les clients par MAC (`regrouper_sources`) ; une source sans MAC est ignorée.

- [ ] **Step 1 : tests rouges**

```python
from api import dnstv, dnstv_detecteur as D

SERVICES = dnstv.ClasseurServices([("fwmrm.net", "FreeWheel", "publicite"), ("ftven.fr", "France Télévisions", "contenu"),
                                   ("youboranqs01.com", "NPAW", "qualite_video"), ("example.org", "Exemple", "contenu")])
MAC = "38:07:16:94:fb:5b"
VOISINS = {"192.168.1.128": MAC, "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57": MAC, "192.168.1.88": "aa:bb:cc:dd:ee:ff"}

def detect(compteurs, exclus=frozenset(), **kw):
    return D.detecter(compteurs, VOISINS, SERVICES, ("fwmrm.net",), set(exclus), **kw)

TV = {"7cd77.v.fwmrm.net": 12, "cloudreplay.ftven.fr": 30, "infinity.youboranqs01.com": 8}

def test_tv_detectee_et_adresses_ipv4_ipv6_regroupees():
    d = detect({"2a01:e0a:dec:c4e0:4951:bf00:df87:2c57": TV})
    assert len(d) == 1 and d[0].mac == MAC and d[0].adresses == ["2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"]
    assert "fwmrm.net" in d[0].preuve and d[0].score > 0

def test_les_deux_adresses_d_un_meme_appareil_se_cumulent():
    moitie = {"7cd77.v.fwmrm.net": 3, "cloudreplay.ftven.fr": 10, "infinity.youboranqs01.com": 4}
    d = detect({"192.168.1.128": moitie, "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57": moitie})
    assert len(d) == 1 and sorted(d[0].adresses) == sorted(["192.168.1.128", "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"])

def test_un_pic_isole_ne_suffit_pas():
    assert detect({"192.168.1.128": {"7cd77.v.fwmrm.net": 1, "cloudreplay.ftven.fr": 2, "infinity.youboranqs01.com": 1}}) == []

def test_sans_insertion_publicitaire_ou_avec_un_seul_service_pas_de_detection():
    assert detect({"192.168.1.128": {"cloudreplay.ftven.fr": 90, "infinity.youboranqs01.com": 40}}) == []
    assert detect({"192.168.1.128": {"7cd77.v.fwmrm.net": 20, "cloudreplay.ftven.fr": 90}}) == []

def test_adresse_sans_mac_jamais_detectee():
    assert detect({"192.168.1.77": TV}) == []

def test_exclusions_box_et_passerelle():
    assert detect({"192.168.1.128": TV}, exclus={"192.168.1.128"}) == []

def test_noms_hostiles_n_empechent_rien_et_ne_sont_pas_proposes():
    c = dict(TV)
    c['x"; reboot'] = 99
    d = detect({"192.168.1.128": c})
    assert len(d) == 1 and "reboot" not in d[0].preuve
```

- [ ] **Step 2 :** `pytest tests/test_dnstv_detecteur.py -q` → Expected : FAIL (module absent).
- [ ] **Step 3 : implémenter**

```python
# api/dnstv_detecteur.py  (en-tête SPDX, puis)
from dataclasses import dataclass
from typing import Dict, List, Set
try:
    from . import dnstv
except ImportError:
    from api import dnstv

TYPES_CONTENU = ("contenu", "qualite_video")


@dataclass
class Detection:
    source: str
    mac: str
    adresses: List[str]
    score: int
    preuve: str


def _suffixe(domaine: str, suffixes) -> bool:
    return any(domaine == s or domaine.endswith("." + s) for s in suffixes)


def detecter(compteurs, voisins, services, declencheurs, exclus: Set[str], min_declencheurs: int = 5, min_services: int = 2) -> List[Detection]:
    par_mac: Dict[str, Dict[str, int]] = {}
    adresses: Dict[str, List[str]] = {}
    for client, doms in compteurs.items():
        mac = voisins.get(client)
        if not mac or client in exclus:
            continue
        adresses.setdefault(mac, []).append(client)
        cumul = par_mac.setdefault(mac, {})
        for d, n in doms.items():
            if dnstv.valider_domaine(d) == d:                       # un nom hostile n'est ni compté ni jamais recopié
                cumul[d] = cumul.get(d, 0) + int(n)
    out: List[Detection] = []
    for mac, doms in par_mac.items():
        dec = sum(n for d, n in doms.items() if _suffixe(d, declencheurs))
        orgs = {org for d in doms for org, typ in [services.classer(d)] if typ in TYPES_CONTENU and org}
        if dec >= min_declencheurs and len(orgs) >= min_services:
            preuve = f"{dec} requêtes d'insertion publicitaire ; services : {', '.join(sorted(orgs))}"[:120]
            out.append(Detection(mac, mac, sorted(adresses[mac]), min(100, dec + 10 * len(orgs)), preuve))
    return sorted(out, key=lambda x: -x.score)
```

`Magasin.compteurs_clients` : `SELECT client, domaine, SUM(hits) FROM dnstv_counts WHERE jour>=? GROUP BY client, domaine`.

- [ ] **Step 4 :** `pytest tests/test_dnstv_detecteur.py tests -q` → Expected : PASS. **Step 5 :** commit `feat: detection des TV et streamers par comportement DNS (ref #1959)`.

---

### Task 4 : profil de base, agrégation, règles proposées

**Files :** créer `api/dnstv_profil.py`, `lists/profil-tv-base.txt` ; modifier `lists/MANIFEST.json` (via `tools/maj-manifeste.py`), `api/dnstv_regles.py` (`proposer(..., motif="proposé")`) ; tester `tests/test_dnstv_profil.py`.

**Interfaces :** `dnstv_regles.Regles.proposer(appareil, domaine, score, risque, maintenant, origine="auto", motif="proposé")` ; `dnstv_profil` : `graine(dossier_listes=None) -> list[str]` ; `agreger(regles: Regles, min_appareils: int = 2) -> dict[str, dict]` (`{"appareils": [...], "maj": ts}`) ; `charger_agrege(dossier=None) -> dict`, `ecrire_agrege(agrege, dossier=None)` (atomique, relue sans lien symbolique, revalidée) ; `profil_effectif(graine, agrege) -> list[tuple[str, str]]` ; `equiper(regles, appareil, profil, maintenant) -> int` (règles **confirmées**, origine `auto`, motif « profil de base » ou « profil agrégé (N appareils) ») ; `candidats_agreges(regles, agrege, appareils_auto, maintenant) -> int` (candidats score 90, motif « confirmé sur N autres appareils », jamais d'état actif).

Règle d'agrégation (Review Focus 7) : une règle compte pour un appareil **seulement si sa dernière transition vers `confirme` est d'origine `admin`** ; les règles issues du profil (`origine=auto`, motif commençant par `profil`) ne comptent jamais.

- [ ] **Step 1 : tests rouges**

```python
from api import dnstv_profil as P, dnstv_regles as R
T0 = 1_800_000_000

def confirmer(r, app, dom, origine="admin", motif="ok"):
    rid = r.proposer(app, dom, 50, "faible", T0, origine=origine)["id"]
    r.transiter(rid, "essai", origine, motif, T0)
    r.transiter(rid, "confirme", origine, motif, T0 + 5)

def test_graine_est_le_profil_valide():
    g = P.graine()
    assert {"videos-pub.ftv-publicite.fr", "c.2mdn.net", "7cd77.v.fwmrm.net"} <= set(g) and len(g) == 35

def test_agregation_seuil_deux_appareils_et_provenance():
    r = R.Regles()
    confirmer(r, "tv-a", "pub.example.com"); confirmer(r, "tv-b", "pub.example.com"); confirmer(r, "tv-a", "seul.example.com")
    a = P.agreger(r, min_appareils=2)
    assert set(a) == {"pub.example.com"} and sorted(a["pub.example.com"]["appareils"]) == ["tv-a", "tv-b"]

def test_les_regles_du_profil_ne_s_auto_renforcent_pas():
    r = R.Regles()
    P.equiper(r, "tv-a", [("pub.example.com", "profil de base")], T0)
    P.equiper(r, "tv-b", [("pub.example.com", "profil de base")], T0)
    assert P.agreger(r, 2) == {}

def test_equiper_cree_des_regles_confirmees_idempotent():
    r = R.Regles()
    assert P.equiper(r, "tv-n", [("a.example.com", "profil de base"), ("b.example.com", "profil agrégé (2 appareils)")], T0) == 2
    assert r.actives("tv-n") == ["a.example.com", "b.example.com"] and P.equiper(r, "tv-n", [("a.example.com", "profil de base")], T0 + 9) == 0
    assert all(x["etat"] == "confirme" and x["origine"] == "auto" for x in r.liste())

def test_candidats_agreges_jamais_actifs_et_pas_chez_ceux_qui_l_ont_ou_l_ont_rejete():
    r = R.Regles()
    confirmer(r, "tv-a", "pub.example.com"); confirmer(r, "tv-b", "pub.example.com")
    rid = r.proposer("tv-d", "pub.example.com", 1, "faible", T0)["id"]; r.transiter(rid, "rejete", "admin", "non", T0)
    n = P.candidats_agreges(r, P.agreger(r, 2), ["tv-a", "tv-b", "tv-c", "tv-d"], T0 + 10)
    assert n == 1 and [x["etat"] for x in r.liste() if x["appareil"] == "tv-c"] == ["candidat"]
    assert "confirmé sur 2 autres" in r.get(R.identifiant("tv-c", "pub.example.com"))["motif"] or True

def test_agrege_ecriture_atomique_lien_symbolique_refuse(tmp_path):
    P.ecrire_agrege({"pub.example.com": {"appareils": ["tv-a", "tv-b"], "maj": T0}}, tmp_path)
    assert "pub.example.com" in P.charger_agrege(tmp_path)
    (tmp_path / "profil-agrege.json").unlink()
    (tmp_path / "ailleurs.json").write_text("{}")
    import os; os.symlink(tmp_path / "ailleurs.json", tmp_path / "profil-agrege.json")
    assert P.charger_agrege(tmp_path) == {}                                   # refusé, jamais suivi
```

Note d'exécution : le dernier `assert … or True` du test des candidats est un échappatoire du brouillon — **le resserrer** en vérifiant `"confirmé sur 2 autres" in …["historique"][0]["motif"]` avant le commit.

- [ ] **Step 2 :** `pytest tests/test_dnstv_profil.py -q` → Expected : FAIL.
- [ ] **Step 3 : implémenter** `proposer(..., motif="proposé")` (le motif alimente `historique[0]` et `motif`) ; générer la graine :

```bash
cd packages/secubox-ad-guard
python3 - <<'EOF'
from pathlib import Path
d = Path("lists"); noms = []
for f in ("advertising", "tracking", "telemetry", "social"):
    noms += [l.strip() for l in (d / f"{f}.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
noms += ["videos-pub.ftv-publicite.fr", "c.2mdn.net", "7cd77.v.fwmrm.net"]
tete = open("api/dnstv_regles.py").read().split('"""')[0]
(d / "profil-tv-base.txt").write_text(tete + "# version: 2026.10.03-1\n# Profil de base : les 35 domaines validés sur 2 Freebox TV réelles (#1943/#1954), appliqués comme règles CONFIRMÉES à un nouvel appareil.\n" + "\n".join(sorted(set(noms))) + "\n")
EOF
python3 tools/maj-manifeste.py
```

puis `dnstv_profil.py` (fonctions ci-dessus ; `agreger` parcourt `regles.liste()`, retient les règles `etat == "confirme"` dont `historique[-1]` a `vers == "confirme"` et `origine == "admin"`, regroupe par domaine, garde ceux d'au moins `min_appareils` appareils distincts) et `equiper`/`candidats_agreges` appelant `Regles.proposer(..., origine="auto", motif=...)` puis `transiter` (`essai` → `confirme`) pour `equiper`.

- [ ] **Step 4 :** `pytest tests -q` → Expected : PASS (dont `test_dnstv_biblio.py` sur le manifeste). **Step 5 :** commit `feat: profil de base, agregation et candidats communs (ref #1959)`.

---

### Task 5 : ajout automatique et suivi des adresses

**Files :** créer `api/dnstv_ajout.py` ; tester `tests/test_dnstv_ajout.py`.

**Interfaces :**
- `Reglage` n'est pas dupliqué : `dnstv_auto.Reglage` gagne `max_par_jour:int=3`, `delai_s:int=3600`, `retrait_jours:int=7`, `min_declencheurs:int=5`, `min_services:int=2`, `min_appareils_agreg:int=2` (lus dans `[adblock_tv_auto]` par `reglage_depuis`).
- `nom_appareil(mac: str, existants: set[str]) -> str` : `TV` + 4 derniers hexadécimaux, unique par slug (`-2`, `-3`…), conforme à `NOM_RE`.
- `charger_suivi(dossier=None) -> dict`, `ecrire_suivi(suivi, dossier=None)` : `{"ajouts": [ts…], "dernier_changement": ts}` (atomique, revalidé).
- `appliquer(etat, regles, detections, voisins, vues, profil, suivi, reglage, maintenant) -> dict` : modifie `etat`, `regles` et `suivi` **en place** et rend `{"changements": [{"type", "nom", "detail"}], "etat_modifie": bool}`. `vues` = `dict[adresse, timestamp de dernière vue]`.

Comportement : rien si `etat["ajout_auto"]` est faux. Un appareil détecté est ajouté seulement si : MAC valide non ignorée et non déjà connue, `maintenant - suivi["dernier_changement"] >= delai_s`, moins de `max_par_jour` ajouts sur 24 h, place pour ses adresses (≤ 32). Ajout : une entrée `clients` par adresse (`mode = etat["mode_defaut"]`, `origine="auto"`, `mac`, `ajoute`, `preuve`, `puits=True`) ; si `mode_defaut == "auto"`, `dnstv_profil.equiper(regles, slug(nom), profil, maintenant)`. Suivi des adresses : pour chaque appareil `origine=auto` connu, les adresses que `voisins` rattache à sa MAC sont ajoutées (même nom, mode, `puits`) ; une adresse `origine=auto` non vue depuis `retrait_jours` est retirée, **sauf la dernière**.

- [ ] **Step 1 : tests rouges** (extraits ; l'implémenteur écrit chacun en entier dans le même style)

```python
MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
VOISINS = {"192.168.1.128": MAC, V6: MAC}
REGLAGE = M.Reglage()
DET = [D.Detection(MAC, MAC, [V6, "192.168.1.128"], 80, "12 requêtes d'insertion publicitaire ; services : France Télévisions, NPAW")]
PROFIL = [("videos-pub.ftv-publicite.fr", "profil de base"), ("c.2mdn.net", "profil de base")]

def monde(ajout_auto=True, clients=None):
    etat = dnstv.valider_etat({"actif": True, "ajout_auto": ajout_auto, "clients": clients or []})
    return etat, R.Regles(), {"ajouts": [], "dernier_changement": 0}

def test_ajout_complet_nom_mode_regles_confirmees_et_audit_des_champs():
    etat, regles, suivi = monde()
    res = A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)
    noms = {c["nom"] for c in etat["clients"]}
    assert noms == {"TV fb5b"} and {c["ip"] for c in etat["clients"]} == {V6, "192.168.1.128"}
    assert all(c["mode"] == "auto" and c["origine"] == "auto" and c["mac"] == MAC and c["ajoute"] == T0 for c in etat["clients"])
    assert regles.actives("tv-fb5b") == ["c.2mdn.net", "videos-pub.ftv-publicite.fr"] and res["etat_modifie"] is True
    dnstv.valider_etat(etat)                                                  # l'état produit reste valide

def test_desactive_par_defaut_ne_change_rien():
    etat, regles, suivi = monde(ajout_auto=False)
    assert A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)["etat_modifie"] is False and etat["clients"] == []

def test_mac_ignoree_ou_connue_jamais_ajoutee():
    etat, regles, suivi = monde(); etat["ignores"] = [MAC]
    A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0); assert etat["clients"] == []

def test_plafond_quotidien_et_delai_entre_rechargements():
    etat, regles, suivi = monde()
    suivi["dernier_changement"] = T0 - 600                                   # < 1 h : différé, sans erreur
    assert A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)["etat_modifie"] is False
    suivi = {"ajouts": [T0 - 3600 * i for i in (2, 3, 4)], "dernier_changement": T0 - 7200}   # 3 ajouts sur 24 h
    assert A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)["etat_modifie"] is False

def test_trente_deux_adresses_au_plus_sans_erreur():
    clients = [{"ip": f"192.168.1.{i}", "nom": f"Autre {i}", "mode": "observe"} for i in range(1, 32)]
    etat, regles, suivi = monde(clients=clients)
    A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)       # 2 adresses n'entrent pas : 31 + 2 > 32
    assert len(etat["clients"]) == 31

def test_nouvelle_ipv6_rattachee_et_adresse_ancienne_retiree_mais_une_reste():
    etat, regles, suivi = monde(); A.appliquer(etat, regles, DET, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)
    neuve = "2a01:e0a:dec:c4e0:9999:1:2:3"
    voisins = {"192.168.1.128": MAC, neuve: MAC}
    vues = {"192.168.1.128": T0 + 8 * 86400, neuve: T0 + 8 * 86400, V6: T0}      # l'ancienne IPv6 n'est plus vue depuis 8 jours
    A.appliquer(etat, regles, [], voisins, vues, PROFIL, suivi, REGLAGE, T0 + 8 * 86400)
    assert {c["ip"] for c in etat["clients"]} == {"192.168.1.128", neuve}
    vues2 = {k: 0 for k in vues}
    A.appliquer(etat, regles, [], {}, vues2, PROFIL, suivi, REGLAGE, T0 + 30 * 86400)
    assert len(etat["clients"]) >= 1                                          # une adresse au moins reste toujours

def test_nom_unique_et_conforme():
    assert A.nom_appareil(MAC, set()) == "TV fb5b" and A.nom_appareil(MAC, {"tv-fb5b"}) == "TV fb5b-2"
    assert dnstv.NOM_RE.match(A.nom_appareil(MAC, set()))

def test_detection_hostile_jamais_ecrite():
    det = [D.Detection("38:07:16:94:FB:5B", "x", ['1.2.3.4"; reboot'], 90, "<img>")]
    etat, regles, suivi = monde()
    A.appliquer(etat, regles, det, VOISINS, {}, PROFIL, suivi, REGLAGE, T0)
    assert etat["clients"] == []
```

- [ ] **Step 2 :** `pytest tests/test_dnstv_ajout.py -q` → Expected : FAIL. **Step 3 : implémenter** `dnstv_ajout.py` selon le comportement ci-dessus (validation de la MAC par `dnstv.MAC_RE`, de chaque adresse par `dnstv._ip`, passage final par `dnstv.valider_etat(etat)` avant de rendre la main : une valeur invalide annule tout). **Step 4 :** `pytest tests -q` → Expected : PASS. **Step 5 :** commit `feat: ajout automatique des appareils detectes et suivi de leurs adresses (ref #1959)`.

---

### Task 6 : moteur — enchaînement, agrégation, application

**Files :** modifier `api/dnstv_auto.py` (`reglage_depuis`, fin de `tick`), `sbin/secubox-adguard-auto`, `sbin/secubox-adguard-tv` (audit) ; tester `tests/test_dnstv_auto_moteur.py`, `tests/test_dnstv_ajout_moteur.py`.

**Interfaces :** `tick(...)` appelle en fin de passage `dnstv_profil.agreger` → `ecrire_agrege` (dans le script) et `candidats_agreges` pour les appareils `auto` ; le script `secubox-adguard-auto` enchaîne, **sous `dnstv_regles.verrou()`** : (1) `voisins = dnstv.lire_voisins()`, `exclus = dnstv.adresses_locales() | passerelle`, compteurs des 2 derniers jours ; (2) `detecter` ; (3) `dnstv_ajout.appliquer` (puis `dnstv.ecrire_etat(etat)`, `dnstv_regles.ecrire`, `ecrire_suivi`) ; (4) `tick` ; (5) agrégation ; (6) appel du contrôleur si l'état a changé ou si une règle a changé d'état (comportement de #1954 conservé, y compris la marque `.a-appliquer`). Le contrôleur audite les **appareils ajoutés/retirés** (comparaison de `modes` entre deux instantanés : une ligne `appareil` par ajout/retrait avec `origine` et `preuve` lus dans `etat.json`).

- [ ] **Step 1 : tests rouges** — (a) un appareil détecté est ajouté, ses règles de base sont **confirmées** et le script appelle le contrôleur une fois ; (b) `ajout_auto` faux : aucun appel, `etat.json` inchangé octet pour octet ; (c) un domaine confirmé par l'administrateur sur 2 appareils devient **candidat** (jamais actif) sur un troisième, et le profil agrégé est écrit ; (d) échec du contrôleur : marque `.a-appliquer`, relance au passage suivant (test de #1954 conservé) ; (e) le contrôleur audite `appareil … origine=auto preuve=…` à l'ajout (test dans `test_dnstv_revue_1954.py`, même banc que `test_i8_*`) ; (f) deux passages dans la même heure n'ajoutent qu'un appareil.
- [ ] **Step 2 :** `pytest tests -q -k "ajout or agreg or audite"` → Expected : FAIL.
- [ ] **Step 3 : implémenter** comme décrit ; `reglage_depuis` lit `max_par_jour`, `delai_s`, `retrait_jours`, `min_declencheurs`, `min_services`, `min_appareils_agreg` (entiers positifs, sinon défauts) ; `config/ad-guard.toml` gagne ces clés avec le commentaire « seuils de départ, à calibrer ».
- [ ] **Step 4 :** `pytest tests -q` ; `ruff check api sbin/secubox-adguard-auto sbin/secubox-adguard-tv sbin/secubox-adguard-dnsfeed` → Expected : PASS. **Step 5 :** commit `feat: le moteur enchaine ajout automatique, regles et agregation (ref #1959)`.

---

### Task 7 : routes d'administration

**Files :** modifier `api/dnstv_routes.py` ; tester `tests/test_dnstv_auto_routes.py`.

**Interfaces** (préfixe `/adblock-tv`) : `GET /auto/detection` (`require_lecture`) → `{"ajout_auto", "mode_defaut", "ignores", "appareils":[{"nom","mac","adresses","origine","ajoute","preuve","puits","mode"}], "plafond":{"max_par_jour","ajouts_24h"}}` ; `POST /auto/detection/reglage` (`require_jwt`, `{"ajout_auto"?:bool, "mode_defaut"?:str}`, valeurs hors liste → 422) ; `POST /auto/appareils/{nom}/ignorer` (`require_jwt`) : retire toutes les adresses du nom, ajoute sa MAC à `ignores` (si connue), supprime ses règles actives, applique ; `POST /auto/appareils/{nom}/puits` (`require_jwt`, `{"actif":bool}`) ; `GET /auto/profil` (`require_lecture`) → profil effectif et provenance. Toutes **synchrones** ; chaque écriture : `with _verrou()`, copie de l'état/des règles avant, `_ctl("regles-appliquer")`, **retour arrière des fichiers si le contrôleur échoue** (patron `_appliquer_ou_annuler` de #1954).

- [ ] **Step 1 : tests rouges** — gardes (401/403), lecture avec les compteurs, réglage valide/invalide, `ignorer` (adresses retirées, MAC ignorée, règles retirées, contrôleur appelé, retour arrière si 502), `puits` bascule et applique, nom hostile (`../x`, 200 caractères) → 404/422, routes synchrones (`inspect.iscoroutinefunction`).
- [ ] **Step 2 :** `pytest tests/test_dnstv_auto_routes.py -q` → Expected : FAIL. **Step 3 : implémenter.** **Step 4 :** `pytest tests -q` → Expected : PASS. **Step 5 :** commit `feat: routes de detection, d'ignorance et de puits (ref #1959)`.

---

### Task 8 : panneau d'administration

**Files :** modifier `www/ad-guard/index.html` ; tester `tests/test_dnstv_ui.py`.

**Contenu** (dans la carte « Mode automatique ») : interrupteur « Ajout automatique » (confirmation avant activation) ; sélecteur « Mode par défaut » (`auto` par défaut) avec la phrase « Un appareil en observe/block sort du puits de production ; en auto il le garde (réglage par appareil) » ; tableau des appareils (nom, adresses regroupées, badge « ajouté automatiquement le … », preuve, case « puits complet », bouton « Retirer et ne plus ajouter ») ; profil agrégé (domaine, appareils, dernière confirmation) ; mention du plafond (`ajouts_24h / max_par_jour`). Rendu par `textContent` ; libellés locaux ; erreur d'API → « indisponible », jamais d'exception ; `await res.json()` déjà corrigé.

- [ ] **Step 1 : tests navigateur rouges** — rendu avec des appareils ajoutés ; **texte piégé** (`<img onerror>`) en nom, preuve, adresse → aucun `img` créé, `window.__pwn` indéfini ; réponse vide ou HTML 502 → aucune exception ; clic « Retirer et ne plus ajouter » → confirmation puis `POST …/ignorer` ; case « puits » → `POST …/puits` ; l'interrupteur demande confirmation.
- [ ] **Step 2 :** `pytest tests/test_dnstv_ui.py -q` → Expected : FAIL. **Step 3 : implémenter** (même style que `dnsBoxRender`/`autoRender`). **Step 4 :** `pytest tests -q` → Expected : PASS. **Step 5 :** commit `feat: panneau de l'ajout automatique, du puits et du profil agrege (ref #1959)`.

---

### Task 9 : paquet 1.5.0, déploiement et essai réel

**Files :** `debian/changelog`, `debian/rules` (installer `lists/profil-tv-base.txt` — déjà couvert par `lists/*.txt` — et les nouveaux modules `api/`), `README.md`, `.claude/HISTORY.md`, `.claude/WIP.md`, spec (écarts éventuels).

- [ ] **Step 1 : version et documentation.** `secubox-ad-guard (1.5.0-1~bookworm1)` : ajout automatique, puits complet par `view-first`, agrégation, journal sans les requêtes de la box. README : routes, modèle (`mode_defaut`, `ajout_auto`, `ignores`, champs d'appareil), TOML, **avertissement** « en `observe`/`block`, un appareil sort du puits ; en `auto` avec `puits` vrai il le garde ».
- [ ] **Step 2 : tests complets** `python -m pytest tests -q`, `ruff`, `dpkg-buildpackage -us -uc -b -d`.
- [ ] **Step 3 : base.** `ssh root@192.168.1.200 'dpkg -l secubox-ad-guard'` doit afficher 1.4.3 ; sinon s'arrêter.
- [ ] **Step 4 : test sur Unbound réel de gk2** (Task 2 step 5) avant d'installer.
- [ ] **Step 5 : déployer** (`dpkg -i`, `reprepro includedeb`, `systemctl restart secubox-group@g1`, **`systemctl restart secubox-aggregator`**, attendre le retour), puis **vérifier par l'adresse publique** les routes `status`, `auto/regles`, `auto/detection`, `auto/profil`, `dns-box`. `ajout_auto` reste **faux**.
- [ ] **Step 6 : essai réel avec le propriétaire présent**, dans cet ordre, en demandant son retour à chaque étape : (a) mesurer le temps de rechargement d'Unbound et sa mémoire avant/après le passage de « TV banc » au puits complet (réglage `puits`) ; lecture d'un replay avec une coupure ; retour arrière par la case `puits` si besoin ; (b) activer `ajout_auto` et vérifier que la **seconde TV** (MAC `38:07:16:94:fb:5b`, vue en IPv6) est détectée et ajoutée, avec son profil de base, un seul rechargement du DNS ; vérifier le journal d'audit et le panneau ; tester « Retirer et ne plus ajouter ».
- [ ] **Step 7 : suivi** HISTORY/WIP (ce qui est mesuré, ce qui ne l'est pas, seuils laissés « à calibrer »), mémoire du projet. `closes #1959` **seulement** après validation du propriétaire.
- [ ] **Step 8 : PR et fusion** (`scripts/agent-worktree.sh finish`), nettoyage du worktree.

---

## Self-Review

**Couverture de la spec.** §1 décisions → T5/T2 (mode par défaut `auto`, profil), §3 puits complet → T2 (rendu, test Unbound réel) ; §4 détection → T3 (compteurs, exclusion des requêtes de la box → T1) ; §5 ajout/suivi/profil de base/rechargements groupés → T4/T5/T6 ; §6 agrégation → T4/T6 ; §7 garde-fous → T5 (plafonds, exclusions, ignores), T6 (audit), T7 (retrait en un clic) ; §8 données/API → T2/T7 ; §9 panneau → T8 ; §10 tests → un fichier par tâche ; §11 livraison → T9. Lacune assumée : la table des voisins du noyau oublie les IPv6 anciennes (STALE puis supprimées) : une IPv6 vue par le DNS mais plus présente dans la table reste « sans MAC » donc non attribuée (limite de `lire_voisins`).

**Placeholders.** Les tests des tâches 6, 7 et 8 sont décrits par cas plutôt qu'écrits en code complet : à compléter par l'implémentateur **avant** l'implémentation, dans le style des tâches 1 à 5. Le test des candidats agrégés (T4) contient un `or True` de brouillon, à resserrer (indiqué). `dnstv_ajout.appliquer` est décrit par son comportement et ses tests, pas par son code.

**Cohérence des types.** `Detection(source, mac, adresses, score, preuve)` (T3) consommée par `appliquer` (T5) ; `Regles.proposer(..., motif=)` (T4) utilisé par `equiper`/`candidats_agreges` ; `Reglage` étendu (T5) lu par `reglage_depuis` (T6) ; `dnstv.MAC_RE`, `adresses_locales`, `compteurs_clients` définis aux tâches 1–3 et consommés en 5–6 ; `puits` défini en T2, consommé en T5/T7/T8.

**Points ouverts, à ne pas présenter comme acquis.** Seuils (5 requêtes d'insertion, 2 services, 3 ajouts/jour, 7 jours, 2 appareils pour l'agrégation) : valeurs de départ d'un seul cas réel ; la combinaison « puits complet + règles » sur « TV banc » n'a pas été jouée telle quelle (réunion de deux états validés) ; la mémoire et le temps de rechargement avec `view-first` restent à mesurer sur gk2 ; le détecteur ne distingue pas une TV d'un téléphone qui regarde le même replay.
